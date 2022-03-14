/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cenkalti/backoff/v4"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

var logger = log.New("dispatcher/inbound")

const (
	kaIdentifier = "#"
)

// MessageHandler handles inbound envelopes, processing then dispatching to a protocol service based on the
// message type.
type MessageHandler struct {
	didConnectionStore     didstore.ConnectionStore
	didcommV2Handler       *middleware.DIDCommMessageMiddleware
	msgSvcProvider         api.MessageServiceProvider
	services               []dispatcher.ProtocolService
	getDIDsBackOffDuration time.Duration
	getDIDsMaxRetries      uint64
	messenger              service.InboundMessenger
	vdr                    vdrapi.Registry
	initialized            bool
	supportedMTPs          []string
}

type provider interface {
	DIDConnectionStore() didstore.ConnectionStore
	MessageServiceProvider() api.MessageServiceProvider
	AllServices() []dispatcher.ProtocolService
	GetDIDsBackOffDuration() time.Duration
	GetDIDsMaxRetries() uint64
	InboundMessenger() service.InboundMessenger
	DIDRotator() *middleware.DIDCommMessageMiddleware
	VDRegistry() vdrapi.Registry
	MediaTypeProfiles() []string
}

// NewInboundMessageHandler creates an inbound message handler, that processes inbound message Envelopes,
// and dispatches them to the appropriate ProtocolService.
func NewInboundMessageHandler(p provider) *MessageHandler {
	h := MessageHandler{}
	h.Initialize(p)

	return &h
}

// Initialize initializes the MessageHandler. Any call beyond the first is a no-op.
func (handler *MessageHandler) Initialize(p provider) {
	if handler.initialized {
		return
	}

	handler.didConnectionStore = p.DIDConnectionStore()
	handler.msgSvcProvider = p.MessageServiceProvider()
	handler.services = p.AllServices()
	handler.getDIDsBackOffDuration = p.GetDIDsBackOffDuration()
	handler.getDIDsMaxRetries = p.GetDIDsMaxRetries()
	handler.messenger = p.InboundMessenger()
	handler.didcommV2Handler = p.DIDRotator()
	handler.vdr = p.VDRegistry()
	handler.supportedMTPs = p.MediaTypeProfiles()

	handler.initialized = true
}

// HandlerFunc returns the MessageHandler's transport.InboundMessageHandler function.
func (handler *MessageHandler) HandlerFunc() transport.InboundMessageHandler {
	return func(envelope *transport.Envelope) error {
		return handler.HandleInboundEnvelope(envelope)
	}
}

// HandleInboundEnvelope handles an inbound envelope, dispatching it to the appropriate ProtocolService.
func (handler *MessageHandler) HandleInboundEnvelope(envelope *transport.Envelope, // nolint:funlen,gocognit,gocyclo
) error {
	var (
		msg service.DIDCommMsgMap
		err error
	)

	inboundMTPs := handler.inferMTPFromCty(envelope.MediaTypeProfile)

	logger.Debugf("inferred MTPs of inbound message: %v", inboundMTPs)

	msg, err = service.ParseDIDCommMsgMap(envelope.Message)
	if err != nil {
		return err
	}

	isDIDEx := (&didexchange.Service{}).Accept(msg.Type())

	isV2 := service.IsDIDCommV2(&msg)

	var (
		myDID, theirDID string
		gotDIDs         bool
	)

	// handle inbound peer DID initial state
	err = handler.didcommV2Handler.HandleInboundPeerDID(msg)
	if err != nil {
		return fmt.Errorf("handling inbound peer DID: %w", err)
	}

	var rec *service.ConnectionRecord

	// if msg is not a didexchange message, do additional handling
	if !isDIDEx {
		myDID, theirDID, err = handler.getDIDs(envelope, msg)
		if err != nil {
			return fmt.Errorf("get DIDs for message: %w", err)
		}

		gotDIDs = true

		rec, err = handler.didcommV2Handler.HandleInboundMessage(msg, theirDID, myDID, inboundMTPs)
		if err != nil {
			return fmt.Errorf("didcomm v2 middleware: %w", err)
		}

		logger.Debugf("Connection record: %#v", rec)
	}

	var foundService dispatcher.ProtocolService

	// find the service which accepts the message type
	for _, svc := range handler.services {
		if svc.Accept(msg.Type()) {
			foundService = svc
			break
		}
	}

	if foundService != nil {
		switch foundService.Name() {
		// perf: DID exchange doesn't require myDID and theirDID
		case didexchange.DIDExchange:
			_, err = foundService.HandleInbound(msg, service.NewDIDCommContext("", "", nil))

			return err
		default:
			if !gotDIDs {
				// note: should no longer ever get here
				panic("should never get here")
				// myDID, theirDID, err = handler.getDIDs(envelope, msg)
				// if err != nil {
				// 	return fmt.Errorf("inbound message handler: %w", err)
				// }
			}
		}

		// when is rec nil, besides didexchange?
		if rec == nil {
			rec = &service.ConnectionRecord{
				MyDID:    myDID,
				TheirDID: theirDID,
			}
		}

		// TODO: add connection record to service.DIDCommContext, with the record returned by the middleware
		//  - this would require a major refactor, however, to avoid an import cycle...
		//    note: refactor done!
		_, err = foundService.HandleInbound(msg, service.ConnectionDIDCommContext(rec, nil))

		return err
	}

	if !isV2 { // nolint:nestif
		h := struct {
			Purpose []string `json:"~purpose"`
		}{}
		err = msg.Decode(&h)

		if err != nil {
			return err
		}

		// in case of no services are registered for given message type, and message is didcomm v1,
		// find generic inbound services registered for given message header
		var foundMessageService dispatcher.MessageService

		for _, svc := range handler.msgSvcProvider.Services() {
			if svc.Accept(msg.Type(), h.Purpose) {
				foundMessageService = svc
			}
		}

		if foundMessageService != nil {
			if !gotDIDs {
				myDID, theirDID, err = handler.getDIDs(envelope, msg)
				if err != nil {
					return fmt.Errorf("inbound message handler: %w", err)
				}
			}

			// when is rec nil?
			if rec == nil {
				rec = &service.ConnectionRecord{
					MyDID:    myDID,
					TheirDID: theirDID,
				}
			}

			return handler.tryToHandle(foundMessageService, msg, service.ConnectionDIDCommContext(rec, nil))
		}
	}

	return fmt.Errorf("no message handlers found for the message type: %s", msg.Type())
}

func (handler *MessageHandler) getDIDs( // nolint:funlen,gocyclo,gocognit
	envelope *transport.Envelope, message service.DIDCommMsgMap,
) (string, string, error) {
	var (
		myDID    string
		theirDID string
		err      error
	)

	myDID, err = handler.getDIDGivenKey(envelope.ToKey)
	if err != nil {
		return myDID, theirDID, err
	}

	theirDID, err = handler.getDIDGivenKey(envelope.FromKey)
	if err != nil {
		return myDID, theirDID, err
	}

	if len(envelope.FromKey) == 0 && message != nil && theirDID == "" {
		if from, ok := message["from"].(string); ok {
			didURL, e := did.ParseDIDURL(from)
			if e == nil {
				theirDID = didURL.DID.String()
			}
		}
	}

	return myDID, theirDID, backoff.Retry(func() error {
		var notFound bool

		if myDID == "" {
			myDID, err = handler.didConnectionStore.GetDID(base58.Encode(envelope.ToKey))
			if errors.Is(err, didstore.ErrNotFound) {
				// try did:key
				// CreateDIDKey below is for Ed25519 keys only, use the more general CreateDIDKeyByCode if other key
				// types will be used. Currently, did:key is for legacy packers only, so only support Ed25519 keys.
				didKey, _ := fingerprint.CreateDIDKey(envelope.ToKey)
				myDID, err = handler.didConnectionStore.GetDID(didKey)
			}

			if errors.Is(err, didstore.ErrNotFound) {
				notFound = true
			} else if err != nil {
				myDID = ""
				return fmt.Errorf("failed to get my did: %w", err)
			}
		}

		if envelope.FromKey == nil {
			return nil
		}

		if theirDID == "" {
			theirDID, err = handler.didConnectionStore.GetDID(base58.Encode(envelope.FromKey))
			if errors.Is(err, didstore.ErrNotFound) {
				// try did:key
				// CreateDIDKey below is for Ed25519 keys only, use the more general CreateDIDKeyByCode if other key
				// types will be used. Currently, did:key is for legacy packers, so only support Ed25519 keys.
				didKey, _ := fingerprint.CreateDIDKey(envelope.FromKey)
				theirDID, err = handler.didConnectionStore.GetDID(didKey)
			}

			if err == nil {
				return nil
			}

			if notFound && errors.Is(err, didstore.ErrNotFound) {
				// if neither DID is found, using either base58 key or did:key as lookup key
				return nil
			}

			theirDID = ""
			return fmt.Errorf("failed to get their did: %w", err)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(handler.getDIDsBackOffDuration), handler.getDIDsMaxRetries))
}

// getDIDGivenKey returns a did:key if the input key is a JWK. If the input key is not a JWK, returns the empty string.
// An error is returned if the key is a JWK but fails to be converted to a did:key.
func (handler *MessageHandler) getDIDGivenKey(key []byte) (string, error) {
	var (
		err    error
		retDID string
	)

	// nolint: gocritic
	if strings.Index(string(key), kaIdentifier) > 0 &&
		strings.Index(string(key), "\"kid\":\"did:") > 0 {
		retDID, err = pubKeyToDID(key)
		if err != nil {
			return "", fmt.Errorf("getDID: %w", err)
		}

		logger.Debugf("envelope Key as DID: %v", retDID)

		return retDID, nil
	}

	return "", nil
}

func pubKeyToDID(key []byte) (string, error) {
	toKey := &crypto.PublicKey{}

	err := json.Unmarshal(key, toKey)
	if err != nil {
		return "", fmt.Errorf("pubKeyToDID: unmarshal key: %w", err)
	}

	return toKey.KID[:strings.Index(toKey.KID, kaIdentifier)], nil
}

func (handler *MessageHandler) tryToHandle(
	svc service.InboundHandler, msg service.DIDCommMsgMap, ctx service.DIDCommContext) error {
	if err := handler.messenger.HandleInbound(msg, ctx); err != nil {
		return fmt.Errorf("messenger HandleInbound: %w", err)
	}

	_, err := svc.HandleInbound(msg, ctx)

	return err
}

func (handler *MessageHandler) inferMTPFromCty(cty string) []string {
	candidates := mtpsForCty(cty)

	return intersect(handler.supportedMTPs, candidates)
}

func mtpsForCty(cty string) []string {
	switch cty {
	case transport.MediaTypeAIP2RFC0019Profile, transport.MediaTypeProfileDIDCommAIP1,
		transport.MediaTypeRFC0019EncryptedEnvelope:
		return []string{
			transport.MediaTypeAIP2RFC0019Profile,
			transport.MediaTypeProfileDIDCommAIP1,
			transport.MediaTypeRFC0019EncryptedEnvelope,
		}
	case transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeV2PlaintextPayload,
		transport.MediaTypeAIP2RFC0587Profile, transport.MediaTypeDIDCommV2Profile:
		return []string{
			transport.MediaTypeV2EncryptedEnvelope,
			transport.MediaTypeV2PlaintextPayload,
			transport.MediaTypeAIP2RFC0587Profile,
			transport.MediaTypeDIDCommV2Profile,
		}
	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV1PlaintextPayload:
		return []string{
			transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
			transport.MediaTypeV1PlaintextPayload,
		}
	default:
		return nil
	}
}

func list2set(list []string) map[string]struct{} {
	set := map[string]struct{}{}

	for _, e := range list {
		set[e] = struct{}{}
	}

	return set
}

// intersect returns the intersection of two lists of strings, in the order of list1.
func intersect(list1, list2 []string) []string {
	set := list2set(list2)

	var out []string

	for _, s := range list1 {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}

	return out
}
