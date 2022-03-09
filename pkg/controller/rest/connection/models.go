/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	client "github.com/hyperledger/aries-framework-go/pkg/client/connection"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// queryConnections model
//
// This is used for querying connections
//
// swagger:parameters queryConnections
type queryConnections struct { // nolint: unused,deadcode
	// Params for querying connections
	//
	// in: path
	// required: true
	client.QueryParams
}

// queryConnectionResponse model
//
// This is used for returning query connections results
//
// swagger:response queryConnectionResponse
type queryConnectionResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		Results []*service.ConnectionRecord `json:"results,omitempty"`
	}
}

// rotateDIDRequest model
//
// This is used for connection did rotation request
//
// swagger:parameters rotateDID
type rotateDIDRequest struct { // nolint: unused,deadcode
	// The ID of the connection record to rotate the DID of
	//
	// in: path
	// required: true
	ID string `json:"id"`
	// KID Key ID of the signing key in the connection's current DID, used to sign the DID rotation.
	KID string `json:"kid"`
	// NewDID DID that the given connection will rotate to.
	NewDID string `json:"new_did"`
	// CreatePeerDID flag that, when true, makes the DID rotation create a new peer DID, ignoring the NewDID parameter.
	CreatePeerDID bool `json:"create_peer_did"`
}

// rotateDIDResponse model
//
// response of rotate DID action
//
// swagger:response rotateDIDResponse
type rotateDIDResponse struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		NewDID string `json:"new_did"`
	}
}

// createConnectionRequest model
//
// Request to create a didcomm v2 connection
//
// swagger:parameters createConnectionV2
type createConnectionRequest struct { // nolint: unused,deadcode
	MyDID    string `json:"my_did"`
	TheirDID string `json:"their_did"`
}

// createConnectionV2Response model
//
// response of create didcomm v2 connection action
//
// swagger:response createConnectionV2Response
type createConnectionV2Response struct { // nolint: unused,deadcode
	// in: body
	Body struct {
		ID string `json:"id"`
	}
}
