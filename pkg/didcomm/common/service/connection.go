/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package service

// ConnectionRecord defines a didcomm connection between two agents.
type ConnectionRecord struct {
	ConnectionID        string
	ParentThreadID      string
	TheirLabel          string
	TheirDID            string
	MyDID               string
	InvitationID        string
	MediaTypeProfiles   []string
	DIDCommVersion      Version
	PeerDIDInitialState string
	MyDIDRotation       *DIDRotationRecord `json:"myDIDRotation,omitempty"`
}

// DIDRotationRecord holds information about a DID Rotation.
type DIDRotationRecord struct {
	OldDID    string `json:"oldDID,omitempty"`
	NewDID    string `json:"newDID,omitempty"`
	FromPrior string `json:"fromPrior,omitempty"`
}
