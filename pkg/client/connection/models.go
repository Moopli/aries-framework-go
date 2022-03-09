/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

// QueryParams holds parameters for connection record queries.
type QueryParams struct {
	ConnectionID   string `json:"connection_id,omitempty"`
	ParentThreadID string `json:"parent_thread_id,omitempty"`
	TheirLabel     string `json:"their_label,omitempty"`
	TheirDID       string `json:"their_did,omitempty"`
	MyDID          string `json:"my_did,omitempty"`
	InvitationID   string `json:"invitation_id,omitempty"`
}
