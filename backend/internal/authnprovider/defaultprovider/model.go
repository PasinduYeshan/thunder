// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package defaultprovider

import "github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

// attributedFailure identifies the subject of a verified proof mismatch.
type attributedFailure struct {
	// entityID is the subject the authentication method compared against. Preferred: it needs no
	// second lookup and is never re-derived from caller input.
	entityID string

	// recipient names the subject indirectly, for a method that holds an identifier, not an entity.
	// Read only when entityID is empty, and never built from a caller-supplied identifier.
	recipient map[string]interface{}
}

// credentialMethod pairs a credential type with the authentication method governance checks it
// under.
type credentialMethod struct {
	credentialType string
	method         providers.AuthenticationMethod
}
