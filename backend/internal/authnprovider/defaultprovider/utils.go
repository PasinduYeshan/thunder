// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package defaultprovider

import (
	"context"
	"slices"

	authncommon "github.com/thunder-id/thunderid/internal/authn/common"
	"github.com/thunder-id/thunderid/internal/authn/otp"
	"github.com/thunder-id/thunderid/internal/authn/passkey"
	authnprovidercm "github.com/thunder-id/thunderid/internal/authnprovider/common"
	"github.com/thunder-id/thunderid/internal/entity"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// credentialMethods lists the credential types that select their own authentication method, in
// dispatch precedence.
var credentialMethods = []credentialMethod{
	// An entity the flow already resolved (created here, or a link holder the user picked) is bound by ID
	// and admitted as a federated sign-in. The federated method carries no lock of its own, so only a
	// suspension or an account-wide lock refuses it.
	{authnprovidercm.CredentialTypeProvisionedEntityID, providers.AuthenticationMethodFederated},
	{authnprovidercm.CredentialTypePasskey, providers.AuthenticationMethodPasskey},
	{authnprovidercm.CredentialTypeOTP, providers.AuthenticationMethodOTP},
	{authnprovidercm.CredentialTypeFederated, providers.AuthenticationMethodFederated},
	{authnprovidercm.CredentialTypeMagicLink, providers.AuthenticationMethodMagicLink},
	{authnprovidercm.CredentialTypeOpenID4VP, providers.AuthenticationMethodOpenID4VP},
}

// selectAuthenticationMethod supplies both dispatch precedence and the authentication method governance checks.
func selectAuthenticationMethod(credentials map[string]interface{}) credentialMethod {
	if len(credentials) == 0 {
		return credentialMethod{}
	}
	for _, entry := range credentialMethods {
		if _, present := credentials[entry.credentialType]; present {
			return entry
		}
	}
	// A mixed map uses the lockable method; adding a machine credential must not bypass counting.
	for key := range credentials {
		if !slices.Contains(authnprovidercm.SystemCredentialTypes, key) {
			return credentialMethod{method: providers.AuthenticationMethodCredential}
		}
	}
	return credentialMethod{method: providers.AuthenticationMethodSystemCredential}
}

// withoutFailure adapts an authentication method that attributes nothing: passkey, federated,
// magic-link and verifiable-presentation failures name no entity, and a provisioned entity checks no
// secret.
func withoutFailure(result *authncommon.AuthnResult, svcErr *tidcommon.ServiceError) (
	*authncommon.AuthnResult, *attributedFailure, *tidcommon.ServiceError) {
	return result, nil, svcErr
}

// otpFailureOf turns a wrong one-time password into evidence naming the code's recipient. The
// recipient comes from the validated session, never the request, so a request cannot pick whose
// account is counted. A recipient naming nobody, or several entities, counts nothing.
func otpFailureOf(failure *otp.VerificationFailure) *attributedFailure {
	if failure == nil {
		return nil
	}
	return &attributedFailure{
		recipient: map[string]interface{}{failure.RecipientAttr: failure.Recipient},
	}
}

// credentialFailureOf carries the identity a credential comparison ran against, already resolved by
// the entity service, so the failure is never re-attributed from the request.
func credentialFailureOf(failure *entity.CredentialFailure) *attributedFailure {
	if failure == nil || failure.EntityID == "" {
		return nil
	}
	return &attributedFailure{entityID: failure.EntityID}
}

// isAttributableAuthenticationError reports whether the refusal is one a failed proof produces.
func isAttributableAuthenticationError(svcErr *tidcommon.ServiceError) bool {
	return svcErr != nil &&
		svcErr.Type == tidcommon.ClientErrorType &&
		svcErr.Code == authnprovidercm.ErrorCodeAuthenticationFailed
}

// accessRefusal maps a governance answer for a verified or failed proof to the authentication error,
// or nil when the identity is admitted. An unreadable authority refuses with the server error an
// unreadable entity gets here; the service has logged the cause.
func accessRefusal(decision providers.AccessDecision, svcErr *tidcommon.ServiceError) *tidcommon.ServiceError {
	if svcErr != nil {
		serverErr := tidcommon.InternalServerError
		return &serverErr
	}
	if !decision.Admitted {
		return refusal(decision)
	}
	return nil
}

// proofPlane returns the plane a verified or failed proof is submitted at: recovery inside a recovery
// flow, authentication otherwise.
func proofPlane(ctx context.Context) providers.AccessPlane {
	if authnprovidercm.IsRecoveryFlow(ctx) {
		return providers.AccessPlaneRecovery
	}
	return providers.AccessPlaneAuthentication
}

// refusal maps a governance decision to the authentication error contract. The reason picks the
// suspended or locked code; a refusal that names none gets the wrong-secret code. The messages are
// replaced by the manager when it normalizes the code.
func refusal(decision providers.AccessDecision) *tidcommon.ServiceError {
	switch decision.Reason {
	case providers.AccessRefusalReasonSuspended:
		return newClientError(authnprovidercm.ErrorCodeAccountSuspended,
			"Account suspended", "The account is suspended")
	case providers.AccessRefusalReasonLocked:
		return newClientError(authnprovidercm.ErrorCodeAccountLocked,
			"Account locked", "The account is locked")
	default:
		return newClientError(authnprovidercm.ErrorCodeAuthenticationFailed,
			"Authentication failed", "Invalid credentials provided")
	}
}

// passkeyEnrollmentRefusal keeps a stated suspension's code through the enrolment error mapping, or
// returns nil for any other error.
func passkeyEnrollmentRefusal(svcErr *tidcommon.ServiceError) *tidcommon.ServiceError {
	if svcErr.Code != passkey.ErrorAccountSuspended.Code {
		return nil
	}
	return refusal(providers.AccessDecision{Reason: providers.AccessRefusalReasonSuspended})
}
