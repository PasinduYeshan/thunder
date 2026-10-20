// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package defaultprovider

import (
	"context"

	"github.com/thunder-id/thunderid/internal/system/security"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// handleAuthenticationFailure answers a failed proof. A failure attributed to an identity is submitted
// to governance. Where a lock limits guessing the method, governance refuses a held identity as it
// would a verified proof and counts nothing; otherwise the failure is counted where it applies and the
// original error returned.
func (p *defaultAuthnProvider) handleAuthenticationFailure(ctx context.Context,
	method providers.AuthenticationMethod, failure *attributedFailure,
	svcErr *tidcommon.ServiceError) *tidcommon.ServiceError {
	if p.governance == nil || failure == nil {
		return svcErr
	}
	if !isAttributableAuthenticationError(svcErr) {
		// A server fault, an invalid request or an unknown subject is not a failed proof, whatever
		// evidence accompanied it.
		return svcErr
	}

	entityID := p.resolveFailedSubject(ctx, failure)
	if entityID == "" {
		return svcErr
	}

	// A failed counter write leaves the attempt uncounted and admitted; a failed read refuses as it does
	// for a verified proof.
	decision, govErr := p.governance.RecordFailure(security.WithRuntimeContext(ctx), entityID,
		proofPlane(ctx), method)
	if refused := accessRefusal(decision, govErr); refused != nil {
		return refused
	}
	return svcErr
}

// resolveFailedSubject turns failure evidence into the identity to count against.
func (p *defaultAuthnProvider) resolveFailedSubject(ctx context.Context,
	failure *attributedFailure) string {
	if failure.entityID != "" {
		return failure.entityID
	}
	if failure.recipient == nil {
		return ""
	}

	entityID, err := p.entityIDFromToken(ctx, failure.recipient)
	if err != nil {
		p.logger.Debug(ctx, "Not counting an authentication failure: its subject did not resolve")
		return ""
	}
	return entityID
}

// checkAuthenticationAccess submits a verified identity to governance.
func (p *defaultAuthnProvider) checkAuthenticationAccess(ctx context.Context,
	method providers.AuthenticationMethod, result *providers.AuthnResult) *tidcommon.ServiceError {
	if p.governance == nil {
		return nil
	}
	if result.EntityReference == nil || result.EntityReference.EntityID == "" {
		return nil
	}
	entityID := result.EntityReference.EntityID

	// A recovery flow's proof is admitted at the recovery plane, where governance decides which locks
	// give way to it.
	authorityCtx := security.WithRuntimeContext(ctx)
	var decision providers.AccessDecision
	var svcErr *tidcommon.ServiceError
	if proofPlane(ctx) == providers.AccessPlaneRecovery {
		decision, svcErr = p.governance.EvaluateAccess(authorityCtx, entityID, providers.AccessPlaneRecovery, method)
	} else {
		decision, svcErr = p.governance.AdmitAuthenticationStep(authorityCtx, entityID, method)
	}
	return accessRefusal(decision, svcErr)
}
