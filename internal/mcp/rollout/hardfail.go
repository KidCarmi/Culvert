package rollout

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// HardClass is the fixed hard-failure taxonomy. A hard failure ALWAYS blocks in
// Shadow, Canary, and Production alike — it is never policy-overridable and never
// downgraded to MONITOR/ALLOW by any rollout mode. The seven security classes
// mandated by ROLLOUT-AND-ROLLBACK.md §2 are joined by HardInspectionPrivacy,
// which carries the PR-7 inspection/DLP hard blocks the spec requires be
// preserved ("Also preserve every hard inspection block from PR-7").
type HardClass uint8

const (
	// HardNone means the reason is NOT a fixed hard failure. It may still deny a
	// request (an ordinary policy DENY, an obligation gate, an operational error, or
	// a control-plane rejection), but a rollout mode may treat it per mode semantics
	// (e.g. Shadow records-and-allows an ordinary policy DENY).
	HardNone HardClass = iota
	// HardAuthIdentity — authentication + sender identity: invalid/expired token,
	// wrong audience/resource, invalid sender constraint, replay, tenant mismatch,
	// identity-session rebind.
	HardAuthIdentity
	// HardServerTrust — server trust: unregistered/disabled server, failed/changed
	// TLS/workload identity, endpoint no longer matching its registered identity.
	HardServerTrust
	// HardCredentialSafety — credential safety: scope mismatch, power exceeds plan,
	// expired/revoked profile, broker/provider failure under a fail-closed profile.
	HardCredentialSafety
	// HardAvailabilityBounds — availability bounds: protocol/body/depth/string limits,
	// queue/admission exhaustion, upstream response limit, redirect/timeout budget.
	HardAvailabilityBounds
	// HardDestinationSafety — destination safety: private/loopback/metadata/reserved
	// destination, DNS rebinding, connect-peer mismatch, forbidden redirect, scheme
	// downgrade; plus inbound Host/Origin rebinding.
	HardDestinationSafety
	// HardToolTrust — tool trust: unknown tool, unapproved fingerprint, privilege
	// expansion, identity/schema drift requiring quarantine.
	HardToolTrust
	// HardManagementSafety — Management safety: any Management mutation/command/secret
	// export/approval/config/publish/rollback mutation through Management MCP.
	HardManagementSafety
	// HardInspectionPrivacy — PR-7 inspection/DLP hard blocks: secret/PII detected,
	// schema invalid/unsupported/over-limit, output too large/invalid, injection,
	// redaction failed, inspection unavailable, or a durable-event secret backstop.
	HardInspectionPrivacy
)

var hardClassToken = map[HardClass]string{
	HardNone:               "none",
	HardAuthIdentity:       "auth_identity",
	HardServerTrust:        "server_trust",
	HardCredentialSafety:   "credential_safety",
	HardAvailabilityBounds: "availability_bounds",
	HardDestinationSafety:  "destination_safety",
	HardToolTrust:          "tool_trust",
	HardManagementSafety:   "management_safety",
	HardInspectionPrivacy:  "inspection_privacy",
}

// String returns the stable token for the class.
func (h HardClass) String() string {
	if s, ok := hardClassToken[h]; ok {
		return s
	}
	return "unknown"
}

// hardClass is the authoritative map from a hard-failure mcperr.Reason to its
// class. A reason present here ALWAYS blocks in every rollout mode. A reason not
// present is not a fixed hard failure (see explicitlyNotHard for the deliberate
// non-hard classification). config_hardfail_test.go pins that every mapped
// mcperr.Reason appears in exactly one of these two tables — so a new security
// reason cannot be introduced without an explicit mode classification.
var hardClass = map[mcperr.Reason]HardClass{
	// ── PR-1 protocol kernel — parse/limit/lifecycle rejections (availability) ──
	mcperr.ReasonMalformedJSON:        HardAvailabilityBounds,
	mcperr.ReasonInvalidJSONRPC:       HardAvailabilityBounds,
	mcperr.ReasonUnsupportedBatch:     HardAvailabilityBounds,
	mcperr.ReasonUnsupportedVersion:   HardAvailabilityBounds,
	mcperr.ReasonUnsupportedMethod:    HardAvailabilityBounds,
	mcperr.ReasonResourceLimit:        HardAvailabilityBounds,
	mcperr.ReasonInvalidLifecycle:     HardAvailabilityBounds,
	mcperr.ReasonUncorrelatedResponse: HardAvailabilityBounds,
	mcperr.ReasonDuplicateCompletion:  HardAvailabilityBounds,

	// ── PR-2 registry & catalog — server + tool trust ──
	mcperr.ReasonInvalidRegistration:    HardServerTrust,
	mcperr.ReasonUnregisteredServer:     HardServerTrust,
	mcperr.ReasonServerIdentityMismatch: HardServerTrust,
	mcperr.ReasonMalformedDiscovery:     HardToolTrust,
	mcperr.ReasonDuplicateTool:          HardToolTrust,
	mcperr.ReasonCanonicalizationFailed: HardToolTrust,
	mcperr.ReasonCapacityExceeded:       HardAvailabilityBounds,
	mcperr.ReasonUnknownTool:            HardToolTrust,
	mcperr.ReasonPrivilegeExpansion:     HardToolTrust,
	mcperr.ReasonSemanticDrift:          HardToolTrust,

	// ── PR-3 identity / token / sender constraint — auth identity ──
	mcperr.ReasonCredentialMissing:         HardAuthIdentity,
	mcperr.ReasonCredentialInQuery:         HardAuthIdentity,
	mcperr.ReasonMalformedToken:            HardAuthIdentity,
	mcperr.ReasonUnsupportedTokenType:      HardAuthIdentity,
	mcperr.ReasonUnsupportedAlgorithm:      HardAuthIdentity,
	mcperr.ReasonSignatureInvalid:          HardAuthIdentity,
	mcperr.ReasonIssuerRejected:            HardAuthIdentity,
	mcperr.ReasonAudienceMissing:           HardAuthIdentity,
	mcperr.ReasonAudienceRejected:          HardAuthIdentity,
	mcperr.ReasonResourceMismatch:          HardAuthIdentity,
	mcperr.ReasonTokenExpired:              HardAuthIdentity,
	mcperr.ReasonTokenNotYetValid:          HardAuthIdentity,
	mcperr.ReasonTokenTTLExceeded:          HardAuthIdentity,
	mcperr.ReasonScopeMissing:              HardAuthIdentity,
	mcperr.ReasonCapabilityMismatch:        HardAuthIdentity,
	mcperr.ReasonTenantMismatch:            HardAuthIdentity,
	mcperr.ReasonDelegationChainInvalid:    HardAuthIdentity,
	mcperr.ReasonSenderConstraintRequired:  HardAuthIdentity,
	mcperr.ReasonDPoPMalformed:             HardAuthIdentity,
	mcperr.ReasonDPoPBindingMismatch:       HardAuthIdentity,
	mcperr.ReasonDPoPReplay:                HardAuthIdentity,
	mcperr.ReasonDPoPNonce:                 HardAuthIdentity,
	mcperr.ReasonMTLSBindingMismatch:       HardAuthIdentity,
	mcperr.ReasonInactiveToken:             HardAuthIdentity,
	mcperr.ReasonSessionIdentityBound:      HardAuthIdentity,
	mcperr.ReasonSessionIdentityRebind:     HardAuthIdentity,
	mcperr.ReasonRegistryServerUnavailable: HardServerTrust,

	// ── PR-4 credential broker — credential safety ──
	mcperr.ReasonCredentialProfileMissing:       HardCredentialSafety,
	mcperr.ReasonCredentialProfileDisabled:      HardCredentialSafety,
	mcperr.ReasonCredentialProfileAmbiguous:     HardCredentialSafety,
	mcperr.ReasonProviderUnavailable:            HardCredentialSafety,
	mcperr.ReasonProviderUnsupportedOperation:   HardCredentialSafety,
	mcperr.ReasonProviderInvalidMaterial:        HardCredentialSafety,
	mcperr.ReasonCredentialScopeMismatch:        HardCredentialSafety,
	mcperr.ReasonCredentialPowerExceeded:        HardCredentialSafety,
	mcperr.ReasonCredentialExpired:              HardCredentialSafety,
	mcperr.ReasonCredentialRevoked:              HardCredentialSafety,
	mcperr.ReasonCredentialVersionStale:         HardCredentialSafety,
	mcperr.ReasonCacheFull:                      HardAvailabilityBounds,
	mcperr.ReasonCacheIntegrityFailure:          HardCredentialSafety,
	mcperr.ReasonRotationFailed:                 HardCredentialSafety,
	mcperr.ReasonRevocationFailed:               HardCredentialSafety,
	mcperr.ReasonMaterializationGateDenied:      HardCredentialSafety,
	mcperr.ReasonMaterializationGateUnavailable: HardCredentialSafety,
	mcperr.ReasonMaterialAlreadyConsumed:        HardCredentialSafety,
	mcperr.ReasonCredentialKindUnsupported:      HardCredentialSafety,

	// ── PR-5 runtime/listener — availability + inbound host/origin ──
	mcperr.ReasonHTTPMethodRejected:      HardAvailabilityBounds,
	mcperr.ReasonHostRejected:            HardDestinationSafety,
	mcperr.ReasonOriginRejected:          HardDestinationSafety,
	mcperr.ReasonAdmissionRejected:       HardAvailabilityBounds,
	mcperr.ReasonTLSRequired:             HardAuthIdentity,
	mcperr.ReasonRequestDeadlineExceeded: HardAvailabilityBounds,

	// ── PR-7 inspection — destination safety + inspection/privacy ──
	mcperr.ReasonSchemaInvalid:             HardInspectionPrivacy,
	mcperr.ReasonSchemaUnsupported:         HardInspectionPrivacy,
	mcperr.ReasonSchemaLimitExceeded:       HardInspectionPrivacy,
	mcperr.ReasonOutputTooLarge:            HardInspectionPrivacy,
	mcperr.ReasonOutputSchemaInvalid:       HardInspectionPrivacy,
	mcperr.ReasonSecretDetected:            HardInspectionPrivacy,
	mcperr.ReasonPIIDetected:               HardInspectionPrivacy,
	mcperr.ReasonRedactionFailed:           HardInspectionPrivacy,
	mcperr.ReasonDestinationMalformed:      HardDestinationSafety,
	mcperr.ReasonDestinationSchemeRejected: HardDestinationSafety,
	mcperr.ReasonSSRFBlocked:               HardDestinationSafety,
	mcperr.ReasonDNSResolutionFailed:       HardDestinationSafety,
	mcperr.ReasonDNSAnswerMixed:            HardDestinationSafety,
	mcperr.ReasonDNSPinMismatch:            HardDestinationSafety,
	mcperr.ReasonRedirectRejected:          HardDestinationSafety,
	mcperr.ReasonRedirectLimitExceeded:     HardDestinationSafety,
	mcperr.ReasonInjectionSuspected:        HardInspectionPrivacy,
	mcperr.ReasonInspectionUnavailable:     HardInspectionPrivacy,
	mcperr.ReasonInspectionLimitExceeded:   HardInspectionPrivacy,

	// ── PR-8 durable events — the secret backstop is a privacy hard block ──
	mcperr.ReasonEventSecretPresent: HardInspectionPrivacy,

	// ── PR-9 Management MCP — management safety + output bound ──
	mcperr.ReasonManagementToolUnknown:      HardManagementSafety,
	mcperr.ReasonManagementToolUnauthorized: HardManagementSafety,
	mcperr.ReasonManagementResultTooLarge:   HardAvailabilityBounds,

	// ── PR-11 upstream leg — server/destination/availability ──
	mcperr.ReasonUpstreamEndpointInvalid:    HardDestinationSafety,
	mcperr.ReasonUpstreamServerUnusable:     HardServerTrust,
	mcperr.ReasonUpstreamVersionUnsupported: HardServerTrust,
	mcperr.ReasonUpstreamTransportRejected:  HardAvailabilityBounds,
	mcperr.ReasonUpstreamResponseInvalid:    HardAvailabilityBounds,
	mcperr.ReasonUpstreamResponseTooLarge:   HardAvailabilityBounds,
	mcperr.ReasonUpstreamTLSIdentity:        HardServerTrust,
	mcperr.ReasonUpstreamTimeout:            HardAvailabilityBounds,
	mcperr.ReasonUpstreamPoolExhausted:      HardAvailabilityBounds,
}

// explicitlyNotHard is the deliberate non-hard classification: reasons that may
// deny a request but are NOT fixed hard failures (kernel cancellation
// tolerations, informational dispositions, config/control-plane rejections,
// obligation gates, durable-event infrastructure, and operational upstream
// failures). Listing them explicitly — rather than defaulting — is what lets the
// parity test fail when a NEW reason is added without a classification decision.
var explicitlyNotHard = map[mcperr.Reason]struct{}{
	mcperr.ReasonNone:                {},
	mcperr.ReasonInvalidCancellation: {},
	mcperr.ReasonLateCancellation:    {},
	mcperr.ReasonStaleSnapshot:       {},
	// credential transient/non-blocking
	mcperr.ReasonCacheMiss:          {},
	mcperr.ReasonRotationInProgress: {},
	// runtime informational / config
	mcperr.ReasonListenerDisabled:      {},
	mcperr.ReasonObserveOnly:           {},
	mcperr.ReasonListenerConfigInvalid: {},
	// policy-engine infrastructure (surfaced as fail-closed deny; not a named class)
	mcperr.ReasonPolicySnapshotInvalid:   {},
	mcperr.ReasonPolicyRuleInvalid:       {},
	mcperr.ReasonPolicyConditionInvalid:  {},
	mcperr.ReasonPolicyObligationInvalid: {},
	mcperr.ReasonPolicyInputInvalid:      {},
	mcperr.ReasonPolicyNamespaceMismatch: {},
	mcperr.ReasonPolicyStaleRevision:     {},
	mcperr.ReasonPolicyLimitExceeded:     {},
	// durable-event infrastructure (durability handled by the event manager)
	mcperr.ReasonEventInvalid:               {},
	mcperr.ReasonEventSchemaVersion:         {},
	mcperr.ReasonEventPartitionMismatch:     {},
	mcperr.ReasonEventTenantConflict:        {},
	mcperr.ReasonEventEvidenceMissing:       {},
	mcperr.ReasonEventTooLarge:              {},
	mcperr.ReasonEventCorrelationMalformed:  {},
	mcperr.ReasonEventReplayConflict:        {},
	mcperr.ReasonEventQueueSaturated:        {},
	mcperr.ReasonEventCommitFailed:          {},
	mcperr.ReasonEventEncryptionUnavailable: {},
	mcperr.ReasonEventEncryptionFailed:      {},
	mcperr.ReasonEventStorageFull:           {},
	mcperr.ReasonEventSpoolCorrupt:          {},
	mcperr.ReasonEventDurabilityDegraded:    {},
	mcperr.ReasonEventDenialLaneDegraded:    {},
	mcperr.ReasonEventReceiptInvalid:        {},
	mcperr.ReasonEventExportUnauthorized:    {},
	mcperr.ReasonEventExportRangeExceeded:   {},
	// admin API / approval / publication (control-plane, not runtime enforcement)
	mcperr.ReasonAdminRequestInvalid:           {},
	mcperr.ReasonAdminRangeExceeded:            {},
	mcperr.ReasonAdminUnknownField:             {},
	mcperr.ReasonAdminNotFound:                 {},
	mcperr.ReasonAdminForbidden:                {},
	mcperr.ReasonAdminTenantScope:              {},
	mcperr.ReasonApprovalNotFound:              {},
	mcperr.ReasonApprovalSelfApproval:          {},
	mcperr.ReasonApprovalExpired:               {},
	mcperr.ReasonApprovalStaleRevision:         {},
	mcperr.ReasonApprovalTerminalState:         {},
	mcperr.ReasonApprovalBindingMismatch:       {},
	mcperr.ReasonPublicationValidationFailed:   {},
	mcperr.ReasonPublicationStaleBase:          {},
	mcperr.ReasonPublicationNotApproved:        {},
	mcperr.ReasonPublicationDurabilityRequired: {},
	mcperr.ReasonConfigInvalid:                 {},
	mcperr.ReasonConfigApplyFailed:             {},
	// PR-10 snapshot / distribution (config-plane)
	mcperr.ReasonSnapshotMalformed:           {},
	mcperr.ReasonSnapshotSchemaUnknown:       {},
	mcperr.ReasonSnapshotCapabilityMismatch:  {},
	mcperr.ReasonSnapshotAlgUnknown:          {},
	mcperr.ReasonSnapshotKeyUntrusted:        {},
	mcperr.ReasonSnapshotHashMismatch:        {},
	mcperr.ReasonSnapshotSignatureInvalid:    {},
	mcperr.ReasonSnapshotTooLarge:            {},
	mcperr.ReasonSnapshotRevisionInvalid:     {},
	mcperr.ReasonSnapshotRevisionRegression:  {},
	mcperr.ReasonSnapshotEpochStale:          {},
	mcperr.ReasonSnapshotEpochInvalid:        {},
	mcperr.ReasonSnapshotMinVersionUnmet:     {},
	mcperr.ReasonSnapshotMinVersionMalformed: {},
	mcperr.ReasonSnapshotValidationFailed:    {},
	mcperr.ReasonSnapshotPersistFailed:       {},
	mcperr.ReasonSnapshotSignerUnavailable:   {},
	mcperr.ReasonDistributionWriteAuthority:  {},
	mcperr.ReasonAckInvalid:                  {},
	mcperr.ReasonAckUnauthenticated:          {},
	mcperr.ReasonRollbackTargetMissing:       {},
	mcperr.ReasonRollbackTargetCorrupt:       {},
	mcperr.ReasonRollbackDirectiveInvalid:    {},
	// PR-11 rollout control-plane + obligation gates + operational upstream
	mcperr.ReasonRolloutModeInvalid:           {},
	mcperr.ReasonRolloutTransitionInvalid:     {},
	mcperr.ReasonRolloutProductionLocked:      {},
	mcperr.ReasonRolloutQualificationInvalid:  {},
	mcperr.ReasonRolloutScopeInvalid:          {},
	mcperr.ReasonRolloutScopeStaleBase:        {},
	mcperr.ReasonRolloutConnectorModeRejected: {},
	mcperr.ReasonRolloutEvidenceInsufficient:  {},
	mcperr.ReasonRolloutEmergencyActive:       {},
	mcperr.ReasonRolloutOutOfScope:            {},
	mcperr.ReasonExecutionNotPermitted:        {},
	mcperr.ReasonConfirmationRequired:         {},
	mcperr.ReasonApprovalRequired:             {},
	mcperr.ReasonObligationReceiptInvalid:     {},
	mcperr.ReasonAllowanceConsumed:            {},
	mcperr.ReasonAllowanceInvalid:             {},
	mcperr.ReasonUpstreamConnectFailed:        {},
	mcperr.ReasonUpstreamCancelled:            {},
	mcperr.ReasonUpstreamRetryDenied:          {},
	mcperr.ReasonUpstreamCallFailed:           {},
	mcperr.ReasonUpstreamDiscoveryFailed:      {},
}

// Classify returns the hard-failure class for a reason, or HardNone if it is not a
// fixed hard failure. It is a pure lookup — no rollout mode can change its result.
func Classify(r mcperr.Reason) HardClass { return hardClass[r] }

// IsHardFailure reports whether the reason ALWAYS blocks regardless of mode.
func IsHardFailure(r mcperr.Reason) bool { return hardClass[r] != HardNone }

// classified reports whether a reason has an explicit classification (used by the
// parity test to prove no security reason is left unclassified).
func classified(r mcperr.Reason) bool {
	if _, ok := hardClass[r]; ok {
		return true
	}
	_, ok := explicitlyNotHard[r]
	return ok
}
