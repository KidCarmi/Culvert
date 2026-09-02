package mcperr

import (
	"errors"
	"strings"
	"testing"
)

func TestReasonCodesStable(t *testing.T) {
	// The machine strings are a contract; pin every one. Structured as a slice of
	// pairs (not a map literal) so it does not read as a duplicate of the source
	// reasonCode map to the dupl linter, while still asserting the full set.
	type pair struct {
		r    Reason
		code string
	}
	want := []pair{
		{ReasonNone, "none"}, {ReasonMalformedJSON, "malformed_json"},
		{ReasonInvalidJSONRPC, "invalid_jsonrpc"}, {ReasonUnsupportedBatch, "unsupported_batch"},
		{ReasonUnsupportedVersion, "unsupported_version"}, {ReasonUnsupportedMethod, "unsupported_method"},
		{ReasonResourceLimit, "resource_limit"}, {ReasonInvalidLifecycle, "invalid_lifecycle"},
		{ReasonUncorrelatedResponse, "uncorrelated_response"}, {ReasonDuplicateCompletion, "duplicate_completion"},
		{ReasonInvalidCancellation, "invalid_cancellation"}, {ReasonLateCancellation, "late_cancellation"},
		{ReasonInvalidRegistration, "invalid_registration"}, {ReasonUnregisteredServer, "unregistered_server"},
		{ReasonServerIdentityMismatch, "server_identity_mismatch"}, {ReasonMalformedDiscovery, "malformed_discovery"},
		{ReasonDuplicateTool, "duplicate_tool"}, {ReasonCanonicalizationFailed, "canonicalization_failed"},
		{ReasonCapacityExceeded, "capacity_exceeded"}, {ReasonUnknownTool, "unknown_tool"},
		{ReasonPrivilegeExpansion, "privilege_expansion"}, {ReasonSemanticDrift, "semantic_drift"},
		{ReasonStaleSnapshot, "stale_snapshot"},
		{ReasonCredentialMissing, "credential_missing"}, {ReasonCredentialInQuery, "credential_in_query"},
		{ReasonMalformedToken, "malformed_token"}, {ReasonUnsupportedTokenType, "unsupported_token_type"},
		{ReasonUnsupportedAlgorithm, "unsupported_algorithm"}, {ReasonSignatureInvalid, "signature_invalid"},
		{ReasonIssuerRejected, "issuer_rejected"}, {ReasonAudienceMissing, "audience_missing"},
		{ReasonAudienceRejected, "audience_rejected"}, {ReasonResourceMismatch, "resource_mismatch"},
		{ReasonTokenExpired, "token_expired"}, {ReasonTokenNotYetValid, "token_not_yet_valid"},
		{ReasonTokenTTLExceeded, "token_ttl_exceeded"}, {ReasonScopeMissing, "scope_missing"},
		{ReasonCapabilityMismatch, "capability_mismatch"}, {ReasonTenantMismatch, "tenant_mismatch"},
		{ReasonDelegationChainInvalid, "delegation_chain_invalid"}, {ReasonSenderConstraintRequired, "sender_constraint_required"},
		{ReasonDPoPMalformed, "dpop_malformed"}, {ReasonDPoPBindingMismatch, "dpop_binding_mismatch"},
		{ReasonDPoPReplay, "dpop_replay"}, {ReasonDPoPNonce, "dpop_nonce"},
		{ReasonMTLSBindingMismatch, "mtls_binding_mismatch"}, {ReasonInactiveToken, "inactive_token"},
		{ReasonSessionIdentityBound, "session_identity_bound"}, {ReasonSessionIdentityRebind, "session_identity_rebind"},
		{ReasonRegistryServerUnavailable, "registry_server_unavailable"},
		{ReasonCredentialProfileMissing, "credential_profile_missing"}, {ReasonCredentialProfileDisabled, "credential_profile_disabled"},
		{ReasonCredentialProfileAmbiguous, "credential_profile_ambiguous"}, {ReasonProviderUnavailable, "provider_unavailable"},
		{ReasonProviderUnsupportedOperation, "provider_unsupported_operation"}, {ReasonProviderInvalidMaterial, "provider_invalid_material"},
		{ReasonCredentialScopeMismatch, "credential_scope_mismatch"}, {ReasonCredentialPowerExceeded, "credential_power_exceeded"},
		{ReasonCredentialExpired, "credential_expired"}, {ReasonCredentialRevoked, "credential_revoked"},
		{ReasonCredentialVersionStale, "credential_version_stale"}, {ReasonCacheMiss, "cache_miss"},
		{ReasonCacheFull, "cache_full"}, {ReasonCacheIntegrityFailure, "cache_integrity_failure"},
		{ReasonRotationInProgress, "rotation_in_progress"}, {ReasonRotationFailed, "rotation_failed"},
		{ReasonRevocationFailed, "revocation_failed"}, {ReasonMaterializationGateDenied, "materialization_gate_denied"},
		{ReasonMaterializationGateUnavailable, "materialization_gate_unavailable"}, {ReasonMaterialAlreadyConsumed, "material_already_consumed"},
		{ReasonCredentialKindUnsupported, "credential_kind_unsupported"},
		{ReasonListenerDisabled, "listener_disabled"}, {ReasonHTTPMethodRejected, "http_method_rejected"},
		{ReasonHostRejected, "host_rejected"}, {ReasonOriginRejected, "origin_rejected"},
		{ReasonAdmissionRejected, "admission_rejected"}, {ReasonObserveOnly, "observe_only"},
		{ReasonTLSRequired, "tls_required"}, {ReasonListenerConfigInvalid, "listener_config_invalid"},
		{ReasonRequestDeadlineExceeded, "request_deadline_exceeded"},
		{ReasonPolicySnapshotInvalid, "policy_snapshot_invalid"}, {ReasonPolicyRuleInvalid, "policy_rule_invalid"},
		{ReasonPolicyConditionInvalid, "policy_condition_invalid"}, {ReasonPolicyObligationInvalid, "policy_obligation_invalid"},
		{ReasonPolicyInputInvalid, "policy_input_invalid"}, {ReasonPolicyNamespaceMismatch, "policy_namespace_mismatch"},
		{ReasonPolicyStaleRevision, "policy_stale_revision"}, {ReasonPolicyLimitExceeded, "policy_limit_exceeded"},
		// PR-7 inspection reasons.
		{ReasonSchemaInvalid, "schema_invalid"}, {ReasonSchemaUnsupported, "schema_unsupported"},
		{ReasonSchemaLimitExceeded, "schema_limit_exceeded"}, {ReasonOutputTooLarge, "output_too_large"},
		{ReasonOutputSchemaInvalid, "output_schema_invalid"}, {ReasonSecretDetected, "secret_detected"},
		{ReasonPIIDetected, "pii_detected"}, {ReasonRedactionFailed, "redaction_failed"},
		{ReasonDestinationMalformed, "destination_malformed"}, {ReasonDestinationSchemeRejected, "destination_scheme_rejected"},
		{ReasonSSRFBlocked, "ssrf_blocked"}, {ReasonDNSResolutionFailed, "dns_resolution_failed"},
		{ReasonDNSAnswerMixed, "dns_answer_mixed"}, {ReasonDNSPinMismatch, "dns_pin_mismatch"},
		{ReasonRedirectRejected, "redirect_rejected"}, {ReasonRedirectLimitExceeded, "redirect_limit_exceeded"},
		{ReasonInjectionSuspected, "injection_suspected"}, {ReasonInspectionUnavailable, "inspection_unavailable"},
		{ReasonInspectionLimitExceeded, "inspection_limit_exceeded"},
		// PR-8 durable decision-event reasons.
		{ReasonEventInvalid, "event_invalid"}, {ReasonEventSchemaVersion, "event_schema_version"},
		{ReasonEventPartitionMismatch, "event_partition_mismatch"}, {ReasonEventTenantConflict, "event_tenant_conflict"},
		{ReasonEventSecretPresent, "event_secret_present"}, {ReasonEventEvidenceMissing, "event_evidence_missing"},
		{ReasonEventTooLarge, "event_too_large"}, {ReasonEventCorrelationMalformed, "event_correlation_malformed"},
		{ReasonEventReplayConflict, "event_replay_conflict"}, {ReasonEventQueueSaturated, "event_queue_saturated"},
		{ReasonEventCommitFailed, "event_commit_failed"}, {ReasonEventEncryptionUnavailable, "event_encryption_unavailable"},
		{ReasonEventEncryptionFailed, "event_encryption_failed"}, {ReasonEventStorageFull, "event_storage_full"},
		{ReasonEventSpoolCorrupt, "event_spool_corrupt"}, {ReasonEventDurabilityDegraded, "event_durability_degraded"},
		{ReasonEventDenialLaneDegraded, "event_denial_lane_degraded"}, {ReasonEventReceiptInvalid, "event_receipt_invalid"},
		{ReasonEventExportUnauthorized, "event_export_unauthorized"}, {ReasonEventExportRangeExceeded, "event_export_range_exceeded"},
		// PR-9 admin API / Management MCP / approval / publication reasons.
		{ReasonAdminRequestInvalid, "admin_request_invalid"}, {ReasonAdminRangeExceeded, "admin_range_exceeded"},
		{ReasonAdminUnknownField, "admin_unknown_field"}, {ReasonAdminNotFound, "admin_not_found"},
		{ReasonAdminForbidden, "admin_forbidden"}, {ReasonAdminTenantScope, "admin_tenant_scope"},
		{ReasonApprovalNotFound, "approval_not_found"}, {ReasonApprovalSelfApproval, "approval_self_approval"},
		{ReasonApprovalExpired, "approval_expired"}, {ReasonApprovalStaleRevision, "approval_stale_revision"},
		{ReasonApprovalTerminalState, "approval_terminal_state"}, {ReasonApprovalBindingMismatch, "approval_binding_mismatch"},
		{ReasonPublicationValidationFailed, "publication_validation_failed"}, {ReasonPublicationStaleBase, "publication_stale_base"},
		{ReasonPublicationNotApproved, "publication_not_approved"}, {ReasonPublicationDurabilityRequired, "publication_durability_required"},
		{ReasonManagementToolUnknown, "management_tool_unknown"}, {ReasonManagementToolUnauthorized, "management_tool_unauthorized"},
		{ReasonManagementResultTooLarge, "management_result_too_large"},
		{ReasonConfigInvalid, "config_invalid"}, {ReasonConfigApplyFailed, "config_apply_failed"},
		// PR-10 signed CP→DP snapshot / fencing / rollback reasons.
		{ReasonSnapshotMalformed, "snapshot_malformed"}, {ReasonSnapshotSchemaUnknown, "snapshot_schema_unknown"},
		{ReasonSnapshotCapabilityMismatch, "snapshot_capability_mismatch"}, {ReasonSnapshotAlgUnknown, "snapshot_alg_unknown"},
		{ReasonSnapshotKeyUntrusted, "snapshot_key_untrusted"}, {ReasonSnapshotHashMismatch, "snapshot_hash_mismatch"},
		{ReasonSnapshotSignatureInvalid, "snapshot_signature_invalid"}, {ReasonSnapshotTooLarge, "snapshot_too_large"},
		{ReasonSnapshotRevisionInvalid, "snapshot_revision_invalid"}, {ReasonSnapshotRevisionRegression, "snapshot_revision_regression"},
		{ReasonSnapshotEpochStale, "snapshot_epoch_stale"}, {ReasonSnapshotEpochInvalid, "snapshot_epoch_invalid"},
		{ReasonSnapshotMinVersionUnmet, "snapshot_min_version_unmet"}, {ReasonSnapshotMinVersionMalformed, "snapshot_min_version_malformed"},
		{ReasonSnapshotValidationFailed, "snapshot_validation_failed"}, {ReasonSnapshotPersistFailed, "snapshot_persist_failed"},
		{ReasonSnapshotSignerUnavailable, "snapshot_signer_unavailable"}, {ReasonDistributionWriteAuthority, "distribution_write_authority"},
		{ReasonAckInvalid, "ack_invalid"}, {ReasonAckUnauthenticated, "ack_unauthenticated"},
		{ReasonRollbackTargetMissing, "rollback_target_missing"}, {ReasonRollbackTargetCorrupt, "rollback_target_corrupt"},
		{ReasonRollbackDirectiveInvalid, "rollback_directive_invalid"},
		// PR-11 — guarded execution, shadow/canary rollout, upstream client
		{ReasonRolloutModeInvalid, "rollout_mode_invalid"},
		{ReasonRolloutTransitionInvalid, "rollout_transition_invalid"},
		{ReasonRolloutProductionLocked, "rollout_production_locked"},
		{ReasonRolloutQualificationInvalid, "rollout_qualification_invalid"},
		{ReasonRolloutScopeInvalid, "rollout_scope_invalid"},
		{ReasonRolloutScopeStaleBase, "rollout_scope_stale_base"},
		{ReasonRolloutConnectorModeRejected, "rollout_connector_mode_rejected"},
		{ReasonRolloutEvidenceInsufficient, "rollout_evidence_insufficient"},
		{ReasonRolloutEmergencyActive, "rollout_emergency_active"},
		{ReasonRolloutOutOfScope, "rollout_out_of_scope"},
		{ReasonExecutionNotPermitted, "execution_not_permitted"},
		{ReasonConfirmationRequired, "confirmation_required"},
		{ReasonApprovalRequired, "approval_required"},
		{ReasonObligationReceiptInvalid, "obligation_receipt_invalid"},
		{ReasonAllowanceConsumed, "allowance_consumed"},
		{ReasonAllowanceInvalid, "allowance_invalid"},
		{ReasonUpstreamEndpointInvalid, "upstream_endpoint_invalid"},
		{ReasonUpstreamServerUnusable, "upstream_server_unusable"},
		{ReasonUpstreamVersionUnsupported, "upstream_version_unsupported"},
		{ReasonUpstreamTransportRejected, "upstream_transport_rejected"},
		{ReasonUpstreamResponseInvalid, "upstream_response_invalid"},
		{ReasonUpstreamResponseTooLarge, "upstream_response_too_large"},
		{ReasonUpstreamConnectFailed, "upstream_connect_failed"},
		{ReasonUpstreamTLSIdentity, "upstream_tls_identity"},
		{ReasonUpstreamTimeout, "upstream_timeout"},
		{ReasonUpstreamPoolExhausted, "upstream_pool_exhausted"},
		{ReasonUpstreamCancelled, "upstream_cancelled"},
		{ReasonUpstreamRetryDenied, "upstream_retry_denied"},
		{ReasonUpstreamCallFailed, "upstream_call_failed"},
		{ReasonUpstreamDiscoveryFailed, "upstream_discovery_failed"},
		{ReasonAmbiguousRequestHeader, "ambiguous_request_header"},
		{ReasonDecisionSnapshotStale, "decision_snapshot_stale"},
		{ReasonToolNotApprovable, "tool_not_approvable"},
		{ReasonToolApprovalStale, "tool_approval_stale"},
		{ReasonToolFingerprintMismatch, "tool_fingerprint_mismatch"},
		{ReasonServerNotUsable, "server_not_usable"},
		{ReasonToolNotFound, "tool_not_found"},
		{ReasonApprovalRevoked, "approval_revoked"},
		{ReasonApprovalTenantConflict, "approval_tenant_conflict"},
		{ReasonApprovalPurposeUnsupported, "approval_purpose_unsupported"},
		{ReasonApprovalNotAuthorized, "approval_not_authorized"},
		{ReasonApprovalStoreUnavailable, "approval_store_unavailable"},
		{ReasonRolloutBudgetExhausted, "rollout_budget_exhausted"},
		{ReasonLiveTrustRevalidationFailed, "live_trust_revalidation_failed"},
	}
	seen := map[Reason]bool{}
	for _, p := range want {
		if p.r.Code() != p.code {
			t.Fatalf("Reason(%d).Code() = %q, want %q", p.r, p.r.Code(), p.code)
		}
		seen[p.r] = true
	}
	// Exhaustiveness: every reason in the source map is pinned above.
	for r := range reasonCode {
		if !seen[r] {
			t.Fatalf("reason %d (%q) is not pinned by the stability test", r, r.Code())
		}
	}
}

func TestReasonOfAndIs(t *testing.T) {
	base := New(ReasonResourceLimit, "decode", "too big")
	wrapped := Wrap(ReasonMalformedJSON, "decode", "bad", base)
	if ReasonOf(wrapped) != ReasonMalformedJSON {
		t.Fatalf("ReasonOf outer = %v", ReasonOf(wrapped))
	}
	if !errors.Is(wrapped, base) {
		t.Fatal("errors.Is should match the wrapped cause")
	}
	if ReasonOf(errors.New("plain")) != ReasonNone {
		t.Fatal("plain error reason should be None")
	}
	// Is matches by reason.
	other := New(ReasonResourceLimit, "", "")
	if !errors.Is(base, other) {
		t.Fatal("same-reason errors should match via Is")
	}
}

func TestSanitizeStripsHostileBytes(t *testing.T) {
	in := "ok\x00\n\"\\\x7f" + strings.Repeat("A", 200)
	out := Sanitize(in, 32)
	if strings.ContainsAny(out, "\x00\n\"\\") || strings.Contains(out, "\x7f") {
		t.Fatalf("Sanitize left hostile bytes: %q", out)
	}
	if len(out) > 33 { // 32 + truncation marker
		t.Fatalf("Sanitize did not bound length: %d", len(out))
	}
	if !strings.HasPrefix(out, "ok") {
		t.Fatalf("Sanitize mangled safe prefix: %q", out)
	}
}

func TestErrorMessageHasNoRawInput(t *testing.T) {
	// The Error() text is a fixed shape; detail is developer-authored.
	e := New(ReasonMalformedJSON, "decode", "invalid UTF-8")
	if got := e.Error(); got != "mcp: decode: malformed_json: invalid UTF-8" {
		t.Fatalf("Error() = %q", got)
	}
}
