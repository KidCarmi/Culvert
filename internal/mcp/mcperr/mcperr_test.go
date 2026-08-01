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
