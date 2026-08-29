package canary

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

func fp(b byte) tooltrust.FingerprintDigest {
	var d tooltrust.FingerprintDigest
	for i := range d {
		d[i] = b
	}
	return d
}

func liveTarget() LiveTarget {
	return LiveTarget{
		Tenant: "t1", ServerID: "srv-canary", ToolName: "echo",
		Fingerprint: fp(0x11), FingerprintFormat: 1,
	}
}

// validLiveApproval is a well-formed live_execution approval that satisfies the first-Canary
// trust contract against liveTarget() at now.
func validLiveApproval(now time.Time) *tooltrust.ToolApproval {
	exp := now.Add(1 * time.Hour)
	return &tooltrust.ToolApproval{
		Tenant: "t1", ServerID: "srv-canary", ToolName: "echo",
		Fingerprint: fp(0x11), FingerprintFormatVersion: 1,
		Purpose:     tooltrust.PurposeLiveExecution,
		Status:      tooltrust.StatusActive,
		RequestedBy: "alice", ApprovedBy: "bob", // four-eyes
		ApprovedAt: now, ExpiresAt: &exp,
	}
}

func TestSatisfiesLiveExecution_ValidApprovalIsAccepted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if r := SatisfiesLiveExecution(validLiveApproval(now), liveTarget(), now); r != TrustOK {
		t.Fatalf("valid live_execution approval rejected: %s", r)
	}
}

// TestSatisfiesLiveExecution_ShadowApprovalNeverQualifies is the firewall's core invariant
// (§3): a shadow_evaluation approval — even one that is otherwise perfectly formed and
// targets the exact tool — can NEVER authorize a live execution.
func TestSatisfiesLiveExecution_ShadowApprovalNeverQualifies(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := validLiveApproval(now)
	a.Purpose = tooltrust.PurposeShadowEvaluation // the ONLY change
	if r := SatisfiesLiveExecution(a, liveTarget(), now); r != TrustNotLiveExecution {
		t.Fatalf("SECURITY: a shadow_evaluation approval must never satisfy live execution, got %q", r)
	}
	// And the disjointness is structural: no purpose permits both.
	if tooltrust.PurposeShadowEvaluation.PermitsLiveExecution() {
		t.Fatal("shadow_evaluation must not permit live execution")
	}
	if tooltrust.PurposeLiveExecution.PermitsShadowEvaluation() {
		t.Fatal("live_execution must not permit shadow evaluation")
	}
}

func TestSatisfiesLiveExecution_Rejections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name   string
		mutate func(*tooltrust.ToolApproval)
		want   TrustReason
	}{
		{"nil", func(a *tooltrust.ToolApproval) { *a = tooltrust.ToolApproval{}; a.Purpose = tooltrust.PurposeUnset }, TrustNotLiveExecution},
		{"not_active", func(a *tooltrust.ToolApproval) { a.Status = tooltrust.StatusRevoked }, TrustNotActive},
		{"no_four_eyes_same", func(a *tooltrust.ToolApproval) { a.ApprovedBy = a.RequestedBy }, TrustNoFourEyes},
		{"no_four_eyes_missing_approver", func(a *tooltrust.ToolApproval) { a.ApprovedBy = "" }, TrustNoFourEyes},
		{"no_four_eyes_missing_requester", func(a *tooltrust.ToolApproval) { a.RequestedBy = "" }, TrustNoFourEyes},
		{"no_expiry", func(a *tooltrust.ToolApproval) { a.ExpiresAt = nil }, TrustNoExpiry},
		{"expired", func(a *tooltrust.ToolApproval) { e := now.Add(-time.Minute); a.ExpiresAt = &e }, TrustExpired},
		{"ttl_too_long", func(a *tooltrust.ToolApproval) {
			e := a.ApprovedAt.Add(MaxInitialCanaryApprovalTTL + time.Hour)
			a.ExpiresAt = &e
		}, TrustTTLTooLong},
		{"approved_in_future", func(a *tooltrust.ToolApproval) {
			// A future approval instant with a future-relative, in-window expiry would pass the
			// TTL ceiling (window measured from the future ApprovedAt) but must be rejected: the
			// approval has not yet become live (Codex P2). ExpiresAt stays after now so it passes
			// the expiry check and actually reaches the ApprovedInFuture guard.
			a.ApprovedAt = now.Add(2 * time.Hour)
			e := a.ApprovedAt.Add(time.Hour) // 3h from now — unelapsed, so not caught as expired
			a.ExpiresAt = &e
		}, TrustApprovedInFuture},
		{"approved_zero", func(a *tooltrust.ToolApproval) {
			// A zero ApprovedAt is a malformed record: the window would be measured from the epoch
			// and trivially exceed the ceiling. Reject as in-future (the instant is not real).
			a.ApprovedAt = time.Time{}
		}, TrustApprovedInFuture},
		{"fingerprint_format", func(a *tooltrust.ToolApproval) { a.FingerprintFormatVersion = 2 }, TrustFingerprintFormat},
		{"fingerprint_mismatch", func(a *tooltrust.ToolApproval) { a.Fingerprint = fp(0x22) }, TrustTargetMismatch},
		{"server_mismatch", func(a *tooltrust.ToolApproval) { a.ServerID = "other" }, TrustTargetMismatch},
		{"tool_mismatch", func(a *tooltrust.ToolApproval) { a.ToolName = "other" }, TrustTargetMismatch},
		{"tenant_mismatch", func(a *tooltrust.ToolApproval) { a.Tenant = "other" }, TrustTargetMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validLiveApproval(now)
			tc.mutate(a)
			if r := SatisfiesLiveExecution(a, liveTarget(), now); r != tc.want {
				t.Fatalf("SatisfiesLiveExecution(%s) = %q, want %q", tc.name, r, tc.want)
			}
		})
	}
}

// TestSatisfiesLiveExecution_NilIsFailClosed pins the explicit nil path.
func TestSatisfiesLiveExecution_NilIsFailClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if r := SatisfiesLiveExecution(nil, liveTarget(), now); r != TrustNil {
		t.Fatalf("nil approval must fail closed with approval_nil, got %q", r)
	}
}
