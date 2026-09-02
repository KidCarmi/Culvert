package canary

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// MaxInitialCanaryApprovalTTL is the hard ceiling on how long a live_execution approval may
// remain valid for the FIRST Canary (§3). A live-execution grant is the authority to cause
// a real, irreversible upstream side effect, so it must be short-lived: it expires quickly
// and must be deliberately re-issued, so a stale approval can never silently re-authorize
// execution weeks later. A later phase may relax this under its own review.
//
// It is DEFINED AS tooltrust.MaxLiveExecutionApprovalTTL so the ISSUE path (tooltrust, which
// enforces the ceiling when a live approval is created/approved) and this CONSUMPTION path can
// never disagree about the ceiling — one authority, referenced from both sides.
const MaxInitialCanaryApprovalTTL = tooltrust.MaxLiveExecutionApprovalTTL

// TrustReason is a bounded classification for WHY a candidate live_execution approval does
// not satisfy the Canary trust requirement. Fixed vocabulary; never interpolated with
// runtime data (tenant/server/tool/actor text never appears in a reason).
type TrustReason string

// Trust rejection sub-reasons (fixed vocabulary; TrustOK is the empty admissible value).
const (
	TrustOK                TrustReason = ""
	TrustNil               TrustReason = "approval_nil"
	TrustNotLiveExecution  TrustReason = "approval_not_live_execution_purpose" // e.g. a shadow_evaluation approval
	TrustNotActive         TrustReason = "approval_not_active"
	TrustExpired           TrustReason = "approval_expired"
	TrustNoExpiry          TrustReason = "approval_missing_expiry"      // a live approval MUST carry an expiry
	TrustTTLTooLong        TrustReason = "approval_ttl_exceeds_ceiling" // expiry beyond MaxInitialCanaryApprovalTTL from approval
	TrustNoFourEyes        TrustReason = "approval_not_four_eyes"       // requester == approver, or either missing
	TrustTargetMismatch    TrustReason = "approval_target_mismatch"     // tenant/server/tool/fingerprint mismatch
	TrustFingerprintFormat TrustReason = "approval_fingerprint_format_mismatch"
	TrustApprovedInFuture  TrustReason = "approval_instant_in_future" // ApprovedAt zero or after now (malformed / clock-skew)
)

// LiveTarget is the exact current tool identity a live execution is about to act on. Every
// dimension comes from the authoritative current observation (registry + catalog), never
// from a request. A live_execution approval must bind to ALL of it.
type LiveTarget struct {
	Tenant            string
	ServerID          string
	ToolName          string
	Fingerprint       tooltrust.FingerprintDigest
	FingerprintFormat uint16
}

// SatisfiesLiveExecution reports whether a candidate ToolApproval authorizes a real upstream
// execution against the given current target, as of now, under the FIRST-Canary governance
// (§3). It is a PURE predicate (injected clock, no I/O) and fail-closed: it returns TrustOK
// only when every one of the following holds, else the first violated sub-reason.
//
//  1. purpose == live_execution (a shadow_evaluation approval NEVER qualifies — the firewall);
//  2. status == active;
//  3. binds the EXACT current target (tenant + server + tool + fingerprint + format — the
//     rug-pull invariant: any drift in the observed fingerprint invalidates the approval);
//  4. carries an expiry, not yet elapsed, and no longer than MaxInitialCanaryApprovalTTL
//     measured from the approval time (short-lived by construction);
//  5. FOUR-EYES: a distinct requester and approver, both present (separation of duties — the
//     human who requested the live grant is not the human who approved it).
//
// It deliberately does NOT consult catalog.Usable or issue anything: it only decides whether
// an already-durable approval object would authorize this exact execution. Issuance of
// live_execution remains refused fail-closed elsewhere (tooltrust Issuable), so in this build
// no approval object of this purpose is producible in production — this predicate is what a
// future live phase's issue path must satisfy.
func SatisfiesLiveExecution(a *tooltrust.ToolApproval, tgt LiveTarget, now time.Time) TrustReason {
	if a == nil {
		return TrustNil
	}
	// (1) the live-execution firewall: only a live_execution purpose qualifies.
	if !a.Purpose.PermitsLiveExecution() {
		return TrustNotLiveExecution
	}
	// (2) active grant only.
	if a.Status != tooltrust.StatusActive {
		return TrustNotActive
	}
	// (5) four-eyes / separation of duties — both present and distinct.
	if a.RequestedBy == "" || a.ApprovedBy == "" || a.RequestedBy == a.ApprovedBy {
		return TrustNoFourEyes
	}
	// (4) short-lived expiry, present and unelapsed.
	if a.ExpiresAt == nil {
		return TrustNoExpiry
	}
	if !now.Before(*a.ExpiresAt) {
		return TrustExpired
	}
	// The validity window is measured from the APPROVAL instant (when the grant became live),
	// not from now, so a long-dormant-then-approved request cannot smuggle a long window. The
	// approval instant must be real and not in the future: a future ApprovedAt (malformed,
	// corrupt, or clock-skewed record) with a future-relative TTL would otherwise be accepted
	// for the whole intervening span, defeating the short-lived ceiling (Codex P2, PR #1249).
	//
	// This check is placed AFTER the unelapsed-expiry check above, and together they make the
	// window necessarily positive: ApprovedAt <= now (here) and now < ExpiresAt (above) imply
	// ExpiresAt > ApprovedAt. So the ceiling below measures a real forward window — Codex P2's
	// "ExpiresAt > ApprovedAt before accepting the TTL" holds by construction, no separate
	// backwards-window branch is reachable.
	if a.ApprovedAt.IsZero() || a.ApprovedAt.After(now) {
		return TrustApprovedInFuture
	}
	if a.ExpiresAt.Sub(a.ApprovedAt) > MaxInitialCanaryApprovalTTL {
		return TrustTTLTooLong
	}
	// (3) exact current-target binding (rug-pull invariant). MatchesTool compares tenant,
	// server, name, fingerprint-format, and the full digest.
	if a.FingerprintFormatVersion != tgt.FingerprintFormat {
		return TrustFingerprintFormat
	}
	if !a.MatchesTool(tgt.Tenant, tgt.ServerID, tgt.ToolName, tgt.Fingerprint, tgt.FingerprintFormat) {
		return TrustTargetMismatch
	}
	return TrustOK
}
