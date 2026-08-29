package canary

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// ScopeApprovalReason is a bounded classification for WHY a set of live_execution approvals
// does not fully and exactly authorize a Canary scope's tools. Fixed vocabulary; never
// interpolated with runtime data.
type ScopeApprovalReason string

// Scope-approval rejection sub-reasons (fixed vocabulary; ScopeApprovalOK is the empty
// admissible value).
const (
	ScopeApprovalOK             ScopeApprovalReason = ""
	ScopeApprovalNoTools        ScopeApprovalReason = "scope_has_no_tools"              // scope names no tool to approve
	ScopeApprovalToolUnapproved ScopeApprovalReason = "scope_tool_unapproved"           // a scoped tool has no matching valid approval
	ScopeApprovalOutsideScope   ScopeApprovalReason = "approval_outside_scope"          // a binding authorizes a tool the scope does not name
	ScopeApprovalDuplicate      ScopeApprovalReason = "scope_tool_duplicate_approval"   // two bindings for one scoped tool identity
	ScopeApprovalFingerprint    ScopeApprovalReason = "approval_fingerprint_not_scoped" // binding target fingerprint != the scope tool's declared fingerprint
)

// ToolApprovalBinding pairs the exact CURRENT target of one scoped tool — resolved from the
// authoritative registry+catalog observation, never from a request — with the candidate
// live_execution approval offered to authorize it.
type ToolApprovalBinding struct {
	Target   LiveTarget
	Approval *tooltrust.ToolApproval
}

// ValidateScopeApprovals enforces §3/§4: EVERY exact tool named by the Canary scope must have
// its OWN matching, valid live_execution approval bound to that exact tool identity — the
// preflight must never trust a single unconstrained approval/target supplied alongside a
// multi-tool scope (Codex P1-C, PR #1249). It is PURE (injected clock, no I/O) and fail-closed:
// it returns ScopeApprovalOK only when
//
//   - the scope names at least one tool;
//   - every scoped tool (matched by exact server+name) has exactly one binding — none missing,
//     none duplicated;
//   - each binding's target fingerprint equals the scope tool's DECLARED fingerprint (the
//     scope's ToolSel.Fingerprint is hex of the same 32-byte digest as LiveTarget.Fingerprint,
//     so a target with a different fingerprint than the scope reviewed is rejected here — the
//     rug-pull cannot be smuggled in through the target);
//   - each binding's approval SatisfiesLiveExecution against its OWN target as of now
//     (purpose/status/four-eyes/expiry/exact-target — the full trust firewall);
//   - no binding authorizes a tool the scope does not name (no approval outside scope).
//
// It does NOT resolve inventory or issue anything; the caller supplies the current targets and
// the candidate approvals, and this decides whether they exactly cover the scope.
func ValidateScopeApprovals(spec rollout.ScopeSpec, bindings []ToolApprovalBinding, now time.Time) ScopeApprovalReason {
	if len(spec.Tools) == 0 {
		return ScopeApprovalNoTools
	}
	type toolKey struct{ server, name string }
	// Index bindings by exact (server, name); reject duplicate bindings for one identity so a
	// second, weaker approval can never shadow the checked one.
	byTool := make(map[toolKey]int, len(bindings))
	for i := range bindings {
		k := toolKey{bindings[i].Target.ServerID, bindings[i].Target.ToolName}
		if _, dup := byTool[k]; dup {
			return ScopeApprovalDuplicate
		}
		byTool[k] = i
	}
	scopeKeys := make(map[toolKey]struct{}, len(spec.Tools))
	for i := range spec.Tools {
		st := spec.Tools[i]
		k := toolKey{st.Server, st.Name}
		scopeKeys[k] = struct{}{}
		bi, ok := byTool[k]
		if !ok {
			return ScopeApprovalToolUnapproved
		}
		b := bindings[bi]
		// The target must bind the EXACT fingerprint the scope declared — not merely the same
		// server+name. ToolSel.Fingerprint and LiveTarget.Fingerprint are the same 32-byte digest
		// (hex vs bytes), so this rejects a target whose fingerprint the scope never reviewed.
		if !strings.EqualFold(hex.EncodeToString(b.Target.Fingerprint[:]), st.Fingerprint) {
			return ScopeApprovalFingerprint
		}
		if SatisfiesLiveExecution(b.Approval, b.Target, now) != TrustOK {
			return ScopeApprovalToolUnapproved
		}
	}
	// No binding may authorize a tool outside the enumerated scope.
	for i := range bindings {
		k := toolKey{bindings[i].Target.ServerID, bindings[i].Target.ToolName}
		if _, in := scopeKeys[k]; !in {
			return ScopeApprovalOutsideScope
		}
	}
	return ScopeApprovalOK
}
