package canary

import (
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// First-Canary scope bounds (§4). The first Canary must be STRUCTURALLY incapable of
// becoming fleet-wide, so its scope is capped to a handful of concrete, enumerated
// targets. These are deliberately tiny — a first Canary is one tool on one server for one
// synthetic principal, not a fleet slice. A later graduation phase raises them under its
// own review; it must edit these constants, and that edit is what a reviewer sees.
const (
	// MaxCanaryServers — the first Canary binds at most this many exact servers.
	MaxCanaryServers = 1
	// MaxCanaryTools — at most this many exact tools.
	MaxCanaryTools = 2
	// MaxCanaryPrincipals — at most this many exact principals/clients (synthetic identities).
	MaxCanaryPrincipals = 2
)

// ScopeReason is a bounded classification for WHY a candidate Canary scope is rejected. It
// is folded into ReasonScopeNotBounded / ReasonScopeNotReadFirst at the readiness layer,
// but ValidateScope returns the precise sub-reason so an operator dry-run can say exactly
// what to fix. Fixed vocabulary; never interpolated with runtime data.
type ScopeReason string

// Scope rejection sub-reasons (fixed vocabulary; ScopeOK is the empty admissible value).
const (
	ScopeOK                     ScopeReason = ""
	ScopeNotGateway             ScopeReason = "scope_not_gateway"
	ScopeUncompilable           ScopeReason = "scope_uncompilable"
	ScopeMatchesNothing         ScopeReason = "scope_matches_nothing"
	ScopeNotEnumerable          ScopeReason = "scope_not_enumerable"      // percentage-only / no concrete inclusion
	ScopeUsesPercentage         ScopeReason = "scope_uses_percentage"     // any percentage sub-sample forbidden for first Canary
	ScopeNoServers              ScopeReason = "scope_no_explicit_servers" // must bind ≥1 exact server
	ScopeNoTools                ScopeReason = "scope_no_explicit_tools"   // must bind ≥1 exact tool (with fingerprint)
	ScopeTooManyServers         ScopeReason = "scope_too_many_servers"
	ScopeTooManyTools           ScopeReason = "scope_too_many_tools"
	ScopeTooManyPrincipals      ScopeReason = "scope_too_many_principals"
	ScopeToolMissingFingerprint ScopeReason = "scope_tool_missing_fingerprint"
	ScopeHighRisk               ScopeReason = "scope_high_risk"      // HighRisk set, or write/destructive operations
	ScopeNotReadFirst           ScopeReason = "scope_not_read_first" // Operations include a non-read class
)

// ValidateScope enforces the first-Canary scope contract (§4/§5) on a candidate
// ScopeSpec: explicit, enumerable, bounded, fail-closed, read-first. It is pure (no I/O)
// and returns ScopeOK ("") when the scope is admissible for a first Canary, else the first
// violated sub-reason. A nil/empty/percentage/wildcard scope is rejected; a scope that
// admits any operation class beyond read/discovery is rejected.
//
// Culvert's own operation classification (rollout.RiskClass, derived by the policy engine
// from Culvert's authoritative rules — never the server-provided MCP readOnlyHint) is the
// authority here: the constraint is on the scope's admitted RiskClasses, not on any hint.
func ValidateScope(spec rollout.ScopeSpec, scopeRev uint64) ScopeReason {
	if spec.Capability != rollout.CapabilityGateway {
		return ScopeNotGateway
	}
	// Raw-field security checks run BEFORE Compile so each violation yields its OWN specific
	// reason. rollout.Compile enforces its own invariants (write/destructive require HighRisk;
	// a tool selector must pin server+name+fingerprint), so a write scope or a fingerprint-less
	// tool would otherwise surface only as the generic scope_uncompilable — the Canary contract
	// wants the precise cause.
	if r := validateScopeRawFields(spec); r != ScopeOK {
		return r
	}
	// Compile to reuse the exact rollout matcher semantics (enumerability, matches-nothing).
	sc, err := rollout.Compile(spec, scopeRev, rollout.DefaultLimits())
	if err != nil {
		return ScopeUncompilable
	}
	if sc.MatchesNothing() {
		return ScopeMatchesNothing
	}
	// Enumerable = built AND has a concrete inclusion dimension. A pure-percentage scope is
	// NOT enumerable and can never enter Canary (rollout scope.go already enforces this;
	// re-assert it here so the Canary contract is self-contained).
	if !sc.Enumerable() {
		return ScopeNotEnumerable
	}
	return validateScopeBounds(spec)
}

// validateScopeRawFields enforces the read-first and exact-fingerprint constraints on the raw
// spec (before Compile), so each violation surfaces its own precise reason.
func validateScopeRawFields(spec rollout.ScopeSpec) ScopeReason {
	// Read-first: the scope must not be high-risk and must admit only read/discovery. An empty
	// Operations set means read-only (rollout semantics), which is admissible.
	if spec.HighRisk {
		return ScopeHighRisk
	}
	for _, op := range spec.Operations {
		if op != rollout.RiskRead {
			return ScopeNotReadFirst
		}
	}
	// Every bound tool must pin an exact server+name+fingerprint — a same-named tool whose
	// fingerprint is unspecified is a wildcard-future-tool, which the first Canary forbids.
	for i := range spec.Tools {
		if spec.Tools[i].Fingerprint == "" || spec.Tools[i].Server == "" || spec.Tools[i].Name == "" {
			return ScopeToolMissingFingerprint
		}
	}
	return ScopeOK
}

// validateScopeBounds enforces the explicit-target and bounded-count constraints. Called after
// Compile has proven the scope enumerable and matching something.
func validateScopeBounds(spec rollout.ScopeSpec) ScopeReason {
	// No percentage sub-sample at all for the FIRST Canary — a bounded enumerated set is the
	// whole point; a percentage over that set is an unnecessary source of non-determinism in
	// which exact requests execute.
	if spec.Percent != 0 {
		return ScopeUsesPercentage
	}
	// Must bind at least one EXACT server and one EXACT tool, so the blast radius is a named
	// target, never "a tenant" or "an environment" alone.
	if len(spec.Servers) == 0 {
		return ScopeNoServers
	}
	if len(spec.Tools) == 0 {
		return ScopeNoTools
	}
	// Bounded counts — structurally incapable of fleet-wide.
	if len(spec.Servers) > MaxCanaryServers {
		return ScopeTooManyServers
	}
	if len(spec.Tools) > MaxCanaryTools {
		return ScopeTooManyTools
	}
	if principalCount(spec) > MaxCanaryPrincipals {
		return ScopeTooManyPrincipals
	}
	return ScopeOK
}

// principalCount counts the distinct identity-dimension bindings that name a principal,
// client, or agent — the "who can trigger the Canary" surface. Groups are deliberately NOT
// counted as a bounded principal: a group can expand to many principals, so a first Canary
// binds exact principals/clients, and a scope that leans on groups is treated as unbounded
// on this axis (0 explicit principals ⇒ the caller must bind at least one; see the runbook).
func principalCount(spec rollout.ScopeSpec) int {
	return len(spec.Principals) + len(spec.Clients) + len(spec.Agents)
}

// ScopeReadFirst reports whether the scope admits only read/discovery operation classes —
// the fact the readiness layer consumes as ScopeReadFirst. It is the isolated read-first
// half of ValidateScope (a scope can be bounded but not read-first, and the two produce
// distinct readiness reasons).
func ScopeReadFirst(spec rollout.ScopeSpec) bool {
	if spec.HighRisk {
		return false
	}
	for _, op := range spec.Operations {
		if op != rollout.RiskRead {
			return false
		}
	}
	return true
}
