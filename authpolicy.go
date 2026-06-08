package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oklog/ulid/v2"
)

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Policy — Phase 0 seams (foundations only).
//
// This file introduces the frozen architecture seams from
// roadmap/AUTHENTICATION-POLICY-SPEC.md WITHOUT changing any runtime behavior:
//
//   - RequestContext / AccessDecision / Decide()  — the unified PDP seam.
//     Decide() is NOT wired into proxy.go in Phase 0; it delegates to the
//     existing Stage-2 access engine and exists only to prove equivalence.
//   - RuleType discriminator with load-default "access".
//   - SubjectMatch typed schema (cidr implemented; unknown types fail-closed).
//   - newRuleID() stable ULID generator for rule IDs.
//   - CULVERT_AUTHBYPASS_DISABLE read-once kill-switch accessor (consulted by
//     nothing yet).
//
// None of these are placed on the request hot path during Phase 0.
// ─────────────────────────────────────────────────────────────────────────────

// ─── RuleType discriminator ─────────────────────────────────────────────────

// ruleType* values discriminate Stage-1 authentication rules from Stage-2
// access rules within the single unified ruleset. An empty RuleType (the zero
// value for rules loaded from JSON written before this field existed) is
// treated as an access rule for full backward compatibility.
const (
	ruleTypeAccess = "access"
	ruleTypeAuth   = "auth"
)

// ruleTypeOf returns the effective rule type, defaulting an empty value to
// "access" (load-default — see §1.3 of the spec).
func ruleTypeOf(r *PolicyRule) string {
	if r == nil || r.RuleType == "" {
		return ruleTypeAccess
	}
	return r.RuleType
}

// ─── SubjectMatch typed schema (extensibility seam — §1.6) ──────────────────

// subjectPredicate type identifiers. Only "cidr" is implemented in Phase 0.
// Future types (directory_group, tag, asset_group, device_id, posture) are
// reserved by the spec but MUST hard-error in validation until implemented —
// silently ignoring an unknown predicate on an authentication waiver would be
// a fail-open trapdoor.
const subjectPredicateCIDR = "cidr"

// SubjectMatch is the versioned, typed subject selector that replaces flat
// scalar source fields. Predicate types are AND'd; values within a type are
// OR'd. New predicate types are additive (bump SchemaVersion); no breaking
// migration is ever required.
type SubjectMatch struct {
	SchemaVersion int                `json:"schemaVersion"`
	All           []SubjectPredicate `json:"all"`
}

// SubjectPredicate is a single typed match criterion.
type SubjectPredicate struct {
	Type   string   `json:"type"`
	Op     string   `json:"op,omitempty"`
	Values []string `json:"values"`
}

// validateSubjectMatch validates a SubjectMatch. A nil selector is valid (the
// field is unused). Unknown predicate types are rejected (fail-closed). In
// Phase 0 only the "cidr" predicate is accepted, and each of its values must be
// a valid IP or CIDR.
func validateSubjectMatch(sm *SubjectMatch) error {
	if sm == nil {
		return nil
	}
	if sm.SchemaVersion < 1 {
		return fmt.Errorf("subjectMatch.schemaVersion must be >= 1")
	}
	if len(sm.All) == 0 {
		return fmt.Errorf("subjectMatch.all must contain at least one predicate")
	}
	for i := range sm.All {
		p := sm.All[i]
		switch p.Type {
		case subjectPredicateCIDR:
			if len(p.Values) == 0 {
				return fmt.Errorf("subjectMatch cidr predicate requires at least one value")
			}
			for _, v := range p.Values {
				if err := validateCIDROrIP(v); err != nil {
					return fmt.Errorf("subjectMatch cidr value %q: %w", v, err)
				}
			}
		default:
			// Fail-closed: reserved/unknown predicate types are not yet
			// implemented and must be rejected, never silently ignored.
			return fmt.Errorf("subjectMatch predicate type %q is not supported", p.Type)
		}
	}
	return nil
}

// validateCIDROrIP returns nil if s parses as a CIDR or a bare IP.
func validateCIDROrIP(s string) error {
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid CIDR")
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP")
	}
	return nil
}

// ─── Stable ULID rule IDs (§1.5) ────────────────────────────────────────────

// newRuleID returns a fresh, time-sortable ULID string used as the stable,
// durable identifier for a policy rule. Stable IDs survive renames/reorders
// and are the canonical join key for SIEM/audit and (later) cluster sync.
func newRuleID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

// ─── Unified PDP seam (§1.1 / §1.4) ─────────────────────────────────────────

// RequestContext is the protocol-neutral input to the unified Policy Decision
// Point. It is introduced in Phase 0 as a stable seam so that SOCKS5 alignment
// and posture/device extensibility become additive rather than breaking
// refactors. Only HTTP/CONNECT populate it today, and several fields stay
// empty until later phases.
type RequestContext struct {
	ClientIP      string
	Host          string
	Port          int
	Protocol      string // "http" | "connect" | "socks5"
	Method        string // HTTP method; empty for SOCKS5
	Identity      string // resolved identity, empty if none
	AuthSource    string // resolved by the auth gate / Stage 1
	Groups        []string
	DeviceSignals any // reserved: posture / device identity (future phases)
}

// AccessDecision is the structured result of the unified PDP. In Phase 0 only
// the Stage-2 access Match is populated (Stage 1 lands in Phase 1).
type AccessDecision struct {
	AuthSource string       // echoed resolved auth source
	Match      *PolicyMatch // Stage-2 access result (nil = no rule matched)
}

// Decide is the single entry point of the unified PDP. In Phase 0 it delegates
// to the existing Stage-2 access engine and is provably equivalent to a direct
// policyStore.Evaluate call (see TestDecide_EquivalentToEvaluate). It is
// intentionally NOT called from proxy.go during Phase 0 — wiring it onto the
// hot path is Phase 1.
func Decide(ctx RequestContext) AccessDecision {
	return AccessDecision{
		AuthSource: ctx.AuthSource,
		Match:      policyStore.Evaluate(ctx.ClientIP, ctx.Identity, ctx.AuthSource, ctx.Host, ctx.Groups),
	}
}

// ─── Kill switch (§1.11) — read-once accessor only ──────────────────────────

// envAuthBypassDisable is the break-glass environment variable that will, in a
// later phase, force all authentication-policy exemptions off (fail to
// "auth required"). In Phase 0 it is parsed but consulted by no runtime path.
const envAuthBypassDisable = "CULVERT_AUTHBYPASS_DISABLE" // #nosec G101 -- environment-variable name (matches "PASS" substring), not a credential

var (
	authBypassDisableOnce sync.Once
	authBypassDisableVal  bool
)

// parseAuthBypassDisable interprets a kill-switch env value. Truthy values:
// "1", "true", "yes", "on" (case-insensitive). Everything else is false.
func parseAuthBypassDisable(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// authBypassDisabled reports whether the break-glass kill switch is engaged.
// The environment is read exactly once (read-once contract, mirroring
// CULVERT_C2_ENFORCE). Phase 0 wires no behavior to this value.
func authBypassDisabled() bool {
	authBypassDisableOnce.Do(func() {
		authBypassDisableVal = parseAuthBypassDisable(os.Getenv(envAuthBypassDisable))
	})
	return authBypassDisableVal
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Policy — Phase 1 Slice 1: AuthOutcome resolver CONTRACT.
//
// This slice introduces the architectural spine from
// roadmap/AUTH-POLICY-PHASE1-PLAN.md as a PURE contract only:
//
//   - AuthOutcome enum (frozen)
//   - AuthRuleSpec (the auth/exempt rule spec; modeled, not yet validated)
//   - AuthDecision (resolver result)
//   - resolveAuthOutcome(ctx) — returns Default for every request today
//
// NOT wired into proxy.go. The Stage-1 evaluator (subject/destination matching)
// lands in later slices; until then every request resolves to Default, which the
// proxy treats as "run today's gate verbatim" — byte-identical to current
// behavior (Plan Freezes #7 and #9). No runtime behavior changes in this slice.
// ─────────────────────────────────────────────────────────────────────────────

// AuthOutcome is the result of the end-user authentication decision. It is the
// architectural spine (Plan Freeze #1): the auth gate resolves an outcome rather
// than a boolean. The enum is FROZEN (Plan Freeze #2).
type AuthOutcome string

const (
	// OutcomeDefault means no auth rule matched; the proxy falls through to the
	// existing global-config-derived gate. In Phase 1 this is byte-identical to
	// today's behavior — a compatibility outcome that Phase 2/3 progressively
	// decompose (Plan Freeze #9).
	OutcomeDefault AuthOutcome = "Default"
	// OutcomeExempt skips end-user authentication without creating an identity.
	// Modeled in Phase 1; the only outcome Phase 1 will eventually implement.
	OutcomeExempt AuthOutcome = "Exempt"
	// OutcomeCredentialRequired requires a non-interactive credential challenge.
	// Mechanism-neutral (Basic/bearer/token/mTLS/agent-cert/future). NOT
	// implemented in Phase 1 (Plan Freeze #2/#7).
	OutcomeCredentialRequired AuthOutcome = "CredentialRequired"
	// OutcomeSSORequired requires browser SSO (portal / OIDC code flow / SAML).
	// NOT implemented in Phase 1 (Plan Freeze #2/#7).
	OutcomeSSORequired AuthOutcome = "SSORequired"
)

// AuthRuleSpec is the auth-only portion of a policy rule (non-nil only for
// ruleType="auth"). Modeled in this slice; field-level validation and the
// matcher land in later slices. See AUTH-POLICY-PHASE1-PLAN.md §3.
type AuthRuleSpec struct {
	Outcome        AuthOutcome `json:"outcome"`                  // Phase 1: "Exempt" only
	Protocol       string      `json:"protocol,omitempty"`       // "http" | "connect" | "" (any); "socks5" rejected in P1
	Method         string      `json:"method,omitempty"`         // optional HTTP method; "" = any
	Owner          string      `json:"owner,omitempty"`          // required (validated in a later slice)
	Reason         string      `json:"reason,omitempty"`         // required (validated in a later slice)
	ExpiresAt      string      `json:"expiresAt,omitempty"`      // RFC3339 UTC; "" = no expiry (breadth-warned)
	BroadExemption bool        `json:"broadExemption,omitempty"` // explicit ack for destination=any
	// IdPRef is RESERVED for Phase 3 (multi-IdP SSORequired targeting): an IdP
	// profile id; empty = email-domain routing / global default. Neither read nor
	// written by Phase 1 (Plan Freeze #2).
	IdPRef string `json:"idpRef,omitempty"`
}

// AuthDecision is the result of resolveAuthOutcome: the chosen outcome and, when
// an auth rule matched, a pointer to it (nil for Default).
type AuthDecision struct {
	Outcome AuthOutcome
	Rule    *PolicyRule // matched auth rule; nil for Default
}

// resolveAuthOutcome resolves the end-user authentication outcome for a request.
// It is the Phase 1 spine, but in Slice 1 it is a pure contract that returns
// Default for every request — the Stage-1 auth-rule evaluator is added in later
// slices. It is intentionally NOT called from proxy.go in this slice.
func resolveAuthOutcome(ctx RequestContext) AuthDecision {
	return resolveAuthOutcomeFrom(policyStore.List(), ctx)
}

// resolveAuthOutcomeFrom is the pure core of the resolver, taking an explicit
// ruleset so it is testable without global state. Slice 1 returns Default
// unconditionally (matching is deferred to later slices); the signature is
// stable so wiring the matcher is purely additive.
func resolveAuthOutcomeFrom(rules []PolicyRule, ctx RequestContext) AuthDecision {
	_ = rules // auth-rule evaluation (matchSubject + dest/protocol/method) lands in later slices
	_ = ctx
	return AuthDecision{Outcome: OutcomeDefault}
}
