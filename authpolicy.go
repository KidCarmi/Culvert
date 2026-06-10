package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
//
// NOTE (Phase 1 Slice 3): this is the SHAPE validator, reached via
// validateAuthRule. Auth (Stage-1) rules with a valid CIDR SubjectMatch are now
// ACCEPTED by validatePolicyRule and PERSISTED (Load / ReplaceAll keep valid
// auth rules, drop invalid ones fail-closed) — but they remain INERT at runtime
// (resolveAuthOutcome still returns Default; the Stage-1 matcher is not wired).
// Access (Stage-2) rules still reject any non-nil SubjectMatch in
// validateAccessRule (Evaluate does not consult it, so allowing it would fail open).
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
	OutcomeCredentialRequired AuthOutcome = "CredentialRequired" // #nosec G101 -- enum value (name contains "Cred"); not a credential
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
// ruleset so it is testable without global state. It evaluates Stage-1 auth
// rules in priority order (lowest Priority value first, mirroring
// PolicyStore.sortLocked / Evaluate) and returns Exempt with the matched rule
// when an enabled, non-expired, in-schedule auth/exempt rule matches the
// request's source / destination / protocol / method. Otherwise it returns
// Default (Plan Freeze #9). It has no side effects and is NOT called from
// proxy.go — wiring it onto the hot path is a later slice.
//
// Only Outcome=Exempt is implemented; CredentialRequired/SSORequired are
// reserved and inert (they never match, so a request with only such rules
// resolves to Default). Access (Stage-2) rules are ignored entirely.
func resolveAuthOutcomeFrom(rules []PolicyRule, ctx RequestContext) AuthDecision {
	// Evaluate in priority order. Sort a copy so the decision is deterministic
	// regardless of the caller's slice ordering (policyStore.List() is already
	// sorted, but the contract must not depend on that).
	ordered := make([]PolicyRule, len(rules))
	copy(ordered, rules)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority < ordered[j].Priority
	})
	for i := range ordered {
		rule := &ordered[i]
		if authRuleMatchesExempt(rule, ctx) {
			return AuthDecision{Outcome: OutcomeExempt, Rule: rule}
		}
	}
	return AuthDecision{Outcome: OutcomeDefault}
}

// authRuleMatchesExempt reports whether a single rule is an enabled, currently
// effective auth/exempt rule that matches the request. Every check fails closed:
// a non-auth rule, a disabled rule, a missing/reserved outcome, an unscoped or
// malformed subject, an unmet destination, an out-of-schedule or expired rule,
// or a protocol/method mismatch all yield false.
func authRuleMatchesExempt(rule *PolicyRule, ctx RequestContext) bool {
	if ruleTypeOf(rule) != ruleTypeAuth { // Stage-1 only; access rules are ignored
		return false
	}
	if !ruleIsEnabled(rule) {
		return false
	}
	spec := rule.Auth
	if spec == nil { // malformed auth rule
		return false
	}
	if spec.Outcome != OutcomeExempt { // only Exempt is implemented; others inert
		return false
	}
	// Source scope: typed CIDR SubjectMatch. nil / unknown predicate / bad IP all
	// fail closed.
	if !matchSubject(rule.SubjectMatch, ctx.ClientIP) {
		return false
	}
	// Destination: an explicit selector, or an acknowledged broad exemption.
	if !authRuleHasDestination(*rule) && !spec.BroadExemption {
		return false
	}
	if !matchDest(rule, ctx.Host) {
		return false
	}
	// Schedule: a malformed timezone must fail closed (require auth), NOT silently
	// fall back to UTC. matchSchedule is shared with Stage-2 access evaluation and
	// stays lenient (changing it would alter traffic behavior); the auth gate adds
	// its own strict pre-check. Bulk persistence paths (Load/ReplaceAll) do not run
	// validatePolicyRule's timezone check, so a hand-edited or cluster-synced auth
	// rule can carry an invalid timezone — that must not grant Exempt.
	if !authScheduleParseable(rule.Schedule) {
		return false
	}
	if !matchSchedule(rule.Schedule) {
		return false
	}
	if !authRuleNotExpired(spec) {
		return false
	}
	return matchAuthProtocolMethod(spec, ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Policy — Phase 1 Slice 5: AuthOutcome OBSERVABILITY (no wiring).
//
// Pure builders that translate an AuthDecision into the low-cardinality SIEM
// fields (AuthLogFields) and a metric counter. NOT called from proxy.go — the
// auth gate is still unwired; these exist so a later slice can emit observability
// without changing request-handling behavior.
// ─────────────────────────────────────────────────────────────────────────────

// authLogFieldsFor builds the low-cardinality observability fields for an auth
// decision. It carries NO identity: an Exempt decision is described by outcome +
// rule id/name (+ low-cardinality subject predicate type names and the matched
// rule's subject schema version) only. A non-Exempt / Default decision yields the
// zero value, so logging stays byte-identical for un-exempted requests. Pure.
func authLogFieldsFor(d AuthDecision) AuthLogFields {
	if d.Outcome != OutcomeExempt || d.Rule == nil {
		return AuthLogFields{}
	}
	f := AuthLogFields{
		Outcome:        d.Outcome,
		PolicyRuleID:   d.Rule.ID,
		PolicyRuleName: d.Rule.Name,
	}
	if d.Rule.SubjectMatch != nil {
		f.SchemaVersion = d.Rule.SubjectMatch.SchemaVersion
		f.SubjectMatchTypes = subjectPredicateTypeNames(d.Rule.SubjectMatch)
	}
	return f
}

// subjectPredicateTypeNames returns the predicate TYPE names of a SubjectMatch
// (e.g. ["cidr"]). Only the bounded, low-cardinality type identifiers are
// returned — never the predicate VALUES (which would be high-cardinality, e.g.
// client CIDRs) — so these are safe as log/metric dimensions.
func subjectPredicateTypeNames(sm *SubjectMatch) []string {
	if sm == nil || len(sm.All) == 0 {
		return nil
	}
	out := make([]string, 0, len(sm.All))
	for i := range sm.All {
		out = append(out, sm.All[i].Type)
	}
	return out
}

// incAuthExempt increments the Stage-1 Exempt-decision counter exposed as
// culvert_auth_exempt_decisions_total. Defined in Slice 5 but intentionally NOT
// called from proxy.go / the request path yet (the metric stays at zero until the
// auth gate is wired in a later slice).
func incAuthExempt() {
	atomic.AddInt64(&statAuthExempt, 1)
}

// matchSubject reports whether clientIP satisfies a typed SubjectMatch. Predicate
// types are AND'd; values within a type are OR'd (mirroring validateSubjectMatch).
// In Phase 1 only the "cidr" predicate is understood; any other type — including
// the identity-dependent predicates that belong on access rules — fails closed,
// as does a nil/empty selector or an unparseable client IP.
func matchSubject(sm *SubjectMatch, clientIP string) bool {
	if sm == nil || sm.SchemaVersion < 1 || len(sm.All) == 0 {
		return false
	}
	if net.ParseIP(clientIP) == nil {
		return false
	}
	for i := range sm.All {
		p := sm.All[i]
		switch p.Type {
		case subjectPredicateCIDR:
			if !cidrPredicateMatches(p.Values, clientIP) {
				return false
			}
		default:
			return false // unknown/unsupported predicate → fail closed
		}
	}
	return true
}

// cidrPredicateMatches reports whether clientIP is contained by ANY of values
// (each a CIDR or bare IP). An empty value list fails closed.
func cidrPredicateMatches(values []string, clientIP string) bool {
	for _, v := range values {
		if matchIPOrCIDR(v, clientIP) {
			return true
		}
	}
	return false
}

// authScheduleParseable reports whether the rule's schedule is well-formed enough
// for the auth gate to trust it. A nil schedule or empty timezone is fine; a
// non-empty but unparseable IANA timezone fails closed (the Stage-1 gate must not
// waive authentication based on a schedule it cannot evaluate, and unlike
// validatePolicyRule the bulk persistence paths never reject such a timezone).
func authScheduleParseable(s *PolicySchedule) bool {
	if s == nil || s.Timezone == "" {
		return true
	}
	_, err := time.LoadLocation(s.Timezone)
	return err == nil
}

// authRuleNotExpired reports whether the rule has not expired. An empty
// ExpiresAt never expires; an unparseable timestamp fails closed (never matches).
func authRuleNotExpired(spec *AuthRuleSpec) bool {
	if spec.ExpiresAt == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339, spec.ExpiresAt)
	if err != nil {
		return false
	}
	return time.Now().Before(exp)
}

// matchAuthProtocolMethod enforces the rule's protocol and method scope. An empty
// protocol matches any; an empty method matches any. Method is ignored when the
// rule targets the "connect" protocol (CONNECT carries no HTTP method), matching
// validateAuthProtocol's "method is ignored for connect" semantics.
func matchAuthProtocolMethod(spec *AuthRuleSpec, ctx RequestContext) bool {
	if spec.Protocol != "" && !strings.EqualFold(spec.Protocol, ctx.Protocol) {
		return false
	}
	if spec.Method != "" && spec.Protocol != "connect" && !strings.EqualFold(spec.Method, ctx.Method) {
		return false
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Policy — Phase 1 Slice 2: auth (Exempt) rule VALIDATION.
//
// Pure validation only. NOT wired into the runtime auth gate (resolveAuthOutcome
// still returns Default for every request). No proxy.go / socks5.go change.
// ─────────────────────────────────────────────────────────────────────────────

// identityPredicateTypes are subject-predicate types that depend on an
// authenticated identity. They are INVALID on auth (Stage-1) rules because no
// identity exists yet when authentication is being decided. They belong on
// access (Stage-2) rules. Rejected explicitly so the invariant holds even after
// later phases teach validateSubjectMatch to understand these types for access
// rules (Plan: "auth rules carry no identity-dependent predicates").
var identityPredicateTypes = map[string]bool{
	"directory_group": true,
	"directory_attr":  true,
	"identity":        true,
	"group":           true,
	"user":            true,
	"email":           true,
	"sub":             true,
}

// validateAuthRule validates a ruleType="auth" rule for Phase 1 (Outcome=Exempt
// only). It returns any non-fatal warnings (broad scope, broad exemption,
// expired, ignored method) alongside a fatal error. It does NOT mutate the rule
// and has no runtime side effects. See roadmap/AUTH-POLICY-PHASE1-PLAN.md §3/§5.
func validateAuthRule(rule PolicyRule) (warnings []string, err error) {
	spec := rule.Auth
	if spec == nil {
		return nil, fmt.Errorf(`ruleType "auth" requires an auth spec`)
	}
	if err := validateAuthOutcomeAndIdP(spec); err != nil {
		return nil, err
	}
	if err := validateAuthOwnership(spec); err != nil {
		return nil, err
	}
	if err := validateAuthSource(rule); err != nil {
		return nil, err
	}
	for _, step := range []func(PolicyRule) ([]string, error){
		validateAuthProtocol, validateAuthExpiry, validateAuthDestination,
	} {
		w, err := step(rule)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, w...)
	}
	warnings = append(warnings, broadSubjectWarnings(rule.SubjectMatch)...)
	return warnings, nil
}

// validateAuthOutcomeAndIdP enforces the Slice-2 outcome (Exempt only) and the
// reserved-IdPRef invariant.
func validateAuthOutcomeAndIdP(spec *AuthRuleSpec) error {
	switch spec.Outcome {
	case OutcomeExempt:
		// supported
	case OutcomeCredentialRequired, OutcomeSSORequired:
		return fmt.Errorf("auth outcome %q is reserved and not yet implemented (only Exempt is supported)", spec.Outcome)
	default:
		return fmt.Errorf("auth outcome must be Exempt")
	}
	if spec.IdPRef != "" {
		return fmt.Errorf("idpRef is reserved for a later phase and cannot be set")
	}
	return nil
}

// validateAuthOwnership enforces mandatory owner + reason.
func validateAuthOwnership(spec *AuthRuleSpec) error {
	if strings.TrimSpace(spec.Owner) == "" {
		return fmt.Errorf("auth rule requires an owner")
	}
	if strings.TrimSpace(spec.Reason) == "" {
		return fmt.Errorf("auth rule requires a reason")
	}
	return nil
}

// validateAuthSource enforces the mandatory, CIDR-only, identity-free source
// scope.
func validateAuthSource(rule PolicyRule) error {
	if rule.SubjectMatch == nil {
		return fmt.Errorf("auth (exempt) rule requires a subjectMatch source scope")
	}
	if err := rejectIdentityPredicates(rule.SubjectMatch); err != nil {
		return err
	}
	return validateSubjectMatch(rule.SubjectMatch)
}

// validateAuthProtocol enforces the allowed protocol set ("", http, connect;
// socks5 rejected) and flags an ignored method on CONNECT.
func validateAuthProtocol(rule PolicyRule) ([]string, error) {
	spec := rule.Auth
	switch spec.Protocol {
	case "", "http", "connect":
		// supported
	case "socks5":
		return nil, fmt.Errorf(`protocol "socks5" is not supported for auth rules in Phase 1`)
	default:
		return nil, fmt.Errorf(`protocol must be "", "http", or "connect"`)
	}
	if spec.Method != "" && spec.Protocol == "connect" {
		return []string{"method is ignored for the connect protocol"}, nil
	}
	return nil, nil
}

// validateAuthExpiry enforces RFC3339 expiry. Expired rules are valid to store
// (they simply will not match later) but are flagged.
func validateAuthExpiry(rule PolicyRule) ([]string, error) {
	if rule.Auth.ExpiresAt == "" {
		return nil, nil
	}
	exp, perr := time.Parse(time.RFC3339, rule.Auth.ExpiresAt)
	if perr != nil {
		return nil, fmt.Errorf("expiresAt must be an RFC3339 timestamp")
	}
	if exp.Before(time.Now()) {
		return []string{"rule is already expired and will not match any request"}, nil
	}
	return nil, nil
}

// validateAuthDestination enforces the destination decision: a selector, or an
// explicit acknowledged broadExemption.
func validateAuthDestination(rule PolicyRule) ([]string, error) {
	if !authRuleHasDestination(rule) && !rule.Auth.BroadExemption {
		return nil, fmt.Errorf("exempt rule requires a destination (destFQDN, destCategory, or destCategoryGroup), or broadExemption=true")
	}
	if rule.Auth.BroadExemption {
		return []string{"broadExemption=true: authentication is waived for ALL destinations from the matched source — least privilege is bypassed; scope a destination if possible"}, nil
	}
	return nil, nil
}

// authRuleHasDestination reports whether the rule carries any destination
// selector (FQDN, a concrete category, or a category group).
func authRuleHasDestination(rule PolicyRule) bool {
	if rule.DestFQDN != "" {
		return true
	}
	if rule.DestCategory != "" && rule.DestCategory != CategoryAny {
		return true
	}
	return rule.DestCategoryGroup != ""
}

// rejectIdentityPredicates returns an error if any predicate is identity-
// dependent (invalid on auth rules — no identity exists at Stage 1).
func rejectIdentityPredicates(sm *SubjectMatch) error {
	if sm == nil {
		return nil
	}
	for i := range sm.All {
		if identityPredicateTypes[strings.ToLower(strings.TrimSpace(sm.All[i].Type))] {
			return fmt.Errorf("subjectMatch predicate %q is identity-dependent and not allowed on auth rules (no identity exists when authentication is decided)", sm.All[i].Type)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Policy — Phase 1 Slice 3: auth-aware PERSISTENCE gate.
//
// Slice 3 lets VALID auth/exempt rules be persisted and round-trip through every
// bulk path (Load, ReplaceAll, import-replace, rollback, cluster sync) WITHOUT
// activating them at runtime — resolveAuthOutcome still returns Default for every
// request, and proxy.go / socks5.go are untouched. The store-level fail-closed
// gate below is the single decision point shared by PolicyStore.Load and
// PolicyStore.ReplaceAll.
// ─────────────────────────────────────────────────────────────────────────────

// policyRulePersistable reports whether a rule may enter the live PolicyStore,
// returning a human-readable reason when it must be dropped. It is the
// store-level fail-closed gate shared by PolicyStore.Load and
// PolicyStore.ReplaceAll (the bulk paths that bypass validatePolicyRule):
//
//   - Auth (Stage-1) rules are KEPT only when validateAuthRule passes. An invalid
//     auth rule is dropped fail-closed rather than activated. A valid one is kept
//     so it survives restart / import-replace / rollback / cluster sync — it is
//     still inert at runtime (the Stage-1 matcher is not wired; resolveAuthOutcome
//     returns Default), so keeping it changes no traffic decision.
//   - Access (Stage-2) rules carrying a non-nil SubjectMatch are DROPPED:
//     Evaluate does not consult SubjectMatch on access rules, so a scoped rule
//     would match every client (fail-open). An Auth spec on a non-auth rule is
//     likewise malformed and dropped fail-closed.
//
// The function is pure: it neither mutates the rule nor has runtime side effects.
func policyRulePersistable(r *PolicyRule) (ok bool, reason string) {
	if r == nil {
		return false, "nil rule"
	}
	if ruleTypeOf(r) == ruleTypeAuth {
		if _, err := validateAuthRule(*r); err != nil {
			return false, fmt.Sprintf("invalid auth rule: %v", err)
		}
		return true, ""
	}
	// Access rule (RuleType "access" or empty/load-default).
	if r.SubjectMatch != nil {
		return false, "subjectMatch is reserved and not yet enforced on access rules"
	}
	if r.Auth != nil {
		return false, "auth spec is only valid on auth rules"
	}
	return true, ""
}

// broadSubjectWarnings flags overly broad source CIDRs (least-privilege nudges).
func broadSubjectWarnings(sm *SubjectMatch) []string {
	if sm == nil {
		return nil
	}
	var w []string
	for i := range sm.All {
		if sm.All[i].Type != subjectPredicateCIDR {
			continue
		}
		for _, v := range sm.All[i].Values {
			if v == "0.0.0.0/0" || v == "::/0" {
				w = append(w, fmt.Sprintf("source %q matches all addresses — extremely broad", v))
				continue
			}
			if _, ipnet, perr := net.ParseCIDR(v); perr == nil {
				if ones, bits := ipnet.Mask.Size(); bits == 32 && ones < 24 {
					w = append(w, fmt.Sprintf("source %q is broader than /24", v))
				}
			}
		}
	}
	return w
}
