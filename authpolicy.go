package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
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

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Policy — Phase 1 Slice 7: runtime wiring (no-credentials path).
// ─────────────────────────────────────────────────────────────────────────────

// authSourceExempt is the categorical auth source recorded for requests whose
// authentication challenge was waived by a Stage-1 exempt rule. Distinct from
// "unauth" (global UnauthMode / pre-gate default) so Stage-2 policy, request
// logs, and SIEM can target explicit exemptions separately — e.g. allow
// authSource=exempt only to specific destinations, or report exempt traffic on
// its own. No identity is ever attached to an exempt request.
const authSourceExempt = "exempt"

// reservedAuthSourceNames is the RESERVED authSource namespace (pre-Phase-2
// correction). These values have fixed meaning in Stage-2 policy matching,
// request logs, and SIEM exports:
//
//	exempt — Stage-1 exemption waived authentication (Slice 7)
//	unauth — no credentials presented / global UnauthMode
//	local  — local bcrypt account authentication
//	system — reserved for internal/system-originated traffic (future)
//
// IdP profile IDs and names must never collide with these: provider Name()
// values are "oidc:<ID>"/"saml:<ID>" and matchAuthSource strips those prefixes
// (stripIdPPrefix), while OIDC/SAML sessions carry the bare profile ID as
// Identity.Provider — so a profile ID or name equal to a reserved word would
// make authSource-scoped access rules ambiguous (e.g. a rule targeting
// authSource="exempt" could match an IdP-authenticated user). Enforced in
// validateIdPProfile; checked case-insensitively after trimming.
var reservedAuthSourceNames = map[string]bool{
	authSourceExempt: true,
	"unauth":         true,
	"local":          true,
	"system":         true,
}

// isReservedAuthSourceName reports whether s collides with the reserved
// authSource namespace (case-insensitive, trimmed).
func isReservedAuthSourceName(s string) bool {
	return reservedAuthSourceNames[strings.ToLower(strings.TrimSpace(s))]
}

// authRequestContext builds the Stage-1 RequestContext for an HTTP/CONNECT
// request at the proxy auth gate. Host is port-stripped (CONNECT targets carry
// ":443"); Protocol is "connect" for CONNECT and "http" otherwise. SOCKS5 has
// its own handler and never reaches this gate (socks5 rules are rejected at
// validation in Phase 1).
func authRequestContext(r *http.Request, clientIP string) RequestContext {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	proto := "http"
	if r.Method == http.MethodConnect {
		proto = "connect"
	}
	return RequestContext{ClientIP: clientIP, Host: host, Protocol: proto, Method: r.Method}
}

// resolveNoCredAuthOutcome evaluates the Stage-1 exemption for a request at the
// proxy auth gate, but ONLY when no Proxy-Authorization header is present at
// all. parseProxyAuth returns ok=false both for an absent header AND for a
// present-but-malformed one (unsupported scheme, bad base64, missing colon,
// overlong username) — the latter is PRESENTED credentials and must take the
// existing 407 path, never an exemption. This guard pins the contract that
// credential failures of any kind are never exempted.
func resolveNoCredAuthOutcome(r *http.Request, clientIP string, defaultOutcome AuthOutcome) AuthDecision {
	if r.Header.Get("Proxy-Authorization") != "" {
		// Presented credentials are NEVER default-exempted: keep today's Default
		// path (validated in arm 2, or 407). Independent of defaultAuthOutcome.
		return AuthDecision{Outcome: OutcomeDefault}
	}
	// RUNTIME PATH — proxy.go's arm-3 hook handles Exempt (waive), CR (407
	// challenge) and, as of Phase 3 Slice 4, SSORequired (302 redirect / 403
	// fail-closed). All three are runtime-active; the highest-priority matching
	// auth rule wins (priority-only model).
	d := resolveAuthOutcome(authRequestContext(r, clientIP))
	// S2 (Slice 3): only when NO scoped rule matched (Outcome=Default, Rule=nil)
	// does the global defaultAuthOutcome apply. Rule stays nil so the caller
	// distinguishes default-Exempt (authSource="unauth") from a scoped Exempt
	// rule (authSource="exempt"). The pure resolveAuthOutcomeFrom is unchanged
	// (simulator-shared); the global-default tail lives here on the runtime path.
	if d.Outcome == OutcomeDefault && d.Rule == nil {
		return AuthDecision{Outcome: defaultOutcome}
	}
	return d
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

// ─── Auth Exempt kill switch (Phase 1 Slice 6) ──────────────────────────────

// authExemptDisabledRuntime is the runtime/global kill-switch toggle for Auth
// Exempt decisions. It augments the read-once env kill switch
// (CULVERT_AUTHBYPASS_DISABLE) with an operator-settable runtime control so an
// admin can fail all exemptions closed without a restart. Backend-only in this
// slice — no API/UI is wired to it yet.
var authExemptDisabledRuntime atomic.Bool

// setAuthExemptDisabled engages (true) or releases (false) the runtime kill
// switch. Defined for a future admin/runtime toggle; not exposed via API/UI yet.
func setAuthExemptDisabled(v bool) { authExemptDisabledRuntime.Store(v) }

// authExemptDisabledRuntimeState reports the runtime toggle state only (excludes
// the env kill switch). Used by diagnostics/observability, not the gate decision.
func authExemptDisabledRuntimeState() bool { return authExemptDisabledRuntime.Load() }

// authExemptKillSwitchEngaged reports whether Auth Exempt resolution must fail
// closed to Default (auth-required). It is engaged when EITHER the read-once env
// kill switch (CULVERT_AUTHBYPASS_DISABLE) is set OR the runtime toggle is on.
func authExemptKillSwitchEngaged() bool {
	return authBypassDisabled() || authExemptDisabledRuntime.Load()
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
	// ProviderRefs is RESERVED (validation-rejected when set; persistence-safe
	// via omitempty). Phase 3 activates it: for SSORequired it targets an IdP
	// profile (single ref; empty = email-domain routing / global default), and
	// for CredentialRequired it names the credential-provider subset that may
	// satisfy the rule (empty = the global validator chain). Supersedes the
	// Phase-1 reserved IdPRef field, which was never activatable (validation
	// rejected any non-empty value), so no stored data can carry it — the
	// replacement is wire-safe (pre-Phase-2 correction).
	ProviderRefs []string `json:"providerRefs,omitempty"`
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

// resolveAuthOutcomeFrom is the FULL pure resolver, taking an explicit ruleset so
// it is testable without global state. It evaluates Stage-1 auth rules in
// priority order (lowest Priority value first, mirroring PolicyStore.sortLocked /
// Evaluate) and returns the matched rule's outcome (Exempt, CredentialRequired,
// or SSORequired) for the first matching auth rule. Otherwise it returns Default
// (Plan Freeze #9). It has no side effects beyond the Exempt kill-switch read.
//
// This full resolver is consumed by the simulator and observability. The RUNTIME
// no-credentials path uses resolveAuthOutcomeFromExcluding with
// runtimeInertOutcomes so that an outcome proxy.go does not yet consume
// (SSORequired, Phase 3 Slice 3) cannot win OR shadow a lower-priority Exempt/CR
// rule. This mirrors the Phase 2 Slice 2 Exempt-only stopgap (removed in Slice 3
// when CR shipped); the SSORequired exclusion is removed in Phase 3 Slice 4 when
// SSORequired is wired onto the hot path.
//
// Break-glass kill switch (env CULVERT_AUTHBYPASS_DISABLE or the runtime toggle)
// disables Exempt ONLY: a matching Exempt rule is suppressed (fails closed to
// auth-required) and evaluation continues to lower-priority rules / Default.
// CredentialRequired and SSORequired are NOT disabled by the kill switch — they
// already require authentication.
//
// Phase 3 Slice 4 wired SSORequired onto the proxy hot path, so the Slice-3
// runtime-inert stopgap (runtimeInertOutcomes / resolveAuthOutcomeFromExcluding)
// is removed: all three outcomes (Exempt, CredentialRequired, SSORequired) are
// runtime-active and ordered purely by priority. A higher-priority SSORequired
// or CR rule legitimately beating a lower-priority Exempt rule is the admin's
// intended priority — not a shadowing regression (overlap diagnostics land in
// Slice 5).
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
		outcome, ok := authRuleMatches(rule, ctx)
		if !ok {
			continue
		}
		// Kill switch disables Exempt only: suppress a matching Exempt rule and
		// fall through to lower-priority rules / Default. CR and SSORequired are
		// unaffected — they already require authentication.
		if outcome == OutcomeExempt && authExemptKillSwitchEngaged() {
			continue
		}
		return AuthDecision{Outcome: outcome, Rule: rule}
	}
	return AuthDecision{Outcome: OutcomeDefault}
}

// authRuleMatches reports whether a single rule is an enabled, currently
// effective Stage-1 auth rule that matches the request, and if so returns its
// outcome (Exempt or CredentialRequired). It returns ("", false) when the rule
// does not apply: a non-auth rule, a disabled rule, a missing spec, a
// not-yet-implemented outcome (Default/unknown), an unscoped or
// malformed subject, an unmet destination, an out-of-schedule or expired rule,
// or a protocol/method mismatch — every check fails closed. The outcome is NOT
// interpreted here (no exempt/challenge semantics); the resolver applies the
// kill switch and the caller decides what each outcome means.
func authRuleMatches(rule *PolicyRule, ctx RequestContext) (AuthOutcome, bool) {
	if ruleTypeOf(rule) != ruleTypeAuth { // Stage-1 only; access rules are ignored
		return "", false
	}
	if !ruleIsEnabled(rule) {
		return "", false
	}
	spec := rule.Auth
	if spec == nil { // malformed auth rule
		return "", false
	}
	switch spec.Outcome {
	case OutcomeExempt, OutcomeCredentialRequired, OutcomeSSORequired:
		// implemented — the pure resolver returns all three. SSORequired is kept
		// off the runtime path via runtimeInertOutcomes until Phase 3 Slice 4.
	default: // Default / unknown — reserved and inert
		return "", false
	}
	// Source scope: typed CIDR SubjectMatch. nil / unknown predicate / bad IP all
	// fail closed.
	if !matchSubject(rule.SubjectMatch, ctx.ClientIP) {
		return "", false
	}
	// Destination: an explicit selector, or an acknowledged broad exemption.
	// (broadExemption is Exempt-only and rejected on CR at validation, so a valid
	// CR rule always carries a concrete destination.)
	if !authRuleHasDestination(*rule) && !spec.BroadExemption {
		return "", false
	}
	if !matchDest(rule, ctx.Host) {
		return "", false
	}
	// Schedule: a malformed timezone must fail closed (require auth), NOT silently
	// fall back to UTC. matchSchedule is shared with Stage-2 access evaluation and
	// stays lenient (changing it would alter traffic behavior); the auth gate adds
	// its own strict pre-check. Bulk persistence paths (Load/ReplaceAll) do not run
	// validatePolicyRule's timezone check, so a hand-edited or cluster-synced auth
	// rule can carry an invalid timezone — that must not grant a Stage-1 outcome.
	if !authScheduleParseable(rule.Schedule) {
		return "", false
	}
	if !matchSchedule(rule.Schedule) {
		return "", false
	}
	if !authRuleNotExpired(spec) {
		return "", false
	}
	if !matchAuthProtocolMethod(spec, ctx) {
		return "", false
	}
	return spec.Outcome, true
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
// decision. It carries NO identity: an Exempt/CredentialRequired/SSORequired
// decision is described by outcome + rule id/name (+ low-cardinality subject
// predicate type names and the matched rule's subject schema version) only.
// providerRefs VALUES are intentionally NOT serialized (they would be a
// higher-cardinality dimension); the decision still carries them via d.Rule for
// later runtime use. A Default decision yields the zero value, so logging stays
// byte-identical for un-decided requests. Pure.
func authLogFieldsFor(d AuthDecision) AuthLogFields {
	if d.Rule == nil || (d.Outcome != OutcomeExempt && d.Outcome != OutcomeCredentialRequired && d.Outcome != OutcomeSSORequired) {
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

// incAuthCredentialRequired increments the Stage-1 CredentialRequired-decision
// counter exposed as culvert_auth_credential_required_total. Wired onto the proxy
// hot path in Phase 2 Slice 3.
func incAuthCredentialRequired() {
	atomic.AddInt64(&statAuthCredentialRequired, 1)
}

// incAuthSSORequired increments the Stage-1 SSORequired-decision counter exposed
// as culvert_auth_sso_required_total. Defined in Phase 3 Slice 3 but intentionally
// NOT called from proxy.go / the request path yet — SSORequired is runtime-inert
// until Slice 4 wires it, so the metric stays at zero.
func incAuthSSORequired() {
	atomic.AddInt64(&statAuthSSORequired, 1)
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

// validateAuthRule validates a ruleType="auth" rule. Supported outcomes are
// Exempt (Phase 1), CredentialRequired (Phase 2 Slice 1) and SSORequired
// (Phase 3 Slice 2 — validated and persisted, but runtime-inert: the resolver
// returns Default for it until a later slice wires it). It returns any non-fatal
// warnings (broad scope, broad exemption, expired, ignored method) alongside a
// fatal error. It is PURE — it does NOT consult the IdP registry or any other
// global (the providerRefs referential check is validateSSOProviderRefsLive,
// applied only at the API write door) — and has no runtime side effects. See
// roadmap/AUTH-POLICY-PHASE1-PLAN.md §3/§5 and roadmap/AUTH-POLICY-PHASE2-PLAN.md.
func validateAuthRule(rule PolicyRule) (warnings []string, err error) {
	spec := rule.Auth
	if spec == nil {
		return nil, fmt.Errorf(`ruleType "auth" requires an auth spec`)
	}
	if err := validateAuthOutcomeAndProviders(spec); err != nil {
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

// validateAuthOutcomeAndProviders enforces the supported outcomes (Exempt,
// CredentialRequired, SSORequired) and the outcome-gated providerRefs rules.
// providerRefs is SHAPE-validated here only (registry-free, so the bulk
// persistence gate via policyRulePersistable stays pure); the referential check
// that each ref names an enabled, type-compatible IdP runs at the API write door
// (validateSSOProviderRefsLive). Outcome gating (Phase 3 Slice 2):
//   - SSORequired: providerRefs allowed (empty = all compatible enabled
//     interactive IdPs; one/many recorded for later runtime selection).
//   - CredentialRequired: providerRefs rejected (deferred to a later slice).
//   - Exempt: providerRefs rejected (no provider concept).
func validateAuthOutcomeAndProviders(spec *AuthRuleSpec) error {
	switch spec.Outcome {
	case OutcomeExempt, OutcomeCredentialRequired, OutcomeSSORequired:
		// supported
	default:
		return fmt.Errorf("auth outcome must be Exempt, CredentialRequired, or SSORequired")
	}
	if spec.Outcome == OutcomeSSORequired {
		return validateSSOProviderRefsShape(spec.ProviderRefs)
	}
	// Exempt and CredentialRequired do not accept providerRefs in Phase 3 Slice 2.
	if len(spec.ProviderRefs) != 0 {
		if spec.Outcome == OutcomeCredentialRequired {
			return fmt.Errorf("providerRefs for CredentialRequired is deferred and cannot be set yet")
		}
		return fmt.Errorf("providerRefs is not valid on Exempt rules")
	}
	return nil
}

// maxAuthProviderRefs caps an SSORequired rule's providerRefs list to a sane
// bound. The realistic ceiling is the number of configured IdP profiles; this
// fixed cap is a generous guard against accidental or abusive blow-up.
const maxAuthProviderRefs = 16

// validateSSOProviderRefsShape validates the SHAPE of an SSORequired rule's
// providerRefs WITHOUT consulting the IdP registry, so it is safe in the pure
// persistence gate. Empty is valid (= all compatible enabled interactive IdPs).
// Each entry must be a trimmed, non-empty profile ID; duplicates are rejected;
// the list is capped. The referential check (each ref is an enabled OIDC/SAML
// profile) lives in validateSSOProviderRefsLive and runs at the API write door
// only — never here — so registry drift can never retroactively drop a stored
// rule (DR-4).
func validateSSOProviderRefsShape(refs []string) error {
	if len(refs) > maxAuthProviderRefs {
		return fmt.Errorf("providerRefs has %d entries; maximum is %d", len(refs), maxAuthProviderRefs)
	}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		// Require canonical (already-trimmed, non-empty) IDs so stored refs match
		// what validateSSOProviderRefsLive looks up and the later runtime selector
		// consumes — and so the duplicate check below cannot be bypassed by
		// surrounding whitespace (e.g. "corp-oidc" vs " corp-oidc ").
		if ref == "" || strings.TrimSpace(ref) != ref {
			return fmt.Errorf("providerRefs entries must be non-empty IdP profile IDs without surrounding whitespace")
		}
		if seen[ref] {
			return fmt.Errorf("providerRefs contains a duplicate entry %q", ref)
		}
		seen[ref] = true
	}
	return nil
}

// validateSSOProviderRefsLive is the REFERENTIAL counterpart to
// validateSSOProviderRefsShape: it checks that every providerRef on an
// SSORequired rule resolves to an ENABLED IdP profile of an interactive type
// (OIDC or SAML) in the live registry. It is consulted ONLY at the API write
// door (apiAuthPolicyCreate/Update) — never in the bulk persistence gate — and
// is fail-closed: a missing, disabled, or non-interactive ref is rejected at
// write time. Empty providerRefs is valid (= all compatible enabled interactive
// IdPs). Stored rules are NOT re-checked here, so a later IdP deletion/disable
// does not drop them (DR-4); runtime + diagnostics fail closed in later slices.
func validateSSOProviderRefsLive(spec *AuthRuleSpec) error {
	if spec == nil || spec.Outcome != OutcomeSSORequired || len(spec.ProviderRefs) == 0 {
		return nil
	}
	if idpRegistry == nil {
		return fmt.Errorf("providerRefs set but no IdP profiles are configured")
	}
	for _, ref := range spec.ProviderRefs {
		id := strings.TrimSpace(ref)
		p := idpRegistry.Get(id)
		switch {
		case p == nil:
			return fmt.Errorf("providerRef %q does not match any configured IdP profile", id)
		case !p.Enabled:
			return fmt.Errorf("providerRef %q references a disabled IdP profile", id)
		case p.Type != IdPTypeOIDC && p.Type != IdPTypeSAML:
			return fmt.Errorf("providerRef %q is not an interactive (OIDC or SAML) IdP", id)
		}
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
// scope (applies to every auth outcome).
func validateAuthSource(rule PolicyRule) error {
	if rule.SubjectMatch == nil {
		return fmt.Errorf("auth rule requires a subjectMatch source scope")
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

// validateAuthDestination enforces the destination decision, which is
// outcome-aware:
//
//   - CredentialRequired requires a concrete destination selector. broadExemption
//     is an Exempt-only acknowledgement (it waives auth for all destinations) and
//     is the opposite of CredentialRequired's hardening intent, so it is rejected
//     here. A "require credentials for ALL destinations" mode, if ever wanted,
//     gets its own correctly-named acknowledgement in a later slice — it is NOT a
//     broadExemption overload. Starting strict keeps any future relaxation a
//     non-breaking loosening.
//   - Exempt requires a destination selector OR an explicit broadExemption ack.
func validateAuthDestination(rule PolicyRule) ([]string, error) {
	// CredentialRequired and SSORequired both require a concrete destination and
	// reject broadExemption: a credential-challenge / SSO-redirect outcome is the
	// opposite of a blanket waiver, so it must be least-privilege. broadExemption
	// remains an Exempt-only acknowledgement.
	if rule.Auth.Outcome == OutcomeCredentialRequired || rule.Auth.Outcome == OutcomeSSORequired {
		if rule.Auth.BroadExemption {
			return nil, fmt.Errorf("broadExemption is an Exempt-only acknowledgement and is not valid on %s rules", rule.Auth.Outcome)
		}
		if !authRuleHasDestination(rule) {
			return nil, fmt.Errorf("%s rule requires a destination (destFQDN, destCategory, or destCategoryGroup)", rule.Auth.Outcome)
		}
		return nil, nil
	}
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

// subjectSourceBreadth classifies the source breadth of a SubjectMatch for
// operator diagnostics (Phase 1 Slice 6). anySource is true if any CIDR value is
// 0.0.0.0/0 or ::/0; wide is true if any IPv4 prefix is broader than /24. Pure;
// mirrors the breadth logic of broadSubjectWarnings without producing strings.
func subjectSourceBreadth(sm *SubjectMatch) (anySource, wide bool) {
	if sm == nil {
		return false, false
	}
	for i := range sm.All {
		if sm.All[i].Type != subjectPredicateCIDR {
			continue
		}
		for _, v := range sm.All[i].Values {
			if v == "0.0.0.0/0" || v == "::/0" {
				anySource = true
				continue
			}
			if _, ipnet, err := net.ParseCIDR(v); err == nil {
				if ones, bits := ipnet.Mask.Size(); bits == 32 && ones < 24 {
					wide = true
				}
			}
		}
	}
	return anySource, wide
}

// authExemptExpired reports whether an exempt rule's expiry has passed. A blank
// ExpiresAt is NOT expired (that "no expiry" risk is a separate diagnostic); an
// unparseable timestamp is treated as expired (consistent with the matcher's
// fail-closed expiry handling). Reuses authRuleNotExpired so the parse logic is
// shared with the resolver.
func authExemptExpired(spec *AuthRuleSpec) bool {
	return spec != nil && spec.ExpiresAt != "" && !authRuleNotExpired(spec)
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
