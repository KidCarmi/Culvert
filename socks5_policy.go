package main

// socks5_policy.go — SWG-901: Stage-2 policy for SOCKS5 destinations.
//
// Owner Decision 4 (roadmap/VERIFICATION-PROGRAM.md) puts SOCKS5 inside the
// managed security boundary. A SOCKS5 CONNECT that has passed every earlier
// gate (posture, connection limit, admission, authentication through the shared
// credential resolver, canonicalization, blocklist, threat feed, plugin) meets
// Stage-2 policy here, at the position CONNECT meets it: after the pre-dispatch
// blocks, before the SSRF guard and dial. The evaluator is the CONNECT
// evaluator — PolicyStore.Evaluate, or its non-accounting half
// PolicyStore.matchAccessRule in shadow (ADR-0026 §4) — with the principal the
// shared resolver produced (identity, groups, auth source; "unauth" for a
// NO-AUTH client), so identity-, group- and auth-source-scoped rules match
// SOCKS5 clients exactly as they match the same credential over HTTP.
//
// proxy.socks5_policy_mode selects how the verdict is used:
//
//   - legacy (the default; the key absent): no Stage-2 evaluation, no new
//     counter, no new log line. Kept only for the integration period; making
//     enforce the default and deleting legacy is a separate, later step (the
//     owner decides when). Deleting it removes one switch arm in
//     socks5ApplyPolicy, one parse case and its tests — nothing else exists to
//     serve it.
//   - shadow: evaluate and record, NEVER refuse on policy. Charges no policy
//     accounting (no rule hit counters, last-hit stamp, ruleMet, request-log
//     entry or statBlocked). Evidence: culvert_socks5_policy_decisions_total,
//     culvert_socks5_requests_total and a rate-limited SOCKS5
//     POLICY_WOULD_BLOCK line. socks5ShadowPolicy returns nothing, which is how
//     "shadow never refuses" is structural rather than a convention.
//   - enforce: the verdict decides (socks5_policy_enforce.go). It is the real
//     decision path, so it charges rule accounting and writes request-log
//     entries the way the CONNECT dispatcher (applyPolicyDecision) does.
//
// What SOCKS5 cannot honour is refused, never downgraded: an Allow rule that
// requires TLS inspection (SSLAction Inspect) would be served by CONNECT as an
// inspected tunnel, and SOCKS5 has no inspection path, so it is refused with
// reason inspection_unsupported (owner direction 2026-11-23, superseding
// proposal decision D5). The only exceptions are the GENERIC ones that already
// turn a CONNECT inspection into a raw tunnel — the operator's explicit SSL
// bypass list and a fail-open decryption profile's learned exclusion — because
// enforce asks resolveSSLDecision, the CONNECT function, whether the tunnel
// would be inspected. No SOCKS5-specific exception exists.
//
// The threat feed and the blocklist are NOT Stage-2 policy: they apply in every
// mode (socks5ContentBlocked, socks5.go).
//
// GUI parity: socks5_policy_mode is a STARTUP-ONLY YAML key
// (proxy.socks5_policy_mode), a recorded GUI-parity deferral in the same class
// as the SOCKS5 listener itself (proxy.socks5_port / -socks5-port, which also
// has no runtime admin surface): it selects how a startup-only listener is
// governed, and a runtime toggle would need config-versioning, snapshot and
// CP→DP decisions for a setting whose end state is a single mode (enforce)
// with no toggle at all. The selected mode is surfaced read-only by the
// mode label of the metric families below and by one startup log line; there
// is no write verb.

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// socks5PolicyMode selects how SOCKS5 destinations meet Stage-2 policy. The
// zero value is legacy, so an unset state can never mean "evaluate".
type socks5PolicyMode int32

const (
	socks5PolicyLegacy  socks5PolicyMode = iota // no Stage-2 evaluation (integration period only)
	socks5PolicyShadow                          // evaluate, record, never enforce
	socks5PolicyEnforce                         // the Stage-2 verdict decides
)

// socks5PolicyModeKey is the YAML key, as operators write it.
const socks5PolicyModeKey = "proxy.socks5_policy_mode"

// parseSOCKS5PolicyMode resolves the YAML value. Absent ("") is legacy. Values
// are case-sensitive, like every other enum key in config.yaml.
//
// TRANSITIONAL (owner direction 2026-11-23). The mode setting, "legacy" and
// "shadow" exist only to validate enforcement before it becomes unconditional.
// Removal criteria, in order: (1) the SWG-901 parity harness
// (socks5_parity_test.go: policy, threat-feed and identity differentials with
// their negative controls) and an end-to-end SOCKS5 verification are green on
// main; (2) "enforce" becomes the default here ("" → socks5PolicyEnforce);
// (3) in a later release "legacy" is deleted — this case, its arm in
// socks5ApplyPolicy and its tests — and, once shadow has served its purpose,
// the key itself, leaving SOCKS5 always enforced. Nothing else in the tree
// exists to serve legacy. Not done in the branch that introduced enforce.
func parseSOCKS5PolicyMode(raw string) (socks5PolicyMode, error) {
	switch raw {
	case "", "legacy":
		return socks5PolicyLegacy, nil
	case "shadow":
		return socks5PolicyShadow, nil
	case "enforce":
		return socks5PolicyEnforce, nil
	}
	return socks5PolicyLegacy, fmt.Errorf("%s: must be \"legacy\", \"shadow\" or \"enforce\", got %q", socks5PolicyModeKey, raw)
}

// socks5PolicyModeState holds the installed mode. Written once at startup
// (installSOCKS5PolicyMode, before the listener binds) and by tests; read on
// every SOCKS5 CONNECT. Atomic so a test that flips it never races a handler.
var socks5PolicyModeState atomic.Int32

// validateSOCKS5PolicyMode rejects an unknown proxy.socks5_policy_mode at
// load, so a typo can never leave an operator believing SOCKS5 is observed or
// enforced when it is not.
func (fc *FileConfig) validateSOCKS5PolicyMode() []string {
	if _, err := parseSOCKS5PolicyMode(fc.Proxy.SOCKS5PolicyMode); err != nil {
		return []string{err.Error()}
	}
	return nil
}

func setSOCKS5PolicyMode(m socks5PolicyMode) { socks5PolicyModeState.Store(int32(m)) }

func loadSOCKS5PolicyMode() socks5PolicyMode {
	return socks5PolicyMode(socks5PolicyModeState.Load())
}

// installSOCKS5PolicyMode installs the configured mode at startup. raw has
// already passed FileConfig.validate, so a parse error here is a wiring bug;
// it is logged and the mode stays legacy, which is today's default. Only a
// non-legacy mode logs, so a legacy install's startup output is unchanged.
func installSOCKS5PolicyMode(raw string, listenerConfigured bool) {
	mode, err := parseSOCKS5PolicyMode(raw)
	if err != nil {
		logger.Printf("SOCKS5 policy mode: %q; staying in legacy mode", sanitizeLog(err.Error()))
	}
	setSOCKS5PolicyMode(mode)
	if mode == socks5PolicyLegacy {
		return
	}
	if !listenerConfigured {
		logger.Printf("SOCKS5 policy mode: %s is configured but the SOCKS5 listener is disabled; it has no effect", socks5ModeLabel(mode))
		return
	}
	if mode == socks5PolicyShadow {
		logger.Printf("SOCKS5 policy mode: shadow — destinations are evaluated against Stage-2 policy and NEVER refused by it")
		return
	}
	logger.Printf("SOCKS5 policy mode: enforce — destinations are decided by Stage-2 policy (the CONNECT evaluator and default action); " +
		"rules that require TLS inspection are refused (inspection_unsupported)")
}

// socks5ModeLabel is the bounded label for a non-legacy mode.
func socks5ModeLabel(m socks5PolicyMode) string {
	if m == socks5PolicyEnforce {
		return "enforce"
	}
	return "shadow"
}

// socks5Grant is what an ALLOWED connection carries to its request-log entries:
// the matched rule (enforce Allow by rule only) and the attribution the CONNECT
// allow branch records. Zero in legacy and shadow, which attribute no rule.
type socks5Grant struct {
	match       *PolicyMatch
	ruleMatched string
	actionTaken string
}

// socks5ApplyPolicy is handleSOCKS5's single Stage-2 hook. It returns the grant
// and true when the connection may proceed to the SSRF guard and dial; false
// means it has already refused the connection (reply or RST, request log) and
// the caller must return.
func socks5ApplyPolicy(conn net.Conn, who ProxyIdentity, host string, atyp byte) (socks5Grant, bool) {
	switch loadSOCKS5PolicyMode() {
	case socks5PolicyLegacy:
		return socks5Grant{}, true
	case socks5PolicyShadow:
		// Called as a bare statement: it has no result to branch on.
		socks5ShadowPolicy(who, host, atyp)
		return socks5Grant{}, true
	default: // socks5PolicyEnforce — and fail closed on any value parse cannot produce
		return socks5EnforcePolicy(conn, who, host, atyp)
	}
}

// Verdict reason labels. Bounded by construction: these constants are the only
// values the counters below are indexed by.
const (
	socks5ReasonRule       = "rule"
	socks5ReasonDefault    = "default"
	socks5ReasonInspection = "inspection_unsupported"
)

// socks5Verdict is one Stage-2 verdict. rule is the matched rule (nil when the
// default action decided); read-only.
type socks5Verdict struct {
	refuse bool
	reason string
	rule   *PolicyRule
}

// classifySOCKS5Policy maps a match onto the verdict applyPolicyDecision would
// dispatch for a CONNECT: an Allow rule (or an empty action, which
// canonicalizes to Allow) proceeds; Drop, Block_Page, Redirect and an UNKNOWN
// action (SEC-POLICYACTION-1, fail closed) refuse; no match follows the default
// action. The inspection refusal is layered on by the caller, which knows
// whether it may charge the SSL decision.
func classifySOCKS5Policy(rule *PolicyRule, defaultAllow bool) socks5Verdict {
	if rule == nil {
		return socks5Verdict{refuse: !defaultAllow, reason: socks5ReasonDefault}
	}
	if action, known := canonicalPolicyAction(rule.Action); known && action == ActionAllow {
		return socks5Verdict{reason: socks5ReasonRule, rule: rule}
	}
	return socks5Verdict{refuse: true, reason: socks5ReasonRule, rule: rule}
}

// socks5PolicyHost is the port-less, bracket-free destination the Stage-2
// evaluator, the SSL decision and the threat feed expect (the form
// HTTP/CONNECT passes after SplitHostPort). The FQDN matcher would strip the
// brackets itself via normalizeHost, but the geo condition reads the RAW host
// (geo.LookupCached), so the evaluator must be handed exactly the CONNECT
// form, not one that happens to normalize the same.
func socks5PolicyHost(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// defaultPolicyAllows reads the process-wide default action (one load of the
// packed word), the same read applyPolicyDecision makes.
func defaultPolicyAllows() bool { return defaultPolicyActionState.Load()&1 == 1 }

// ── Shadow ──────────────────────────────────────────────────────────────────

// socks5ShadowEvaluate computes the verdict enforce would reach for this
// destination, without charging it: PolicyStore.matchAccessRule (the same
// snapshot, scan index and core Evaluate uses) with the resolved principal.
//
// The inspection prediction is socks5RuleWouldInspect, not resolveSSLDecision:
// the latter charges the fail-open exclusion cache's hit counters and logs
// bypass lines. So shadow can over-report inspection_unsupported for a host a
// fail-open decryption profile has learned to exclude — the conservative
// direction. Rule matching itself is exactly enforce's.
func socks5ShadowEvaluate(who ProxyIdentity, host string) socks5Verdict {
	policyHost := socks5PolicyHost(host)
	rule := policyStore.matchAccessRule(who.ClientIP, who.Identity, who.AuthSource, policyHost, who.Groups)
	v := classifySOCKS5Policy(rule, defaultPolicyAllows())
	if !v.refuse && rule != nil && socks5RuleWouldInspect(rule.SSLAction, policyHost) {
		v.refuse, v.reason = true, socks5ReasonInspection
	}
	return v
}

// socks5RuleWouldInspect is the side-effect-free part of resolveSSLDecision: a
// rule asking for inspection is inspected unless the operator's explicit SSL
// bypass list names the host.
func socks5RuleWouldInspect(action SSLAction, host string) bool {
	return action == SSLInspect && !sslBypass.Matches(host)
}

// socks5ShadowPolicy records the shadow verdict and RETURNS NOTHING: the caller
// has no value it could branch on.
func socks5ShadowPolicy(who ProxyIdentity, host string, atyp byte) {
	// A panic in the evaluator must not become the one way shadow changes an
	// outcome: unrecovered here it would unwind into handleSOCKS5's
	// recoverGoroutine and close a connection legacy mode would have served.
	// It is recorded (crash counter, throttled audit/log — no destination
	// bytes) and the connection proceeds unevaluated.
	defer func() {
		if v := recover(); v != nil {
			recordCrash("socks5-policy-shadow", "", v)
		}
	}()
	noteSOCKS5RequestATYP(atyp)
	v := socks5ShadowEvaluate(who, host)
	noteSOCKS5PolicyDecision(socks5PolicyShadow, v)
	if v.refuse && socks5WouldBlockLogAllowed() {
		logSOCKS5WouldBlock(who, host, v)
	}
}

// logSOCKS5WouldBlock emits the sampled evidence line. host is raw client
// bytes (SEC-SOCKS5-LOG-1) and every other value sits inside the {} block, so
// all of them are sanitised; it is walled in socks5_log_injection_test.go
// exactly like handleSOCKS5.
func logSOCKS5WouldBlock(who ProxyIdentity, host string, v socks5Verdict) {
	clientIP := who.ClientIP
	if v.rule == nil {
		logger.Printf("SOCKS5 POLICY_WOULD_BLOCK %s -> %q {mode=shadow reason=default default_action=deny identity=%s auth_source=%s action_taken=none}",
			clientIP, sanitizeLog(host), sanitizeLogFieldToken(who.Identity), sanitizeLogFieldToken(who.AuthSource))
		return
	}
	logger.Printf("SOCKS5 POLICY_WOULD_BLOCK %s -> %q {mode=shadow reason=%s rule=%q rule_id=%q action=%q identity=%s auth_source=%s action_taken=none}",
		clientIP, sanitizeLog(host), sanitizeLogFieldToken(v.reason), sanitizeLogFieldToken(v.rule.Name), sanitizeLogFieldToken(v.rule.ID),
		sanitizeLogFieldToken(string(v.rule.Action)), sanitizeLogFieldToken(who.Identity), sanitizeLogFieldToken(who.AuthSource))
}

// ── Evidence counters ───────────────────────────────────────────────────────

// SOCKS5 ATYP wire values (RFC 1928 §4).
const (
	socks5ATYPIPv4   byte = 0x01
	socks5ATYPDomain byte = 0x03
	socks5ATYPIPv6   byte = 0x04
)

var (
	// socks5PolicyDecisions is indexed [mode][refused][reason]: shadow/enforce
	// × allow/refuse × rule/default/inspection_unsupported. The array bounds
	// the label set; allow × inspection_unsupported is unreachable and never
	// emitted.
	socks5PolicyDecisions [2][2][3]atomic.Int64
	// socks5PolicyATYP is indexed ipv4/ipv6/domain.
	socks5PolicyATYP [3]atomic.Int64
)

func socks5ReasonIndex(reason string) int {
	switch reason {
	case socks5ReasonDefault:
		return 1
	case socks5ReasonInspection:
		return 2
	}
	return 0
}

func noteSOCKS5PolicyDecision(mode socks5PolicyMode, v socks5Verdict) {
	m := 0
	if mode == socks5PolicyEnforce {
		m = 1
	}
	r := 0
	if v.refuse {
		r = 1
	}
	socks5PolicyDecisions[m][r][socks5ReasonIndex(v.reason)].Add(1)
}

func noteSOCKS5RequestATYP(atyp byte) {
	switch atyp {
	case socks5ATYPIPv4:
		socks5PolicyATYP[0].Add(1)
	case socks5ATYPIPv6:
		socks5PolicyATYP[1].Add(1)
	case socks5ATYPDomain:
		socks5PolicyATYP[2].Add(1)
	}
}

// writeSOCKS5PolicyMetrics emits the SOCKS5 policy families, and ONLY in shadow
// or enforce mode: on a legacy node the series are absent, not zero, so a
// dashboard can tell "not evaluated" from "evaluated, nothing refused". The
// mode is startup-only, so only the installed mode's series are emitted; the
// refusal verdict reads would_block in shadow (nothing was refused) and block
// in enforce.
func writeSOCKS5PolicyMetrics(w io.Writer) {
	mode := loadSOCKS5PolicyMode()
	if mode == socks5PolicyLegacy {
		return
	}
	m, refused := 0, "would_block"
	if mode == socks5PolicyEnforce {
		m, refused = 1, "block"
	}
	label := socks5ModeLabel(mode)
	d := &socks5PolicyDecisions[m]
	_, _ = fmt.Fprintf(w, `# HELP culvert_socks5_policy_decisions_total SOCKS5 CONNECT requests evaluated against Stage-2 policy, by mode, verdict and reason; shadow verdicts are never enforced
# TYPE culvert_socks5_policy_decisions_total counter
culvert_socks5_policy_decisions_total{mode="%[1]s",verdict="allow",reason="rule"} %[3]d
culvert_socks5_policy_decisions_total{mode="%[1]s",verdict="allow",reason="default"} %[4]d
culvert_socks5_policy_decisions_total{mode="%[1]s",verdict="%[2]s",reason="rule"} %[5]d
culvert_socks5_policy_decisions_total{mode="%[1]s",verdict="%[2]s",reason="default"} %[6]d
culvert_socks5_policy_decisions_total{mode="%[1]s",verdict="%[2]s",reason="inspection_unsupported"} %[7]d

# HELP culvert_socks5_requests_total SOCKS5 CONNECT requests that reached Stage-2 policy evaluation, by destination address type
# TYPE culvert_socks5_requests_total counter
culvert_socks5_requests_total{atyp="ipv4"} %[8]d
culvert_socks5_requests_total{atyp="ipv6"} %[9]d
culvert_socks5_requests_total{atyp="domain"} %[10]d
`,
		label, refused,
		d[0][0].Load(), d[0][1].Load(),
		d[1][0].Load(), d[1][1].Load(), d[1][2].Load(),
		socks5PolicyATYP[0].Load(), socks5PolicyATYP[1].Load(), socks5PolicyATYP[2].Load(),
	)
}

// ── Log rate gate (shadow) ──────────────────────────────────────────────────

// socks5WouldBlockLogWindowNanos is the minimum spacing between two
// POLICY_WOULD_BLOCK lines. The line is SAMPLED evidence — the decisions
// counter is the exact total — so one line per second is enough to name the
// rules and destinations involved without letting a client that loops on a
// would-block destination write the log at its own rate. Atomic so a test can
// shrink it while handlers run.
//
// Enforce refusals are not sampled: like every CONNECT refusal they are
// decisions, written to the request log and the process log once each.
var socks5WouldBlockLogWindowNanos atomic.Int64

// socks5WouldBlockLogLast is the UnixNano of the last emitted line (0 = none).
var socks5WouldBlockLogLast atomic.Int64

func init() { socks5WouldBlockLogWindowNanos.Store(int64(time.Second)) }

// socks5WouldBlockLogAllowed reports whether this would-block may log, arming
// the window when it does. Same lock-free shape as noteOversizeHostLog: the
// suppressed path is one load and a compare, the CAS picks one winner per
// window, and a clock that went backwards re-arms rather than suppressing.
func socks5WouldBlockLogAllowed() bool {
	now := time.Now().UnixNano()
	last := socks5WouldBlockLogLast.Load()
	if last != 0 {
		if d := now - last; d >= 0 && d < socks5WouldBlockLogWindowNanos.Load() {
			return false
		}
	}
	return socks5WouldBlockLogLast.CompareAndSwap(last, now)
}
