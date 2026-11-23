package main

// socks5_policy_shadow.go — SWG-901 stage 2: NON-ENFORCING Stage-2 policy
// evaluation of SOCKS5 destinations ("shadow").
//
// Owner Decision 4 (roadmap/VERIFICATION-PROGRAM.md) puts SOCKS5 inside the
// managed security boundary in stages; this file is stage 2 only. In shadow
// mode a SOCKS5 CONNECT that has passed every existing gate (admission, auth,
// canonicalization, blocklist, plugin) is evaluated through the SAME Stage-2
// matcher HTTP/CONNECT uses — PolicyStore.matchAccessRule, the non-accounting
// half of PolicyStore.Evaluate (ADR-0026 §4) — and the verdict is recorded as
// evidence only:
//
//   - culvert_socks5_policy_decisions_total{mode,verdict,reason}
//   - culvert_socks5_requests_total{atyp}
//   - a rate-limited "SOCKS5 POLICY_WOULD_BLOCK" log line
//
// What shadow mode deliberately does NOT do:
//
//   - It never changes the connection's outcome. The verdict is computed and
//     discarded; the handler continues to the SSRF guard and dial exactly as in
//     legacy mode. Enforcement is stage 4 and is not selectable.
//   - It charges no policy accounting: no rule hit counters, no last-hit stamp,
//     no ruleMet (Prometheus rule hits), no request-log entry, no statBlocked.
//     Owner D4 chose log + metric as the evidence channel; a request-log status
//     would touch the SIEM/UI taxonomy.
//   - It does not resolve an identity. SOCKS5 has no shared credential resolver
//     yet (stage 3): the existing USER/PASS check returns only a bool. Every
//     shadow evaluation therefore runs as identity "" / authSource "unauth" /
//     no groups, for NO-AUTH and USER/PASS clients alike. Identity-, group- and
//     auth-source-scoped rules do not match a SOCKS5 client in shadow (and an
//     "unauth"-scoped rule matches even a USER/PASS client), so the shadow
//     verdict is NOT a parity claim for such rulebases. The log line carries
//     auth_source=unauth so nobody reads it as one.
//
// Legacy mode (the default; the key absent) performs no evaluation, counts
// nothing and logs nothing new: socks5ShadowPolicy returns on its first
// statement and the metric families are not emitted at all.
//
// GUI parity: socks5_policy_mode is a STARTUP-ONLY YAML key
// (proxy.socks5_policy_mode), a recorded GUI-parity deferral in the same class
// as the SOCKS5 listener itself (proxy.socks5_port / -socks5-port, which also
// has no runtime admin surface): it selects whether a startup-only listener is
// observed, and a runtime toggle would need the config-versioning, snapshot
// and CP→DP decisions the SWG-901 proposal (§6.4, D2) leaves to the enforce
// stage. The selected mode is surfaced read-only by the presence of the metric
// families above and by one startup log line; there is no write verb.

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// socks5PolicyMode selects how SOCKS5 destinations meet Stage-2 policy. The
// zero value is legacy, so an unset state can never mean "evaluate".
type socks5PolicyMode int32

const (
	socks5PolicyLegacy socks5PolicyMode = iota // no Stage-2 evaluation (today's behaviour)
	socks5PolicyShadow                         // evaluate, record, never enforce
)

// socks5PolicyModeKey is the YAML key, as operators write it.
const socks5PolicyModeKey = "proxy.socks5_policy_mode"

// parseSOCKS5PolicyMode resolves the YAML value. Absent ("") is legacy, so an
// existing config is byte-identical. "enforce" is refused by name rather than
// as an unknown value: it is the documented next stage, and an operator who
// writes it must be told it does not exist yet instead of getting a typo error
// — and must never be silently downgraded to a mode that does not block.
func parseSOCKS5PolicyMode(raw string) (socks5PolicyMode, error) {
	switch raw {
	case "", "legacy":
		return socks5PolicyLegacy, nil
	case "shadow":
		return socks5PolicyShadow, nil
	case "enforce":
		return socks5PolicyLegacy, fmt.Errorf("%s: \"enforce\" is not available in this release (SWG-901 stage 4); use \"legacy\" or \"shadow\"", socks5PolicyModeKey)
	}
	return socks5PolicyLegacy, fmt.Errorf("%s: must be \"legacy\" or \"shadow\", got %q", socks5PolicyModeKey, raw)
}

// socks5PolicyModeState holds the installed mode. Written once at startup
// (installSOCKS5PolicyMode, before the listener binds) and by tests; read on
// every SOCKS5 CONNECT. Atomic so a test that flips it never races a handler.
var socks5PolicyModeState atomic.Int32

// validateSOCKS5PolicyMode rejects an unknown proxy.socks5_policy_mode — and
// "enforce", which is not available yet — at load, so a typo can never leave
// an operator believing SOCKS5 is observed or enforced when it is not.
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
// already passed FileConfig.validate, so a parse error here is a wiring bug
// and fails closed to legacy — the mode that changes nothing — after saying so.
// Only a non-legacy mode logs, so a legacy install's startup output is
// unchanged.
func installSOCKS5PolicyMode(raw string, listenerConfigured bool) {
	mode, err := parseSOCKS5PolicyMode(raw)
	if err != nil {
		logger.Printf("SOCKS5 policy mode: %q; staying in legacy mode", sanitizeLog(err.Error()))
	}
	setSOCKS5PolicyMode(mode)
	if mode != socks5PolicyShadow {
		return
	}
	if !listenerConfigured {
		logger.Printf("SOCKS5 policy mode: shadow is configured but the SOCKS5 listener is disabled; it has no effect")
		return
	}
	logger.Printf("SOCKS5 policy mode: shadow — destinations are evaluated against Stage-2 policy and NEVER refused by it; " +
		"evaluated as auth_source=unauth (identity/group rules cannot match SOCKS5 until stage 3)")
}

// Shadow verdict and reason labels. Bounded by construction: these constants
// are the only values the counters below are indexed by.
const (
	socks5VerdictAllow      = "allow"
	socks5VerdictWouldBlock = "would_block"
	socks5ReasonRule        = "rule"
	socks5ReasonDefault     = "default"
)

// socks5ShadowAuthSource is the auth source every shadow evaluation uses. It is
// what HTTP stamps when no credentials were presented (proxy.go), and it is the
// honest value here: SOCKS5 resolves no identity until stage 3.
const socks5ShadowAuthSource = "unauth"

// socks5ShadowResult is one shadow verdict. rule is the matched PUBLISHED
// definition (nil when the default action decided); read-only.
type socks5ShadowResult struct {
	verdict string
	reason  string
	rule    *PolicyRule
}

// socks5ShadowEvaluate computes the Stage-2 verdict the CONNECT path would
// reach for this destination, without charging it. It is the shadow path's
// ONLY contact with the policy engine and takes the matcher from
// PolicyStore.matchAccessRule, i.e. the same snapshot, scan index and core
// Evaluate uses; the differential test pins verdict equality against the
// CONNECT dispatcher.
//
// host is the SOCKS5 wire form; IPv6 brackets are stripped so the evaluator
// sees what CONNECT's SplitHostPort hands it for the same destination.
func socks5ShadowEvaluate(clientIP, host string) socks5ShadowResult {
	rule := policyStore.matchAccessRule(clientIP, "", socks5ShadowAuthSource, socks5PolicyHost(host), nil)
	return classifySOCKS5Shadow(rule, defaultPolicyActionState.Load()&1 == 1)
}

// classifySOCKS5Shadow maps a match onto the verdict applyPolicyDecision would
// dispatch for a CONNECT: an Allow rule (or an empty action, which canonicalizes
// to Allow) proceeds; Drop, Block_Page, Redirect and an UNKNOWN action
// (SEC-POLICYACTION-1, fail closed) refuse; no match follows the default action.
func classifySOCKS5Shadow(rule *PolicyRule, defaultAllow bool) socks5ShadowResult {
	if rule == nil {
		if defaultAllow {
			return socks5ShadowResult{verdict: socks5VerdictAllow, reason: socks5ReasonDefault}
		}
		return socks5ShadowResult{verdict: socks5VerdictWouldBlock, reason: socks5ReasonDefault}
	}
	if action, known := canonicalPolicyAction(rule.Action); known && action == ActionAllow {
		return socks5ShadowResult{verdict: socks5VerdictAllow, reason: socks5ReasonRule, rule: rule}
	}
	return socks5ShadowResult{verdict: socks5VerdictWouldBlock, reason: socks5ReasonRule, rule: rule}
}

// socks5PolicyHost is the port-less, bracket-free destination the Stage-2
// evaluator expects (the form HTTP/CONNECT passes after SplitHostPort). The
// FQDN matcher would strip the brackets itself via normalizeHost, but the geo
// condition reads the RAW host (geo.LookupCached), so the evaluator must be
// handed exactly the CONNECT form, not one that happens to normalize the same.
func socks5PolicyHost(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// socks5ShadowPolicy is the handler's single shadow hook. In legacy mode it
// returns on its first statement — no evaluation, no counter, no log. In
// shadow mode it records the verdict and RETURNS NOTHING: the caller has no
// value it could branch on, which is how "shadow never blocks" is made
// structural rather than a convention.
func socks5ShadowPolicy(clientIP, host string, atyp byte) {
	if loadSOCKS5PolicyMode() != socks5PolicyShadow {
		return
	}
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
	res := socks5ShadowEvaluate(clientIP, host)
	noteSOCKS5ShadowDecision(res)
	if res.verdict == socks5VerdictWouldBlock && socks5WouldBlockLogAllowed() {
		logSOCKS5WouldBlock(clientIP, host, res)
	}
}

// logSOCKS5WouldBlock emits the sampled evidence line. host is raw client
// bytes (SEC-SOCKS5-LOG-1) and the rule fields sit inside the {} block, so all
// of them are sanitised; it is walled in socks5_log_injection_test.go exactly
// like handleSOCKS5.
func logSOCKS5WouldBlock(clientIP, host string, res socks5ShadowResult) {
	if res.rule == nil {
		logger.Printf("SOCKS5 POLICY_WOULD_BLOCK %s -> %q {mode=shadow reason=default default_action=deny auth_source=unauth action_taken=none}",
			clientIP, sanitizeLog(host))
		return
	}
	logger.Printf("SOCKS5 POLICY_WOULD_BLOCK %s -> %q {mode=shadow reason=rule rule=%q rule_id=%q action=%q auth_source=unauth action_taken=none}",
		clientIP, sanitizeLog(host), sanitizeLogFieldToken(res.rule.Name), sanitizeLogFieldToken(res.rule.ID), sanitizeLogFieldToken(string(res.rule.Action)))
}

// ── Evidence counters ───────────────────────────────────────────────────────

// SOCKS5 ATYP wire values (RFC 1928 §4).
const (
	socks5ATYPIPv4   byte = 0x01
	socks5ATYPDomain byte = 0x03
	socks5ATYPIPv6   byte = 0x04
)

var (
	// socks5ShadowDecisions is indexed [verdict][reason]: allow/would_block ×
	// rule/default. Four cells, so the label set is bounded by the array.
	socks5ShadowDecisions [2][2]atomic.Int64
	// socks5ShadowATYP is indexed ipv4/ipv6/domain.
	socks5ShadowATYP [3]atomic.Int64
)

func noteSOCKS5ShadowDecision(res socks5ShadowResult) {
	v, r := 0, 0
	if res.verdict == socks5VerdictWouldBlock {
		v = 1
	}
	if res.reason == socks5ReasonDefault {
		r = 1
	}
	socks5ShadowDecisions[v][r].Add(1)
}

func noteSOCKS5RequestATYP(atyp byte) {
	switch atyp {
	case socks5ATYPIPv4:
		socks5ShadowATYP[0].Add(1)
	case socks5ATYPIPv6:
		socks5ShadowATYP[1].Add(1)
	case socks5ATYPDomain:
		socks5ShadowATYP[2].Add(1)
	}
}

// writeSOCKS5PolicyShadowMetrics emits the shadow evidence families, and ONLY
// in shadow mode: on a legacy node the series are absent, not zero, so a
// dashboard can tell "not evaluated" from "evaluated, nothing would block".
func writeSOCKS5PolicyShadowMetrics(w io.Writer) {
	if loadSOCKS5PolicyMode() != socks5PolicyShadow {
		return
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_socks5_policy_decisions_total SOCKS5 CONNECT requests evaluated against Stage-2 policy, by mode and verdict; shadow verdicts are never enforced and are evaluated as auth_source=unauth
# TYPE culvert_socks5_policy_decisions_total counter
culvert_socks5_policy_decisions_total{mode="shadow",verdict="allow",reason="rule"} %d
culvert_socks5_policy_decisions_total{mode="shadow",verdict="allow",reason="default"} %d
culvert_socks5_policy_decisions_total{mode="shadow",verdict="would_block",reason="rule"} %d
culvert_socks5_policy_decisions_total{mode="shadow",verdict="would_block",reason="default"} %d

# HELP culvert_socks5_requests_total SOCKS5 CONNECT requests that reached Stage-2 policy evaluation, by destination address type
# TYPE culvert_socks5_requests_total counter
culvert_socks5_requests_total{atyp="ipv4"} %d
culvert_socks5_requests_total{atyp="ipv6"} %d
culvert_socks5_requests_total{atyp="domain"} %d
`,
		socks5ShadowDecisions[0][0].Load(), socks5ShadowDecisions[0][1].Load(),
		socks5ShadowDecisions[1][0].Load(), socks5ShadowDecisions[1][1].Load(),
		socks5ShadowATYP[0].Load(), socks5ShadowATYP[1].Load(), socks5ShadowATYP[2].Load(),
	)
}

// ── Log rate gate ───────────────────────────────────────────────────────────

// socks5WouldBlockLogWindowNanos is the minimum spacing between two
// POLICY_WOULD_BLOCK lines. The line is SAMPLED evidence — the decisions
// counter is the exact total — so one line per second is enough to name the
// rules and destinations involved without letting a client that loops on a
// would-block destination write the log at its own rate. Atomic so a test can
// shrink it while handlers run.
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
