package main

// decryption_metrics.go — ADR-0011 Phase 2 (Metrics): the decryption coverage counter.
//
// culvert_decrypt_sessions_total counts every decryption DECISION once per session,
// labelled by the bounded (outcome, decision_source, tls_version) enums. It is the
// coverage series operators alert on ("what fraction of TLS is actually inspected, and
// why is the rest bypassed"). All three labels are CLOSED enum sets (6 × 8 × 3 = 144 max
// combinations), so — unlike autoExcludeLearns, whose scope label is admin-created — this
// counter needs NO cardinality cap: the label space is bounded by construction, and every
// label value is coerced through decEnumOr so only in-vocabulary tokens ever reach a label.
//
// Wiring (exactly once per session): recordDecryptSession is called from the session-
// terminal points — recordTunnelCloseGatedDec (bypass / learned-bypass / rescue /
// non-TLS-fallback all pass a non-nil DecryptionOutcome there), handleTunnelInspect
// (the inspect-success path, which logs per-inner-request and never reaches the close
// seam), and recordDecryptFailureEntry (every FAILED attempt: the origin/client
// handshake failures AND the pre-handshake tcp_connect failure), which pairs the
// coverage count with the culvert_decrypt_failures_total taxonomy.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decSessionLabel is one (outcome, decision_source, tls_version) series with its count.
type decSessionLabel struct {
	outcome string
	source  string
	tlsVer  string
	n       int64
}

// decSessionCounter is the hand-rolled, bounded-label counter behind
// culvert_decrypt_sessions_total. It mirrors autoExcludeLearnCounter's shape (RWMutex +
// insertion-ordered series) but drops the cardinality-cap folding: all three labels are
// closed enum sets, so the series count can never exceed |Outcome|·|DecisionSource|·
// |TLSVersion| = 144 regardless of traffic.
type decSessionCounter struct {
	mu     sync.RWMutex
	counts map[string]*decSessionLabel
	order  []string
}

var decSessions = &decSessionCounter{counts: make(map[string]*decSessionLabel)}

// record increments the (outcome, source, tlsVer) series. Callers pass already-bounded
// enum strings (recordDecryptSession coerces via decEnumOr), so no validation is needed
// here — the values are compile-time enum members, never raw/attacker tokens.
func (c *decSessionCounter) record(outcome, source, tlsVer string) {
	k := outcome + "\x00" + source + "\x00" + tlsVer
	c.mu.RLock()
	ll, ok := c.counts[k]
	c.mu.RUnlock()
	if ok {
		atomic.AddInt64(&ll.n, 1)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ll, ok = c.counts[k]; ok { // double-check after upgrading the lock
		atomic.AddInt64(&ll.n, 1)
		return
	}
	c.counts[k] = &decSessionLabel{outcome: outcome, source: source, tlsVer: tlsVer, n: 1}
	c.order = append(c.order, k)
}

// writePrometheus appends the counter's series in text-exposition form. Emits nothing
// until at least one session is recorded (no zero-value noise), matching the other
// hand-rolled counters.
func (c *decSessionCounter) writePrometheus(w *strings.Builder) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.order) == 0 {
		return
	}
	w.WriteString("\n# HELP culvert_decrypt_sessions_total Decryption decisions by outcome, decision source, and negotiated TLS version (ADR-0011 coverage)\n")
	w.WriteString("# TYPE culvert_decrypt_sessions_total counter\n")
	for _, k := range c.order {
		ll := c.counts[k]
		fmt.Fprintf(w, "culvert_decrypt_sessions_total{outcome=%q,decision_source=%q,tls_version=%q} %d\n",
			ll.outcome, ll.source, ll.tlsVer, atomic.LoadInt64(&ll.n))
	}
}

// decSessionSample is one coverage series in structured (JSON-friendly) form.
type decSessionSample struct {
	Outcome    string `json:"outcome"`
	Source     string `json:"decision_source"`
	TLSVersion string `json:"tls_version"`
	Count      int64  `json:"count"`
}

// snapshot returns a copy of every coverage series. Safe to call concurrently with
// record; used by the /api/decryption/health aggregate (read path, off the hot path).
func (c *decSessionCounter) snapshot() []decSessionSample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]decSessionSample, 0, len(c.order))
	for _, k := range c.order {
		ll := c.counts[k]
		out = append(out, decSessionSample{ll.outcome, ll.source, ll.tlsVer, atomic.LoadInt64(&ll.n)})
	}
	return out
}

// recordDecryptSession increments the coverage counter once per session from a finalized
// DecryptionOutcome. Labels pass through decEnumOr so an unset/cast enum coerces to its
// sentinel (never "" or a raw token) — the same bounded-label guard toBlock uses, keeping
// the metric vocabulary closed even if a future caller under-populates the struct. A nil
// outcome (the non-decryption tunnel closes — WebSocket / SOCKS5 — that pass no dec block)
// is a no-op: those are not decryption decisions and must not inflate coverage.
func recordDecryptSession(o *DecryptionOutcome) {
	if o == nil {
		return
	}
	decSessions.record(
		decEnumOr(o.Outcome, decryptobs.OutcomeNotDecrypted),
		decEnumOr(o.DecisionSource, decryptobs.DecisionNonTLSFallback),
		decEnumOr(o.TLSVersion, decryptobs.TLSVersionUnknown),
	)
}

// decFailureLabel is one (fail_category, fail_stage) failure series with its count.
type decFailureLabel struct {
	category string
	stage    string
	n        int64
}

// decFailureCounter backs culvert_decrypt_failures_total{fail_category,fail_stage}. Like
// decSessions it needs no cardinality cap: both labels are closed enum sets (10 categories
// × 7 stages = 70 max series). It is the failure-taxonomy counter — the "why did decryption
// fail" breakdown operators triage from (PAN-OS Decryption Error-Index parity).
type decFailureCounter struct {
	mu     sync.RWMutex
	counts map[string]*decFailureLabel
	order  []string
}

var decFailures = &decFailureCounter{counts: make(map[string]*decFailureLabel)}

func (c *decFailureCounter) record(category, stage string) {
	k := category + "\x00" + stage
	c.mu.RLock()
	ll, ok := c.counts[k]
	c.mu.RUnlock()
	if ok {
		atomic.AddInt64(&ll.n, 1)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ll, ok = c.counts[k]; ok {
		atomic.AddInt64(&ll.n, 1)
		return
	}
	c.counts[k] = &decFailureLabel{category: category, stage: stage, n: 1}
	c.order = append(c.order, k)
}

func (c *decFailureCounter) writePrometheus(w *strings.Builder) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.order) == 0 {
		return
	}
	w.WriteString("\n# HELP culvert_decrypt_failures_total Decryption failures by normalized category and lifecycle stage (ADR-0011; PAN-OS Error-Index parity)\n")
	w.WriteString("# TYPE culvert_decrypt_failures_total counter\n")
	for _, k := range c.order {
		ll := c.counts[k]
		fmt.Fprintf(w, "culvert_decrypt_failures_total{fail_category=%q,fail_stage=%q} %d\n",
			ll.category, ll.stage, atomic.LoadInt64(&ll.n))
	}
}

// decFailureSample is one failure series in structured (JSON-friendly) form.
type decFailureSample struct {
	Category string `json:"fail_category"`
	Stage    string `json:"fail_stage"`
	Count    int64  `json:"count"`
}

// snapshot returns a copy of every failure series. Safe to call concurrently with record.
func (c *decFailureCounter) snapshot() []decFailureSample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]decFailureSample, 0, len(c.order))
	for _, k := range c.order {
		ll := c.counts[k]
		out = append(out, decFailureSample{ll.category, ll.stage, atomic.LoadInt64(&ll.n)})
	}
	return out
}

// recordDecryptFailure records a FAILED decryption session: it counts the failure
// taxonomy (culvert_decrypt_failures_total) AND the coverage total (outcome=failed) — the
// two are always paired at a failure site, so this is the single call the inspect failure
// paths make. Labels pass through decEnumOr so the vocabulary stays closed. nil is a no-op.
func recordDecryptFailure(o *DecryptionOutcome) {
	if o == nil {
		return
	}
	recordDecryptSession(o) // a failed session also counts toward coverage
	decFailures.record(
		decEnumOr(o.FailCategory, decryptobs.FailCategoryOther),
		decEnumOr(o.FailStage, decryptobs.FailStageUpstreamHandshake),
	)
}

// decFailedStatus is the request-log status stamped on a decryption-handshake
// failure feed row. It has no explicit LevelForStatus case, so it maps to ERROR
// (the default) — landing the row in the feed's "Auth & Errors" tab, where a
// decryption error belongs.
const decFailedStatus = "DECRYPT_FAILED"

// recordDecryptFailureEntry records a FAILED decryption BOTH to the taxonomy
// metric (recordDecryptFailure — coverage + culvert_decrypt_failures_total) AND
// as a request-log feed row carrying the ADR-0011 dec block, so the Decryption
// Health "view sessions → failed" drill-down resolves to the offending sessions
// instead of an empty feed (the per-session record projection deferred from the
// metrics slice). The row is written LOG-ONLY via persistLogEntry — NOT through
// the recordRequest* fan-out — because the CONNECT was already stats-counted at
// POLICY_ALLOW time; re-running recordStats would double-count statTotal for the
// same tunnel (same reasoning as recordTunnelCloseGatedDec's log-only close).
// A decryption failure is an ERROR, so — like a block — it is written
// UNCONDITIONALLY, never gated by the rule's log-traffic flag: an operator must
// see decryption errors regardless of quiet-rule settings. hostOnly/SNI are
// projected under the §4 redaction posture via toBlock(redact). nil is a no-op.
func recordDecryptFailureEntry(o *DecryptionOutcome, id ProxyIdentity, hostOnly string, match *PolicyMatch, redact bool) {
	recordDecryptFailure(o) // metric + coverage (unchanged; nil-tolerant)
	if o == nil {
		return
	}
	ruleName, ruleID := "", ""
	if match != nil && match.Rule != nil {
		ruleName = match.Rule.Name
		ruleID = match.Rule.ID
	}
	auth := AuthLogFields{RuleID: ruleID, Dec: o.toBlock(redact)}
	// CONNECT method, "inspect" SSLAction, no bytes/duration/uri — a terminal
	// handshake failure, mirroring recordInspectBlock's block row minus the stats.
	persistLogEntry(id.ClientIP, "CONNECT", hostOnly, decFailedStatus, ruleName, "", id.Identity, 0, 0, 0, "inspect", "", auth)
}
