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

// decSeriesKey identifies one coverage series. It is a STRUCT key, not the
// "outcome\x00source\x00tlsVer" string this counter used to build: a struct key
// hashes its three fields in place, where the concatenation allocated a fresh
// 48-byte string on EVERY recorded session. See decSessionCounter.record.
type decSeriesKey struct {
	outcome string
	source  string
	tlsVer  string
}

// decSessionCounter is the hand-rolled, bounded-label counter behind
// culvert_decrypt_sessions_total. It drops the cardinality-cap folding the admin-created
// scope labels need: all three labels are closed enum sets, so the series count can never
// exceed |Outcome|·|DecisionSource|·|TLSVersion| = 144 regardless of traffic.
//
// ── Why the index is published, not locked ──────────────────────────────────
//
// record runs ONCE PER SESSION — every CONNECT tunnel that carries a decryption
// decision, which on a gateway is ~all traffic — and it used to take mu.RLock
// around the map read. A reader lock is not cheap at that position:
// sync.RWMutex.RLock/RUnlock are two atomic read-modify-writes on ONE shared
// word, so every tunnel in the process wrote the same cache line purely to read
// a map that, after the first 144 sessions, can never change again. That is not
// a constant cost but a THROUGHPUT CEILING — the same shape already found and
// fixed in hostCounter (store.go), internal/threatfeed, internal/connlimit, the
// IP filter and alerts.HasSubscriber.
//
// The series index is therefore an immutable map published through an atomic
// pointer and rebuilt copy-on-write under mu on the rare FIRST sighting of a
// series (at most 144 times in the life of the process, because the label space
// is closed). A steady-state record is one atomic pointer load, one map read on
// a stack-allocated key, and one atomic add on the series' own counter — no
// allocation and no read-modify-write on any word another tunnel also writes.
// The *decSessionLabel values are shared between the old and new maps and their
// counts are only ever touched atomically, so a concurrent record holding the
// previous map still increments the SAME counter the new map publishes.
//
// Measured on a 4-vCPU Xeon @2.10GHz, go1.27.4/linux-amd64, every arm in ONE
// invocation, -count=5, medians, against a frozen copy of the RWMutex+concat
// shape (decryption_metrics_bench_test.go — re-measure the whole set in one go
// rather than comparing a new number against the ones quoted here):
//
//	arm                           │  P=1   │  P=2   │  P=4   │ allocs/op
//	RWMutex + concat, serial       │  86 ns │  77 ns │  78 ns │  1 (48 B)
//	published + struct key, serial │  25 ns │  24 ns │  25 ns │     0
//	RWMutex + concat, one series   │  91 ns │ 161 ns │ 175 ns │  1 (48 B)
//	published + struct key, same   │  25 ns │  96 ns │ 104 ns │     0
//	RWMutex + concat, mixed        │  93 ns │ 175 ns │ 194 ns │  1 (41 B)
//	published + struct key, mixed  │  33 ns │  46 ns │  26 ns │     0
//
// "Mixed" rotates the live series the way a real fleet does (several outcomes
// and sources in flight at once) and is the shape that matters: it IMPROVES
// with core count (93 → 26 ns, 7.5x ahead of the locked form at four cores)
// where the locked form degrades (93 → 194 ns). State the floor honestly too —
// the single-series arm still rises (25 → 104 ns) because every worker then
// atomically increments the SAME counter word. That is inherent to a shared
// counter and a floor the locked form also pays (91 → 175 ns, so this shape
// stays ~1.7x ahead even there); this change removes only the lock and the
// per-call key allocation stacked on top of it.
//
// decFailures below deliberately KEEPS the locked shape: it fires only when a
// decryption attempt fails, not once per tunnel, so it is not at this position
// and has no measurement to justify changing it.
type decSessionCounter struct {
	// published is the immutable series index. Loaded lock-free by record;
	// replaced (never mutated in place) under mu. nil until the first record,
	// so the zero value is usable.
	published atomic.Pointer[map[decSeriesKey]*decSessionLabel]

	// mu guards the copy-on-write publish and order — the rare paths only.
	// record never takes it except on a series' first sighting. It is a plain
	// Mutex rather than an RWMutex deliberately: the only readers left are the
	// /metrics scrape and /api/decryption/health, which walk at most 144 series
	// and do not need to run concurrently with each other, and keeping a reader
	// lock here would invite the next edit to put record back behind it.
	mu    sync.Mutex
	order []decSeriesKey // insertion order, for stable exposition
}

var decSessions = &decSessionCounter{}

// record increments the (outcome, source, tlsVer) series. Callers pass already-bounded
// enum strings (recordDecryptSession coerces via decEnumOr), so no validation is needed
// here — the values are compile-time enum members, never raw/attacker tokens.
func (c *decSessionCounter) record(outcome, source, tlsVer string) {
	k := decSeriesKey{outcome: outcome, source: source, tlsVer: tlsVer}
	if m := c.published.Load(); m != nil {
		if ll, ok := (*m)[k]; ok {
			atomic.AddInt64(&ll.n, 1)
			return
		}
	}
	c.insert(k)
}

// insert adds k's series if the published index does not already carry it, then
// counts the observation. It runs at most once per series per process (144 times
// at the absolute maximum), so the copy of the index is not a hot-path cost.
func (c *decSessionCounter) insert(k decSeriesKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.seriesLocked()
	if ll, ok := cur[k]; ok { // re-check: a concurrent insert may have published it
		atomic.AddInt64(&ll.n, 1)
		return
	}
	next := make(map[decSeriesKey]*decSessionLabel, len(cur)+1)
	for kk, ll := range cur {
		next[kk] = ll // the label POINTER is shared, so in-flight atomic adds survive
	}
	next[k] = &decSessionLabel{outcome: k.outcome, source: k.source, tlsVer: k.tlsVer, n: 1}
	c.order = append(c.order, k)
	c.published.Store(&next)
}

// seriesLocked returns the currently published index (nil-safe). Callers must hold mu,
// or otherwise be off the mutation path — a published map is never mutated in place, so
// reading one obtained under mu stays safe after the unlock.
func (c *decSessionCounter) seriesLocked() map[decSeriesKey]*decSessionLabel {
	if m := c.published.Load(); m != nil {
		return *m
	}
	return nil
}

// writePrometheus appends the counter's series in text-exposition form. Emits nothing
// until at least one session is recorded (no zero-value noise), matching the other
// hand-rolled counters.
func (c *decSessionCounter) writePrometheus(w *strings.Builder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.order) == 0 {
		return
	}
	series := c.seriesLocked()
	w.WriteString("\n# HELP culvert_decrypt_sessions_total Decryption decisions by outcome, decision source, and negotiated TLS version (ADR-0011 coverage)\n")
	w.WriteString("# TYPE culvert_decrypt_sessions_total counter\n")
	for _, k := range c.order {
		ll := series[k]
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
	c.mu.Lock()
	defer c.mu.Unlock()
	series := c.seriesLocked()
	out := make([]decSessionSample, 0, len(c.order))
	for _, k := range c.order {
		ll := series[k]
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
	auth := AuthLogFields{RuleID: ruleID, Dec: o.toBlock(redact), AuthSource: id.AuthSource}
	// CONNECT method, "inspect" SSLAction, no bytes/duration/uri — a terminal
	// handshake failure, mirroring recordInspectBlock's block row minus the stats.
	persistLogEntry(id.ClientIP, "CONNECT", hostOnly, decFailedStatus, ruleName, "", id.Identity, 0, 0, 0, "inspect", "", auth)
}
