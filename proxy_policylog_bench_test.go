package main

// Per-request policy-decision log-line cost (Performance Guardian).
//
// applyPolicyDecision emits exactly one decision line per proxied request
// (POLICY_ALLOW / POLICY_BLOCK / POLICY_DROP / POLICY_REDIRECT). Profiling the
// end-to-end forward benchmark (BenchmarkPerfQual_ProxyHTTPForward, alloc_objects)
// attributed 65,538 of the 99,878 objects handleRequest allocates OUTSIDE the
// upstream round trip to that single line's argument construction — roughly two
// thirds of the dispatch pipeline's own allocation, before any policy, auth or
// transport work is counted.
//
// ROUND 1 removed two allocations that were pure waste (an fmt.Sprintf over an
// int and a duplicated sanitizeLog call); see the contract comment above
// logPolicyAllow in proxy.go. Round 1's own profile then showed the line STILL
// holding the largest Culvert-owned allocation site on both hot paths — 7
// objects per request, 51% of the dispatch pipeline's own allocations on the
// plain-HTTP forward path and the #1 site on the CONNECT path too — because the
// remaining cost is not waste inside the arguments but fmt's variadic interface
// itself: nine boxed arguments plus reflective verb dispatch.
//
// ROUND 2 (this file's current baseline) renders the line by appending into a
// pooled buffer and hands the logger ONE argument. See "Decision-line
// rendering" in proxy.go for the measurement table and the three contracts.
//
// ── THE SINK MATTERS, AND GETTING IT WRONG MEASURED NOTHING ──────────────────
//
// These benchmarks used to swap in io.Discard. log.Logger carries an isDiscard
// fast path: when its writer IS io.Discard, Printf returns BEFORE calling
// fmt.Appendf at all. So the pre-round-2 figures (≈310 ns/op for the production
// allow line) were the cost of BOXING NINE ARGUMENTS AND THROWING THEM AWAY,
// with the formatting step — the larger half — never executed. Against a real
// sink the same shape costs ≈1040 ns/op. A baseline that skips the work being
// optimised understates the win and, worse, would have made an append-based
// rewrite look like a REGRESSION (it does its rendering unconditionally, so it
// cannot benefit from the same short circuit).
//
// Every benchmark and gate here therefore writes to plSink, which counts bytes
// and is deliberately NOT io.Discard. TestPolicyDecisionLine_BenchSinkReachesFmt
// pins that, so the trap cannot return silently.
//
// EVERYTHING BELOW MEASURES THE PRODUCTION FUNCTIONS. logPolicyAllow and its
// siblings are the real emitters applyPolicyDecision calls, so a change that
// reintroduces an allocation on the request path shows up here and in the gate.
// The exceptions are plLegacyAllowLine and the plFmt* replicas, which freeze the
// two PRE-CHANGE shapes so the before/after comparison stays reproducible
// in-tree on any runner — the convention BenchmarkHTTPForward_LegacyClientPerRequest
// already follows. They are baselines, never the thing under test.
//
//	go test -run '^$' -bench 'BenchmarkPolicyDecisionLine' -benchmem -count=6 .

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
)

// Representative arguments: an ordinary allowed request through a named rule.
// Nothing here carries a control character, which is the overwhelmingly common
// case and therefore the one worth measuring.
const (
	plRule     = "corp-saas-allow"
	plPriority = 100
	plClientIP = "203.0.113.7"
	plMethod   = "GET"
	plHost     = "files.example.com"
	plCond     = "fqdn,category"
	plReqID    = "0123456789abcdef"
	plIdentity = "alice@corp.example.com"
)

// plLegacyAllowFmt is the POLICY_ALLOW format string verbatim as it stood
// before ROUND 1. It differs from the round-1 one in exactly one verb:
// pri=%s (a pre-rendered string) became pri=%d (the int itself), which
// TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb pins.
const plLegacyAllowFmt = "POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"

// The four format strings verbatim as they stood after ROUND 1 and before
// ROUND 2 — the fmt shape the append-based emitters replace. Frozen here so the
// differential tests and the gate's control compare against real code rather
// than against a prose claim about it.
const (
	plFmtAllow    = "POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"
	plFmtDrop     = "POLICY_DROP rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}"
	plFmtBlock    = "POLICY_BLOCK rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}"
	plFmtRedirect = "POLICY_REDIRECT rule=%q pri=%d %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}"
)

// plLegacyAllowLine reproduces the pre-ROUND-1 argument construction verbatim,
// writing to the same package logger the production emitter uses.
//
// It takes the SAME parameter list as logPolicyAllow, and that is load-bearing
// rather than cosmetic. An earlier draft referenced the pl* constants directly
// inside the function body; Go boxes a constant into an interface at compile
// time into read-only data, so every one of those arguments went into the
// Printf argument list for free. That understated BOTH shapes and, worse,
// understated them UNEQUALLY once the production side started receiving runtime
// values as parameters — comparing a constant-folded baseline against a real
// one would have made the fix look like a regression. Both sides now receive
// identical runtime strings.
func plLegacyAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	logger.Printf(plLegacyAllowFmt,
		sanitizeLog(rule),
		strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", ""),
		clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions),
		reqID, sanitizeLog(identity), sanitizeLog(rule))
}

// The four plFmt*Line replicas are the ROUND-1 emitters verbatim: one
// logger.Printf per line, sanitize-once on the rule name, %d on the priority.
// They are what the append-based production emitters must render identically.

func plFmtAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtAllow, safeRule, priority, clientIP, method,
		sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtDropLine(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtDrop, safeRule, priority, clientIP,
		sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtBlockLine(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtBlock, safeRule, priority, clientIP,
		sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtRedirectLine(rule string, priority int, clientIP, host, redirectURL, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtRedirect, safeRule, priority, clientIP, sanitizeLog(host),
		sanitizeLog(redirectURL), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

// plArgs is the representative argument set, held in variables rather than used
// as constants at the call sites so the boxing cost is measured, not folded away.
var plArgs = struct{ clientIP, method, host, cond, reqID, identity, redirectURL string }{
	plClientIP, plMethod, plHost, plCond, plReqID, plIdentity, "https://portal.example.com/blocked",
}

// plLegacy runs the frozen pre-ROUND-1 shape with the standard arguments.
func plLegacy(rule string, priority int) {
	plLegacyAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// plFmtShape runs the frozen pre-ROUND-2 (fmt) allow shape.
func plFmtShape(rule string, priority int) {
	plFmtAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// plCurrentAllowLine calls the PRODUCTION emitter with the same inputs.
func plCurrentAllowLine(rule string, priority int) {
	logPolicyAllow(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// plSink is the benchmark log destination: a real writer, so log.Logger's
// isDiscard fast path cannot skip the formatting step the benchmarks exist to
// measure (see the header). It counts bytes so the sink itself is observable,
// and does no I/O — production's sink is asynchronous anyway (internal/logsink),
// so what these benchmarks measure is the work the REQUEST goroutine performs.
type plSink struct{ n int64 }

func (s *plSink) Write(p []byte) (int, error) { s.n += int64(len(p)); return len(p), nil }

// plSwapLogger points the package logger at w and returns a restore func.
func plSwapLogger(w io.Writer) func() {
	prev := logger
	logger = log.New(w, "", 0)
	return func() { logger = prev }
}

// plSwapSink is plSwapLogger against a fresh plSink — the only destination
// benchmarks and gates in this file may use.
func plSwapSink() func() { return plSwapLogger(&plSink{}) }

// ── Before vs after ─────────────────────────────────────────────────────────
//
// Three shapes, all timed against the same real sink in the same run so the
// comparison is machine-independent: the pre-ROUND-1 form, the fmt form ROUND 2
// replaces, and production.

func BenchmarkPolicyDecisionLine_Legacy(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plLegacy(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_FmtShape(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plFmtShape(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Current(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plCurrentAllowLine(plRule, plPriority)
	}
}

// ── Concurrency ─────────────────────────────────────────────────────────────
//
// A gateway serves many requests at once, so the figure that matters is the
// per-op cost when every core is emitting a decision line simultaneously.
// log.Logger serialises internally on its own mutex, which is what production
// does too, so these numbers include that contention — the same for both shapes,
// so the comparison stays honest. The render buffer comes from a sync.Pool,
// which is per-P and adds no shared lock of its own.

func BenchmarkPolicyDecisionLine_FmtShapeParallel(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plFmtShape(plRule, plPriority)
		}
	})
}

func BenchmarkPolicyDecisionLine_CurrentParallel(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plCurrentAllowLine(plRule, plPriority)
		}
	})
}

// ── The other three decision lines ──────────────────────────────────────────
//
// Block and drop are the branches that run hottest under a scanning or
// beaconing flood, so they are measured too rather than assumed to match.

func BenchmarkPolicyDecisionLine_Block(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Drop(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyDrop(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Redirect(b *testing.B) {
	defer plSwapSink()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyRedirect(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.redirectURL, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

// ── Isolated: the priority rendering alone ──────────────────────────────────

func BenchmarkPolicyPriority_LegacySprintf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = strings.ReplaceAll(fmt.Sprintf("%d", plPriority), "\n", "")
	}
}

// ── Correctness: the rendered line must not change ──────────────────────────

// plCapture runs fn with the package logger redirected into a buffer and
// returns what was written.
func plCapture(fn func()) string {
	var buf strings.Builder
	restore := plSwapLogger(&buf)
	fn()
	restore()
	return buf.String()
}

// plDivergenceRules are the rule-name / host / identity shapes worth probing:
// the ordinary case, the empty string, quoting and escaping edges, the control
// characters sanitizeLog exists to scrub, and non-ASCII.
var plDivergenceRules = []string{
	"corp-saas-allow",
	"",
	"rule with spaces",
	"rule\nwith\nnewlines",
	"rule\rwith\rCR",
	"rule\twith\ttabs",
	"rule\x00with\x1bcontrol",
	"ünïcode-rule-名前",
	`quotes"and\backslashes`,
	"percent %s %d %q verbs",
	"\x7f\x1f boundary bytes",
	strings.Repeat("long-", 120) + "tail",
}

var plDivergencePriorities = []int{0, 1, 7, 42, 100, 999, 2147483647, -1, -32768, -2147483648}

// TestPolicyDecisionLine_RenderIsByteIdentical is the half that outranks every
// benchmark here. The decision lines are consumed by SIEM forwarders and log
// parsers, so this change is only acceptable if the emitted bytes are unchanged.
// It compares production against the PRE-ROUND-1 shape, so it spans BOTH cost
// changes this line has had: %d on an int emits exactly the digits
// fmt.Sprintf("%d", …) produced and the ReplaceAll it fed could never match,
// and appending emits exactly what fmt's verbs emit.
func TestPolicyDecisionLine_RenderIsByteIdentical(t *testing.T) {
	for _, rule := range plDivergenceRules {
		for _, pri := range plDivergencePriorities {
			legacy := plCapture(func() { plLegacy(rule, pri) })
			current := plCapture(func() { plCurrentAllowLine(rule, pri) })
			if legacy != current {
				t.Errorf("rendered line diverged for rule=%q pri=%d:\n legacy: %q\ncurrent: %q",
					rule, pri, legacy, current)
			}
		}
	}
}

// TestPolicyDecisionLine_AllEmittersMatchTheirFmtShape is the ROUND-2
// differential: each of the FOUR production emitters against the fmt replica it
// replaces, over every divergence shape, in every string position.
//
// It exists because the equivalence ROUND 2 rests on is a claim about fmt's
// verbs — that %q on a string IS strconv.AppendQuote, %d on an int IS
// strconv.AppendInt base 10, and %s on a string is the bytes themselves. That
// claim is true of the fmt this tree builds against; pinning it here means a
// future fmt or strconv change fails CI instead of quietly rewriting the log
// format that SIEM parsers depend on. The previous round's test covered the
// allow line only, which would have left three emitters unproven.
func TestPolicyDecisionLine_AllEmittersMatchTheirFmtShape(t *testing.T) {
	for _, v := range plDivergenceRules {
		for _, pri := range plDivergencePriorities {
			// Drive the variable shape through every string position in turn,
			// so a misplaced separator in one field cannot hide behind a
			// constant value in another.
			cases := []struct {
				name            string
				production, fmt func()
			}{
				{"allow", func() { logPolicyAllow(v, pri, plArgs.clientIP, plArgs.method, v, v, plArgs.reqID, v) },
					func() { plFmtAllowLine(v, pri, plArgs.clientIP, plArgs.method, v, v, plArgs.reqID, v) }},
				{"drop", func() { logPolicyDrop(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) },
					func() { plFmtDropLine(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) }},
				{"block", func() { logPolicyBlock(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) },
					func() { plFmtBlockLine(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) }},
				{"redirect", func() { logPolicyRedirect(v, pri, plArgs.clientIP, v, v, v, plArgs.reqID, v) },
					func() { plFmtRedirectLine(v, pri, plArgs.clientIP, v, v, v, plArgs.reqID, v) }},
			}
			for _, tc := range cases {
				want := plCapture(tc.fmt)
				got := plCapture(tc.production)
				if want != got {
					t.Fatalf("%s line diverged for value=%q pri=%d:\n   fmt: %q\nappend: %q",
						tc.name, v, pri, want, got)
				}
			}
		}
	}
}

// FuzzPolicyDecisionLine drives the same differential with arbitrary bytes in
// every string field. A hand-picked matrix covers the shapes we thought of;
// this covers the ones we did not.
func FuzzPolicyDecisionLine(f *testing.F) {
	f.Add("corp-saas-allow", 100, "files.example.com", "fqdn,category", "alice@corp", "https://p/x")
	f.Add("", 0, "", "", "", "")
	f.Add("a\nb", -1, "\x00", "\x7f", `"\`, "%s%d")
	f.Fuzz(func(t *testing.T, rule string, pri int, host, cond, identity, redirect string) {
		pairs := []struct {
			name            string
			production, ref func()
		}{
			{"allow", func() { logPolicyAllow(rule, pri, plArgs.clientIP, plArgs.method, host, cond, plArgs.reqID, identity) },
				func() { plFmtAllowLine(rule, pri, plArgs.clientIP, plArgs.method, host, cond, plArgs.reqID, identity) }},
			{"drop", func() { logPolicyDrop(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity) },
				func() { plFmtDropLine(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity) }},
			{"block", func() { logPolicyBlock(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity) },
				func() { plFmtBlockLine(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity) }},
			{"redirect", func() { logPolicyRedirect(rule, pri, plArgs.clientIP, host, redirect, cond, plArgs.reqID, identity) },
				func() { plFmtRedirectLine(rule, pri, plArgs.clientIP, host, redirect, cond, plArgs.reqID, identity) }},
		}
		for _, p := range pairs {
			want := plCapture(p.ref)
			got := plCapture(p.production)
			if want != got {
				t.Fatalf("%s line diverged:\n   fmt: %q\nappend: %q", p.name, want, got)
			}
		}
	})
}

// TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb pins the claim the
// pre-ROUND-1 equivalence test rests on: the fmt-shape format string is the
// legacy template with pri=%s replaced by pri=%d. Read out of the emitted bytes
// rather than compared as strings, so it tracks the frozen replicas rather than
// a prose claim about them.
func TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb(t *testing.T) {
	// A priority whose rendering is unmistakable in the output.
	const pri = 4242
	got := plCapture(func() { plCurrentAllowLine(plRule, pri) })
	want := plCapture(func() {
		logger.Printf(strings.Replace(plLegacyAllowFmt, "pri=%s", "pri=%d", 1),
			sanitizeLog(plRule), pri, plClientIP, plMethod, sanitizeLog(plHost),
			sanitizeLog(plCond), plReqID, sanitizeLog(plIdentity), sanitizeLog(plRule))
	})
	if got != want {
		t.Errorf("production POLICY_ALLOW line is not the legacy template with pri=%%s -> pri=%%d:\n  want: %q\n   got: %q", want, got)
	}
}

// TestPolicyDecisionLine_SanitizesTheRuleNameOnBothOccurrences pins that
// sanitizing the rule name ONCE and using it twice is not a shortcut that
// weakens the CWE-117 guarantee: a rule name carrying newlines must come out
// scrubbed in BOTH the leading rule=%q and the trailing rule=%s, and the whole
// line must stay on one physical line.
func TestPolicyDecisionLine_SanitizesTheRuleNameOnBothOccurrences(t *testing.T) {
	emitters := map[string]func(){
		"allow":    func() { logPolicyAllow("ev\nil", 1, plClientIP, plMethod, plHost, plCond, plReqID, plIdentity) },
		"block":    func() { logPolicyBlock("ev\nil", 1, plClientIP, plHost, plCond, plReqID, plIdentity) },
		"drop":     func() { logPolicyDrop("ev\nil", 1, plClientIP, plHost, plCond, plReqID, plIdentity) },
		"redirect": func() { logPolicyRedirect("ev\nil", 1, plClientIP, plHost, "https://x/", plCond, plReqID, plIdentity) },
	}
	for name, emit := range emitters {
		out := strings.TrimSuffix(plCapture(emit), "\n")
		if strings.Contains(out, "\n") {
			t.Errorf("%s: emitted line was split across physical lines (log forging): %q", name, out)
		}
		if strings.Contains(out, "ev\nil") {
			t.Errorf("%s: raw newline survived into the line: %q", name, out)
		}
		if n := strings.Count(out, "ev_il"); n != 2 {
			t.Errorf("%s: want the sanitized rule name twice (rule=%%q and the trailing rule=%%s), got %d in %q", name, n, out)
		}
	}
}

// TestPolicyDecisionLine_UnquotedFieldsStillCarryTheSanitiser is the reason
// strconv.AppendQuote is not treated as a substitute for sanitizeLog. Two of
// the values on every line — the matched conditions and the identity — are
// emitted UNQUOTED, so nothing but sanitizeLog stands between a newline in
// either of them and a forged log record.
func TestPolicyDecisionLine_UnquotedFieldsStillCarryTheSanitiser(t *testing.T) {
	const forged = "x\nPOLICY_ALLOW rule=\"forged\" pri=1"
	cases := map[string]func(){
		"conditions": func() { logPolicyAllow(plRule, 1, plClientIP, plMethod, plHost, forged, plReqID, plIdentity) },
		"identity":   func() { logPolicyAllow(plRule, 1, plClientIP, plMethod, plHost, plCond, plReqID, forged) },
	}
	for field, emit := range cases {
		out := strings.TrimSuffix(plCapture(emit), "\n")
		if strings.Contains(out, "\n") {
			t.Errorf("%s: a newline reached the log sink unscrubbed — the line was forged: %q", field, out)
		}
	}
}

// TestPolicyDecisionLine_BenchSinkReachesFmt pins the trap described in this
// file's header. log.Logger short-circuits Printf entirely when its writer IS
// io.Discard, so a benchmark using io.Discard measures argument boxing and
// nothing else — which is how the pre-ROUND-2 baseline understated the fmt
// shape by ~3x and would have reported an append-based rewrite as a regression.
//
// The assertion is that plSink receives the WHOLE rendered line, not merely a
// non-zero write: the expected length is taken from plCapture of the same
// emitters, so the gate fails both if the sink is swapped back to io.Discard
// (nothing arrives) and if some future short circuit delivered a truncated or
// unformatted line to a real writer.
func TestPolicyDecisionLine_BenchSinkReachesFmt(t *testing.T) {
	emit := func() {
		plCurrentAllowLine(plRule, plPriority)
		plFmtShape(plRule, plPriority)
		plLegacy(plRule, plPriority)
	}
	want := int64(len(plCapture(emit)))

	sink := &plSink{}
	restore := plSwapLogger(sink)
	emit()
	restore()

	if sink.n != want {
		t.Fatalf("plSink received %d bytes, want %d: the benchmark sink is short-circuiting or truncating "+
			"the logger, so every figure in this file measures argument construction only — see the header",
			sink.n, want)
	}
}

// TestPolicyDecisionLine_PooledBufferIsNotSharedAcrossEmits is the concurrency
// half. The render buffer now comes from a sync.Pool, so a buffer that were
// returned to the pool before the logger finished with it, or handed to two
// emitters at once, would interleave two requests' decision lines — mixing one
// client's destination into another's audit record.
//
// Every goroutine emits a line whose rule name identifies it, then the captured
// output is checked line by line: each physical line must be internally
// consistent (its two rule= occurrences must agree) and there must be exactly
// as many lines as emissions. Run under -race this also covers the buffer
// handoff itself.
func TestPolicyDecisionLine_PooledBufferIsNotSharedAcrossEmits(t *testing.T) {
	const goroutines, each = 8, 200

	var mu sync.Mutex
	var buf strings.Builder
	restore := plSwapLogger(&lockedWriter{mu: &mu, w: &buf})
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rule := fmt.Sprintf("rule-%d-%s", g, strings.Repeat("x", g*7))
			for i := 0; i < each; i++ {
				logPolicyAllow(rule, g, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
			}
		}(g)
	}
	wg.Wait()
	restore()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != goroutines*each {
		t.Fatalf("got %d physical lines, want %d — a render buffer was reused before the logger was done with it",
			len(lines), goroutines*each)
	}
	for _, ln := range lines {
		// Every line names its rule twice — `rule="NAME"` near the front and
		// `rule=NAME action=allow}` at the end. Bytes from two emissions in one
		// buffer would leave those disagreeing, so requiring the line to END
		// with the suffix its OWN leading name implies checks the whole span
		// between them in one assertion.
		quoted := plFieldBetween(ln, `rule="`, `"`)
		if quoted == "" || !strings.HasSuffix(ln, " rule="+quoted+" action=allow}") {
			t.Fatalf("line is internally inconsistent (two requests' bytes interleaved): %q", ln)
		}
	}
}

// lockedWriter serialises writes so the test observes whole lines; production's
// serialisation is log.Logger's own mutex, which a strings.Builder does not have.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func plFieldBetween(s, openTok, closeTok string) string {
	i := strings.Index(s, openTok)
	if i < 0 {
		return ""
	}
	rest := s[i+len(openTok):]
	j := strings.Index(rest, closeTok)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
