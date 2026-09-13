package main

// Per-request policy-decision line: the frozen `logger.Printf` baseline, the
// byte-identity proof, and the before/after measurement (Performance Guardian
// sweep, 2026-09-12; corrected 2026-09-13 after Codex review on PR #1377).
//
// WHY THIS FILE EXISTS. applyPolicyDecision emits exactly one decision line per
// proxied request, and it was the largest Culvert-owned ALLOCATION site on both
// hot paths — 7 objects per request on the HTTP forward path
// (BenchmarkPerfQual_ProxyHTTPForward, alloc_objects: 21,007 of the 41,719
// objects handleRequest allocates outside the upstream round trip, i.e. HALF
// the dispatch pipeline's own allocation) and 7 per tunnel on the CONNECT path,
// where it was 5.02% of every object the whole three-actor benchmark process
// allocated. proxy.go now assembles the line by hand instead; this file keeps
// the shape it replaced, so the comparison stays reproducible in-tree — the
// convention BenchmarkHTTPForward_LegacyClientPerRequest already follows.
//
// MEASURED (Intel Xeon @2.80GHz, 4 cores, Go 1.26, medians of 5, against a real
// log sink):
//
//	                       serial ns/op   4-core ns/op   B/op   allocs/op
//	  frozen Printf baseline    1007          441.6       128       8
//	  production (hand-built)    339.6        321.2       192       1
//	  delta                      -66%          -27%      +50%     -88%
//
// The four-core pair is measured in an isolated process (9 samples each,
// medians quoted) because both arms serialise on log.Logger's own mutex and the
// spread is wide — production 242-339 ns, baseline 352-485 ns. The serial pair
// is stable to a few percent.
//
// The B/op rise is real and is the right trade: eight 16-byte interface boxes
// (pointer-bearing, so the GC must scan every one) become one 192-byte string
// body, which is pointer-free and never scanned.
//
// THE TRAP THAT NEARLY BURIED THIS, because it is the whole reason the file
// reads the way it does. The first measurement pointed the package logger at
// io.Discard, which is what every other benchmark on this path did. log.New
// records `isDiscard = (w == io.Discard)` and Logger.output returns BEFORE
// invoking its append callback — so the Printf arm evaluated and boxed its
// arguments and then formatted NOTHING, while the hand-built arm, which
// assembles its line before Output is ever called, was charged in full. That
// reported a 24% serial win and a 7.7% parallel one, and on those numbers the
// change was written up as MEASURED AND REJECTED. It is a 66% / 27% win. A
// reviewer caught it (Codex P1, PR #1377).
//
// Two things make this worth recording rather than quietly fixing. The
// disproving measurement was already in hand and was explained away: a
// standalone fmt.Appendf of the same line measured 1117 ns against the same
// Printf's 403 ns, which is impossible if Printf formats, and it was written
// off as a benchmark artifact instead of being chased. And the direction of the
// error is the dangerous one — an io.Discard benchmark makes fmt look free, so
// it will always argue for keeping fmt.
//
// The rule, now enforced by construction on this path: benchmarks here use
// plSilentLogger (a no-op writer that is NOT that sentinel), never
// plSwapLogger(io.Discard). benchSilenceLogger (autoexclude_bench_test.go) has
// the SAME defect and is used by the end-to-end BenchmarkPerfQual_Proxy*
// harness, so every profile taken through it understates logging cost —
// recorded here as a follow-up rather than changed inside this one, since it
// moves the reported numbers of many unrelated benchmarks.
//
// WHAT DID NOT CHANGE: the emitted bytes (proven below against this frozen
// baseline, including the control characters sanitizeLog exists to scrub), and
// the CWE-117 contract — every string argument still passes through sanitizeLog
// before it is appended.
//
//	go test -run 'TestPolicyDecisionLine|TestPolicyLineQuote' .
//	go test -run '^$' -bench 'PolicyDecisionLine|PolicyLineQuote' -benchmem -count=5 .

import (
	"math/rand"
	"strconv"
	"testing"
)

// plPrintfAllowFmt is the POLICY_ALLOW format string verbatim as it stood
// before the hand-built emitters, i.e. the post-#1256 / pre-#1377 shape.
const plPrintfAllowFmt = "POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"

// plPrintfAllowLine reproduces that emitter verbatim, writing to the same
// package logger production uses. It is the baseline, never the thing under
// test — do not wire it back into applyPolicyDecision.
func plPrintfAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfAllowFmt,
		safeRule, priority, clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions),
		reqID, sanitizeLog(identity), safeRule)
}

// plPrintf runs the frozen baseline with the standard arguments, so the
// benchmarks below compare it against plCurrentAllowLine on identical inputs.
func plPrintf(rule string, priority int) {
	plPrintfAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// ── Correctness: the emitted bytes must not have changed ────────────────────

// TestPolicyDecisionLine_MatchesFrozenPrintfShape is the half that outranks
// every benchmark here. These lines are consumed by SIEM forwarders and log parsers,
// so replacing fmt with hand-assembly is only acceptable if the bytes are
// unchanged. Every verb the production emitter re-implements is exercised: %q
// over control characters, quotes, backslashes, DEL, high bytes and non-ASCII,
// and %d over negative and multi-digit priorities.
func TestPolicyDecisionLine_MatchesFrozenPrintfShape(t *testing.T) {
	priorities := []int{0, 1, 7, 42, 100, 999, 2147483647, -1, -32768}
	rules := []string{
		"corp-saas-allow",
		"",
		"rule with spaces",
		"rule\nwith\nnewlines",
		"rule\rwith\rCR",
		"rule\twith\ttabs",
		"rule\x00with\x1bcontrol",
		"ünïcode-rule-名前",
		`quotes"and\backslashes`,
		"\x7fdel-and-\x80high",
	}
	for _, rule := range rules {
		for _, pri := range priorities {
			baseline := plCapture(func() { plPrintf(rule, pri) })
			production := plCapture(func() { plCurrentAllowLine(rule, pri) })
			if baseline != production {
				t.Errorf("production POLICY_ALLOW diverged from the frozen Printf baseline for rule=%q pri=%d:\n  baseline: %q\nproduction: %q",
					rule, pri, baseline, production)
			}
		}
	}
}

// TestPolicyDecisionLine_AllBranchesMatchTheirPrintfShape covers the other three
// emitters. They are not variations on the allow line — each has its own
// separators and its own verb order — so a hand-assembly slip in any one of
// them would be invisible to the test above.
func TestPolicyDecisionLine_AllBranchesMatchTheirPrintfShape(t *testing.T) {
	const rule = "ev\nil\"rule"
	const pri = -77
	a := plArgs
	cases := []struct {
		name       string
		production func()
		baseline   func()
	}{
		{"block",
			func() { logPolicyBlock(rule, pri, a.clientIP, a.host, a.cond, a.reqID, a.identity) },
			func() {
				logger.Printf("POLICY_BLOCK rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}",
					sanitizeLog(rule), pri, a.clientIP, sanitizeLog(a.host), sanitizeLog(a.cond), a.reqID, sanitizeLog(a.identity), sanitizeLog(rule))
			}},
		{"drop",
			func() { logPolicyDrop(rule, pri, a.clientIP, a.host, a.cond, a.reqID, a.identity) },
			func() {
				logger.Printf("POLICY_DROP rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}",
					sanitizeLog(rule), pri, a.clientIP, sanitizeLog(a.host), sanitizeLog(a.cond), a.reqID, sanitizeLog(a.identity), sanitizeLog(rule))
			}},
		{"redirect",
			func() { logPolicyRedirect(rule, pri, a.clientIP, a.host, a.redirectURL, a.cond, a.reqID, a.identity) },
			func() {
				logger.Printf("POLICY_REDIRECT rule=%q pri=%d %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}",
					sanitizeLog(rule), pri, a.clientIP, sanitizeLog(a.host), sanitizeLog(a.redirectURL), sanitizeLog(a.cond), a.reqID, sanitizeLog(a.identity), sanitizeLog(rule))
			}},
	}
	for _, tc := range cases {
		if got, want := plCapture(tc.production), plCapture(tc.baseline); got != want {
			t.Errorf("%s: production diverged from its Printf shape:\n  want: %q\n   got: %q", tc.name, want, got)
		}
	}
}

// TestPolicyLineQuote_FastPathMatchesStrconv pins production's appendQuotedLog
// against strconv.AppendQuote itself — the oracle, and the same function fmt's
// %q calls, so the two cannot drift if a future Go release changes what %q
// renders. Every single byte value is covered exhaustively (alone, and embedded
// between two ASCII bytes so the fast path is entered and then has to bail out
// mid-string), plus randomised strings drawn from a byte-weighted alphabet that
// straddles the printable-ASCII boundary the fast path keys on.
func TestPolicyLineQuote_FastPathMatchesStrconv(t *testing.T) {
	check := func(s string) {
		t.Helper()
		want := string(strconv.AppendQuote(nil, s))
		got := string(appendQuotedLog(nil, s))
		if want != got {
			t.Fatalf("quoting diverged for %q: strconv %q, production %q", s, want, got)
		}
	}
	for _, s := range []string{"", "a", "corp-saas-allow", "files.example.com", "ünïcode-名前", `q"b\s`} {
		check(s)
	}
	for i := 0; i < 256; i++ {
		b := string([]byte{byte(i)})
		check(b)
		check("x" + b + "y")
		check(b + "trailing")
	}
	rng := rand.New(rand.NewSource(0x9E3779B9)) //nolint:gosec // deterministic test corpus, not security material
	for i := 0; i < 20000; i++ {
		buf := make([]byte, rng.Intn(24))
		for j := range buf {
			// Weighted toward the boundary bytes the fast path decides on.
			// Each arm draws strictly below 256, so plByte cannot truncate.
			switch rng.Intn(4) {
			case 0:
				buf[j] = plByte(rng.Intn(0x20)) // control
			case 1:
				buf[j] = plByte(0x20 + rng.Intn(0x5f)) // printable ASCII
			default:
				buf[j] = plByte(rng.Intn(256)) // anything, incl. invalid UTF-8
			}
		}
		check(string(buf))
	}
}

// plByte narrows a value the caller has already bounded to [0,256) — the
// conversion is checked here rather than suppressed at each call site, so the
// bound is asserted rather than asserted-in-a-comment.
func plByte(v int) byte {
	if v < 0 || v > 0xff {
		panic("plByte: value out of range")
	}
	return byte(v)
}

// ── Before vs after, in one run ─────────────────────────────────────────────
//
// Both shapes are timed in the same process on the same hardware, so the
// comparison is reproducible in-tree rather than a pair of numbers from a
// commit message.
//
// Both use plSilentLogger, never io.Discard — see the header. The parallel pair
// is the one production experiences: a gateway serves many requests at once and
// log.Logger serialises internally on its own mutex.

func BenchmarkPolicyDecisionLine_PrintfBaseline(b *testing.B) {
	defer plSilentLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plPrintf(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_PrintfBaselineParallel(b *testing.B) {
	defer plSilentLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plPrintf(plRule, plPriority)
		}
	})
}

// ── The quoting cost, isolated ──────────────────────────────────────────────
//
// Two short pure-ASCII strings — a rule name and a hostname, exactly what the
// two quoted values on the decision line receive.

func BenchmarkPolicyLineQuote_Strconv(b *testing.B) {
	var arr [256]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		x := strconv.AppendQuote(arr[:0], plRule)
		benchQuoteSink = len(strconv.AppendQuote(x, plArgs.host))
	}
}

func BenchmarkPolicyLineQuote_FastPath(b *testing.B) {
	var arr [256]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		x := appendQuotedLog(arr[:0], plRule)
		benchQuoteSink = len(appendQuotedLog(x, plArgs.host))
	}
}

var benchQuoteSink int
