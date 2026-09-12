package main

// Per-request policy-decision line: the REJECTED alternative, frozen with its
// measurements (Performance Guardian sweep, 2026-09-12).
//
// WHY THIS FILE EXISTS. applyPolicyDecision emits exactly one decision line per
// proxied request, and profiling says it is the single largest Culvert-owned
// ALLOCATION site on both hot paths — 7 objects per request on the HTTP forward
// path (BenchmarkPerfQual_ProxyHTTPForward, alloc_objects: 21,007 of the 41,719
// objects handleRequest allocates outside the upstream round trip, i.e. HALF the
// dispatch pipeline's own allocation) and 7 per tunnel on the CONNECT path,
// where it is 5.02% of every object the whole three-actor benchmark process
// allocates. Nothing else Culvert owns on either path comes close.
//
// That makes "stop paying fmt's interface boxing — hand-roll the line into a
// byte buffer" the obvious next move, and PR #1256 already took the easy half of
// it (10 -> 8 allocs). It was built, measured, and REJECTED. The alternative is
// kept here, byte-identical and benchmarked head to head in the same run,
// because the number is the only thing that stops it being re-derived: it looks
// like a clear win right up until you measure the axis that matters.
//
// MEASURED (Intel Xeon @2.80GHz, 4 cores, Go 1.26, medians of 5):
//
//	                      serial ns/op   4-core ns/op   B/op   allocs/op
//	  production (Printf)     412.9          160.3       128       8
//	  hand-rolled + fast %q   315.2          148.0       192       1
//	  delta                    -24%           -7.7%     +50%      -88%
//
// WHY IT WAS REJECTED, in one line: the allocation count collapses and almost
// nothing else moves, because fmt was never the cost.
//
// Decomposing the production line accounts for essentially all of its ~400ns in
// work that BOTH shapes must do:
//
//	  sanitizeLog x4                       128 ns   (the CWE-117 scrubs)
//	  strconv.AppendQuote x2 (the two %q)  232 ns   (fmt's %q calls this too)
//	  ------------------------------------------
//	  shared, unavoidable                  360 ns
//	  everything fmt adds on top            ~40 ns  <- the 8 allocations
//
// So the eight interface boxes cost about 40ns between them. Removing all of
// them cannot buy more than that, and the hand-rolled shape spends most of the
// saving straight back: log.Logger.Printf appends via fmt.Appendf DIRECTLY into
// the logger's reused internal buffer, whereas a hand-rolled builder must
// materialise its own []byte and then convert it to a string for Logger.Output
// — one extra copy, and one 192-byte object where there were eight 16-byte ones.
// Object count is down 88%; allocated BYTES are up 50%, and byte rate is what
// drives GC frequency. Under the 4-core parallel load a gateway actually runs,
// the two shapes are 7% apart.
//
// Against that: four security-relevant emitters would trade a readable format
// string for ~60 lines of manual appends, and the CWE-117 sanitiser convention
// (see the Code Conventions note on sanitizeLog) would move off the
// logger.Printf shape CodeQL's go/log-injection query is known to accept here.
// That is a real risk for a ~7% parallel gain on a line that is itself 7.5% of
// the dispatch pipeline's CPU. Not a trade this codebase makes.
//
// WHAT IS WORTH KEEPING is the third row of the decomposition: strconv.AppendQuote
// costs 232ns to quote two short pure-ASCII strings, and a one-pass fast path
// does it in 36ns — 6.4x — because appendQuotedWith decodes and IsPrint-tests
// rune by rune and appends one rune at a time even when nothing needs escaping.
// It is measured here so the number is on record for any future caller that
// quotes on a hot path with its own buffer. It is deliberately NOT wired into
// production: reaching it requires the hand-rolled emitter above, which is the
// thing being rejected.
//
//	go test -run 'TestPolicyDecisionLine_HandRolled|TestPolicyLineQuote' .
//	go test -run '^$' -bench 'PolicyDecisionLine|PolicyLineQuote' -benchmem -count=5 .

import (
	"io"
	"math/rand"
	"strconv"
	"testing"
)

// plNeedsQuoteEscape reports whether strconv.AppendQuote would render any byte
// of s as something other than itself — i.e. whether the fast path below is
// unsafe. Any byte outside printable ASCII disqualifies the whole string: a
// non-ASCII byte may begin a multi-byte rune that AppendQuote escapes (or an
// invalid sequence it renders as \xNN), and deciding that per rune is exactly
// the work the fast path exists to skip.
func plNeedsQuoteEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return true
		}
	}
	return false
}

// plAppendQuoted is strconv.AppendQuote with a single-pass fast path for the
// overwhelmingly common input: a short, printable-ASCII rule name or hostname
// carrying nothing that needs escaping, whose quoted form is just the string
// between two quote bytes. Anything else falls through to strconv, so the
// output is strconv's by construction on every input the fast path declines.
func plAppendQuoted(dst []byte, s string) []byte {
	if plNeedsQuoteEscape(s) {
		return strconv.AppendQuote(dst, s)
	}
	dst = append(dst, '"')
	dst = append(dst, s...)
	return append(dst, '"')
}

// plHandRolledAllowLine is the FROZEN rejected alternative to logPolicyAllow: the
// same line, assembled by hand into a stack buffer and emitted through
// Logger.Output instead of Logger.Printf, so no argument is boxed into an
// interface. Logger.Output and Logger.Printf both funnel into the same internal
// output method and the production logger carries no Lshortfile/Llongfile flag,
// so the calldepth is immaterial and the emitted bytes are identical — which
// TestPolicyDecisionLine_HandRolledAlternativeIsByteIdentical proves rather than
// assumes.
//
// It is the baseline, never the thing under test. Do not wire it into
// applyPolicyDecision; read the header first.
func plHandRolledAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	// 256 bytes covers the representative line (~170) without growing; a longer
	// rule name or identity grows onto the heap, which is the pathological case,
	// not the measured one.
	var arr [256]byte
	b := arr[:0]
	b = append(b, "POLICY_ALLOW rule="...)
	b = plAppendQuoted(b, safeRule)
	b = append(b, " pri="...)
	b = strconv.AppendInt(b, int64(priority), 10)
	b = append(b, ' ')
	b = append(b, clientIP...)
	b = append(b, ' ')
	b = append(b, method...)
	b = append(b, ' ')
	b = plAppendQuoted(b, sanitizeLog(host))
	b = append(b, " ["...)
	b = append(b, sanitizeLog(matchedConditions)...)
	b = append(b, "] {req_id="...)
	b = append(b, reqID...)
	b = append(b, " identity="...)
	b = append(b, sanitizeLog(identity)...)
	b = append(b, " rule="...)
	b = append(b, safeRule...)
	b = append(b, " action=allow}"...)
	_ = logger.Output(2, string(b)) //nolint:errcheck // frozen benchmark baseline; the sink is io.Discard
}

// plHandRolled runs the frozen alternative with the standard arguments, so the
// benchmarks below compare it against plCurrentAllowLine on identical inputs.
func plHandRolled(rule string, priority int) {
	plHandRolledAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// ── Correctness: the alternative must render the same bytes ─────────────────

// TestPolicyDecisionLine_HandRolledAlternativeIsByteIdentical is what makes the
// benchmark comparison honest. A faster shape that emitted different bytes would
// not be a cheaper implementation of this line, it would be a different line —
// and these lines are consumed by SIEM forwarders and log parsers, so a
// divergence is a product break, not a formatting detail. Every verb the
// hand-rolled form re-implements is exercised: %q over control characters,
// quotes, backslashes and non-ASCII, and %d over negative and multi-digit
// priorities.
func TestPolicyDecisionLine_HandRolledAlternativeIsByteIdentical(t *testing.T) {
	priorities := []int{0, 1, 42, 100, 999, 2147483647, -1, -32768}
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
			production := plCapture(func() { plCurrentAllowLine(rule, pri) })
			alternative := plCapture(func() { plHandRolled(rule, pri) })
			if production != alternative {
				t.Errorf("hand-rolled alternative diverged for rule=%q pri=%d:\n production: %q\nalternative: %q",
					rule, pri, production, alternative)
			}
		}
	}
}

// TestPolicyLineQuote_FastPathMatchesStrconv pins the quoting fast path against
// strconv.AppendQuote itself — the oracle, so the two cannot drift if a future
// Go release changes what %q renders. Every single byte value is covered
// exhaustively (alone, and embedded between two ASCII bytes so the fast path is
// entered and then has to bail out mid-string), plus randomised strings drawn
// from a byte-weighted alphabet that straddles the printable-ASCII boundary the
// fast path keys on.
func TestPolicyLineQuote_FastPathMatchesStrconv(t *testing.T) {
	check := func(s string) {
		t.Helper()
		want := string(strconv.AppendQuote(nil, s))
		got := string(plAppendQuoted(nil, s))
		if want != got {
			t.Fatalf("quoting diverged for %q: strconv %q, fast path %q", s, want, got)
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
		n := rng.Intn(24)
		buf := make([]byte, n)
		for j := range buf {
			// Weighted toward the boundary bytes the fast path decides on.
			switch rng.Intn(4) {
			case 0:
				buf[j] = byte(rng.Intn(0x20)) // control
			case 1:
				buf[j] = byte(0x20 + rng.Intn(0x5f)) // printable ASCII
			default:
				buf[j] = byte(rng.Intn(256)) // anything, incl. invalid UTF-8
			}
		}
		check(string(buf))
	}
}

// ── Before vs after, in one run ─────────────────────────────────────────────
//
// Both shapes are timed in the same process on the same hardware, so the
// comparison is reproducible in-tree rather than a pair of numbers from a
// commit message — the convention BenchmarkPolicyDecisionLine_Legacy and
// BenchmarkHTTPForward_LegacyClientPerRequest already follow.
//
// The parallel pair is the one that decides this: a gateway serves many
// requests at once, and log.Logger serialises internally on its own mutex, so
// the four-core figure is what production experiences. It is where the
// alternative's advantage nearly vanishes.

func BenchmarkPolicyDecisionLine_HandRolled(b *testing.B) {
	defer plSwapLogger(io.Discard)()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plHandRolled(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_HandRolledParallel(b *testing.B) {
	defer plSwapLogger(io.Discard)()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plHandRolled(plRule, plPriority)
		}
	})
}

// ── The quoting cost, isolated ──────────────────────────────────────────────
//
// Two short pure-ASCII strings — a rule name and a hostname, exactly what the
// two %q verbs on the decision line receive.

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
		x := plAppendQuoted(arr[:0], plRule)
		benchQuoteSink = len(plAppendQuoted(x, plArgs.host))
	}
}

var benchQuoteSink int
