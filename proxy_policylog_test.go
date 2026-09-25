package main

// Correctness contract for the per-request policy-decision log lines.
//
// The emitters build their line by appending into a stack buffer rather than by
// handing nine arguments to logger.Printf (see the cost note above
// emitPolicyDecision in proxy.go). These lines are consumed by SIEM forwarders
// and log parsers, so the acceptance condition for that change is that the
// emitted BYTES are unchanged — not "equivalent", identical.
//
// The frozen Printf format strings (plPrintf*Fmt) are kept as the executable
// specification: every branch is rendered both ways here and the results must
// match. That is what makes the appends safe to read — nothing takes them on
// trust.

import (
	"bytes"
	"io"
	"log"
	"strconv"
	"strings"
	"testing"
)

// plCapture runs fn with the package logger redirected into a buffer and
// returns what was written.
func plCapture(fn func()) string {
	var buf strings.Builder
	restore := plSwapLogger(&buf)
	fn()
	restore()
	return buf.String()
}

// ── The harness trap ────────────────────────────────────────────────────────

// TestLogBenchHarness_DiscardShortCircuitsTheLogger pins the defect that hid
// two thirds of this line's cost for as long as it was benchmarked.
//
// log.Logger.output opens with `if l.isDiscard.Load() { return nil }`, and
// SetOutput sets that flag on `w == io.Discard` exactly. A benchmark that
// silences the logger with log.New(io.Discard, …) therefore measures argument
// construction and NOTHING ELSE: no formatHeader, no fmt verb parsing, no %q.
// Silencing it with any other write-nowhere sink measures the real path.
//
// This test asserts the difference DIRECTLY — a discard logger must write
// nothing anywhere, while plNullSink must receive the fully formatted line —
// so if a future Go release drops the short-circuit this test fails and tells
// whoever reads it that the harness note above plNullSink is now stale, rather
// than leaving a benchmark quietly measuring the wrong thing again.
func TestLogBenchHarness_DiscardShortCircuitsTheLogger(t *testing.T) {
	prev := logger
	defer func() { logger = prev }()

	sink := &plNullSink{}
	logger = log.New(sink, "[Culvert] ", log.LstdFlags)
	if !loggerFormats(logger) {
		t.Fatal("a logger over plNullSink is not formatting: it is being treated as a discard " +
			"writer, so every benchmark using it is measuring a no-op logger")
	}
	logPolicyAllow(plRule, plPriority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	if sink.n == 0 {
		t.Fatal("plNullSink received no bytes from a real decision line")
	}

	// io.Discard: the whole call is skipped inside log.Logger, formatting included.
	if loggerFormats(log.New(io.Discard, "[Culvert] ", log.LstdFlags)) {
		t.Error("log.New(io.Discard, …) no longer short-circuits: it formatted its argument. " +
			"The benchmark harness note above plNullSink in proxy_policylog_bench_test.go is " +
			"stale, and the io.Discard-vs-real figures it quotes no longer hold")
	}
}

// formatProbe records whether fmt was asked to render it.
type formatProbe struct{ rendered bool }

func (p *formatProbe) String() string { p.rendered = true; return "probe" }

// loggerFormats reports whether l formats its arguments at all. There is no
// exported accessor for log.Logger.isDiscard, so the property is observed
// directly at the step it governs: fmt calls String() only if it renders the
// verb, and log.Logger.output returns before the formatting closure runs when
// it is discarding.
//
// OBSERVE THE FORMATTING, NOT THE WRITER. The first version of this helper
// probed the sink — it allocated a plNullSink, never installed it, and returned
// `sink.n == 0`, which is true unconditionally, so the helper could not return
// false and the test below could not fail (Codex P2, PR #1495). Even installed,
// a writer probe would not distinguish the two states that matter: a logger
// that formats and then throws the bytes away writes nothing either, so a
// future Go release that dropped the short-circuit and kept writing to
// io.Discard would still read as "discarding". That is the same
// cannot-fail-for-its-own-regression defect this PR exists to document,
// reintroduced in the test written to pin it.
func loggerFormats(l *log.Logger) bool {
	p := &formatProbe{}
	l.Printf("%s", p)
	return p.rendered
}

// TestLogBenchHarness_ProbeIsNotATautology is the CONTROL for the test above.
//
// That test is only evidence if its probe can answer BOTH ways, and the version
// it replaces could not: it returned `sink.n == 0` for a sink it never
// installed, so it was true unconditionally and the test passed no matter what
// log.Logger did. A control that pins the probe's discrimination directly is
// the cheapest way to stop that from coming back — an assertion that something
// is detected means nothing until you have shown the detector can also fail.
func TestLogBenchHarness_ProbeIsNotATautology(t *testing.T) {
	if !loggerFormats(log.New(&plNullSink{}, "[Culvert] ", log.LstdFlags)) {
		t.Error("loggerFormats reported no formatting for a logger over a real sink; " +
			"the probe cannot answer true, so the discard test above proves nothing")
	}
	if loggerFormats(log.New(io.Discard, "[Culvert] ", log.LstdFlags)) {
		t.Error("loggerFormats reported formatting for an io.Discard logger; either the " +
			"probe cannot answer false, or Go's short-circuit is gone (the test above says which)")
	}
}

// ── Byte identity, every branch ─────────────────────────────────────────────

// plRenderCase is one branch rendered both ways.
type plRenderCase struct {
	name    string
	current func(rule string, pri int, host, cond, identity string)
	frozen  func(rule string, pri int, host, cond, identity string)
}

func plRenderCases() []plRenderCase {
	const redirectURL = "https://portal.example.com/blocked?x=1"
	return []plRenderCase{
		{
			name: "allow",
			current: func(rule string, pri int, host, cond, identity string) {
				logPolicyAllow(rule, pri, plArgs.clientIP, plArgs.method, host, cond, plArgs.reqID, identity)
			},
			frozen: func(rule string, pri int, host, cond, identity string) {
				plPrintfAllowLine(rule, pri, plArgs.clientIP, plArgs.method, host, cond, plArgs.reqID, identity)
			},
		},
		{
			name: "drop",
			current: func(rule string, pri int, host, cond, identity string) {
				logPolicyDrop(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity)
			},
			frozen: func(rule string, pri int, host, cond, identity string) {
				plPrintfDropLine(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity)
			},
		},
		{
			name: "block",
			current: func(rule string, pri int, host, cond, identity string) {
				logPolicyBlock(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity)
			},
			frozen: func(rule string, pri int, host, cond, identity string) {
				plPrintfBlockLine(rule, pri, plArgs.clientIP, host, cond, plArgs.reqID, identity)
			},
		},
		{
			name: "redirect",
			current: func(rule string, pri int, host, cond, identity string) {
				logPolicyRedirect(rule, pri, plArgs.clientIP, host, redirectURL, cond, plArgs.reqID, identity)
			},
			frozen: func(rule string, pri int, host, cond, identity string) {
				plPrintfRedirectLine(rule, pri, plArgs.clientIP, host, redirectURL, cond, plArgs.reqID, identity)
			},
		},
	}
}

// plAwkwardStrings are the values worth pushing through both renderings: the
// control characters sanitizeLog exists to scrub, the two characters %q escapes
// (quote and backslash), multi-byte and invalid UTF-8 (which take the quoter's
// fallback), the empty string, and DEL / the printable-ASCII boundaries.
var plAwkwardStrings = []string{
	"corp-saas-allow",
	"",
	" ",
	"rule with spaces",
	"rule\nwith\nnewlines",
	"rule\rwith\rCR",
	"rule\twith\ttabs",
	"rule\x00with\x1bcontrol",
	"del\x7fhere",
	"low\x1fboundary",
	"high\x7eboundary",
	"ünïcode-rule-名前",
	"emoji-\U0001F600-rule",
	"\xff\xfe invalid utf8",
	`quotes"and\backslashes`,
	`\`,
	`"`,
	strings.Repeat("long-", 80) + "tail",
}

// TestPolicyDecisionLine_RenderIsByteIdentical is the half that outranks every
// benchmark. It renders all four branches through the PRODUCTION emitters and
// through the frozen Printf templates they replaced, over the awkward-value
// corpus and a spread of priorities, and requires the bytes to match exactly.
func TestPolicyDecisionLine_RenderIsByteIdentical(t *testing.T) {
	priorities := []int{0, 1, 7, 42, 100, 999, 2147483647, -1, -32768}
	for _, tc := range plRenderCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range plAwkwardStrings {
				for _, pri := range priorities {
					// Drive the same awkward value through every string
					// position in turn, so a mistake confined to one field
					// cannot hide behind a benign value in the others.
					fields := []struct {
						what                  string
						rule, host, cond, ide string
					}{
						{"rule", v, plHost, plCond, plIdentity},
						{"host", plRule, v, plCond, plIdentity},
						{"cond", plRule, plHost, v, plIdentity},
						{"identity", plRule, plHost, plCond, v},
						{"all", v, v, v, v},
					}
					for _, f := range fields {
						got := plCapture(func() { tc.current(f.rule, pri, f.host, f.cond, f.ide) })
						want := plCapture(func() { tc.frozen(f.rule, pri, f.host, f.cond, f.ide) })
						if got != want {
							t.Fatalf("%s line diverged (%s=%q, pri=%d):\n frozen: %q\ncurrent: %q",
								tc.name, f.what, v, pri, want, got)
						}
					}
				}
			}
		})
	}
}

// TestPolicyDecisionLine_RedirectTargetIsNotInferredFromEmptiness pins that the
// ` => %q` clause is governed by policyDecision.hasTarget, not by the redirect
// URL being non-empty. Inferring it from the value would make an empty
// admin-configured RedirectURL silently emit a DIFFERENT line shape from every
// other redirect — a parser-visible change driven by config content.
func TestPolicyDecisionLine_RedirectTargetIsNotInferredFromEmptiness(t *testing.T) {
	got := plCapture(func() {
		logPolicyRedirect(plRule, 1, plClientIP, plHost, "", plCond, plReqID, plIdentity)
	})
	want := plCapture(func() {
		plPrintfRedirectLine(plRule, 1, plClientIP, plHost, "", plCond, plReqID, plIdentity)
	})
	if got != want {
		t.Fatalf("empty redirect target changed the line shape:\n frozen: %q\ncurrent: %q", want, got)
	}
	if !strings.Contains(got, `=> ""`) {
		t.Errorf(`want the => "" clause present for an empty target, got %q`, got)
	}
}

// TestPolicyDecisionLine_LegacySprintfPriorityUnchanged keeps the PR #1256
// claim under test: rendering the priority with %d emits exactly what
// strings.ReplaceAll(fmt.Sprintf("%d", …), "\n", "") did.
func TestPolicyDecisionLine_LegacySprintfPriorityUnchanged(t *testing.T) {
	for _, pri := range []int{0, 1, 42, 999, 2147483647, -1, -32768} {
		legacy := plCapture(func() { plLegacy(plRule, pri) })
		current := plCapture(func() { plCurrentAllowLine(plRule, pri) })
		if legacy != current {
			t.Errorf("pri=%d: pre-#1256 Sprintf rendering diverged:\n legacy: %q\ncurrent: %q", pri, legacy, current)
		}
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

// TestPolicyDecisionLine_EveryFieldIsSanitized drives a forging payload through
// each client-influenced field in turn and requires it never to reach the sink
// intact. The host and the matched-conditions string are the two that carry
// destination-derived text, so this is the CWE-117 half of the change, checked
// per field rather than inferred from the rule-name case above.
func TestPolicyDecisionLine_EveryFieldIsSanitized(t *testing.T) {
	const forge = "a\nPOLICY_ALLOW forged"
	for _, tc := range plRenderCases() {
		for _, field := range []string{"rule", "host", "cond", "identity"} {
			rule, host, cond, ide := plRule, plHost, plCond, plIdentity
			switch field {
			case "rule":
				rule = forge
			case "host":
				host = forge
			case "cond":
				cond = forge
			case "identity":
				ide = forge
			}
			out := strings.TrimSuffix(plCapture(func() { tc.current(rule, 1, host, cond, ide) }), "\n")
			if strings.Contains(out, "\n") {
				t.Errorf("%s/%s: payload forged a second physical line: %q", tc.name, field, out)
			}
		}
	}
}

// ── The quoter ──────────────────────────────────────────────────────────────

// TestAppendQuotedForLog_MatchesStrconvAppendQuote is the differential that
// licenses the fast path. appendQuotedForLog must be strconv.AppendQuote with a
// shortcut, never a different quoting — %q is what the frozen templates emit.
//
// Every single byte value is covered explicitly (0x00–0xff, alone and embedded),
// because the fast path's whole correctness rests on its boundary conditions:
// 0x1f/0x20 and 0x7e/0x7f, plus '"' and '\\' inside the printable range and
// everything at or above 0x80.
func TestAppendQuotedForLog_MatchesStrconvAppendQuote(t *testing.T) {
	var corpus []string
	corpus = append(corpus, plAwkwardStrings...)
	for b := 0; b < 256; b++ {
		c := string([]byte{byte(b)})
		corpus = append(corpus, c, "x"+c, c+"x", "a"+c+"b")
	}
	for _, s := range corpus {
		want := strconv.AppendQuote(nil, s)
		got := appendQuotedForLog(nil, s)
		if !bytes.Equal(got, want) {
			t.Fatalf("appendQuotedForLog(%q) = %s, strconv.AppendQuote = %s", s, got, want)
		}
	}
}

// TestAppendQuotedForLog_PreservesExistingBufferContent pins that the helper
// APPENDS rather than overwrites — it is called mid-line, with the first half
// of the decision line already in the buffer.
func TestAppendQuotedForLog_PreservesExistingBufferContent(t *testing.T) {
	prefix := []byte("POLICY_ALLOW rule=")
	got := appendQuotedForLog(prefix, "corp-saas-allow")
	if want := `POLICY_ALLOW rule="corp-saas-allow"`; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// FuzzAppendQuotedForLog is the open-ended half of the differential above.
func FuzzAppendQuotedForLog(f *testing.F) {
	for _, s := range plAwkwardStrings {
		f.Add(s)
	}
	f.Add("\x00\x01\x02")
	f.Add("ÿĀ￿")
	f.Fuzz(func(t *testing.T, s string) {
		want := strconv.AppendQuote(nil, s)
		got := appendQuotedForLog(nil, s)
		if !bytes.Equal(got, want) {
			t.Fatalf("appendQuotedForLog(%q) = %s, strconv.AppendQuote = %s", s, got, want)
		}
	})
}
