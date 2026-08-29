package main

// Per-request policy-decision log-line cost (Performance Guardian).
//
// applyPolicyDecision writes exactly one decision line per proxied request
// (POLICY_ALLOW / POLICY_BLOCK / POLICY_DROP / POLICY_REDIRECT). Profiling the
// end-to-end forward benchmark (BenchmarkPerfQual_ProxyHTTPForward, alloc_objects)
// attributed 65,538 of the 99,878 objects handleRequest allocates OUTSIDE the
// upstream round trip to that single line's argument construction — roughly two
// thirds of the dispatch pipeline's own allocation, before any policy, auth or
// transport work is counted.
//
// Two of its allocations were pure waste:
//
//  1. The matched rule's integer Priority was rendered as
//     strings.ReplaceAll(fmt.Sprintf("%d", p), "\n", "") — an int formatted to a
//     string, then that string scanned for a newline a decimal integer cannot
//     contain. That costs the Sprintf result plus boxing it back into the
//     Printf argument list. %d on the int emits the same digits for free.
//
//  2. sanitizeLog(match.Rule.Name) was called TWICE on the same line (the
//     leading rule=%q and the trailing rule=%s), scanning the same string twice
//     per request for one value. It is now hoisted once per decision.
//
// The legacy shape is frozen below as BenchmarkPolicyDecisionLine_Legacy* so the
// before/after comparison stays reproducible in-tree on any runner, the same
// convention BenchmarkHTTPForward_LegacyClientPerRequest already follows.
//
//	go test -run '^$' -bench 'BenchmarkPolicyDecisionLine' -benchmem -count=6 .

import (
	"fmt"
	"io"
	"log"
	"strings"
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

const (
	// The format strings verbatim, before and after. They differ in exactly one
	// verb: pri=%s (a pre-rendered string) became pri=%d (the int itself).
	plLegacyAllowFmt  = "POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"
	plCurrentAllowFmt = "POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"
)

// plLegacyAllowLine reproduces the pre-change argument construction verbatim.
// Kept so the comparison below measures a real difference rather than a
// remembered number.
func plLegacyAllowLine(dst *log.Logger, rule string, priority int) {
	dst.Printf(plLegacyAllowFmt,
		sanitizeLog(rule),
		strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", ""),
		plClientIP, plMethod, sanitizeLog(plHost), sanitizeLog(plCond),
		plReqID, sanitizeLog(plIdentity), sanitizeLog(rule))
}

// plCurrentAllowLine mirrors what applyPolicyDecision does today.
func plCurrentAllowLine(dst *log.Logger, rule string, priority int) {
	safeRule := sanitizeLog(rule)
	dst.Printf(plCurrentAllowFmt,
		safeRule, priority,
		plClientIP, plMethod, sanitizeLog(plHost), sanitizeLog(plCond),
		plReqID, sanitizeLog(plIdentity), safeRule)
}

// discardLogger writes nowhere, so the benchmarks measure argument construction
// and formatting — the work the request goroutine actually performs — without
// the log sink's I/O, which is asynchronous in production anyway (internal/logsink).
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// ── Before vs after ─────────────────────────────────────────────────────────

func BenchmarkPolicyDecisionLine_Legacy(b *testing.B) {
	dst := discardLogger()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plLegacyAllowLine(dst, plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Current(b *testing.B) {
	dst := discardLogger()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plCurrentAllowLine(dst, plRule, plPriority)
	}
}

// ── Concurrency ─────────────────────────────────────────────────────────────
//
// A gateway serves many requests at once, so the figure that matters is the
// per-op cost when every core is constructing a decision line simultaneously.
// Each goroutine gets its OWN logger: the production sink is shared and
// serialises internally, but that is internal/logsink's contract (already
// benchmarked there), not this line's, and including it here would measure the
// sink instead of the argument construction under test.

func BenchmarkPolicyDecisionLine_LegacyParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		dst := discardLogger()
		for pb.Next() {
			plLegacyAllowLine(dst, plRule, plPriority)
		}
	})
}

func BenchmarkPolicyDecisionLine_CurrentParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		dst := discardLogger()
		for pb.Next() {
			plCurrentAllowLine(dst, plRule, plPriority)
		}
	})
}

// ── Isolated: the priority rendering alone ──────────────────────────────────

func BenchmarkPolicyPriority_LegacySprintf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = strings.ReplaceAll(fmt.Sprintf("%d", plPriority), "\n", "")
	}
}

// ── Correctness: the rendered line must not change ──────────────────────────

// TestPolicyDecisionLine_RenderIsByteIdentical is the half that outranks every
// benchmark here. The decision lines are consumed by SIEM forwarders and log
// parsers, so this change is only acceptable if the emitted bytes are unchanged.
// %d on an int emits exactly the digits fmt.Sprintf("%d", …) produced, and the
// ReplaceAll it fed could never match, so the two renderings must agree for
// every priority — including negative and multi-digit values — and for rule
// names carrying the control characters sanitizeLog exists to scrub.
func TestPolicyDecisionLine_RenderIsByteIdentical(t *testing.T) {
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
	}
	for _, rule := range rules {
		for _, pri := range priorities {
			var legacy, current strings.Builder
			plLegacyAllowLine(log.New(&legacy, "", 0), rule, pri)
			plCurrentAllowLine(log.New(&current, "", 0), rule, pri)
			if legacy.String() != current.String() {
				t.Errorf("rendered line diverged for rule=%q pri=%d:\n legacy: %q\ncurrent: %q",
					rule, pri, legacy.String(), current.String())
			}
		}
	}
}

// TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb pins the claim the
// equivalence test rests on: the two format strings are the same template with
// pri=%s replaced by pri=%d. If a future edit changes anything else about the
// line, this fails and the equivalence test above stops being evidence for it.
func TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb(t *testing.T) {
	if got := strings.Replace(plLegacyAllowFmt, "pri=%s", "pri=%d", 1); got != plCurrentAllowFmt {
		t.Errorf("format strings differ beyond the priority verb:\n  want: %q\n   got: %q", plCurrentAllowFmt, got)
	}
}

// TestPolicyDecisionLine_SanitizeIsIdempotentForTheHoist pins the other half of
// the change: hoisting sanitizeLog(match.Rule.Name) to a local is only sound if
// calling it once and using the value twice equals calling it twice. That holds
// because sanitizeLog is a pure function of its argument, which this states
// explicitly so a future stateful sanitizeLog (a counter, a rate gate) fails
// here rather than silently changing two log fields into one.
func TestPolicyDecisionLine_SanitizeIsIdempotentForTheHoist(t *testing.T) {
	for _, s := range []string{"", "plain", "with\nnewline", "with\x1bescape", "ünïcode"} {
		first, second := sanitizeLog(s), sanitizeLog(s)
		if first != second {
			t.Errorf("sanitizeLog(%q) is not pure: %q then %q", s, first, second)
		}
		if got := sanitizeLog(first); got != first {
			t.Errorf("sanitizeLog(%q) is not idempotent: %q then %q", s, first, got)
		}
	}
}
