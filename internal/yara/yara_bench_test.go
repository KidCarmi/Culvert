package yara

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// buildRuleSet compiles src into a RuleSet without a *testing.T (bench-friendly).
func buildRuleSet(tb testing.TB, src string) *RuleSet {
	tb.Helper()
	rules, err := parseYARASrc(src)
	if err != nil {
		tb.Fatalf("parseYARASrc: %v", err)
	}
	return &RuleSet{rules: rules}
}

// benchBody is a ~1 MB body that matches none of the benchmark strings, so
// every string in every rule is evaluated (worst case for the scan loop).
func benchBody() []byte {
	return bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog 0123456789 "), 19000)
}

// nocaseRuleSet builds `rules` rules each with `perRule` nocase literal strings,
// condition "any of them". None of the literals appear in benchBody.
func nocaseRuleSet(tb testing.TB, rules, perRule int) *RuleSet {
	var src strings.Builder
	for r := 0; r < rules; r++ {
		var strs strings.Builder
		for s := 0; s < perRule; s++ {
			fmt.Fprintf(&strs, "        $s%d = \"ZZMALWARESIG%d_%d\" nocase\n", s, r, s)
		}
		src.WriteString(yaraRule(fmt.Sprintf("NoCase%d", r), strings.TrimRight(strs.String(), "\n"), "any of them"))
	}
	return buildRuleSet(tb, src.String())
}

// literalRuleSet is the same shape but case-sensitive (no nocase), so it
// isolates the per-rule map-allocation cost from the body-lowering cost.
func literalRuleSet(tb testing.TB, rules, perRule int) *RuleSet {
	var src strings.Builder
	for r := 0; r < rules; r++ {
		var strs strings.Builder
		for s := 0; s < perRule; s++ {
			fmt.Fprintf(&strs, "        $s%d = \"ZZMALWARESIG%d_%d\"\n", s, r, s)
		}
		src.WriteString(yaraRule(fmt.Sprintf("Lit%d", r), strings.TrimRight(strs.String(), "\n"), "any of them"))
	}
	return buildRuleSet(tb, src.String())
}

// BenchmarkMatch_NoCaseHeavy exercises Slice A (body lowered once per scan
// instead of once per nocase string) + Slice B (no per-rule map). 20 rules × 10
// nocase strings = 200 nocase evaluations over a 1 MB body per scan.
func BenchmarkMatch_NoCaseHeavy(b *testing.B) {
	y := nocaseRuleSet(b, 20, 10)
	body := benchBody()
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(y.Match(body)) != 0 {
			b.Fatal("benchmark body should match nothing")
		}
	}
}

// BenchmarkMatch_LiteralAnyOfThem isolates Slice B: case-sensitive any-of-them
// across 20 rules — the pre-change path allocated one map[string]bool per rule
// per scan; the short-circuit path allocates none.
func BenchmarkMatch_LiteralAnyOfThem(b *testing.B) {
	y := literalRuleSet(b, 20, 10)
	body := benchBody()
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(y.Match(body)) != 0 {
			b.Fatal("benchmark body should match nothing")
		}
	}
}
