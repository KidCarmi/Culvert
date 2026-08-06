package yara

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Benchmarks for the hoisted ReDoS timeout harness. The property under
// measurement is that the harness cost is CONSTANT in the number of regex
// strings, not linear in it.

// regexRuleSet builds `rules` rules of `perRule` regex strings each, none of
// which match benchRegexBody. Every string is therefore evaluated — the worst
// case for the scan loop, and the common one (most bodies are clean).
//
// The patterns are literal-prefixed and case-sensitive, which is what the
// shipped yara/sample_rules.yar compiles to and what most operator rules look
// like: RE2 matches them in a few hundred nanoseconds, so the timeout harness
// around them is the dominant cost.
func regexRuleSet(tb testing.TB, rules, perRule int) *RuleSet {
	tb.Helper()
	var src strings.Builder
	for r := 0; r < rules; r++ {
		var strs strings.Builder
		for s := 0; s < perRule; s++ {
			fmt.Fprintf(&strs, "        $r%d = /ZZMALWARE%d_%d[0-9]{3}/\n", s, r, s)
		}
		src.WriteString(yaraRule(fmt.Sprintf("Re%d", r), strings.TrimRight(strs.String(), "\n"), "any of them"))
	}
	return buildRuleSet(tb, src.String())
}

func benchRegexScan(b *testing.B, rules, perRule int) {
	y := regexRuleSet(b, rules, perRule)
	body := filler(16 << 10)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(y.Match(body)) != 0 {
			b.Fatal("benchmark body should match nothing")
		}
	}
}

// BenchmarkMatch_Regex* sweep the regex-string count over a fixed 16 KB body.
// Pre-change these were linear in the string count (5 allocs/461 B at 1 string,
// 250 allocs/21 KB at 50); the harness is now paid once per scan.
// 1-3 bracket the break-even: the per-scan worker's setup/teardown makes a
// one-regex-string rule set slightly slower, two roughly neutral, and three
// onwards a win. See the cost table in regexrunner.go.
func BenchmarkMatch_Regex1(b *testing.B)  { benchRegexScan(b, 1, 1) }
func BenchmarkMatch_Regex2(b *testing.B)  { benchRegexScan(b, 1, 2) }
func BenchmarkMatch_Regex3(b *testing.B)  { benchRegexScan(b, 1, 3) }
func BenchmarkMatch_Regex10(b *testing.B) { benchRegexScan(b, 5, 2) }
func BenchmarkMatch_Regex20(b *testing.B) { benchRegexScan(b, 10, 2) }
func BenchmarkMatch_Regex50(b *testing.B) { benchRegexScan(b, 10, 5) }

// BenchmarkMatch_RegexParallel is the concurrency case: many scans in flight at
// once, which is what the proxy actually does. The per-string harness put a
// goroutine spawn and a timer registration on every string of every concurrent
// scan; one worker per scan removes that scheduler pressure.
func BenchmarkMatch_RegexParallel20(b *testing.B) {
	y := regexRuleSet(b, 10, 2)
	body := filler(16 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if len(y.Match(body)) != 0 {
				b.Fatal("benchmark body should match nothing")
			}
		}
	})
}

// BenchmarkMatch_RegexStress is the saturation shape: a large rule set (100
// regex strings) over a 256 KB body, scanned from every core at once.
func BenchmarkMatch_RegexStress(b *testing.B) {
	y := regexRuleSet(b, 20, 5)
	body := filler(256 << 10)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if len(y.Match(body)) != 0 {
				b.Fatal("benchmark body should match nothing")
			}
		}
	})
}

// BenchmarkMatchRegex_HarnessOnly isolates the guard from the work it guards:
// one literal-prefixed regex over a 16 KB body, which re.Match alone completes
// in ~420 ns with zero allocations. Anything this benchmark reports above that
// is the timeout harness.
func BenchmarkMatchRegex_HarnessOnly(b *testing.B) {
	re := regexp.MustCompile(`ZZMALWARE0_0[0-9]{3}`)
	body := filler(16 << 10)
	ctx := &scanCtx{}
	defer ctx.closeRegexRunner()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ctx.matchRegex(re, body, 5*time.Second) {
			b.Fatal("benchmark body should match nothing")
		}
	}
}

// BenchmarkMatchRegex_RawNoHarness is the floor the benchmark above is measured
// against: the same match with no timeout guard at all.
func BenchmarkMatchRegex_RawNoHarness(b *testing.B) {
	re := regexp.MustCompile(`ZZMALWARE0_0[0-9]{3}`)
	body := filler(16 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if re.Match(body) {
			b.Fatal("benchmark body should match nothing")
		}
	}
}

// TestBenchGate_YARARegexAllocsConstantInStringCount is the regression gate.
//
// Match runs on every response body the scan orchestrator inspects. Bounding
// each regex string with a ReDoS timeout needs a goroutine, because re.Match is
// not interruptible, and that harness used to be paid PER STRING: measured 5
// allocs/425 B each, so a rule set with 10 regex strings charged 50 allocs/4.3 KB
// to every scanned body and one with 50 charged 250 allocs/21 KB. It is now
// hoisted to ONE worker per scan (regexrunner.go), making the overhead a small
// constant.
//
// The bound is deliberately a CONSTANT rather than a function of the string
// count — that is the entire point. Reintroducing per-string harness cost blows
// through it immediately (10 strings would land at ~50).
func TestBenchGate_YARARegexAllocsConstantInStringCount(t *testing.T) {
	// Measured flat across string counts. The bound leaves headroom for
	// escape-analysis differences across Go releases while staying far below the
	// O(strings) failure mode.
	const maxAllocs int64 = 14

	// Cheap literal-prefixed patterns over a tiny body: the measurement is then
	// almost entirely the timeout harness, which is what this gate is about.
	body := []byte("clean")
	for _, count := range []struct{ rules, perRule int }{{1, 1}, {5, 2}, {10, 2}, {10, 5}} {
		total := count.rules * count.perRule
		y := regexRuleSet(t, count.rules, count.perRule)
		if got := y.Match(body); len(got) != 0 {
			t.Fatalf("strings=%d: clean body matched %v — the gate is not measuring the miss path", total, got)
		}

		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				y.Match(body)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Match strings=%d: %d allocs/op (bound %d), %d B/op, %d ns/op",
			total, allocs, maxAllocs, res.AllocedBytesPerOp(), res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: Match with %d regex strings allocates %d/op, exceeds constant bound %d — "+
				"the ReDoS timeout harness (goroutine + channel + timer) is being paid PER STRING again "+
				"instead of once per scan, on every scanned response body. "+
				"See internal/yara/regexrunner.go scanCtx.matchRegex.", total, allocs, maxAllocs)
		}
	}
}
