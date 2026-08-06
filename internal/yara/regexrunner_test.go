package yara

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Tests for the hoisted ReDoS timeout harness: a scan now runs every regex
// string through ONE worker goroutine instead of spawning one per string.
// These pin the properties that made that safe — the budget is still PER
// STRING, a timeout still fails closed and still does not abort the scan, and
// an abandoned worker is still accounted for and cannot be reused.

// slowRe has no literal prefix and is case-insensitive, so RE2 cannot use its
// memchr fast path and the match cost scales with the body — which is what lets
// these tests exercise the timeout path with real regex work rather than a fake.
var slowRe = regexp.MustCompile(`(?i)([a-z]|[0-9])+(zz|qq)(xx|yy)[0-9]{3}[a-f]+`)

func filler(n int) []byte {
	unit := []byte("the quick brown fox jumps over the lazy dog 0123456789 ")
	return bytes.Repeat(unit, n/len(unit)+1)
}

// inflightBaseline settles what it can and returns the counter value to measure
// against.
//
// Assertions here are DELTAS from this baseline, never absolute values: several
// long-standing tests in this package drive yaraInflight with Store() to
// simulate saturation, which clobbers concurrent accounting, and -shuffle can
// place them anywhere. Absolute assertions turn that into a phantom failure in
// this file (observed: "inflight = -1"). The per-runner accounting itself is
// exact — release() is CAS-guarded, so a runner increments and decrements
// exactly once — which is what these deltas actually test.
func inflightBaseline(t *testing.T) int64 {
	t.Helper()
	for i := 0; i < 100; i++ {
		if yaraInflight.Load() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return yaraInflight.Load()
}

// waitInflight waits for the counter to come back to want, so a test never
// leaves a draining worker behind for the next one to trip over.
func waitInflight(t *testing.T, want int64) int64 {
	t.Helper()
	for i := 0; i < 200; i++ {
		if got := yaraInflight.Load(); got == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return yaraInflight.Load()
}

// waitReleased waits for one specific abandoned worker to finish its runaway
// match and give back its slot. Deterministic, unlike waiting on the counter.
func waitReleased(t *testing.T, r *regexRunner) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if r.released.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("abandoned worker never released its inflight slot")
}

// TestRegexRunner_ReusesOneWorkerPerScan is the core cost contract: every regex
// string in a scan shares one worker, so the goroutine/channel/timer harness is
// paid once per scan instead of once per string.
func TestRegexRunner_ReusesOneWorkerPerScan(t *testing.T) {
	base := inflightBaseline(t)

	ctx := &scanCtx{}
	defer ctx.closeRegexRunner()

	re := regexp.MustCompile(`nomatch-zzz`)
	body := []byte("clean body")

	if ctx.runner != nil {
		t.Fatal("runner should not exist before the first regex string")
	}
	if ctx.matchRegex(re, body, time.Second) {
		t.Fatal("clean body must not match")
	}
	first := ctx.runner
	if first == nil {
		t.Fatal("runner should exist after the first regex string")
	}

	for i := 0; i < 25; i++ {
		if ctx.matchRegex(re, body, time.Second) {
			t.Fatalf("string %d: clean body must not match", i)
		}
		if ctx.runner != first {
			t.Fatalf("string %d: worker was replaced — the harness is being paid per string again", i)
		}
	}
	if got := yaraInflight.Load() - base; got != 1 {
		t.Errorf("inflight delta = %d after 26 regex strings in one scan, want 1 (one worker per scan)", got)
	}
}

// TestRegexRunner_NoWorkerWithoutRegexStrings pins the lazy creation: a rule set
// of literals only must not start a goroutine, arm a timer, or touch inflight.
func TestRegexRunner_NoWorkerWithoutRegexStrings(t *testing.T) {
	base := inflightBaseline(t)

	y := buildRuleSet(t, yaraRule("LiteralOnly", `        $a = "ZZNOPE"`, "any of them"))
	before := runtime.NumGoroutine()
	if got := y.Match([]byte("clean body")); len(got) != 0 {
		t.Fatalf("Match = %v, want no matches", got)
	}
	if got := yaraInflight.Load() - base; got != 0 {
		t.Errorf("inflight delta = %d after a literal-only scan, want 0", got)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutines %d -> %d: a literal-only scan must not start a regex worker", before, after)
	}
}

// TestRegexRunner_BudgetIsPerString is the policy contract. The timer is now
// armed once per string on a shared worker rather than once per string on its
// own goroutine, so this proves the budget did not silently become a WHOLE-SCAN
// budget: a scan whose strings each finish well inside the timeout must succeed
// even when their TOTAL far exceeds it. A whole-scan budget would fail closed
// here and block legitimate traffic.
func TestRegexRunner_BudgetIsPerString(t *testing.T) {
	inflightBaseline(t)

	const strings = 20
	body := filler(64 << 10)

	// Calibrate against this machine rather than hardcoding a duration: -race
	// slows regexp by more than an order of magnitude, so a fixed budget is
	// either flaky there or meaningless without it. A budget of 8x one match is
	// far more than any single string needs, while 20 strings still sum to ~2.5x
	// it — so only a whole-scan budget can fail this test.
	var one time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		slowRe.Match(body)
		if d := time.Since(start); d > one {
			one = d
		}
	}
	perString := 8 * one

	ctx := &scanCtx{}
	defer ctx.closeRegexRunner()

	start := time.Now()
	for i := 0; i < strings; i++ {
		if ctx.matchRegex(slowRe, body, perString) {
			t.Fatalf("string %d failed closed after %v with a %v per-string budget: "+
				"the per-string budget has become a whole-scan budget", i, time.Since(start), perString)
		}
	}
	total := time.Since(start)
	if total <= perString {
		t.Skipf("scan took %v, still under the %v per-string budget — cannot prove the distinction here", total, perString)
	}
	t.Logf("%d strings in %v with a %v per-string budget (one match ~%v) — no string failed closed",
		strings, total, perString, one)
}

// TestRegexRunner_TimeoutFailsClosedAndScanContinues pins both halves of the
// timeout contract: the string that overran fails closed, and the scan is NOT
// aborted — the next string is evaluated normally on a fresh worker. Under the
// old code each string had its own goroutine, so continuation was structural;
// now that strings share a worker, a wedged one must be dropped rather than
// poisoning the rest of the scan.
func TestRegexRunner_TimeoutFailsClosedAndScanContinues(t *testing.T) {
	inflightBaseline(t)

	ctx := &scanCtx{}
	defer ctx.closeRegexRunner()

	// Start the worker on a trivial string first, so the one that is about to be
	// abandoned can be captured and drained deterministically at the end.
	if ctx.matchRegex(regexp.MustCompile(`nomatch-zzz`), []byte("clean"), time.Second) {
		t.Fatal("clean body must not match")
	}
	doomed := ctx.runner

	// 512 KB against a regex with no literal prefix: tens of milliseconds of real
	// work against a 1 ms budget, so the timeout fires with a wide margin while
	// the abandoned worker still drains quickly enough not to skew later tests.
	huge := filler(512 << 10)
	if !ctx.matchRegex(slowRe, huge, time.Millisecond) {
		t.Skip("match completed inside the 1ms budget — machine too fast to exercise the timeout path")
	}
	if ctx.runner != nil {
		t.Error("the wedged worker must be dropped, not reused for the next string")
	}
	// The abandoned worker keeps its slot while its runaway match is still
	// running — that is exactly the goroutine the cap exists to count.
	if doomed.released.Load() {
		t.Error("an abandoned worker must hold its inflight slot until its match returns")
	}
	defer waitReleased(t, doomed)

	// The scan continues: the next string gets a fresh worker and a correct answer.
	if !ctx.matchRegex(regexp.MustCompile(`evil`), []byte("this is evil"), time.Second) {
		t.Error("expected a match after a timeout — a timeout must not abort the rest of the scan")
	}
	if ctx.matchRegex(regexp.MustCompile(`evil`), []byte("this is fine"), time.Second) {
		t.Error("expected no match after a timeout — the stale result must not leak into the next string")
	}
}

// TestRegexRunner_TimeoutRespectsFailOpenPosture pins that the shared worker did
// not hardcode the verdict: the on_timeout posture still decides.
func TestRegexRunner_TimeoutRespectsFailOpenPosture(t *testing.T) {
	inflightBaseline(t)

	old := GetOnTimeout()
	defer SetOnTimeout(old)
	SetOnTimeout(FailOpenWithAlert)

	ctx := &scanCtx{}
	defer ctx.closeRegexRunner()

	if ctx.matchRegex(regexp.MustCompile(`nomatch-zzz`), []byte("clean"), time.Second) {
		t.Fatal("clean body must not match")
	}
	doomed := ctx.runner

	huge := filler(512 << 10)
	start := time.Now()
	got := ctx.matchRegex(slowRe, huge, time.Millisecond)
	if time.Since(start) < time.Millisecond {
		t.Skip("match completed inside the 1ms budget — machine too fast to exercise the timeout path")
	}
	defer waitReleased(t, doomed)
	if got {
		t.Error("on_timeout=fail_open_with_alert must return false; the shared worker must not hardcode fail-closed")
	}
}

// TestRegexRunner_SaturationFailsClosed pins that the in-flight cap is still
// enforced where a goroutine would be created.
func TestRegexRunner_SaturationFailsClosed(t *testing.T) {
	inflightBaseline(t)

	old := yaraInflight.Load()
	defer yaraInflight.Store(old)
	yaraInflight.Store(GetMaxInflight() + 100)

	ctx := &scanCtx{}
	defer ctx.closeRegexRunner()

	if !ctx.matchRegex(regexp.MustCompile(`clean`), []byte("completely clean content"), time.Second) {
		t.Error("saturation must fail closed; returning false silently allows unscanned content through")
	}
	if ctx.runner != nil {
		t.Error("a saturated engine must not have started a worker")
	}
}

// TestRegexRunner_NoGoroutineLeak pins that a completed scan parks nothing: the
// worker now outlives individual strings, so Match must shut it down.
func TestRegexRunner_NoGoroutineLeak(t *testing.T) {
	base := inflightBaseline(t)

	y := regexRuleSet(t, 5, 4) // 20 regex strings
	body := []byte("clean body that matches nothing")

	y.Match(body) // warm up: first scan may grow runtime-internal pools
	waitInflight(t, base)
	before := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		if got := y.Match(body); len(got) != 0 {
			t.Fatalf("scan %d: Match = %v, want no matches", i, got)
		}
	}
	waitInflight(t, base)

	for i := 0; i < 100 && runtime.NumGoroutine() > before; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutines %d -> %d after 20 scans x 20 regex strings: workers are leaking", before, after)
	}
	if got := waitInflight(t, base) - base; got != 0 {
		t.Errorf("inflight delta = %d after all scans completed, want 0", got)
	}
}

// TestRegexRunner_ResultsUnchanged is the equivalence check: the shared-worker
// scan path must return exactly what the standalone one-match-per-goroutine path
// returns, hit and miss, for regex, literal, nocase and mixed rules.
func TestRegexRunner_ResultsUnchanged(t *testing.T) {
	inflightBaseline(t)

	src := yaraRule("Re", `        $a = /ev[il]+_MARKER/`, "any of them") +
		yaraRule("Lit", `        $b = "PLAIN_MARKER"`, "any of them") +
		yaraRule("NoCase", `        $c = "nocase_marker" nocase`, "any of them") +
		yaraRule("Mixed", "        $d = /MIX_[0-9]{2}/\n        $e = \"MIX_LITERAL\"", "all of them") +
		yaraRule("Miss", `        $f = /NEVER_ZZQQ[0-9]/`, "any of them")
	y := buildRuleSet(t, src)

	bodies := [][]byte{
		[]byte("nothing interesting here"),
		[]byte("contains evil_MARKER only"),
		[]byte("contains PLAIN_MARKER only"),
		[]byte("contains NOCASE_MARKER upper"),
		[]byte("MIX_42 and MIX_LITERAL together"),
		[]byte("MIX_42 without the literal"),
		[]byte("evil_MARKER PLAIN_MARKER NoCase_Marker MIX_07 MIX_LITERAL"),
	}

	for _, body := range bodies {
		got := y.Match(body)

		// Reference: evaluate every rule with the standalone path, which spawns
		// its own goroutine per string exactly as the pre-change code did.
		var want []string
		for i := range y.rules {
			r := &y.rules[i]
			ref := &scanCtx{data: body}
			hit := make(map[string]bool, len(r.strings))
			for j := range r.strings {
				s := &r.strings[j]
				if s.re != nil {
					hit[s.id] = matchRegexWithTimeout(s.re, body, time.Second)
					continue
				}
				hit[s.id] = matchYARAString(s, ref)
			}
			ref.closeRegexRunner()
			if referenceRuleHit(r, hit) {
				want = append(want, r.name)
			}
		}

		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("body %q: Match = %v, standalone-path reference = %v", body, got, want)
		}
	}
}

// referenceRuleHit mirrors evalYARARule's decision from a fully-populated hit
// map, so the equivalence test compares match RESULTS rather than re-using the
// code path under test.
func referenceRuleHit(r *yaraCompiledRule, hit map[string]bool) bool {
	switch r.condKind {
	case yaraAnyOfThem:
		for _, v := range hit {
			if v {
				return true
			}
		}
		return false
	case yaraAllOfThem:
		if len(hit) == 0 {
			return false
		}
		for _, v := range hit {
			if !v {
				return false
			}
		}
		return true
	default:
		return evalBoolCondition(r.condExpr, hit)
	}
}

// TestRegexRunner_ConcurrentScans pins that scans stay independent: each has its
// own worker, and no result crosses between them.
func TestRegexRunner_ConcurrentScans(t *testing.T) {
	base := inflightBaseline(t)

	y := buildRuleSet(t, yaraRule("Hit", `        $a = /CONCURRENT_[0-9]+/`, "any of them"))
	hitBody := []byte("payload CONCURRENT_12345 payload")
	missBody := []byte("payload nothing to see here payload")

	done := make(chan error, 16)
	for w := 0; w < 16; w++ {
		wantHit := w%2 == 0
		go func() {
			for i := 0; i < 50; i++ {
				body, want := missBody, 0
				if wantHit {
					body, want = hitBody, 1
				}
				if got := y.Match(body); len(got) != want {
					done <- fmt.Errorf("Match(%q) = %v, want %d matches", body, got, want)
					return
				}
			}
			done <- nil
		}()
	}
	for w := 0; w < 16; w++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if got := waitInflight(t, base) - base; got != 0 {
		t.Errorf("inflight delta = %d after all concurrent scans finished, want 0", got)
	}
}
