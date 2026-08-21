package yara

// yara_match_panic_test.go — CHAOS-25: containment for the per-match goroutine.
//
// matchRegexWithTimeout spawns a goroutine that runs attacker-supplied bytes
// through a compiled regexp on the response-scanning path. It was the last
// unguarded detached go-site left by the CHAOS-24 sweep (§12.6 of
// roadmap/CHAOS-ENGINEERING-REVIEW.md). An unrecovered panic there terminates
// the whole in-line gateway.
//
// Unlike a worker loop there is no "next round" to keep alive, so the guard
// covers the whole one-shot body and the parent must still receive an answer.
// A contained panic yields NO verdict about the content — the same epistemic
// state a timeout leaves — so it resolves through the SAME admin-selectable
// posture rather than silently defaulting to "clean".

import (
	"regexp"
	"testing"
	"time"
)

// injectMatchPanic swaps the match seam for one that always panics, restoring
// it (and the posture + counter baseline) on cleanup.
func injectMatchPanic(t *testing.T) {
	t.Helper()
	orig := yaraMatchFn
	origPosture := GetOnTimeout()
	yaraMatchFn = func(*regexp.Regexp, []byte) bool { panic("simulated fault inside the regex match") }
	t.Cleanup(func() {
		yaraMatchFn = orig
		SetOnTimeout(origPosture)
	})
}

// TestChaos25_MatchPanic_FailsClosedByDefault is the primary gate: the process
// survives, the caller gets an answer, and with the default posture that answer
// is BLOCK — a scanner that cannot decide must not report "clean".
func TestChaos25_MatchPanic_FailsClosedByDefault(t *testing.T) {
	injectMatchPanic(t)
	SetOnTimeout(FailClosed)
	before := MatchPanics()

	re := regexp.MustCompile(`evil`)
	if !matchRegexWithTimeout(re, []byte("some response body"), time.Second) {
		t.Fatal("a contained match panic must fail CLOSED (treated as suspicious) under the default posture")
	}
	if got := MatchPanics() - before; got != 1 {
		t.Errorf("contained match panics = %d, want 1 — the containment must stay observable", got)
	}
}

// TestChaos25_MatchPanic_HonoursFailOpenPosture proves the guard does not
// hard-code a posture: an operator who chose availability over strictness still
// gets availability, exactly as they do on a timeout.
func TestChaos25_MatchPanic_HonoursFailOpenPosture(t *testing.T) {
	injectMatchPanic(t)
	SetOnTimeout(FailOpenWithAlert)

	re := regexp.MustCompile(`evil`)
	if matchRegexWithTimeout(re, []byte("some response body"), time.Second) {
		t.Fatal("with fail_open_with_alert selected, a contained match panic must allow, matching the timeout path")
	}
}

// TestChaos25_MatchPanic_AnswersImmediately pins that a panic does not leave
// the caller waiting out the full timeout. The panic already proved the match
// will never complete, so stalling every subsequent scan for the timeout window
// would turn a contained fault into a throughput collapse.
func TestChaos25_MatchPanic_AnswersImmediately(t *testing.T) {
	injectMatchPanic(t)
	SetOnTimeout(FailClosed)

	re := regexp.MustCompile(`evil`)
	start := time.Now()
	matchRegexWithTimeout(re, []byte("body"), 5*time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("contained panic took %s — it must answer immediately, not wait out the timeout", elapsed)
	}
}

// TestChaos25_MatchPanic_ReleasesTheInflightSlot proves containment does not
// leak the saturation budget. yaraInflight bounds concurrent match goroutines;
// if a panicking one never decremented it, a repeatable fault would walk the
// counter to the cap and every later scan would resolve by the SATURATION
// posture instead of by its rules — a silent, permanent scanner degradation.
func TestChaos25_MatchPanic_ReleasesTheInflightSlot(t *testing.T) {
	injectMatchPanic(t)
	SetOnTimeout(FailClosed)

	re := regexp.MustCompile(`evil`)
	before := Inflight()
	for i := 0; i < 25; i++ {
		matchRegexWithTimeout(re, []byte("body"), time.Second)
	}
	// The decrement is deferred in the goroutine; give it a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	for Inflight() > before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := Inflight(); got > before {
		t.Errorf("inflight = %d after 25 contained panics (baseline %d) — the guard leaked the saturation budget", got, before)
	}
}

// TestChaos25_HealthyMatchIsUnchanged is the no-regression half: with no fault
// injected, matching behaves exactly as before and charges no panic.
func TestChaos25_HealthyMatchIsUnchanged(t *testing.T) {
	before := MatchPanics()
	re := regexp.MustCompile(`evil`)

	if !matchRegexWithTimeout(re, []byte("this is evil"), time.Second) {
		t.Error("healthy match must still report a hit")
	}
	if matchRegexWithTimeout(re, []byte("this is fine"), time.Second) {
		t.Error("healthy non-match must still report a miss")
	}
	if got := MatchPanics() - before; got != 0 {
		t.Errorf("healthy matches charged %d panics, want 0", got)
	}
}
