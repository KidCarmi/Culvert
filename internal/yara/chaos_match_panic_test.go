package yara

// chaos_match_panic_test.go — CHAOS-25: per-match goroutine panic containment.
//
// matchRegexWithTimeout spawns a goroutine PER REGEX MATCH, on the content-scan
// path, over attacker-supplied bytes. Go terminates the process on an
// unrecovered panic in any goroutine, so a fault in the regexp engine (or a
// corrupt compiled rule) there is a total outage of an in-line gateway.
//
// The containment is only half the fix. The other half is WHAT VERDICT a
// faulted match yields: a panic produced no answer, so returning "no match"
// would convert an engine fault into a silent CLEAN verdict and let the scanned
// object through. A faulted match is epistemically identical to a timed-out
// match, so it takes the same admin-controlled on_timeout posture — fail closed
// unless the admin explicitly chose fail_open_with_alert.

import (
	"regexp"
	"testing"
	"time"
)

func withOnTimeout(t *testing.T, posture string) {
	t.Helper()
	prev := GetOnTimeout()
	SetOnTimeout(posture)
	t.Cleanup(func() { SetOnTimeout(prev) })
}

// A nil compiled rule is the cheapest faithful stand-in for a corrupt *Regexp:
// (*Regexp).Match dereferences the receiver, so this panics inside the spawned
// goroutine exactly where a real engine fault would.
func TestChaos25_YaraMatchPanic_IsContainedAndFailsClosed(t *testing.T) {
	withOnTimeout(t, FailClosed)

	if got := matchRegexWithTimeout(nil, []byte("payload"), 5*time.Second); !got {
		t.Fatal("a faulted match returned CLEAN under the fail-closed posture — an engine fault must never " +
			"become a silent clean verdict on a security scan")
	}
}

// The posture is the admin's call, in both directions: an operator who chose
// availability over inspection must still get it.
func TestChaos25_YaraMatchPanic_HonoursFailOpenPosture(t *testing.T) {
	withOnTimeout(t, FailOpenWithAlert)

	if got := matchRegexWithTimeout(nil, []byte("payload"), 5*time.Second); got {
		t.Fatal("a faulted match blocked despite the fail_open_with_alert posture")
	}
}

// The guard is on the CALL, not the goroutine: the goroutine must still deliver
// a verdict on the channel. A guard that let it return silently would park the
// scan for the FULL timeout on every match — a deterministic fault would then
// add 5s per regex to every scanned object, which is a DoS in its own right.
func TestChaos25_YaraMatchPanic_DoesNotStallForTheWholeTimeout(t *testing.T) {
	withOnTimeout(t, FailClosed)

	start := time.Now()
	matchRegexWithTimeout(nil, []byte("payload"), 3*time.Second)
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("a faulted match took %s — the guard must deliver the verdict immediately, "+
			"not park the caller until the timeout expires", elapsed)
	}
}

// The inflight gauge drives the saturation posture. A faulted match must still
// decrement it, or a repeatable fault would walk the gauge up to the cap and
// take every LATER match down the saturation path.
func TestChaos25_YaraMatchPanic_ReleasesTheInflightSlot(t *testing.T) {
	withOnTimeout(t, FailClosed)

	// Settle first: an abandoned goroutine from an earlier test decrements
	// asynchronously, so sampling the gauge without waiting reads a transient.
	waitInflight(t, 0, "baseline")
	for i := 0; i < 20; i++ {
		matchRegexWithTimeout(nil, []byte("payload"), time.Second)
	}
	waitInflight(t, 0, "after 20 faulted matches")
}

// waitInflight waits for the inflight gauge to reach want, then fails with the
// observed value. The gauge is released by a deferred Add in the match
// goroutine, so it converges rather than being instantaneous.
func waitInflight(t *testing.T, want int64, when string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if yaraInflight.Load() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("inflight = %d, want %d (%s) — faulted matches leaked their slots toward the saturation cap",
		yaraInflight.Load(), want, when)
}

// A clean match must be byte-identical in behavior: the guard is not allowed to
// change any verdict on the healthy path.
func TestChaos25_YaraGuardDoesNotChangeHealthyVerdicts(t *testing.T) {
	withOnTimeout(t, FailClosed)

	re := regexp.MustCompile(`evil`)
	if !matchRegexWithTimeout(re, []byte("this is evil content"), 5*time.Second) {
		t.Error("a matching pattern no longer matches")
	}
	if matchRegexWithTimeout(re, []byte("this is fine"), 5*time.Second) {
		t.Error("a non-matching pattern now reports a match")
	}
}
