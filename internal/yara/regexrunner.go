package yara

import (
	"regexp"
	"sync/atomic"
	"time"
)

// ── Per-scan regex worker ─────────────────────────────────────────────────────
//
// re.Match is not interruptible, so a hard per-string ReDoS deadline needs a
// goroutine to abandon. That harness — goroutine + channel + timer — used to be
// paid PER REGEX STRING, so its fixed cost scaled with the number of regex
// strings in the loaded rule set, on every scanned response body.
//
// Measured on this machine (Go 1.26, literal-prefixed regex, 16 KB body — the
// shape the shipped yara/sample_rules.yar compiles to):
//
//	re.Match alone                    423 ns/op    0 allocs/op      0 B/op
//	re.Match + per-string harness    2350 ns/op    5 allocs/op    425 B/op
//
// i.e. the guard cost 4.6x the work it guarded. Whole-ruleset scans scaled the
// same way: 5 allocs/461 B for 1 regex string, 50/4.3 KB for 10, 100/8.5 KB for
// 20, 250/21 KB for 50. The starter rule set alone carries 10 regex strings, so
// every scanned body paid ~19 us and ~4 KB of pure harness on top of ~4 us of
// actual matching.
//
// The harness is now hoisted to ONE worker goroutine per SCAN, reused across
// every regex string the scan evaluates, making the overhead constant in the
// regex-string count. This mirrors the same fix already shipped for the DPI
// content scanner (internal/scanner patternSet.scan); CLAUDE.md recorded the
// YARA half as a deliberate follow-up.
//
// The trade-off, stated plainly: a per-scan worker has to be set up and torn
// down, and that fixed cost is NOT free at the smallest size. Measured over 16 KB
// (BenchmarkMatch_Regex*, n=10):
//
//	regex strings │  before  │  after   │
//	      1       │  2.42us  │  3.18us  │  +31%   (5 -> 8 allocs)
//	      2       │  5.03us  │  5.52us  │  +10%   (10 -> 8 allocs)
//	      3       │  7.80us  │  6.92us  │  -11%   (15 -> 8 allocs)
//	     10       │  23.99us │  16.28us │  -32%   (50 -> 8 allocs)
//	     20       │  47.99us │  30.29us │  -37%   (100 -> 8 allocs)
//	     50       │ 118.83us │  72.81us │  -39%   (250 -> 8 allocs)
//
// So a rule set with ONE regex string is ~750 ns slower per scanned body; the
// break-even is three, and everything past it wins by a growing margin. That is
// accepted deliberately rather than papered over: the shipped starter rule set
// already carries ten, real deployments only add rules, and the alternative —
// keeping a second execution path just for the one-string shape — was built,
// measured (no better at 20 strings) and thrown away rather than carried.
//
// This is a COST change, not a POLICY change. Everything the old path decided,
// this path decides identically:
//
//   - The budget stays PER STRING. Each string re-arms the timer for a full
//     timeout, so a rule set of N regex strings still tolerates up to
//     N*timeout in total, exactly as it did with one timer each. (A whole-scan
//     budget would have been simpler, but it would fail closed — block
//     legitimate traffic — on a large body with many individually-fine strings.)
//   - A timeout still fails closed by default and still respects the
//     on_timeout posture, via the unchanged yaraTimeoutResult.
//   - A timeout still affects only the string that overran. The scan continues
//     with the remaining strings and rules; it is not aborted.
//   - Saturation still fails closed by default via the unchanged
//     yaraSaturationCheck, and abandoned goroutines are still counted by
//     yaraInflight so they cannot accumulate unbounded.
//
// yaraInflight's magnitude is unchanged. It never counted regex strings: a scan
// evaluates its strings SEQUENTIALLY, waiting for each, so a healthy scan only
// ever had one live regex goroutine at a time. It counted concurrent scans plus
// abandoned (hung) matches, and it still does — one worker per in-flight scan,
// released when the worker exits, which for an abandoned worker is when its
// runaway match finally returns.

// regexJob is one match request handed from a scan to its worker.
type regexJob struct {
	re   *regexp.Regexp
	data []byte
}

// regexRunner owns at most one worker goroutine for the lifetime of a scan.
//
// It is created lazily — a rule set with no regex strings never starts a
// goroutine, never allocates a timer, and never touches yaraInflight — and is
// discarded on the first timeout, because a worker stuck in a runaway match
// cannot be reused.
type regexRunner struct {
	jobs    chan regexJob
	results chan bool
	timer   *time.Timer

	// abandoned tells the worker the parent has already failed the outstanding
	// match closed, so it should stop rather than start any further work. The
	// runaway match itself cannot be interrupted; this only prevents burning CPU
	// beyond it.
	abandoned atomic.Bool

	// released guards the yaraInflight decrement so it happens exactly once,
	// whichever side gets there first — see release.
	released atomic.Bool
}

// release returns this worker's yaraInflight slot, at most once.
//
// Which side calls it is the whole accounting rule. The cap exists to bound
// goroutines the engine can no longer control, so the slot must be held for
// exactly as long as the goroutine is out of the scan's hands:
//
//   - Normal end of scan: the worker is IDLE, parked on jobs with no work left
//     and guaranteed to exit as soon as it is scheduled. The parent releases
//     SYNCHRONOUSLY in close, so the slot is free the instant the scan ends.
//   - Timeout: the worker is WEDGED in a match that cannot be interrupted. Only
//     the worker itself knows when that ends, so it releases on the way out.
//
// Releasing synchronously on the healthy path matters more than it looks. The
// worker now spans a whole scan rather than a single match, so leaving the
// decrement to the goroutine's exit lets short scans retire slower than they
// are created: under concurrent load the counter drifts up on workers that are
// already finished, reaches the cap, and starts failing scans closed — blocking
// clean traffic for no reason. Caught by TestRegexRunner_ConcurrentScans.
func (r *regexRunner) release() {
	if r.released.CompareAndSwap(false, true) {
		yaraInflight.Add(-1)
	}
}

// newRegexRunner starts a worker with the timer already armed for the caller's
// first match, and registers it in yaraInflight.
func newRegexRunner(timeout time.Duration) *regexRunner {
	r := &regexRunner{
		// Both buffered so neither side can be wedged by the other: the parent
		// can hand off a job without a rendezvous, and an abandoned worker can
		// publish the result nobody is waiting for and exit instead of leaking.
		jobs:    make(chan regexJob, 1),
		results: make(chan bool, 1),
		timer:   time.NewTimer(timeout),
	}
	yaraInflight.Add(1)
	go r.run()
	return r
}

// run is the worker half: match whatever arrives until the scan closes jobs.
//
// It may outlive its scan — that is the whole point of the timeout — which is
// why it touches nothing but its own regexRunner and the immutable arguments in
// the job.
func (r *regexRunner) run() {
	defer r.release()
	for j := range r.jobs {
		if r.abandoned.Load() {
			return
		}
		r.results <- j.re.Match(j.data)
	}
}

// close shuts down an IDLE worker at the end of a scan, freeing its inflight
// slot immediately. Callers must have collected the result of every job they
// submitted; a wedged worker is retired with abandon instead.
func (r *regexRunner) close() {
	r.timer.Stop()
	r.abandoned.Store(true)
	r.release()
	close(r.jobs)
}

// abandon retires a worker still stuck inside a match that blew its budget. The
// match cannot be interrupted, so the worker keeps its inflight slot — that is
// exactly the goroutine the cap exists to count — and releases it on exit.
func (r *regexRunner) abandon() {
	r.timer.Stop()
	r.abandoned.Store(true)
	close(r.jobs)
}

// matchRegex runs re against data under a per-string timeout, reusing this
// scan's worker goroutine.
//
// Returns true (suspicious / fail closed) when the match cannot be completed
// within timeout or when the in-flight cap is reached, unless the admin has
// selected fail_open_with_alert for that posture.
func (c *scanCtx) matchRegex(re *regexp.Regexp, data []byte, timeout time.Duration) bool {
	r := c.runner
	if r == nil {
		// Saturation and the approaching-saturation alert are evaluated where a
		// goroutine is actually about to be created. Reusing this scan's existing
		// worker adds no goroutine, so it cannot push the process over the cap and
		// is deliberately not re-checked (which also stops the degraded-mode alert
		// from firing once per regex string per scan while saturated).
		inflight := yaraInflight.Load()
		if saturated, result := yaraSaturationCheck(inflight); saturated {
			return result
		}
		yaraDegradedCheck(inflight)
		r = newRegexRunner(timeout)
		c.runner = r
	} else {
		// Re-arm for this string's own full budget. Safe without the classic
		// drain: since Go 1.23 timer channels are unbuffered and Stop/Reset are
		// guaranteed not to deliver a stale value afterwards, and go.mod pins
		// 1.26. (The old `if !t.Stop() { <-t.C }` idiom would now BLOCK here.)
		r.timer.Reset(timeout)
	}

	r.jobs <- regexJob{re: re, data: data}

	select {
	case matched := <-r.results:
		r.timer.Stop()
		return matched
	case <-r.timer.C:
		// The worker is wedged in this match and cannot be reused. Drop it — it
		// releases its yaraInflight slot when the match finally returns — and let
		// the next regex string in this scan start a fresh one.
		r.abandon()
		c.runner = nil
		return yaraTimeoutResult(timeout, re.String())
	}
}

// closeRegexRunner releases this scan's worker. Always deferred by Match, so a
// scan never leaves a goroutine parked on its jobs channel.
func (c *scanCtx) closeRegexRunner() {
	if c.runner != nil {
		c.runner.close()
		c.runner = nil
	}
}
