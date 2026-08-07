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
//	      1       │  2.42us  │  4.29us  │  +77%   (5 -> 8 allocs)
//	      2       │  5.03us  │  5.39us  │   +7%   (10 -> 8 allocs)
//	      3       │  7.80us  │  6.11us  │  -22%   (15 -> 8 allocs)
//	     10       │  23.99us │  16.76us │  -30%   (50 -> 8 allocs)
//	     20       │  47.99us │  31.54us │  -34%   (100 -> 8 allocs)
//	     50       │ 118.83us │  75.69us │  -36%   (250 -> 8 allocs)
//
// So a rule set with ONE regex string is ~1.9 us slower per scanned body; the
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
//   - Saturation is still checked per MATCH via the unchanged
//     yaraSaturationCheck, still fails closed by default, and abandoned
//     goroutines are still counted by yaraInflight so they cannot accumulate.
//
// yaraInflight keeps its exact old meaning: the number of regex matches
// currently running, plus abandoned ones still burning CPU. It is booked when a
// match starts and given back when it returns — NOT held for the lifetime of the
// worker. See charge/releaseCharge for why that distinction is load-bearing;
// getting it wrong blocks clean traffic under the default fail-closed posture.

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

	// charged is true while a yaraInflight slot is booked for the match that is
	// currently outstanding — see charge/releaseCharge.
	charged atomic.Bool
}

// charge books a yaraInflight slot for the match about to start, and
// releaseCharge gives it back. Exactly one release happens per charge: the CAS
// makes it whichever side gets there first.
//
// The slot tracks the MATCH, not the worker. That distinction is the whole
// accounting rule, and getting it wrong is a fail-closed availability bug in
// both directions:
//
//   - Hold it for the worker's LIFETIME and a scan that has finished its regex
//     strings keeps occupying the cap while it evaluates literal strings and
//     later rules. Concurrent clean scans then trip yaraSaturationCheck and are
//     blocked under the default fail-closed posture, with no regex work
//     actually running. The old per-string code never did this, because each
//     match's goroutine released as soon as that match returned.
//     (Reported on PR #1067; pinned by TestRegexRunner_IdleWorkerHoldsNoSlot
//     and TestRegexRunner_IdleWorkerDoesNotSaturatePeers.)
//   - Release it ASYNCHRONOUSLY, from the worker's exit, and short scans retire
//     slots slower than they book them; under concurrent load the counter
//     drifts up on already-finished work, reaches the cap, and blocks clean
//     traffic just the same. (Pinned by TestRegexRunner_ConcurrentScans.)
//
// So the parent books before handing off a job and releases the moment the
// result arrives. The one case it must NOT release is a timeout: the worker is
// still wedged inside a match that cannot be interrupted, which is precisely
// the runaway goroutine the cap exists to count. There the charge is handed to
// the worker, which releases it on the way out.
func (r *regexRunner) charge() {
	r.charged.Store(true)
	yaraInflight.Add(1)
}

func (r *regexRunner) releaseCharge() {
	if r.charged.CompareAndSwap(true, false) {
		yaraInflight.Add(-1)
	}
}

// newRegexRunner starts a worker with the timer already armed for the caller's
// first match. It does not book an inflight slot — charge does that per match.
func newRegexRunner(timeout time.Duration) *regexRunner {
	r := &regexRunner{
		// Both buffered so neither side can be wedged by the other: the parent
		// can hand off a job without a rendezvous, and an abandoned worker can
		// publish the result nobody is waiting for and exit instead of leaking.
		jobs:    make(chan regexJob, 1),
		results: make(chan bool, 1),
		timer:   time.NewTimer(timeout),
	}
	go r.run()
	return r
}

// run is the worker half: match whatever arrives until the scan closes jobs.
//
// It may outlive its scan — that is the whole point of the timeout — which is
// why it touches nothing but its own regexRunner and the immutable arguments in
// the job.
// The deferred releaseCharge is the abandoned case: on a normal scan the parent
// has already released each match's charge, so the CAS finds nothing to give
// back and this is a no-op.
func (r *regexRunner) run() {
	defer r.releaseCharge()
	for j := range r.jobs {
		if r.abandoned.Load() {
			return
		}
		r.results <- j.re.Match(j.data)
	}
}

// close shuts down an IDLE worker at the end of a scan. Callers must have
// collected the result of every job they submitted — so no charge is
// outstanding — and a wedged worker is retired with abandon instead.
func (r *regexRunner) close() {
	r.timer.Stop()
	r.abandoned.Store(true)
	close(r.jobs)
}

// abandon retires a worker still stuck inside a match that blew its budget. The
// match cannot be interrupted, so the worker inherits the outstanding charge —
// that is exactly the goroutine the cap exists to count — and releases it when
// the match finally returns.
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
	// Saturation is evaluated per MATCH, exactly as the old per-string code did:
	// the cap governs concurrent regex work, and this is the point where this
	// scan is about to add some. Checking it once per scan instead would let a
	// scan that started before the engine saturated keep matching afterwards.
	inflight := yaraInflight.Load()
	if saturated, result := yaraSaturationCheck(inflight); saturated {
		return result
	}
	yaraDegradedCheck(inflight)

	r := c.runner
	if r == nil {
		r = newRegexRunner(timeout)
		c.runner = r
	} else {
		// Re-arm for this string's own full budget. Safe without the classic
		// drain: since Go 1.23 timer channels are unbuffered and Stop/Reset are
		// guaranteed not to deliver a stale value afterwards, and go.mod pins
		// 1.26. (The old `if !t.Stop() { <-t.C }` idiom would now BLOCK here.)
		r.timer.Reset(timeout)
	}

	r.charge()
	r.jobs <- regexJob{re: re, data: data}

	select {
	case matched := <-r.results:
		r.timer.Stop()
		r.releaseCharge()
		return matched
	case <-r.timer.C:
		// The worker is wedged in this match and cannot be reused. Drop it — it
		// inherits the charge and releases it when the match finally returns —
		// and let the next regex string in this scan start a fresh one.
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
