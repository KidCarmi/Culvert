package secscan

// F-P2 (PR #1528): a clean verdict from clamd is not trusted while clamd is
// faulting.
//
// Lab run 38013626508 recorded every clamd conversation during repeated
// root-filesystem fills. Once, clamd answered a bare "stream: OK" to a complete
// 142-byte EICAR stream (2 ms, against 8-11 ms for the detections around it),
// and the body was delivered. Culvert's parser did what it must — a single OK
// reply IS the protocol's clean verdict — so nothing in the reply can tell a
// real clean from this one. What does distinguish them is the company it
// keeps: the bad OK came 0.44 s after clamd failed another stream with
// "Error writing to temporary file", and in 280 recorded at-fill samples
// clamd never answered OK to an EICAR outside such an episode.
//
// So a genuine engine fault (recordClamFailure's default branch: not our own
// deadline, not our own capacity limit) opens a quarantine window, and every
// further fault extends it. Inside the window a clean ClamAV verdict is
// treated like the fault it may be hiding: never cached, and under
// av_unavailable=closed the body is REFUSED — the posture the operator chose
// for "the AV engine cannot vouch for this content". Detections inside the
// window still block (blocking is always the safe reading). The window ends
// on its own once clamd has gone clamQuarantineWindow without a fault.
//
// This is reactive by construction: a bad OK that precedes the first fault of
// an episode is not caught. That residual is recorded with the reproduction
// (test/e2e/appliance/lab/evidence/fp2-reproduction.md) and reported upstream.

import (
	"fmt"
	"sync/atomic"
	"time"
)

// clamQuarantineWindow is how long after the last engine fault clean verdicts
// stay untrusted. Long enough to cover the episodes recorded in the lab (the
// silent OK followed a fault by 0.44 s; faults recur every few hundred ms while
// the spool is full) with a wide margin, short enough that one transient fault
// costs at most a minute of refusals under the closed posture.
const clamQuarantineWindow = 60 * time.Second

// ClamQuarantineWindow exposes the window to tests outside the package.
const ClamQuarantineWindow = clamQuarantineWindow

var (
	// statClamCleanQuarantined counts clean ClamAV verdicts not trusted
	// because they arrived inside the window (refused under closed, forwarded
	// uncached under open).
	statClamCleanQuarantined int64
	// quarantineNow is the clock seam for tests.
	quarantineNow = time.Now
)

// noteClamEngineFault opens (or extends) the quarantine window. The stamp is
// per Scanner (one in production): the window describes THIS daemon.
func (ss *Scanner) noteClamEngineFault() { ss.lastClamEngineFault.Store(quarantineNow().UnixNano()) }

// clamQuarantineRemaining reports how much of the window is left (0 = not
// quarantined). A fault stamped in the FUTURE (the clock went backwards) keeps
// the quarantine on — the fail-safe reading — but re-stamps it at the current
// time, so a large rollback costs one window, never an indefinite one.
func (ss *Scanner) clamQuarantineRemaining() time.Duration {
	t := ss.lastClamEngineFault.Load()
	if t == 0 {
		return 0
	}
	now := quarantineNow().UnixNano()
	age := time.Duration(now - t)
	if age < 0 {
		ss.lastClamEngineFault.CompareAndSwap(t, now)
		return clamQuarantineWindow
	}
	if age >= clamQuarantineWindow {
		return 0
	}
	return clamQuarantineWindow - age
}

// clamQuarantineStatus is the ClamAVStatus value while the window is open:
// the daemon may answer, but this node will not vouch for its clean verdicts.
func clamQuarantineStatus(remaining time.Duration) string {
	return fmt.Sprintf("%s: clean verdicts quarantined for %ds after an engine fault",
		ClamStatusScanFailingPrefix, int(remaining.Round(time.Second)/time.Second))
}

// ClamCleanQuarantinedTotal reports clean verdicts not trusted so far.
func ClamCleanQuarantinedTotal() int64 { return atomic.LoadInt64(&statClamCleanQuarantined) }

// SetClamQuarantineClockForTest replaces the quarantine clock (nil restores
// time.Now) and returns a restore func.
func SetClamQuarantineClockForTest(now func() time.Time) (restore func()) {
	prev := quarantineNow
	if now == nil {
		now = time.Now
	}
	quarantineNow = now
	return func() { quarantineNow = prev }
}
