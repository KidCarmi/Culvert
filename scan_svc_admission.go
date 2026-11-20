package main

// Scan-sidecar admission control — CHAOS-115.
//
// WHY THIS FILE EXISTS. The sidecar's `/scan` handler read the request body
// before doing anything else:
//
//	data, truncated, err := readScanWindow(r.Body, scanSvcWindow())
//
// `readScanWindow` buffers up to `window+1` bytes into this process's heap, and
// nothing above it bounded how many handlers could be inside that call at once.
// The sidecar's buffered-body exposure was therefore
// `open_connections x (window+1)`, with `open_connections` set by whatever the
// network delivered — not by any configured capacity.
//
// MEASURED on the pre-fix tree (TestChaos115_SlowCallersCannotOutrunTheWindow's
// ancestor), 1 MiB window, callers that declare Content-Length and then stall
// one byte short so every handler parks inside readScanWindow:
//
//	slow callers | handlers in readScanWindow | sidecar heap delta
//	          64 |                         64 |            75.8 MiB
//	         192 |                        192 |           244.5 MiB
//
// Linear, at ~1.27x the window per request — io.ReadAll grows by doubling, so a
// request transiently holds the old buffer and the new one. Extrapolated to the
// shipped 5 MiB default that is ~1.2 GiB at 192 concurrent callers, and to a
// 20 MiB fleet ~4.9 GiB. The SIMULATE list's "thousands of simultaneous
// connections" row needs no malice to get there: a shared sidecar's concurrency
// is the SUM over every node pointed at it, and `scan_svc.go`'s own doc comment
// offers "shared scanning: multiple proxy instances sharing one scanner" as a
// reason to deploy it.
//
// WHY IT MATTERED MORE THAN AN ORDINARY MEMORY BUG. The sidecar is the process
// the CHAOS-52 runbook RECOMMENDS as the remedy for in-process scanner faults,
// and its death is not one node's problem: every caller pointed at a sidecar
// that is not answering takes `internal/secscan`'s fail-OPEN branch
// (remoteScanFail, recorded owner decision WK-2b) and forwards bodies
// UNSCANNED. So the pre-fix failure mode was a security control that collapses
// fleet-wide, under load, with the OOM arriving exactly when traffic is
// heaviest — and CHAOS-113/114's supervisor cannot help, because an OOM kill
// takes the whole process, not the listener. On restart the queued storm hits
// the fresh process immediately, which is the crash-loop shape CHAOS-114's flap
// detector pages for with a remedy that names "an OOM kill" but cannot name the
// cause.
//
// WHAT THIS FILE DOES, AND WHAT IT DELIBERATELY DOES NOT. It bounds the number
// of handlers that may be buffering a body at once, and refuses the overflow
// with HTTP 429. It does NOT invent a posture: `internal/secscan`'s client has
// classified 429 as `remoteOutcomeCapacity` -> `remoteScanRefused` -> fail
// CLOSED since CHAOS-52, with its own counter (`statRemoteScanSaturated`,
// `culvert_remote_scan_saturated_total`), the local path's timeout vocabulary
// and the existing `scan_timeout` alert — and with a test,
// TestChaos_SidecarCapacityRefusalFailsClosed. scanOnce's comment on that
// branch used to say the quiet part out loud — "The shipped sidecar never emits
// 429 today; a load balancer or a third-party scanner in front of it can" — and
// that sentence is what this file falsifies, so it has been corrected in place
// (internal/secscan/remote.go) rather than left to tell the next reader that
// the branch is dead. It is not: it is now the branch a saturated fleet takes,
// and anything that reclassified it would drop the refusal through to
// "sidecar returned HTTP %d", which is a FAULT and fails OPEN.
//
// The caller's half of this contract was complete, tested and unreachable. This
// file reaches it. No wire field, no new alert event and no caller change.
//
// THE SHAPE IS THE ONE THE TREE ALREADY USES. internal/clamav's acquireSlot
// bounds concurrent ClamAV scans with a channel semaphore, waits on the
// CALLER's budget, and reports a distinguishable queue-full outcome precisely
// so an operator can tell "at capacity, add capacity" from "the engine
// faulted". This is that function, one layer out, for the resource the HTTP
// layer spends before any engine is reached.
//
// WHERE THE ENGINE LIVES. The slot arithmetic, the semaphore, the bounded wait
// and the gauge-before-slot release order are internal/secscan/sidecargate
// (IM-016, ADR-0051). This file is the sidecar's composition around it: the
// process gauges /metrics and /health read, the test seam that forces a slot
// count, the 429 and its counter, and the throttled refusal line.

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan/sidecargate"
)

const (
	// scanSvcQueueWait is how long a request waits for a slot before the
	// handler answers 429. The value and the reason it is chosen against the
	// caller's budget are sidecargate.QueueWait's; the name stays here for the
	// refusal line and the tests that bound the handler by it.
	scanSvcQueueWait = sidecargate.QueueWait

	// scanSvcCapacityLogInterval throttles the refusal line. The producer's
	// rate is set by TRAFFIC, so the same discipline refuseTruncatedScan and
	// internal/secscan's degraded lines use applies: the counter carries the
	// magnitude, the line carries the news.
	scanSvcCapacityLogInterval = time.Minute
)

// statScanSvcAtCapacity counts /scan requests refused because every slot was
// busy for scanSvcQueueWait. It is a SATURATION counter, not a fault counter:
// the scanner is healthy and this node is at its scanning capacity, which is
// the distinction internal/clamav's ErrQueueFull doc and the caller's
// statRemoteScanSaturated both exist to preserve.
var statScanSvcAtCapacity int64

// lastScanSvcCapacityLog throttles the refusal log line (CAS shape shared with
// scanSvcOversizeLogAllowed).
var lastScanSvcCapacityLog atomic.Int64

// scanSvcInflight is the number of /scan handlers currently holding a slot —
// i.e. currently permitted to buffer a body. Package-level because /metrics and
// /healthz read it without a ScanService handle, and there is one sidecar per
// process. Every gate newScanSvcAdmission builds is handed this gauge and is
// its only writer.
//
// It is the sidecar-side sibling of the caller's culvert_remote_scan_inflight:
// a value pinned at the slot count means requests are queueing for a slot,
// which is the leading indicator of the refusal regime.
var scanSvcInflight atomic.Int64

// scanSvcSlots publishes the derived slot count for the same two surfaces.
// Written once per NewScanService, read by /metrics, /health and the tests.
var scanSvcSlots atomic.Int64

// scanSvcSlotsOverride forces the slot count. A seam only for this package's
// white-box tests (same role as scanSvcListenHook), and 0 — ignored — in
// production: the derived count is 32 at the shipped 5 MiB default and still 12
// at 16 MiB, and filling that many slots with real bodies to reach the refusal
// path would make the gates both slow and allocation-heavy for no added
// coverage. The arithmetic it bypasses has its own direct test, and the two
// wait-bound gates need a FULL gate rather than a large one.
var scanSvcSlotsOverride atomic.Int64

// newScanSvcAdmission builds the gate for the window configured now, publishes
// its slot count and binds it to the process in-flight gauge.
func newScanSvcAdmission(window int64) *sidecargate.Gate {
	slots := sidecargate.Slots(window)
	if forced := scanSvcSlotsOverride.Load(); forced > 0 {
		slots = int(forced)
	}
	scanSvcSlots.Store(int64(slots))
	return sidecargate.New(sidecargate.Options{Slots: slots, Inflight: &scanSvcInflight})
}

// refuseScanAtCapacity answers 429 for a request that could not get a slot.
//
// 429 and not 503: the caller's scanOnce switch reads 429 as
// `remoteOutcomeCapacity` and fails CLOSED with the saturation counter, while
// any other non-200 becomes `sidecar returned HTTP %d` — a FAULT, which fails
// OPEN. Getting the status wrong here would turn this fix into a fleet-wide
// fail-open under exactly the load it exists to survive, so the status code is
// load-bearing and TestChaos115_CapacityRefusalFailsClosedAtTheCaller gates it
// through the real client rather than by inspection.
func refuseScanAtCapacity(w http.ResponseWriter, r *http.Request, slots int) {
	atomic.AddInt64(&statScanSvcAtCapacity, 1)
	if scanSvcCapacityLogAllowed() {
		logger.Printf("ScanSvc: refused /scan from %q — all %d scan slot(s) busy for %s; the sidecar is at capacity and callers fail CLOSED (blocked, not forwarded); window %d bytes, total %d",
			sanitizeLog(r.RemoteAddr), slots, scanSvcQueueWait, scanSvcWindow(), atomic.LoadInt64(&statScanSvcAtCapacity))
	}
	http.Error(w, "scan service at capacity", http.StatusTooManyRequests)
}

// scanSvcCapacityLogAllowed reports whether enough time has passed to log
// another refusal. Same CAS shape as scanSvcOversizeLogAllowed.
func scanSvcCapacityLogAllowed() bool {
	now := time.Now().UnixNano()
	prev := lastScanSvcCapacityLog.Load()
	if prev != 0 && now-prev < int64(scanSvcCapacityLogInterval) {
		return false
	}
	return lastScanSvcCapacityLog.CompareAndSwap(prev, now)
}
