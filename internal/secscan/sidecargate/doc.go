// Package sidecargate is the admission gate in front of the scan sidecar's
// body read (CHAOS-115; IM-016, ADR-0051).
//
// THE RULE. The sidecar's /scan handler buffers up to window+1 bytes of
// request body before any engine runs. Without a bound, its buffered-body
// exposure is open_connections x (window+1), set by whatever the network
// delivers. The gate bounds how many handlers may be buffering at once and
// tells the handler when to refuse the overflow:
//
//   - The slot count is a budget in BYTES divided by the per-request cost
//     (Slots), clamped to [MinSlots, MaxSlots]. What runs out under load is
//     memory and the per-request cost is the operator's scan window, so a
//     fixed request count would silently multiply the exposure of anyone who
//     widens the window.
//   - A request that finds every slot busy waits at most QueueWait. That
//     value is chosen against the caller's own budget (internal/secscan's
//     ScanBodyTimeout): answering before the caller's deadline keeps a
//     capacity refusal classified as capacity rather than as a timeout.
//   - A parked waiter costs a goroutine and a connection it already had, and
//     no buffer at all. That is the point of acquiring before the read.
//
// Ownership: package main owns the ScanService that holds the Gate, the
// decision to answer HTTP 429 (the status the secscan client fails CLOSED
// on), the refusal counter, the throttled log line, the process gauges that
// /metrics and /health publish, and the test seam that forces a slot count.
// This package owns the slot arithmetic, the semaphore, the bounded wait and
// the order in which the in-flight gauge and the slot are released. It holds
// no package-level state, starts no goroutines, does no I/O or logging and
// imports no other Culvert package.
package sidecargate
