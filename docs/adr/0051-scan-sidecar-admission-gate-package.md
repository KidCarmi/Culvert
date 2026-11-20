# ADR-0051: The scan sidecar's admission gate is owned by internal/secscan/sidecargate

- Status: Proposed for review with the implementation PR (IM-016, 2026-11-20).
- Numbering: ADR-0050 is the highest merged; ADR-0040 is reserved by open
  PR #1526. No other open PR adds a numbered file under `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-016.
  Related: ADR-0002, ADR-0038 (instance-owned state), ADR-0042..0050.

## Context

`scan_svc_admission.go` (273 lines, package main; CHAOS-115) held two
responsibilities:

1. **An engine.** The slot arithmetic (`scanSvcAdmissionSlots`: a 256 MiB
   buffered-body budget divided by `window+1`, clamped to 2..32), the channel
   semaphore, the two-select acquire with its bounded wait
   (`scanSvcQueueWait`, 5 s, chosen against the caller's 10 s
   `secscan.ScanBodyTimeout`), and the release order (gauge before slot, so
   the gauge never reads above the slot count). It referenced two root names:
   the process gauge `scanSvcInflight`, which it wrote directly, and the
   published slot count `scanSvcSlots`.
2. **Composition.** The two process gauges that `/metrics` (`metrics.go`) and
   the sidecar's `/health` read without a `ScanService` handle, the test seam
   that forces a slot count (`scanSvcSlotsOverride`), the HTTP 429 writer and
   its saturation counter, and the throttled, sanitized refusal line.

The gate was already an instance (`ScanService.admission`, set once in
`NewScanService`). Only its in-flight count was a package global.

ADR-0002 does not list the scan sidecar files; `security_scan.go` (the
proxy-side scan wiring it does list) is not touched. So there is no conflict
to supersede.

## Decision

Move the engine (1) to `internal/secscan/sidecargate` with 8 exported
identifiers: the constants `HeapBudget`, `MinSlots`, `MaxSlots` and
`QueueWait`, the function `Slots`, and `Options`, `Gate` and `New` (`Gate`
has the methods `Acquire`, `Slots` and `Inflight`). Keep the composition (2)
in main.

- **The gauge is injected, not owned by the package.** `Options.Inflight` is
  a `*atomic.Int64` the gate adds to on admission and subtracts from on
  release. Main passes `&scanSvcInflight`, so `/metrics`, `/health` and every
  root test read the same variable as before, and the gate remains its only
  writer. Without it a gate counts privately, so two gates share nothing
  unless their owner hands both the same gauge. A pointer rather than a pair
  of callbacks keeps the uncontended path at the one allocation it had before
  the move (measured on main `28de730` and after: 1).
- **The wait is an option with the production default.** `Options.QueueWait`
  exists so the bounded-wait behavior is testable in milliseconds; zero means
  `QueueWait`, and main does not set it.
- **Root keeps `newScanSvcAdmission`** as the binding: derive the count,
  apply the test override, publish `scanSvcSlots`, build the gate with the
  process gauge. `scan_svc.go` changes on four lines (the field type,
  `Acquire`, two `Slots()` reads). `scanSvcQueueWait` stays as a constant
  bound to `sidecargate.QueueWait` for the refusal line and the root tests
  that bound the handler by it.
- **One new input rule.** `New` raises a slot count below 1 to `MinSlots`.
  Main never passes one (the derived count is at least 2 and the override is
  applied only when positive), so no production path changes; the rule exists
  because a gate that admits nothing refuses every request and every caller
  of a refusing sidecar fails closed.

The package sits under `internal/secscan` because the wait is defined
against that package's caller budget and the 429 the handler answers on a
refusal is that package's fail-closed capacity outcome. The dependency does
not run in either direction in production code: `sidecargate` imports no
Culvert package, and one external test compares the two constants.

Lifecycle, in one sentence: `NewScanService` builds one `Gate` and holds it
for the life of the `ScanService`; the gate starts no goroutine, owns no
context, and each `Acquire` waits only on the caller's context and its own
bounded timer.

Unchanged: the slot count for every window, the 5 s wait, the 429 status and
body, the refusal counter and log line (`sanitizeLog` + `%q` on the remote
address), the `/metrics` series and their configured-sidecar guard, the
`/health` fields, the acquire-before-read order in `handleScan`, and the
gauge-before-slot release order.

## Tests

Moved with names and assertions unchanged (engine-only):
`TestChaos115_SlotArithmetic` and `TestChaos115_HeapCeilingIsStatedNotImplied`.

Stay root (they need the sidecar's HTTP server, the scan window and the
secscan client): the other eight `TestChaos115_*` tests in
`scan_svc_admission_chaos_test.go` and the `benchgate`-tagged heap
measurement. None of them changed.

New engine tests: refusal after the configured wait (and not the default),
the deadlineless waiter bounded by the gate, early release on cancellation,
admission when a slot frees, the gauge never above the slot count,
independent instances, the injected gauge maintained and restored, the
floor for a non-positive count, the defaults, the allocation count, the
`QueueWait < secscan.ScanBodyTimeout` relation, and a boundary test (no
Culvert import, no package variable, no `init`, no I/O/logging/`sync`
imports, exported-surface cap) with negative controls.

Mutation checks: changing the divisor to `window` or ignoring the configured
wait fails deterministically. Swapping the release order (slot before gauge)
failed 5 of 7 runs of the gauge test; the window is a few instructions wide,
so that control is probabilistic and the order is also stated at the
function.

## Consequences

The gate is testable without compiling the application and without a 5 s
wait per case. The process gauges stay where their readers are. A second
sidecar listener in one process, if one is ever added, can choose whether to
share the gauge. The root constant `scanSvcQueueWait` can be removed later by
naming the package at its uses.
