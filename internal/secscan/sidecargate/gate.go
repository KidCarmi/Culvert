package sidecargate

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	// HeapBudget is the buffered-body heap the sidecar is willing to hold at
	// once. It is the only number here chosen rather than derived, and it is
	// deliberately a budget in BYTES: what runs out under load is memory, and
	// the per-request cost is the operator's `security.max_scan_mb`, so a
	// fixed REQUEST count would silently multiply the exposure of anyone who
	// widens the window — the one direction that must not surprise.
	HeapBudget = 256 << 20

	// MinSlots keeps a pathologically wide window from serialising the
	// sidecar completely. At or below this floor the budget is advisory: an
	// operator who sets a 512 MiB window has chosen a sidecar that holds two of
	// them, and the `/health` and `/metrics` surfaces say so.
	MinSlots = 2

	// MaxSlots is the ceiling, and it is NOT about memory. The engines
	// behind the handler have their own, much smaller concurrency: ClamAV
	// admits internal/clamav's clamMaxConcurrent = 4 at a time. Slots far above
	// that buy no throughput — they only let the HTTP layer buffer work the
	// engines cannot start, which is the defect. 32 is 8x the ClamAV limit,
	// chosen so the gate cannot be the bottleneck on any healthy deployment.
	MaxSlots = 32

	// QueueWait bounds how long a request waits for a slot, and it is
	// chosen AGAINST THE CALLER'S BUDGET rather than for its own sake.
	//
	// internal/secscan's ScanBodyTimeout is 10 s. Waiting past that would let
	// the caller's own deadline fire first, and the caller would then classify
	// a capacity refusal as `remoteOutcomeBudget` — fail-closed either way, but
	// counted as a timeout and pointing an operator at a slow scanner rather
	// than at a saturated one. Answering at 5 s keeps the classification,
	// and therefore the operator action ("add capacity"), correct.
	//
	// Same value and same role as internal/clamav's clamQueueWaitFallback.
	QueueWait = 5 * time.Second
)

// Slots derives the slot count from a scan window.
//
// Exposure is slots x (window+1) bytes of buffered body, so the slot count is
// the budget divided by the per-request cost, clamped at both ends for the
// reasons the two constants give. Pure, so the arithmetic is testable without
// a listener.
func Slots(window int64) int {
	if window <= 0 {
		return MaxSlots
	}
	slots := HeapBudget / (window + 1)
	if slots > MaxSlots {
		return MaxSlots
	}
	if slots < MinSlots {
		return MinSlots
	}
	return int(slots)
}

// Options configures one Gate. All fields are read once, in New.
type Options struct {
	// Slots is the number of holders admitted at once, normally Slots(window).
	// A value below 1 is raised to MinSlots: a gate that admits nothing would
	// refuse every request, and every caller of a refusing sidecar fails
	// CLOSED.
	Slots int

	// Inflight, when non-nil, is the gauge the gate adds to on admission and
	// subtracts from on release, so the owner can publish it without holding
	// the Gate (the sidecar's /metrics reads it that way). The gate only ever
	// applies its own +1/-1 pairs to it. Nil means the gate counts privately;
	// Gate.Inflight reads whichever is in use.
	Inflight *atomic.Int64

	// QueueWait overrides the bounded wait. Zero or negative means QueueWait,
	// which is what production uses.
	QueueWait time.Duration
}

// Gate is the bounded gate in front of the body read.
//
// Immutable after construction — the channel, the count and the wait are set
// in New and never reassigned — which is why its owner can hold one outside
// its own mutex. A window changed at runtime does not retune an already-built
// gate; that is recorded rather than fixed, because a resizable semaphore is
// materially more machinery than this fault needs and the owner derives the
// count again on every sidecar start.
type Gate struct {
	sem      chan struct{}
	slots    int
	wait     time.Duration
	inflight *atomic.Int64
	own      atomic.Int64
}

// New builds a gate. Gates are independent: two gates share nothing unless
// their owner hands both the same Options.Inflight gauge.
func New(o Options) *Gate {
	slots := o.Slots
	if slots < 1 {
		slots = MinSlots
	}
	wait := o.QueueWait
	if wait <= 0 {
		wait = QueueWait
	}
	g := &Gate{sem: make(chan struct{}, slots), slots: slots, wait: wait}
	g.inflight = o.Inflight
	if g.inflight == nil {
		g.inflight = &g.own
	}
	return g
}

// Slots is the number of holders this gate admits at once.
func (g *Gate) Slots() int { return g.slots }

// Inflight is the gauge this gate maintains: its own holders, or the shared
// total when the owner supplied Options.Inflight to more than one gate.
func (g *Gate) Inflight() int64 { return g.inflight.Load() }

// Acquire books one slot. The returned release is nil when admission failed
// and is always safe to defer otherwise; it must be called exactly once.
//
// Two selects, not one: the uncontended path must not allocate a timer, and on
// a sidecar that is not saturated that is every request.
//
// WHAT BOUNDS THE WAIT, precisely, because the obvious reading is wrong and
// the CHAOS-115 round's own test caught it. The gate's wait (QueueWait) is the
// operative bound and effectively the only one. An HTTP request carries no
// deadline over the wire, so `r.Context()` on the SERVER side has no deadline
// either, however short the caller's own budget is — that is exactly why
// QueueWait is chosen against internal/secscan's ScanBodyTimeout rather than
// left to the caller. `r.Context()` contributes CANCELLATION only, and
// net/http does not reliably deliver even that before the handler has started
// reading the body: measured, a client that aborted at 400 ms left its waiter
// parked until the 5 s backstop. Passing it is still right — a cancellation
// that does arrive frees the waiter early, and a handler must not outlive its
// request — but the guarantee is the backstop, not the caller.
//
// A parked waiter costs a goroutine and a connection it already had, and no
// buffer at all, which is the entire point of acquiring before the read.
func (g *Gate) Acquire(ctx context.Context) (release func(), ok bool) {
	select {
	case g.sem <- struct{}{}:
		g.inflight.Add(1)
		return g.release, true
	default:
	}

	waitCtx, cancel := context.WithTimeout(ctx, g.wait)
	defer cancel()
	select {
	case g.sem <- struct{}{}:
		g.inflight.Add(1)
		return g.release, true
	case <-waitCtx.Done():
		return nil, false
	}
}

// release returns the slot. The gauge is decremented BEFORE the channel receive
// so the gauge can never read above the slot count.
func (g *Gate) release() {
	g.inflight.Add(-1)
	<-g.sem
}
