package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// M5 supportability: a bounded in-memory ring of recent HA role transitions.
// There was no failover-event history surfaced before this — an operator could
// see the CURRENT role/term/epoch on /api/cluster/ha but had no record of WHEN
// the node last promoted or self-fenced. This ring is a RAW FACT surface only:
// it records transitions as they happen and hands them to the HA panel + support
// bundle; it draws no conclusion about split-brain or cluster-wide causality
// (that correlation is the TAC Cloud tier's job, per the REVISION 2 two-track
// split). It is VOLATILE — in-memory, cleared on restart, never CP→DP synced.

// haFailoverMaxEvents bounds the ring. Role transitions are rare (a healthy
// cluster sees none for days), so a small cap still holds a long history; the
// bound exists only to cap memory against a pathological flap loop.
const haFailoverMaxEvents = 64

// haFailoverEvent is one recorded HA role transition. Times are RFC3339 UTC;
// from_role/to_role are the low-cardinality HA role labels; reason is a bounded
// internal descriptor (promotion trigger or self-fence cause); epoch is the
// fencing epoch in effect at the transition (0 = legacy / no lease).
type haFailoverEvent struct {
	TS       string `json:"ts"`
	FromRole string `json:"from_role"`
	ToRole   string `json:"to_role"`
	Reason   string `json:"reason,omitempty"`
	Epoch    int64  `json:"epoch,omitempty"`
}

// haFailoverRing is a bounded, mutex-guarded ring. It is written from failover
// goroutines (promote runs on the standby loop or a manual-promote request;
// selfFence runs on the lease keepalive loop) and read from the /api/cluster/ha
// HTTP handler, so every access takes the mutex (verified under -race).
type haFailoverRing struct {
	mu     sync.Mutex
	events []haFailoverEvent
}

// globalHAFailoverRing is an atomic.Pointer so tests can swap in an isolated
// ring (haFailoverRingSwapForTest) race-free while background failover
// goroutines concurrently Load() it to record — a plain package-var reassign
// would data-race those reads under -race.
var globalHAFailoverRing atomic.Pointer[haFailoverRing]

func init() { globalHAFailoverRing.Store(&haFailoverRing{}) }

// record appends a transition, evicting the oldest once at capacity. reason is
// length-bounded so a flap loop with verbose lease errors cannot balloon a row.
func (r *haFailoverRing) record(fromRole, toRole, reason string, epoch int64, now time.Time) {
	ev := haFailoverEvent{
		TS:       now.UTC().Format(time.RFC3339),
		FromRole: fromRole,
		ToRole:   toRole,
		Reason:   boundedErr(reason),
		Epoch:    epoch,
	}
	r.mu.Lock()
	r.events = append(r.events, ev)
	if len(r.events) > haFailoverMaxEvents {
		// Re-slice to the newest cap-many, copied into a fresh backing array so
		// the evicted head is not pinned by the growing slice offset.
		trimmed := make([]haFailoverEvent, haFailoverMaxEvents)
		copy(trimmed, r.events[len(r.events)-haFailoverMaxEvents:])
		r.events = trimmed
	}
	r.mu.Unlock()
}

// list returns a copy of the ring, NEWEST first (most recent transition on top,
// matching how the HA panel renders it).
func (r *haFailoverRing) list() []haFailoverEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]haFailoverEvent, len(r.events))
	for i, ev := range r.events {
		out[len(r.events)-1-i] = ev
	}
	return out
}

// haFailoverRingSwapForTest installs a fresh isolated ring and returns a restore
// func — the per-test isolation seam (mirrors swapAutoExclude). Race-free via the
// atomic pointer even while failover goroutines record concurrently.
func haFailoverRingSwapForTest() (restore func()) {
	prev := globalHAFailoverRing.Load()
	globalHAFailoverRing.Store(&haFailoverRing{})
	return func() { globalHAFailoverRing.Store(prev) }
}
