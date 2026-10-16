package main

import "time"

// monoEpoch anchors this process's monotonic clock reading. time.Now() records
// a wall-clock time AND a monotonic reading, and time.Sub/time.Since subtract
// the monotonic readings whenever both operands carry one — so
// time.Since(monoEpoch) is a pure monotonic measurement, unaffected by any
// wall-clock step.
var monoEpoch = time.Now()

// monoNanos returns the nanoseconds elapsed since monoEpoch, measured on the
// monotonic clock. It is the stamp source for any value that is later turned
// back into an elapsed duration, and it replaces time.Now().UnixNano() on
// those paths (CHAOS-71).
//
// Why the replacement matters: UnixNano() DISCARDS the monotonic reading (a
// time.Time carries one only in-process), and time.Unix(0, n) reconstructs a
// value that has none either. So the idiom
//
//	stamp := time.Now().UnixNano()
//	... later ...
//	elapsed := time.Since(time.Unix(0, stamp))
//
// subtracts two WALL-clock values. An NTP step, a VM suspend/resume, a
// container host's clock correction or a manual date change silently changes
// the measured elapsed time, and a BACKWARDS step makes it negative — so a
// `elapsed >= d` deadline simply does not fire for as long as the step was
// large, and a `elapsed < d` suppression gate stays latched for just as long.
//
// internal/admission already treats this as a contract for its cluster-count
// freshness stamp (clusterCountStore.FreshCount rejects a negative age, and
// internal/admission/AGENTS.md lists "future stamps" as a standing review
// control). Rejecting negatives is right where a bad stamp must fail CLOSED.
// It is the WRONG answer for a deadline whose expiry tears something down or
// flips a readiness row to fail: there, "negative means expired" would reap
// live tunnels and flap the probe on any backwards step, however small.
// Measuring on the monotonic clock removes the choice — the elapsed time is
// correct across a step in either direction, so neither caller needs a
// negative-age branch at all.
//
// NEVER PERSIST OR TRANSMIT A monoNanos STAMP. It is relative to THIS
// process's monoEpoch, so it is meaningless in another process or on another
// node: written to disk and read back after a restart, or gossiped to a peer,
// it would decode as an arbitrary instant. Every current holder is a
// process-local atomic.Int64 (the per-tunnel activity stamp,
// dpCPPollFailingSince, the two roster log gates) and none is serialised. A
// stamp that must survive a restart or cross a node boundary is an ABSOLUTE
// instant and belongs on the wall clock — see internal/mcp/rollout's persisted
// soak start, which pairs time.Unix(seconds, 0) with a negative-age clamp.
//
// Scope note: a monotonic reading does not advance while the machine is
// suspended on some platforms, so this measures elapsed RUNNING time. For an
// idle-teardown deadline and a probe grace window — both of which exist to
// bound how long this process holds something or hides something — running
// time is the intended quantity, not civil time.
//
// A stamp is STRICTLY POSITIVE (hence the +1), because 0 is the "never
// stamped" sentinel at every call site that holds one in an atomic.Int64 —
// readyz_dp_health.go's `since != 0`, the roster log gates' `last != 0`. On the
// wall clock that sentinel was unreachable for free: 0 is 1970. In a
// process-relative domain 0 is the process's own first nanosecond, so the
// invariant has to be stated rather than assumed. monoSince subtracts two
// stamps, so the offset cancels and no caller sees it.
//
// Var, not func, so a test can drive elapsed time deterministically; the same
// idiom tunnelIdleTimeout already uses. Tests that swap it must not run in
// parallel.
var monoNanos = func() int64 { return int64(time.Since(monoEpoch)) + 1 }

// monoSince returns the duration elapsed since a stamp taken from monoNanos.
func monoSince(stamp int64) time.Duration { return time.Duration(monoNanos() - stamp) }
