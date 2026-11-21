// Package keyedmutex provides a per-key mutual-exclusion lock: callers that
// name the same string key run one at a time, and callers that name different
// keys do not wait for one another (ADR-0054).
//
// A Mutex keeps one entry per key that is currently held or waited for, and
// removes the entry when its last holder or waiter releases it, so the set of
// keys a long-lived Mutex has seen does not grow without bound. The lock that
// guards the entry table is never held during a caller's critical section.
//
// Each Mutex is independent: the package has no package-level state, no init,
// no goroutine, no I/O and no logging. The owner of a Mutex decides what a key
// means. Package main has two: the SaaS feed generation store serializes
// in-process writers of one generation id, and the CDR control plane
// serializes renewal, revoke, delete and enroll for one instance name (and
// one "op:"-prefixed operation id).
//
// It is not a reader/writer lock, it is not reentrant (a goroutine that locks
// a key it already holds deadlocks, exactly as with sync.Mutex), and it takes
// no context: acquisition cannot be cancelled.
package keyedmutex
