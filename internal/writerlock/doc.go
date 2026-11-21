// Package writerlock takes the single-writer lock on a persisted-state
// directory (CHAOS-103, ADR-0058): an exclusive, non-blocking advisory lock on
// one well-known file inside the directory, held for as long as the returned
// Lock is open.
//
// The package answers one question, "does a live process already hold this
// directory?", and reports one of three verdicts. Acquired: the caller now
// holds it. Held: a process that is running right now holds it; the kernel
// releases an flock when its owner dies, so there is no stale-lock case.
// Undetermined: the question could not be answered (no directory named, the
// directory or the lock file could not be created, the platform or the
// filesystem has no advisory locking).
//
// What a verdict means is the caller's decision. Package main refuses to boot
// on Held unless the operator set an override, and degrades with a notice on
// Undetermined; none of that is here. The package reads no environment
// variable, logs nothing, starts no goroutine and has no package-level state.
// Each Take is independent, and the lock it returns is released only by
// Close or by the process exiting, so the caller must keep the Lock reachable
// for as long as it means to be the writer.
//
// It is deliberately not built on internal/storeguard, whose locks are
// per-attempt markers armed and released around one store open. This lock has
// the opposite lifetime.
package writerlock
