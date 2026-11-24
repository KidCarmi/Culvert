// Package listenretry holds the two retry-sleep rules a listener supervisor
// applies between bind attempts (ADR-0064): the doubling ladder and the clamp
// that keeps one sleep from straddling the unavailability threshold. Both are
// arithmetic over time.Duration values. The package holds no state, reads no
// clock, sleeps nowhere, performs no I/O and does no logging.
//
// Ownership: package main owns each listener's supervisor, its constants (the
// first rung, the ceiling, the threshold, the floor), the jitter, the timer,
// the health record and the alert. A supervisor states its constants in a
// Ladder or a Clamp value at the call and owns everything that follows. This
// package owns only what the next rung is and how a sleep is shortened.
//
// # Why the clamp is a correctness rule
//
// A listener's "unavailable" alert is raised by a bind ATTEMPT: the failure
// recorder holds the fire-once latch and nothing else wakes the supervisor.
// A sleep that begins before the threshold and ends after it therefore delays
// the page by the part of the sleep that lies past the threshold. At a 30 s
// ceiling with +20% jitter, a failure at 29 s would not attempt again for up
// to 36 s. Clamp.Sleep shortens that one sleep to end at the threshold. Once
// the threshold is passed it returns every sleep unchanged, so the ceiling
// still bounds a long outage's cadence.
//
// # What the rules do at the edges
//
// The rules are the bodies the supervisors carried, unchanged, including at
// inputs no supervisor produces. Ladder.Next answers Initial for any rung at
// or below zero. It doubles with ordinary int64 arithmetic, so a rung above
// half the int64 range wraps negative and is returned as is; no supervisor
// reaches it, because every rung it hands back is at most Ceiling. Clamp.Sleep
// subtracts with the same arithmetic. Neither validates its configuration: a
// Ladder whose Ceiling is below its Initial answers Initial first and Ceiling
// afterwards, and the zero Clamp returns a sleep unchanged for every failingFor
// that is not negative.
package listenretry
