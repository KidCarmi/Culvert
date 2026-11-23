# ADR-0064: The listener retry-sleep rules are owned by internal/listenretry

- Status: Proposed for review with the implementation PR (IM-027, 2026-11-23).
- Numbering: ADR-0061 is the highest merged. ADR-0062 is reserved by open
  PR #2017 (IM-029), ADR-0063 by open PR #2060 and ADR-0040 by open PR #1526.
  No other open PR adds a numbered file under `docs/adr/` (checked against
  every open PR head on 2026-11-23).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-027.
  Related: ADR-0002, ADR-0058 (`internal/listenfault`, which named these two
  rules as the ones it left repeated).

## Context

Each listener supervisor in package main sleeps between bind attempts by two
rules, and each carried its own copy of them:

1. **The ladder.** The first failure waits the listener's initial backoff;
   each further failure doubles it; it never exceeds the listener's ceiling.
2. **The clamp.** The "unavailable" alert is raised by an attempt, so a sleep
   that begins before the unavailability threshold and ends after it delays
   the page. The sleep is shortened to end at the threshold, but not below a
   floor.

On main `46b4ffa6e` the copies were:

| Rule | Function | File | Open PR editing the file |
|---|---|---|---|
| ladder | `nextCPGRPCBindBackoff` | `cp_grpc_bind.go` | none |
| ladder | `nextScanSvcBindBackoff` | `scan_svc_listener.go` | none |
| ladder | `nextSOCKS5BindBackoff` | `socks5_bind.go` | #2034, #1549, #1548, #1536 |
| clamp | `clampCPGRPCBindSleep` | `cp_grpc_health.go` | none |
| clamp | `clampSOCKS5BindSleep` | `socks5_health.go` | none |

The three ladders are the same five statements over two constants. The two
clamps are the same six statements over two constants. None reads a root name
other than its own listener's constants, and none reads a clock.

The files they sit in are listener supervisors and health records, which
ADR-0002 keeps in main. That is unchanged: no supervisor, record, alert or
constant moves. No decision is superseded.

## Decision

Move rules 1 and 2 to a new package, `internal/listenretry`, as two value
types with one method each:

```go
type Ladder struct{ Initial, Ceiling time.Duration }
func (l Ladder) Next(cur time.Duration) time.Duration

type Clamp struct{ Threshold, Floor time.Duration }
func (c Clamp) Sleep(wait, failingFor time.Duration) time.Duration
```

Two exported names. The bodies are the statements main carried, unchanged.

The four root functions in files no open PR edits keep their names and
signatures and become bindings that state their own listener's constants:

```go
func nextCPGRPCBindBackoff(cur time.Duration) time.Duration {
	return listenretry.Ladder{Initial: cpGRPCBindBackoffInitial, Ceiling: cpGRPCBindBackoffMax}.Next(cur)
}
```

No call site and no existing test is edited.

**Why value types and not two functions of three and four durations.** A
function `ClampSleep(wait, failingFor, threshold, floor)` takes four values of
one type, and a call with two of them exchanged compiles. The fields are named
at every call instead. The mutation checks exchange them in each binding and
each exchange fails a test.

**Why not `internal/listenfault`.** That package maps an error to a reason
class, and its boundary test refuses a `time` import so that it cannot acquire
a clock. These rules are arithmetic on `time.Duration`. Admitting `time` there
would weaken a rule that package has for a reason; a sibling keeps both
boundaries exact. `listenretry`'s own boundary test admits `time` and refuses
every name from it except `Duration`.

**Not moved.**

- `nextSOCKS5BindBackoff`: `socks5_bind.go` is edited by four open PRs. It
  binds to `listenretry.Ladder` in one line once they are disposed of.
- `nextSOCKS5AcceptBackoff` (`socks5.go`): a different rule. It tests
  `cur == 0`, so a negative rung is doubled, where the bind ladders answer the
  initial value. `socks5.go` is also edited by eight open PRs.
- The admin UI's ladder, written inline in `ui.go`'s supervisor loop
  (`if backoff *= 2; backoff > adminUIListenBackoffMax`). It is not a
  function, so there is no pre-move verdict to capture and no binding that
  leaves the loop unedited. No open PR edits `ui.go`; it is a follow-up.
- The two jitter functions (`jitterDuration`, `jitterScanSvcBackoff`). They
  differ (a caller-chosen fraction either side against a fixed 0.75 to 1.25
  range), draw from `math/rand`, and the first belongs to HA lease recovery.
- Every constant. A listener's ceiling and threshold are its contract with its
  runbook and stay beside its health record.

Lifecycle, in one sentence: there is none; a supervisor calls a pure method
once per failed attempt and owns the timer, the cancellation and everything
that follows.

Unchanged: every value the four functions return, for every input, including
inputs where the int64 arithmetic wraps.

## Tests

No existing test is moved or edited. `TestChaos71_DefectSleepIsClampedToTheThreshold`,
`TestChaos66_BindSleepNeverStraddlesTheThreshold`,
`TestChaos113_BackoffLadderIsBoundedAndResets` and the scan-sidecar flap tests
call the root functions and stay where they are.

New in root (`listen_retry_wiring_test.go`, 3 tests):

- Two verdict tables. Each ladder is walked over 219 durations and each clamp
  over 219 × 219 = 47,961 pairs: every boundary of the constants, both signs,
  the int64 limits and 180 generated values. The SHA-256 digests were captured
  by running the same test against main `46b4ffa6e` before the bind, where it
  passed.
- A test that each binding reads its own listener's constants. The digests
  alone cannot show this, because today all listeners use the same four
  values.

New in the package (13 tests, 2 fuzz targets):

- Schedule, edge and zero-value tables for both rules, including the wrap
  cases and the case where the floor lengthens a short wait.
- The property the clamp exists for: a sleep that starts before the threshold
  ends no later than the threshold plus the floor, and is never zero.
- Differential tests against frozen copies of the pre-move bodies over 60,000
  generated inputs each, and `FuzzLadderNext` / `FuzzClampSleep` against the
  same copies.
- A concurrent-call test under `-race`.
- A boundary test: no import except `time`; no name from `time` except
  `Duration`; no renamed or dot import; no package variable; no `init`; no
  pointer receiver; no function-typed field, parameter or result; no goroutine
  or channel; exported-surface cap of 8. Twenty-two negative controls.

Mutation checks: 29 mutations, 26 fail a test. The three that survive return
the same value as the original at the one input where they differ (`>` against
`>=` at the ceiling, `<=` against `<` when the wait equals the remaining time,
`<` against `<=` when the remaining time equals the floor).

## Found, not changed

1. **Two supervisors raise the alert from an attempt and do not clamp.** The
   scan sidecar (`scanSvcWaitBackoff`, alert in `maybeAlertScanSvcDown`) and
   the admin UI (`ui.go` supervisor, alert in `noteAdminUIListenFailure`) both
   fire "unavailable" only when a failed attempt finds the episode 30 s old,
   and both sleep the jittered rung unclamped. With the ladder 1, 2, 4, 8, 16 s
   the sixth attempt lands near 31 s; when jitter puts it just under 30 s, the
   next sleep is a full 30 s rung (up to 36 s for the admin UI, 37.5 s for the
   sidecar), and the page documented for 30 s arrives at up to about 66 s. This
   is the delay the clamp removed from the Control Plane and SOCKS5 listeners
   (CHAOS-55's rule). Applying `listenretry.Clamp` in each is one line and one
   floor constant, and it changes when an alert fires, so it is the owner's to
   ask for.
2. **The floor is not compared with the wait.** A straddling wait shorter
   than the floor is returned as the floor, which is longer. No supervisor
   reaches it: the shortest wait is a jittered 1 s rung. Pinned by a test.

## Consequences

The doubling rule and the clamp are each written once, with the property the
clamp exists for tested without a listener. A listener that needs the clamp
states two constants. The SOCKS5 ladder is the remaining copy and is recorded
under IM-027 as a one-line follow-up.

`fuzz-nightly.yml` is a hand-maintained matrix; adding the two targets is a
workflow edit left to the owner, as for IM-001, IM-023 and IM-028.
