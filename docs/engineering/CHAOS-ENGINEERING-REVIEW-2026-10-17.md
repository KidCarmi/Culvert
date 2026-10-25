# Chaos Engineering Review — 2026-10-17

## CHAOS-84 — The wall clock steps backwards and four bounds stop expiring

**Scope.** Every interval in the tree that is measured from a stamp held as a
bare `int64` (unix nanos or millis) rather than a `time.Time`: the raw-tunnel
idle reaper (`proxy_tunnel.go`), the parent-proxy circuit breaker
(`internal/upstream/upstream.go`), the Sluice/CDR circuit breaker
(`cdr_breaker.go`), the data-plane readiness grace (`readyz_dp_health.go`), and
the two roster-durability log gates plus the OCSP responder-cap gate
(`roster_persist_durability.go`, `internal/ocsp/ocsp.go`).

> **Reconciled when main was brought in (id and scope).** First written as
> `CHAOS-71`; renumbered in merge order to `CHAOS-84` (register §48), because
> `CHAOS-71` had merged on main as the CP gRPC listener sweep. The shipped scope
> is narrower than the analysis below: the tunnel idle reaper (CK-1), the DP
> readiness grace (CK-4) and the roster log gates (half of CK-5) are fixed by
> the sibling sweep `CHAOS-83` (#1644, monotonic stamps in `monotime.go`), whose
> readiness contract (a future stamp leaves `cp_poll` at `ok`) contradicts the
> "count it as expired" guard this sweep first shipped for CK-4; and the CDR
> breaker (CK-3) was already moved onto a monotonic stamp on main. This change
> therefore ships CK-2, the OCSP half of CK-5 and the five CK-9 gates. The
> analysis of the withdrawn sites is kept because it is still the record of
> the class; the register rows say which change closes each.

**Origin.** Not a register row. A systematic sweep of the SIMULATE list's three
clock faults — *clock skew*, *clock rollback*, *NTP failure* — which no previous
sweep had taken as its subject.

---

## 1. Executive Summary

**Go's monotonic clock protects an interval only while it stays inside a
`time.Time`. This tree has fourteen intervals that leave one, and five of them
were the recovery bound for a degraded state.**

`time.Now()` carries a monotonic reading, and `time.Since(t)` uses it when `t`
has one — which is why most elapsed-time code here is already immune to a clock
step. The immunity ends the moment a stamp is stored as an `int64`:
`time.Unix(0, n)` and `time.UnixMilli(n)` rebuild a `time.Time` with **no**
monotonic reading, so the subtraction falls back to the wall clock.

The tree holds **twenty-two** such interval comparisons. Eight were already
guarded. **Twelve were not**: seven are recovery bounds or the only operator
signal for a degraded state (CK-1…CK-5, below), and five more are evidence and
log gates found only after review rejected this sweep's first inventory (CK-9,
§8c). The remaining two are a fail-closed budget window, recorded under CK-8 and
deliberately not changed here.

> **The first version of this section claimed seventeen and called the inventory
> exhaustive.** Codex rejected that on PR #1650 and named three live
> comparisons with the same defect. It was right, and the cause was the
> *search*, not an oversight about any one site. §8c has the method failure and
> the five sites; the count above is the corrected one.

A backward wall-clock step is ordinary infrastructure, not an exotic fault: an
NTP correction after the RTC came up wrong (routine on appliances and VMs), a
hypervisor resuming a snapshot, a migration to a host with a skewed clock, an
operator fixing the date. The appliance does not log it, does not detect it, and
has no reason to.

**The failure is always the same shape, and it is never an error.** The measured
interval goes negative, every `elapsed >= limit` test is false, and a bound whose
whole job is to END a degraded state never fires again until the wall clock
catches back up. After a step of Δ, that is Δ. Nothing throws, nothing is
counted, nothing is logged. The subsystem simply never recovers.

**Eight comparisons in this tree already guard exactly this** — `internal/scanner`
`budgetRemaining` ("clock stepped backwards — re-arm for a full budget"),
`internal/admission` `engine.go` (`age < 0 || age >= maxAge`),
`internal/mcp/canary` `windowOpenLocked` (`elapsed >= 0 && ...`),
`internal/mcp/rollout` `elapsed` (`d < 0 → 0`), `store.go` `advanceLocked`
(`diff <= 0`), and the `proxy_host_bounds.go` / `request_tracing_bounds.go` log
windows (`d >= 0 &&`), and `internal/mcp/canary` `windowOpenLocked` again for the
activation window. So the rule was already adopted, written down in a comment,
and applied in eight places. The ones below are the ones that were missed, and
they are the ones where the bound is load-bearing.

### The sharpest one: the only limit on a dead tunnel

`idleCopyCounted` is the sole bound on a half-open CONNECT tunnel. It arms a read
deadline every half-window and reaps when the shared activity stamp has been
stale for a full window.

The deadline is **monotonic** — netpoll converts it against `runtimeNano` — so
after a backward step the loop keeps waking exactly on schedule. It is the
*verdict* that is lost, not the wake-up. Every pop re-arms, forever. Per dead
tunnel that pins two goroutines, two FDs, a pooled relay buffer and the
connection-limiter slot, for the whole of Δ. A half-open peer is the normal
outcome of a NAT timeout, a packet-loss blackhole or a hard client reset — the
exact conditions that make a tunnel dead without closing it — so the leak needs
no attacker, only a clock correction while tunnels are open.

### The one with a security outcome: the parent-proxy chain unchains itself

`internal/upstream` `CircuitBreaker.Allow` holds `openedAt` as `UnixMilli`. A
backward step pins every tripped breaker **open**, because open→half-open is the
only route back to service and it is gated on a wall-clock subtraction.

That matters more here than in an ordinary breaker, because `Pool.Next` falls
back to **direct egress** when nothing is eligible — the deliberate PX-2
fail-open posture, counted and alerted since CHAOS-11. So one transient parent
outage (enough to trip the breakers) followed by a clock correction leaves the
appliance egressing **around** the enterprise's parent-proxy chain for the
duration of the step, long after the parents recovered. The alert fires once on
the transition and then tells the truth forever; what never happens is the
recovery it is waiting for.

### The one that keeps a dead node in the load balancer

`readyz_dp_health.go`'s `cp_poll` row fails only once control-plane polling has
been continuously failing for `dpCPPollFailGrace` (5 minutes). The transition
stamp is unix nanos, so after a backward step the grace becomes
**unexpirable**: a data-plane node whose control-plane link is known dead keeps
answering `ok` on `/ready` for the whole of Δ, and a load balancer keeps routing
production traffic to it on indefinitely stale configuration.

### And two that convert a visible degradation into a silent one

The roster-durability gates (CHAOS-70) and the OCSP responder-cap gate are log
rate limiters, and a future stamp reads as *"already logged"*. The roster line is
the **only** notice that an admin credential or roster mutation applied in memory
and did not reach the volume. A clock correction silences it for Δ and
increments a suppression counter nothing pages on — which is precisely the
silent-failure class this review series exists to remove.

---

## 2. Failure Scenarios

Δ = the size of the backward step. Every row is reached with no attacker and no
privilege; the trigger is an ordinary clock correction.

| # | Scenario | Before | After |
|---|---|---|---|
| CK-1a | Half-open CONNECT tunnel open across a backward step | idle reaper **never fires**; 2 goroutines + 2 FDs + relay buffer + connlimit slot pinned for Δ | monotonic basis — a wall step cannot reach the verdict |
| CK-1b | **Quiet-but-alive** tunnel during a FORWARD step | **torn down at the next deadline pop**, after seconds of real idleness: a quiet tunnel moves no bytes, so nothing refreshes its stamp | monotonic basis — same immunity, both directions |
| CK-2a | Parent proxies trip, then the clock steps back | every breaker pinned **open** for Δ → `Pool.Next` returns nil → **direct egress, parent chain bypassed** | one reset timeout from the step, then half-open probes resume |
| CK-2b | Same, diagnostics view | `OpenedAt()` reports a trip instant in the future | re-anchored to the stepped clock; the published instant stays coherent |
| CK-3 | Sluice recovers, but the clock stepped back | CDR breaker pinned **open** for Δ → content disarm unavailable | one `ResetTimeout` from the step, then a probe |
| CK-4 | DP node's CP link dies, then the clock steps back | `/ready` `cp_poll` = **ok** for Δ → LB keeps routing to a node on stale config | `fail` — an unmeasurable grace counts as expired |
| CK-5a | Roster/credential write fails during a step | durability warning **suppressed** for Δ, suppression counter only | emitted; the interval is claimed from the stepped clock |
| CK-5b | OCSP responder output capped during a step | cap notice suppressed for Δ | emitted |

---

## 3. Risk Matrix

| ID | Finding | Likelihood | Impact | Priority |
|---|---|---|---|---|
| CK-1 | Idle-tunnel reaper stops firing → unbounded FD/goroutine/connlimit leak | **Medium** (a clock correction is routine; half-open peers are the normal NAT/blackhole outcome) | **High** (the only bound on a dead tunnel; FD exhaustion is a total data-plane outage on an in-line appliance) | **P1 → CLOSED** |
| CK-2 | Parent-proxy breakers pinned open → sustained **direct-egress bypass** of the parent chain | Medium (needs one parent blip plus a step) | **High** (an egress control the customer bought is off, for Δ, after the cause cleared) | **P1 → CLOSED** |
| CK-4 | DP readiness grace unexpirable → dead node stays in the LB rotation | Medium | High (traffic served on indefinitely stale policy, probe reports healthy) | **P1 → CLOSED** |
| CK-3 | CDR breaker pinned open → content disarm unavailable after the Sluice recovered | Medium | Medium (a scanning control is dark; posture elsewhere already alerts) | **P2 → CLOSED** |
| CK-5 | Durability / responder-cap warnings suppressed → a visible degradation goes silent | Medium | Medium (CHAOS-70's only operator signal) | **P2 → CLOSED** |

---

## 4. Recovery Assessment

**The posture choice is not uniform, and the asymmetry is the finding's
substance.** "An unmeasurable interval must never count as infinite" fixes all
five. What it should count as instead depends on what the bound protects.

- **Monotonic basis** — CK-1. The tunnel stamp was moved off the wall clock
  entirely (`relayEpoch` + `relayMonoNanos`), which is strictly stronger than
  guarding it: a wall-clock step cannot be *represented* in a monotonic stamp, so
  neither direction can reach the verdict and there is no negative case left to
  decide. This was taken after review showed the guard closed only the backward
  half — see the correction note below. It is available here because the stamp is
  process-internal (all five holders pass it straight to `idleCopyCounted`;
  nothing publishes it), which is not true of the breakers below.
- **Re-anchor** — CK-2, CK-3. These bounds govern a **live resource** or a
  **live dependency**. Treating the step as "expired" would reap every quiet
  tunnel on the appliance at the first deadline pop after a routine clock
  correction, and fire every breaker's probe simultaneously at parents that may
  still be down — a mass reset *caused by the mitigation*. Their stamps cannot
  move to a monotonic basis the way CK-1's could, because `OpenedAt()` publishes
  the trip instant on `/api/diagnostics`, so the wall stamp is an observable
  contract. Re-anchoring the stamp
  to the stepped clock grants exactly **one** fresh window measured from the
  step: bounded, deterministic, and it costs a genuinely dead tunnel or a
  recovered parent at most one extra window. Each re-anchor is a
  `CompareAndSwap`, so a concurrent writer's fresher stamp is never overwritten.
- **Treat as expired** — CK-4, CK-5. A readiness probe has no live resource to
  protect, and the failing state is already established independently of the
  clock; leaving the rotation is the safe answer when the node cannot say how
  long it has been degraded. The read path stays side-effect-free — the stamp is
  not rewritten in a probe handler. For a log gate, "expired" simply means the
  operator hears about a real degradation.

**Recovery is automatic in every case and needs no operator action.** Nothing
latches, no state is persisted, and no restart is required. Recovery time is
bounded by one window of the bound in question (one idle window, one reset
timeout, one grace period) measured from the step — not by Δ.

---

## 5. Operational, Security and Data-Integrity Impact

**Operational.** CK-1 and CK-4 were both outage-shaped. CK-1 leaks the resources
an in-line gateway runs out of first (FDs, connlimit slots); CK-4 hides a node
that should have left the rotation. Neither produced a log line, a counter or an
alert, so the operator-visible symptom was "the appliance degrades after a
maintenance window" with nothing connecting it to the clock.

**Security.** CK-2 is the security row: for Δ, traffic egresses direct instead of
through the parent proxy chain, which in the deployments that configure one is
where additional egress policy lives. CK-3 leaves content disarm dark after its
dependency recovered. Neither is a *new* fail-open posture — both are the
existing, deliberate, alerted ones (PX-2 / CHAOS-11, and the CDR pool's) — but
the recovery that is supposed to END them never ran.

**Data integrity.** No state is written on any of these paths and no persisted
format changed. CK-5's impact is to the **evidentiary** record only: the roster
line is the sole notice that a credential mutation did not reach the volume, so
suppressing it loses the operator's chance to act before the restart that
discards the mutation.

**Monitoring visibility.** Unchanged by design — this sweep adds no metric and no
alert. Every one of these faults lands on a series that already exists
(`upstream_pool_down` and the fallback counters for CK-2, the CDR breaker's own
stats for CK-3, `/ready` for CK-4, the roster counters for CK-5). A second name
for one operator action is the thing CHAOS-47's naming note warns against. What
was missing was never a signal; it was the recovery the signal is waiting for.

---

## 6. Suggested Improvements — shipped in this PR

1. `proxy_tunnel.go` — the activity stamp moves to a **monotonic basis**
   (`relayEpoch`, `relayMonoNanos`), and `tunnelIdleFor` replaces the inline
   `time.Since(time.Unix(0, shared.Load()))`. All five holders (three in
   `proxy_tunnel.go`, one in `proxy_tunnel_h2.go`, one in `socks5.go`) seed and
   compare on that basis, so both step directions are closed at once.
2. `internal/upstream/upstream.go` — `Allow` splits the open case: a negative
   `since` re-anchors `openedAt` (CAS) and denies; the timeout comparison is
   otherwise unchanged. `openedAt` stays a wall stamp because `OpenedAt()`
   publishes it on `/api/diagnostics`.
3. `cdr_breaker.go` — the same shape on the injectable clock, preserving the
   `totalTrips` accounting for the denial.
4. `readyz_dp_health.go` — an unmeasurable grace (`d < 0`) now reports `fail`.
5. `roster_persist_durability.go` (both gates) and `internal/ocsp/ocsp.go` — a
   future stamp no longer suppresses; the interval is claimed from the stepped
   clock by the existing CAS.

No new configuration, no new surface, no new metric, no persisted format change,
no posture change in the absence of a clock step.

---

## 7. Residual Risk / deliberately left

- **A forward step still shortens CK-4 and CK-5.** A jump forward expires the
  readiness grace early, and shortens the log intervals by at most one interval
  (the symmetric window below bounds it). Both are the *honest* direction for
  those two — report the degradation, emit the line — so this is left as correct
  behaviour rather than guarded. CK-1 is immune in **both** directions now that
  the basis is monotonic. CK-2/CK-3 lose part of a reset timeout on a forward
  step, which costs one early probe at a dependency: self-correcting, and the
  cheapest outcome of the three.
- **Nothing detects or reports the step itself.** Each bound now recovers
  locally, but no subsystem says "the wall clock moved backwards by an hour",
  which is the single log line that would have made all five of these diagnosable
  at once. A process-wide monotonic-vs-wall drift detector is a reasonable
  follow-up and a better place for it than five call sites; it is larger than
  this fault and would need its own threshold and alert design. Recorded as
  **CK-6**.
- **CK-8 — the MCP canary RATE window is the same class, left in place.**
  `internal/mcp/canary` `budget_enforce.go` rolls its per-minute window on
  `now.UnixNano()-e.rateWindowStart >= budgetRateWindow`, unguarded, in both
  `Reserve` (line 214) and the matching read `reservableLocked` (line 320) —
  while the *activation* window two functions away guards it explicitly. A
  backward step therefore pins the rate window open, `rateCount` never resets,
  and once the per-minute cap is reached every reserve returns
  `BudgetDeniedRate` for the duration of the step. It is left unchanged for two
  reasons: the direction is **fail-closed** (a canary stalls rather than
  over-executing, which is the posture that boundary is built for), and `Reserve`
  is a budget boundary carrying its own reviewed invariants — a monotonic total,
  and an explicit "do NOT mutate here, this is a read" contract on the twin — so
  re-anchoring it is a change to a security budget rather than a chaos
  remediation. Recorded for an owner with the fix shape stated: re-anchor
  `rateWindowStart` without resetting `rateCount`, which keeps the deny for one
  more window and then rolls over normally.
- **The eight already-guarded comparisons were each re-checked at this revision**
  and are the controls for the class; they are enumerated in the gate file's
  header. If a new
  bound is added on an int64 stamp, nothing structural stops it repeating this —
  a lint rule or an AST wall over `time.Unix(`/`time.UnixMilli(` inside a
  comparison would, and is recorded as **CK-7** rather than built here, because
  the honest version needs to tell a recovery bound from a log gate — CK-8 is
  exactly the case where that distinction decides the answer.
- **Clock skew BETWEEN cluster nodes is not this sweep.** `internal/halease`
  delegates expiry to etcd, which decides leases server-side, so the leader lease
  is not exposed to a local step. Cross-node skew in gossiped freshness was
  closed separately (`internal/admission` `engine.go` already guards `age < 0`);
  this sweep deliberately stayed on single-node wall-clock steps.
- **NTP failure as such is not a fault here.** A clock that never corrects is a
  clock that never steps, which is the benign case for every bound above. The
  fault is the correction, not its absence.

---

## 8. Required Tests

**All ten defect gates were verified FAILING against the shape each replaces**,
not written after the fix. The eight below are the original sweep's; the review
round in §8b adds two more (the wall-clock-basis proof and the roster ordering
pair) with their own pre-fix results recorded there:

| Gate | Pre-fix result |
|---|---|
| `TestChaos84_TunnelIdleReaperSurvivesABackwardClockStep` (original form) | FAIL — `idleCopyCounted never reaped a half-open tunnel after a backward clock step` (timed out at 3 s). **Superseded in §8b**: once the stamp moved to a monotonic basis a wall-clock step could no longer be injected into it at all, so this behavioural gate was replaced by `TestChaos84_TunnelActivityStampIsNotOnTheWallClock`, which proves the basis instead (pre-fix: `activity stamp = 1792278133265559320, want < 86400000000000`). |
| `TestChaos84_CDRBreakerRecoversAfterABackwardClockStep` | FAIL — `breaker never left open after a backward clock step plus a full reset timeout` |
| `TestChaos84_DPReadinessFailsWhenTheGraceCannotBeMeasured` | FAIL — `cp_poll status = "ok", want "fail"` |
| `TestChaos84_RosterPersistWarningIsNotSuppressedByABackwardClockStep` | FAIL — `rosterPersistSuppress = 1, want 0` |
| `TestChaos84_RosterNotDurableWarningIsNotSuppressedByABackwardClockStep` | FAIL — `rosterNotDurableSuppress = 1, want 0` |
| `TestChaos84_BreakerHalfOpensAfterABackwardClockStep` (upstream) | FAIL — `breaker never left open after a backward clock step` (2 s budget) |
| `TestChaos84_BreakerRecoveryIsBoundedFromTheStep` (upstream) | FAIL — `breaker never recovered` (5 s budget) |
| `TestChaos84_TruncationLogIsNotSuppressedByABackwardClockStep` (ocsp) | FAIL — `allowTruncationLog suppressed the responder-cap notice after a backward clock step` |

**Fault injection.** A backward step of Δ is observationally identical to a
stamp Δ in the FUTURE, because the stamp is written before the step and read
after it. Every gate injects exactly that, so each is deterministic, needs no
`sleep` for the fault itself, and needs no control of the host clock. The two
breaker gates with an injectable clock (`cdr_breaker`) step a fake clock in both
directions and so also pin the *recovery interval*, not merely that recovery
eventually happens.

**CONTROLS** — a passing gate must not be able to mean the mechanism simply
stopped firing. Seven, one per changed decision:

- `TestChaos84_TunnelIdleReaperReapsAnIdleTunnel` — an ordinary hour-idle tunnel
  is still reaped, i.e. the monotonic switch did not break the CHAOS-03
  guarantee this bound exists for.
- `TestChaos84_TunnelIdleForIgnoresAWallClockEpochStamp` — a stamp on the wrong
  basis can never produce a REAPABLE idleness and tear down a live tunnel.
- `TestChaos84_TunnelIdleReaperDoesNotReapAFreshTunnel` — the guard cannot
  become "always reap"; a current stamp survives a full window. (It also joins
  the relay goroutine before returning, so the package-global timeout is never
  read by a leaked goroutine — caught by `-race`.)
- `TestChaos84_CDRBreakerStillHoldsOpenWithoutAClockStep` — still denies inside
  `ResetTimeout`, still half-opens after it.
- `TestChaos84_BreakerStillHoldsOpenForItsTimeout` (upstream) — still denies
  well inside the timeout, and `OpenedAt()` still publishes a sane trip instant.
- `TestChaos84_BreakerRecoveryIsBoundedFromTheStep` (upstream) — doubles as the
  control that the re-anchor is not an instant half-open: recovery must take at
  least a full timeout measured from the step, so the fix cannot degrade into a
  probe flood.
- `TestChaos84_DPReadinessStillHonoursTheGraceWindow` — a just-happened
  transition is still inside the grace and still reports `ok`.
- `TestChaos84_RosterRateGatesStillSuppressWithinTheInterval` — both gates still
  rate-limit to one line per interval.

**Counts.** 15 defect gates + 15 controls = **30 new gates**, in
`chaos84_clock_rollback_test.go` (root, 19 as first shipped; 6 after the reconciliation above), `internal/upstream/clock_rollback_test.go` (3),
`internal/ocsp/clock_rollback_test.go` (2), `internal/secscan/clock_rollback_test.go` (3)
and `internal/yara/clock_rollback_test.go` (3) — including the four added by the
review round in §8b and the twelve added by §8c.

**Verification run.** `go build ./...` clean; `go vet ./...` clean;
`gofmt` clean. The 15 gates pass, and pass under `-race` together with the
pre-existing `TestTunnelIdle_*` / CHAOS-03 reaper suite.
`go test -race ./internal/upstream/ ./internal/ocsp/` green. The full root
package suite reports **nine pre-existing failures**, all in the IdP
registry/API tests (`TestIdPRegistry_*`, `TestAPIIdP*`), which fail identically
on the unmodified merge base with `idp oidc issuer: URL must be https:// and
must not point to a private address` — a sandbox DNS/SSRF-guard artifact, not a
regression, and untouched by this change. `golangci-lint` could not run in this
environment (the installed binary is built with Go 1.25 and panics on a Go 1.26
module); the hosted Fast PR Gate runs the pinned version.

---

## 8b. Review round — the guard closed one half of CK-1, and the other guard had an ordering bug

Two findings from CodeRabbit on `4535833`, both labelled Minor, both correct on
the substance and both traced to a real path before being acted on.

### CK-1b was documented as immune, and was not

The table above originally read *"CK-1b … unaffected — an active direction
re-stamps before the check."* That is true only of a tunnel **actively moving
bytes**. A tunnel that is **quiet but alive** — an idle SSH session, a long-poll
waiting on an event — moves no bytes, so `n > 0` is never true and nothing
refreshes its stamp. After a forward step the apparent idleness jumps by the
step, and the tunnel is torn down at the next deadline pop having been idle for
seconds in real time.

The behaviour was not a regression — the pre-fix code measured the forward
direction identically — but **the claim of immunity was wrong**, and the fault
matters more than the write-up implied. The forward step is arguably the *more
common* direction on an appliance: a dead or wrong RTC boots the clock at a
default, NTP then corrects it forward, possibly by years, and every quiet tunnel
on the box is reset at the next pop.

The response was not to add a second guard but to remove the need for one: the
stamp moved to a **monotonic basis**, which closes CK-1a and CK-1b together
because a wall-clock step cannot be represented in it at all. That is a smaller
conceptual surface than the guard it replaces — the negative branch is gone —
and it is available precisely here because the stamp is process-internal. The
permanent proof is `TestChaos84_TunnelActivityStampIsNotOnTheWallClock`, which
asserts the **basis** rather than a behaviour: a behavioural gate cannot step the
host clock, so only the basis is checkable, and if anyone restores a wall stamp
it fails immediately with the reason.

### The CK-5 guard mistook its own staleness for a rollback

Sharper, because this one *was* introduced by this sweep. The roster gates claim
their rate-limit interval with a CAS loop, and the guard read a negative interval
as "the clock stepped back, emit". But negative does not mean stepped: a caller
that **loses the CAS** re-reads a stamp the winner just stored from a later
sample, so the difference is negative for an **ordering** reason. The loser then
emitted a duplicate line and moved the stamp backwards — reintroducing exactly
the log amplification a previous sweep's Codex review added the CAS to prevent,
arriving when the volume is already failing.

CodeRabbit's proposed fix — re-sample the clock after each `Load` — was
**insufficient**, and measuring it showed why: the winner's sample may still be
later than ours, so the window narrows but does not close. The gate was failing
on the wrong question.

**Magnitude is the discriminator, not sign.** A lost CAS puts the stamp
microseconds ahead; a rollback worth reacting to puts it the whole step ahead. So
both roster gates and the OCSP gate now suppress while the stamp is within one
interval of now in **either** direction, and emit once it is further ahead than
the interval. A rollback therefore costs at most **one** suppressed line — which
the rate limit already permits — instead of silencing the warning for the whole
step, and an ordering artifact can never be read as a clock step. The clock is
also now sampled after each `Load`, which is simply the correct ordering even
though the symmetric window is what closes the hole.

**The OCSP half of that finding was not a live defect.** `allowTruncationLog` has
no CAS *loop*: it loads once, and a lost CAS returns false, which suppresses. So
the interleaving could not produce a duplicate there. The symmetric rule was
applied anyway, for one rule with one reason across the three gates rather than
two rules and a subtle argument about why one of them is safe — and its `now`
stays an injected parameter, so the deterministic-clock contract its tests rely
on is untouched.

### What the round changes about the sweep's own claims

- CK-1's posture is **monotonic basis**, not re-anchor. CK-2 and CK-3 still
  re-anchor, and now state why they cannot do the same: `OpenedAt()` publishes
  their stamp, so the wall basis is an observable contract.
- CK-1 is immune in **both** step directions, not just backward.
- CK-5's bound is "silenced for at most one interval", not "emits on any
  backward step".

Four gates were added (`TunnelActivityStampIsNotOnTheWallClock`,
`TunnelIdleForIgnoresAWallClockEpochStamp`,
`RosterGateDoesNotMistakeItsOwnStalenessForARollback`,
`RosterGateNeverMovesItsStampBackwards`). Three of the four were verified failing
against the shape each replaces; the fourth passes in both trees and is labelled
a control for that reason. The roster pair was additionally re-run against the
sign-based guard to confirm it discriminates, and the second of them caught the
stamp provably moving backwards (`1792278293183292997 < 1792278293183342788`).

### The lesson in it

**A guard on the sign of an interval is a guard on the wrong thing.** Both
findings are the same mistake in different places: the sweep reasoned that a
negative interval means the clock moved, when a negative interval only means the
two readings are out of order — and concurrency produces that without any clock
involvement. Where the quantity being measured has a natural scale (one rate-limit
interval, one idle window), compare against that scale. Where it can be taken off
the wall clock entirely, do that instead and there is no sign to test.

---

## 8c. Second review round — the inventory was not exhaustive, and the search was why

Codex (P2) rejected §1's claim of an exhaustive inventory and named three live
comparisons carrying the same defect: `crashguard.go:167`,
`internal/secscan/secscan.go:828` and `internal/yara/yara.go:643`. It was right
on all three.

**The cause was the search, not an oversight about any one site.** The original
sweep grepped for the subtraction sitting syntactically beside the time call —
`UnixNano() -`, `.Unix() -`, `time.Since(time.Unix(` — which cannot match the
far more common two-step form:

```go
now := time.Now().UnixNano()
...
if prev != 0 && now-prev < int64(degradedLogInterval) {
```

Re-running the sweep on the generalised shape found Codex's three **and two more
it had not named**:

| Site | Gate | Found by |
|---|---|---|
| `crashguard.go` | crash-evidence throttle | Codex |
| `internal/secscan/secscan.go` | scanner degraded log | Codex |
| `internal/yara/yara.go` | YARA degraded log | Codex |
| `cdr_proxy.go` | Sluice call-error log | re-sweeping the generalised shape |
| `policy.go` | file-profile unresolved-block warning | walking every file that seeds an int64 from a time call |

`policy.go` is the instructive one: it compares against a **bare literal**
(`now-last >= 300`, in Unix *seconds*), so even the generalised
`int64(<duration>)` search missed it. Finding it required enumerating every file
that assigns a `time.Now().Unix*()` into a variable and reading each
subtraction. Three different searches, three different yields — which is the
point.

### The sharpest of the five: crash evidence

`crashThrottleAllow` gates `recordCrash`. After one crash of a component and a
backward step, the negative difference reads as inside the one-second window, so
`recordCrash` returns **before** updating `lastCrash` and before emitting the
stack-bearing log and the audit entry — for every subsequent same-component
crash until the clock catches up. Crash evidence is the one record an operator
cannot reconstruct after the fact, which makes this a worse instance of the CK-5
shape than CK-5 itself. The other four are degradation and error notices:
scanner saturation/abandonment, YARA saturation, Sluice call errors, and the
fail-closed file-profile block.

All five take the same symmetric-window rule §8b arrived at — compare the
**absolute** interval, so a step costs at most one suppressed line and a
concurrent claimant's marginally-future stamp is never read as a clock step.
Four are nanos and use `time.Duration(d).Abs()`; `policy.go` is in seconds and
negates explicitly.

### The lesson

**An inventory is only as exhaustive as the shapes its search can express.**
The first write-up said "seventeen comparisons" as though it had counted a
closed set, when it had counted *the matches of three regexes*. The honest claim
would have named the shape searched for and admitted what it could not reach —
at which point the two-step form is obvious, because it is the form most of this
tree actually uses.

This is also the strongest argument for **CK-7**, the structural wall recorded
as a follow-up: a convention applied by hand across twenty-two sites in one
repository was wrong at five of them, and the review that caught it was a
different reader, not a check. Until that wall exists, the next bound added on an
int64 stamp is one more hand-application of a rule nothing enforces.

---

## 8d. The CI red was mine: a gate stricter than the mechanism it measured

`Gate · go test -race (sharded) / Race · non-root packages` went red on the first
head, and two aggregate checks (`Race · verdict + coverage evidence`,
`✅ Fast PR Gate — APPROVED`) failed behind it. The job logs available through
the API carried only post-job cleanup, so the first read of the situation was
"red on a superseded head" — which was not good enough, and was wrong.

Running the same shard locally (`go test -race ./internal/...`) reproduced it:

```
--- FAIL: TestChaos84_BreakerRecoveryIsBoundedFromTheStep (0.30s)
```

**The defect was in the gate, not the fix.** `CircuitBreaker.openedAt` is a
`UnixMilli` stamp, so `time.UnixMilli` truncates the re-anchor instant DOWN by up
to one millisecond, and recovery can legitimately land that much before the
nominal timeout. The gate asserted `elapsed >= timeout` — stricter than the
resolution of the thing it was measuring. Measured over 40 `-race` runs, the
worst case was **−791µs**: under 1ms, exactly as truncation predicts.

The tolerance now written into the gate is the stamp resolution, not slack. The
property under test is that the re-anchor serves a FULL reset timeout instead of
half-opening instantly — 0ms versus ~300ms — which one millisecond cannot mask.
Re-stressed at `-count=15` under `-race`, plus the whole `./internal/...` shard.

Two things worth keeping from it:

- **A timing gate must be no stricter than the resolution of the clock it
  reads.** This one asserted against a nominal duration while measuring a
  millisecond-truncated stamp, so it was guaranteed to fail some fraction of
  runs. It passed locally the first time and twice more before CI caught it,
  which is the signature of this bug class rather than evidence against it.
- **"Red on a superseded head" is not a diagnosis.** The check had run against
  code that is still in the PR, so the only honest way to dismiss it was to
  reproduce it — and reproducing it showed it was ours. Where the log API gives
  nothing, the local shard is the authority, not the head SHA.

---

## 9. The process lesson

**A rule that lives in a comment is not a rule the tree follows.**

Six call sites here already guarded the backward step, one of them with the
explanation written out in full — *"clock stepped backwards — re-arm for a full
budget"*. The guard had been derived, argued and shipped. What never happened was
anyone asking **where else the same subtraction appears**, and the answer was:
in the four places where the interval was not a log window or a scan budget but
the recovery bound for a degraded state.

The second half is about which faults get swept. Forty sections of this review
have gone domain by domain — storage, identity, scanning, cluster, listeners.
A wall-clock step is not a domain; it is a property of a *representation* that
cuts across all of them, and it produced one P1 in the data plane, one in the
upstream plane and one in the readiness plane, in code three different sweeps had
already visited for other reasons. Sweeping by domain will not find that class.
The question that finds it is "what does this measurement actually depend on,
and what happens when that dependency moves?" — asked of the whole tree at once.

> **The rule this sweep produces:** an interval measured from a stamp that has
> left a `time.Time` is a WALL-CLOCK interval, and a wall-clock interval can go
> negative. An unmeasurable interval must never count as INFINITE. Where the
> bound protects a live resource, re-anchor and serve one fresh window; where it
> only reports, count it as expired.
