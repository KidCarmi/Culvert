# Chaos Engineering Review — 2026-08-24

**Sweep:** CHAOS-55 — the HA fencing lease's recovery paths
**Domain:** Control Plane / Cluster / HA (ADR-0005)
**Register rows:** HA-7 (closed), HA-16, HA-17 (new), HA-18 (new, recorded)
**Summary section:** `roadmap/CHAOS-ENGINEERING-REVIEW.md` §23

---

## 1. Executive summary

ADR-0005 built the fencing lease to answer one question — *may this node
write?* — and it answers it correctly and safely in every direction. What it
never built was the way **back**.

The lease has three exits from write authority: denied on promotion, denied on
resume, and self-fenced by the keepalive. It shipped a return path for exactly
one of them (a demoted leader with a recorded ex-standby re-enters standby,
where the standby loop can eventually re-promote). The other two dead-ended,
and the dead end was silent: a node in that state reported `culvert_ha_role 1`
— byte-identical, on the only surface a Prometheus rule can read, to a
completely healthy leader.

Two defects, one mechanism, and the mechanism is the same sentence twice:

> **An unknown was treated as a decision.**

`ha_lease.go`'s own header states the rule for the other direction —
*"leadership cannot be taken while the fence's state is unknown"* — and the
promotion path obeys it exactly. The resume path breaks it in reverse: it
**gave leadership up** on an unknown, and then stopped asking.

- **HA-7 (registered, P1, open since the first sweep).** `acquireLeaseForResume`
  carries a 45-second budget (`haResumeGhostWait`) and spent it exclusively on
  waiting out its **own** previous process's ghost lease — the one denial shape
  that is not a fault. A transport error returned `false` on the **first**
  attempt, with zero retries. `ResumeAsLeader` then asserted `role="leader"`
  with `leaseEpoch=0`, and `startLeaseKeepalive` no-ops on a zero epoch, so
  **nothing left in the process ever called `Acquire` again**. The node served
  reads forever and could not issue a certificate, accept a revocation, or
  publish a config snapshot. `PromoteManually` refuses a node whose role is
  already `leader`, so the *only* recovery was a process restart by a human.

  The trigger is not exotic. It is **boot ordering**: on a host reboot the
  container runtime starts culvert and etcd concurrently, and a few seconds of
  `connection refused` was enough.

- **HA-16 (new, and the more serious of the two).** When the ex-standby's
  address *was* recorded, `ResumeAsLeader` demoted to standby on **any** failed
  resume — including an unreachable backend. In a two-node cluster restarting
  together that is symmetric: the ex-leader stands by against the ex-standby
  while the ex-standby stands by against it. Neither can sync, because a
  lease-configured puller rejects a bundle carrying no live holder
  (`verifyBundleEpoch`, `ha_fencing.go`). `lastSyncOK` therefore stays zero,
  and `leaseAutoPromote`'s freshness gate refuses every promotion, forever.
  **A whole-site power restore could leave the cluster permanently leaderless**
  — no split brain, no data loss, no alert that says so, and no automatic way
  out.

Both are fixed. The unifying rule is stated in the code:

> **The only thing that may conclude "another node is the leader" is an
> affirmative read showing a live foreign holder.** Failing to reach the fence
> is not that read.

---

## 2. HA-7 — the budget spent on the wrong fault

### 2.1 The code

```go
deadline := time.Now().Add(haResumeGhostWait)   // 45s
for {
    if h.acquireLeaseForLeadership("leader resume") { return true }
    st, err := p.Read(ctx)
    if err != nil || st.Holder != id {
        return false        // ← "real denial (other holder) or unknown backend state"
    }
    ...wait out our own ghost, retry...
}
```

The comment names the conflation precisely and then acts on both halves the
same way. A foreign holder is a **decision** — retrying it means waiting for a
live leader to die. An unreachable backend is an **absence of one**.

Worse, the fail-closed choice made here is discarded three lines later.
Refusing leadership on an unknown fence is correct; the caller then takes the
leader role *anyway*, without write authority, and with nothing that will ever
ask again. The safety decision bought nothing and the availability cost was
permanent.

### 2.2 What the operator saw

| surface | unfenced leader | healthy leader |
|---|---|---|
| `culvert_ha_role` | `1` | `1` |
| `culvert_ha_failovers_total` | unchanged | unchanged |
| any other `/metrics` series | *(none existed)* | — |
| `/healthz` `lease_valid` | `false` | `true` |
| `ha_resume_unfenced` alert | fired **once**, at boot | — |

The one Prometheus-visible signal did not exist. `lease_valid` lived only on
JSON that a human has to look at, and the alert fired once — if the webhook was
down during the restart that caused the problem, which is a correlated failure,
the state was completely invisible thereafter.

### 2.3 The fix

Two changes, deliberately split:

1. **`acquireLeaseForResume` now retries transport errors** instead of
   returning on the first one. `resumeAcquireRound` classifies each round into
   `granted / foreign / ownGhost / unknown / raceRetryable`. No new state, and
   it alone covers the common case — etcd seconds behind us at boot.

   The retry gets its **own** budget, `haResumeUnreachableWait` (5 s), not the
   ghost path's 45 s, and that split is deliberate. `ResumeAsLeader` runs inside
   `initCluster`, which `main.go` orders ahead of the root CA, the policy
   engine, the proxy listener and the admin UI — so every second blocked here is
   a second the **secure web gateway data plane is not serving**. Reusing 45 s
   would have closed a control-plane write outage by opening a data-plane
   availability one, and the fence governs control-plane writes and nothing on
   the data path. The resume absorbs the short race it exists for; anything
   longer is the background loop's job and costs the boot nothing. The ghost
   budget stays 45 s — a condition with a known, self-clearing expiry, and
   pre-existing behaviour.

   Worth recording as an observation rather than a change: the **ghost** wait
   can still block the boot for up to 45 s. In practice the ghost clears in one
   lease TTL (≥3 s, typically 10 s), so the ceiling is rarely approached.

2. **A bounded background recovery loop** (`ha_lease_recovery.go`) for when the
   budget is exhausted. The node still takes the read-only leader role, but now
   keeps trying.

Recovery is bounded in **rate**, never in **attempts** — 1 s doubling to a 30 s
ceiling with ±20 % jitter. Giving up would reinstate the exact dead end the
file exists to remove. This does not violate the register's "avoid infinite
retries" rule for the same reason CHAOS-54's accept loop does not: **the retry
is never silent.** First failure logged immediately, then at most one line per
60 s, then a recovery line naming what was suppressed; magnitude in
`culvert_ha_lease_reacquire_attempts_total`.

The jitter is not decoration. Every CP in a fleet restarts together after a
site-wide power event, so a fixed cadence has them all hit the recovering etcd
on the same tick — the WK-13 thundering-herd shape, aimed at the component
whose recovery everything else is waiting on.

---

## 3. HA-16 — giving leadership up on an unknown

### 3.1 The deadlock

`ResumeAsLeader`, pre-fix:

```go
leaseGranted := h.acquireLeaseForResume()
if !leaseGranted && h.leaseConfigured() {
    if h.enterStandbyResync("unfenced leader resume") { return }
}
```

`enterStandbyResync` is right when the peer promoted while we were down. It is
a guess when we simply could not see the fence — and in a two-node cluster both
nodes make the mirror-image guess at the same time:

| | node A (persisted leader) | node B (persisted standby) |
|---|---|---|
| resume | acquire fails: etcd not up yet | — |
| role | **standby**, syncing from B | **standby**, syncing from A |
| sync | rejected — `verifyBundleEpoch` sees no live holder | rejected, same |
| `lastSyncOK` | stays zero | stays zero |
| `leaseAutoPromote` | refused: *"no successful state sync yet"* | refused, same |

Steady state: two healthy processes, an etcd that has been up for hours, and no
leader. Nothing is red. `culvert_ha_role 2` on both nodes is the honest report
of a cluster with no leader, but no alert says so, and there is no path out
except an operator running a manual promote.

### 3.2 The fix

`acquireLeaseForResume` now returns `(granted, sawForeignHolder)`, and the
demotion is gated on the second value. An unknown fence keeps the read-only
leader role and hands the decision to the recovery loop, which reads the
backend **before** it acquires and demotes only on an affirmative foreign
holder.

One atomic `Acquire` is what makes the loop safe. It cannot succeed while
anyone else holds the lease, so a grant *is* proof the fence was free; and when
it denies, the transaction reports the holder that made it so. Quietly retrying
until a live peer *dies* and then taking over would make a node with state of
unknown age authoritative — precisely the judgement `haPromoteFreshnessWindow`
was built to make — so recovery routes to it rather than around it: an observed
foreign holder is **latched**, the loop exits, and the node never acquires again
in that process.

The first draft of this reached for the holder with a separate `Read` before the
`Acquire`, because the bool wrapper around `acquireLeaseForLeadership` discarded
the Status the transaction had already computed. Codex review of the PR showed
that was both redundant and racy: a foreign holder whose lease expired between
the read and the acquire read back as free, downgrading a definite denial into a
retry and erasing the one observation that says this node must not lead.
`acquireLeaseAttempt` now surfaces the transaction's own answer, which removes
the window and one round trip. See §7.1 for the bound that has to sit alongside
it.

The latched disposition mirrors the shipped ADR-0005 S4/S2 decision rather than
inventing a third stance — resync from the recorded ex-standby when the
material exists, otherwise keep the read-only leader role with a CRITICAL
alert.

---

## 4. HA-17 — an unfenced leader was invisible to Prometheus

Six series, emitted **only when a fencing backend is armed**:

| series | meaning |
|---|---|
| `culvert_ha_write_authority` | 1 = confirmed lease write authority |
| `culvert_ha_lease_epoch` | current fencing epoch (0 = not held) |
| `culvert_ha_unfenced` | **the paging condition**: leader role, no write authority |
| `culvert_ha_lease_recovering` | 1 = the re-acquire loop is armed |
| `culvert_ha_lease_reacquire_attempts_total` | failed recovery rounds |
| `culvert_ha_lease_reacquired_total` | completed recoveries, no operator |

Two rules, both load-bearing and both borrowed from earlier sweeps:

- **Absent, not zero, on a node without the feature** (CHAOS-54). The
  documented paging rule is `culvert_ha_unfenced == 1` / `write_authority == 0`,
  and a `0` on a node that never had a lease is indistinguishable from a
  fenced-out one.
- **`culvert_ha_unfenced` is not `!WriteAllowed()`.** A standby has no write
  authority either, and that is its healthy steady state. The gauge fires only
  for a node that believes it is the leader and cannot write.

`culvert_ha_lease_recovering` carries the distinction an operator actually
needs at 3 a.m.: **read-only and working on it** versus **read-only and
stuck**. `unfenced=1 AND recovering=0` is the second state, and it is the one
that needs a human. It is also on `/healthz` and `/api/cluster/ha` as
`lease_recovering`.

---

## 5. HA-18 — recorded, not fixed

**A self-fenced ex-leader with no recorded ex-standby is a passive standby
forever.** `selfFence` demotes, calls `enterStandbyResync`, and when there is
no `standbyAddr` (a lease-armed CP that has never had a standby connect) the
node has no sync loop, no keepalive, and no recovery loop. If the self-fence
was caused by a transient etcd outage, nobody else could have acquired either,
so when etcd returns the lease is free and no node in the cluster is asking for
it.

The recovery loop deliberately does **not** cover this: re-acquiring from
`role=standby` is a *promotion*, and promotions are gated on freshness
(`lastSyncOK`) and hysteresis. Those gates are structurally wrong for an
ex-leader — a leader does not sync, so `lastSyncOK` is zero or ancient, and the
freshness gate would refuse the one node whose state is by definition the
freshest in the cluster.

**Owner question:** should an ex-leader's own last-write timestamp substitute
for `lastSyncOK` in the freshness gate? That changes what freshness *means* on
the promotion path and has split-brain implications well beyond a chaos fix, so
it is recorded rather than settled here. Sibling of WK-2b and CA-3b.

---

## 6. Two smaller notes

**`WriteAllowed()` is silently false whenever `leaseValidFor ≤
haLeaseWriteMargin`** (1 s). The startup path already floors the configured TTL
at `haLeaseMinTTLSec` (3 s) and makes a shorter one fatal, so the config
surface is covered. But the value `WriteAllowed` trusts comes from the
**backend** (`st.ValidFor` / the keepalive's `validFor`), not from config, so a
backend reporting a shorter validity than configured would reproduce the state:
a leader that acquires, renews successfully forever, logs nothing but success,
and can never write. Surfaced by `culvert_ha_write_authority 0` +
`culvert_ha_lease_epoch != 0` — a combination that is otherwise impossible and
worth an operator rule. Not otherwise changed.

**`Fake` and `Etcd` disagree about `Read` on a free lease.** `Fake` returns
`Status{Epoch: watermark}`; `Etcd` returns a zero `Status{}` — etcd deletes the
key on expiry, so there is no watermark to report. Nothing depends on it today
(`verifyBundleEpoch` keys on `Holder == ""`, and the recovery loop likewise),
but the conformance suite claims the two agree, and a future caller reading
`Epoch` from a free-lease `Read` would behave differently against the two
backends. Recorded.

---

## 6.1 HA-19 — a free lease is not proof that the fence never moved

Also from Codex review, and the deeper of the two. A free lease proves nobody
holds it *now*. It does not prove nobody held it since we last looked. A peer
can acquire, take configuration writes, crash, and have its lease expire; if
that entire tenure fits between two of our observations, we see only "free" and
re-acquire as a stale leader, reverting the peer's writes.

The mechanical half is closed. etcd keeps a holder's key until its lease
expires, i.e. for **at least one full TTL** after the holder stops renewing — so
a peer's key is visible for ≥ TTL, and looking at least once per TTL makes a
completed-and-vanished tenure impossible to miss. `recoveryPollCeiling` caps the
backoff at half the configured TTL (falling back to the smallest TTL the startup
path accepts when it is unknown, because the safe direction for an unknown is to
poll *more* often). The cost is bounded and small: at the default 10 s TTL that
is one RPC per 5 s per unfenced node — less traffic than the keepalive a healthy
leader already runs against the same backend.

What remains is a blind period this node cannot bound from the inside: **a
partition in which we cannot reach etcd but a peer can.** Two things keep it in
proportion. First, a *failing* backend cannot have granted the lease to anyone
else either, so the ordinary etcd-outage case — the one this whole loop exists
for — is not affected. Second, the shipped resume path already has the same
property: an operator-restarted leader acquires a free lease with no proof
either. The change makes the class reachable without a restart; it does not
create it.

Closing it properly needs one of two things, and neither is a small edit:

- **Durable evidence of an intervening epoch.** Not available from this backend.
  etcd's `create_revision` advances on unrelated writes, so an epoch gap carries
  no information about how many grants happened, and a `Read` of a free lease
  returns no watermark at all (the key is deleted on expiry).
- **Route a long-blind recovery through the standby freshness machinery** rather
  than acquiring — ask the peer instead of guessing, which is what
  `enterStandbyResync` and `haPromoteFreshnessWindow` already exist to do.

That is a safety-versus-availability posture decision of exactly the class
already recorded as HA-18, so it is written down as **HA-19** for an owner
rather than settled inside a chaos fix.

---

## 7. Gates

`ha_lease_recovery_chaos_test.go` — 20 tests. Every **defect** gate was verified
**failing against the pre-fix tree** before the fix landed; the arming, latching
and jitter gates pin new behaviour and have no pre-fix counterpart.

| gate | pins |
|---|---|
| `ResumeDuringBackendOutage_RegainsWriteAuthority` | the registered HA-7 test: outage → recovery → write authority, no operator |
| `RecoveredLeaderKeepsRenewing` | recovery starts the keepalive; authority survives past a full TTL |
| `ResumeAbsorbsAShortBackendOutage` | the budget covers the common boot-order case with no read-only window at all |
| `ResumeDoesNotBlockBootOnALongOutage` | the other end of that budget: an etcd outage must not delay the proxy data plane's startup |
| `UnknownFenceStateDoesNotDemoteToStandby` | HA-16: an unreachable fence is not a fence decision |
| `ForeignHolderOnResumeStillEntersStandby` | the shipped S4 demotion does not regress |
| `ForeignHolderSeenDuringRecovery_EntersStandby` | fence taken while blind → stand down |
| `ForeignHolderWithoutTarget_LatchesAndStopsRetrying` | latched: never take over when a foreign leader vanishes |
| `RealDenialIsNotRetriedIntoLeadership` | a live holder is answered immediately, not waited out |
| `OwnGhostLeaseStillWaitedOut` | the S5 ghost path survives the refactor |
| `StopIsPromptDuringRecoveryBackoff` | interruptible sleep, 8 trials (CHAOS-54's many-trial rule) |
| `RecoveryNeverArmsForAStandby` / `ForAHealthyLeader` | the arming conditions |
| `UnfencedLeaderIsVisibleOnMetrics` | HA-17, including absence on a lease-less node |
| `StandbyIsNotReportedUnfenced` | the paging rule is not diluted |
| `LeaseHealthReportsRecovering` | the JSON surfaces |
| `RecoveryBackoffIsJittered` | fleet spreading |
| `ForeignHolderEvidenceSurvivesAnExpiringLease` | a denial naming a live holder is never downgraded to a retry, even if that lease expires immediately after |
| `RecoveryPollCeilingStaysBelowTheLeaseTTL` | HA-19: the poll interval stays under the TTL at every configured value, and an unknown TTL polls faster, not slower |
| `LegacyModeUnchanged` | nil provider is byte-identical |

---

## 8. The process lesson

CHAOS-54 generalised §21's lesson from back ends to listeners. This sweep
generalises it again, to **decisions**:

> A subsystem that is careful about what it may CONCLUDE from an unknown in one
> direction is not automatically careful in the other. `ha_lease.go` documents
> "leadership cannot be taken while the fence's state is unknown" and enforces
> it exactly — while, forty lines away, leadership was **given up** on the same
> unknown, and the node then stopped asking. When a component has a rule about
> uncertainty, check that the rule is applied to every branch that consumes it,
> not just the one it was written for.
