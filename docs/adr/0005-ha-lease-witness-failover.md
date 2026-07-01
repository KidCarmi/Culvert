# ADR-0005: Safe automatic HA failover via a fencing lease + witness

- **Status:** Proposed (2026-07-01). Design under adversarial review before implementation.
- **Date:** 2026-07-01
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (directed "do lease+witness").
- **Builds on:** ADR-0004 (HA split-brain Slice 1 — merged in PR #525). This is the deferred
  "automatic-failover mechanism" that ADR-0004 left open, and the maintainer chose **lease + witness**
  (Raft shelved — "no 3CP now").
- **Closes:** the residual of **RISK-001** (safe *automatic* failover on unplanned leader loss +
  failback) once implemented.

## Context — what Slice 1 left open

ADR-0004 made 2-CP HA safe-by-default (manual failover) and honest (term-visible `/healthz`), and added
an explicit promote primitive. It did **not** provide safe *automatic* failover on unplanned leader
loss, because a witness-less 2-node cluster provably cannot: on a symmetric partition the standby
cannot distinguish "leader dead" from "leader alive but unreachable." The earlier **DP-quorum** attempt
was rejected by adversarial review (F1 stale-quorum dual-majority, F2 two independent denominators, F4
silent data loss, F6 ungated CA issuance, F7 term-tie). Its core defect: **no single authority and no
total order** — two sides evaluated stale, independent views.

A **fencing lease held at a witness** fixes exactly those: one authority grants the lease, and the
lease's monotonic **fencing token** is a true total order.

## Decision — a fencing lease arbitrated by a witness

### The lease

A single cluster-wide **lease** with a monotonic **fencing token** (uint64, call it `epoch`). Exactly
one CP holds the lease at any instant. **The lease-holder is the leader; only the holder has write
authority.** The lease has a TTL; the holder must renew before it expires or it becomes acquirable.

Lease API (backend-agnostic `LeaseProvider` interface, so the arbiter is pluggable):

- `Acquire(candidateID) → (granted bool, epoch uint64, holder string, leaseExpiry time)`
  Grants the lease **and increments `epoch`** iff the lease is currently free or expired. If a live
  holder exists, returns `granted=false` + the current holder/epoch (deny).
- `Renew(holderID, epoch) → (ok bool, newExpiry time)`
  Extends the TTL iff `holderID` **and** `epoch` match the current record. Fails if the epoch is stale
  (someone else acquired), which is the holder's signal that it has **lost** the lease.
- `Read() → (holder, epoch, expiry)` — read-only, for `/healthz` and failback checks.

`epoch` **only ever increases**, and increases **only** on a successful `Acquire`. That is the total
order the DP-quorum design lacked.

### The witness

A lightweight arbiter that owns the lease record. It is **NOT a Control Plane**: it holds no cluster
state, no CA, serves no Data Planes, does no replication. It only arbitrates the lease. This satisfies
the maintainer's "no 3rd CP."

- **Default backend — embedded witness mode:** `./culvert --witness --witness-addr :50052`. A tiny
  gRPC service exposing `LeaseAcquire`/`LeaseRenew`/`LeaseRead` over the **existing mTLS** infra
  (reuses `cpServerOption` / `wrapUnary` / the `culvert.ConfigService` machinery or a sibling
  `culvert.WitnessService`). The lease record lives in memory + an atomic-write file so a witness
  restart does not lose the epoch floor (monotonicity across restart is load-bearing — a witness that
  forgets the epoch and restarts to a lower one re-opens the split-brain door; see F-checks below).
- **Pluggable alternative (future):** an object-store conditional-write / DynamoDB-conditional lease
  implementing the same `LeaseProvider`. Deferred; the interface is designed for it now.

The witness is a **single point of failure for FAILOVER, not for SERVING.** If the witness is down,
the current leader keeps serving (it holds a valid lease until TTL; see "witness-down" below) but a NEW
failover cannot happen until the witness returns. That is the correct trade for a 2-CP topology and is
strictly better than today (no safe auto-failover at all). Operators who need witness HA run it on a
separate failure domain; a future object-store backend removes the SPOF entirely.

### Leader behavior (the renew loop + self-fence)

1. On becoming leader (via `Acquire`), the CP records `(epoch, leaseExpiry)`.
2. A **renew loop** renews every `renewInterval` (e.g. 3s). Each successful renew refreshes
   `leaseExpiry = now + leaseTTL` (e.g. 10s).
3. **Write authority is gated on a locally-valid lease:** `role==leader AND epoch==currentEpoch AND
   now < leaseExpiry`. Every state-mutating path checks this (admin writes, CA signing, cluster-state
   apply). A write when the lease is not locally-valid is **rejected** — this bounds divergence to
   nothing committed after the lease goes stale locally (closes DP-quorum's F4).
4. **Self-fence:** if a renew FAILS (stale epoch ⇒ lost the lease; or witness unreachable ⇒ cannot
   confirm), the leader immediately **stops writing** and, once the lease is locally expired, **demotes
   to read-only standby**. The demote path is new (Slice 1 had none).

### Standby behavior (acquire-on-loss)

1. Standby syncs from the leader as today (HASync pull), and seeds its epoch from the leader's epoch.
2. On **leader loss** (HASync failing past the threshold), the standby attempts `Acquire`.
   - The witness grants **only if the lease is free or expired** — i.e. the old leader has stopped
     renewing (because it died, or self-fenced on losing witness contact). If the old leader is alive
     and still renewing, `Acquire` is **denied** and the standby stays read-only.
3. On a granted `Acquire` (new, higher epoch), the standby **promotes** with that epoch.

### The safety argument (why this is safe where DP-quorum was not)

- **Single authority + total order:** all promotion decisions funnel through the witness's lease record;
  `epoch` is monotonic. No two stale denominators (kills F2); no term-tie (kills F7 — the witness
  assigns the epoch, so the side that acquired later provably has the higher one).
- **No dual-write window IF the timing invariant holds:**
  `leaseTTL  >  (leader self-fence reaction time)  +  (max clock skew)`.
  The witness must not grant a new `Acquire` until `leaseTTL` has elapsed since the last renew; the old
  leader must stop writing within `leaseTTL` of a failed renew. With the acquire-side TTL strictly
  greater than the leader's stop-writing latency + skew, the old leader has provably stopped writing
  before the new leader can acquire. This is the standard fencing-lease argument (Chubby/etcd-lease
  class), and it is a **theorem given the invariant**, not a hope.
- **Fencing tokens stop a zombie leader's writes at every sink:** a partitioned old leader that
  wrongly believes it leads carries a **stale epoch**. Its HASync bundles are rejected by the new
  leader (epoch check); its DP config/cert issuance is stamped with the stale epoch and rejected by
  recipients. This closes DP-quorum's F6 (ungated CA) **only if cert issuance is also epoch-gated** —
  which this ADR requires (see scope).
- **Failback dissolves the merge problem:** because write authority requires a locally-valid lease,
  the old leader stopped committing when it lost the lease. On reconnect its `Renew` fails (stale
  epoch) → it demotes and resyncs from the new leader. There is no divergent committed history to
  merge (closes F4), so failback = the existing full-bundle resync, now correct.

### Scope (implementation slices — each behind green CI)

- **S1 — LeaseProvider + embedded witness:** the interface, the in-memory+file lease record (monotonic
  epoch across restart), `--witness` mode + gRPC `WitnessService`, mTLS reuse. Pure, heavily unit-
  tested (acquire-free, acquire-denied-when-held, renew-ok, renew-stale-epoch-fails,
  acquire-after-expiry, epoch-monotonic-across-restart).
- **S2 — leader renew loop + self-fence + demote:** wire `Acquire` into promote; renew loop; the demote
  path (`role: leader→standby`, stop renew, resume HASync pull). Write-authority gate keys on
  locally-valid lease. `/healthz` surfaces `epoch` + `lease_valid`.
- **S3 — fencing token on write sinks:** stamp `epoch` on HASync bundles (reject stale on apply),
  admin mutations, and **cert issuance / enrollment** (reject stale-epoch). This is the F6 closure and
  the most invasive slice — every write sink audited.
- **S4 — standby acquire-on-loss + failback:** replace the auto-promote path (still opt-in via
  `--ha-auto-failover`, but now SAFE) with lease-acquire; reconnecting-leader → demote+resync.
- **S5 — config/flags/GUI parity + docs:** `--ha-witness-addr`, witness TLS, witness status in the HA
  panel; operator runbook; ADR-0004/RISK-001 updated; evidence tests re-pinned.

### Timing parameters (subject to review)

`renewInterval = 3s`, `leaseTTL = 10s`, `acquireGrace = leaseTTL` (witness won't grant until TTL since
last renew), leader stop-writing latency ≤ 1 renew interval. These give a failover time of ~lease TTL
(≈10s) — slower than Slice 1's unsafe 15s auto-promote is fast, but SAFE. Tunable.

## Consequences

- **Positive:** first *safe* automatic failover for 2-CP HA; deterministic total order; failback
  without a merge problem; the DP-quorum failure modes are structurally closed (single authority + total
  order + write-gating + epoch-fenced issuance). Backend-agnostic interface leaves object-store HA open.
- **Cost:** a new **witness** process to deploy (one more small container; not a CP). Failover latency
  ≈ lease TTL. Fencing-token plumbing touches every write sink (S3 is invasive; the audit is the work).
- **Risk / SPOF:** the witness is a SPOF **for failover** (not for serving). Documented; object-store
  backend is the removal path. Clock-skew assumption is explicit and must be validated (S2 test).
- **This does NOT demote the manual promote** (ADR-0004 Slice 1e) — that stays as the break-glass path
  and for planned handoffs.

## Alternatives considered (recap)

- **DP-quorum** — rejected by adversarial review (no single authority / no total order). See ADR-0004.
- **Raft (≥3 CPs)** — shelved by the maintainer.
- **No witness (stay manual)** — the current safe posture; this ADR is the opt-in upgrade to safe
  *automatic*.

## Open questions for review (before coding)

1. **Witness restart monotonicity:** is the atomic-write epoch floor sufficient, or does a witness that
   loses its disk (fresh volume) re-open split-brain? (Mitigation: witness refuses to start on a missing
   floor unless explicitly reset; document.)
2. **Witness-unreachable vs lease-lost:** the leader must treat "cannot reach witness" the same as
   "lost the lease" for self-fencing once the local lease expires — but must NOT self-fence early while
   the local lease is still valid (else a witness blip needlessly fails over). Is the
   local-expiry-gated demote correct?
3. **Clock skew:** the timing invariant assumes bounded skew. Do we need the witness to be the sole
   clock (leases expressed in witness-relative time / renewal round-trips) rather than trusting CP
   wall-clocks?
4. **Split of write sinks (S3):** have we enumerated EVERY state-mutating sink that must be epoch-gated
   (admin API, CA sign, enrollment, cluster-state apply, config version, threat-feed, bandwidth, node
   groups)? A missed sink is an F6-class hole.
