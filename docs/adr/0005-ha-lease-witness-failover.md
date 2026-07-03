# ADR-0005: Safe automatic HA failover via a fencing lease in etcd

- **Status:** Accepted-direction, **RESUMED — S0 + S1 SHIPPED** (S1: 2026-07-03, after the
  ADR-0002 decomposition program completed). Design adversarially reviewed and revised from a
  hand-rolled witness to an **etcd-backed fencing lease** (maintainer: "do it like the big stable
  vendors" + self-hosted → etcd). S2–S5 remain. **F4 posture: documented bounded-LWW (option A)**
  — not state-in-etcd.
- **Safety posture while parked:** unchanged from ADR-0004 Slice 1 — HA is safe-by-default (manual
  failover, explicit promote, planned handoff, term-visible `/healthz`). Nothing regresses by pausing;
  only the *automatic* convenience is deferred.
- **Date:** 2026-07-01
- **Deciders:** Chief Engineering Advisor (proposed + revised); project maintainer (chose etcd + LWW-A).
- **Builds on:** ADR-0004 (HA Slice 1 — merged, PR #525). This is the deferred automatic-failover
  mechanism ADR-0004 left open. **Closes** the residual of **RISK-001** once implemented.

## Context — what Slice 1 left open

ADR-0004 made 2-CP HA safe-by-default (manual failover) + honest (`/healthz` term) + added an explicit
promote primitive, but did **not** provide safe *automatic* failover on unplanned leader loss: a
witness-less 2-node cluster provably cannot. The prior **DP-quorum** attempt was killed by adversarial
review (no single authority, no total order → F1 stale-quorum dual-majority, F2 two independent
denominators, F4 silent data loss, F6 ungated issuance, F7 term-tie).

## Decision — a fencing lease held in etcd

A single cluster-wide **lease** with a monotonic **epoch** (fencing token), arbitrated by **etcd** — a
Raft-backed, strongly-consistent store. This is the industry-standard self-hosted leader-election
backend (it is what Kubernetes itself runs on; k8s' own `coordination.k8s.io` Lease sits on etcd).
**We do NOT hand-roll consensus** — the whole point of "like the big stable vendors" is to stand on a
proven Raft implementation, not write one.

### Why etcd (and why not the hand-rolled witness that this ADR originally proposed)

The first draft proposed an embedded, hand-rolled "witness." Adversarial review (below) showed its
durability model is the load-bearing risk (Finding 5: disk-loss → epoch reset → split-brain, or
refuse-to-start → liveness trap). etcd **structurally retires that**: its lease + key **`mod_revision`**
give a durable, network-replicated, strictly-monotonic fencing token with correct restart semantics,
and etcd — not a CP wall-clock — is the lease-time authority. The embedded witness is dropped (kept
only as a documented, single-arbiter, air-gapped fallback behind the same interface, if ever needed).

### `LeaseProvider` interface (etcd is the default implementation)

```
Acquire(candidateID)      → (granted, epoch, holder, leaseValidFor)   // grants + bumps epoch iff free/expired
Renew(holderID, epoch)    → (ok, leaseValidFor)                       // keepalive; fails on stale epoch (⇒ lost)
Read()                    → (holder, epoch, leaseValidFor)            // for /healthz + puller-trust
```

etcd mapping: a lease-bound key `/culvert/ha/leader` whose value is the candidateID; the **fencing
token `epoch` is the key's `create_revision`** (strictly monotonic across the etcd cluster's life,
survives etcd restarts, cannot go backwards). `Renew` = etcd lease keepalive; a `Renew` whose
`create_revision` no longer matches ⇒ this node lost the lease. Backend-agnostic so k8s-Lease /
object-store can be added later.

etcd is a SPOF **for failover, not for serving** — a lost etcd freezes *new* failovers, not the
current leader's serving. Operators run etcd on its own failure domain (or a 3-node etcd for real HA);
this is the standard, understood trade and is strictly safer than today (no safe auto-failover at all).

### Leader / standby / failback (unchanged in shape from the witness design)

Leader holds + keepalives the lease; **write authority is gated on a locally-valid lease AND
re-validated at commit time** (see Finding 3/4). On keepalive failure it **self-fences** (stops
writing, then demotes to read-only standby). Standby, on leader loss, calls `Acquire` — granted only
once the old leader stopped keepaliving (died or self-fenced) — and promotes with the new epoch.
Reconnecting old leader → `Renew` fails → demote + resync **from the standby's recorded address (S0)**.

## Adversarial review findings (2026-07-01) — and how this revision answers them

The review of the original (hand-rolled-witness) draft found the shape correct (it does close F1/F2/F7
— single authority + monotonic token) but four claims over-stated and one path non-implementable.
Recorded so implementation cannot forget them:

| # | Finding | Sev | Resolution in this revision |
|---|---|---|---|
| 1 | **Failback has no sync target** — the leader never recorded the standby's address (ADR-0004 asymmetry), so a demoted leader has nowhere to resync from. | CRIT | **S0 (blocking prerequisite):** HASync request carries the standby's advertised address; the leader records it. Failback + puller-trust both need it. Nothing else starts until S0 lands. |
| 2 | **Issuance ungated / DPs have no reference epoch** — `Enroll`/`SignCSR`/`RenewCert`/`SyncRevocations` have no HA gate, and DPs pick a CP by reachability and never learn the epoch, so a zombie leader keeps signing with the shared CA. | CRIT | **S3:** propagate the current epoch to DPs (ConfigSnapshot + heartbeat reply) and gate all four issuance RPCs on a locally-valid lease; DPs reject issuance stamped below their last-seen epoch. The fencing token is only real once the *recipient* knows it. |
| 3 | **Wall-clock lease + GC/CPU pause** defeats the timing "theorem" (self-fence code is what's frozen). | HIGH | Gate writes on **etcd-confirmed** remaining lease (keepalive round-trip), and **re-validate the token at commit**, forbidding a commit unless a keepalive was confirmed within `TTL − maxWriteLatency`. etcd is the clock, not the CP. |
| 4 | **F4 narrowed, not closed** — admission-time check + async pull + destructive `ImportFullState` still silently eats the leader's last pre-fence writes. | HIGH | **Accepted as bounded-LWW (option A):** document a failover data-loss window of ≤ un-replicated interval; commit-time fencing minimizes it. Full closure (state-in-etcd) is recorded as a future phase, explicitly NOT done now. |
| 5 | **Hand-rolled witness durability** — disk-loss → epoch reset → split-brain, or refuse-to-start → liveness trap. | HIGH | **Dissolved by using etcd** (durable, Raft-replicated, monotonic `create_revision`). This finding is the main reason the backend changed. |
| 6 | **Two epochs** (`term` vs lease) + the old 15s HASync-miss auto-promote survives alongside the lease. | MED | **S2/S4:** collapse `term` into the etcd epoch (single monotonic value, witness-assigned; delete unilateral `term++` and `seedTermFromLeader`'s term role); **delete the 15s `onMaxFail` auto-promote trigger** — promotion is gated ONLY on `Acquire`. |
| 7 | **Zombie leader serves a stale bundle** to a puller (HASync is pull; the fence was described on the wrong side). | MED | **S3:** the *puller* reads the current epoch (etcd `Read`) and rejects any bundle stamped below it before `ImportFullState`. |
| 8 | **3-way partition / pull staleness + flap** — a standby can `Acquire` then promote on stale state; flapping links churn. | MED | **S4:** freshness gate — refuse to promote on a bundle older than a threshold; add hysteresis to self-fence. |

## Scope — implementation slices (each behind green CI)

- **S0 — peer-address (BLOCKING prerequisite).** HASync request carries the standby's advertised
  address; the leader records it in `HAState`/`ClusterStore`. Small, testable, and unblocks failback +
  puller-trust. *Nothing else starts until this lands.*
- **S1 — `LeaseProvider` + etcd impl.** Interface + etcd client (lease + `/culvert/ha/leader` key,
  `create_revision` = epoch). Integration-tested against an embedded/test etcd; Culvert-side logic
  unit-tested against a fake `LeaseProvider`. New dep: `go.etcd.io/etcd/client/v3` (justified by the
  maintainer's etcd decision; recorded in go.mod).
- **S2 — leader keepalive + self-fence + demote; collapse term→epoch.** Wire `Acquire` into promote;
  keepalive loop; the new demote path; write-authority gate = locally-valid lease **re-checked at
  commit**; `/healthz` surfaces `epoch` + `lease_valid`.
- **S3 — epoch fencing at every write sink + DP propagation.** Stamp epoch on HASync bundles (puller
  rejects stale via etcd `Read`); gate `Enroll`/`SignCSR`/`RenewCert`/`SyncRevocations` on a
  locally-valid lease; propagate epoch to DPs (ConfigSnapshot + heartbeat) and have DPs reject
  below-epoch issuance. The F6 closure — most invasive; every sink audited.
- **S4 — standby acquire-on-loss + failback + freshness gate.** Replace the (deleted) 15s trigger with
  `Acquire`-gated promotion; reconnecting-leader → demote + resync from the S0-recorded address; refuse
  to promote on stale state; self-fence hysteresis.
- **S5 — config/flags/compose/GUI/docs.** `--ha-etcd-endpoints` (+ TLS), the etcd service in
  `docker-compose.yml`, epoch/lease status in the HA panel (GUI parity), operator runbook incl. the
  **documented LWW window**, evidence tests re-pinned, ADR-0004/RISK-001 updated.

## Implementation log

### 2026-07-03 — S1 SHIPPED: `internal/halease` (LeaseProvider + etcd impl + conformance suite)
- **Package `internal/halease`:** `Provider` interface exactly per this ADR (`Acquire`/`Renew`/
  `Read` + `Close`), with the contract written into the interface doc: grants are strictly
  monotonic (the fencing property), **loss is an outcome (`ok=false`, nil error), transport
  failure is an error (truth UNKNOWN)** — callers fail toward self-fence on both. `Close` MUST NOT
  revoke a held lease (release-on-shutdown is S2 policy, not a primitive).
- **`Etcd`:** lease-bound key `/culvert/ha/leader`; **epoch = the key's `create_revision`**
  (from the grant txn's header revision) exactly as designed. `Acquire` is a single txn
  (`CreateRevision==0 → Put(lease)` else `Get`); a **denied Acquire revokes its scratch lease**
  (pinned by test — leaked leases would accumulate on every standby retry). `Renew` keepalives
  then **re-verifies the key still carries (holder, epoch)** — guarding the fencing property even
  if a stray keepalive outlives the key; `ErrLeaseNotFound` ⇒ loss, everything else ⇒ error.
- **`Fake`:** injectable clock, `ExpireForTest`; the S2 Culvert-side logic unit-tests against it.
- **One conformance suite, two backends:** `testConformance` pins grant/deny/read/renew/stale-
  epoch/expiry-reacquire/**fencing-monotonicity** and runs against the Fake always AND against a
  REAL etcd — `TestEtcd_Conformance_Embedded` boots `go.etcd.io/etcd/server/v3` **embed**
  in-process (TEST-ONLY dependency; state in `t.TempDir`), so etcd's actual Raft state machine
  exercises the mapping on every CI run with zero external infrastructure. An env-gated leg
  (`CULVERT_TEST_ETCD_ENDPOINTS`) can additionally target an external etcd.
- **Dependency reality check (recorded):** `go.etcd.io/etcd/{client,api,server}/v3` were ALREADY
  in the module graph as indirects of existing dependencies — pinning them direct at v3.6.13
  added ~80 go.sum lines total. The "point of no cheap return" was far cheaper than the parking
  note assumed. The shipped binary links only `client/v3` (and only once S2 wires it into ha.go);
  `server/v3` is imported exclusively by `_test.go` files.
- **Not in S1 (by design):** no runtime wiring, no flags, no compose/GUI — the primitive is
  dormant until S2. Nothing about ADR-0004's safe-by-default posture changes yet.

## Consequences

- **Positive:** first *safe* automatic failover for 2-CP HA, standing on etcd (Raft) rather than a
  hand-rolled arbiter — the big-vendor way. F1/F2/F5/F7 structurally closed; F6 closed by DP-side epoch
  enforcement; F3 closed by etcd-clock + commit-time re-check. Backend-agnostic interface keeps
  k8s-Lease / object-store open.
- **Cost / honest limits:** a new **etcd** dependency + one more container to run (its own failure
  domain for real HA). **F4 is a documented bounded-LWW window, not closed** — failover may lose the
  leader's last un-replicated admin writes; full closure (state-in-etcd, the k8s model) is a future
  control-plane re-architecture, explicitly deferred. Failover latency ≈ lease TTL (~10s). S3 fencing
  touches every write sink — the audit is the work.
- **Does NOT demote manual promote** (ADR-0004 Slice 1e) — stays as break-glass + planned handoffs.
- **Effort is real:** this is a multi-slice program with genuine distributed-systems subtlety; the big
  vendors have teams-years here. We match the *pattern* (etcd fencing lease) and are honest about the
  *bound* (LWW-A), not pretending to match Spanner.

## Alternatives considered

- **Hand-rolled embedded witness** (this ADR's first draft) — rejected after review (Finding 5
  durability); kept only as a documented air-gapped fallback behind `LeaseProvider`.
- **State-in-etcd (full k8s model, F4-B)** — structurally closes F4 but is a control-plane
  re-architecture; recorded as a future phase, deferred by the maintainer.
- **DP-quorum** — rejected earlier (no single authority/total order). **Raft-in-Culvert** — shelved
  ("no 3CP"); note etcd *is* Raft, just out-of-process, which is the point.
