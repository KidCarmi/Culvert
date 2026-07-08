# ADR-0004: Control-Plane HA split-brain — make it visible and manual now; pick a fencing mechanism deliberately

- **Status:** Accepted + SHIPPED (Slice 1: 2026-06-30). The automatic-failover **mechanism** decision this ADR deliberately deferred was made and shipped as **ADR-0005** (etcd-backed fencing lease, S0–S5 complete 2026-07-03): with `--ha-etcd-endpoints` set, leadership is lease-arbitrated and automatic failover is safe. Without a lease, this ADR's safe-manual posture remains the exact runtime behavior (nil provider = byte-identical).
- **Date:** 2026-06-30
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (accepted Slice 1 direction)
- **Risk:** Closes the design gap behind **RISK-001** (BLOCKER) in `docs/engineering/TECHNICAL-RISK-REGISTER.md`.
- **Supersedes the "Now (S)" recommendation in RISK-001** with a concrete, reviewed plan.

## Context

Culvert ships Control-Plane **High Availability** as a headline capability. The implementation
(`ha.go`, 570 LOC) is 2-node active/passive with leader→standby state replication over the existing
mTLS gRPC channel. The behavior is **pinned** (not accidental) by
`ha_split_brain_failover_evidence_test.go`.

### Verified current state (file:line evidence, re-confirmed 2026-06-30)

- **Topology:** exactly 2 CPs (leader + standby). The standby *pulls* a full `HAStateBundle`
  (`controlplane.go:873` — `ClusterState`, `CACertPEM`, `CAKeyEncrypted`, `Config`, `Version`) every
  **5s** (`ha.go:150`).
- **Detection is standby-only.** After **3** missed syncs ≈ **15s** (`ha.go:154`), the standby calls
  `promote()` (`ha.go:292`), starts a gRPC server, sets `role="leader"`, and the sync loop **returns
  forever** (`ha.go:193-195`).
- **No demotion / fencing / quorum** exists anywhere. `promote()` is one-way; `Stop()` only closes a
  channel. A grep for `demote`/`stepDown`/`quorum`/`fenc*` returns nothing.
- **Leader-on-restart self-asserts** (`main.go:647-653`): if `ha_config.json` has `Enabled==true` it
  calls `EnableAsLeader` — and it does **not even read `haCfg.Role`**. A node persisted as `standby`
  that restarts on the CP path becomes a **leader**. The doc comment at `ha.go:29-33` ("detects the
  peer is already serving, becomes standby") describes code that **does not exist**.
- **Both sides answer `/healthz` with `leader:true`** (`ha.go:404-408`) — no term, no peer-agreement
  field. A load balancer cannot distinguish them.
- **No reconciliation on heal.** Two diverged `ClusterStore`s never merge; `applyHABundle` →
  `ImportFullState` (`ha.go:236`) is a **destructive full overwrite**. Rolling-update state is not even
  replicated (CL-5, pinned in the evidence test).
- **The "HA token" is not a fence.** It is a static, shared secret the standby presents to authenticate
  the pull (`ha.go:79-83`). It never rotates on promotion and arbitrates nothing.

### The timing facts that matter (verified 2026-06-30)

The field that marks a DP `connected` is written by `PushMetrics` → `UpdateNodeSeen`
(`controlplane.go:664`), and `PushMetrics` runs on `metricsLoop(ctx, pollInterval*2)` where
`pollInterval = 30s` (`main.go:2116`, `controlplane.go:1215`):

| Event | Interval | Source |
|---|---|---|
| DP liveness heartbeat (sets `Status="connected"`, `LastSeen`) | **60s** | `controlplane.go:1215` (`pollInterval*2`) |
| DP declared `disconnected` | **90s** timeout | `enrollment.go:588` |
| Standby → leader promotion | **15s** (3 × 5s) | `ha.go:150,154` |
| DP-side CP failover | after 3 consecutive **config-poll** (30s) failures; round-robin by reachability; **never consults `/healthz`** | `controlplane.go:1190-1254` |

**The promotion delay (15s) is far shorter than the liveness timeout (90s).** This single inversion is
why a naive "promote when I see a DP majority" rule is unsafe (see §Rejected, F1).

## The governing theorem (state this plainly, because it drives everything)

**A 2-node active/passive cluster with no witness cannot perform safe automatic failover.** On a
symmetric partition the standby cannot distinguish "leader is dead" from "leader is unreachable but
alive and still serving DPs." Any automatic promotion in that topology *is* the split-brain. This is a
property of the topology, not a tuning problem; no epoch/token cleverness removes it without a third
vote (a witness, a DP-majority quorum, or real consensus across ≥3 CPs).

The corollary for the product: **today's "automatic HA failover" is only safe when the leader truly
died and stays dead.** On the most common real failure — a network partition where the old leader
survives — it splits the cluster into two divergent leaders whose admin mutations (enrollment, tokens,
CA, CRL) diverge permanently. "Enterprise HA" currently overstates the guarantee.

## A reviewed-and-rejected design: hand-rolled DP-quorum write fencing

The first design proposed using the **Data Planes as the quorum/witness**: a CP holds write authority
only while a majority of the DP fleet heartbeats it; a standby promotes only on observing that majority;
a leader self-fences when it loses it. The appeal was "native, no new dependency, no third CP."

An adversarial review (distributed-systems failure analysis, grounded in the code) **broke the
load-bearing claim** that "because write authority requires DP-majority, nothing diverges." The
findings, kept here so any future revival inherits them:

- **F1 (critical) — stale-quorum dual-majority.** Quorum was computed from the replicated `LastSeen`
  field, which stays `connected` for up to **90s** after a DP stops reaching a CP. Because promotion
  happens at **15s**, a freshly-promoted standby inherits a *full-majority* view of a fleet it cannot
  actually reach, while the old leader still sees its DPs inside the 90s window. **Both clear the
  majority bar simultaneously.** The 15s-promote-vs-90s-timeout inversion makes this structural.
- **F2 (critical) — independent stale denominators.** Each side computes majority locally from a
  bundle that is up to 90s behind and only persisted every 10th heartbeat (`enrollment.go:384`). The
  two sides can legitimately compute different fleet sizes (e.g. an enroll/revoke just before the
  partition) and both clear their own bar. Two independently-evaluated majority predicates over two
  stale snapshots do not compose into a single-writer guarantee.
- **F3 (high) — DPs don't converge.** DP failover is per-DP, reachability- and config-order-driven
  (`controlplane.go:1190`), and **does not fire at all** in the canonical CP-to-CP-only partition
  (each DP can still reach `addrs[0]`). The fleet partitions by static config order, not by liveness.
  (This is primarily an *availability* problem: with a fresh-heartbeat rule the starved side correctly
  stays read-only, so the core idea is salvageable — but the convergence the design assumed is absent.)
- **F4 (high) — silent data loss, the merge problem does NOT dissolve.** Even with perfect mutual
  exclusion of *concurrent* writes, a write that commits on the old leader after its last 5s snapshot
  but before it fences is **silently overwritten** on heal by the destructive `ImportFullState`. The
  hard problem is converted into quiet last-writer-wins data loss, not removed.
- **F5 (high) — fix-induced unavailability.** A DP-side outage (switch failure, bad DP rollout) that
  drops *both* sides below majority makes the healthy leader self-fence into read-only during exactly
  the incident where admin write access matters most. Even-split and <3-DP fleets go read-only by
  construction; most real 2-CP deployments have small fleets, so they get *no* automatic failover.
- **F6 (high) — CA issuance is a second, ungated write surface.** A fenced ex-leader still holds the
  cluster CA and keeps answering `SignCSR`/`Enroll` (`controlplane.go:835`) for DPs pinned to it. Two
  CPs signing with the same key diverge the enrolled set + CRL — a *security* divergence the
  admin-API-only gate doesn't touch.
- **F7 (med-high) — term tie on heal.** Both sides bump term independently → both reach N+1; "higher
  term wins" has no tiebreaker correlated with *which side took writes*, so the wrong side can win and
  discard the majority-blessed writes. A term must be blessed by a shared authority (the majority
  itself), not bumped unilaterally.
- **F8/F9 (med) — restart-during-election + self-fence lag.** The `main.go:647` self-assert compounds
  double-failover; self-fencing keyed on the 90s-stale field lags reality by `90s + N·interval`,
  widening the divergence window.

**Verdict:** the design *narrows* the split-brain window but does not close it, and adds new data-loss
and availability failure modes. Making it safe requires fresh-heartbeat quorum (zero on promotion,
freshness timeout **shorter** than the promotion delay), a **sub-second heartbeat redesign**,
majority-acked terms, gated cert issuance, and either write-ahead replication or a documented LWW
data-loss window. **At that cost you have hand-rolled most of a consensus protocol** — with subtler
failure modes than an off-the-shelf one. This shifted the cost/benefit decisively away from "native and
cheap," which was its only advantage over a lease or Raft.

## Decision

Split the work into a **committed no-regret Slice 1** and an **open mechanism decision**.

### Accepted now — Slice 1 (no-regret; correct under every mechanism)

These hold regardless of which automatic-failover mechanism is later chosen, and they convert *silent*
split-brain into *visible, operator-recoverable* split-brain:

1. **Default HA to MANUAL failover.** Gate the 15s auto-promote behind an explicit opt-in
   (`--ha-auto-failover`, default off / config field). With the theorem above, unattended 2-node
   auto-promotion is unsafe; default-off stops the dangerous behavior. A dead leader is promoted by an
   operator (or by a later, safe mechanism). **This is a behavior change** and must be documented in the
   release notes and the operator runbook.
2. **Restart honors the persisted role.** Rewrite `main.go:647`: a restarting HA node must NOT
   self-assert leader. It reads and honors the persisted `Role` (today it ignores it): a **standby
   re-enters standby** (never silently becomes a second leader); a **leader resumes leadership** with an
   honest split-brain-risk warning when auto-failover is enabled.
   - **Scope correction (discovered during implementation, 2026-06-30):** the ADR originally said a
     restarted leader should "probe the peer and become standby if it already leads." That is **not
     implementable in the current topology**: the standby is the gRPC *client*, so the leader never
     records the standby's address — `peerAddr` holds the *leader's own* advertised address (verified at
     `controlplane.go:1905-1906` and `haDeployCommand`). A leader therefore has no peer address to probe
     on restart. True peer-handshake-on-restart requires **recording the standby's advertised address**
     (a small HASync-protocol addition) and is deferred to the failover-mechanism slice, which needs
     peer identity anyway. Slice 1 ships the role-honoring half (the verified `main.go:647` bug) plus the
     honest leader-resume warning; the term-visible `/healthz` (item 3) is what makes a double-leader
     *detectable* in the interim.
3. **Term/epoch plumbing + `/healthz` visibility.** Add a monotonic `term` to `ha_config.json` and
   `HAStateBundle` (plumbing + persistence only — cross-side *comparison semantics* are
   mechanism-dependent, F7, and are deferred). Surface `role`, `term`, `write_authority`, and
   `peer_agreement` in `/healthz` so a load balancer / operator can SEE a split-brain instead of both
   sides claiming `leader:true`.
4. **Flip the evidence test.** `ha_split_brain_failover_evidence_test.go` pins today's (unsafe)
   behavior by design; update its assertions to pin the new behavior as each fact changes, preserving
   it as the regression backstop.
5. **Slice 1e — the explicit promote primitive (added during PR #525 review).** Making auto-failover
   opt-in exposed two gaps a Codex review surfaced: (a) **no operator promote path existed** — Slice 1
   told operators to "promote via the admin UI," but `promote()` was only reachable from the
   auto-failover loop; and (b) the **CP rolling-update path (`updateCPWithHA`) relied on the standby
   auto-promoting**, so with auto-failover off it would leave the cluster leaderless. Both are closed by
   one primitive: `HAState.PromoteManually()` (idempotent `promote()` guard so loop/manual/planned
   can't double-fire) + `POST /api/cluster/ha/promote` (RoleAdmin) + a UI "Promote to Leader" button
   shown for a standby. For the update path, the leader arms a **coordinated planned handoff**
   (`HAStateBundle.PromoteRequested`): the standby promotes on its next HASync pull — honored even when
   auto-failover is off, because a planned update is deliberate, not unattended. *Failback* (the old
   leader rejoining as standby) is unchanged — still the deferred 2-node-failback work, now at least
   detectable via the `/healthz` term.

Slice 1 is **mitigation, not a cure**: it makes the failure honest and recoverable, removes the unsafe
default, and gives operators/orchestrators a real (planned) promote path. It does not yet provide
*safe automatic* failover on unplanned leader loss — that is the mechanism decision.

### Open — the automatic-failover mechanism (decide deliberately, separate change)

| Option | Essence | Honest cost | New dependency |
|---|---|---|---|
| **Manual only (stop here)** | Keep Slice 1; operator promotes. | None beyond Slice 1. Loses *automatic* failover. | None |
| **Lease + witness** | Single-writer lease against one small witness (object-store/file/DNS lease, or a tiny 3rd voter); fencing token on every write. | Medium. One new component to run + secure. Simpler to reason about and strictly safer than hand-rolled quorum. | One witness |
| **Corrected DP-quorum** | DP-majority as witness, built to the review's full bar (fresh-heartbeat quorum, sub-second heartbeat, majority-acked term, gated issuance, documented LWW). | Large — a hand-rolled consensus core. No external dependency. | None (heavier heartbeat) |
| **Raft (≥3 CPs)** | `hashicorp/raft`; ClusterStore becomes an FSM. | Largest — multi-month, changes the persistence model, 3-node minimum. The only option that makes "enterprise HA" literally true. | Raft lib + 3rd CP |

**Maintainer decision (2026-06-30): Raft is SHELVED** — "I don't need 3CP now." Recorded as a
long-horizon roadmap option only, to be revisited if/when multi-CP consensus becomes a hard product
requirement. It is NOT the next step.

**Advisor recommendation for the remaining decision:** if/when *automatic* failover becomes a priority,
**lease + witness** is the path — and crucially it does **not** require a 3rd CP (the witness is a
small external lease target: an object-store/file/DNS lease, not a Culvert node), so it is fully
compatible with the "no 3CP" decision. Until then, **Slice 1's manual-by-default posture is the
resting state** and is safe for any topology. The choice between "rest at manual" and "build
lease+witness" stays the maintainer's; the corrected-DP-quorum option remains rejected on
cost/verifiability grounds (see §Rejected).

## Consequences

- **Positive:** the BLOCKER's *dangerous* behavior (silent split-brain, restart self-assert) is removed
  by Slice 1 with low risk; split-brain becomes observable; the product's HA claim can be stated
  honestly (active/passive with manual failover) instead of overstated. The expensive mechanism
  decision is de-risked by a written, reviewed cost analysis instead of being made implicitly in code.
- **Cost / behavior change:** default-manual failover means an unattended dead leader does **not**
  auto-promote until the operator acts (or a safe mechanism ships). This must be loud in the release
  notes, the GUI HA panel, and `docs/operator/`. Deployments relying on today's auto-promote must opt
  in with `--ha-auto-failover` and accept the documented split-brain risk until the mechanism lands.
- **Risk:** Slice 1 touches the HA boot path and the gRPC bundle (sensitive). Mitigated by the evidence
  test as a behavior backstop, `-race`, and the determinism gate; each sub-slice ships as its own
  validated commit.

## Alternatives considered

- **Do nothing / keep auto-promote.** Rejected: leaves a BLOCKER live with a known unsafe default and an
  overstated product claim.
- **Jump straight to Raft.** Rejected as the *next* step: disproportionate to the current need and a
  multi-month persistence-model change; recorded as the long-horizon option.
- **Ship hand-rolled DP-quorum as first scoped.** Rejected: the adversarial review (above) showed it
  narrows but does not close split-brain and adds data-loss/availability regressions; safe version costs
  as much as a lease with more failure surface.

## Decision needed from the maintainer (for the OPEN part)

Slice 1 has landed and Raft is shelved (maintainer, 2026-06-30 — "no 3CP now"). The remaining choice,
deferrable until automatic failover becomes a priority, is between **resting at manual failover** (the
current safe-by-default posture — a legitimate permanent answer for 2-CP HA) and **building
lease+witness** (automatic failover without a 3rd CP). Corrected-DP-quorum stays rejected. No further
HA code is required to be in a safe state today.
