# Preserved source: Cluster And Ha

Historical evidence from main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, not current architectural authority.
Read the [current task routes](../README.md) and [verified errata](../errata.md) first.
No benchmark, status, location or instruction in these blocks is independently revalidated by moving it here.
Links inside preserved text retain their original spelling and source-root context; use each pinned source link to follow original references.
Do not import this file into startup instructions.

## Topics

- [Node groups](#claude-main-l251-l251)
- [Bandwidth/QoS](#claude-main-l252-l252)
- [ConfigSnapshot sync](#claude-main-l253-l253)
- [Cluster gaps](#claude-main-l254-l254)
- [HA fencing lease (ADR-0005 — PROGRAM COMPLETE S0–S5, closes RISK-001)](#claude-main-l255-l255)
- [The fencing lease has a way BACK (CHAOS-55, `ha_lease_recovery.go`)](#claude-main-l256-l256)

<a id="claude-main-l251-l251"></a>

## Node groups

[Original lines 251–251](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L251-L251) · `claude-main-L251-L251`

<!-- BEGIN preserved-block: claude-main-L251-L251 -->
- **Node groups**: Label selectors (`map[string]string`) for matching enrolled nodes; auto GeoIP labels (`geo:country`, `geo:country_name`) assigned on enrollment/heartbeat
<!-- END preserved-block: claude-main-L251-L251 -->

<a id="claude-main-l252-l252"></a>

## Bandwidth/QoS

[Original lines 252–252](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L252-L252) · `claude-main-L252-L252`

<!-- BEGIN preserved-block: claude-main-L252-L252 -->
- **Bandwidth/QoS**: Token bucket rate limiting per node group, configurable rates (KB/s, MB/s, GB/s), stored in `/data/bandwidth_policies.json`
<!-- END preserved-block: claude-main-L252-L252 -->

<a id="claude-main-l253-l253"></a>

## ConfigSnapshot sync

[Original lines 253–253](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L253-L253) · `claude-main-L253-L253`

<!-- BEGIN preserved-block: claude-main-L253-L253 -->
- **ConfigSnapshot sync**: CP pushes `ConfigSnapshot` to DP nodes containing policy rules, blocklist, PAC exclusions, threat feed data, session HMAC, bandwidth policies, and node groups
<!-- END preserved-block: claude-main-L253-L253 -->

<a id="claude-main-l254-l254"></a>

## Cluster gaps

[Original lines 254–254](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L254-L254) · `claude-main-L254-L254`

<!-- BEGIN preserved-block: claude-main-L254-L254 -->
- **Cluster gaps**: All 8 items from CLUSTER-GAPS.md implemented: PAC sync, rolling upgrades, config versioning, geo-aware grouping, bandwidth/QoS, secrets sync, threat feed sync, config diff
<!-- END preserved-block: claude-main-L254-L254 -->

<a id="claude-main-l255-l255"></a>

## HA fencing lease (ADR-0005 — PROGRAM COMPLETE S0–S5, closes RISK-001)

[Original lines 255–255](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L255-L255) · `claude-main-L255-L255`

<!-- BEGIN preserved-block: claude-main-L255-L255 -->
- **HA fencing lease (ADR-0005 — PROGRAM COMPLETE S0–S5, closes RISK-001)**: `-ha-etcd-endpoints`/`-ha-etcd-cert`/`-ha-etcd-key`/`-ha-etcd-ca`/`-ha-lease-ttl` (or `cluster.etcd_*`/`lease_ttl_seconds` YAML; read once at startup) arm an etcd fencing lease (`internal/halease`; key `/culvert/ha/leader`, epoch = `create_revision`) via `armHALease` BEFORE any role branch — malformed lease config is FATAL, unreachable etcd = lazily denied leadership (fail-closed). Layers: `ha_lease.go` (S2 — Acquire-gated promotion, keepalive with etcd-as-clock, `selfFence`, `WriteAllowed()`, term = epoch), `ha_fencing.go` (S3 — per-RPC issuance gate, puller-side bundle-epoch verify incl. no-live-holder reject, DP `dpLastSeenEpoch` CAS ratchet), `ha_failover.go` (S4/S5 — `leaseAutoPromote` hysteresis 30s → freshness 10m → Acquire; `enterStandbyResync` demote-and-resync; `acquireLeaseForResume` ghost-lease wait ≤45s for fast leader restarts). In lease mode `--ha-auto-failover` is IGNORED (fence arbitrates; manual promote bypasses freshness/hysteresis as break-glass); nil provider = legacy ADR-0004 byte-identical. `/healthz` + `/api/cluster/ha` expose `lease_mode`/`lease_valid`/`epoch`; the HA panel's Fencing Lease card is STATUS-ONLY (endpoints are startup-scoped — recorded GUI-parity deferral). Compose: profile-gated `etcd` witness (`--profile ha`, LAB ONLY — production wants a third machine + TLS). Bounded-LWW window (≤TTL) on partition is the documented F4 posture. Runbook: `docs/operator/ha-lease-failover.md`. **The way BACK from an unfenced leader is CHAOS-55 (`ha_lease_recovery.go`)** — see the next bullet.
<!-- END preserved-block: claude-main-L255-L255 -->

<a id="claude-main-l256-l256"></a>

## The fencing lease has a way BACK (CHAOS-55, `ha_lease_recovery.go`)

[Original lines 256–256](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L256-L256) · `claude-main-L256-L256`

<!-- BEGIN preserved-block: claude-main-L256-L256 -->
- **The fencing lease has a way BACK (CHAOS-55, `ha_lease_recovery.go`)**: ADR-0005 has three exits from write authority (denied on promotion, denied on resume, self-fenced by the keepalive) and shipped a return path for exactly one. The other two dead-ended, and the mechanism is one sentence twice: **an unknown was treated as a decision.** `ha_lease.go`'s header states the rule for the other direction — *"leadership cannot be taken while the fence's state is unknown"* — and the promotion path obeys it exactly; the resume path broke it in reverse. **(1) HA-7:** `acquireLeaseForResume`'s 45 s budget (`haResumeGhostWait`) was spent ONLY on waiting out this node's own ghost lease, and a transport error returned false on the FIRST attempt — so the fault that actually happens, **boot ordering** (a host reboot starts culvert and etcd concurrently; seconds of `connection refused` is enough), got zero retries. `ResumeAsLeader` then asserted `role=leader, leaseEpoch=0`, and because `startLeaseKeepalive` no-ops on a zero epoch, NOTHING in the process ever called `Acquire` again: no issuance, no revocation sync, no snapshot a DP would accept, and `PromoteManually` refuses a node already roled `leader`, so a human restart was the ONLY lever. **(2) HA-16, worse:** with a recorded `standbyAddr`, ANY failed resume demoted to standby — including an unreachable backend. In a 2-node cluster restarting together the guess is symmetric: each stands by against the other, neither can sync (`verifyBundleEpoch` rejects a bundle with no live holder), `lastSyncOK` stays zero, and `leaseAutoPromote`'s freshness gate then refuses every promotion — **a permanently leaderless cluster from a few seconds of etcd being slow to boot.** Four rules now hold. **(a)** `resumeAcquireRound` classifies each round (`granted`/`foreign`/`ownGhost`/`unknown`/`raceRetryable`) and the resume retries the retryable ones — this alone covers the boot-order case with no read-only window — but under its OWN budget `haResumeUnreachableWait` (5s), NOT the ghost path's 45s: `ResumeAsLeader` runs inside `initCluster`, which `main.go` orders BEFORE the root CA, the policy engine, the proxy listener and the admin UI, so blocking here is time the DATA PLANE is not serving, and the fence governs control-plane writes only. Reusing the 45s budget would have traded a CP write outage for a data-path outage; anything longer is the background loop's job, which costs the boot nothing (pinned from both ends). **(b)** A longer outage arms a background re-acquire loop, bounded in RATE and never in ATTEMPTS (1 s→30 s, ±20% jitter — a fleet restarts together, so a fixed cadence aims a synchronised herd at the recovering etcd, the WK-13 shape). That does not violate "avoid infinite retries" for CHAOS-54's reason: the retry is never silent (first failure immediately, then ≤1 line/60 s, then a recovery line naming the suppressed count; magnitude in a counter), and the sleep is INTERRUPTIBLE so `Stop` never waits out a backoff. **(c) ONE ATOMIC ACQUIRE decides, and an AFFIRMATIVE foreign holder is LATCHED.** `Provider.Acquire` is a single transaction: it cannot succeed while anyone else holds the lease, and when it denies it reports the holder it saw. So a grant IS proof the fence was free and a denial carries the evidence — `acquireLeaseAttempt` surfaces that Status (the bool wrapper discarded it, which forced a second `Read` whose window let a foreign holder expire between the two calls and read back as free; Codex review of PR #1223). Quietly retrying until a live peer DIES and then taking over would make a node of unknown state age authoritative, which is precisely `haPromoteFreshnessWindow`'s judgement, so recovery routes to it rather than around it: an observed foreign holder is LATCHED (loop exits, this process never acquires again) and its disposition MIRRORS the shipped S4/S2 decision — resync from the recorded ex-standby, else keep the read-only leader role + CRITICAL alert. **The poll interval is capped BELOW the lease TTL (`recoveryPollCeiling`) and that is a CORRECTNESS bound, not tuning:** a free lease proves nobody holds it now, not that nobody held it since we last looked, and etcd keeps a holder's key for ≥1 TTL after it stops renewing — so looking at least once per TTL makes a completed-and-vanished peer tenure impossible to miss between two SUCCESSFUL observations (HA-19; the residual blind-partition case is recorded for an owner, and the shipped resume path already shares it). **(d) Panic containment lands the OPPOSITE way from `leaseRenewRound`**, and the contrast is the point: containing a keepalive panic is dangerous because it would extend authority the node is no longer confirming (CHAOS-24), whereas here there is NO authority to extend, so containing and backing off is strictly fail-closed. Observability closes HA-17 (an unfenced leader emitted `culvert_ha_role 1`, byte-identical to a healthy one, on the only surface a Prometheus rule can read): `culvert_ha_{write_authority,lease_epoch,unfenced,lease_recovering,lease_reacquire_attempts_total,lease_reacquired_total}`, emitted ONLY when a fence is armed (CHAOS-54's rule — a `0` on a node that never had a lease is indistinguishable from a fenced-out one), plus `lease_recovering` on `/healthz` + `/api/cluster/ha`. **`culvert_ha_unfenced` is deliberately NOT `!WriteAllowed()`** — a standby has none either and that is healthy; it fires only for a node that believes it is the leader and cannot write. The alertable pair is `unfenced=1 AND recovering=0`: read-only and no longer trying. Deliberately left: **HA-18** (a self-fenced ex-leader with no recorded ex-standby stays a passive standby — re-acquiring from `role=standby` is a PROMOTION whose freshness gate is keyed on `lastSyncOK`, structurally wrong for a node that does not sync; an owner posture decision, recorded not fixed), and the note that `WriteAllowed()` is silently false whenever `leaseValidFor ≤ haLeaseWriteMargin` (the CONFIG path is floored at `haLeaseMinTTLSec` 3 s and fatal below, but the value trusted at runtime comes from the BACKEND — now detectable as `write_authority 0` with a non-zero `lease_epoch`). Gates: `ha_lease_recovery_chaos_test.go` (18); every DEFECT gate was verified failing against the pre-fix tree (the arming/latching/jitter gates pin new behaviour and have no pre-fix counterpart). See `roadmap/CHAOS-ENGINEERING-REVIEW.md` §23 and `docs/operator/ha-lease-recovery.md`.
<!-- END preserved-block: claude-main-L256-L256 -->
