# HA Leader-Reachability Classification (PR-2 / findings A3, A8)

**Status:** implemented in `ha.go` on branch `claude/decision-integrity-pr2-ha-reachability` (Draft PR #838).
**Owner decisions:** ADR-0012 §6.2 #1–#5 (ratified 2026-07-18).
**Review basis:** four-reviewer adversarial panel (HA/distributed, networking/TLS/gRPC, concurrency, security).

## Invariant

> A standby may **automatically promote** only on **positive, attributed evidence** that the leader is
> unreachable per the failure detector. A local inability to validate, persist, decrypt, authenticate, or
> apply leader state — and any error whose origin cannot be confidently attributed to leader
> unavailability — is **never** such evidence. Ambiguous failures **hold**; proven reachability **resets**;
> proven unreachability **advances**.

## Why a status code is not enough

gRPC collapses genuinely different root causes into one `codes.Unavailable`. Empirically (grpc v1.82.0):

| root cause | gRPC code |
|---|---|
| connection refused / TCP reset | `Unavailable` |
| DNS / name-resolution failure | `Unavailable` |
| TLS unknown-authority / expired-server-cert / hostname-mismatch / mTLS-reject (**leader alive**) | `Unavailable` |
| TCP blackhole / slow leader | `DeadlineExceeded` |

So `Unavailable` cannot separate a **down leader** from a **live leader we failed to reach for TLS/cert/DNS
reasons**, and `DeadlineExceeded` cannot separate a **dead** leader from a **slow-but-alive** one.
Scraping the error `desc` string to disambiguate is explicitly rejected (owner #5). Therefore **no gRPC
status code alone yields `LeaderUnreachableProven`.**

## Typed outcomes (`reachabilityOutcome`)

`classifyLeaderReachability` (+ `syncFromLeader`, + the local preflight) produce one of:

- **`LeaderReachable`** — sync succeeded; leader alive → **reset**.
- **`RemoteRejected`** — leader answered but rejected/failed the call (app error, malformed/epoch-stale
  bundle). Leader alive → **reset**. (Integrity signal, never availability — a leader serving untrusted
  state is *reachable*, not unreachable.)
- **`LocalFailure`** — local TLS preflight / client construction / disk / decrypt fault → **hold + warn**.
- **`Ambiguous`** — `Unavailable`, `DeadlineExceeded`, `Unknown`, `Internal`, `Canceled`, … → **mode-aware**
  (below). This is where the un-attributable transport/TLS/DNS/timeout cases land.
- **`LeaderUnreachableProven`** — positive attributed transport-loss proof → **advance**. **Not currently
  produced** (see "Deferred").

## Mode-aware policy (`stepStreak`) — legacy vs fenced are deliberately separate (owner #3)

| outcome | Legacy / unfenced (no lease) | Fenced (lease configured) |
|---|---|---|
| `LeaderReachable` / `RemoteRejected` | reset | reset |
| `LocalFailure` | hold + warn | hold + warn |
| `Ambiguous` | **hold + warn (fail-safe)** | **advance the streak** (candidate only) |
| `LeaderUnreachableProven` | advance | advance |

- **Legacy** has no external arbiter, so an un-attributable failure must **hold** — it cannot safely
  auto-promote on ambiguous evidence. Consequence: **legacy auto-failover no longer auto-promotes on a
  gRPC transport error** (all such errors are `Ambiguous`). Genuine leader death in legacy mode now
  requires **operator action** (a latched `ha_ambiguous_leader_error` alert asks for it) or **lease-fenced
  mode**. This is the owner-mandated fail-safe (ADR-0012 §6.2 #1); it is a deliberate behavior change from
  the prior "advance on `Unavailable`/`DeadlineExceeded`".
- **Fenced** may advance on `Ambiguous` because the **lease is the final authority**: `onMaxFail` →
  `leaseAutoPromote` → `acquireLeaseForLeadership` is denied while the leader holds the lease and fails
  closed on transport error. A false-unreachable therefore cannot cause a second leader. Verified:
  `TestFenced_AmbiguousCannotBypassHeldLease`.

## Local TLS preflight (owner #4)

`preflightLocalTLS` deterministically validates local material **before** any RPC failure is used as
evidence: cert/key readable & matching (via `loadDPNodeKeyPair`), leaf currently valid (NotBefore/NotAfter),
trust roots parse. A failure is a **`LocalFailure`** (hold + warn, client dropped for rebuild after repair).
A **success does not** prove the remote handshake will succeed — it only removes local material as a cause.

## Deferred (documented, NOT built — a redesign, not a patch)

Positively re-enabling legacy auto-promotion (distinguishing genuine transport loss from TLS/cert/DNS
`Unavailable`) requires **lower-layer evidence** — a layered probe: local-prereq → DNS → TCP dial → TLS
handshake → gRPC → auth → protocol, emitting the typed outcomes above. Reviewer B classified this as a
redesign; per owner guidance ("document rather than silently expand"), it is **not** implemented here.
`outcomeLeaderUnreachableProven` is the reserved seam for it. **Owner-gated**: it also carries a security
nuance (an on-path attacker forging TCP RSTs could forge "unreachable" to force a legacy promotion), so
legacy auto-failover should remain gated behind the fence/witness regardless.

## Out of scope for PR-2 (recorded from the panel; not addressed here)

- **Asymmetric partition / no-witness** (Reviewer A/C): a 2-node no-lease cluster cannot safely arbitrate
  from standby-local evidence — needs an external witness / quorum. Legacy auto-failover remains
  documented-unsafe-without-witness (RISK-001).
- **`verifyBundleEpoch` is anti-replay, not anti-forgery** (Reviewer D2): bearer-token + monotonic epoch
  floor; a MITM with a cluster-CA-trusted cert could serve a forged high-epoch bundle. Pre-existing
  auth-model property; not a PR-2 regression.
- **`buildClientTLS` empty `caFile` → system roots** (D3) and **`seedTermFromLeader` term-wrap** (D4):
  pre-existing, config-dependent / legacy-monitoring-signal.
- **Legacy `onMaxFail` returns true on a failed `promote()`** (Reviewer C2) and **no second-loop guard**
  (C3): pre-existing state-machine follow-ups, outside the A3/A8 change.
