# MCP Shadow-Readiness — Current Composition & Reachability Matrix

**Phase:** Culvert MCP — Shadow Activation Architecture & Readiness
**Baseline:** merged `main` HEAD `0f5cc1f` (PR #1224 merge commit). Branch `claude/mcp-shadow-readiness`.
**Status of this document:** GROUND TRUTH for the rest of the phase. Every row was
re-derived from the merged tree (not carried over from the #1224 report) and the
load-bearing rows (side-effect boundary, "no executor composed", Shadow disposition)
were independently re-read at the cited lines.

This matrix is the answer to Phase task 2. The two facts that drive the whole phase:

1. **The default production posture is inert.** With no MCP YAML and no
   `CULVERT_MCP_DISTRIBUTION_TRUST_KEYS`, nothing binds, no applier composes, CP
   publication is orphaned, the health plane emits nothing, and the Secure Web
   Gateway request path is byte-identical to a build without MCP.
2. **Shadow is currently "a live executor told to execute."** `resolveShadow`
   (`internal/mcp/rollout/resolve.go:143`) emits `EffectExecute` — the *same*
   disposition as Canary/Production — which dispatches into the *same* `runExecute`
   upstream path. Shadow is gated off today ONLY by (a) the executor never being
   composed in production and (b) the transition-time `execDepsConfigured` gate.
   There is **no request-time "Shadow cannot execute" branch.** This is precisely
   the anti-pattern this phase must replace with capability separation.

---

## Legend

- **Prod-composed** — wired in the shipped `main.go` startup path (not just tests).
- **Reachable (default)** — can a real request/RPC reach it in the *default* posture
  (no MCP YAML, no trust-keys env). "No" ⇒ requires explicit operator opt-in.
- **Side-effect** — can it cause an irreversible *external* effect (network egress,
  secret materialization, durable evidence).
- **Guard** — what stops it.
- **Fail** — failure semantics.

---

## Matrix

### Data plane

| Component | Compiled | Constructed | Prod-composed | Reachable (default) | Side-effect | Guard | Persisted | Fail | Operator-visible |
|---|---|---|---|---|---|---|---|---|---|
| **Gateway listener** | yes | `newListener` in `runtime.go:60` | yes, YAML `mcp.gateway.enabled` (default **off**) | **No** (no socket bound) | **No** (Observe: no executor/upstream/broker/inspection) | YAML gate + fail-closed prereqs: TLS cert/key, client-CA, ≥1 trusted JWKS key, non-empty scopes | none | fail-closed; enabled-but-invalid ⇒ nothing binds; never blocks SWG startup | `/api/mcp/health`, `/healthz`, `/readyz`, `culvert_mcp_gateway_*` |
| **Management listener** | yes (same type) | only if `cfg.Management.Enabled` (tests only) | **No** — never populated in any prod path | No | N/A | compile-time absence | none | N/A | fixed `disabled` state |
| **readiness/health plane** | yes | package-level, latch `mcpAlertState` | yes, always wired, self-suppressing | yes (unauth `/healthz`,`/readyz`,`/metrics`) | only `mcp_gateway_down` webhook (subscriber-gated) | `Configured` gate; `HasSubscriber`; fixed closed-set detail strings | none (in-mem latch) | **report-only; never an SWG SPOF** (`/readyz` row never sets `allOK`) | this *is* the operator surface |

### Decision providers (read-only / plan-only; the pre-side-effect pipeline)

| Component | Compiled | Prod-composed | Reachable (default) | Side-effect | Guard | Persisted | Fail |
|---|---|---|---|---|---|---|---|
| **Policy provider** | yes | yes, only if `qualification_policy_file` set | No | No (pure decision; ALLOW ⇒ `execution_state=not_implemented`) | fail-closed compose; Gateway-only | in-mem snapshot | missing snapshot ⇒ **deny** |
| **Event provider** | yes | yes, only if telemetry configured | No | **Yes — the one durable-evidence writer** (encrypted spool + local archive, **no network**) | commit-before-response (ALLOW-class); redaction backstop; KEK-encrypted | encrypted spool + archive under `DataDir` (0600/0700) | critical commit fail ⇒ **block**; ordinary ⇒ degraded |
| **Registry** | yes | yes (when gateway enabled, usually empty) | No | No (in-mem copy-on-write) | mutex; pre-auth oracle avoidance | none | unknown server ⇒ deny (post-auth) |
| **Catalog** | yes | yes (when gateway enabled, empty) | No | No (in-mem CAS) | sticky-quarantine floor | none | drift ⇒ `DecisionSnapshotStale` |
| **Inspection** | yes | **No** — never composed (test-only) | No | No (decision-only; optional bounded DNS read) | N/A (unwired) | none | hard-fail blocks (test path) |

### Execution plane (side-effect capable; **dark in production**)

| Component | Compiled | Prod-composed | Reachable (default) | Side-effect | Guard | Persisted | Fail |
|---|---|---|---|---|---|---|---|
| **Executor** | yes | **No** — `Deps.Executor` nil; every assignment test-only; AST posture wall | No | **Yes** — drives upstream call + credential materialization | rollout resolution + kill switch (checked first) + `execDepsConfigured` gate + posture wall | in-mem allowance | fail-closed → `blocked(...)` |
| **Upstream client** | yes | **No** — `upstreamclient.New` test-only | No | **Yes — real HTTPS egress** (`transport.go:112` `client.Do`) | method allowlist; endpoint from registered record; SSRF + pinned-IP dial + TLS identity pin; idempotent-only retry | none | fail-closed, sanitized errors |
| **Credential broker** | yes | **No** — `broker.New` test-only | No | **Yes — materializes real secret** (no network itself) | **two-phase `Plan` (metadata-only) vs `Materialize` (secret)**; mandatory `PreMaterializationGate`; power ceiling | encrypted-envelope cache | fail-closed; provider errors sanitized |

### Rollout & distribution

| Component | Compiled | Prod-composed | Reachable (default) | Side-effect | Guard | Persisted | Fail |
|---|---|---|---|---|---|---|---|
| **rollout coordinator** | yes | yes (disabled-by-default) | restore-only | No | `execDepsConfigured` gate at 4 points | per-cap 0600 JSON under `DataDir` | fail-closed to Disabled |
| **kill switch** | yes | yes | yes (admin/emergency) | No | checked **first** in `Execute`; **NOT re-checked at the `run.go` irreversible boundary** (gap — see architecture doc) | durable in `StatePersist` | in-mem disable always in effect |
| **Shadow** | yes (resolver) | No (unreachable) | No | **Would execute** — `resolveShadow`→`EffectExecute`→`runExecute` | transition-time `execDepsConfigured` only (no request-time gate) | durable mode | — |
| **Canary** | yes (resolver) | No | No | Would execute | `execDepsConfigured` | durable | — |
| **Production** | yes (resolver) | No | No | Would execute | `execDepsConfigured` **+** unobtainable `ProductionQualificationVerifier` receipt (no in-tree issuer) | durable | — |
| **CP→DP distribution (DP-apply)** | yes | yes, env `CULVERT_MCP_DISTRIBUTION_TRUST_KEYS` (default **off**) | No | node-local durable state + coupled rollout commit (no external effect) | ed25519 sig + epoch + revision + min-DP-version + bounds; executing-mode precheck needs exec deps | `<dataDir>/mcp_distribution/` | fail-closed; empty/invalid ⇒ no applier |
| **CP→DP distribution (CP-publish)** | yes | **No** — orphaned (`setCPPublished` no prod caller) | No | N/A | N/A | N/A | `distribution_state = local_only` |

---

## The side-effect boundary (Phase task 6 — the crux)

All irreversible external effects funnel through the executor, which is **not
composed in production**. Within it, the boundary is precise:

- **Network egress:** `internal/mcp/execution/run.go:71` —
  `e.cfg.Upstream.Call(ctx, target, in.Method, ...)`. The concrete syscall-level
  line is `internal/mcp/upstreamclient/transport.go:112` (`client.Do(req)`).
- **Credential materialization (secret):** `internal/mcp/credentials/broker/materialize.go`
  (`Materialize` → provider fetch / cache decrypt). The broker's `Plan()` is
  metadata-only and touches no secret.

Both are reached ONLY inside a mandatory durable-commit callback
(`run.go:92` `Events.CommitThenAct`), and the network call is preceded by a
last-moment tool-drift re-check (`run.go:67-70`). Everything above `run.go:71` is
planning / validation / evidence; `run.go:71` is where the side effect begins.

**Everything a Shadow evaluation legitimately needs sits ABOVE this line:**
authentication, sender-binding verification, identity, registry/catalog validation,
policy, approval/allowance, credential **Plan** (not Materialize), inspection
**plan**, and the durable decision commit. Only `run.go:71` and `Materialize` are
below it. This is why a capability-separated Shadow is achievable: give the Shadow
runtime everything above the line and none of the two objects (`Upstream`,
`Broker.Materialize`) below it.

---

## What is already true and load-bearing for Shadow readiness

- **The decision pipeline is a distinct, side-effect-free plane** consumed via
  read-only / plan-only seams (`PolicyProvider`, `InspectionProvider`, registry/catalog
  reads, `EventProvider.WriteAllowedCritical` readiness probe, broker `Plan`).
- **The side-effect capability is isolated in a single optional dependency**
  (`runtime.Deps.Executor`, an `ExecutionProvider`), nil-by-default, enforced by the
  `mcp_execution_posture_test.go` AST wall (no prod assignment; nothing outside
  `internal/mcp/execution` imports it; arming hooks uncalled).
- **The credential broker already separates Plan from Materialize** — the exact seam
  Shadow needs to check readiness without possessing a secret.
- **The event provider already writes durable, redacted, KEK-encrypted evidence** —
  the substrate for Shadow evidence.

## What is NOT yet true (the phase's work)

- **Shadow shares the `EffectExecute` disposition and `runExecute` path with the
  enforcing modes.** A composed executor in Shadow mode WOULD cross `run.go:71`.
  → Phase task 5/7/15: give Shadow its own non-executing disposition and, ultimately,
  a runtime that does not possess `Upstream`/`Materialize` at all.
- **The kill switch is not re-checked at the irreversible boundary** (`run.go`
  `callUpstream`), only once at the top of `Execute`.
  → Phase task 12: re-check authoritative execution state at the boundary.
- **`assurance` conflates sender-binding strength with authentication assurance**
  (OVN-05) — see `docs/adr/0032-mcp-assurance-authn-vs-sender-binding.md`.
- **Admission is coarse and pre-auth only** (RISK-026) — no per-source / per-principal
  fairness. See `docs/adr/0033-mcp-admission-fairness.md`.
</content>
