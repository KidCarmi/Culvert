# MCP backend hardening run — 2026-08-24/25

**Scope:** the MCP Agent Security Gateway backend (`internal/mcp/**`, `internal/mcpacceptance/**`,
and the root `mcp_*.go` wiring). Frontend explicitly out of scope and untouched.
**Branch:** `claude/culvert-mcp-security-review-lzyhlf` · baseline `4c536b1`
**Predecessor:** `2026-08-24-mcp-backend-full-review.md` (15 findings, MCP-01…MCP-15)
**Method:** rounds of REVIEW → PROVE → FIX → TEST → RE-REVIEW. Every finding was
reproduced against the pre-fix tree before any patch was written, and every guard was
mutation-verified: the fix was reverted and the test required to fail.

> **Verdict is recorded in §8. It is not "Production Ready", and this document does not
> authorise enabling execution.**

---

## 1. What changed, and what deliberately did not

Guarded execution is **still disabled**, by the same three absences as at baseline, now
enforced by `mcp_execution_posture_test.go` (OVN-13). Nothing in this run enabled Shadow,
Canary or Production; nothing weakened TLS, OAuth, DPoP, mTLS, policy, durable-event or
four-eyes requirements; no protocol allowlist was widened and `2026-07-28` remains off.

## 2. Finding ledger

Severity: **P0** reachable today and security-relevant · **P1** reachable, correctness or
availability · **P2** latent / pre-activation · **P3** accuracy and maintainability.

| ID | Severity | Finding | State |
|---|---|---|---|
| OVN-01 | P1 | The DPoP concurrency bound was taken on requests that ran no DPoP verification, and was acquired *after* the auth slot — so the expensive path was ordered behind the cheap one. | Fixed `b2627cb` |
| OVN-02 | P2 | `pipeline.validateClaims` became dead once credential validation was unified; dead security code invites divergent re-use. | Removed `b61c8c4` |
| OVN-03 | P1 | The policy-snapshot read took a mutex on the request path. Replaced with `atomic.Pointer`, matching `internal/threatfeed` and the IP filter. | Fixed `d0631f4` |
| OVN-04 | P0 | An upstream redirect was constrained by **host only**. A redirect to a different **port** on the approved host was admitted, so the request reached an endpoint other than the one it named. | Fixed `7e24e05` |
| OVN-05 | P1 | `assurance` is documented as NIST AAL but is derived from the **sender binding**. Culvert never reads `amr`/`acr` and cannot observe AAL. | **OPEN — needs a product decision.** Additive part shipped (`58273ab`); see `docs/design/mcp/OPEN-DECISION-assurance-model.md` |
| OVN-06 | P1 | The credential was fully validated **twice** per request — the most expensive attacker-reachable operation, doubled. | Fixed `b61c8c4` |
| OVN-07 | P1 | HTTP/2 multiplexing let **one connection** occupy the whole worker pool: 36 requests from one socket sat in a shared queue behind a 4-worker pool. `http.Server.HTTP2.MaxConcurrentStreams` is silently ignored on the `ServeTLS` auto-h2 path — verified empirically; the first attempted fix was itself a no-op. | Fixed `2cdeb92` via a per-connection budget in `ConnContext` |
| OVN-08 | P1 | Server identity was resolved from the registry **before** authentication, so response behaviour distinguished a known from an unknown server id for an invalid credential — an enumeration oracle. | Fixed `e8550bf` |
| OVN-09 | P1 | A tool's fingerprint could change between the policy decision and execution (a "rug pull"); the decision was not re-checked at the execution boundary. | Fixed `4ccc0e8` |
| OVN-10 | P2 | Expired ALLOW_FOR_SESSION grants were reclaimed only on same-key lookup, so dead grants held slots until the 65536 cap refused every new allowance. | Fixed `3b94092` — **see §3, the first fix was wrong** |
| OVN-11 | P0 | The acceptance harness reported **overall PASS for a run in which a required criterion FAILED**. Requiredness was read from a per-call boolean duplicated at ~44 sites, while the canonical list gated only presence. | Fixed `d288892` |
| OVN-12 | P3 | On mTLS fixture failure the harness emitted an id (`tls.mtls`) in no canonical set, so the artifact reported two MISSING criteria instead of the control that failed. | Fixed `a1fd3af` |
| OVN-13 | P2 | Nothing enforced the disabled-execution posture; it rested on three absences no test observes. | Walled `3bc1c71` |
| OVN-14 | P2 | `parseECPublic` built an `ecdsa.PublicKey` from raw coordinates (Go 1.26 SA1019). Validation *was* present, but **no test pinned it** — removing the on-curve check kept the suite green. | Fixed + pinned `10b5abd` |
| OVN-15 | P3 | The upstream SSRF comment described `AllowPrivate` as scoped to "approved internal servers". It is client-wide: enabling it for one internal server disables private/loopback/metadata rejection for **every** registered server. | Comment corrected `54aa2a3`; per-target policy recorded as an absent design |
| DEBT-011 | P2 | Six of the previous review's fifteen findings were the same shape — a control designed, documented and unit-tested but never invoked. | Limits anti-drift wall `cb57a80` |
| RISK-026 | P1 | No per-source admission exists; `AdmissionBudget` has zero enforcement sites. | **OPEN.** ADR proposal written; knob recorded as `reserved` in the wall |
| OVN-16 | P2 | The `mcp_gateway_down` alert was evaluated only when something read `/healthz` — an alert that fires only when someone is already looking. | Fixed `a42fede` (30s poller, disabled-by-default) |
| RISK-027 | P1 | MCP had no `/healthz` field, no `/readyz` row and no metrics — a dead listener was invisible. | Closed `9be3445`, completed by `a42fede` |

### Refuted (investigated, no defect)

- **Cross-server upstream contamination.** Transports are built per call and closed after;
  TLS config, auth header and DNS pin are per call; there is no pin cache; per-server pools
  are correctly keyed. Server A cannot inherit server B's connection or identity.
- **`admittedMethods` unenforced.** It is enforced at `Client.Call`.
- **Upstream response id never compared to the request id.** One request per dedicated
  pinned-TLS connection, so HTTP itself provides correlation; a hostile upstream can echo
  any id regardless. Defence-in-depth only, not a defect.
- **`Apply` can reject after its durable persist (steps 8–9).** Both post-persist failure
  branches re-check conditions already checked at steps 2 and 4b under the same mutex, and
  the ratchet has no other mutator. Unreachable; defensive duplication, not a hole.
- **Execution-dependency gate implemented only in the coordinator.** It is enforced inside
  `commitRolloutTransition` under `durableMu`; the coordinator's check is genuine
  defence-in-depth that avoids staging distribution state.

## 3. Two mistakes made during this run, and what they cost

Recording these because a review that only lists other people's defects is not a review.

**The first OVN-10 fix was wrong and would have weakened a control.** I gave ALLOW_ONCE
records a TTL, reasoning that the allowance key is session-scoped. It is not:
`identity.ResolvedContext.Fingerprint` is a stable hash over capability, tenant, subject,
client, agent, resource, server and tool, with no time, session id or nonce. The same
principal invoking the same tool yields the same key for the life of the deployment, so an
expiring ALLOW_ONCE record is not garbage collection — it is a replay window, silently
redefining single-use as once-per-8-hours. Caught by checking my own premise before
committing. The shipped fix reclaims only expired **session** grants, which is provably
behaviour-neutral because `consume` already treats them as absent. The reasoning is now a
test (`TestAllowance_OnceGrantsNeverBecomeReplayable`) rather than a comment.

**The criterion-id wall had a blind spot, found by mutation, not by review.** It read
`runCriterion` arguments and `CriterionResult` literals, missing table-driven emission —
which is how the oauth, tenant and protocol scenarios name their criteria. An orphan id
substituted into such a table passed the wall. The first scoping attempt then used a flag
set on entering an emitting function and never cleared, so every later table in the file
counted as emitted; it passed only because the file that would have exposed it happens to
contain no emitting functions. Both are fixed and both directions are now pinned
(`emitted ⊆ classified` and `classified ⊆ emitted`).

**A mutation sweep reported two false SURVIVED verdicts, and following them would have
weakened a correct control.** Sweeping mutations across this review's own fixes, two came
back "no test caught this": the OVN-07 per-connection budget and the duplicate-security-header
rejection. Both were wrong, and for the same reason — the mutation did not change behaviour.

For OVN-07 the mutation rewrote `if relConn, ok := acquireConnBudget(ctx); ok` into
`ok || true`. But a request that cannot get a slot *blocks inside* `acquireConnBudget` on the
semaphore; it only returns `false` when the context is done. So the altered branch was never
reached and the mutant was semantically identical to the original. Replacing it with a real
bypass — substituting a function that always grants — immediately produced
`peak_queued=36` against a 4-worker pool and failed the test with its intended message. The
control works and the test is a genuine gate.

The lesson is about the harness, not the code: **a mutation must be shown to change behaviour
before "survived" means anything.** A sweep that skips that step manufactures phantom gaps in
exactly the places a reviewer is most likely to act on them — the natural next step from
"survived" is to strengthen the test, and the step after that is to conclude the control is
not doing anything. Diagnosing this one also corrected a second error of mine: I had read
`len(bk.entered)` as evidence of concurrency when it is sampled *after* the fixture is
released, so it measures nothing.

## 4. Verification

Exit codes captured directly from `go test`, never inferred from piped or truncated output.

| Check | Result |
|---|---|
| `go build ./...` | PASS |
| `go vet ./internal/mcp/... .` | PASS (exit 0) |
| `go test ./internal/mcp/... -count=1` | PASS (exit 0, 38 packages) |
| `go test . -count=1` | PASS (exit 0) |
| `go test ./internal/mcpacceptance/... ./cmd/... -count=1` | PASS (exit 0) |
| Fuzz sweep, 18 targets × 60s | PASS (all exit 0, no corpus entries written) |
| `staticcheck ./internal/mcp/... ./internal/mcpacceptance/...` | PASS (exit 0, clean) |
| `golangci-lint` | **NOT AVAILABLE** — installed binary is built with go1.25 and panics on this go1.26 module. Not remedied: changing the toolchain to satisfy a scanner was out of scope. |
| `govulncheck` | **NOT AVAILABLE** — installs and builds against go1.26, but `vuln.go.dev` is blocked by the environment's network policy (403 at the proxy). No local database available. |
| `gosec`, `gitleaks`, `trivy` | **NOT AVAILABLE** — not installed in this environment. |
| Mutation sweep over this review's controls | PASS — OVN-04, OVN-07, OVN-09 and the duplicate-header rejection each fail their own test under a *behaviour-changing* mutation (see above). |
| `go test -race ./internal/mcp/... ./internal/mcpacceptance/...` | PASS (exit 0) |
| `go test -race -shuffle=on ./internal/mcp/...` | PASS (exit 0) |
| `go test -race .` (root) | PASS (exit 0) |
| `go test -shuffle=on .` (root) | PASS (exit 0) |

Fuzz targets exercised: jsonrpc decode; authn JWT / claims / introspection; JOSE JWK parse;
runtime pipeline, credential parse and transport method; protocol negotiation; policy
compile, evaluate and glob; rollout signed-config decode; destination canonicalize and
redirect; catalog ingest; DLP scan; schema compile.

## 5. Execution posture at end of run

| Property | State | Enforced by |
|---|---|---|
| `markGatewayExecDepsReady` called in production | NO | `TestExecPosture_ArmingHooksHaveNoProductionCaller` |
| `markManagementExecDepsReady` called in production | NO | same |
| `runtime.Deps.Executor` assigned in production | NO | `TestExecPosture_NoProductionExecutorAssignment` |
| `internal/mcp/execution` imported by production | NO | `TestExecPosture_ExecutionPackageHasNoProductionImporter` |
| Shadow / Canary / Production reachable | NO — fails closed at `commitRolloutTransition` | existing rollout tests |
| MCP protocol `2026-07-28` | NOT enabled | unchanged |

## 6. Still open, deliberately

- **RISK-026 — per-source admission.** Every keying strategy is right for one deployment
  topology and wrong for another, and the product does not currently declare its MCP
  topology. Implementation-ready proposal in
  `docs/design/mcp/ADR-PROPOSAL-mcp-admission-fairness.md`. Needs an architecture decision.
- **OVN-05 — the assurance semantic model.** Redefining `assurance` as AAL is the correct
  end state and would hard-deny every write operation in every deployment on the day it
  lands, because nothing supplies `amr`/`acr` and `engine.go` denies `Unknown`. Needs a
  product decision on migration. See `docs/design/mcp/OPEN-DECISION-assurance-model.md`.
- **Per-target upstream destination policy** (OVN-15). Absent by design today; supporting a
  genuinely internal MCP server needs one.

## 7. What this run did not cover

- The frontend, by instruction.
- Live behaviour against real MCP servers: no real upstream was contacted and no side
  effect was performed.
- The execution plane under actual execution — it cannot be exercised without arming it,
  which was forbidden and remains forbidden.
- `golangci-lint`, `govulncheck`, `gosec`, `gitleaks`, `trivy` — see §4.

## 8. Verdict

**OBSERVE READY — with two open decisions.**

The Observe-mode backend is materially stronger than at baseline: an enumeration oracle, a
redirect-scope escape, an HTTP/2 admission amplification, a decision rug-pull and a
double-validation are closed; the capability is now visible to fleet monitoring; and the
acceptance harness no longer has a path to certifying a run it watched fail — which
matters more than any single fix, because that harness is what an operator would have
trusted.

It is **NOT** ready for Shadow activation. That is a separate review with its own
prerequisites, none of which this run performed or could perform: composed guarded
execution and credential containment, a stable host, real scope, parity evidence,
monitoring, ownership and fresh identity. RISK-026 in particular should be settled before
any mode that performs real upstream work, because pre-authentication admission is the
control that decides who can make the gateway do that work at all.

This document does not authorise enabling execution.
