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
| OVN-17 | P2 | The OVN-09 fix refused a drifted tool at the executor's **entry**, not at the side effect. Durable commit, credential planning and provider fetch all run in between, so a catalog ingest landing there still reached the upstream call under a stale decision. | Fixed `e000f2f` — re-checked at `callUpstream`, the single chokepoint both branches route through |
| OVN-18 | P2 | `authFailures` was charged for **all five** guarded singleton headers. Duplicating `Origin`, `Mcp-Session-Id` or `Mcp-Protocol-Version` — ordinary protocol traffic — was indistinguishable from a credential attack on `culvert_mcp_auth_failures_total`. | Fixed `3806803` — split onto `culvert_mcp_ambiguous_header_total`; the durable denial record is still written for every one |
| OVN-19 | P2 | `culvert_mcp_requests_total` was incremented only inside `pipeline.Process`, while three transport-level branches reject before it. Under overload `requestsRejected` could **exceed** the total, so the rejection rate derived from the pair is not a rate. | Fixed `3806803` — counted at the transport entrypoint |
| CI-01 | P2 | The root package's `-race` + coverage run sits ON its 15m per-binary budget: `origin/main` clears it by **2.1s (0.23%)**, less than the suite's own run-to-run variance. This branch's five touched root test files cost 4.7s in total, which tips it. Not a defect in either tree; a required check running at coin-flip reliability. | **OPEN — needs a CI-ownership decision.** See §9 |
| CI-02 | P3 | `TestBenchGate_LearnObserveEnabledBoundedAllocs` (Policy Learning, untouched by this branch) measures process-global `MemStats.Mallocs` while the learning engine's drain goroutine allocates concurrently, so it fails on scheduling. Reproduces on unmodified `origin/main`. | **OPEN — not this PR's.** See §9 |

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

## 9. Three CI findings that are not this branch's code

Both were found while driving PR #1224 to green. Neither is caused by the MCP work, and
both are recorded here rather than fixed inside a security PR, because widening this PR to
carry unrelated CI repairs is exactly the habit that makes a security diff unreviewable.

### CI-01 — the root package's `-race` + coverage run sits ON its 15m budget

`pr-fast-gate.yml` runs `go test -race -count=1 -timeout=15m -coverprofile=... ./...`. The
`-timeout` is **per test binary**, and the root package alone consumes essentially all of
it. Every other package finishes in seconds; the largest, `internal/ssrf`, takes 37s.

Measured, all on the same container, `-timeout=40m` where marked *unclamped* (a clamped
run cannot report more than ~902s — the timeout firing is not a duration):

| Tree | Run | Root package |
|---|---|---|
| this branch @ `adf7de8` | GitHub Actions | 902.4s — **timed out** |
| this branch @ `1e27e0e` | GitHub Actions | 902.1s — **timed out** |
| this branch @ `adf7de8` | local, clamped | 902.1s — **timed out** |
| `origin/main` @ `17f237e` | local, clamped | 901.4s — **timed out** |
| this branch | local, unclamped, quiet box | **918.5s** — passes |
| `origin/main` | local, unclamped, quiet box | **897.9s** — passes, 2.1s of headroom |

**A correction to an earlier reading of this data.** Two contended local runs put
`origin/main` over 900s, and this section previously concluded that `main` itself exceeds
the budget. The clean unclamped re-measurement refutes that: `main` comes in at 897.9s and
passes. The contended figures (901.4s clamped, and a 929.3s run that shared the machine
with a `staticcheck`/`gocritic` sweep) were measuring my own background load, not `main`.

The corrected finding is narrower and more useful: **`main` clears the budget by 2.1
seconds — 0.23%.** That is smaller than the run-to-run variance of this suite, which makes
real network calls during the run (the job log shows lookups to `urlhaus.abuse.ch`,
`openphish.com` and `raw.githubusercontent.com`). A required check with a 0.23% margin is
not a check that passes; it is a check that is currently winning a coin flip.

This branch's own contribution is small but lands on that margin: **all 52 test functions
in the five root test files it touches cost 4.7s** measured in isolation under
`-race -coverprofile` (down from 8.3s — `49b2d3c` made the execution-posture wall parse
the module once instead of three times). 4.7s against 2.1s of headroom is enough to tip it,
and the failure is a budget overrun rather than a hang: the panic dump names a test that
had only just started at 0s, and no run has produced a data race.

So this is not "a failure that isn't this PR's" — but neither is it a defect in this PR.
Optimising the new tests further cannot fix it, because even zero added cost leaves 2.1s
of margin on a suite whose variance is an order of magnitude larger. The durable fix is a
CI-ownership decision, not a change this security PR should make on its own authority:

1. **Raise the per-binary budget** (`-timeout=15m` and the job's `timeout-minutes: 25`).
   One line, unblocks every PR, and honest about what the suite now costs.
2. **Split the root package**, which is the real problem — 902s of a 15m budget in one
   test binary while the other 65 packages finish in seconds.

Either is out of scope for a diff whose subject is the MCP trust boundary.

### CI-02 — `TestBenchGate_LearnObserveEnabledBoundedAllocs` is a racy measurement

The `Gate · perf-regression (allocs/op)` failure on `adf7de8` was
`enabled enqueue (no groups) allocates 10.0/op, want 0`, in Policy Learning — code this
branch does not touch.

`testing.AllocsPerRun` brackets the measured loop with `runtime.ReadMemStats` and reads
`MemStats.Mallocs`, which is **process-global**: it counts every goroutine's allocations,
not the measured function's. The learning engine's drain goroutine aggregates observations
concurrently, and `Observe`'s channel send is itself a scheduling point, so
`GOMAXPROCS(1)` does not keep the drain out of the measured window.

Correlating the two directly over 300 measurements: measurements that failed drained a
mean of **1193** observations inside the window; measurements that passed drained **188**.
Every failure sits in the high-drain tail. The producer's own path is provably not at
fault — the identity fences (`learnFencedStamp`) held on every failing measurement, and
292 of 300 measurements reported exactly 0 allocs/op for the same call.

It reproduces on unmodified `origin/main` (1 failure in 40 runs) and on this branch
(1 in 20 in one sample). A gate that fails a few percent of the time gets muted, which is
the outcome `internal/connlimit`'s benchgate notes already warn against.

The fix is to make the measurement observe only the producer — drain the queue to
quiescence before measuring, or measure against an engine whose consumer is not running —
not to widen the bound, which would retire the contract the gate exists to hold.

### CI-03 — `Deep · determinism` intermittently fails in the root package, unlocatable from here

`Deep · determinism (shuffle, count=2)` runs `go test -count=2 -shuffle=on ./...`
without `-race`. On this branch it **passed on `ff622ad` (2 of 2, including a re-run)
and failed on `5d607af` (2 of 2)**. The failure is genuinely puzzling and, after a full
investigation, could be neither attributed to this PR's changes nor located.

What is established:

- The **only** package `5d607af` changed is `internal/mcp/runtime`, and it **passed in
  both failing runs** (8.954s), as did `internal/mcp/execution` and
  `internal/mcp/catalog`. The failing package both times is the **root package**
  (`package main`), which `5d607af` does not touch. No causal path from an
  `internal/mcp/runtime` change to a root-package test is evident.
- The root package **could not be made to fail locally in 7 `count=2 -shuffle` runs** —
  2 at the exact CI seeds (`1787658349191607536`, `1787659684864451945`; 534.5s / 539.6s)
  and 5 at fresh seeds — all exit 0. So it is **not an order-dependent bug reproducible
  without the network**.
- The root package's tests make **live calls to `urlhaus.abuse.ch` and `openphish.com`**
  (the threat-feed defaults), which this review container's egress policy **blocks with
  403** but CI permits — confirmed against the agent proxy's own recent-failure log. A
  CI-only failure is therefore consistent with an **environment-dependent live-network
  test**: it fetches real feed data in CI (variable, occasionally slow or malformed) and
  fails open locally (so it passes here every time).
- `internal/secscan` **also** failed on the first run (`TestChaos_AbandonedScansAreCountedAndUnwind`,
  "precondition: inflight = 1, want 0" — a cross-test in-flight-scan leak under
  `-count=2`) and **passed on the re-run**, so that one was a plain flake — independent
  corroboration that this job carries pre-existing intermittency.

What could not be obtained, and why — recorded rather than worked around:

- **The failing test's name.** `get_job_logs` is tail-capped (~5000 lines) below the point
  where the root package's `--- FAIL` line sits (the root binary emits thousands of
  `POLICY_*` log lines, so its per-test failure is far above the tail window), and the
  pre-signed `deep-determinism-log` **artifact blob host is egress-blocked (403)**. The
  agent-proxy contract is to **report** such egress denials, not route around them, so the
  log was not retrieved by other means.

Conclusion: the `5d607af` correlation is unexplained, but with 7/7 local passes and no
causal path from the changed package to the failing one, it is **most consistent with a
pre-existing, environment-sensitive live-network flake landing fail/fail by chance**
(a ~6% coincidence given a ~50%-ish per-run flake rate). It is **not** demonstrably this
PR's code. Resolving it needs one datum this review environment cannot produce: the failing
test's name, which is in the owner-accessible `deep-determinism-log` artifact on the failed
run. The durable fixes are the same shape as CI-01/CI-02 — make the root package's
threat-feed tests hermetic (seed the feed, never dial the real URLhaus/OpenPhish endpoints
under `go test`), and give secscan's chaos test a per-test in-flight reset — both
repo-owned, neither a change a security PR should make blind to the failing assertion.

## §11 — Owner-triggered `@codex review` round on `7fd0869` (two P2s, both fixed)

The owner re-ran `@codex review` on head `7fd0869`. Two new P2 findings, both
confirmed against the code by direct trace before any patch, both fixed and
mutation-verified.

**F-CDR — credential-path tool drift surfaced as `none`, not `decision_snapshot_stale`
(`internal/mcp/execution/run.go`).** The OVN-09 side-effect-boundary drift re-check
lives in `callUpstream`, shared by both commit paths. On the NO-credential path the
drift error escapes `CommitThenAct` and the `staleAtCall` remap reclassifies it. On
the CREDENTIAL path `materializeAndCall` swallows the same error into a blocked
`ExecOutput` whose reason is `ReasonOf(errToolDriftedBeforeCall) == ReasonNone` (the
sentinel is package-private and unregistered) and the `CommitThenAct` callback returns
`nil`, so the remap never ran — clients and block telemetry read `none` on exactly the
ordinary enterprise shape (an executed `tools/call` carrying a credential profile).
Fix (44cfd3a): apply the same `staleAtCall` reclassification on the `didBlock` branch.
`staleAtCall` is set only by `callUpstream`, so on that branch it is true iff the block
was the drift refusal; the boolean is robust to any error wrapping the broker might add
(unlike `errors.Is` on a verbatim-returned sentinel). Regression test builds a REAL
materializing broker (Plan → PR-8 gate → provider materialization → scoped callback):
a control proves the harness executes with the materialized bearer credential, and the
drift case pins the stale reason. Verified failing with `reason=none` against the
pre-fix tree.

**F-DPOP — DPoP concurrency slot held across access-token validation
(`internal/mcp/runtime/auth.go`).** `ValidateCredential` performs the access-token
crypto (JWT signature OR opaque introspection); the DPoP proof is a separate
verification that runs later inside `AuthenticateVerified`. The pipeline acquired the
DPoP slot FIRST (OVN-02 scarcest-first) and held it across `ValidateCredential`, so a
slow introspection — or an invalid token that never reaches the proof stage at all —
occupied a scarce DPoP slot while no DPoP work was in progress; with
`DPoPConcurrency < AuthConcurrency` such requests could stall legitimate DPoP callers
into a timeout. Fix (529bf7e), matching Codex's recommendation exactly: validate the
access token under the auth bound, RELEASE it, then acquire the DPoP bound only
afterward and only when a proof will actually be verified (`dpopVerificationRuns`). The
two bounds are never held at once, which closes BOTH starvation shapes at their root —
no hold-and-wait on the auth pool (auth released before DPoP taken, so OVN-02 still
holds), and no DPoP slot held across validation. The OVN-02 test was rewritten to
exercise the invariant faithfully under the new model (a DPoP waiter parks on DPoP
holding no auth slot); a new test pins the F-DPOP invariant (no DPoP slot held during
validation). Each was verified failing against a DISTINCT regression: the pre-fix
DPoP-first-across-validation ordering, and a hold-and-wait mutation, respectively. All
other Limits-wall and slot-deadline tests are unchanged (`limits_ownership_test.go`
pins only that both bounds are read via `acquireSlot`, which the restructure preserves).

Both packages pass `go test -race` (execution 126.5s, runtime 17.6s); gofmt clean;
both fixes committed by logical fix and pushed. All 19 PR #1224 review threads resolved.
Execution remains disabled — neither fix composes an executor, arms a rollout mode, or
touches the guarded-execution wiring.
