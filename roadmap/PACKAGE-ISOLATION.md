# Package isolation: owned engines and independently runnable tests

Assessment and pilot design, 2026-09-30. Baseline: freshly fetched
`origin/main` **1f7f42c6937847c26f29387dcaae6685e356a9b0**. This equals the
previously inspected SHA; it was rechecked, not assumed. Work is on
`codex/package-isolation-pilot` in a separate worktree. ADR-0002 is **complete**.
This is a new program with [ADR-0037](../docs/adr/0037-shutdown-registry-package-isolation.md),
not a reopened leaf-extraction checklist. The existing runtime-ownership and
CI-redesign programs remain authoritative for lifecycle and CI semantics.

## Current state

The baseline has 382 root production Go files (135,297 lines), 904 root test
files (263,122 lines), and 6,757 runnable root test/fuzz/example entries under
the race-sharding source inventory. Size explains the cost of a focused root
build, but is **not** the selection criterion. Many files are already shims.

The following is a domain map, not a suggestion to create one package per row.
Callers name production composition points; test prefixes are navigation aids,
not replacement CI selectors. Cross-domain tests stay with the composition they
exercise. Read source and test helpers before sizing each implementation PR.

| Remaining root domain | Production callers and dependencies | State, persistence, lifecycle | Tests and boundary decision |
|---|---|---|---|
| Shutdown execution (`runtime_shutdown.go`) | `runProxyUntilShutdown` → registry; `main_shutdown.go` → partition and RunAll; only stdlib plus root logger | Per-registry mutex/hooks/ran; **global** grace/minimum timing; no persistence; one transient goroutine per hook, timer/cancel owned by execution | `runtime_shutdown_test.go`, synthetic parts of CHAOS-56; **pilot**. Real service order, phase budgets, signal escalation, tunnel/gRPC behavior and durable flush tests stay root |
| IP admission and sliding-window rate limiting (`security.go`) | HTTP/SOCKS5/policy gates; startup/admin settings/UI/config import and CP→DP snapshot; shared CIDR prefix representation | IPFilter write lock + immutable atomic view; RateLimiter shards + atomic settings/exemption view; global cluster enable/count state and test publish hook; persistence belongs to configuration adapters; cleanup loop in `connlimit_startup.go` parented to app lifecycle | `security_ipfilter_*`, `security_ratelimit_*`, mixed `security_test`, distributed/freshness/startup/integration tests. Next design must separate instance state before moving engine; retain SSRF/hostutil shims |
| Policy rule vocabulary, store, evaluator and drafts | `proxy*`, `socks5*`, `ui_policy*`, shadow/replay/learning adapters; existing `urlcat`, `catgroup`, `sslbypass`, file profiles, geo lookups | Published snapshots, rule counters, policy-store locks, draft/write coordinator; caller-side durable saves and cross-store learning-accept intent protocol | Policy/auth-policy/draft/shadow/conformance tests. Keep full hub in main now. ADR-0026 establishes one evaluator, not an independent policy-store ownership boundary |
| Identity and admin authentication | Proxy auth resolution, admin middleware, IdP routes and CP snapshots; existing `session`, `authstate`, `authcost`, `totp`, `lockout` | Root `cfg`, IdP registry/live providers, interactive runtime adapters; user/provider/settings files; provider and session lifecycle | `auth*`, `ui_auth*`, D0/C1/C2 and redaction suites. Existing engines are already internal; next candidates must own a real protocol/state boundary, not just aliases |
| Proxy/CONNECT/SOCKS5 orchestration | Dispatch → identity → policy → upstream → scanner/CDR → telemetry; existing leaf engines | Request/tunnel ownership, connection accounting, published upstream transport, cancellation and drain | Socket, H1/H2, SSRF, policy/security and traffic suites. Keep request-path composition in main (ADR-0002 verdict still applies) |
| Cluster, HA and config publication | CP server/client, enrollment, snapshot apply, HA transitions; `halease`, session and domain stores | Cross-store ordering, cluster persistence/CA, heartbeat and fencing goroutines, transport and epoch ownership | `controlplane*`, HA/CHAOS-55, enrollment and flush tests. Keep snapshot DTO and apply orchestrator in main; extract only a separately mapped state machine, not a ConfigSnapshot hub |
| Configuration, admin REST and diagnostics | `FileConfig`, `AdminSettings`, config-version backup/import/rollback; route metadata and startup resolution | Persistence formats and application-wide publication/validation; no single independently owned aggregate | OpenAPI conformance, config-surface parity, rollback, RBAC, diagnostics. Keep schemas, route assembly and cross-domain transactions in main; reuse `internal/apicontract` for generic contract work |
| MCP composition and canary/rollout adapters | Main constructs `internal/mcp/*` engines; root routes, execution dependencies, telemetry and CP/DP distribution | Root runtime publications and callback bindings; spool/key stores already internal; shutdown and distribution recovery ordering | `mcp_*` real-runtime/canary integration versus package unit tests. Do not move the entire adapter layer. Spool KDF cost needs an independent security/fixture design |
| Release management | Root operator routes and host-agent client compose catalog verification/dispatch and release state | Trusted catalog, status/refresh latches, on-disk config; refresh/watchdog goroutines follow app lifecycle | Catalog/dispatch/status/security tests. Preserve signing, release publication, host privilege boundaries; assess a state owner only after mapping agent/catalog effects |
| Support/telemetry and observability | Root diagnostics/consent/export/metrics adapters compose internal collectors, logsink, logstore, audit, reqlog, OTLP | Root telemetry publication and consent; existing stores/queues own persistence; source-side redaction and shutdown ordering | Support redaction/golden/export and metrics tests. ADR-0028–0031 boundaries prohibit moving collection authority into a generic shared service |
| Startup and existing shims | `main.go`, `*_startup*.go`, `*_vars.go`, `session.go`, `upstream.go`, etc. | Process owner selects config/env, creates engines and registers stop callbacks | Startup precedence, composition and integration tests stay root. A file already delegating to internal code is not a fresh extraction candidate |

Evidence: ADR-0002 closure/rejected core-hub designs; ADR-0003 foundation seams;
ADR-0006 explicit scanner dependencies; ADR-0025/0026 policy-learning/evaluation;
ADR-0028–0031 support authority; RUNTIME-OWNERSHIP S4/S5/S7 and shipped phases;
CI-REDESIGN §§13–20; current Fast/Deep and `qa-race-shards.yml`.

## Shortlist and choice

| Rank | Boundary | Local isolation value | CI evidence / expected effect | Coupling, risk and review cost |
|---|---|---|---|---|
| 1, pilot | Ordered shutdown execution | Engine tests stop compiling/linking all root tests; per-owner timing/logging allows independent concurrent tests | Whole CHAOS-56 family was 25 s of a historical root double run, but **most is integration**. The moved 17 entries total about 1 s in the checked-in race timing sample. Expect small root execution change, not a gate-scale saving | Stdlib engine; one logger dependency; stable sequencing API. Lifecycle semantics are sensitive, so preserve watchdog arithmetic and concrete root integration. One bounded implementation PR |
| 2 | Admission engines: IP filter + limiter | Larger set of isolated white-box/matcher/window tests; eliminate cluster/test-hook global fixtures | Hot-path benchgates and many root tests; **no measured current critical-path saving**. Measure before choosing full extraction | Prefix representation shared between engines; distributed limiter reads global state; broad persistence adapters. Ownership prerequisite plus extraction, roughly two focused PRs |
| 3 | Policy store/evaluator/draft | Potentially high, but adapters and vocabulary dominate test coupling | ADR-0026 removes duplicate evaluation; no current measurement justifying full package relocation | Highest semantic/security/durability coupling; #1470 overlaps publication. Reassess pure evaluator only after dependency mapping; do not transplant root policy hub |
| Separate performance track | MCP spool/test fixture key derivation | Could reduce repetitive integration setup without moving code | CI-REDESIGN §19.1 measured ~221 CPU seconds in a root double run; engine is **already** internal | Sharing mutable spools loses isolation; weakening KDF is prohibited. Requires security design and equivalence proof; excluded from this behavior-preserving pilot |

The pilot is the best bounded *ownership/extraction* step, not the largest CI
bottleneck. Moving all CHAOS-56 tests would misclassify gRPC/tunnel/production
wiring as engine behavior just to improve a timing chart.

ADR-0002's policy rejection is revisited against current evidence: the second
consumer trigger is partly met (tester/shadow/replay now share the ADR-0026 core),
but live lookups, auth vocabulary, fail-closed load gates and draft durability
still prevent a narrow independent package. Its old absolute "no second
consumer" rationale is historical, not a present fact. Proxy and ConfigSnapshot
remain composition hubs. Already-extracted upstream/session engines are not
re-extracted.

## Open-PR coordination

REST file inventories for all 30 open PRs were checked on 2026-09-30; none used
ADR number 0037 or changed the registry engine/tests. #1494 changes only the
syslog callback's handle lookup in `main_shutdown.go`; this PR preserves that
callback and its registration order. #1504 overlaps `main.go` flag handling,
not shutdown construction. Several PRs touch CLAUDE.md; keep the guidance hunk
small. #1470 overlaps policy publication, reinforcing the decision to defer it.
Re-fetch/recheck before merge; this is a snapshot, not a reservation.

## Pilot ownership and migration

`internal/shutdown.Registry` owns mutex, hooks, run-once marker and copied
constructor options. No setters, persistence, implicit init, package singleton,
application logger, or service imports. The two immutable timing defaults retain
3 s grace / 1 s minimum. `PartitionAt` consumes the source exactly as before,
creates independent hook lists and inherits timing/sink. `Hooks` returns copied
name/order metadata, never callbacks. Main's alias is a permanent local name for
an internal type, **not** a temporary implementation adapter; its constructor
only binds the application's existing logger. No parallel legacy engine remains.

Main owns phase contexts, Total/Early/Flush budgets, cutoff constants, callback
registration, cancellation order and persistence. Registry execution owns its
per-hook context cancellation and watchdog timer. A context-ignoring hook can
outlive abandonment; this existing shutdown-only contract remains. Test-created
blocked hooks are released, and new lifecycle tests bound their completion.

| Old owner | New owner | Assertions retained |
|---|---|---|
| `runtime_shutdown_test.go` (9) | `internal/shutdown/registry_test.go` | order/ties, error aggregation, run-once/concurrent run-once, context propagation, nil/late registration, empty registry |
| `shutdown_envelope_test.go` (4) | `internal/shutdown/envelope_test.go` | shared grace bound and positive slices, durable closers complete before return, healthy/unbounded controls; root pins fixture phase sizes to the actual envelope |
| Four synthetic tests in `shutdown_chaos_test.go` | `internal/shutdown/watchdog_test.go` | minimum slice, panic containment, named immediate abandonment diagnostic, healthy slow hook |
| Remaining CHAOS-56 + wiring/audit/cluster tests | **Remain main** | three-phase reserve, real hook inventory, gRPC/tunnels/signals, persisted flush behavior, compose stop-grace envelope |

All 17 moved entry names are unchanged. Source inventory: root **6,757 → 6,742**
(17 moved, 2 new integration contracts); new package **24** entries (17 moved,
7 new ownership/boundary tests). Whole-module runnable entries rise from 9,964 to 9,973; no name/multiplicity
lost, and all 309 benchmarks remain (152 in root).
The actual `cmd/rootshard inventory -check-list` agrees with the candidate root
binary. CI's non-root lane uses `go list ./...` minus the exact root import path,
so the package is included automatically; the independent coverage universe uses
the same discovery. Historical `.github/qa-root-shard-timings.json` is balancing
data, not inclusion authority: stale moved names need no selector change.

The root nil-stop check now relies on production registration traversing the
engine's still-tested panic-on-nil API, rather than exporting callbacks just for
inspection. The arithmetic assertions remain white-box beside the algorithm;
the root fixture/default contract fails if the production phase sizes change.
New tests cover concurrent independent owners, copied options, partition timing
and sink inheritance, detached metadata, cancellation/completion, and production
logger wiring. The package boundary test rejects application/persistence imports,
implicit initialization and shared runtime variables, with negative controls.

## Ordered follow-up PRs

1. **Complete — shutdown execution owner and package (#1522).** Dependency: none beyond
   current main. Accept: unchanged production sequence and diagnostics; all 17
   assertions relocated; inventory equivalence; race/shuffled package + root
   integration; full gates and coverage reviewed. Keep signal handling, phase
   budgets and service closures in main. No release or workflow redesign.
2. **Implemented — instance-owned distributed admission state (ADR-0038).**
   Baseline `60f127389d7a1004a6af7dd4dd352b908b8ad313`, including merged #1522.
   Each limiter now owns remote counts/stamp, enablement and freshness history;
   each IP filter owns its publication observer. Gossip captures the application
   limiter explicitly; config, HTTP/SOCKS5 and diagnostics use that owner.
   Cleanup lifecycle, wire/config formats and all admission policy remain intact.
   No package extraction in this prerequisite. Existing engine/CHAOS-61 names
   stay in root with local fixtures; only real adapter tests bind the application
   handle. Concurrent ownership, CP→DP/ingress/diagnostic wiring and unchanged
   freshness verdicts are the acceptance gates. See [ADR-0038](../docs/adr/0038-instance-owned-admission-state.md)
   and [evidence](../docs/engineering/admission-state-ownership.md).
3. **Exact next PR — `internal/admission` engine extraction.** Depends on 2. Choose one cohesive package
   for filter/limiter/shared CIDR representation, reusing existing hostutil/ssrf
   without duplicating security decisions. Move engine tests and tagged
   benchgates; leave config persistence, HTTP/SOCKS5 call sites and the parented
   cleanup loop in main. Accept: old/new verdict differential tests and hot-path
   allocation gates unchanged; `security.go` 70% coverage selector deliberately
   follows the moved implementation (no floor reduction); root and non-root
   inventory proof; baseline/candidate focused and gate measurements.
   Move `IPFilter`, `RateLimiter`, prefix matching, remote store and derived
   freshness status together with engine tests and benchmark contracts. Keep
   `rl`/`ipf` composition handles, gossip DTO/transport, CP fleet aggregation,
   metrics/API rendering and transition logging in main; expose a narrow
   observation result for the latter without creating a second freshness
   authority. Split mixed test files by behavioral ownership, preserving every
   assertion/name. Keep real snapshot, rollback, HTTP/SOCKS5 and cancellation
   integration tests root. No temporary second engine or `internal/app` hub.
4. **Policy pure-core feasibility and ownership design.** Depends on coordination
   with #1470 and admission results, not a promise to extract. Map rule vocabulary,
   live match dependencies and hit-accounting ownership against ADR-0026. Accept:
   one evaluator across enforcement/tester/replay; no injected fail-open load
   gate, no generic DTO/common hub; concrete immutable input and state-owner
   design with mixed tests accounted for. Keep draft commit/learning-accept and
   config/snapshot transactions in main until separately designed.
5. **Choose the next implementation from fresh timings.** Reprofile current
   root determinism and compilation after 3. Prefer a complete domain over
   splitting source-contract tests into an unrelated package. MCP spool setup
   remains a separate security-reviewed performance project; no weaker KDF,
   shared mutable test spool or skipped assertions as an isolation shortcut.

## Measurement and validation contract

See [pilot evidence](../docs/engineering/package-isolation-pilot.md). Keep focused
local command time, prebuilt root execution, extracted package execution, Fast,
Deep, both-required-gates completion and total runner-seconds separate. Record
Go/CPU/flags, cache state, test outcomes and attempt identity. Compare matched
runs on the same machine; do not treat historical CI samples as controlled pairs.
No test-result cache is used for execution measurements (`-count=1`).

Current CI: Fast runs the shared four-root-shards/non-root/universe/verdict engine
and the unchanged 55% global + per-file coverage floors. Deep runs the full
`-count=2 -shuffle` suite for test changes. The new package enters both without
workflow edits. Release evidence, privileged mount regression, race/shuffle and
all existing floors remain required. This PR does not claim that a faster
focused command reduces either gate or overall PR completion.

## Admission development guidance

Until step 3 lands, admission engine changes belong beside `security.go` and
use explicitly constructed owners in tests. Do not restore distributed-state
singletons or global observer registries. `newRateLimiter` initializes active
local admission; zero literals retain disabled/read/configuration support.
Treat a published remote map as transferred and immutable. Configure/enable
switches retain history; lifecycle cancellation belongs to the caller. After
extraction, engine tests must run with `go test ./internal/admission` without
application globals; adapters continue to test real composition from main.
The concurrent-owner tests and publication negative controls enforce this seam.
