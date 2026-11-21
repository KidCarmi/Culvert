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
2. **Complete — instance-owned distributed admission state (#1523, ADR-0038).**
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
3. **Implemented — admission engine extraction (ADR-0039).** Depends on merged
   #1523. `internal/admission` owns filters, local windows, shared prefix
   matching, remote state and derived freshness/episode accounting. Main retains
   composition, persistence/rollback, HTTP/SOCKS5, gossip DTO/transport, CP fleet
   aggregation, cleanup lifecycle, metrics/API and transition logging. Aliases
   contain no parallel engine. 97 entries relocated (74 default tests, 21
   benchmarks, 2 tagged gates); real integrations stay root. Fast, QA and weekly
   benchgate selectors include both packages; engine and freshness each have
   70% floors, with the residual security shim's 70% retained. Global 55% and all
   other contracts stay intact. Negative controls reject missing gate targets
   and omitted/uncovered implementation profiles. See [design](../docs/adr/0039-admission-engine-package.md),
   [inventory](../docs/engineering/admission-test-migration.tsv) and
   [validation/measurements](../docs/engineering/admission-engine-extraction.md).
4. **Mapped 2026-10-30 — policy pure-core feasibility (verdict: not ready under the current boundary; see "Policy pure-core mapping" and the #1526 reconciliation below; authoritative next action is IM-006).** Depends on coordination
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

6. **Implemented — identity-backend result cache (`internal/identcache`,
   ADR-0041, #1633).** Codex P1 on the CHAOS-76 sweep: the cache shared by the
   LDAP bind and both RFC 7662 introspection backends had been introduced as a
   `package main` engine. `identcache.Cache[T]` owns the entries, client
   buckets, expiry, compaction and eviction policy. The cap and the eviction
   sink are `Options`, and the package holds no globals. Main keeps the
   zero-value-usable binding `identityResultCache[T]`, which passes
   `maxAuthCacheSize` and the process-wide `/metrics` total, and all backend,
   dispatch and metrics integration gates. Nine engine gates moved with their
   names unchanged. Boundary, ownership and one root binding gate were added.
   `store.go`'s victim ordering delegates to `identcache.BetterVictim`. Merging
   it with `authCacheStore` and `internal/authstate` is deliberately not done
   (CHAOS-76 §54.7).

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

Admission engine changes and white-box tests belong in `internal/admission`;
use explicitly constructed owners in tests. See [ADR-0039](../docs/adr/0039-admission-engine-package.md)
and the [migration evidence](../docs/engineering/admission-engine-extraction.md). Do not restore distributed-state
singletons or global observer registries. `newRateLimiter` initializes active
local admission; zero literals retain disabled/read/configuration support.
Treat a published remote map as transferred and immutable. Configure/enable
switches retain history; lifecycle cancellation belongs to the caller. Engine tests must run with `go test ./internal/admission` without
application globals; adapters continue to test real composition from main.
The concurrent-owner tests and publication negative controls enforce this seam.

## Policy pure-core mapping (2026-10-30, shortlist item 4)

Mapping night: no code moved. Baseline `origin/main` 174f157f. #1470 (snapshot
O(1) memo) merged 2026-10-19, so the coordination blocker is gone. Shortlist
items 1–3 and 6 are shipped (`internal/shutdown`, `internal/admission`,
`internal/identcache`); item 4 is the next unshipped one and is explicitly a
feasibility step, not an extraction.

**Evaluator surface (source: `policy.go`, `policy_hostcat.go`, `policy_scanindex.go`,
`categorygroup.go`).** `evalAccessRules(rules, rows, *accessEvalInput, now, trace)`
is the single scan (ADR-0026). Callers: `PolicyStore.Evaluate` (policy.go:1779,
hit accounting stays in the caller) and the Policy Tester (`ui_policy.go:2783`);
tests: `coverage_isolation_policy_test.go`, `policy_scanindex_{,bench_}test.go`.
It is pure of mutation/logging/locks, but its matchers are not pure of
*environment*:

| Hidden input read by matchers | Where | Nature |
|---|---|---|
| `catStore` (`internal/urlcat`) | `policy_hostcat.go` (9 refs), `matchCategory` | package-level singleton, already an internal owner |
| category-group store | `categorygroup.go` `categoryGroupMatchesHostScratch` | root singleton over `internal/catgroup` |
| `geo.LookupCached` + `noteGeoCountryUnresolved` | `matchDestNorm` | singleton plus metrics side effect on the "pure" path |
| `noteFileProfileUnresolvedBlock`, `logger` | `FileProfileBlocked` (policy.go:2378–2445) | log/metric side effects, fail-closed behavior |
| `time.Now` | injected already | fine |
| `scheduleLocCache` | policy.go:1854 | process-wide `sync.Map`, benign cache |

**Store/state side (not part of a pure core).** `PolicyStore` (policy.go:265) owns
`mu`, published rules, `verified` memo, `scanIndex`, per-rule `counters`, version
meta, and persistence (`Load/Save/saveTo/saveMeta`, `DroppedOnLoad` fail-closed
load gate). Plus `policy_draft.go` (1,204 lines), `policy_mutation.go`,
`policy_learning_*`, `policy_refs.go`, `policy_ref_validation.go`. Total
`policy*.go` production ≈ 6.3k lines; 29 root production files reference
`policyStore`; 194 root test files mention `PolicyStore`/`PolicyRule`, 59 are
`policy*_test.go` (~15k lines). That is far over the ~15 file / ~1,500 line
extraction ceiling for one night, even for the evaluator alone once
`PolicyRule` (35 JSON-tagged fields plus unexported precomputed matcher state, used by config import, CP snapshot, UI,
learning) must move with it.

**Verdict: not ready under the current boundary** (restated 2026-10-30 after
the #1526 reconciliation below).
1. The scan loop is not the obstacle; `PolicyRule` is: it is the persistence,
   CP-snapshot and API wire type. Under the *current* boundary this mapping
   found two options, an exported-struct package consumed by every root domain
   (a shared vocabulary hub, which ADR-0002 rejects) or a mirror type converted
   on the hot path. The only *measured* number here is ADR-0026's +4.5% from a
   call boundary alone; the cost of a mirror conversion is inference, not a
   measurement. ADR-0040 (#1526) describes a third path this mapping did not
   assess: make the lookup environment explicit in main first, then extract an
   ordinal-returning matching engine that never receives `PolicyRule`.
2. The four hidden inputs above are what ADR-0040 calls the lookup
   environment. Today they are process globals, so an extraction would need
   callbacks into main; after the ADR-0040 prerequisite they are construction
   inputs owned in main. "Callbacks into main" is a property of the current
   boundary, not a permanent fact.
3. Geo and file-profile side effects (metric increments, the fail-closed log)
   sit inside what ADR-0026 calls "pure". ADR-0040 keeps the geo observation in
   main's adapter; the file-profile notifier is an addition this mapping found.

**Narrower follow-ups (each needs its own accepted design; none started):**
- (a) Leaf matchers that take only strings and no `PolicyRule`:
  `matchScheduleAt`/`scheduleClock`/`parseClockMinutes` (policy.go:1854–2085,
  ~230 lines), `matchIPOrCIDR`/`clientSource`, `matchAuthSource`/`splitIdPSource`.
  **Blocked** pending IM-006 and a separately accepted boundary: ADR-0040 requires
  `scheduleLocCache` to become an explicit schedule-resolver instance, so (a) must
  not carry it across as a package global. White-box tests:
  `policy_schedule_{clock,minutes}_test.go`, `policy_srcprefix_test.go` (mixed;
  its publication/draft assertions stay root per the #1526 inventory).
- (b) `hostCatScratch` (policy_hostcat.go, 258 lines) only after `catStore`
  becomes an explicit owner (ADR-0040's borrowed-store treatment).
- (c) `PolicyStore`, drafts, learning-accept and snapshot transactions stay main.

### Reconciliation with #1526 (ADR-0040, `codex/policy-core-feasibility`)

Inspected #1526 at head `884b1fb4` (merge-base with main `77c0c583`) against
main `174f157f`. Its design, inventory and measurements are evidence to keep,
not to discard. Closing, merging or superseding #1526 is the owner's call;
nothing here supersedes ADR-0040.

| #1526 finding | Status on `174f157f` | Evidence |
|---|---|---|
| **PREREQUISITE FIRST**: explicit lookup owners in main before any package | **Still valid** | `accessEvaluator`, `accessEvalSources`, `policyScheduleResolver`, `newAccessEvaluator` absent from main; `catStore` (policy.go:65) and `scheduleLocCache` (policy.go:1854) still process-wide |
| Step 1, wait for #1470's disposition | **Resolved** | #1470 merged 2026-10-19 (`97099d2f`); use it intact; `verified`/`sameRuleSlice` are on main |
| #1505 overlap (urlcat lock sharding, `policy_category_bench_test.go`) | **Landed** | the bench file is on main; #1526's `policy-core-baseline.json` predates it and must be re-measured before reuse |
| #1485 overlap (IdP availability / startup integration) | **Merged** (`98920187`) | recheck the startup integration tests named in #1526 before the ownership PR |
| SOCKS5 does not call `PolicyStore.Evaluate` | Not rechecked tonight | carry as unverified; verify in IM-006's map |
| Test inventory TSV, 327 entries, 31 conditional moves | **Preserved by reference** | still the migration inventory; its `baseline` column (`3fcc07e7`) needs a refresh pass, not a rewrite |
| focused-38 timings and benchmarks | Valid for `3fcc07e7` only | not current evidence; re-run per the measurement contract |
| ADR number 0040 | Still free on main | `docs/adr` holds 0037, 0038, 0039, 0041 |

Where the two mappings differ: this one adds the file-profile notifier and
counts `geo` as a hidden input; #1526 adds the feed view, community DB,
category-group store and the Stage-1/CDR shared-matcher consumers, which this
mapping did not enumerate. Union them in IM-006's map.

**One authoritative policy next action:** IM-006, ADR-0040 step 2
("refactor(policy): bind evaluation lookup owners"), after the owner decides
#1526's disposition. No policy extraction, and no leaf-matcher move, before it.

## Internal migration program (nightly shift state)

This section is the program's state. The nightly shift reads it first and
changes it only when evidence, implementation or a plan decision changes.

**Operating rules.**
- Each run first reconciles the active program PR and current main. A PR is
  updated only when evidence, implementation or a meaningful plan decision
  changes. `WAITING_REVIEW`, `WAITING_CI`, `IDLE` and `BLOCKED` are valid run
  outcomes; no PR or documentation transition is manufactured to satisfy a
  daily quota.
- **One open program PR at a time**, counting discovery, prerequisite and code
  PRs. While it waits, maintain it or report waiting; start no other slice.
- States: `proposed → mapped → implementation under review → shipped (merged)`,
  or `rejected/deferred`. An unmerged implementation is not shipped; closing
  without merge is not acceptance. "One transition per run" is a work bound,
  never an obligation to advance.
- Identification: PR title prefix `[internal-migrate]`, body marker
  `<!-- culvert-internal-migration -->`, task IDs `IM-nnn`. No label is required.
- Pilot limit: at most **three sequential code PRs**, then an assessment of
  ownership, independently runnable tests, review burden and failures before
  the owner accepts continuation. Independent review and owner-controlled
  merge; no auto-merge, release or OVA promotion.
- Code starts only after this plan is merged or the owner explicitly accepts
  the pilot.

**Tasks.** Evidence levels: *packet* (source, callers and tests read; ready for
owner acceptance), *lead* (parse-level counts only; not a design). The
2026-10-30 parse-level walk of 439 root files at `174f157f` counts top-level
identifiers used from other root files and root files/tests referencing the
candidate; it does not type-check and it over-counts common words (IM-001's
"9 tests" in the first draft was the word `cursor`; the real count is one file).

| ID | Task | Status | Owner | Base / head | PR | Depends on | Evidence | Next action |
|---|---|---|---|---|---|---|---|---|
| IM-000 | Discovery: policy mapping, #1526 reconciliation, this program section | shipped (merged 2026-10-30, `5eef0c25`) | nightly shift | `main` | #1760 | — | this document | — |
| IM-001 | `inspect_h2_alpn.go` → `internal/alpnpeek` (pilot 1 of ≤3) | **shipped** (merged 2026-10-31, `86c095a49`) | nightly shift | `main` | #1766 | IM-000 shipped | **packet** below; ADR-0042; moved `alpn.go`, `doc.go`, `boundary_test.go`, `alpn_test.go`; root inventory 8072 → 8070; assessment below | owner: accept continuation to IM-002 (map) or stop the pilot |
| IM-002 | `saas_feed_floor.go` → `internal/feedfloor` | **blocked 2026-11-20: surface measured, 23 names** (see "IM-019" below) | — | — | — | IM-020 (shared record codec owner) | **map** (908 ln, 1077-ln test file; 23 top-level names read by 10 other root production files, before struct fields and methods) | IM-020 first; then re-count what is left for the floor |
| IM-003 | `saas_feed_genstore.go` → same package | **blocked 2026-11-20: 16 names** (see "IM-019" below) | — | — | — | IM-002; `keyedMutex` owner (`cdr_lineage.go` also uses it) | **map** (539 ln; 16 top-level names read by 4 other root production files) | after IM-020 |
| IM-004 | `upstream_backup_strip.go` → `internal/upstream/backupstrip` (pilot 2 of ≤3) | **shipped** (merged 2026-11-09, #1842) | nightly shift | `main` | #1842 | IM-001 shipped | **packet** in ADR-0043; 2 exported names (`Strip`, `CountRequiringReplacement`); callers `backup.go`, `restore.go`; 15 engine-only tests moved with names unchanged, 5 neighbouring tests stay root | review PR; owner decides pilot continuation to a third code PR |
| IM-005 | `policy.go` leaf matchers (follow-up (a)) | **blocked** | — | — | — | IM-006 + accepted boundary | mapping above | none until IM-006 ships |
| IM-006 | Policy evaluation lookup owners (ADR-0040 step 2) | blocked on #1526 disposition | owner decides | — | #1526 (design) | owner | ADR-0040, `policy-core-feasibility.md`, TSV | owner: merge/rebase/close #1526; then one ownership PR |
| IM-007 | `realclientip.go` → `internal/realclientip` | **shipped** (merged 2026-11-15, `de0b6d1`) | nightly shift | `main` | #1892 | ADR-0038 pattern | ADR-0045; 4 exported names (`Resolver`, `SetTrustedProxies`, `TrustedProxies`, `ClientIP`); instance owner and move in one PR because root keeps the three wrapper names, so no caller changed; root globals 2 → 1 (`clientIPResolver`); root `realclientip_test.go` untouched | — |
| IM-008 | `traffic_redaction.go` → `internal/pseudonym` | **shipped** (merged 2026-11-10, `168040c`) | nightly shift | `main` | #1845 | IM-007 not required (posture stays in main) | ADR-0044; 6 exported names; engine split from the `decRedactHosts` posture gate; root keeps wrapper names so no caller changed; 6 engine tests moved with names unchanged | — |
| IM-009 | `mcp_evidence_readmodel.go` → `internal/mcp/evidenceview` | **shipped** (merged 2026-11-19, `19b2ee8`) | nightly shift | `main` | #1941 | overlap check passed 2026-11-18 (no open MCP PR) | ADR-0046; 5 exported names (`Build`, `View`, `Requirement`, `Summary`, `State`); 1 production caller + 1 `uie2e` fixture call updated, no root alias; shared category slice → per-call slice; wire bytes pinned by golden + 5-case before/after comparison; 5 engine tests moved with names unchanged, 2 handler tests stay root | — |
| IM-010 | `proxy_path_bounds.go`, `proxy_host_bounds.go`, `request_tracing_bounds.go` | proposed | — | — | — | benchgate measurement | lead (hot path; cross-linked) | measure before mapping |
| IM-011 | `mcp_shadow_metrics.go` → `internal/mcp/shadowmetrics` (split from IM-009) | **shipped** (merged 2026-11-19, `babaf34`) | nightly shift | `main` | #1944 | — | ADR-0047; 2 exported names; the `sync.Once` instance and the never-armed nil gate on `/metrics` stay main; see "IM-011 extraction" below | — |
| IM-012 | saas-feed wire field grammar: root `canonicalUTCSecond`/`validSHA256Hex` → bindings to `internal/urlcatfeed` | **shipped** (merged 2026-11-20, `949d650`) | nightly shift | `main` | #1955 | — | duplicate-rule removal: `urlcatfeed.parseCanonicalRFC3339`/`isSHA256Hex` were byte-equivalent private copies of the root validators; now exported (`ParseCanonicalRFC3339`, `IsSHA256Hex`) and the root names delegate, so 0 root callers changed; differential test with frozen root oracles + 2 mutation negative controls; see "IM-012" below | — |
| IM-013 | `cluster_ca_validity.go` policy → `internal/clusterca` | **shipped** (merged 2026-11-20, `398a889`) | nightly shift | `main` | #1965 | — | ADR-0048; see "IM-013" below | — |
| IM-015 | `revocation_sync_budget.go` planner → `internal/session/revsync` | **shipped** (merged 2026-11-20, `ff8bc28`) | nightly shift | `main` | #1966 | — | ADR-0049; 4 exported names; see "IM-015" below | — |
| IM-016 | `scan_svc_admission.go` gate → `internal/secscan/sidecargate` | **shipped** (merged 2026-11-20, `0fe4578`) | nightly shift | `main` | #1975 | — | ADR-0051; 8 exported names; see "IM-016" below | — |
| IM-017 | `ui_frontend_v2.go` artifact validator → `internal/frontendbundle` | **shipped** (merged 2026-11-20, `631750a`) | nightly shift | `main` | #1972 | — | ADR-0050; 3 exported names; see "IM-017" below | — |
| IM-019 | `inspect_host_pin.go` predicate → `internal/hostpin` | **shipped** (merged 2026-11-21, `2421870`) | nightly shift | `main` | #1981 | — | ADR-0052; 1 exported name (`Pinned`); root keeps `innerHostPinnedToTunnel` as a binding, so `proxy_tunnel.go` is not edited; see "IM-019" below | — |
| IM-020 | saas-feed node-local record codec → `internal/urlcatfeed/noderecord` | **shipped** (merged 2026-11-21, `58f4a44`) | nightly shift | `main` | #1985 | — | ADR-0053; 4 exported names; see "IM-020" below | — |
| IM-021 | `keyedMutex` in `saas_feed_genstore.go` → `internal/keyedmutex` | **shipped** (merged 2026-11-21, `c5674f2`) | nightly shift | `main` | #1988 | — | ADR-0054; 2 exported names; see "IM-021" below | — |
| IM-022 | directory-fsync rule (`fsyncDir`, `isBenignDirSyncErr`, the copy in `support_durable_write.go`) → `internal/fileutil` | **implementation under review** | nightly shift | `main` | #1989 | — | 2 exported names (`SyncDir`, `DirSyncUnsupported`); see "IM-022" below | review PR |

Not candidates (ADR-0002 "Decomposition Complete" decisions): `proxy.go`,
`store.go`, the `policy.go` store/draft/hub, `controlplane*.go`,
`enrollment.go`, `upstream.go`, `upstream_transport.go` (zero root deps in the
walk, but main owns the published transport by convention), `ca.go`,
`release_*.go`, `ui_*.go`, `auth_*.go`, `auth.go`, `identity.go`,
`security_scan.go`, `configversion.go`, `*_startup*.go`, `*_vars.go` and the
`*_health.go` probe adapters. Performance benefit of any task is unmeasured
until matched runs per the measurement contract establish it.

### Pilot 1 assessment (MEASURE, 2026-10-31, main `8138243fb`)

Evidence only; no performance claim (the item is stateless and cold).

- **Ownership.** One sentence holds: main's tunnel code owns the buffered
  reader and fallback decision; `internal/alpnpeek` owns only the parse. 2
  exported identifiers, no package vars/`init`, boundary test with negative
  controls. Size: PR #1766 was 7 files, +177/-44; package is 405 lines
  including tests.
- **Independently runnable tests.** `go test -race -count=3 -shuffle=on
  ./internal/alpnpeek` passes in about 1 s; the root lane
  `-run 'Tunnel|H2|ALPN|Inspect' .` (count=2) passes in about 47 s, dominated by
  root setup, not engine work.
- **Review burden.** Zero review threads; the one merge needed a `main` merge
  commit. All Fast/Deep gate jobs on the final head passed (87 check runs;
  non-skipped all green).
- **Failures.** None attributable to the move. PR body recorded two gaps:
  the full-tree lint comparison and the full root suite were not run locally
  (CI covered both).
- **Open gaps (owner).** (1) `fuzz-nightly.yml` still lacks
  `{ target: FuzzParseClientHelloALPN, pkg: "./internal/alpnpeek" }`: the
  moved fuzz target remains outside nightly fuzzing. (2) No root test covers
  the `peekClientALPN` fallback directly.
- **Recommendation.** Continue to IM-002 as a MAP run only if the owner accepts;
  IM-004 and IM-007 are equally stateless candidates. The pilot has used 1 of 3
  code PRs.

### IM-001 acceptance packet: `inspect_h2_alpn.go` → `internal/alpnpeek`

Baseline `174f157f`; source, both callers and the test file read in full.

- **Responsibility.** Read-only, bounds-checked extraction of the ALPN protocol
  list from a buffered plaintext TLS ClientHello, fail-closed (`ok=false`) on
  any inconsistency, never over-reading or panicking; plus the `h2` membership
  predicate. One cohesive concern; the security-posture comment moves verbatim
  into `doc.go`.
- **Symbols.** `inspect_h2_alpn.go` (198 lines, no build tag, no `go:embed` or
  `go:generate`): consts `tlsHandshakeClientHello`, `tlsRecordHandshake`,
  `extALPN`; funcs `parseClientHelloALPN`, `scanExtensionsForALPN`,
  `parseALPNExtension`, `clientOffersH2`; type `cursor` with `remaining`,
  `skip`, `skipVec8`, `skipVec16`, `readVec16`. `cursor` is declared nowhere
  else in root.
- **State, initialization, lifecycle.** None: no package variable, no `init`,
  no goroutine, no I/O, no logging. Input slice is borrowed read-only for the
  call; returned strings are copies. Imports nothing; uses no identifier from
  any other root file (read, not only counted). Ownership in one sentence:
  main's tunnel code owns the buffered reader and the fallback decision; the
  package owns only the parse.
- **Proposed API** (2 exported identifiers): `func Parse(buf []byte) (protos
  []string, ok bool)` and `func OffersH2(protos []string) bool`. Everything
  else unexported. Package name `alpnpeek`; files `doc.go`, `alpn.go`,
  `alpn_test.go`.
- **Production callers.** `proxy_tunnel_h2.go:312` (`parseClientHelloALPN(full)`
  inside `peekClientALPN(br *bufio.Reader) []string`) and `proxy_tunnel_h2.go:160`
  (`clientOffersH2(clientOffer)`). `peekClientALPN` stays in main: it owns the
  `bufio.Peek(5)` / `Peek(5+recLen)` window and the `["http/1.1"]` fallback,
  which is the fail-closed policy. The two call sites change to
  `alpnpeek.Parse` / `alpnpeek.OffersH2`; no root alias file is needed because
  no other production or test code references the symbols.
- **Tests.** `inspect_h2_alpn_test.go` (119 lines, default tag):
  `TestParseClientHelloALPN` (six subtests), `FuzzParseClientHelloALPN` (five
  in-code seeds; no checked-in corpus under `testdata/fuzz/`), and the helpers
  `u8`/`be16`/`be24`/`buildClientHello`. All are engine-only and move with
  names unchanged. **Root integration coverage:** no root test references
  `peekClientALPN`, `handshakeUpstreamALPN` or `newMITMClientConfigForALPN`
  directly; the fallback path is covered only indirectly by tunnel tests. The
  pilot adds no test and changes no behavior; the gap is recorded, not fixed.
- **Overlap (fresh, 2026-10-30).** Open PRs #1705 and #1528 touch
  `proxy_tunnel.go`, not `proxy_tunnel_h2.go` or `inspect_h2_alpn.go`; #1549,
  #1548, #1536 and #1526 touch neither. No semantic overlap found; recheck
  heads before the code PR.
- **CI, coverage and discovery.** No per-file coverage floor names
  `inspect_h2_alpn.go` or `proxy_tunnel_h2.go` (`.github/scripts/coverage-floor.sh`);
  the global 55% floor still counts the moved statements. The non-root lane
  discovers the package through `go list ./...`; CodeQL's path filter already
  includes `internal/**`. `.github/qa-root-shard-timings.json` names the moved
  entries, which is balancing data, not inclusion authority. **Pre-existing
  gap:** `fuzz-nightly.yml` is a hand-maintained matrix of nine targets and does
  not include `FuzzParseClientHelloALPN` today; adding
  `{ target: FuzzParseClientHelloALPN, pkg: "./internal/alpnpeek" }` is a
  workflow edit for the owner, outside the pilot's no-gate-change rule.
- **Verification plan for the code PR** (record exact SHA and output):
  `go build ./...`; `go vet ./...`; `go test -race -count=3 -shuffle=on
  ./internal/alpnpeek`; `go test -run '^$' -fuzz '^FuzzParseClientHelloALPN$'
  -fuzztime 60s ./internal/alpnpeek`; `go test -race -count=2 -shuffle=on -run
  'Tunnel|H2|ALPN|Inspect' .`; the Fast gate's pinned `golangci-lint` built with
  the `go.mod` toolchain, `--new-from-rev origin/main` plus a full-tree
  comparison; `cmd/rootshard inventory -check-list` to show the root inventory
  lost exactly the two entries and the package gained them; a boundary test in
  the package (no imports beyond stdlib, no package variable, no `init`) with a
  negative control, as `internal/identcache` does. Expected properties:
  byte-for-byte identical parser logic, unchanged fallback behavior, ADR number
  per `docs_adr_numbering_test.go` (0040 is held by #1526; 0042 is the next
  free number if #1526 keeps 0040).
- **Why this pilot first.** It is the smallest move that exercises the whole
  program mechanism (packet, review, inventory check, ADR, merge) on code
  whose behavior is fully pinned by its own tests and fuzz target. Its size is
  not the argument; its lack of state, callers and hidden dependencies is.

### IM-013 cluster CA validity policy (EXTRACT, 2026-11-20, main `491b963`)

Task record (its table row lands after #1955, which edits the same table rows,
so the two PRs do not conflict textually):

| Field | Value |
|---|---|
| ID / task | IM-013: `cluster_ca_validity.go` policy → `internal/clusterca` |
| Status | **implementation under review** (PR on `claude/modest-bell-p29x58`) |
| Depends on | — (no open PR touches `cluster_ca_validity.go` or the root test files that exercise it; #1528 edits `enrollment.go`, `healthcheck.go`, `controlplane_server.go`, which this change leaves untouched) |
| Evidence | ADR-0048; 8 exported names (`Usable`, `ClampNodeValidity`, `UnusableKind`, `Remediation`, `RenewalWindow`, `ErrUnusable`, `ErrExpired`, `ErrNotYetValid`); root keeps six one-line bindings so 0 callers and 0 tests changed; frozen-oracle differential test over a clock matrix + mutation controls; boundary test with negative controls; root test inventory 8516 → 8516 |
| Risks | message bytes are operator-visible (pinned by the oracle); the strict-`NotBefore` divergence from `internal/ca` is the security property (pinned twice) |
| Next action | review PR; add this row to the table once #1955 merges |

- **Reconciled.** IM-009 (#1941) and IM-011 (#1944) merged 2026-11-19; their
  table rows are corrected by open #1955 (IM-012), which also owns the
  saas-feed files, so IM-002/IM-003 cannot start without overlapping it.
  IM-010 still needs a benchgate measurement. IM-005/IM-006 stay blocked on
  #1526. A parse-level walk of all 463 root production files found
  `cluster_ca_validity.go` with 2 root dependencies (`clusterCA`, the type its
  two methods hang off) and a pure policy inside it.
- **Program rule.** The "one open program PR at a time" rule was already
  exceeded by #1941 and #1944, both merged by the owner; this PR runs beside
  #1955 on the same basis because the two share no source file. If the owner
  wants strict serialisation, this PR can wait for #1955 unchanged.
- **Moved:** the predicate, sentinels, kind classifier, remediation text,
  issuer clamp and renewal window. **Stays main:** the `clusterCA` instance
  (`enrollment.go`, `ha.go`), its `Usable`/`Expiry` lock reads, and every
  caller. No ADR-0002 conflict: the file is not on its list, and its
  cluster/HA row admits a separately mapped piece that is not a hub.
- **Discovered, not fixed here (pre-existing on main `491b963`).**
  `go test -race -run 'Chaos50|…' -shuffle=1795165242677438098 .` fails
  identically on unmodified main: `TestChaos50_RecoveryIsBounded`
  (`rootca_recovery_test.go:244`) reaches `StartCAAutoRotation` through
  `loadRootCA`, whose first `checkRound` reads `globalClusterCA` (`ca.go:112`);
  nothing joins that goroutine's `done` channel before the test returns, so a
  later `installClusterCA` write (`cluster_ca_chaos_test.go:98`) races it.
  Test isolation only; the fix belongs in the CA-recovery test helpers.
- **Discovered: IM-014 lead, release catalog trust kernel.**
  `release_catalog.go` (2 root dependencies, `oNoFollow` and `version`; 34
  inbound production files), `release_catalog_verify.go`, `_freshness.go`,
  `_sigstore.go`, `_bundle.go` total 1,638 lines and already speak exported
  types (`Catalog`, `TrustStore`, `CatalogSource`). Too large for one PR, and
  ADR-0002/the release row say map agent/catalog effects first. First step:
  list `Catalog`'s unexported-field readers outside `release_catalog*.go`
  (`release_dispatch*.go`, `release_api.go`) to see whether the loader +
  freshness + verify trio can move with `Catalog` as one boundary.
- **Next.** After #1955 merges: IM-002+IM-003 as one boundary (first step
  unchanged from the IM-012 note: read `saas_feed_genstore.go` exports used by
  `saas_feed_activate.go`, `_recover.go`, `_gc.go`, `_runtime.go` and count
  the alias surface). Independent of #1955: IM-014 mapping as above.

### IM-011 extraction (EXTRACT, 2026-11-18, main `348a2cf`)

IM-011 is the Shadow metrics sink split from IM-009 (its table row lands with
#1941). Status: **implementation under review** (PR pending).

- **Moved:** the `Sink` engine (counters, outcome bucketing, `View`, the
  `culvert_mcp_shadow_*` serializer) to `internal/mcp/shadowmetrics`
  (ADR-0047); 2 exported names. **Stays main:** the `sync.Once` instance, the
  never-armed nil gate on `/metrics` and status, and the live-executor reuse.
  Root keeps the two type names as aliases, so no caller changed beyond two
  `snapshot()` → `Snapshot()` sites.
- **Constraint found:** the execution-posture wall scans all module production
  files, so the package cannot import `internal/mcp/execution`; conformance is
  a test-file assertion.
- **Next:** IM-010 needs its benchgate measurement first (hot path). Before
  that, re-check IM-002/IM-003: decide the shared saas-feed validator owner by
  reading `validateFloorRecord`/`validateFloorFields` (`saas_feed_floor.go`)
  and the `fsyncDir` callers (`saas_feed_genstore.go`, `saas_feed_runtime.go`).

### IM-015 SyncRevocations budget planner (EXTRACT, 2026-11-20, main `530445b`)

Task record (the table row was added on 2026-11-20 after #1955 and #1965
merged; IM-014 is the release-catalog lead recorded under IM-013):

| Field | Value |
|---|---|
| ID / task | IM-015: `revocation_sync_budget.go` planner → `internal/session/revsync` |
| Status | **implementation under review** |
| Depends on | — (no open PR touches `revocation_sync_budget.go`, its test file or `internal/session`; the long-lived appliance branches do not contain the file) |
| Evidence | ADR-0049; 4 exported names (`Cursor`, `Request`, `BuildRequest`, `BuildResponse`); root keeps four binding names, so the two call sites (`controlplane_client.go`, `controlplane_server.go`) and all root tests are untouched; one line changed in `controlplane.go` (`!c.set` → `!c.Active()`); 2 engine tests moved with names unchanged, 3 integration tests stay root; both legs' bytes pinned by digests captured from main before the move |
| Risks | the planner is a security rule (deferred, never dropped): a wrong order or a jammed rotation delays or starves a revocation. Pinned by the moved coverage tests, the digests and three mutation checks |
| Next action | review PR |

- **Reconciled.** At selection time #1955 (IM-012) and #1965 (IM-013) were
  open with green checks and no review threads; both have since merged, so
  IM-002/IM-003 no longer overlap an open PR. IM-005/IM-006 stay blocked on #1526. IM-014 (release catalog) is a
  lead recorded in #1965.
- **Why this file.** A parse-level walk of the 464 root production files for
  cohesive engines with few root dependencies. The planner references one
  root name (`RevocationEntry`, already a `session` alias), has two call
  sites, and its state was already an instance value owned by its callers.
- **Moved:** priority classes and order, prefix + rotating window, byte
  accounting, the request envelope. **Stays main:** the budgets (derived from
  the cluster gRPC limits), the budget variables, the deferral counters,
  `/metrics` text, the log line, the cursors' owners and the RPC. No ADR-0002
  conflict: `controlplane.go` is not moved.
- **Program rule.** Opened as a third program PR beside #1955 and #1965,
  sharing no source file with either; both merged on 2026-11-20, so this is
  again the only open program PR.
- **Assessed, correctly located, no change:** `pac_fence.go` (HTTP refusal
  adapter shared by root handlers), `ocsp_coverage.go` (constant claims about
  root TLS wiring, pinned against root configs).
- **Discovered: IM-016 lead, scan-sidecar admission gate.**
  `scan_svc_admission.go` (273 ln): `scanSvcAdmissionSlots` (pure) and the
  `scanSvcAdmission` semaphore with its bounded wait are an engine; the
  process gauges (`scanSvcInflight`, `scanSvcSlots`), the 429 writer and the
  log throttle are composition. Blocked for now: `/metrics` reads the gauges
  in `metrics.go`, which open #1962 and #1963 edit. First step once they
  merge: read the gauge readers in `metrics.go` and `healthcheck.go` and
  decide whether the gate owns its in-flight count (instance method) with
  main publishing it, keeping the decrement-before-release order.
- **Discovered: smaller lead.** `ha_failover_ring.go` holds a bounded
  transition ring behind a process pointer set in `init()`; the ring type is
  about 45 lines. Too small to justify a package alone; revisit with
  `ha_fencing.go`/`ha_intent.go` if an HA state owner is mapped.
- **Next.** IM-002+IM-003 as one boundary (first step in the IM-012 note),
  now unblocked. Then IM-014 mapping (first step in the IM-013 note) and
  IM-016 as above.

### IM-021 per-key lock (EXTRACT, 2026-11-21, main `8090fdf`)

Task record (the table is edited by open #1981 and the end of this file by
open #1985; this section sits at a third anchor so the three PRs do not
conflict textually, and the IM-021 row is added once they merge):

| Field | Value |
|---|---|
| ID / task | IM-021: `keyedMutex` in `saas_feed_genstore.go` → `internal/keyedmutex` |
| Status | **implementation under review** |
| Depends on | — (#1981 touches `inspect_host_pin*.go` and `internal/hostpin`; #1985 touches `saas_feed_floor.go`, `_activation.go`, `_authority.go` and `internal/urlcatfeed`; no open PR changes `saas_feed_genstore.go`, `cdr_lineage.go`, `cdr_ui.go` or `cdr_health.go`) |
| Evidence | ADR-0054; 2 exported names (`New`, `Mutex`) and one method (`Lock`); body moved statement for statement; 9 call sites in 4 root files name the package, no root binding; no existing test named the type, so none moved or changed; 6 new engine tests, boundary test with 9 negative controls, 4 mutation checks |
| Risks | the lock orders CDR renew/revoke/delete/enroll and same-id generation persists. The algorithm is unchanged and the root tests of both owners pass unedited |
| PR | #1988 |
| Next action | review PR |

- **Reconciled.** #1981 (IM-019) and #1985 (IM-020) are open; on both, every
  non-skipped check passed and there is no review thread, so there was
  nothing to fix. IM-005/IM-006 stay blocked on #1526.
- **Why this.** The IM-019 count named `keyedMutex` as an owner that falls
  out of the IM-003 surface: a generic lock declared in the generation store
  file and also used by the CDR control plane (`cdrLifecycle`). It read no
  root symbol and no test reached into it, so it could move whole.
- **Moved:** the `keyedMutex` and `keyedEntry` types, the constructor and
  `lock`, as `keyedmutex.Mutex`, an unexported `entry`, `New` and `Lock`.
  **Stays main:** the `cdrLifecycle` instance and its key vocabulary, the
  generation store and its per-id use of the lock.
- **Size.** 4 root production files edited (−52/+13 lines;
  `saas_feed_genstore.go` 539 → 499), 2 new production files (63 lines with
  the package comment). Root test inventory unchanged (8,590 entries on
  main and on this change); package 8 tests.
- **Effect on IM-003.** One name fewer read from the genstore file (16 → 15)
  and the `keyedMutex` owner question is closed. IM-003 stays blocked on the
  store's own surface.
- **Discovered: IM-022 lead, directory fsync.** `fsyncDir` and
  `isBenignDirSyncErr` in `saas_feed_genstore.go` repeat
  `fileutil.syncDirTolerant` (same EINVAL/ENOTSUP/EOPNOTSUPP tolerance, same
  close-error rule) with one real difference: `fsyncDir` returns the
  directory-open error and `fileutil` swallows it. `fsyncDir` is called from
  `saas_feed_genstore.go` and `saas_feed_reverify.go`;
  `cmd/culvert-maint/internal/journal` has its own. Not a blind merge: the
  strict open is a durability decision of the generation store and must be
  kept.
- **Next.** IM-022. First step: read `fileutil.syncDirTolerant` and its
  callers, `fsyncDir`'s callers, and `TestF3b2_*` cases that inject a
  dir-sync failure through `genFS`, and decide whether `fileutil` exports one
  strict directory sync (open failure returned) that the tolerant form
  calls, with a differential test against a frozen copy of `fsyncDir`. It has
  no prerequisite and no open-PR overlap today. After it: the IM-018
  prerequisite (pool-supplied breaker clock), the single strict decoder for
  the three F3 records once #1985 merges, then IM-014 mapping.
- **Seen again, not fixed here (pre-existing on main `8090fdf`).** The
  order-dependent `TestDec2EB_RotationChangesObservableGeneration` failure
  recorded under IM-020 (#1985) reproduced: seed 1795248876535768401 fails it
  identically on unmodified main (`decryption_2eb_red_test.go:186`, same
  `key_id` before and after rotation). The selection matched it only through
  the word `Generation`. Still undiagnosed.

### IM-022 directory fsync rule (ORGANIZE, 2026-11-21, main `c5674f2`)

- **Reconciled.** IM-019 (#1981), IM-020 (#1985) and IM-021 (#1988) all
  merged on 2026-11-21; their rows are updated or added. No program PR was
  open. Open PRs are #1526 (IM-006), #1987 (geoip) and the appliance set
  (#1528, #1536, #1548, #1549, #1705); none changes `saas_feed_genstore.go`,
  `saas_feed_gc.go`, `support_durable_write.go` or `internal/fileutil`.
- **Finding.** The rule "fsync a directory, treat EINVAL/ENOTSUP/EOPNOTSUPP
  as a filesystem that cannot do it, report the close error only after a
  good fsync" was written four times: `fsyncDir` + `isBenignDirSyncErr`
  (root, generation store and GC), `syncDirTolerant` and
  `syncParentAfterRename` (`internal/fileutil`), and `syncDirEntry`
  (`support_durable_write.go`, whose comment already named a single exported
  `fileutil` primitive as the right end state).
- **Organized.** `internal/fileutil/syncdir.go` owns the rule:
  `DirSyncUnsupported(err)` is the errno set and `SyncDir(dir)` is the strict
  form. `fsyncDir` and `isBenignDirSyncErr` are deleted from root; the two
  production seams (`osGenFS`, `osGCFS`) name `fileutil.SyncDir`. `AtomicWrite`
  and `syncDirEntry` keep their own structure and call the predicate.
- **What was deliberately not merged.** Whether an unopenable directory is a
  failure stays each caller's decision: the generation store and GC fail
  (strict), `AtomicWrite`/`WriteFileExclusive` skip it, and `syncDirEntry`
  skips it, ignores the read-only handle's close result and logs. None of
  those outcomes changed.
- **Evidence.** Both former decision bodies are frozen in
  `syncdir_test.go` and compared, by returned error identity, with the shared
  rule over 196 (sync, close) outcome pairs; open-failure behavior is pinned
  on a real missing path for both forms; a file-scoped boundary test with
  negative controls keeps `syncdir.go` free of package state and of imports
  beyond `errors`, `os`, `syscall`, and fails if another `fileutil` production
  file spells the errno set again. Six mutation checks; one (dropping
  `ENOTSUP`) is an equivalent mutant on Linux, where it equals `EOPNOTSUPP`.
- **Size.** 4 production files edited (−68/+10 lines), 1 new production
  file, 1 new test file. No existing test moved or edited; test inventory
  13,831 → 13,838 (7 new, none removed). No ADR: no new package and no
  ownership decision beyond the one `support_durable_write.go` recorded.
- **Effect on IM-003.** Two more names leave the genstore file's outward
  surface (`fsyncDir`; `isBenignDirSyncErr` was file-local). IM-002/IM-003
  stay blocked on the store's own surface.
- **Left alone, with reasons.** `internal/mcp/events/spool.syncDir` returns
  the close error even after an unsupported fsync, so it is not the same
  rule; `internal/storeguard.syncDir` has no tolerance at all (deliberate for
  the fault marker); `cmd/culvert-maint/internal/journal` is a separate
  binary's owner. The spool difference looks accidental rather than decided
  and is worth one question to its owner, not a silent change.
- **Next.** The IM-018 prerequisite, in main and needing no package: the CDR
  pool supplies its breaker's clock at construction and resolves the
  fallback deadline before it builds a breaker. First step: read
  `newCDRBreaker`'s callers and the three test files that call `b.setNowFn`
  on a pool-built breaker (`cdr_breaker_nonrpc_probe_test.go`,
  `cdr_breaker_wedge_chaos_test.go`, `cdr_rpc_reservation_wall_test.go`).
  Independent and smaller: one strict decoder for the three F3 records
  (differential test over `TestFloor_StrictDecode_Rejections`). Then IM-014
  mapping.

### IM-002 / IM-007 mapping (MAP, 2026-11-09, main `09235d1`)

Evidence only; no code moved. Nothing in the repository records the owner's
acceptance of pilot continuation after the IM-001 assessment, so no further
code PR was started.

- **IM-002 (`saas_feed_floor.go`).** Source read. It is node-local durable
  floor/commit-intent state with its own codec, CRC-32C, two-record write
  quorum, selection, equivocation detection and recovery classification, and
  already takes its filesystem through the narrow `floorFS` seam and
  `fileutil.AtomicWrite`. That is a good engine. The obstacles are boundary,
  not code quality: (1) six root production files consume it
  (`saas_feed_activate`, `_activation`, `_checkpoint`, `_gc`, `_recover`,
  `_runtime`) and seven root test files reference it, so aliases would carry a
  wide surface (`floorRecord`, `floorStore`, `floorRecovery`, `floorHealth`,
  `floorWatermark`, `floorFS`, `floorReadStatus`, `selectFloor`, ...), above the
  8-identifier guideline; (2) its validators `validGenerationID`,
  `validSHA256Hex` and `canonicalUTCSecond` are shared with three to five other
  saas-feed root files, so they need a decided owner first (moving them into
  `feedfloor` would make it a helper hub; duplicating them would fork a
  validation rule); (3) `saas_feed_genstore.go` (IM-003) shares `fsyncDir` and
  the generation-identity rules, so IM-002 alone splits one subsystem. The file
  header states the subsystem is UNWIRED until F3b-3; verify current wiring in
  `saas_feed_runtime.go` before design. Verdict: map IM-002 and IM-003 together
  as one boundary only after the helper-owner decision; do not extract the
  floor alone.
- **IM-007 (`realclientip.go`).** Not a pure move. Trusted-proxy CIDRs are a
  process global (`trustedProxyNets` under `trustedProxyNetsMu`) mutated by
  `SetTrustedProxyCIDRs`; 32 non-test references sit outside the file. Per the
  ADR-0038 pattern, an instance owner constructed in main must land first, then
  the move. The trust gate (XFF honoured only from a configured trusted peer)
  is the security contract and must stay byte-for-byte.
- **Recommended next.** IM-004 (`upstream_backup_strip.go`, 517 ln, 0 root deps,
  2 inbound) is the remaining stateless candidate. First step: read
  `upstream_backup_strip.go` and classify its 12 referencing test files into
  engine-only versus integration, and define the byte-identical output fixture.
  IM-004 still needs the owner's pilot-continuation acceptance (2 of 3 code PRs).

### IM-017 frontend artifact validator (EXTRACT, 2026-11-20, main `5333aab`)

Task record (kept out of the table because open #1955 edits those rows; open
#1965 and #1966 add their records at other anchors, so the four PRs do not
conflict textually; the row is added once they merge):

| Field | Value |
|---|---|
| ID / task | IM-017: `ui_frontend_v2.go` embedded-artifact validator → `internal/frontendbundle` |
| Status | **implementation under review** |
| Depends on | — (no open PR touches `ui_frontend_v2.go` or its test file; the six long-lived branches carry the same blobs as main for both) |
| Evidence | ADR-0050; 3 exported names (`Validate`, `Asset`, `ManifestEntry`); root keeps `validateFrontendV2` as a binding and `frontendV2Asset` as an alias, so the one caller and the handlers are unchanged apart from `asset.ContentType`; 7 validator tests moved with names unchanged, the real-dist half of `TestFE1B_ShellManifestBinding` stays root under the same name; 53-tree verdict table captured from main before the move; root file 727 → 273 lines |
| Risks | the error text decides ready versus 503 and reaches the log; content types are served under `nosniff`. Both are pinned byte for byte by the verdict table and the content-type oracle |
| Next action | review PR |

- **Reconciled.** #1955 (IM-012), #1965 (IM-013) and #1966 (IM-015) are open
  with passing or still-running checks and nothing to fix. IM-002/IM-003 still
  overlap #1955; IM-005/IM-006 stay blocked on #1526.
- **Why this file.** A per-function walk of the 465 root production files for
  functions that reference no other root file. `ui_frontend_v2.go` held about
  450 lines of validator whose only root references were `sanitizeLog` and a
  MIME table nothing else read.
- **ADR-0002.** It lists `ui_*.go` as main-owned. That stays true for the
  routes, handlers, gate and published state, which did not move. ADR-0050
  narrows it for the validator only.
- **Gate surface kept.** `pr-fast-gate.yml` classifies `ui_frontend_v2*` as
  frontend surface. The PR adds `internal/frontendbundle/*` to the same `case`
  so a validator change still runs the frontend job. Nothing is removed.
- **Program rule.** This is a fourth open program PR. It shares no source file
  with the other three.
- **Assessed and blocked: IM-018 lead, CDR circuit breaker.**
  `cdr_breaker.go` (607 ln) is a real state machine with an instance-owned
  lock and injected clocks, and production callers use only its exported
  methods. It cannot move yet: root integration tests install a clock on a
  pool-built breaker after construction (`b.setNowFn` in
  `cdr_breaker_nonrpc_probe_test.go`, `cdr_breaker_wedge_chaos_test.go`,
  `cdr_rpc_reservation_wall_test.go`) and read `halfOpenTried`, `staleProbes`
  and `cfg.*` directly (also `cdr_fail_closed_unavailable_test.go`,
  `diagnostics_cdr_capacity_test.go`, `cdr_breaker_overflow_test.go`). Moving
  the type would need exported setters and accessors for tests only, which the
  program's stop rule forbids. `withDefaults` also reads the published CDR
  config (`cdrEffectivePerFileDeadline`). Prerequisite, in main first: the pool
  takes its breaker clock at construction, the fallback deadline is resolved
  by the pool before it builds a breaker, and those tests assert through
  `Stats()` and behavior. #1963 (which edited `cdr_ui.go`, `cdr_health.go` and
  `cdr_startup.go`) merged on 2026-11-20, so no open PR overlaps it now.
- **IM-016 is unblocked.** #1962 and #1963 merged and neither left an open
  edit to `metrics.go`. The gate can take its in-flight observer as constructor
  options so the two process gauges and their readers stay in main.
- **Next.** IM-016 (first step: read the `scanSvcInflight` and `scanSvcSlots`
  readers in `metrics.go:1499` and `scan_svc.go:427`, and the override seam in
  `scan_svc_admission_chaos_test.go`). After #1955 merges: IM-002+IM-003 as one
  boundary. Then the IM-018 prerequisite above.
- **Discovered, not fixed here.** A full root run
  (`go test -race -count=1 -shuffle=1795175878818164299 .`, 2,324 s) reported
  21 data races, all the same one: `TestLoadUIAccessPolicy_IdPProfilesMissingFileIsNonFatal`
  (`ui_access_policy_startup_test.go:179`) reaches
  `go runIdPMetadataDegradationWatchdog(resolveLifecycleCtx())`
  (`ui_access_policy_startup.go:116`), which nothing stops when the test ends;
  every 2.5 minutes its round reads `idpRegistry`
  (`idp_metadata_health.go:993`) while later tests swap that global
  (`withTestIdPRegistry`, `chaos87Env`, `startAuthProxy`, ...). Test isolation
  only, and it needs a run longer than the tick to show. None of those files
  is in this change. The fix belongs in the test: give it a cancellable
  lifecycle context and join the watchdog.

### IM-016 scan-sidecar admission gate (EXTRACT, 2026-11-20, main `28de730`)

- **Reconciled.** No program PR is open: IM-012 (#1955), IM-013 (#1965),
  IM-015 (#1966) and IM-017 (#1972) all merged on 2026-11-20; the IM-015 row
  is updated and the IM-017 row added. Open PRs are #1526 (IM-006) and the
  appliance set (#1528, #1536, #1548, #1549, #1705). Their six branches
  predate CHAOS-115 and do not contain `scan_svc_admission.go` or its test
  file; `metrics.go` is not edited here.
- **Moved:** the slot arithmetic, the semaphore, the bounded wait and the
  gauge-before-slot release (`gate.go`, 8 exported names: `HeapBudget`,
  `MinSlots`, `MaxSlots`, `QueueWait`, `Slots`, `Options`, `Gate`, `New`).
  **Stays main:** the process gauges `scanSvcInflight`/`scanSvcSlots` and
  their readers (`metrics.go`, `/health`), the slot-count test seam, the 429
  and its counter, the refusal line. Root file 273 → 173 lines; `scan_svc.go`
  changed on four lines plus the import.
- **Gauge ownership, decided.** The lead asked whether the gate should own its
  in-flight count. It takes the gauge as `Options.Inflight`
  (`*atomic.Int64`): main hands it `&scanSvcInflight`, so every reader and
  root test is unchanged and the gate is the gauge's only writer. A gate
  built without one counts privately.
- **Tests.** 2 arithmetic tests moved with names unchanged; 8 handler-level
  `TestChaos115_*` tests and the `benchgate` heap measurement stay root,
  unedited. 11 new engine tests plus the boundary pair. Root inventory:
  2 fewer top-level tests, as the rootshard comparison is expected to show.
- **ADR-0002.** No conflict: the sidecar files are not on its list.
- **Next.** IM-002+IM-003 as one boundary. Nothing open overlaps
  `saas_feed_*.go` now. First step: list the names `saas_feed_activate.go`,
  `saas_feed_recover.go`, `saas_feed_gc.go` and `saas_feed_runtime.go` use
  from `saas_feed_floor.go` and `saas_feed_genstore.go`, and count the
  surface a combined floor+genstore package would export; if it is above 8,
  record the API pressure and decide between two packages (floor record
  codec, generation store) and one. After that: the IM-018 prerequisite
  (pool-supplied breaker clock) and IM-014 mapping.

### IM-019 inner-host pin predicate (EXTRACT, 2026-11-20, main `0fe4578`)

- **Reconciled.** IM-016 (#1975) merged on 2026-11-20; its row is updated. No
  program PR was open. Open PRs are #1526 (IM-006) and the appliance set
  (#1528, #1536, #1548, #1549, #1705); none changes `inspect_host_pin.go`,
  its test file or `internal/hostutil`. #1528 and #1705 edit
  `proxy_tunnel.go`, which this change does not touch.
- **IM-002+IM-003 measured and blocked.** The first step recorded under
  IM-016 was done: other root production files read 23 top-level names from
  `saas_feed_floor.go` (among them `floorRecord`, `floorStore`,
  `floorRecovery`, `floorWatermark`, `floorFS`, `floorHealth` and three of
  its values, `floorReadStatus` and three of its values, `selectFloor`,
  `readBothFloorRecords`, `floorSchemaVersion`) and 16 from
  `saas_feed_genstore.go` (the candidate, meta and store types, seven file
  and schema constants, `sha256Hex`, `fsyncDir`, `newKeyedMutex`). That is 39
  names before any struct field or method, against a guideline of 8, and
  root test files also reach unexported floor names (`floorFileA`/`B` in
  five). Two packages do not help: the split leaves the floor alone at 23.
  The real boundary is the F3 node-local store as a whole (`saas_feed_floor`,
  `_genstore`, `_activation`, `_authority`, `_gc`, `_reverify`, `_recover`,
  `_activate`: about 3,600 lines in 8 files), which is over the program's
  size bound for one change. Two smaller owners fall out of the count:
  IM-020 (the canonical record codec, which six files outside the floor
  call) and `keyedMutex`, a generic per-key lock declared in the genstore
  file and also used by `cdr_lineage.go`.
- **Why this file instead.** The parse-level walk of the 466 root production
  files showed `inspect_host_pin.go` reading four root names, all of them in
  its gate half (`logger`, `sanitizeLog`, `statBlocked`, `blockResponder`).
  The predicate half read none.
- **Moved:** `innerHostPinnedToTunnel`, `innerAuthorityAsSent` and
  `innerAuthorityBracketsValid` with their comments, as `hostpin.Pinned` and
  two unexported helpers. **Stays main:** the refusal counter and its
  `/metrics` series, `blockInnerHostMismatch` (log line and 403), the scope
  statement, and the call in `runInspectExchange`. Root file 368 → 136
  lines.
- **Tests.** 3 predicate tests moved with names unchanged; 8
  `TestInnerHostPin_*` tests stay root, unedited, including the SWG-002
  contract test. New in the package: a 1,386-pair verdict table whose digest
  was captured from main before the move, a fuzz target over the wire
  oracle, a concurrent-call test and the boundary pair.
- **Product contract.** SWG-002 lists `inspect_host_pin.go`; the registry
  gains `internal/hostpin/pin.go` as a further code path so the contract
  follows the predicate. No entry is reworded and no test is dropped.
- **ADR-0002.** No conflict: the request path stays in main and the file is
  not on its list.
- **Next.** IM-020: read the six callers of `floorCanonicalBytes`
  (`saas_feed_activation.go`, `_authority.go`, `_client.go`, `_gc.go`,
  `_genstore.go`, `_reverify.go`) and the two of `floorCRCTable`, and decide
  whether the codec is feed-protocol grammar (then `internal/urlcatfeed`,
  as IM-012) or a node-local record format (then its own small package).
  It has no prerequisite and no open-PR overlap. After it: the IM-018
  prerequisite (pool-supplied breaker clock), then IM-014 mapping.
- **Discovered, not fixed here (pre-existing on main `0fe4578`).** Under CPU
  load, `go test -race -count=2 -shuffle=on -run
  'InnerHostPin|Tunnel|Inspect|H2|PlaintextFallback' .` failed 2 of 8 runs on
  unmodified main (seeds 1795216508587846871 and 1795216666073957688) and 0
  of 8 on this change. One race: `setTunnelIdleTimeout`
  (`proxy_tunnel_idle_test.go:24`) writes the package variable
  `tunnelIdleTimeout` while a relay goroutine left running by an earlier test
  reads it (`idleCopyCounted`, `proxy_tunnel.go:309`); `swapMonoNanos`
  (`monotime_chaos_test.go:42`) has the same shape for `monoNanos`, read at
  `proxy_tunnel.go:270`. It surfaced in
  `TestChaos83_TunnelReaperFiresOnMonotonicElapsed` and
  `TestTunnelIdle_ActiveDirectionKeepsSilentDirectionAlive`. Test isolation
  only. The fix belongs in those tests: join the relay goroutines before the
  cleanup restores the variable.

### IM-009 extraction and next selection (EXTRACT, 2026-11-18, main `348a2cf`)

- **Reconciled.** IM-007 (#1892) and IM-008 (#1845) are merged; their rows
  said "under review". Open PRs: #1526 (policy design, IM-006), the appliance
  set (#1528, #1536, #1548, #1549, #1705). None touches MCP code, so the IM-009
  overlap check passed.
- **Split.** IM-009 named two files with different responsibilities. The
  evidence read model is a pure projection over `rollout.EvidenceSummary` and
  moved (ADR-0046). The Shadow metrics sink is a process singleton and is now
  IM-011.
- **Recommended next: IM-011.** It is the remaining MCP root file with a
  narrow owner (`internal/mcp/execution.Metrics` is the interface it
  implements) and no open-PR overlap. Prerequisite: an instance owner in main;
  the singleton's nil-ness is a contract (`/metrics` emits nothing on a node
  that never armed Shadow), so it must survive byte-for-byte. First step: read
  `newMCPShadowMetrics` callers in `mcp_shadow_startup.go` and
  `mcp_live_startup.go`, and the `shadowMetricsView` delta assertions in
  `shadow_soak_test.go`. IM-002/IM-003 stay mapped-not-ready until the shared
  saas-feed validator owner is decided; IM-010 still needs a benchgate
  measurement before mapping.

### IM-012 saas-feed field grammar owner (ORGANIZE, 2026-11-19, main `491b963`)

- **Reconciled.** IM-009 (#1941) and IM-011 (#1944) merged on 2026-11-19; rows
  updated. Open PRs: #1526 (IM-006) and the appliance set (#1528, #1536,
  #1548, #1549, #1705); none touches `saas_feed_*.go` or `internal/urlcatfeed`.
- **Finding.** The IM-002 blocker "where do `validGenerationID`,
  `validSHA256Hex`, `canonicalUTCSecond` live" was partly a duplicate-rule
  problem: `internal/urlcatfeed/verify.go` (the feed protocol's trust kernel)
  already carried private copies of the timestamp and digest rules, and the
  node-local F3 records bind exactly those manifest values. The protocol is
  the owner. IM-012 exports them (`ParseCanonicalRFC3339`, `IsSHA256Hex`) and
  makes the root names one-line bindings; no root caller changed. The rune vs
  byte loop difference is not observable at length 64 (any non-ASCII byte or
  `RuneError` falls outside `[0-9a-f]`); the frozen-oracle differential test
  covers that case and invalid UTF-8.
- **Not moved.** `validGenerationID` is not wire grammar (no `generation_id`
  field in `urlcatfeed`); it is the node-local generation store's path-segment
  identity and belongs with the IM-002+IM-003 engine. `validCRC32Hex` is
  floor-record-only and moves with the floor. `fsyncDir` stays a genstore/gc
  concern (`cmd/culvert-maint` has its own).
- **Next.** IM-002+IM-003 as one boundary. First step: read
  `saas_feed_genstore.go` exports used by `saas_feed_activate.go`,
  `_recover.go`, `_gc.go` and `_runtime.go`, and count the alias surface the
  combined floor+genstore package would need (the 8-name guideline was the
  other IM-002 blocker). IM-010 still needs a benchgate measurement; its
  three files are mostly process-global atomics, log throttles and HTTP
  writers, so only the pure bound predicates are candidates.

### IM-026 data-directory single-writer lock (EXTRACT, 2026-11-21, main `ef9431189`)

Task record (open #1992 appends at the end of this file and open #1993
inserts before the IM-023 section, and both leave the task table alone until
they merge; this section sits before the IM-020 one, an anchor neither
touches, and the IM-026 row is added once they merge):

| Field | Value |
|---|---|
| ID / task | IM-026: the lock acquisition in `datadir_writer_lock.go` and its two platform files → `internal/writerlock` |
| Status | **implementation under review** |
| Depends on | — (no open PR changes `datadir_writer_*.go` or `internal/storeguard`, checked against all eight open PR heads; #1992 edits `mcp_telemetry*.go`, #1993 edits `mcp_live_*.go` and `mcp_rollout.go`) |
| Evidence | ADR-0058; 8 exported names (`Take`, `Attempt`, `Verdict`, `Acquired`, `Held`, `Undetermined`, `Lock`, `FileName`); acquisition body moved statement for statement; root keeps its five names as bindings, so `main.go`, `datadir_writer_diagnostics.go` and all 12 root tests are unedited; 14 new engine tests and a boundary pair with 12 negative controls; 18 mutation checks, 17 failing a new test |
| Risks | the lock is what refuses a second process on one data directory (CHAOS-103), and a second process keeps the unauthenticated first-run window open. The unedited root tests pin the refusal, the override, the degraded cases, the first-boot directory creation and the order against `checkInterruptedRestore` |
| Next action | review PR |

- **Reconciled.** #1991 (IM-023) merged. #1992 (IM-024): every non-skipped
  check passed, no review thread. #1993 (IM-025): checks were still running
  when this run started, none failed, no review thread. Nothing to fix in
  either. IM-005/IM-006 stay blocked on #1526.
- **Why this file.** A parse-level count, for each root production file, of
  the names it reads from other root files. `datadir_writer_lock.go` read
  two: the flock function in its own platform files, and `logger`. The
  acquisition reads neither a logger nor configuration; the boot decision
  does. The acquisition also wrote its result into a package variable from
  inside the function, so it could not run without touching process state.
- **Moved:** the directory creation, the lock-file open, the non-blocking
  exclusive flock and its non-unix stub, the three verdicts and the file
  name. `Take` returns the open lock; main stores it where it did before.
  **Stays main:** `checkDataDirSingleWriter` and its place in `main()`, the
  `CULVERT_ALLOW_MULTIPLE_WRITERS` override, the refusal and notice texts,
  the deferred log line, the posture and its Diagnostics row.
- **The entry point is `Take`, not `Acquire`, because of an existing wall.**
  `TestChaos71_Wall_EveryLeaseGrantIsInstalledOrCleared` fails any root
  function other than `acquireLeaseAttempt` that calls something named
  `Acquire`: the name is how it recognizes an HA lease acquisition. The first
  draft of this change tripped it. The wall is unedited; the package uses a
  name it does not key on. `TryLock` was passed over for the same reason
  (`ha_alert_lock_chaos_test.go` keys on it).
- **Size.** Root: 3 production files → 1 (282 → 195 lines). Package: 4
  production files, 164 lines with the package comment. Root test inventory
  unchanged.
- **ADR-0002.** No conflict: the files postdate "Decomposition Complete" and
  are not classified there; startup and the boot decision stay in main. The
  earlier decision not to share `internal/storeguard`'s flock (different lock
  lifetime) is kept: a separate package, no import of `storeguard`.
- **Program rule.** This is a third open program PR beside #1992 and #1993.
  It shares no source file with either; all three edit this document at
  different anchors, and ADR numbers 0056 and 0057 are left to them.
- **Looked at and left in main.** `socks5_posture_gate.go` (188 lines, 90 of
  them the file comment) is three atomics and two log lines read by
  `socks5.go`, `metrics.go` and startup; a package for it would be smaller
  than its import line is worth. `configsnapshot_apply_health.go` is two
  atomics. Both are correctly located.
- **Next.** The support upload queue: `support_upload_queue.go` (379 lines)
  holds the queue entry record, its per-bundle file store, the state
  vocabulary, the retry backoff and the drain step, and reads five root
  names (`dataDir`, `durableSupportWrite`, `mkdirDurableSupport`,
  `sanitizeLog`, `supportBundleIDRe`). `internal/supportupload` already owns
  the transfer and its `Receipt`. First step: read
  `support_durable_write_chokepoint_test.go` and
  `support_upload_arch_test.go` to see which of them key on the root file
  path, then list what `support_upload_worker.go` and `support_upload_wire.go`
  read from the queue, and decide whether the directory and the two durable
  write functions become constructor options of a queue instance. It has no
  open-PR overlap today. Unchanged alternatives: `mcp_rollout_execdeps.go`
  once #1993 is decided, one strict decoder for the three F3 records, then
  IM-014 mapping.

### IM-020 saas-feed node-local record codec (EXTRACT, 2026-11-21, main `0fe4578`)

Task record (the IM-020 table row is added by open #1981, which edits the
table; this section sits at a different anchor so the two PRs do not conflict
textually, and the row's status is updated once #1981 merges):

| Field | Value |
|---|---|
| ID / task | IM-020: canonical bytes + CRC-32C seal of the F3 node-local records → `internal/urlcatfeed/noderecord` |
| Status | **implementation under review** |
| Depends on | — (#1981 touches `inspect_host_pin*.go` and `internal/hostpin` only; no open PR changes `saas_feed_*.go` or `internal/urlcatfeed`) |
| Evidence | ADR-0053; 4 exported names (`Canonical`, `Checksum`, `Seal`, `ValidChecksum`); `urlcatfeed` exports its one encoder as `CanonicalJSON`; root keeps `floorCanonicalBytes` and `validCRC32Hex` as bindings, so the six calling files and every existing root test are unchanged; frozen-oracle differential tests, RFC 3720 vectors, fuzz target, boundary test with negative controls; activation and authority record bytes captured from main before the bind |
| Risks | the bytes and the checksum decide whether a record already on disk is accepted after an upgrade. Pinned by the three records' full-byte goldens and six mutation checks |
| Next action | review PR |

- **Reconciled.** #1981 (IM-019) is open with every non-skipped check passed
  and no review thread, so there was nothing to fix. IM-016 (#1975) is merged.
  IM-005/IM-006 stay blocked on #1526. The appliance set (#1528, #1536,
  #1548, #1549, #1705) does not contain the saas-feed files' current blobs.
- **The lead's question, answered.** "Feed-protocol grammar or node-local
  format" was both, in two parts. `floorCanonicalBytes` was a second copy of
  `urlcatfeed.canonicalJSON` (the same finding as IM-012), so the byte form
  is the protocol's and there is now one encoder. The CRC-32C seal is
  node-local corruption detection and is not authenticity, so it does not
  belong in the protocol's trust kernel; it is the new subpackage's.
- **Moved:** the encoder copy (deleted, bound to the protocol's), the
  Castagnoli seal and its `%08x` form, the 8-lowercase-hex predicate.
  `floorCRCTable`, `isLowerHex` and `isHexByte` are gone from root.
  **Stays main:** the four record types, their field validation, strict
  decoders, sentinel errors, files, the floor quorum and `validGenerationID`.
- **Size.** 3 root production files edited (−58/+26 lines), 1 line-group
  added to `internal/urlcatfeed/jsonstrict.go`, 2 new production files. No
  existing test moved or edited; root inventory 8,352 → 8,354 (2 new tests, none removed), package 12 entries.
- **Effect on IM-002.** Modest and stated as such: other root files now read
  22 names from `saas_feed_floor.go`, not 23 (`floorCRCTable` is gone);
  `floorCanonicalBytes` leaves the count only when its six callers name the
  package. IM-002 and IM-003 stay blocked on surface.
- **Next.** The IM-018 prerequisite, which is in main and needs no package:
  the CDR pool supplies its breaker's clock at construction and resolves the
  fallback deadline before it builds a breaker. First step: read
  `newCDRBreaker`'s callers and the three test files that call `b.setNowFn`
  on a pool-built breaker (`cdr_breaker_nonrpc_probe_test.go`,
  `cdr_breaker_wedge_chaos_test.go`, `cdr_rpc_reservation_wall_test.go`), and
  decide whether a pool option carries the clock. Smaller and independent:
  one strict decoder for the three F3 records (same shape, different
  sentinels; needs a differential test over the rejection table in
  `TestFloor_StrictDecode_Rejections`). Then IM-014 mapping.
- **Discovered, not fixed here (pre-existing on main `0fe4578`).**
  `go test -race -count=2 -shuffle=1795244492712948356 -run
  'IM020|Floor|F3b|F3c|Activation|Authority|SaaSFeed|SaasFeed|Genstore|GenStore|Generation|Reverify|ADRNumbering|Urlcat|URLCat' .`
  fails identically on unmodified main:
  `TestDec2EB_RotationChangesObservableGeneration`
  (`decryption_2eb_red_test.go:186`) reports the same `key_id` before and
  after a rotation. The selection matched it only through the word
  `Generation`; it is a decryption-redaction test and shares no file with
  this change. It passes under other orders, so it depends on what ran
  before it. Not diagnosed further here.

### IM-023 qualification inventory document (EXTRACT, 2026-11-21, main `6795ec63a`)

Task record (the table is edited by open #1989 and #1990, so the IM-023 row
is added once one of them merges; this section sits at the end of the file,
an anchor neither touches):

| Field | Value |
|---|---|
| ID / task | IM-023: the QUAL-2 inventory read, decode, validation and seeding in `mcp_inventory.go` → `internal/mcp/qualinventory` |
| Status | **implementation under review** |
| Depends on | — (no open PR changes `mcp_inventory*.go`, `mcp_peer_refresh_wall_test.go`, `internal/mcp/catalog` or `internal/mcp/registry`; the appliance branches carry no MCP edit) |
| Evidence | ADR-0055; 7 exported names (`ReadFile`, `Decode`, `Seed`, `Doc`, `ServerEntry`, `ToolEntry`, `MaxFileBytes`); bodies moved with only the names substituted; root keeps three bindings and one alias, so `loadQualificationInventory` and the ten root test files that build fixtures through them are unedited; 3 engine tests moved with names unchanged, 18 `TestInventory_*` tests stay root; 87-document verdict table whose digest was captured from main before the move |
| Risks | the engine decides which operator inventory file is accepted and what lands in the registry the Gateway resolves against. Pinned by the verdict table (error phrase, both revisions, every stamped field and fingerprint) and the unedited activation tests |
| Next action | review PR |

- **Reconciled.** IM-019 (#1981), IM-020 (#1985) and IM-021 (#1988) merged on
  2026-11-21; their table rows still say "under review" or are missing, and
  #1989 corrects them. **Two open PRs implement IM-022**, #1989 and #1990,
  from two sessions started minutes apart; they edit the same four files
  (`saas_feed_genstore.go`, `saas_feed_gc.go`, `internal/fileutil/fileutil.go`,
  a new `syncdir.go`) and cannot both merge. Both have passing checks and no
  review thread, so there is nothing to fix in either; which one stays is the
  owner's call. #1989 is the wider one (it also binds
  `support_durable_write.go` and `AtomicWrite` to the shared predicate and
  updates the table). IM-005/IM-006 stay blocked on #1526.
- **Why this file.** A per-function walk of the 468 root production files
  for functions that read no name from another root file.
  `mcp_inventory.go` had about 350 such lines: an input engine for an
  operator-supplied file, with four `internal/mcp` imports and nothing else.
- **Moved:** the bounded read, the strict decode, the three document shapes,
  the opaque-field and route-safe-id rules, the capability and
  destination-class vocabularies, the Register → VerifyIdentity → Ingest →
  optional-disable seeding and the bounded error phrases. **Stays main:**
  `loadQualificationInventory` (reads the startup config, returns the state),
  the state type, the published holder, the Admin API adapters and the
  status view. Root file 604 → 261 lines.
- **The provenance wall moved with the code.**
  `TestPeerWall_SeedReachesOnlyTheSeededEntrypoint` names the one production
  function allowed to call `catalog.Ingest` by `file:Func`. The entry is now
  `internal/mcp/qualinventory/inventory.go:seedTools`, as the wall's own
  failure text instructs for a moved path, and its converse check
  (`IngestObserved` must not be named by the provisioning path) covers the
  root file and the new package. This is the one edit to an existing test
  beyond removing the three moved ones; it needs a reviewer's eye.
- **ADR-0002.** No conflict: MCP composition stays in main, and the engine
  was not composition.
- **Program rule.** This is a third open program PR beside the two IM-022
  PRs. It shares no file with either except this document, at a different
  anchor.
- **Not done.** `fuzz-nightly.yml` is a hand-maintained matrix; adding
  `{ target: FuzzDecodeSeed, pkg: "./internal/mcp/qualinventory" }` is a
  workflow edit left to the owner, as for IM-001.
- **Discovered: IM-024 lead, qualification archive exporter.**
  `mcp_telemetry.go` (915 lines) ends with `qualArchiveExporter`,
  `telemetryCursorStore`, `validateBatch` and `buildArchiveBatch` (about 330
  lines from line 585). Only `mcp_telemetry.go` and `mcp_telemetry_test.go`
  name them. They write files, so unlike IM-023 the package would own
  durable output: map the fsync and rename rules and the `events.Exporter`
  interface it implements before sizing.
- **Next.** IM-024. First step: read `mcp_telemetry.go:585-915`, list which
  `mcp_telemetry_test.go` tests reach unexported exporter or cursor fields,
  and check whether `internal/mcp/events` already has a home for a file
  exporter (then it is a move into an existing package, not a new one). It
  has no prerequisite and no open-PR overlap today. After it: the IM-018
  prerequisite (pool-supplied breaker clock), the single strict decoder for
  the three F3 records, then IM-014 mapping.
