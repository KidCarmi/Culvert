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
| IM-000 | Discovery: policy mapping, #1526 reconciliation, this program section | implementation under review | nightly shift | `main` / `claude/hopeful-knuth-kyvpgs` | #1760 | — | this document | owner review; merge or amend |
| IM-001 | `inspect_h2_alpn.go` → `internal/alpnpeek` (pilot 1 of ≤3) | proposed, **awaiting owner acceptance** | nightly shift | `main` / tbd | — | IM-000 merged or accepted | **packet** below | on acceptance: one code PR per the packet |
| IM-002 | `saas_feed_floor.go` → `internal/feedfloor` | proposed | — | — | — | IM-001 assessment | lead (906 ln, 0 root deps, `fileutil`+`urlcatfeed`, 10 inbound; `var` block is error sentinels + CRC table) | map: callers, fsync/path ownership, F3 §B cross-check, the 9 referencing test files |
| IM-003 | `saas_feed_genstore.go` → same package | proposed | — | — | — | IM-002 | lead (539 ln; 2 deps, both in IM-002) | map after IM-002 |
| IM-004 | `upstream_backup_strip.go` → `internal/upstream/backupstrip` | proposed | — | — | — | IM-001 assessment | lead (517 ln, 0 root deps, 2 inbound; 12 test files by grep, unclassified) | map: classify tests, define byte-identical output fixture |
| IM-005 | `policy.go` leaf matchers (follow-up (a)) | **blocked** | — | — | — | IM-006 + accepted boundary | mapping above | none until IM-006 ships |
| IM-006 | Policy evaluation lookup owners (ADR-0040 step 2) | blocked on #1526 disposition | owner decides | — | #1526 (design) | owner | ADR-0040, `policy-core-feasibility.md`, TSV | owner: merge/rebase/close #1526; then one ownership PR |
| IM-007 | `realclientip.go` → `internal/realclientip` | proposed | — | — | — | — | lead (154 ln, 0 root deps, 15 inbound; `var` block unaudited) | map: is the `var` block trusted-proxy config (then instance owner first, ADR-0038 pattern) |
| IM-008 | `traffic_redaction.go` → `internal/redaction` | proposed | — | — | — | posture injection | lead (341 ln; reads `decRedactHosts`; atomic key state) | map: posture as construction input |
| IM-009 | `mcp_evidence_readmodel.go`, `mcp_shadow_metrics.go` → `internal/mcp/…` | proposed | — | — | — | overlap check | lead (0 root deps; heavy open MCP PR traffic) | map only after an overlap check against open MCP PRs |
| IM-010 | `proxy_path_bounds.go`, `proxy_host_bounds.go`, `request_tracing_bounds.go` | proposed | — | — | — | benchgate measurement | lead (hot path; cross-linked) | measure before mapping |

Not candidates (ADR-0002 "Decomposition Complete" decisions): `proxy.go`,
`store.go`, the `policy.go` store/draft/hub, `controlplane*.go`,
`enrollment.go`, `upstream.go`, `upstream_transport.go` (zero root deps in the
walk, but main owns the published transport by convention), `ca.go`,
`release_*.go`, `ui_*.go`, `auth_*.go`, `auth.go`, `identity.go`,
`security_scan.go`, `configversion.go`, `*_startup*.go`, `*_vars.go` and the
`*_health.go` probe adapters. Performance benefit of any task is unmeasured
until matched runs per the measurement contract establish it.

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
