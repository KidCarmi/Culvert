# ADR-0040: Own the access-evaluation environment before package extraction

- Status: proposed for review; decision **PREREQUISITE FIRST**
- Date: 2026-10-01
- Baseline: `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af` (fresh `origin/main`)
- Authorities: [ADR-0002](0002-flat-package-to-internal-decomposition.md),
  [ADR-0025](0025-policy-learning-advisory-boundary.md),
  [ADR-0026](0026-single-access-policy-evaluator-core.md)
- Evidence and migration inventory: [assessment](../engineering/policy-core-feasibility.md)

## Decision

First make the access evaluator's **lookup environment explicit and independently
constructible in main**. Do not extract `PolicyStore`, `PolicyRule`, or a policy
package in that implementation PR. Its acceptance criteria are below. A subsequent
extraction of the ordered access scan, matching predicates and scan-local scratch
into `internal/accesspolicy` is conditional on that proof. This is distinct from
`internal/mcp/policy`, which evaluates a different vocabulary and authority.

The smallest useful boundary is a matching engine: immutable matching definitions
plus one canonical first-match scan, source/address matching, schedule predicates,
destination matching and category scratch. It returns a matched ordinal; it does
not activate a rule, account a hit, choose the default action, persist anything or
own the application's security gates. Merely moving `evalAccessRules` while its
helpers read main's globals would not create independently runnable tests.

ADR-0002's completed decomposition is not reopened. Its historical “no second
consumer” argument no longer describes the tester. Its rule-schema, load-gate
and live-dependency objections still matter. ADR-0026's pure core means no rule
mutation or hit accounting, **not** a referentially pure or independently owned
runtime: geo misses schedule warming and increment health accounting; timezone
resolution caches values and can log. Preserve these existing effects.

## Current consumers and guarantees

| Consumer | Actual current path | Boundary |
|---|---|---|
| HTTP, CONNECT, WebSocket enforcement | `handleRequest` → `PolicyStore.Evaluate` → `evaluationSnapshot` → `evalAccessRules`; dispatch consumes detached `PolicyMatch` | Auth, input/host limits, pre-dispatch block/threat/plugin/file gates, default action, logging and learning brackets stay main |
| `Decide` | `authpolicy.go` compatibility/PDP seam → `policyStore.Evaluate` | A wrapper, not a second scan; not the request dispatch entry |
| Policy Tester | `apiPolicyTest` → `effectivePolicyList` → `walkPolicyTestRules` → same core | Running/draft selection, RBAC, input limits, Stage-1 simulation and response trace stay main; no hit accounting |
| Learning | `learnDecisionSnapshot` / `learnObserveDecision` bracket the real decision; drain resolves categories | Observation and recommendation, not a call to the access evaluator |
| Access replay/shadow | Future consumers in ADR-0026; no shipped caller found | Must use this same core if implemented. Do not count MCP replay/shadow as access-core consumers |
| Stage-1 auth / CDR | `authRuleMatchesScratch` / `CDRPolicyStore.Evaluate` reuse destination, source and schedule helpers | Different decision loops remain main; share matching primitives, never replace their gates with the Stage-2 scan |
| SOCKS5 | `handleSOCKS5` performs admission, auth, host, blocklist, plugin and SSRF checks, then dials | It does **not** call `PolicyStore.Evaluate` on this baseline. Do not add access-policy enforcement as part of ownership work |

Access rules scan ascending priority order, first match wins. Keep the actual
`sort.Slice` ordering, including its existing handling of ties; do not introduce
a stable sort. Empty rule type means access; other types are skipped. Preserve
nil-enabled, empty-field, identity/group trimming and auth-source alias semantics.
An exact source IP compares raw strings; CIDRs use the current `netip.Prefix`
fast path with IPNet/raw fallback and mapped-address behavior. No eager parsing.

The schedule clock is read zero times until an enabled access rule passes source
matching and reaches a schedule, then once for the scan. Accounting's later
`time.Now` is a **different** operation. Keep invalid-timezone UTC fallback for
Stage-2, Stage-1's validity rejection, malformed-time legacy comparison,
start-inclusive/end-exclusive and overnight behavior. CDR currently reads its
clock through `matchSchedule` per reached rule; do not silently give it the
Stage-2 single-instant contract.

## Ownership and synchronization

| State / dependency | Current owner and read semantics | Required owner / future package treatment |
|---|---|---|
| Ordered rule revision | `PolicyStore.mu`; copy-on-write slice and definitions, scan after releasing lock | Main retains publication and transactions. Future immutable program is derived from and captured **with the same revision**, never an independently refreshed authority |
| Nested rule values | Publication copies country/day slices, bool pointers, subject predicates and their values, auth provider refs; clears/rebuilds match caches | Retain defensive copies. Compiled matching definitions own copied inputs; no exported mutable rule pointers |
| Hit cells | Shared atomic cell across edits/reorders/rename revisions; `ReplaceAll` deliberately resets; reload preserves by valid stable ID | Main owns accounting and detached `PolicyMatch`. Apply hit to the rule in the captured revision, never re-lookup current rule by ordinal/name/ID after scan |
| Compiled fields | `sortLocked`: normalized FQDN, parsed IPNet/prefix, condition summary, Stage-1 subject nets | Matching package may own access compiler later. Stage-1 nets and display summary remain with their owners; no second evaluator or public cache setters |
| Admin taxonomy | `catStore` (`urlcat.Store`), per-call synchronized reads | Explicit borrowed store; do not freeze the entire taxonomy per scan |
| Effective signed-feed view | `saasEffectiveView.Current()`, one lazy capture per category scratch, including nil | Explicit feed reader, same lazy capture; view's nested maps remain immutable and inaccessible to callers |
| Community taxonomy | `communityDB.Lookup`, first available lookup memoized; nil is not memoized | Explicit live source accessor, preserving nil→available within a scan; DB lifecycle remains startup/feed/shutdown owned |
| Category fusion/membership | `hostCatScratch`: fusion/classification once; membership per category; cross-layer OR; group ID-first with name fallback only if ID unresolved | Evaluator owns stack-local scratch; existing stores retain synchronization. Preserve classification versus many-to-many membership and `DestCategoryGroup != ""` activation condition |
| Category groups | `globalCategoryGroups` (`catgroup.Store`), membership read per rule | Explicit borrowed store, not a frozen copy or pre-resolved group definition |
| Country lookup | Root `geoResolver.LookupCached` borrows process DNS/IP caches, may schedule bounded warm; unresolved count per reached miss | Narrow lookup/observation adapter bound to its service. Production intentionally shares geo service; isolated evaluator tests supply independent local readers. Do not claim this makes geo itself instance-owned |
| Timezone cache | Process `scheduleLocCache`, shared with auth/CDR; invalid result cached with warning | Explicit schedule-resolver instance; one shared production instance, separate instances in independent tests. Preserve lookup timing, invalid-result caching and warning behavior; no eager compile-time warnings |
| Clock / trace | Explicit clock function; optional rule-pointer callback, nil in enforcement | Keep clock lazy; trace future ordinal+static reason only. No closure allocation on nil-trace path; callback never receives mutable engine internals |
| Security admission to store | `Load`/`ReplaceAll` call `policyRulePersistable`; interactive validation includes live provider/reference checks | **Always main-owned concrete calls**, never injectable predicates. Full wire DTO, auth vocabulary and validation stay main |
| Draft/learning/config | Mutation fences, durable save/rollback, learning-accept intent protocol, CP→DP application | Main. No package owns a second policy store, draft commit or activation path |

Production category/group stores have stable handles and mutate their own content.
Community DB is installed during startup; its explicit accessor must retain that
late-binding behavior. Main composes dependencies once their owners exist and
before request serving; optional community absence is a real value, not a reason
to fall back to a global. Test fixture replacement of global handles must rebind
and restore the production evaluator explicitly. New isolated tests use local
owners and never swap application globals.

The evaluator has no goroutine, persistence, cancellation or shutdown method.
It borrows dependencies for each synchronous call; application lifecycle keeps
those dependencies alive until requests drain. Geo owns its existing warming
lifecycle. The ownership PR must not invent a new lifecycle for those services.

## Concrete prerequisite API (all in main)

The following is a signature/ownership proposal, not shipping code:

```go
type policyCountryReader interface {
    LookupCountryForPolicy(host string) (code string, cached bool)
}

type accessEvalSources struct {
    Categories *CategoryStore
    Groups     *CategoryGroupStore
    Feed       *feedLiveStore
    Community  func() *CommunityDB // live owner accessor, NOT an allow predicate
    Country    policyCountryReader
}

type policyScheduleResolver struct { /* private cache and warning sink */ }
type accessEvaluator struct { /* private sources and schedule resolver */ }

func newAccessEvaluator(accessEvalSources, *policyScheduleResolver) (*accessEvaluator, error)
func evalAccessRules(e *accessEvaluator, rules []*PolicyRule, in *accessEvalInput,
    now func() time.Time, trace func(*PolicyRule, string)) *PolicyRule
```

Constructor rejects missing required dependencies; an explicitly empty taxonomy,
unarmed feed, unavailable country reader or accessor returning nil community is
valid existing state. There is no “nil evaluator means use globals” path, no
`Allow`, `ValidateRule`, `LoadOK` or `MatchRule` callback. The source bundle is
private and specific to policy lookup, not an application dependency container.
The warning sink is for observability only, never a decision. The concrete
country adapter calls the existing cached lookup and, on a miss, records the
existing unresolved observation before returning. Thus diagnostic accounting
stays in main's adapter and retains its per-reached-rule timing; the core owns
no counter and does not batch observations after the scan. Independent test
adapters own their own observations.

`PolicyStore.Evaluate` remains the compatibility composition method: capture its
revision, explicitly pass the application's constructed evaluator to the one
core, then perform existing accounting/copying. Its zero-value store behavior
remains intact; do not add a hidden per-store fallback. A main-only helper accepts
an explicit evaluator and captured revision for independent tests. The tester
uses the same application evaluator. Auth/CDR and category API wrappers use the
same matching implementation/resolver with their original scan/clock contracts.

## Intended extraction API after the prerequisite

`internal/accesspolicy` would own a matching vocabulary, **not** the JSON DTO:

```go
// All fields are construction inputs; Compile deep-copies nested values.
type Rule struct {
    Kind string // preserve unknown and auth skip behavior, not just an Access bool
    Enabled bool // main resolves nil-enabled as true
    SourceIP, Identity, Group, AuthSource string
    FQDN, Category, CategoryGroup, CategoryGroupID string
    Countries []string
    Schedule *Schedule
}
type Schedule struct { Days []string; Start, End, Timezone string }
type Input struct { ClientIP, Identity, AuthSource, Host string; Groups []string }
type Program struct { /* private ordered compiled definitions */ }
type Engine struct { /* explicit lookup environment; no rule publication */ }
type SkipReason string
func Compile(ordered []Rule) *Program
func (e *Engine) Scan(p *Program, in *Input, now func() time.Time,
    trace func(ordinal int, why SkipReason)) (ordinal int) // -1 = no match
```

`Compile` preserves supplied order and does not validate/activate application
policy. Main maps the already-admitted revision, including skipped non-access
rows, into the matching vocabulary; it stores program plus corresponding rules
as one publication. Core returns only an ordinal into **that captured revision**.
Keep the full `PolicyRule`, actions, file/decryption profiles, auth specs, display
metadata and counters in main. No generic DTO package or public mutable caches.
Input groups are borrowed read-only for the synchronous scan and never retained;
the package derives normalized host internally. Stage-1/CDR need narrowly exposed
matching predicates/scratch, not access to private compiled rules or a second
copy of matching logic. Their exact wrappers are a later extraction deliverable.

The package's lookup interfaces must expose facts only: admin membership and
classification, current immutable feed view, community availability/classification,
group ID resolution/membership and cached country lookup. Keep their current
read/memoization schedule, including repeated live membership probes. Do not
replace them with a precomputed “destination allowed” callback or eager snapshot
of all lookups. Final interface layout and escape analysis are acceptance work
for the prerequisite; this design does not claim an unmeasured zero-allocation
interface implementation. If it cannot meet parity, defer extraction again.

## Generation and load safeguards

A rule revision is coherent, but its live lookup environment is **not one atomic
snapshot**. Capturing every category/group/geo fact at scan start would change
semantics. Preserve the existing lazy feed snapshot, once-per-scan fusion and
community result, live admin/group membership, and per-reached-rule geo behavior.

Learning's `policyContentKey` combines policy generation, group revision and the
packed default-action revision. Its taxonomy fence holds feed-view identity and
admin revision; before/after checks witness ABA transitions. The restart-stable
v2 epoch uses admin content fingerprint and feed/config identities. These fences,
the captured learning engine/window, and the observation drain brackets stay in
main/`policylearn` as today. UT1 has no generation identity; geo cache changes are
not covered by these keys. Neither extraction nor a “pure” label upgrades that
evidence to a fully pinned environment. Replay requiring stronger guarantees
needs a separate design and must report unavailable guarantees.

`policyRulePersistable` rejects nil rules, invalid auth definitions and access
rules carrying unsupported `SubjectMatch` or `Auth`; loaders keep old state on
read/parse failure, boot and hot reload have different error handling. Preserve
these paths, interactive live-provider validation, and all transaction fences.
Compile never receives the authority to bypass them. Negative controls must prove
an unsupported scoped access rule cannot enter enforcement through load/replace,
and that a future program/rule revision mismatch cannot account or return a rule.

## Sequencing and ready-to-execute implementation task

1. **#1470 disposition first.** It is open at `db819dbfe95c2938dc17939a3979be15f7a5582c`.
   Current main scans every rule for nil counters; #1470 memoizes that predicate
   by slice identity under the existing lock. It does not own live dependencies.
   This design does not merge, copy, benchmark as current, or depend on its code.
   Before implementation: re-fetch; if merged, use it intact; if explicitly
   deferred/closed, record that disposition and keep main's existing scan. If
   still in flight, hold the overlapping implementation rather than parallel-edit
   `policy.go`. Never independently implement `verified`/`sameRuleSlice`.
2. **One ownership PR:** “refactor(policy): bind evaluation lookup owners”. Keep
   all production and test code in main. Add the explicit environment and schedule
   owner; pass it through the canonical scan and existing shared matcher paths;
   bind production and fixtures; preserve all publication/DTO/accounting code.
3. Prove independent concurrent evaluators with disjoint taxonomy, groups,
   feed/community readers, country observations and schedule caches. Cover both
   positive matches and negative controls; a hidden global read must fail. Keep
   real tester/enforcement/Stage-1/CDR, load/rollback and learning-fence tests.
4. Pin clock calls (zero/one and short-circuit order), trace reasons/order, lazy
   nil-community transition, membership/classification and geo effect counts.
   Retain every existing allocation gate and full required race/shuffle/coverage
   checks. Compare matched baseline/candidate benchmarks and inspect escapes;
   no per-rule allocation or relaxed bound. Use ADR-0026's measured end-to-end
   qualification method if interfaces materially affect hot-path latency.
5. Only after those checks, decide the bounded extraction PR from this API and
   the [test inventory](../engineering/policy-core-test-inventory.tsv). Preserve
   #1470 tests in main because publication remains there. Extend coverage and
   CI selectors as described in the evidence; do not start policy extraction in
   this design PR or in the ownership prerequisite.

Risks: hidden globals below adapters, interface-induced escapes, accidentally
freezing live lookups, trace exposing mutable definitions, cross-revision result
mapping, and overclaiming generation coverage. The prerequisite is valuable as
an isolation proof, not a promised reduction in CI duration. No non-shipping
prototype was necessary to establish these concrete ownership blockers.
