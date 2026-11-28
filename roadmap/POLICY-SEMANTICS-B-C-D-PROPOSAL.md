# Policy semantics proposals: B (invalid categories), C (equal priorities), D (default_action spellings)

> **Status: owner decision recorded 2026-11-23 (Decision 3 in roadmap/VERIFICATION-PROGRAM.md):** the conservative recommendations for B, C and D are approved, each to land independently; the renumber endpoint is not yet decided. This document is the design record.
> Evidence-backed investigation for the verification program (see roadmap/VERIFICATION-PROGRAM.md); differential evidence: PR #2029.

Revision `8178c19` (a shallow clone, so there is no `git log` history). This was a read-only investigation and
nothing was implemented. Every claim is either checked against source at this revision or marked as inferred.

**Three corrections to the brief, up front:**
1. **B.** `validateAccessRule` does not check `DestCategory`, but new and modified rules are already validated by
   `refuseDanglingRuleRefs` → `validateRuleObjectRefs` → `referencedCategoryResolvable`
   (`policy_ref_validation.go:73,129-131`), and every bulk door has an equivalent. The real gaps are: the
   persisted-file loaders, categories that disappear after a rule is written (authority drift), and case variants
   of `Any`.
2. **D.** YAML `default_action` already fails startup unless it is exactly `allow` or `deny` (`config.go:613-616`,
   through `loadFileConfig` `:514` and `log.Fatalf` at `main.go:672`). The `CULVERT_DEFAULT_ACTION` entry in the
   POL-002 `configs` list (`contracts/registry.yaml:113`) has no reader anywhere in the code.
3. **C.** Ties already exist in the wild. The header of `policy_priority_dedup_test.go:3-13` records that Add and
   import-merge used to accept duplicate priorities, so older installs may still carry them.

---------------------------------------------------------------------------------------------------------------------
## B. Invalid or unresolvable `DestCategory`

### Current behaviour
- **Hot path.** `catSet := DestCategory != "" && != CategoryAny` (`policy.go:2505`), then `sc.matchesCategory`
  (`policy_hostcat.go:291-327`). `CategoryAny = urlcat.Any = "Any"` (`policy.go:56`, `internal/urlcat/urlcat.go:80`).
  - Only exact `"Any"` and `""` are wildcards.
  - Category matching folds case (`categoryKey`, `urlcat.go:1204`). So `"any"` is a category name, and it matches
    nothing unless some authority carries that name.
  - Nothing reserves the name `Any` (`catStore.Set`, `ui_policy.go:1173`; acknowledged at `policy_refs.go:152-157`).
    If an admin creates a category called "Any", a rule with `"any"` matches that category's hosts, while a rule
    with `"Any"` stays a wildcard.
- **The valid set is time-varying.** `referencedCategoryResolvable` (`policy_ref_validation.go:73-97`) mirrors the
  hot path. With the signed view installed, valid names are admin (non-BuiltIn) catStore names, view classes
  (`saas_feed_view.go:209`) and UT1 community names. With no view, they are the whole catStore plus UT1.
  - The set changes after a rule is written when a feed generation drops a class, a SaaS override tombstones one,
    the view arms or disarms (which flips whether BuiltIn names count), or the community DB is absent or late.
    Categories load in `initURLCategories`, after `initPolicy` (`main.go:275-276`).
  - There is no category rename (PUT only replaces hosts, `ui_policy.go:1235`). Deleting a referenced category via
    the admin API returns 409 (`ui_policy.go:1255-1268`; the walk covers running and draft rules,
    `policy_refs.go:64-104`). **Drift caused by feeds or the community DB is neither guarded nor reported.**

| Rule write path | Category validation | Priority uniqueness (used in C) |
|---|---|---|
| API create / update `?priority=` / update `?id=` | `refuseDanglingRuleRefs` `ui_policy.go:2056,2150,2309` | `:2075,2177,2339` |
| authpolicy create/update; learning accept | `ui_authpolicy.go:277,363`; `policy_learning_accept.go:265` | `:295,387`; `:251` |
| draft staging | same fenced handlers (target = candidate) | same |
| draft commit `commitActivate` | **none** (`validatePolicyRule` only, `policy_draft.go:490-494`) | **blind** (see C) |
| draft reload from disk | **none** (`ReplaceAll`, `policy_draft.go:103`) | none |
| config import, merge and replace | whole effective candidate `ui_config.go:1299` → `bulk_ref_validation.go:475` | merge only (`ui_config.go:1173`); replace none (`:1153`) |
| config-version rollback | `validateRestoredCandidateRefs` `configversion.go:335` | none (`validatePolicyRule(..,nil,-1)` `:630`) |
| CP→DP apply **and** CP publish gate | `validateSnapshotRefGraph` `controlplane_snapshot.go:474` (via `validateConfigSnapshot`, publish `:846`) | none (`ReplaceAll` `:1563`) |
| `PolicyStore.Load` (boot and SIGHUP, `main.go:950,1788`) | **none** (`policyRulePersistable`+`warnInertSourceIP`, `policy.go:518-531`) | none |
| YAML seed | does not exist (YAML only has `policy_file`, `config.go:29`) | n/a |

- **`DestCategoryGroup`, the analogous case.** It is validated on write (`policy_ref_validation.go:133`, plus a bulk
  name-or-ID check). Deleting a referenced group is blocked, and a rename cascades by ID (`ui_policy.go:686-698`). At
  evaluation a dangling group matches nothing (`categorygroup.go:94-99`, `internal/catgroup/catgroup.go:1146-1148`).
  That is the same fail-open-for-Drop shape, and it is not reported either.
- **Precedent for reporting.** `file_profile_health.go` exposes a live `/api/diagnostics` row plus a counter for
  dangling file-profile references.

### Legacy and compatibility risk
- A dangling legacy rule can only enter through a hand-edited policy or draft file, or through drift. Such a rule is
  inert, but **not harmless**. Every bulk gate refuses its whole candidate when one is present:
  - the CP's full publish is refused, so the fleet freezes on its last snapshot (`controlplane_snapshot.go:846`→`:474`);
  - a merge import is refused, because untouched live rules are judged too (`bulk_ref_validation.go:398-420`);
  - a rollback is refused when the version omits `PolicyRules` (`:524-527`).
- *Inferred, not verified:* the DP judges with its own view and UT1 (`postApplyCategoryClosure`, `:44-60`). A CP rule
  keyed on a UT1 category could therefore be rejected by a DP that has no community DB.
- **Never canonicalise stored `any`/`ANY` to `Any`.** A Drop rule that matches nothing would become drop-all, and an
  Allow rule would become allow-all.

### Options
1. **Refuse the rule on load.** Enforcement would not change. But the authorities load after policy, and UT1 and the
   feed arrive asynchronously, so a rule could never start matching once its feed arrives. Rejected.
2. **Load verbatim, plus warning, metric, diagnostics row and UI flag.** No enforcement change. Mirrors
   `warnInertSourceIP` (`policy.go:441-452`).
3. **Tighten ingress for `Any`.** This check does not depend on state, so it can run pre-fence in
   `validateAccessRuleIngress` (`ui_helpers.go:256`). Exact `"Any"` and `""` stay wildcards; any other case-fold of
   `any` gets a 400. Category creation refuses names that case-fold to `any` (`ui_policy.go:1173`); an existing such
   category stays loadable and deletable.

### Recommendation
- **New or modified rules.** Keep the existing `validateRuleObjectRefs` door; it already gives explicit errors. Add
  option 3, with the error text
  `destCategory "any" is not a category; use "Any" (exact) or omit destCategory for any destination`, and do not
  canonicalise. Draft commit: run `validateRuleObjectRefs` per candidate under the shared gate, returning the
  structured 400 from `writeDanglingRefError`.
- **Stored rules: option 2, never refuse.**
  - A new `danglingCategoryRules` check covers category and group references. It runs after `initURLCategories`
    (not in `Load`) and after each taxonomy, feed or override recompose.
  - Per rule it emits
    `Policy: rule %q references category %q which no current category authority resolves; it matches no traffic`,
    sets the gauge `culvert_policy_rules_unresolved_refs{type=category|category_group}`, and feeds a diagnostics row.
  - Serve the UI flag from a separate read endpoint, for example the `/api/objects/references` family. A new field on
    `PolicyRule` JSON would break clients that echo the rule back through strict `decodeJSON`
    (`DisallowUnknownFields`, `ui_helpers.go:288-291`).
  - Make the bulk-refusal errors name this diagnostics row as the remedy.
- **Cluster and rollback.** Leave the bulk gates as they are (they already fail closed). Document the fleet-freeze
  risk. Whether the DP should judge against the CP's resolvable set is an owner question (POL-902); it needs a wire
  field.
- **Owner sign-off needed** for the customer-visible changes: the 400 on `any` variants, the reserved `Any` name, and
  draft commit refusing drifted references. Warnings and metrics are not enforcement changes.

### Contract impact and tests
- **Registry.**
  - New **POL-005** (enforced): "A new or modified access rule whose destCategory/destCategoryGroup no current
    authority resolves is refused; exact `Any` and empty are the only wildcards."
  - New **POL-902** (open): drift handling, and DP closure vs CP closure.
  - `policy.go` is listed under POL-001, so `contractcheck impact` fires if it is touched. Most of the work sits in
    `policy_ref_validation.go`, `ui_helpers.go` and a new health file.
- **Tests.** `"any"`/`"ANY"` get a 400 on create, update, update-by-ID, authpolicy and import-merge; `"Any"` gets
  200. Creating a category named `aNy` gets a 400; a pre-existing admin `Any` category with an `any` rule keeps
  today's behaviour (negative control). Loading a dangling rule keeps it; the warning fires only after categories
  load, the gauge reads 1, and the row clears without restart once the category appears. Draft commit is refused
  after the referenced feed class disappears. A stored `"any"` never becomes a wildcard.

---------------------------------------------------------------------------------------------------------------------
## C. Equal priorities

### Current behaviour
- `sortLocked` sorts with `sort.Slice` on `Priority` alone (`policy.go:1413`).
- Evaluation is first-match in slice order (`policy.go:1727`), and `saveTo` persists in slice order (`:710-729`).
- **Go source, go1.27.4 (the `go.mod` toolchain).** `Slice` calls `pdqsort_func` (`$GOROOT/src/sort/slice.go:24-30`).
  - With length ≤ 12 it runs `insertionSort_func`, which only swaps on strict less, so it is **stable**
    (`zsortfunc.go:62-74`).
  - Already non-decreasing input gives zero pivot swaps, so `increasingHint` leads to `partialInsertionSort`, which
    returns with no swaps. The result is **identity** (`:100-103,195-208`).
  - Otherwise partitioning permutes ties. The result is deterministic for a given input and Go version, but nobody
    designed it.
- **Probe.** I ran a standalone `sort.Slice` vs `sort.SliceStable` program with go1.27.4
  (a throwaway program outside the repository; it does not touch package main):

  | Input | Share differing from a stable sort |
  |---|---|
  | Arbitrary, n ≤ 12 | 0 of 220k trials |
  | Arbitrary, n ≥ 13 | 89–100% |
  | Sorted, with ties, n = 13–10000 | 0 (identity) |
  | Sorted with ties, plus one appended mid-range priority ("gap Add") | ~87% at n = 13–21; 0% at n ≥ 51 (shifting starts at 50) |
  | Sorted with ties, one priority changed ("move") | 69% at n = 13; 6% at n = 100; 0.7% at n = 1000 |

- **Writers that feed sorted input (identity today):** `UpdateByID`, which preserves priority (`policy.go:982`);
  `Cascade*` and `RefreshObjectRefNames` (`:1025,1062,1099,1129`); `ReplaceAll` of `List()`-derived input (rollback,
  CP snapshot, draft commit); `Load` of a file Culvert wrote. `Delete` does not re-sort at all (`:945-957`).
- **Writers that feed unsorted input (ties among other rules can be permuted at n ≥ 13):** `Add` into a free gap
  (`:897-914`); `Update` by priority with a changed priority (`:919-940`); `PermutePriorities`, used by move
  (`ui_policy.go:2733`) and authpolicy reorder (`ui_authpolicy.go:568`); `Load` or replace-import of an unsorted
  hand-edited file. `Reorder` has no production caller, and its `byOldPri` map would mishandle ties anyway.
- **Paths that admit ties.**
  - `Load`; replace-import (`ui_config.go:1153`); rollback (`configversion.go:630`); CP→DP; draft reload
    (`policy_draft.go:103`).
  - Draft commit: `validatePolicyRule(cand[i], cand, cand[i].Priority)` skips every rule at the same priority in both
    the name and priority checks, so it is tie-blind (`policy_draft.go:491`, `ui_helpers.go:163-177`).
  - `PUT /api/policy?priority=` with body `priority <= 0`: the check is skipped (`ui_helpers.go:173`), and `Update`
    stores the value verbatim. This is reachable through the API only; both UIs send a priority
    (`static/index.html:13173`, and the React client uses `?id=`, `frontend/src/api/policyWrite.ts:236`).
  - Create, merge import, and `Add` itself (which reassigns to max+1) all refuse or fix ties.
- **Collateral effects of ties.** Move refuses any subset that touches a tie (`policy.go:1298`), so the operator
  cannot fix a tie through the UI. Delete or update by priority hits the first tied rule. `diffPolicyRules` keys on
  priority, so version diffs collapse tied rules (`configversion.go:1074-1082`). `DetectConflicts` runs only on `Add`.

### Today's effective order
In steady state, tie order **equals the stored file/slice order**. That holds for CP and DPs at any n, because once a
file has been loaded and saved it is sorted, and every non-perturbing writer then returns it unchanged. The order
drifts only when n ≥ 13 and a gap Add, a priority edit or a move happens. The drifted order is then persisted. The
other case is the first load of an unsorted hand-edited file with ties at n ≥ 13.

### Options
1. **Stable sort on `Priority`**, using the input index as tie-break (stays on pdqsort), or `slices.SortStableFunc`.
   It is identical to today for every sorted input and for n ≤ 12. It differs only in the artefact cases above,
   where it yields input order.
2. **Tie-break on ULID.** IDs are backfilled by `freshRuleID` (`policy.go:601-631`) and have no relation to
   evaluation order, so this would reorder existing ties. It changes customer behaviour. Rejected.
3. **Auto-renumber on load.** This silently rewrites customer data, and it still has to pick an order. Rejected as
   automatic; acceptable as an explicit admin action.

### Recommendation
- **Option 1, with documented precedence:** "equal priorities evaluate in stored order (policy file / snapshot /
  backup)". Benchmark-gate the change with `BenchmarkPolicyPublish_SortLocked` (`policy.go:1378-1386`): the sort runs
  under the writer lock, which stalls evaluation.
- **Upgrade safety for the artefact case** (an unsorted tied input at n ≥ 13 reaching `Load` or `ReplaceAll`).
  - For one release, also compute the legacy `sort.Slice` order and warn if it differs:
    `Policy: %d rule(s) share priority %d; evaluation order now follows stored order (%q before %q), which differs from the previous release`.
  - Keep the gauge `culvert_policy_priority_ties` and a diagnostics row permanently.
- **Stop admitting new ties.** `Update` by priority: reject `priority <= 0`, or keep the stored priority as
  `UpdateByID` does. Draft commit: add a real duplicate-priority check. Replace-import: return a 400 naming the
  colliding rules, at preview and commit. `Load`, rollback and CP→DP stay faithful restores and only warn.
- **New `POST /api/policy/renumber`.** It audits, then calls `saveConfigVersion`, and has a GUI button for parity. It
  assigns 1..n in the current order, which preserves evaluation and unblocks move. Optionally, key `diffPolicyRules`
  on ID.
- **Owner sign-off needed** for: tie order becoming a contract (no steady-state change), the new 400s on
  replace-import and draft commit, and the renumber endpoint.

### Contract impact and tests
- **Registry.** **POL-001** (`registry.yaml:81-100`): an `amended` record saying "ties evaluate in stored order"
  (touching `policy.go` triggers impact). New **POL-006** (enforced): API, import and draft-commit writes cannot
  create duplicate priorities.
- **Tests.** A table test at n ∈ {2, 12, 13, 50, 51, 1000}: after a gap Add, a priority Update or a move, untouched
  tied rules keep their relative order (today's code fails at n = 13). Loading an unsorted tied file yields stored
  order, and the legacy-diff warning fires exactly when the orders differ. CP→DP keeps tie order. `PUT ?priority=`
  with 0 and draft commit with a tie are rejected. Renumber preserves evaluation (differential `Evaluate` over a host
  corpus).

---------------------------------------------------------------------------------------------------------------------
## D. `default_action` spellings

### Current behaviour
`setDefaultPolicyAction` treats exact `"allow"` as allow and anything else as deny (`proxy.go:35-47`). The getter
only reports `allow` or `deny` (`proxy.go:50-55`).

| Source | Accepts today | Outcome for a non-canonical value such as `Allow` |
|---|---|---|
| YAML at boot | `allow`, `deny` or empty (`config.go:613-616`) | **startup fails**: `Cannot load config file: validate <path>: default_action: must be "allow" or "deny", got "Allow"` |
| YAML on SIGHUP | same validation (`main.go:1306-1310`); empty means no change (`:1796`) | reload refused: `Config reload error: … — keeping current config` |
| Env or CLI | **none** (POL-002's `CULVERT_DEFAULT_ACTION` is a stale registry entry) | — |
| Empty YAML | derived from the rule count (`rewrite_default_action_startup.go:30-40`) | n/a |
| `admin_settings.json` (applied after YAML: `main.go:291,298`) | any non-empty string (`admin_settings.go:427-429`) | **silent deny**. No log line; the last thing printed may be `Policy: default action: allow` from YAML. UI/API GET show `deny`. The next settings save rewrites the file to `"deny"` (`:1031`), which is already a silent normalisation. |
| `POST /api/policy/default-action` | exact only (`ui_policy.go:2946-2949`) | 400 `action must be "allow" or "deny"` |
| Config import | exact only (`ui_config.go:1362-1364`) | silently ignored: the current value is kept, and the preview omits it (`:1051`) |
| Config-version rollback | unconditional set (`configversion.go:637`) | deny. `""` (pre-field versions) and `"block"` also become deny. Only dry-run warns (`:478-479,283`), and it exempts `"block"`. |
| CP→DP snapshot | any non-empty value (`controlplane_snapshot.go:1557-1558`); the CP always sends canonical (`:2100`) | silent deny |

For contrast, rule actions are exact at ingress (`ui_helpers.go:229-236`) but case-folded on load
(`canonicalPolicyAction`, `authpolicy.go:1231-1240`). That is a precedent for rules, not for `default_action`.

### Compatibility risk
No running YAML deployment can hold a non-canonical value, because it would not start. The only other sources are a
hand-edited `admin_settings.json` or version file, a third-party backup, or a forged or newer snapshot, and all of
these fail closed today. Reading `Allow` as allow would flip existing deny deployments to allow: a weakening
reinterpretation, so it is rejected.

### Options
1. **Fail startup on a non-canonical admin-settings value.** Consistent with YAML, but it turns a fail-closed state
   into an outage on upgrade, for data that Culvert never writes itself.
2. **Keep deny, but make it loud and non-destructive.** Warn, add a diagnostics row and a metric, and keep the raw
   value instead of rewriting it.
3. **Reject at each bulk door.** Rollback and import would return a 400, and DPs would reject the snapshot. That
   costs availability during incidents, and it would freeze older DPs on any future CP value.

### Recommendation
- **One validator**, `parseDefaultAction(s) (canonical string, ok bool)`, accepting only `allow` and `deny`. Every
  caller decides what to do on failure; enforcement stays deny.
- **`admin_settings.json`: option 2** (YAML stays unchanged).
  - Warn with `sanitizeLog` + `%q`:
    `AdminSettings: default_action %q is not "allow" or "deny"; enforcing deny (fail-closed). Set it explicitly via Policy → Default action.`
  - Add a diagnostics row and the gauge `culvert_default_action_noncanonical{source=…}`.
  - Write the raw value back verbatim on save until an explicit API set (`admin_settings.go:1031`). This satisfies
    "do not silently normalise".
- **Rollback.** Keep deny for `""`, `"block"` and anything else. Return the warnings in the real response as well as
  in dry-run, and include `"block"` and `""` among them. Put `default_action applied as deny (stored %q)` in the
  audit detail.
- **Import.** Return the warning `defaultAction %q ignored: must be "allow" or "deny"` in both the import response
  and the preview.
- **CP→DP.** Keep deny, add a warning and a counter, and do not reject the snapshot (forward compatibility). The
  API stays unchanged.
- **Registry.** Remove `CULVERT_DEFAULT_ACTION` from POL-002, or decide separately whether that env var should exist.
- **Owner sign-off needed** for the customer-visible changes: preserving the raw value instead of rewriting it to
  `deny`, and the new warnings in rollback and import responses. No enforcement outcome changes. Choosing option 1
  instead would be an availability change and needs explicit approval.

### Contract impact and tests
- **Registry.**
  - **POL-002** (`registry.yaml:102-123`): an `amended` record fixing the stale `configs` entry. Optionally add: "a
    non-canonical stored value is enforced as deny and reported, never reinterpreted."
  - **POL-900** (`:588-598`): `admin_settings.go` is in its code list, so impact fires. The change must not alter the
    boot derivation or how a derived allow persists, which is POL-900's open question. Say so in the PR.
- **Tests.** Admin settings holding `"Allow"`, `"ALLOW"`, `"block"` or `" allow"` give deny, the warning text and
  the gauge, and an unrelated save leaves the file unchanged. Rollback of `"Allow"`, `""` or `"block"` gives deny,
  with the warning in the real response. Import of `"Allow"` leaves the value unchanged and returns the warning. A DP
  snapshot with `"Allow"` gives deny and increments the counter. Must stay green:
  `TestConfigValidate_InvalidDefaultAction` (`p5_test.go:23`) and the four-case tests in
  `rewrite_default_action_startup_test.go`.

---------------------------------------------------------------------------------------------------------------------
## Uncertainties and checks not run
- No repository tests were run. The pdqsort claims rest on the standalone probe and a reading of the source; the
  probe did not exercise `PolicyStore` itself.
- Two B risks are inferred from code, not reproduced: the DP/CP closure mismatch, and the fleet freeze caused by a
  live dangling rule.
- There is no telemetry on how many deployments have ties or `any` values, and the clone's history is too shallow to
  date earlier behaviour.
- The separate CDR policy store (`cdrpolicy.go:570`) was not examined. It probably needs the same treatment as B.
