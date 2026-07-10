# DEBT-006 — `ConfigSnapshot` CP→DP god-DTO: parity-wall design plan

**Status:** DESIGN v2 (revised after adversarial design review — see §8)
**Authority:** this file; derives from the config-surface registry pattern
(`config_surfaces.go`, DEBT-004) and the uiRoutes/C1 route-metadata pattern.
**Owner surface:** `controlplane_snapshot.go`, `controlplane_server.go`
**Related closed work:** DEBT-004 (`configBackup` god-struct → registry, SHIPPED).

> **v2 note.** The v1 draft mis-stated the current state (it proposed
> "register all 34 fields" as new work — they are ALREADY registered and
> enforced) and specified two checks that would have been red or wrong on first
> run. A design review caught five concrete errors; this revision folds all of
> them in. The corrected scope is *smaller and sharper* than v1 claimed.

---

## 1. The debt, precisely

`ConfigSnapshot` (`controlplane_snapshot.go:21`) is the 34-field DTO the Control
Plane pushes to every Data Plane node on each config sync. Adding one synced
setting touches **four** places nothing forces to agree:

1. **The struct** — field + JSON tag + the `omitempty` choice (semantically
   load-bearing: see §4).
2. **`CurrentConfigSnapshot()`** (`:581`) — CP-side capture from the owning
   global. (Two meta fields — `Version`, `UpdatedAt` — are stamped LATER in
   `ConfigStore.Update`, `:188-189`, NOT here; the parity test must know this.)
3. **`validateConfigSnapshot()`** (`:125`) — the H5 per-slice DoS cap.
4. **The `applySnapshot*` fan-out** (`applyConfigSnapshot:232` → four helpers)
   — DP-side apply with per-field nil/[]/""/zero semantics.

**Interest:** a field added to the struct+capture but not `validate` = uncapped
DoS vector; not `apply` = silently-unsynced setting (DP diverges, no error);
capture/apply empty-semantics mismatch = a delete that doesn't replicate. All
silent until a cluster misbehaves.

**Why walling, not restructuring.** Capturing into typed sub-structs and
flattening to the same JSON on the wire *is* compatible — `json.Marshal`
doesn't care how the Go value was assembled, so the wire+epoch compat
constraint bounds the *serialized shape*, not the internal capture/apply
structure. We **choose** to wall-first (add enforcement over the frozen shape)
rather than restructure, because the enforcement is what stops the bleeding and
is independently valuable; a later ADR may shard the DTO behind version
negotiation. (v1 wrongly claimed compat *forbids* restructuring — it does not.)

---

## 2. What ALREADY exists (do not rebuild — this is the corrected baseline)

- **All 34 `ConfigSnapshot` fields are already registered** in `configSurfaces`
  (`config_surfaces.go`) with `Kind` + `Apply` populated, and
  **`TestConfigSurfaces_ReflectionParity`** (`config_surfaces_test.go`, the
  `case 0` branch) **already fails the build if any field lacks exactly one
  binding.** The "struct-field-not-registered" drift is ALREADY WALLED.
- **`TestConfigSurfaces_SnapshotCapParity`** already asserts every capped slice
  maps to a real field (cap *existence*, not magnitude).
- `TestConfigSurfaces_SensitiveInvariants` asserts `SessionHMAC`/`IdPProfiles`
  stay OFF the rollback surface and use the redacted `configBackup` export — but
  it explicitly does **NOT** test the ConfigSnapshot GetConfig redaction.

So Layer A of v1 ("add registry rows") is a **non-task**. The genuine gaps are
the three behavioral tests below.

---

## 3. Design — the actual missing enforcement

### Layer B — capture parity (`TestConfigSurfaces_SnapshotCaptureParity`)
Reflect over `ConfigSnapshot`; assert each field is assigned somewhere in the
**capture family** = `CurrentConfigSnapshot` **∪ `ConfigStore.Update`** (Version
+ UpdatedAt live in `Update`, `:188-189`). Requirements the v1 draft missed:
- **Type-scope the composite-literal match to `ConfigSnapshot`** (or bind the
  assignment target to the returned `snap`). A bare `X:`-key scan false-passes
  on same-named keys in unrelated literals — `CurrentConfigSnapshot` builds a
  `FileExtProfile` literal (`:606-609`) and the plain field names (`Version`,
  `Name`) are the collision-prone ones.
- **Scan a capture *family*, not one function.** `applySnapshot*` is already
  split four ways for gocognit; `CurrentConfigSnapshot` is still a monolith but
  will likely get the same split. Enumerate the capture functions in one place
  so the test survives that refactor.
- Presence only — does NOT prove the right owner (see §7, unclosed).

### Layer C — apply parity (`TestConfigSurfaces_SnapshotApplyParity`)
Assert each field with a DP-side effect is read in the `applySnapshot*` family,
and every slice/map field has a `validateConfigSnapshot` cap (fold in the
existing cap-parity assertion). **Coverage axis = "has an apply effect", NOT
`kindConfig`** — this is the review's most important correction:
- **`Epoch` drives `dpObserveEpoch`** (`:239`) — the fence ratchet that rejects
  stale-epoch snapshots. Security-critical.
- **`CAFingerprint` drives `caRotationNotify`** (`applySnapshotClusterRuntime`,
  `:373-383`) — triggers immediate DP cert renewal.
- Both are `kindMeta`. If apply-parity keyed on `kindConfig` (v1's spec), both
  would be **exempt** — deleting `dpObserveEpoch` or the CA-rotation block would
  fire no test. Introduce an explicit **`AppliesOnDP bool`** on the binding (or a
  `kindMetaApplied` kind) so every field with a DP side-effect is apply-checked
  regardless of `Kind`. Genuinely-inert meta (`Version`, `UpdatedAt`,
  `PolicyVersion`, `AuthEnabled`, `DefaultAuthOutcome` — no `applySnapshot*`
  reads them) sets `AppliesOnDP=false`.

### Layer D — redaction parity (`TestConfigSurfaces_SnapshotRedaction`) — NEW, highest severity
`controlplane_server.go:99-102` zeroes `SessionHMAC` and `IdPProfiles` for
non-enrolled `GetConfig` callers. Nothing tests this stays wired; deleting those
two lines leaks the session HMAC + OIDC client secrets to any unenrolled TLS
peer, and no parity test fires. Add a `Secret bool` (or reuse the existing
sensitive flag) on the ConfigSnapshot bindings and assert every secret-bearing
field is zeroed on the redaction path (AST: field appears in the
`!callerIsEnrolledNode` block) — mirroring how `SensitiveInvariants` walls the
rollback surface. This is the drift the wall most needs to catch and v1 omitted.

### Layer E — empty-semantics, corrected (§4)

---

## 4. Empty-semantics / omitempty — the v1 check was wrong; here is the correct one

v1 proposed: "for every `semNilSkipEmptyWipe` field assert NO `omitempty`."
**12 of the 13 such fields HAVE `omitempty`** (`PolicyRules:41`,
`SSLBypassPatterns:43`, `URLCategories:44`, `FileProfiles:45`, `RewriteRules:46`,
`DPIPatterns:47`, `PACExclusions:57`, `ThreatDomainAllowlist:62`,
`BandwidthPolicies:72`, `NodeGroups:75`, `CategoryGroups:78`,
`FileBlockExtensions:81`). Only `RateLimitExempt` (`:31`) has no `omitempty`.

Consequence: `omitempty` omits a non-nil **empty** slice, so for those 12 the
`[]`→wipe half of `semNilSkipEmptyWipe` is **dead over the wire** — an operator
clearing the last rule yields `[]`, which is omitted, which the DP reads as
nil→skip (`applySnapshotPolicyAndTraffic:316`, `if snap.PolicyRules != nil`).
The apply-side nil/[] branch is real code but unreachable via JSON for all 12.

So the correct invariant is a **three-way agreement**, checked only for fields
declared wire-wipe-capable (today: `RateLimitExempt`):
1. registry `Apply == semNilSkipEmptyWipe` **and** a new `WireWipeCapable` flag,
2. struct tag has **no** `omitempty`,
3. capture emits a **non-nil** slice unconditionally (`RateLimitExempt` at
   `:621` does; the 12 conditional captures at `:624-644` may send nil),
4. apply performs the wipe on non-nil-empty.

For the other 12 the plan must **explicitly record the intended posture**: their
`[]`-wipe is intentionally wire-dead (clearing a list does not propagate; the
operator must push a non-empty replacement or the DP keeps the last set). Either
(a) accept + document this as the contract, or (b) file a SEPARATE, deliberate,
reviewed wire change to drop `omitempty` (that IS a serialized-shape change and
must not ride this test-only PR). The test asserts the *documented* posture per
field, not a blanket rule. (v1's blanket rule both false-failed 12 fields and
its "fix" silently committed the forbidden wire change — self-contradiction.)

---

## 5. Explicitly NOT in scope
- No DTO restructure / field split / retype; no `omitempty` flips inside these
  PRs (a flip is a wire change → its own reviewed PR, §4).
- No behaviour change to capture or apply. Layers B–E are tests + registry
  metadata (`AppliesOnDP`, `WireWipeCapable`, `Secret`). A first-run failure is
  a REAL pre-existing gap → wire it, don't exempt it.

## 6. Delivery slices (corrected — no "register the rows" slice)
1. **PR-1 (capture wall):** `SnapshotCaptureParity` scanning the capture family
   with type-scoped matching + the Update-stamped carve-out. Green on current
   code (the v1 `Version`/`UpdatedAt` false-fail is designed out here).
2. **PR-2 (apply + redaction wall):** add `AppliesOnDP` + `Secret` metadata;
   `SnapshotApplyParity` (effect-based, covers `Epoch`/`CAFingerprint`) + the
   cap-parity fold-in; `SnapshotRedaction` (Layer D).
3. **PR-3 (semantics + doc):** the corrected three-way wire-wipe check (§4) with
   per-field posture recorded; fold ConfigSnapshot into the CLAUDE.md
   config-surface note; mark DEBT-006 CLOSED.

Each PR is independently green (PR-1's scoping is the fix that makes this true,
which v1 failed to establish).

## 7. Formerly-known-unclosed — resolved 2026-07-05 (post-close follow-up)
- **Wrong-owner wiring — WALLED (direct captures).** `TestConfigSurfaces_
  SnapshotCaptureOwner` scans `CurrentConfigSnapshot` for direct-receiver
  captures (`snap.Field = owner.Method(...)`) and asserts the receiver ident
  equals the registry `Owner`. Catches the type-COMPATIBLE swap the compiler
  can't (e.g. `snap.SSLBypassPatterns = dpiScanner.List()` — both `[]string`);
  the type-INcompatible swap the compiler already rejects. Out of scope by
  construction (documented, coverage-floored ≥10): captures through an
  intermediate local (`cats := catStore.All(); snap.URLCategories = cats`), a
  helper (`buildCPAddressList()`), or a stdlib wrapper (`SessionHMAC =
  hex.EncodeToString(session.SigningKey())` — receiver `hex` is not a store
  Owner, so it is skipped rather than mis-flagged).
- **Apply ordering — CLOSED BY ANALYSIS (not applicable to this surface).**
  The v1 claim ("leaf-first url_categories → category_groups → policy_rules")
  conflated this surface with the config-IMPORT path. Traced: the snapshot
  apply actually runs PolicyRules (`:317`) BEFORE URLCategories (`:334`) BEFORE
  CategoryGroups (`:447`) — the *opposite* order — and it works because each
  store's `ReplaceAll` is an independent atomic swap and rules reference
  categories/groups BY NAME, resolved at EVALUATION time
  (`policy.go:828 categoryGroupMatchesHost`), never at apply time.
  `policyStore.ReplaceAll` validates rule *shape* only (`policyRulePersistable`),
  not reference existence, so applying rules before groups drops nothing. There
  is no load-bearing apply-time ordering on the ConfigSnapshot path; a
  round-trip ordering test would assert a non-dependency. No test warranted.
- **Cap magnitude — WALLED.** `SnapshotCapParity` now asserts every cap is
  `≤ snapshotCapCeiling` (1M; current max 200k), so a `MaxInt`/absurd cap that
  defeats the H5 bound fails instead of passing the existence check.

## 8. Design-review corrections folded in (audit trail)
1. Registry rows already exist + enforced by `ReflectionParity` → PR-1 rescoped
   to the capture test only.
2. Compat framing corrected: won't-restructure-yet, not can't.
3. Capture test made robust: scan capture *family* incl. `ConfigStore.Update`;
   type-scope composite-literal match; carve out Update-stamped `Version`/
   `UpdatedAt` (else PR-1 is red).
4. omitempty check reworked: 12/13 target fields have `omitempty`; blanket
   "no omitempty" is wrong and its fix is a forbidden wire change. Restrict to
   `WireWipeCapable` fields (today `RateLimitExempt`), check the three-way
   agreement, record per-field posture.
5. `Epoch` + `CAFingerprint` have DP side-effects (`:239`, `:373-383`) → apply
   parity keys on a new `AppliesOnDP` flag, not `kindConfig`, so they can't be
   silently unwired.
6. Added Layer D redaction parity (`controlplane_server.go:99-102`) — the
   highest-severity uncovered drift (secret leak), omitted by v1.

## 9. Acceptance
- Adding a synced setting fails CI until it is registered, captured, applied
  (if it has a DP effect), capped, redacted (if secret), and wire-semantically
  consistent — the four-way + redaction drift becomes unmergeable silently.
- No production code path changes; full `-race` + existing `config_surfaces`
  invariants stay green.
- DEBT-006 MEDIUM → CLOSED, "walled by reflection parity," matching DEBT-004.
