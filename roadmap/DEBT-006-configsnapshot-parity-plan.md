# DEBT-006 — `ConfigSnapshot` CP→DP god-DTO: parity-wall design plan

**Status:** DESIGN (not yet implemented)
**Authority:** this file; derives from the config-surface registry pattern
(`config_surfaces.go`, DEBT-004) and the uiRoutes/C1 route-metadata pattern.
**Owner surface:** `controlplane_snapshot.go`
**Related closed work:** DEBT-004 (`configBackup` god-struct → registry, SHIPPED).

---

## 1. The debt, precisely

`ConfigSnapshot` (`controlplane_snapshot.go:21`) is the 34-field DTO the Control
Plane pushes to every Data Plane node on each config sync. Adding one synced
setting today means hand-wiring it into **four** locations that nothing forces
to stay in agreement:

1. **The struct** — `ConfigSnapshot` field + JSON tag + (crucially) the correct
   `omitempty` / no-`omitempty` choice. The no-`omitempty` choice is
   *semantically load-bearing*: `RateLimitExempt` documents that an empty slice
   MUST serialize as `[]` (not be omitted) so "operator removed the last
   exemption" propagates as a clear, not a skip. Get this wrong and a delete
   silently fails to replicate.
2. **`CurrentConfigSnapshot()`** (`:581`) — the CP-side capture: read the live
   value out of its owning global (`bl.List()`, `policyStore.List()`,
   `rl.ListExemptions()`, …). ~40 hand-written assignments, several gated on an
   `Enabled()`/non-nil owner.
3. **`validateConfigSnapshot()`** (`:125`) — the H5 per-slice DoS cap. A new
   `[]T` field with no cap lets a compromised CP pack the 4 MiB gRPC frame and
   force proportional alloc on every DP poll. 19 of the slice fields have caps;
   nothing proves a 20th slice field got one.
4. **The `applySnapshot*` fan-out** (`applyConfigSnapshot:232` →
   `applySnapshotPolicyAndTraffic` / `applySnapshotClusterRuntime` /
   `syncSnapshotIdPProfiles` / `applySnapshotExtendedState`) — the DP-side
   apply, each field with bespoke `nil`→skip / `[]`→wipe / `""`→skip / zero→skip
   semantics that MUST mirror the capture's serialization choice from (1).

**Interest paid:** the same drift disease `configBackup` had. A field added to
the struct + capture but forgotten in `validate` is an uncapped DoS vector; one
forgotten in `apply` is a silently-unsynced setting (DP diverges from CP with no
error); a capture/apply empty-semantics mismatch is a delete that doesn't
replicate. All three are invisible until a cluster misbehaves in production —
the failure mode is silent divergence, not a crash.

**Why it's worse than `configBackup` was:** this DTO crosses the CP↔DP **wire**
and the ADR-0005 fencing-epoch boundary. A naive "just split the struct" is
unsafe: old DPs must still parse new snapshots (forward-compat) and new DPs must
apply old snapshots (backward-compat), so we cannot rename/retype fields freely.
The safe move is therefore NOT to restructure the DTO — it is to **wall the
existing DTO with a parity registry + reflection tests**, exactly as DEBT-004
did, so the four lists cannot drift even though the wire shape is frozen.

---

## 2. What already exists (do not rebuild)

`config_surfaces.go` **already registers `ConfigSnapshot`** as surface #4 and
`validateConfigSnapshot` caps as surface #5, and
`TestConfigSurfaces_SnapshotCapParity` already asserts every capped slice maps
to a real field. So the registry *knows about* ConfigSnapshot for the
export/rollback axis. **The gap:** the registry does NOT yet enforce the two
ConfigSnapshot-specific invariants that actually drift:

- **Capture parity** — every `kindConfig` ConfigSnapshot field is assigned in
  `CurrentConfigSnapshot()`.
- **Apply parity** — every `kindConfig` ConfigSnapshot field is consumed in one
  of the `applySnapshot*` helpers, with empty-semantics matching the registry's
  declared `Apply` value.

These are the reflection/AST checks DEBT-004 built for `configBackup`'s
capture/apply trio but never extended to the CP→DP surface.

---

## 3. Design — three enforcement layers, zero wire change

### Layer A — complete the registry rows (data only)
Extend `configSurfaces` so **every** `ConfigSnapshot` field has a row carrying:
- `Kind` (config / meta / sentinel) — `Version`/`Epoch`/`UpdatedAt`/
  `PolicyVersion`/`CAFingerprint`/`DefaultAuthOutcome` are `kindMeta`
  (informational or fence/version plumbing the DP does not "apply" as config).
- `Apply` empty-semantics for the DP path: `semNilSkipEmptyWipe`
  (`RateLimitExempt`, `PolicyRules`, `SSLBypassPatterns`, …), `semSkipIfZero`
  (`DefaultAction`, `MaxConnsPerIP`), `semAlwaysReplace` (`IPFilterMode`+`IPList`
  rebuild), `semValidatedSkip` (`IdPProfiles`, `IPList` entries).
- `Cap` binding for slice fields (already half-present via the cap-parity test).

### Layer B — capture parity test (reflection + AST)
`TestConfigSurfaces_SnapshotCaptureParity`: reflect over `ConfigSnapshot`
fields; for each `kindConfig`/`kindMeta` field assert the identifier appears as
an assigned field (`snap.X =` or a composite-literal key `X:`) in
`CurrentConfigSnapshot`'s AST. Fails naming the exact field left uncaptured.
(Mirrors `config_surfaces_test.go`'s existing source-scan style — no new deps.)

### Layer C — apply + cap parity test
`TestConfigSurfaces_SnapshotApplyParity`: for each `kindConfig` field assert the
identifier is read (`snap.X`) somewhere in the `applySnapshot*` family; assert
every `[]T`/`map` `kindConfig` field has a `validateConfigSnapshot` cap (fold in
the existing `SnapshotCapParity` assertion). A field captured-but-not-applied,
or applied-but-uncapped, fails by name.

**Empty-semantics cross-check (the high-value one):** for each field whose
registry `Apply == semNilSkipEmptyWipe`, assert the capture serializes nil-vs-[]
faithfully — i.e. the struct field has NO `omitempty` (else an operator's
"cleared to empty" is dropped on the wire and the DP keeps stale state). This is
the check that would have caught the `RateLimitExempt` class of bug at test
time instead of in a cluster.

---

## 4. Explicitly NOT in scope

- **No DTO restructure / field split / retype.** Wire+epoch compat is frozen;
  this is a test-wall, not a refactor. (If a future ADR wants to shard the DTO,
  it does so behind a version negotiation — out of scope here.)
- **No behaviour change** to capture or apply. Layers B/C are pure tests; Layer
  A is pure data. If a parity test fails on first run it has found a REAL
  pre-existing drift — fix by wiring the field, not by exempting it.
- **No new `omitempty` flips** except where an empty-semantics test proves a
  current tag contradicts the declared apply semantics (that IS a latent bug;
  fix it and note it).

## 5. Delivery slices
1. **PR-1 (data + capture wall):** complete registry rows for all 34 fields;
   ship `SnapshotCaptureParity`. Any drift it finds → wire + note.
2. **PR-2 (apply + semantics wall):** `SnapshotApplyParity` + the
   nil-vs-`[]` omitempty cross-check; fold in the existing cap-parity assertion.
3. **PR-3 (doc):** fold the ConfigSnapshot surface into the CLAUDE.md
   config-surface-registry note; mark DEBT-006 CLOSED in the debt register.

Each slice is independently green and reversible; PR-1 is safe even if PR-2/3
never land (it only adds a test + data).

## 6. Acceptance
- Adding a synced setting fails CI until the field is present in the struct,
  captured, applied, capped, and registered — the four-way drift is impossible
  to merge silently.
- No production code path changes; the full `-race` suite + the existing
  `config_surfaces_test.go` invariants stay green.
- DEBT-006 moves MEDIUM → CLOSED with the same "walled by reflection parity"
  status DEBT-004 carries.
