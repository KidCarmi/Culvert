# F3 — Architecture Closure: Ownership Contract & Second-Floor Durability

**Status:** DESIGN ONLY (F3 architecture-closure gate). No implementation code, no
source-dataset edits, no F5 publisher/workflow, no DNS/R2/Cloudflare/publication,
no Sigstore issuer/SAN/root change, no runtime wiring, no new runtime
dependencies. This document resolves the two design items F0 left open
(§20 items 2 and 3) so that F3 implementation can proceed safely and reviewably.

**Base:** branch `claude/feeds-f3-design`, forked from `origin/main` @ `6810fce`
(the PR #978 source-reconciliation merge). Clean worktree. The only file this
checkpoint adds is this document.

**Authoritative inputs:**
- `roadmap/FEEDS-DISTRIBUTION-F0-DESIGN.md` (rev 2, merged) — the architecture this
  document closes. F0 §7.3 declares the CP/DP split at a level of intent; §8/§9 the
  immutable-generation + atomic-activation-record model; §20 items 2/3 flag the two
  items resolved here.
- `roadmap/FEEDS-SOURCE-RECONCILIATION.md` (merged) — the accepted dataset (frozen;
  not touched here).
- `internal/urlcatfeed/` (F1/F2 trust kernel, merged PR #975) — `Generate`,
  `VerifyEnvelope`, `EvaluateReadiness`, `NormalizeHost`, `SchemaVersion=1`,
  `Protocol="signed_manifest_v1"`, `FeedID="url-categories/saas"`,
  `MaxValidity=30*24h`, `MaxArtifactSize=8<<20`, `MaxBundleBytes=1<<20`.
- Repository evidence inspected for this document (file:line grounding):
  - CP→DP transport: `controlplane_snapshot.go:22-112` (`ConfigSnapshot`),
    `:45` (`URLCategories`), `:95` (`CategoryGroups`), `:105`
    (`DecryptionProfiles` — the no-omitempty/WireWipeCapable delete-propagation
    precedent), `:135-163` (per-slice caps), `:207` (`maxSnapURLCategoryHosts`),
    `:637-673` (`applyConfigSnapshot`), `:754-760` (URL-categories apply),
    `:890-896` (category-groups apply), `:1048-1132` (`CurrentConfigSnapshot`),
    `:443-493` (`ConfigStore.Update`), `:27`/`:1050` (`Epoch`).
  - Redaction: `controlplane_server.go:171-174` (`redactUnenrolledSnapshot`).
  - Fencing: `ha_fencing.go:113`/`:122-150` (`dpObserveEpoch` ratchet).
  - Registry + parity: `config_surfaces.go:273-293` (category rows), `:349-350`
    (`saas_feed_url` row), `:365-380` (autoexclude AdminDurable-only exemplar);
    `config_surfaces_test.go` (8 ConfigSnapshot parity tests; capped-count literal
    `:146` = 22).
  - Settings persistence: `admin_settings.go:23-160` (struct), `:102-103`
    (`SaaSFeedURL`), `:314-317` (apply), `:573-576` (save), `:91-100`/`:333-357`/
    `:489-500` (`BlocklistFeedsSaved` sentinel exemplar), `:170-215` (load +
    quarantine).
  - One-way migration precedent: `store.go:756-771` (envelope, `*string`
    absent-vs-empty), `:617-640` (read-iff-absent), `:850-864` (never-write).
  - Export/import + rollback: `ui_policy.go:1196-1300` (`configBackup`),
    `ui_config.go:664-667`/`:1228-1245` (category export/import, leaf-first,
    never-wipe), `configversion.go:43-99`/`:311-464`/`:490-577` (capture/apply/diff,
    leaf-first, 50-version cap).
  - Durability reference stack: `release_catalog_freshness.go:69-72`
    (`catalogStateFile` `(version, generated_at)` pair), `:131-140`
    (`checkCatalogReplay`), `:147-180` (`applyFreshnessAndRollback`), `:200-219`
    (`readFloorState` — corrupt=fail-closed), `:230-250` (`writeFloorState`);
    `release_autoseed.go:110-132` (`swapCatalogDir` move-aside),
    `release_catalog_holder.go:113-130` (`Reload` — floor persist BEFORE in-memory
    store); `internal/fileutil/fileutil.go:19-71` (`AtomicWrite` —
    temp+fsync+rename+parent-fsync).
  - Category engine: `internal/urlcat/urlcat.go:305-327` (`MatchesHost` —
    per-category suffix walk, NO longest-match/priority), `:80-119` (embed +
    `DefaultEntries`), `:123-146` (`Load`); `policy.go:1540-1552` (`matchCategory`).
  - Current SaaS feed surface: `internal/saasfeed/saasfeed.go:37`/`:114-154`
    (`DefaultFeedURL`, `Configure`), `saas_feed.go:41-75` (additive
    `mergeSaaSCategories`), `ui_policy.go:1158-1184`/`:2244` (read-only
    `apiURLCatFeedStatus`) — **no writable API/GUI exists today**.
  - Handler/route/OpenAPI/GUI pattern: `decryption_redaction.go:36-122`
    (GET-viewer/PUT-admin, apply-then-persist-with-rollback, audit),
    `ui_policy.go:2238` (route), `ui_routes_meta.go:282-286` (metadata),
    `api/openapi/openapi.yaml:4533-4583` (`x-culvert-*` vendor block),
    `static/index.html:3185-3237` (status-panel + admin-editable-panel pattern),
    route-count gate `d0_helpers_test.go`.

---

## 0. Executive summary

**Part A (F3a ownership).** Feed state splits into **four ownership domains**, each
with a single authoritative owner and a fixed lifecycle:

1. **Feed configuration** (which URL, which protocol, enabled/managed, refresh
   interval) — **CP-authoritative, fleet-uniform**: dual `AdminDurable` +
   `ClusterSynced` (the `default_action`/`base_url` precedent). The DP applies the
   synced settings, then **independently** fetches + verifies + activates. CP-sync
   never weakens trust because the DP's local Sigstore verification, SSRF guard, and
   single-protocol enforcement are the backstop (a hostile URL from a compromised CP
   can only produce a verify failure, never unsigned data).
2. **Admin category overrides** (`overrides.json`: tombstones / recategorizations /
   additions) — **CP-authoritative, fleet-uniform**: joins the `ConfigSnapshot`
   category surface next to `URLCategories`/`CategoryGroups`, but with the
   **`DecryptionProfiles` delete-propagation posture** (no `omitempty` +
   `WireWipeCapable`) because clearing overrides must reach the DP.
3. **Active feed generation + activation record + rollback floor** — **node-local
   durable**, never synced/exported/rolled-back. Each node fetches, verifies, and
   activates its own generation (the release-catalog precedent).
4. **Runtime status** (state, counters, provenance, freshness) — **node-local
   runtime/derived**, read-only API only.

**Part B (F3b second floor).** Selected design: **two redundant floor/commit-intent
records** (`floor.a`/`floor.b`, peers — not primary/mirror) plus the activation
record's floor copy, each self-checksummed (CRC-32C, corruption detection only — *not*
authenticity) and written via `AtomicWrite`. The design **separates four concerns
explicitly** — rollback-floor selection, active-generation selection,
resumable-candidate state, and the live in-memory commit point — so **a floor number
never implicitly selects content for activation**. Floor selection is the numeric
`max` over *valid, compatible, non-equivocating* records (+ compiled checkpoint);
content selection is record-driven and **digest-re-verified**, never numeric/filename/
mtime. Each floor record **binds the candidate generation id + manifest/artifact
digests**, so an interruption after the floor advances but before the activation
commits is **resumed** (Option 1: re-verify the exact immutable generation from its
signed bytes and complete activation idempotently — zero freshness lag, versus one
publish cycle of staleness for the reject-and-wait alternative). Two same-version
records with different digests are **equivocation** ⇒ fail closed + critical. This
closes F0 §9's hole for **both** the floor and the served content, keeps the F0 §8
commit ordering (generation durable → commit-intent durable → activation commit →
serve), and — stated honestly — the two records are **redundant durable records on one
filesystem, not independent failure domains**: they protect against isolated record
loss/corruption and interrupted replacement under the `fsync`/FS assumption, **not**
against whole-volume rollback, FS-wide corruption, a privileged local attacker, or
loss of the directory/device. Those need an external anchor (out of F3b scope); the
compiled checkpoint is the only floor none of them can lower.

**Part C.** Six slices: `F3a-1` (schema/ownership/migration, no wire),
`F3a-2` (API/OpenAPI/GUI/export-import + CP→DP), `F3b-1` (floor storage + state
machine), `F3b-2` (downloader/verify + immutable-generation storage),
`F3b-3` (activation/recovery/GC), `F3b-4` (observability + failure injection). F5
(the CI publisher) may proceed **in parallel** against the frozen F1/F2 on-wire
contract; the only thing it must not get ahead of is a change to the artifact/
manifest schema — which F3 does not make.

---

# PART A — F3a OWNERSHIP & CONTRACT

## A.0 The four ownership domains (and why the split is safe)

F0 §7.3 stated the split as intent ("overrides are CP-authoritative; the snapshot is
node-local"). F3a makes it exact. The governing principle, grounded in the existing
registry semantics (`config_surfaces.go`):

| Domain | Owner | Persisted | CP→DP | Export/Import | Rollback | Rationale |
|---|---|---|---|---|---|---|
| Feed configuration | CP (fleet) | yes (`AdminSettings` + `ConfigSnapshot`) | **yes** | yes | yes | Fleet must agree where the feed comes from and whether it is on — this is management policy, like `default_action` (`config_surfaces.go:152-159`). |
| Category overrides | CP (fleet) | yes (`overrides.json` + `ConfigSnapshot`) | **yes** | yes | yes | F0 §7.3: URL categories are fleet policy, not appliance tuning. |
| Active generation + activation record + floor | Node-local | yes (node-local files) | **no** | no | no | Security-critical fetch/verify/floor is re-derivable and signature-verified locally; syncing it would import another node's trust decisions (release-catalog precedent, `release_catalog_freshness.go`). |
| Runtime status | Node-local | no (runtime) / partial (activation record) | no | no | no | Derived telemetry; never a config input. |

**Why CP-syncing the feed URL does not weaken the trust boundary** (addresses the
"arbitrary/private-mirror URL", "SSRF weakening", "protocol downgrade" concerns):
the URL is *transport addressing only*. Every byte the DP fetches from it is verified
in-binary against the **pinned feed identity + baked Sigstore root** (F0 §5), with
**no unsigned/raw fallback and no protocol downgrade** (F0 §13, single
`signed_manifest_v1`). The DP's `isPrivateHost` SSRF guard rejects private
destinations regardless of who set the URL. Therefore a compromised CP that pushes a
hostile or private URL can, at worst, cause the DP's fetch to **fail verification or
be SSRF-refused** — it can never cause unsigned/attacker data to activate. The CP is
inside the trust boundary for *addressing*, outside it for *content*. This is the same
property that lets `otlp_endpoint`/`base_url` be CP-synced today.

## A.1 Per-field ownership table (authoritative)

Legend — **Persist**: `durable` (survives restart) / `runtime`. **Owner**: `CP`
(fleet-authoritative, synced) / `node` (node-local) / `compiled` (immutable binary
constant) / `derived`. **Mut**: `configurable` / `immutable`.

| Field | Persist | Owner | Mut | API | GUI | Exp/Imp | Rollback | CP→DP | Downgrade behavior | Default / validation | Change triggers |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `saas_feed_protocol` | durable | CP | configurable (1 legal value) | GET viewer / PUT admin | admin panel | yes | yes | yes (scalar, `omitempty`) | old binary ignores unknown key; on-wire value only ever `signed_manifest_v1` | default `signed_manifest_v1`; reject any other value at settings-write | validation only (no refetch) |
| `saas_feed_url` | durable | CP | configurable (official origin only) | GET viewer / PUT admin | admin panel | yes | yes | yes (scalar, `omitempty`) | old binary ignores unknown key | default `""`⇒built-in official envelope URL; validate per the §A.8 contract (exact official origin, or a historical URL rewritten to it; **all else rejected**) | **triggers refetch+verify+activate** on the node |
| `saas_feed_managed` | durable | CP | configurable | (folded into settings PUT) | admin toggle | yes | yes | yes (scalar bool, no `omitempty` — see §A.5) | old binary reads `false`⇒on-by-default preserved | default `false` (never touched) | resolves enable |
| `saas_feed_enabled` | durable | CP | configurable | (folded into settings PUT) | admin toggle | yes | yes | yes (scalar bool, no `omitempty`) | old binary reads `false` but `managed=false`⇒still on-by-default | authoritative only when `managed=true` | enable⇒arm loop; disable⇒serve embedded |
| `saas_feed_refresh_interval` | durable | CP | configurable | GET viewer / PUT admin | admin panel | yes | yes | yes (scalar, `omitempty`) | old binary ignores unknown key | default `24h`; min-clamp `1h`, parse `time.Duration` | re-arm ticker |
| category **overrides** (`added`/`recategorized`/`tombstones`) | durable | CP | configurable | GET viewer / PUT admin | overrides editor | yes | yes | **yes (slice, no `omitempty` + `WireWipeCapable`)** | old binary ignores unknown snapshot field⇒overrides simply not applied (feed-only view) | per-host `NormalizeHost` parity (§A.4); reject IP/wildcard/PSL-only | recompute composed view |
| `COMPILED_MIN_FEED_VERSION` | compiled | compiled | immutable | (surfaced read-only) | read-only status | no | no | no | n/a | baked at build | fresh-install floor |
| `COMPILED_MAX_VALIDITY` (30d) | compiled | compiled | immutable | (surfaced read-only) | read-only status | no | no | no | n/a | baked `30*24h` (= `urlcatfeed.MaxValidity`) | validity ceiling |
| fetch timeout / `MaxArtifactSize` / `MaxBundleBytes` / envelope cap | compiled | compiled | immutable | — | — | no | no | no | n/a | `urlcatfeed.MaxArtifactSize=8<<20`, `MaxBundleBytes=1<<20` | bounded reads |
| `active_feed_version` | durable | node | derived | GET viewer | read-only status | no | no | no | n/a | from activation record | — |
| `active_source` (`downloaded`/`cached`/`embedded`) | runtime | derived | derived | GET viewer | read-only status | no | no | no | n/a | derived | — |
| `rollback_floor` (`version`,`generated_at`) | durable | node | derived (monotonic) | GET viewer | read-only status | no | no | no | n/a | `max(compiled_checkpoint, valid floors)` (Part B) | ratchets on activation |
| `state`/`last_attempt`/`last_success`/`last_outcome`/`consecutive_failures`/`failures_since_start`/`last_error_class`/`last_http_status`/`last_activation_delta`/`signature_status`/`manifest_expires_at` | runtime | derived | derived | GET viewer | read-only status | no | no | no | n/a | F0 §14 | — |

## A.2 CP-authoritative feed settings — exact wiring

### A.2.1 `AdminSettings` additions (`admin_settings.go`)

Replaces the single `SaaSFeedURL string` (`admin_settings.go:103`) with the F0 §3
sentinel set. snake_case; sentinel bools carry **no** `omitempty` (they must
serialize as `false` to be meaningful — the `admin_settings.go:91-100` convention):

```go
// SaaS signed category feed (F3a). SaaSFeedManaged is the sentinel that
// distinguishes "operator never touched it" (false ⇒ on-by-default, F0 §2.2)
// from "explicitly configured". SaaSFeedEnabled is authoritative only when
// managed. Empty URL ⇒ built-in envelope endpoint (never conflated with
// disable — F0 §2.3). Protocol has one legal value today; the field exists so
// a future scheme is an explicit versioned change, not a silent flip (F0 §13).
SaaSFeedManaged        bool   `json:"saas_feed_managed"`
SaaSFeedEnabled        bool   `json:"saas_feed_enabled"`
SaaSFeedURL            string `json:"saas_feed_url,omitempty"`
SaaSFeedProtocol       string `json:"saas_feed_protocol,omitempty"`   // "" ⇒ signed_manifest_v1
SaaSFeedRefreshSeconds int64  `json:"saas_feed_refresh_seconds,omitempty"`
```

- **Apply** (`applyAdminServices`, replacing `admin_settings.go:314-317`): resolve
  `(managed, enabled, url, protocol, interval)` via the F0 §3 single-source rule,
  validate, and drive the new downloader engine (F3b) — **not** the legacy
  `globalSaaSFeed.Configure` additive syncer, which F3b retires. Gate on `managed`
  the way `applyBlocklistFeeds` gates on `BlocklistFeedsSaved`
  (`admin_settings.go:333-357`): a pre-F3a file (`managed=false`, no fields) keeps
  the on-by-default built-in endpoint; an explicit disable (`managed=true,
  enabled=false`) is durable.
- **Save** (`saveAdminSettingsWithOverrides`, replacing `admin_settings.go:573-576`):
  snapshot all five fields from the live resolver — per the
  `admin_settings.go:506-508` warning, every durable field MUST be snapshotted here
  or it is silently dropped on the next unrelated mutation.

### A.2.2 `ConfigSnapshot` additions (`controlplane_snapshot.go`)

Five scalar fields (scalars ⇒ `SnapshotCap = 0`, so they do **not** bump the capped
count literal). `omitempty` on the value fields (an absent field means "CP has not
set it", the DP keeps its local resolution); the two sentinel bools carry **no**
`omitempty` so a `false` propagates:

```go
SaaSFeedManaged        bool   `json:"saas_feed_managed"`
SaaSFeedEnabled        bool   `json:"saas_feed_enabled"`
SaaSFeedURL            string `json:"saas_feed_url,omitempty"`
SaaSFeedProtocol       string `json:"saas_feed_protocol,omitempty"`
SaaSFeedRefreshSeconds int64  `json:"saas_feed_refresh_seconds,omitempty"`
```

- **Capture** in `CurrentConfigSnapshot` (`controlplane_snapshot.go:1048-1132`):
  `snap.SaaSFeed* = <resolver getters>`.
- **Apply** in an `applySnapshot*` function (the traffic/extended-state family,
  `controlplane_snapshot.go:754-903`): validate then drive the downloader; a
  URL/protocol change **triggers a node-local refetch**. Not sensitive ⇒ no
  redaction.
- These are **not** secrets ⇒ they stay out of `redactUnenrolledSnapshot`
  (`controlplane_server.go:171-174`).

### A.2.3 `config_surfaces.go` rows

Replace the single `saas_feed_url` AdminDurable-only row
(`config_surfaces.go:349-350`) with dual `AdminDurable + ClusterSynced` rows (the
`default_action` shape, `config_surfaces.go:152-159`), each with **two** bindings
(`AdminSettings` + `ConfigSnapshot`):

```go
{ID: "saas_feed_url", Kind: kindConfig, Owner: "saasFeed",
    AdminDurable: true, ClusterSynced: true,
    Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "saas_feed_url",
    Bindings: []surfaceBinding{
        {Struct: "AdminSettings", Field: "SaaSFeedURL"},
        {Struct: "ConfigSnapshot", Field: "SaaSFeedURL", Apply: semSkipIfZero}}},
// … analogous rows for saas_feed_protocol, saas_feed_managed, saas_feed_enabled,
//     saas_feed_refresh_seconds (managed/enabled use Apply: semAlwaysReplace since
//     a false bool must propagate; the value fields use semSkipIfZero).
```

### A.2.4 Parity-test deltas (`config_surfaces_test.go`)

Scalars, so: `TestConfigSurfaces_ReflectionParity` gains five claimed struct fields
(each on both `AdminSettings` and `ConfigSnapshot`);
`TestConfigSurfaces_SnapshotCaptureParity` requires each `ConfigSnapshot` field
assigned in `CurrentConfigSnapshot`; `TestConfigSurfaces_SnapshotApplyParity`
requires each read in the apply family; `TestConfigSurfaces_SnapshotCaptureOwner`
requires direct-receiver captures to match `Owner:"saasFeed"` (use an intermediate
local if the getter shape differs, as `URLCategories` does). **The capped-count
literal (`config_surfaces_test.go:146`, currently `22`) does NOT change** for these
scalars. Rollback membership adds `csrNilGuardCases`? No — scalars are diffed
directly, not nil-guarded; add scalar diff coverage to `diffConfigs`
(`configversion.go:490-577`) and a `TestConfigSurfaces_DiffCoverage` row.

## A.3 CP-authoritative category overrides — exact wiring

### A.3.1 Override model (node-composed, CP-owned data)

`overrides.json` (F0 §7.2), a new engine `internal/catoverride` with a
`catgroup`-style `Store`:

```go
type Overrides struct {
    Added         map[string]string `json:"added"`          // host → category
    Recategorized map[string]string `json:"recategorized"`  // host → category
    Tombstones    []string          `json:"tombstones"`     // hosts (host+subdomain scope)
}
```

The **composed effective view** = feed snapshot − tombstones, then apply
recategorizations, then union `added` (F0 §7.2, a pure function recomputed on
activation and on override edits). Host keys carry the **same suffix semantics as a
feed entry** (F0 §7.5), matching `MatchesHost`'s per-category suffix walk
(`internal/urlcat/urlcat.go:305-327`) — verified against `NormalizeHost` (§A.4).

### A.3.2 `ConfigSnapshot` addition + wire-wipe decision

```go
CategoryOverrides CategoryOverrideSet `json:"category_overrides"`   // NO omitempty
```

**Decision — follow the `DecryptionProfiles` posture, not `URLCategories`.**
`URLCategories`/`CategoryGroups` are `omitempty` + `semNilSkipEmptyWipe` +
**not** `WireWipeCapable` ("import never wipes", `config_surfaces.go:287-293`):
their empty-slice clear is intentionally wire-dead. Overrides are different — an
admin clearing all overrides is a **security-relevant policy change that must reach
every DP** (a stale tombstone left on a DP would keep a host suppressed after the
fleet un-suppressed it). This is exactly the `DecryptionProfiles` rationale
(`controlplane_snapshot.go:97-104`): no `omitempty`, `WireWipeCapable:true`, so a
last-override delete propagates as an empty clear. `SnapshotCap =
maxSnapCategoryOverrides` (proposed `100_000` host-keys, `≤ snapshotCapCeiling` 4M).

- **Apply ordering**: leaf-first, **before** the composed view is built and before
  `PolicyRules` — same ordering discipline as `url_categories → category_groups →
  policy_rules` (`config_surfaces.go:148,276,283`). Overrides layer on the feed
  snapshot, which is node-local; the apply re-runs the composition.
- **Redaction**: overrides are not secrets ⇒ **not** in `redactUnenrolledSnapshot`.

### A.3.3 `config_surfaces.go` row + parity deltas

```go
{ID: "category_overrides", Kind: kindConfig, Owner: "globalCategoryOverrides",
    Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "category_overrides",
    DiffNilGuarded: true, ClusterSynced: true, WireWipeCapable: true,
    SnapshotCap: maxSnapCategoryOverrides,
    Note: "apply ordered before the composed view + policy_rules; delete-propagates (DecryptionProfiles posture)",
    Bindings: []surfaceBinding{
        {Struct: "configBackup", Field: "CategoryOverrides", Apply: semNilSkipEmptyWipe},
        {Struct: "ConfigSnapshot", Field: "CategoryOverrides", Apply: semNilSkipEmptyWipe}}},
```

Parity deltas: this is a **capped `ConfigSnapshot` slice**, so
`config_surfaces_test.go:146` **bumps 22 → 23** (`TestConfigSurfaces_SnapshotCapParity`);
add a new cap constant `maxSnapCategoryOverrides` in `controlplane_snapshot.go:135-163`
and its `configSnapshotSliceCaps` row + host-aggregate math in
`validateConfigSnapshot`; add a `csrNilGuardCases` entry
(`config_surfaces_test.go:183-231`) for `TestConfigSurfaces_DiffNilGuardMirrorsApply`;
add a `TestConfigSurfaces_SnapshotWireWipe` pairing (`WireWipeCapable` ⇔ no
`omitempty`); capture in `CurrentConfigSnapshot`, apply in the family, and add the
rollback round-trip (`TestConfigSurfaces_RollbackRoundTrip`).

## A.4 Node-local runtime & durable state (NOT synced)

Node-local durable (Part B governs the on-disk contract):

```
<dataDir>/saas_feed/
  generations/<feed_version>/{manifest.envelope.json, artifact.json,
                             artifact.json.sigstore, snapshot.normalized.json}
  activation-state.json          ← node-local activation authority (F0 §8)
  floor.a.json  floor.b.json     ← redundant floor/commit-intent records (Part B)
```

`overrides.json` is CP-authoritative (§A.3) and lives beside these but is **synced**;
everything else here is node-local, never in `ConfigSnapshot`, `configBackup`, or the
rollback surface — declared with **no** `ConfigSnapshot`/`configBackup` binding
(the `metrics_token`/autoexclude-tunables node-local shape,
`config_surfaces.go:365-380`).

**Normalization parity (F0 §7.5, exact).** Producer and client both use
`urlcatfeed.NormalizeHost` (merged), which must be parity-equal to
`hostutil.NormalizeHost` + the index's trailing-dot strip
(`internal/urlcat/urlcat.go:71`). Overrides key on the same normalized form. A
mismatch between the artifact's stated hosts and their normalized form ⇒ candidate
rejected (F0 §6 step 7). This parity is pinned by a test that feeds every embedded
host through both normalizers and asserts equality.

## A.5 Schema versioning & migration

### A.5.1 Store schema marker (F0 §12)

Add `saas_store_schema_version` (int, current `1`) to the `activation-state.json`
envelope and to `overrides.json` — **confirmed absent today** (no
`saas_store_schema_version` anywhere; the category store persists a bare array with
no envelope, `internal/urlcat/urlcat.go:154`). This gives future upgrades a real
migration edge. Unknown-newer schema ⇒ fail-closed to embedded baseline + critical
signal (never silently mis-parse).

### A.5.2 Durable-disable — the `*string` absent-vs-empty pattern

The F0 §3 sentinel (`managed`+`enabled`) is the primary mechanism, but the migration
**input** must reproduce the retired-`unauth_mode` discipline
(`store.go:756-771,617-640,850-864`): the legacy `saas_feed_url` is a **read-only,
one-way migration input** consulted **only** when the new sentinel fields are absent;
it is **never rewritten to the old GitHub value**. Concretely, load resolves in this
order (fail-closed, idempotent):

1. If `saas_feed_managed`/`saas_feed_enabled` present ⇒ authoritative (F0 §3 rule).
2. Else migrate from the legacy `saas_feed_url` per the §A.5.3 matrix; set
   `managed` only when the operator had explicitly set a custom URL.

### A.5.3 URL migration matrix (F0 §15, exact-string, idempotent)

| Persisted `saas_feed_url` | Class | Action |
|---|---|---|
| `""` / absent | unset | built-in envelope endpoint; no rewrite; no spurious `managed`. |
| `…/main/default_categories.json` (pre-move) | historical built-in | rewrite → built-in `feeds.culvertlabs.com` envelope URL. |
| `…/main/internal/urlcat/default_categories.json` (current, = `saasfeed.DefaultFeedURL`) | historical built-in | rewrite → built-in envelope URL. |
| already the built-in envelope URL | migrated | no-op. |
| any other non-empty value | unsupported | **reject** at validation (§A.8); never rewritten, never silently trusted, never activated as a generic mirror. |

Exact-string match only (no substring/prefix — a fork must not be caught).
Persistence-failure ⇒ migration **not** marked applied; the in-memory resolved URL
still targets the correct endpoint this run; retried next boot; **never** falls back
to the old GitHub URL.

**R1 obligation 6 — no generic mirror feature.** F0 §13's "any `signed_manifest_v1`
mirror" phrasing is **narrowed here**: F3 does **not** ship a general "point the feed
at any signed mirror" capability. The `saas_feed_url` field is retained (persisted +
CP-synced) **only for schema consistency and future extensibility** — the *only* values
that pass validation are the official origin and the two historical URLs (which are
*rewritten* to it). Every other value **fails validation** (§A.8); it never becomes a
signed-feed mirror. Signature verification is **not** a licence to accept arbitrary
destinations — SSRF is enforced independently, at dial time (§A.8).

## A.6 API / OpenAPI / GUI / export-import / rollback behavior

**Handler** (the `apiDecryptionRedaction` template, `decryption_redaction.go:36-122`):
a new `apiSaaSFeedSettings` (GET viewer / PUT admin) — `switch r.Method`,
`requireRole(w,r,RoleViewer|RoleAdmin)`, `decodeJSON`, **apply-then-persist with
runtime rollback** on `SaveAdminSettings()` failure, `auditEvent(r,
"saasfeed.settings", …)`, `saveConfigVersion(actor,"saasfeed.settings")`, `jsonOK`.
Overrides get `apiSaaSFeedOverrides` (GET viewer list / PUT admin full-set). Read-only
status stays on the existing `GET /api/urlcat/feed-status`
(`ui_policy.go:1158-1184`), extended with the F0 §14 fields.

- **Route registration** in `registerPolicyRoutes` (`ui_policy.go:2208`); metadata
  rows in `uiRoutes` (`ui_routes_meta.go`); **route-count gate must bump**
  (`d0_helpers_test.go` + `ui_routes_meta_test.go`).
- **OpenAPI**: add the paths with the full `x-culvert-*` vendor block + request/
  response `$ref` schemas (`api/openapi/openapi.yaml:4533-4583` shape); regen
  `make api-bundle`; pass `TestOpenAPI_Gate3`.
- **GUI**: a SaaS-feed section in the URL-Categories view — a read-only status panel
  (bound to `/api/urlcat/feed-status`, already rendered by `loadURLCatFeedStatus`,
  `static/index.html:6193`) + a `data-min-role="admin"` editable panel (URL /
  protocol / enabled / interval + overrides editor), the exact
  status-panel + admin-panel pattern of the Decryption Exclusions view
  (`static/index.html:3185-3237`).
- **Export/import** (`configBackup`, `ui_config.go`): add `SaaSFeed*` scalars +
  `CategoryOverrides` (camelCase, no `omitempty` for the override slice); import is
  **never-wipe on absent/empty** for the settings (guard `len>0`/non-empty, the
  `importCategoryTaxonomy` rule `ui_config.go:1228-1245`), overrides apply
  leaf-first before policy rules (`ui_config.go:970`).
- **Rollback** (`configversion.go`): capture non-nil, apply nil-skip/`[]`-wipe,
  nil-guarded diff, leaf-first (`configversion.go:316-321`). The **node-local**
  generation/floor/activation state is deliberately **off** every one of these
  surfaces.

## A.7 Anti-drift summary (what tests/literals change in F3a)

- `config_surfaces_test.go:146` capped literal **22 → 23** (only the `CategoryOverrides`
  capped slice; the five scalars do not count).
- New rows + bindings in `config_surfaces.go`; new cap constant
  `maxSnapCategoryOverrides` in `controlplane_snapshot.go`.
- Route-count gates in `d0_helpers_test.go` / `ui_routes_meta_test.go` bump for the
  new API routes.
- `make api-bundle` regen + `TestOpenAPI_Gate3` for the OpenAPI additions.
- The 8 `ConfigSnapshot` parity tests name every unwired place if a field is added to
  the struct without its capture/apply/redaction/cap wiring.

## A.8 Manifest-URL & SSRF contract (R1 obligation 6)

The `saas_feed_url` field addresses *transport only*; the accepted-URL contract is
**deliberately narrow** — the official origin, nothing else — and SSRF is enforced at
dial time **independently of, and prior to, signature verification** (a fetch to a
private address is an SSRF probe regardless of whether the response would later fail to
verify; signature checking is not a substitute for an SSRF guard).

**Accepted manifest URL (validated at settings-write AND re-checked before every
fetch):**

| Rule | Requirement |
|---|---|
| Scheme | exactly `https` (reject `http`, and every non-`https` scheme). |
| Origin (host) | exactly `feeds.culvertlabs.com` (exact-string host; **no** subdomain wildcard, **no** other host). |
| Userinfo | reject any `user[:pass]@` component. |
| Port | reject an explicit port other than the implicit 443 (no `:8443`, etc.). |
| Query / fragment | reject any `?query` or `#fragment` on the manifest URL. |
| IP literals | reject IPv4/IPv6 literal hosts (host must be the exact DNS name above). |
| Path — manifest | exactly the canonical `/v1/url-categories/saas/manifest.sigstore.json`. |
| Path — artifact | the artifact/`.sigstore` keys are **not** operator-supplied — they are read from the *verified* manifest payload's `artifact_path`, validated as a safe single-segment relative key under `/v1/url-categories/saas/` (no `..`, no leading `/`, allowed charset), exactly F0 §6 step 4. |

**Fetch-time network protections (independent of the above, always on):**
- **DNS + private-address guard:** resolve the host, then **dial the resolved IP** and
  run `isPrivateHost` on it (loopback/link-local/RFC1918/ULA/CGNAT/multicast/
  unspecified rejected). Inline `url.Parse` + scheme check + `isPrivateHost` at the call
  site (CLAUDE.md CodeQL convention), not only a wrapper. DNS-rebind resistant
  (dial-the-resolved-IP).
- **TLS SNI + certificate hostname pinning:** even though the connection is dialed to
  the *previously-validated resolved IP* (above), the TLS handshake **MUST** set
  `ServerName = "feeds.culvertlabs.com"` (SNI) and verify the presented certificate
  against that **DNS hostname**, never against the IP. Concretely: the transport uses
  `tls.Config{ServerName: "feeds.culvertlabs.com"}` with default verification (no
  `InsecureSkipVerify`), and `HandshakeContext` (not `Handshake`, CLAUDE.md convention).
  So the IP is only the dial target; the authenticated peer identity is always the
  official hostname — dial-the-resolved-IP for SSRF safety and hostname-pinned TLS are
  applied **together**, not as a trade-off.
- **Redirect policy:** at most 5 redirects; **every hop is re-validated** against the
  *entire* accepted-URL contract above (scheme, exact host, no userinfo/port/query/
  fragment, IP-literal rejection, **and the exact approved path**) **and** the dial-time
  SSRF guard + the hostname-pinned TLS above. A redirect to a different **origin OR a
  different path** — anything other than the exact `feeds.culvertlabs.com` origin and
  the exact approved manifest/artifact key — is **rejected, not followed**. A redirect
  can therefore never escape the exact approved origin *and* path contract.
- **Response bounds:** manifest envelope read with `LimitReader(MaxBundleBytes+1)`
  (`urlcatfeed.MaxBundleBytes = 1<<20`); artifact with
  `LimitReader(min(artifact_size, urlcatfeed.MaxArtifactSize)+1)`
  (`MaxArtifactSize = 8<<20`), rejecting a body whose length ≠ declared size or > cap.
- **Timeout:** a compiled per-request timeout via `http.NewRequestWithContext` +
  `DialContext` (never bare `http.NewRequest`/`DialTimeout`, CLAUDE.md convention).

**Unsupported-value handling:** any `saas_feed_url` that is non-empty and not the exact
official origin (or one of the two historical URLs, which are *rewritten* to it) **fails
validation** with operator guidance — it is never persisted as a live mirror, never
CP-synced as an accepted value, and never fetched. Private mirrors and arbitrary feed
URLs remain **unsupported** (F0 §13); an air-gap path, if ever needed, is a separate
signed-*bundle* import (like the catalog's `bundleProvider`), out of F3 scope. The
field's CP-sync + persistence exist for schema/GUI-parity consistency, not to enable a
generic mirror feature.

---

# PART B — F3b SECOND-FLOOR DURABILITY

> **Revision note (architecture review R1).** This part is rewritten to resolve the
> phantom-floor interruption (§B.4/§B.7/§B.9), the floor-record schema + equivocation
> rule (§B.3), honest redundancy terminology + fair journal comparison (§B.2), the
> write-quorum contract (§B.6), mechanically-precise GC roots (§B.10), and time/
> freshness resilience (§B.11). The **four concerns are separated explicitly** (§B.1):
> a floor value never implicitly selects a generation for activation.

## B.1 The four separated concerns (governing model)

The single biggest correction from R1: F3b keeps **four distinct pieces of state**
with four distinct authorities. Conflating any two is the root of the phantom-floor
hazard.

| Concern | What it decides | Authority | Selection rule |
|---|---|---|---|
| **1. Rollback-floor selection** | which future fetches are *accepted* (reject `< floor`) | the floor/commit-intent records + compiled checkpoint | numeric `max` over *valid, compatible, non-equivocating* records (§B.6). **Governs accept/reject only — never selects served content.** |
| **2. Active-generation selection** | which immutable generation is *served* | the activation record + explicit candidate re-verification | record-driven + digest-re-verified (§B.7). **Never** numeric max, filename order, dir enumeration, or mtime. |
| **3. Resumable-candidate state** | an in-flight activation to *complete idempotently* after a crash | the commit-intent binding inside the floor record (generation id + digests) | present iff a valid record binds a generation *ahead of* the activation record's active gen (§B.7 floor-ahead). |
| **4. Live in-memory commit point** | the instant serving *cuts over* | `atomic.Pointer[EffectiveView].Store` | strictly last; a crash before it changes nothing live. |

**A floor number alone never activates a generation.** The floor *record* binds a
concrete generation identity + manifest/artifact digests; recovery treats a
floor-ahead binding as a *resumable candidate* and **fully re-verifies that exact
immutable generation from its signed bytes** before it can be served (§B.9,
option 1). Selection is always explicit and verified.

## B.2 Fault model, redundancy terminology, and honest approach comparison

### B.2.1 What "second floor" actually buys (corrected terminology)

Two records **on the same filesystem are redundant durable records, not independent
failure domains.** They share every **common-mode** fault of that filesystem/volume.
Stating this precisely (R1 obligation 3):

| Fault class | Two same-FS records | Why |
|---|---|---|
| Isolated record loss/corruption (one file hit by a bad block, bit-rot, an interrupted replacement of *that* file) | **Protected** | The other record survives; recovery excludes the corrupt one and takes the max of the survivors (§B.6). |
| Interrupted replacement (crash between writing the two records) | **Protected** | `AtomicWrite` makes each record old-or-new (never torn); the max of `{new, old}` is the new floor (§B.6/§B.7). |
| Whole-volume FS-snapshot rollback | **NOT protected** | A snapshot restore reverts *all* records consistently; nothing on the volume can detect the reversion of the very state that would detect it. |
| Filesystem-wide corruption | **NOT protected** | A corruption that spans the FS can take both records. |
| Privileged local modification (root) | **NOT protected** | Root can rewrite/delete every record to any value. |
| Loss of the containing directory / device | **NOT protected** | Both records live under that directory/device. |

So the honest claim is narrow: **the second floor protects against isolated record
loss/corruption and interrupted replacement, under the filesystem + honest-`fsync`
assumption.** It does *not* create independent failure domains and does *not* protect
against whole-volume rollback, FS-wide corruption, a privileged local attacker, or
loss of the directory/device. Those need an **external trust anchor** (TPM-sealed
counter, CP/etcd-side floor, remote attestation) — out of F3b scope. The compiled
`COMPILED_MIN_FEED_VERSION` is the only floor none of those can lower without
replacing the binary (image-signing / secure-boot trust domain).

Per-fault durability primitives (unchanged, for reference): crash / power-loss / torn
write are handled by `fileutil.AtomicWrite` (temp → fsync → rename → parent-dir fsync,
`fileutil.go:19-71`) — the target is always old-or-new, never partial.

### B.2.2 Approaches compared (fair journal treatment)

| Approach | Isolated-record fault | Common-mode fault | Recovery statefulness | Complexity | Verdict |
|---|---|---|---|---|---|
| **A1 — two redundant records (chosen)** | survives one lost/corrupt record | shares FS common-mode (§B.2.1) | stateless: `max` + equivocation check over fixed paths | low (reuses `AtomicWrite` verbatim, no in-place writes) | **selected** |
| **A2 — two-slot journal (two physical files)** | survives one lost slot-file | shares the same FS common-mode as A1 | needs a monotonic `seq`/epoch + slot bookkeeping | medium | equivalent safety; more moving parts |
| **A2′ — two-slot journal (one physical file)** | a whole-file loss takes both slots | worse than A1 for single-file loss | seq + in-place slot writes (bypass rename atomicity) | medium | rejected: single physical file *does* share fate |
| **A3 — floor derived from on-disk generations** | collapses to checkpoint whenever no generation is on disk (embedded fallback / post-GC) | — | — | low | rejected: cannot hold a floor without a generation — the exact F0 §9 state |

**Correction to the prior draft (R1 obligation 3):** the earlier rejection of the
two-slot journal for "single-file fate" was only valid for the **one-physical-file**
variant (A2′). A **two-physical-file** journal (A2) shares A1's fault profile exactly —
same isolated-record protection, same common-mode exposure. A1 is therefore chosen
**not** because A2 is unsafe but because A1 is *simpler*: it needs no monotonic
sequence counter and no slot bookkeeping (the `(feed_version, generated_at)` pair is
already monotonic, so recovery is a stateless `max` + equivocation check over two
fixed paths), and it never writes in place (every write is an `AtomicWrite` rename).
A3 remains rejected because a box serving the embedded baseline has no generations and
would derive the floor as the bare compiled checkpoint — reproducing, not fixing, the
F0 §9 hole.

## B.3 Floor / commit-intent record — canonical schema & equivocation rule

The record is both the **rollback floor** (concern 1) and the **resumable-candidate
binding** (concern 3). It binds enough to detect ambiguity and to safely resume:

```jsonc
{
  "schema_version": 1,
  "protocol": "signed_manifest_v1",           // must equal urlcatfeed.Protocol
  "feed": "url-categories/saas",              // must equal urlcatfeed.FeedID
  "feed_version": 42,                          // the floor watermark (int64 ≥ 1)
  "generated_at": "2026-07-31T00:00:00Z",     // RFC3339 UTC; SEC-F4 replay half of the pair
  "generation_id": "42",                       // immutable generation dir name (= feed_version, string)
  "manifest_sha256": "<64 lowercase hex>",     // digest of generations/<id>/manifest.envelope.json
  "artifact_sha256": "<64 lowercase hex>",     // digest of generations/<id>/artifact.json
  "crc32c": "1a2b3c4d"                          // EXACTLY 8 lowercase hex chars (see below)
}
```

- **No sequence/epoch field.** The `(feed_version, generated_at)` pair is already the
  monotonic ordering key (higher version wins; at equal version, newer `generated_at`
  wins — the SEC-F4 ordering, `release_catalog_freshness.go:131-140`), and the
  digest binding + equivocation rule cover ambiguity. A separate counter would be
  unused state, so it is deliberately **omitted** (obligation 2 "any field *actually
  required*").
- **`crc32c` representation (explicit + deterministic).** A JSON **string** of
  **exactly 8 lowercase hexadecimal characters** — the CRC-32/Castagnoli value
  zero-padded to 8 digits via `fmt.Sprintf("%08x", sum)`. Not an integer, not
  uppercase, not variable-width, so the record's canonical bytes are byte-stable across
  writers and platforms. On read, the string is parsed and compared to the recomputed
  value; a wrong length, non-hex, or mismatched value ⇒ record excluded.
- **Checksum input (explicit).** The checksum covers the **complete canonical record
  with the `crc32c` field entirely OMITTED from the encoding** (the field is absent —
  not present-but-empty, not zero-valued). Concretely: marshal a struct/view containing
  every field **except** `crc32c` under the canonical scheme below, CRC-32/Castagnoli
  those exact bytes, format per the rule above, then emit the full record including
  `crc32c`. Verification re-derives the same crc32c-omitted canonical bytes and
  recomputes — never depends on where `crc32c` would sort or on its stored value.
- **Canonicalization.** Both the crc32c-omitted input and the full record use the same
  canonical scheme as the rest of the feed (F1): `json.Encoder` with
  `SetEscapeHTML(false)`, fields emitted in the fixed struct order above, no trailing
  newline.
- **Checksum algorithm.** CRC-32/Castagnoli (`crc32.Castagnoli`, hardware-accelerated,
  stdlib). **A checksum is corruption detection, not authenticity** — any local writer
  (including a privileged attacker) can recompute a valid `crc32c`. Authenticity of the
  *feed content* comes solely from the Sigstore signatures over the stored
  `manifest.envelope.json` / `artifact.json`, which recovery **re-verifies** against
  the pinned identity + baked root (§B.9). The CRC only tells honest recovery "this
  record is intact vs. bit-rotted," never "this record is authentic."
- **Equivocation ⇒ fail closed (obligation 2).** If two records are individually valid
  (CRC + structural) and carry the **same `feed_version`** but differ in **any bound
  identity field** — `generation_id`, `generated_at`, `manifest_sha256`, **or**
  `artifact_sha256` (any one difference is sufficient) — recovery treats it as
  **equivocation/corruption**, does **not** pick one arbitrarily, refuses to advance or
  resume, emits a **critical** `saas_feed_floor_equivocation` alert + audit event, and
  falls to the safe floor/content precedence (§B.6/§B.7). Identical records at the same
  version (all bound fields equal) are the normal case (both replicas written from the
  same accept) and are idempotent.

`readFloorRecord(path)` is fail-closed like `readFloorState`
(`release_catalog_freshness.go:200-219`): missing ⇒ "no contribution" (a single file's
absence is legitimate; the pair is anchored by the compiled checkpoint);
unreadable / CRC-mismatch / structurally-invalid / wrong protocol|feed / negative
version / unparseable time ⇒ **excluded** from selection (never a silent reset, never a
zero that could lower the max). `writeFloorRecord(path, rec)` computes the CRC over the
canonical bytes and calls `fileutil.AtomicWrite(path, b, 0o600)`.

## B.4 On-disk contract

```
<dataDir>/saas_feed/
  floor.a.json           ← redundant floor/commit-intent record A
  floor.b.json           ← redundant floor/commit-intent record B (same schema)
  activation-state.json  ← ACTIVE-GENERATION authority (points at one generation) + a
                           copy of the floor record (an additional max input, obligation 4)
  generations/<id>/      ← immutable: manifest.envelope.json, artifact.json,
                           artifact.json.sigstore, snapshot.normalized.json
  overrides.json         ← CP-authoritative (§A.3), synced; not a durability concern here
```

The two floor records are peers named `a`/`b` (no "primary/secondary" precedence —
recovery is a symmetric `max`, obligation 7). The activation record's embedded floor
copy is a *third* max input, so the floor survives as long as **any one** of the three
records is intact.

## B.5 Commit ordering & state machine (the four concerns made explicit)

Advancing from a durable state at floor `F`/gen `G` to a newly-verified candidate at
`F'`/gen `G'` (`F' > F`). Each step annotates which of the four concerns it moves:

```
S0  steady: active=G(F); floor records = {F,G}; activation-state → G(F)+floor{F,G}
    │  candidate F' passes full verify (envelope sig + freshness + rollback ≥ floor + replay)
    ▼
S1  build gen(G') off-path (temp): 4 files, fsync each + temp dir            (concern 3: staging)
    ▼
S2  re-verify stored bytes; fsync; rename temp → generations/G'; fsync parent
                                                              [G' IMMUTABLE + DURABLE]  (concern 3)
    ▼
S3  writeFloorRecord(floor.a) = {F', G', digests}; then writeFloorRecord(floor.b) = same
                                                    [COMMIT-INTENT DURABLE]  (concerns 1 + 3)
    ▼
S4  AtomicWrite(activation-state) → active=G', floor{F',G'}, committed_etag
                                                    [ACTIVE-GEN COMMIT]  (concern 2)
    ▼
S5  atomic.Pointer[EffectiveView].Store(view(G'))   [LIVE CUTOVER]  (concern 4)
    ▼
S0' steady at F'/G'
```

Ordering rationale (why each edge is safe):
- **S2 before S3 (generation before commit-intent):** the commit-intent record binds a
  generation that is already immutable and durable, so a resume can always find and
  re-verify the exact bytes it names.
- **S3 before S4 (commit-intent before active-gen):** raising the floor and recording
  the resumable candidate *before* flipping the active generation is what makes the
  interruption safe. The floor moving to `F'` is purely *conservative* (it only
  *rejects more* — and there is no legitimate version in `[F, F')` we would ever want,
  since `F'` is the newest verified). The candidate binding lets a crash here be
  *completed*, not lost (§B.9 option 1).
- **S4 before S5 (active-gen before live cutover):** disk is authoritative; the live
  pointer is the very last move, so any earlier crash leaves serving unchanged.

## B.6 Write quorum & rollback-floor selection

### B.6.1 Write quorum (obligation 4)

- **Clean in-process activation REQUIRES both floor records durable (A and B) AND the
  activation record durable, before the live cutover.** The normal path is
  `write A → write B → write activation-state → store pointer`. If **any required
  write fails**, the in-process activation **ABORTS**: no live cutover, the old LKG
  keeps serving, the immutable candidate stays on disk, `state=degraded`, a
  `saas_feed_activation_incomplete` alert + `culvert_saasfeed_activation_incomplete`
  metric fire, and the transaction is retried next refresh cycle or resumed on restart.
  **No required durability failure is ever converted into a live activation** — the
  cutover (S5) is unreachable unless S3+S4 both succeeded.
- **Recovery tolerates a one-record floor.** A crash *between* the two floor writes (A
  written, B not) is not a durability *failure* of the transaction — it is an
  *interruption*. On restart, recovery reads whichever records are valid, takes the
  max, and (because A binds a floor-ahead candidate) **completes** the activation
  idempotently (§B.9). So the *floor's* recovery quorum is "≥1 valid record"; the
  *clean activation* quorum is "both records + activation record."

### B.6.2 Rollback-floor selection (concern 1; obligation 7)

```
selectFloor():
  cands := []                                   // FIXED paths only — no dir scan / mtime
  for src in [floor.a, floor.b, activation_state.floor]:
      if rec, ok := readValidated(src); ok: cands.append(rec)
  if equivocates(cands):                         // same feed_version, different digests/id/gen_at
      CRITICAL saas_feed_floor_equivocation; return (COMPILED_MIN_FEED_VERSION, zero)  // fail closed
  floor := (COMPILED_MIN_FEED_VERSION, zero)
  for rec in cands: floor := maxPair(floor, (rec.feed_version, rec.generated_at))
  return floor
```

- `maxPair` compares `feed_version`, then `generated_at` at equal version. Numeric max
  is used **only** across *valid, compatible, non-equivocating* records — it is a floor
  operation, never a content-selection operation.
- The floor is unconditionally bounded below by `COMPILED_MIN_FEED_VERSION`; no missing/
  corrupt combination lowers it below the binary's checkpoint.
- **Equivocation fails closed** (to the compiled checkpoint + critical signal), rather
  than arbitrarily trusting one branch.

## B.7 Active-generation selection & recovery precedence (concern 2; obligation 7)

Content selection is **separate** from floor selection and never uses numeric max /
filenames / directory order / mtime. On boot (and after any aborted activation):

```
1. floor := selectFloor()                                   // concern 1 (may fail closed → checkpoint)
2. candidate := floorAheadCandidate(floor records)          // concern 3: a valid record whose
   //   generation_id is AHEAD of activation_state.active_generation, digests bound
   if candidate != nil:
       if reVerifyImmutable(candidate) == OK:               // §B.9 option 1 — full signed re-verify
           completeActivation(candidate)                    // idempotent: write missing floor
           //   record(s) + activation-state → candidate, then serve
           return SERVE(candidate)   // active_source = cached; state per freshness (§B.11)
       else:
           CRITICAL saas_feed_candidate_reverify_failed     // fall through, candidate discarded
3. if activation_state valid AND reVerifyImmutable(activation_state.active_generation) == OK:
       return SERVE(active_generation)                      // active_source = cached (LKG)
4. return SERVE(embedded baseline)                          // active_source = embedded;
   //   signature_status = compiled_trusted; CRITICAL saas_feed_recovery_degraded
```

Precedence, stated as the review requires — **separately per axis**:

| Axis | Precedence |
|---|---|
| **Max trusted rollback floor** | `max` over valid compatible non-equivocating floor records, else compiled checkpoint (§B.6). Equivocation ⇒ checkpoint + critical. |
| **Resumable candidate** | a floor-ahead, digest-bound generation that **fully re-verifies** — completed idempotently (§B.9). Never selected by number alone. |
| **Currently active generation** | `activation-state.active_generation`, if it re-verifies. |
| **Last-known-good generation** | the active generation *is* the LKG until a new activation commits; the retention window (§B.10) keeps the prior N as rollback candidates, but only the record selects what is served. |
| **Embedded baseline** | the terminal fallback when nothing above re-verifies — explicit, `compiled_trusted`, critical signal. |

## B.8 Crash matrix (every interruption point; obligation 1)

`F`=old floor/gen, `F'`/`G'`=candidate. "Floor" = `selectFloor()` result; "Serves" =
`SELECT` result. Every row keeps the old LKG serving until a durable candidate is
re-verified.

| Crash point | floor.a | floor.b | activation-state | selectFloor | Resumable candidate? | Serves | Action / signal |
|---|---|---|---|---|---|---|---|
| During S1 (temp) | F | F | F | F | no | G(F) | GC temp; no change. |
| After S2, before S3 (gen durable, no commit-intent) | F | F | F | F | **no** (no record binds G') | G(F) | G' is an orphan (no record references it) → GC (§B.10). Re-fetch next cycle. *A floor number never selects G'.* |
| **Mid-S3: A written, B not** | **F',G'** | F | F | **F'** | **yes** (A binds G') | G(F) then → G' | Re-verify G' by bound digests → complete activation (write B + activation-state) → serve G'. Idempotent (§B.9). |
| After S3, before S4 (both records, no active-gen) | F',G' | F',G' | F | F' | yes (A,B agree) | G(F) then → G' | Same as above; A,B agree so no equivocation. |
| After S4, before S5 (active-gen committed, no cutover) | F',G' | F',G' | F',G' | F' | (already active=G') | G' | Reboot re-verifies G', serves it. Converged. |
| **One record has G', other + activation-state have old F** (partial, different versions) | F',G' | F | F | **F'** | yes (the F' record) | G(F) then → G' | Different *versions* ⇒ not equivocation; max=F'; resume G' via its digests. Then rewrite the stale record to F'. |
| Two records same version F' but **different digests** | F',G'₁ | F',G'₂ | any | **checkpoint** | no (refused) | G(F) or embedded | **Equivocation** → fail closed + `saas_feed_floor_equivocation` critical. Neither branch resumed. |
| One record corrupt (CRC), other valid | ✗ | F',G' | F',G' | F' | yes | per record | Corrupt excluded; floor + candidate intact. |
| Both floor records corrupt, activation-state valid | ✗ | ✗ | F',G' | F' (from activation-state copy) | (active=G') | G' | Floor from the record copy; degraded-records alert. |
| **Activation record corrupt, both floor records valid (the F0 §9 hole)** | F',G' | F',G' | ✗ | **F'** | yes (floor records bind G') | → G' | **Floor PRESERVED and content RESUMED**: re-verify G' from its bound digests, rebuild the activation record, serve G'. The §9 hole is closed for both floor *and* content. |
| All three records corrupt | ✗ | ✗ | ✗ | **checkpoint** | no | embedded | Fail closed → checkpoint + `saas_feed_recovery_degraded` critical. |

## B.9 Floor-ahead recovery policy — Option 1 (re-verify & complete idempotently)

**Selected: Option 1.** A floor-ahead candidate is recovered by **re-verifying the
exact immutable generation from its signed bytes and completing activation
idempotently** — not by discarding it and waiting for a strictly-newer version.

Why Option 1 is deterministic and safe:
- The candidate generation is **immutable and content-addressed**: the floor record
  binds `generation_id` + `manifest_sha256` + `artifact_sha256`. Recovery reads exactly
  `generations/<generation_id>/`, checks the two digests match the bound values, and
  runs the **full F0 §6 verify** (envelope Sigstore bundle over the raw manifest bytes,
  artifact Sigstore bundle over the raw artifact bytes, both against the pinned identity
  + baked root; `feed`/`protocol`/`feed_version` equality; normalization/integrity
  re-assert). Only on full success does it complete activation.
- **Idempotent:** completing means writing the still-missing floor record(s) and the
  activation record (both `AtomicWrite`) and storing the view. Re-running it produces
  byte-identical records (the generation and digests are fixed), so repeated
  crash/restart cycles converge.
- **Not a same-version network path.** The strictly-greater-version rule for *network*
  fetches is unchanged (`Generate`/accept still require `feed_version > prev`,
  `generate.go:58`). The recovery exception applies **only** to a locally-stored,
  already-verified, **digest-bound** immutable generation named by a valid floor
  record — it accepts *that exact generation*, re-verified, and nothing else. It can
  never widen into "accept an equal version from the wire": there is no digest binding
  for a wire object, and the wire path never consults the commit-intent record.

Option 2 (retain LKG, require strictly newer version) is **rejected** for the normal
case: it would *discard a fully-verified generation* the box had already committed the
floor to, forcing the served content to lag the floor (serving `G(F)` while refusing
`< F'`) until the publisher happens to ship `F'+1`. Availability/freshness impact of
option 2, quantified: after any crash in the S3–S4 window the box would serve stale
`F`-era categories for **one full publish cycle at minimum** (daily–weekly per F0 §10;
worst case until the next successful publish), even though the correct newer data is
sitting verified on disk. Option 1 has **zero** such lag — it serves `F'` as soon as
recovery re-verifies it. Option 2's only benefit (never re-activating across a reboot)
is not a safety gain, because option 1's re-verification is the same trust check the
original activation passed. Option 1 therefore dominates.

## B.10 GC roots (mechanically precise; obligation 5)

**Do floor records reference generations?** **Yes** (changed from the prior draft): a
floor record binds `generation_id` + digests (§B.3), so it **is** a generation GC
root. The prior "a numeric floor references no generation" statement is retracted.

**Complete GC root set** (a generation dir is retained iff it is in this set):
1. `activation-state.active_generation` — the currently-served generation.
2. `generation_id` of **every** valid floor record (`floor.a`, `floor.b`) — covers a
   floor-ahead resumable candidate.
3. The last `N` verified generations by the retention window (rollback candidates).

**GC rules:**
- GC runs **only after a new activation transaction is fully committed** (S4 durable +
  S5 done) — never during S1–S4.
- A generation dir is collectible iff it is **not** in the root set **and** not within
  the retention window **and** a newer activation has fully committed. An orphan from a
  crash after S2/before S3 (a generation no record binds) is collectible once the
  in-flight transaction has either completed or been abandoned.
- **If the floor records disagree or equivocate, or any record is corrupt, GC does not
  run at all** (the process is in a degraded/critical state; collecting under ambiguity
  could delete a generation a valid record still needs). GC resumes only after recovery
  reaches a consistent, non-equivocating state.
- GC proves a dir unreferenced by set membership (fixed identities), never by directory
  ordering or mtime, then `os.RemoveAll`.

## B.11 Time & freshness resilience (obligation 8)

The rollback **floor is clock-independent** (version-ordered), so version rollback is
resisted regardless of the clock. Freshness (`expires_at`) is inherently clock-bound;
F3b's stance is **conservative + observable, never claiming protection from a malicious
clock** (there is no external trusted-time source — stated explicitly).

| Condition | Behavior |
|---|---|
| **Wall-clock rollback** (clock moves backward) | Version floor still rejects `< floor` (clock-independent). A previously-expired active snapshot may transiently re-appear "fresh" — not a trust downgrade (content is version-floored + signed). If a monotonic-clock vs wall-clock divergence is detectable, emit `saas_feed_clock_anomaly` and hold current serving state; never advance freshness on the strength of a backward jump. |
| **Large forward clock jump** | A valid LKG may cross `expires_at` → `state=stale` (served, never fail-closed on age, F0 §10). A future-dated candidate (`generated_at > now+skew`, skew 5m) is **rejected** (F0 §10). Emit `saas_feed_clock_anomaly` if the active manifest's `generated_at` is suddenly far in the past relative to the jump. |
| **Reboot with expired LKG** | Serve the LKG (re-verified), `state=stale`; do **not** fail closed on age. Signatures are immutable, so the content is trust-valid; only freshness lapsed. |
| **304 near/after expiry** | Near/after `expires_at`, refetch **unconditionally** (no `If-None-Match`) so a CDN cannot pin staleness via a false 304 (F0 §10). A 304 recomputes freshness on the current active manifest; it never means "healthy." |
| **Expired candidate (fresh network fetch)** | Rejected, never activated (F0 §10). |
| **Offline startup** | No network: serve the re-verified active generation (`active_source=cached`), or embedded baseline if none re-verifies. Floor from the records. `state=degraded`/`stale` per age; no fail-closed on age. |
| **Floor-ahead candidate whose signed manifest is now expired** (crash in S3–S4, resumed after `expires_at`) | The candidate's **signatures are still valid** (immutable) and the **floor already advanced to it**, so completing activation is the consistent choice: **resume it (§B.9) and immediately mark `state=stale`.** Reverting to the older LKG would serve content *below* the committed floor and lose already-verified data; resuming keeps served content ≥ floor. Treated exactly like an active snapshot that crossed expiry — served, stale, refreshed on the next successful fetch. |

## B.12 Invariants (with proof sketch)

1. **No unverified generation reaches live state.** Live cutover (S5) follows S4, which
   references a generation that passed S2 re-verification; every recovery serve path
   (§B.7 steps 2–4) re-verifies the immutable generation from its signed bytes before
   serving. ∎
2. **No live change before durable commit.** S5 is strictly after S4; a crash before S5
   leaves the in-memory pointer untouched. Recovery only cuts over after re-verifying. ∎
3. **LKG not removed before a durable replacement exists.** GC (§B.10) runs only after a
   new activation fully commits and never collects a generation in the root set; the
   prior LKG is a root (active-gen or retention window) until superseded. ∎
4. **One-record corruption doesn't erase the floor.** `selectFloor` (§B.6) takes the max
   over the *surviving* valid records + the compiled checkpoint; a corrupt record is
   excluded. Loss needs all three records corrupt (→ checkpoint, fail-closed). ∎
5. **Stale-valid can't beat a newer floor.** `maxPair` is monotonic; a lower
   `(version, generated_at)` never wins over a higher one. ∎
6. **Recovery never uses filename/dir-order/mtime.** `selectFloor` and §B.7 read only
   fixed paths + bound generation identities; §B.10 GC keys on set membership. No dir
   scan or mtime anywhere. ∎
7. **A floor number never implicitly activates a generation.** Content is selected only
   via the activation record or a **digest-bound, fully re-verified** floor-ahead
   candidate (§B.7/§B.9). The floor's numeric max governs accept/reject only. ∎
8. **Incomplete durability never silently activates.** The clean path requires both floor
   records + the activation record durable before cutover (§B.6.1); any required-write
   failure aborts to the old LKG. An *interruption* leaves a resumable candidate that is
   re-verified before it can serve (§B.9). ∎
9. **Equivocation fails closed.** Two valid same-version records with different
   digests/identities ⇒ floor → checkpoint, no candidate resumed, critical signal
   (§B.3/§B.6/§B.8). Never an arbitrary pick. ∎
10. **Embedded-baseline fallback is explicit and critically observable.** The terminal
    §B.7 step-4 path sets `active_source=embedded`, `signature_status=compiled_trusted`,
    and emits `saas_feed_recovery_degraded` (critical) + audit. ∎
11. **GC can't delete a generation referenced by a durable record.** The GC root set
    (§B.10) includes every valid floor record's `generation_id` and the active
    generation; GC is disabled under record disagreement/corruption. ∎
12. **Fresh install is bounded by the checkpoint + 30-day ceiling.** No records ⇒ floor =
    `COMPILED_MIN_FEED_VERSION`; a fetched manifest is rejected if `expires_at -
    generated_at > COMPILED_MAX_VALIDITY` (= `urlcatfeed.MaxValidity` = 30d) or already
    expired (F0 §10). ∎

## B.13 Guarantees provided / explicitly NOT provided

**Provided** (under the filesystem + honest-`fsync` assumption):
- Durability of the rollback floor and the resumable-candidate binding against
  **isolated record loss/corruption** and **interrupted replacement** (crash / power
  loss / torn write / one-file bit-rot), via two redundant `AtomicWrite` records + the
  activation-record copy + the compiled checkpoint (`max` of survivors).
- **Phantom-floor safety:** every S1–S5 interruption resolves to a consistent state
  that either resumes the verified candidate or keeps the old LKG — never a partial or
  unverified activation (§B.8).
- **Equivocation detection** (fail-closed, critical).
- **Floor-content separation:** a floor number never activates content; content is
  always record-driven + digest-re-verified.

**NOT provided** (need an external trust anchor; the compiled checkpoint is the only
floor they cannot lower):
- Whole-volume FS-snapshot rollback.
- Filesystem-wide corruption taking all records.
- Privileged local modification/deletion of the records (a checksum is not
  authenticity; root can forge a valid CRC).
- Loss of the containing directory/device.
- Protection from a **malicious system clock** (no trusted-time source) — only
  conservative, observable behavior under detected anomalies (§B.11).
- Closing the fresh-install replay window below `≤ COMPILED_MAX_VALIDITY` (30d)
  (F0 §10 / T7 — inherent to offline trust).
- Any guarantee if `fsync` lies (out of software scope).

---

# PART C — IMPLEMENTATION SLICING

Each slice is independently reviewable, preserves prior invariants, and is small
enough for one focused PR. Ordering: F3a-1 → F3a-2 (settings/ownership) and
F3b-1 → F3b-2 → F3b-3 → F3b-4 (durability engine) are two mostly-independent
chains that meet at F3b-3 (activation consumes the composed view, which consumes
overrides from F3a-1).

### F3a-1 — Schema, ownership model, migration (no wire, no API)

- **Files:** new `internal/catoverride/` (`Overrides` store, composition function,
  `Load`/`Save`/`ReplaceAll` mirroring `internal/catgroup`); `admin_settings.go`
  (five `SaaSFeed*` fields + apply/save + sentinel gate + migration input);
  new `saas_feed_migrate.go` (URL matrix §A.5.3, `*string`-style absent-vs-empty);
  `saas_store_schema_version` marker; `config_surfaces.go` (rows — declared but
  ClusterSynced wiring lands in F3a-2). **Do not** touch
  `internal/urlcat/default_categories.json`.
- **Depends:** F0 (merged), F1/F2 (`urlcatfeed.NormalizeHost`).
- **Tests + failure injection:** migration matrix (each row, idempotent,
  persistence-failure-not-applied, no old-URL fallback — inject a write error);
  sentinel (fresh on-by-default, explicit disable survives restart, empty ≠
  disabled); composition purity (tombstone/recategorize/add, host+subdomain scope);
  `NormalizeHost` parity over the embedded dataset; corrupt-envelope fail-closed
  (inject a bad `saas_store_schema_version`).
- **Acceptance:** settings resolve deterministically; overrides compose as a pure
  function; no writable wire yet; `go test ./...` green; `config_surfaces_test.go`
  green (rows declared consistent with bindings).
- **Rollback:** additive fields with `omitempty`/sentinel semantics; reverting the
  slice leaves an older binary reading defaults. Retire nothing yet
  (`globalSaaSFeed` additive syncer still present, unused by the new path).
- **Non-goals:** no downloader, no CP→DP, no GUI, no floor.

### F3a-2 — API / OpenAPI / GUI / export-import / CP→DP for settings + overrides

- **Files:** `saas_feed_api.go` (`apiSaaSFeedSettings`, `apiSaaSFeedOverrides`);
  `ui_policy.go` (route registration); `ui_routes_meta.go` (metadata) + route-count
  gate bumps (`d0_helpers_test.go`, `ui_routes_meta_test.go`); `controlplane_snapshot.go`
  (scalar `SaaSFeed*` + `CategoryOverrides` field, cap constant, capture, apply);
  `controlplane_server.go` (confirm overrides NOT redacted); `config_surfaces.go`
  (flip `ClusterSynced`, add bindings) + `config_surfaces_test.go` (**capped literal
  22 → 23**, nil-guard case, wire-wipe pairing); `ui_config.go` +
  `configversion.go` (export/import + rollback capture/apply/diff, leaf-first);
  `api/openapi/openapi.yaml` + `make api-bundle`; `static/index.html` (admin panel).
- **Depends:** F3a-1.
- **Tests + failure injection:** handler RBAC (viewer GET / admin PUT / 403 / 405);
  apply-then-persist rollback (inject `SaveAdminSettings` failure); CP→DP round-trip
  (settings scalars + overrides, including an **empty-override wire-wipe** —
  `WireWipeCapable`); redaction proof (overrides present to unenrolled caller,
  secrets still zeroed); the 8 `ConfigSnapshot` parity tests; export/import
  never-wipe-on-absent + leaf-first; rollback round-trip; `TestOpenAPI_Gate3`.
- **Acceptance:** an admin can set URL/protocol/enabled/interval + overrides from the
  GUI; the fleet converges via `ConfigSnapshot`; clearing all overrides
  delete-propagates; `make api-verify` green.
- **Rollback:** revert the ClusterSynced flip (rows back to AdminDurable-only) — DPs
  fall back to local settings; no data loss.
- **Non-goals:** no downloader/floor (settings drive the F3b engine, wired at F3b-3).

### F3b-1 — Durable floor/commit-intent records + selection state machine

- **Files:** new `saas_feed_floor.go` (`floorRecord` schema §B.3, CRC-32C over
  canonical bytes, `readFloorRecord`/`writeFloorRecord` via `fileutil.AtomicWrite`,
  `maxPair`, `selectFloor` §B.6 with the **equivocation** check, `floorAheadCandidate`
  §B.7, `COMPILED_MIN_FEED_VERSION` + `COMPILED_MAX_VALIDITY` constants).
- **Depends:** F0, `internal/fileutil` (existing).
- **Tests + failure injection (deterministic):** injected clock; ratchet-forward
  (higher version; same-version newer `generated_at`; same-version older refused —
  replay guard); per-record corruption matrix (bad CRC, truncate, negative version,
  unparseable time, wrong protocol/feed) asserting each is **excluded** from the max;
  **equivocation** (same version, different digests) ⇒ checkpoint + critical, not an
  arbitrary pick; three-record corruption ⇒ compiled checkpoint; missing file ⇒
  zero-contribution; crash-between-records simulated by writing only `floor.a` then
  selecting (max=F', candidate bound).
- **Acceptance:** every §B.8 crash-matrix row and §B.12 invariants 4/5/6/7/9 have a
  passing test; no directory enumeration / mtime read in `selectFloor` or
  `floorAheadCandidate`.
- **Rollback:** self-contained new file; unused until F3b-3 wires it.
- **Non-goals:** no fetch, no activation.

### F3b-2 — Downloader / verify / immutable-generation storage

- **Files:** new `saas_feed_download.go` (manifest-envelope-first fetch reusing the
  catalog HTTP building blocks — bounded reads, ETag pending→commit, dial-time SSRF +
  redirect guard); verify-before-parse via `urlcatfeed.VerifyEnvelope` +
  `VerifyArtifact`; off-path immutable-generation build (4 files, fsync, rename) per
  F0 §8 S1–S2.
- **Depends:** F1/F2 (`urlcatfeed`), F3b-1 (floor gates the accept decision).
- **Tests + failure injection:** valid accept; forged envelope ⇒ zero artifact
  fetches; tampered payload/artifact ⇒ reject; wrong SAN/issuer ⇒ reject;
  cross-feed/version mismatch ⇒ reject; size/path traversal ⇒ reject; expired-on-first
  install ⇒ reject; validity > 30d ⇒ reject; `feed_version < floor` ⇒ reject (uses
  F3b-1); inject a partial write during the off-path build ⇒ temp only, no rename.
- **Acceptance:** a verified candidate produces a durable `generations/<v>` dir; no
  candidate ever mutates live state; all F0 §18 envelope/freshness/integrity rows
  pass.
- **Rollback:** engine is dormant until F3b-3 activates it; revert is deletion of the
  new file.
- **Non-goals:** no activation cutover, no GC, no serving.

### F3b-3 — Activation, record-driven recovery, GC

- **Files:** new `saas_feed_activate.go` (write-quorum sequence §B.6.1 —
  `floor.a`→`floor.b`→`activation-state`→pointer; `completeActivation` idempotent
  resume §B.9; boot recovery precedence §B.7; GC root set §B.10); wire the composed
  view from `internal/catoverride` (F3a-1); wire the settings resolver (F3a-2) to
  arm/refetch; **retire** the additive `mergeSaaSCategories`/`globalSaaSFeed.Configure`
  path (`saas_feed.go:41-75`, `internal/saasfeed`).
- **Depends:** F3a-1 (overrides/settings), F3b-1 (floor), F3b-2 (generations).
- **Tests + failure injection:** every §B.8 crash row, incl. **mid-S3 (A written, B
  not) ⇒ resume G' idempotently**; **activation record corrupt + both floor records
  valid ⇒ floor preserved AND content resumed** (the F0 §9 fix, asserted explicitly);
  **equivocation ⇒ fail closed**, no arbitrary pick; required-write failure (inject an
  `AtomicWrite` error on `floor.b` or the activation record) ⇒ **abort to LKG, no live
  cutover** (quorum §B.6.1); floor-ahead candidate with an expired manifest ⇒ resume +
  `stale` (§B.11); referenced-gen re-verify failure ⇒ embedded fallback; GC disabled
  under record disagreement; GC never deletes a root-set generation; LKG never GC'd
  before a new activation fully commits.
- **Acceptance:** activation meets the write quorum; recovery is record-driven,
  floor-preserving, and **content-resuming**; the invariants §B.12 1/2/3/7/8/9/11 have
  passing tests; the legacy additive syncer is gone.
- **Rollback:** feature-flag the new engine behind the resolved `enabled`; a revert
  restores the embedded baseline serving path (no additive syncer needed — the
  baseline is always the fallback).
- **Non-goals:** GUI telemetry polish (F3b-4).

### F3b-4 — Observability & failure injection surface

- **Files:** `release_alerts.go`-style latched alerts (`saas_feed_recovery_degraded`,
  `saas_feed_stale`, `saas_feed_refresh_failing`, `saas_feed_recovered`);
  `metrics.go` hand-written Prometheus (`culvert_saasfeed_*`: floor version gauge,
  refresh outcomes counter, `expires_in_seconds`); `healthcheck.go` readiness row;
  extend `apiURLCatFeedStatus` (`ui_policy.go:1158-1184`) with the F0 §14 fields;
  audit events on activation/floor-raise/recovery.
- **Depends:** F3b-3.
- **Tests + failure injection:** each F0 §14 state transition; `never_succeeded`
  renders null delta; recovery-after-failures; embedded ⇒ `compiled_trusted`; restart
  ⇒ `cached`; 304 provenance unchanged; `context.Canceled` not counted; latched alerts
  fire once per threshold crossing; metric shapes.
- **Acceptance:** the operator sees state + floor + freshness in the GUI and on
  `/metrics`; degraded recovery is critically visible (invariant 8).
- **Rollback:** additive observability; safe to revert.

## C.1 F5 parallelization — NORMATIVE constraints (R1 obligation 9)

**F5 (the CI publisher `publish-feeds.yml`) MAY proceed in parallel with F3**, but
**only** under the following constraints, which are **normative (MUST)** for the F5
slice, not advisory:

1. **Build/test-only against the frozen contract.** F5 implementation MAY build and
   test the **dormant** publisher against the frozen F1/F2 on-wire contract —
   `urlcatfeed.SchemaVersion=1`, `Protocol="signed_manifest_v1"`,
   `FeedID="url-categories/saas"`, the envelope shape (`{payload_b64, bundle}`), the
   manifest/artifact field sets (F0 §4.3/§4.4), and the pinned identity
   (`feeds_identity.env`) — using the **same `internal/urlcatfeed` code** (`Generate`,
   `AssembleEnvelope`, `EvaluateReadiness`) so producer and client cannot drift. **F3
   changes none of these** (F3a adds node-side settings/ownership; F3b adds node-side
   durability — neither touches the artifact/manifest bytes or the signing identity).
2. **`FEEDS_PUBLISH_ENABLED` MUST remain fail-closed / off.** The publish job stays
   dormant-gated (F0 §11.1); a PR/CI run receives neither production OIDC signing
   identity nor publishing credentials.
3. **No live side effects.** The F5 slice MUST NOT perform any R2 mutation, DNS change,
   Cloudflare change, signing publication, or live-credential activation. It produces
   and verifies artifacts as GitHub Actions workflow artifacts only.
4. **F6 / live publication MUST wait** until **both** F3b-3 (client can verify + floor
   + activate) **and** F5 (publisher can produce) are merged **and** pass end-to-end
   verification (a client built from `main` fetches, verifies, floors, and activates a
   publisher-produced manifest). Only then does the owner apply F6 (live R2/DNS).

**The integration contract F5 must not get ahead of** is exactly the on-wire schema +
pinned identity in constraint 1 — the one thing F3 does not modify. Because F3 leaves
that surface frozen, F5 and F3 share no mutable contract and can land in either order,
provided constraints 2–4 hold.

---

## Return — checkpoint summary

1. **Branch/base/worktree:** branch `claude/feeds-f3-design`, base `origin/main`
   @ `6810fce` (PR #978 merge), clean worktree. Only this document added.
2. **Repository evidence inspected:** the file:line set enumerated in the header
   (CP→DP transport + registry + parity tests; AdminSettings persistence + sentinel +
   one-way-migration precedent; export/import + config-version rollback; the
   release-catalog durability stack + `AtomicWrite`; the category engine + embed +
   current SaaS syncer; the handler/route/OpenAPI/GUI pattern).
3. **Selected CP/DP ownership model:** four domains — feed configuration
   (CP-authoritative, dual AdminDurable+ClusterSynced) and category overrides
   (CP-authoritative, ConfigSnapshot slice with DecryptionProfiles delete-propagation
   posture) are fleet-synced; the active generation + activation record + floor are
   node-local durable; runtime status is node-local/derived. CP-sync of the URL does
   not weaken trust because the DP verifies every byte locally with no unsigned/raw
   fallback and an unremoved SSRF guard.
4. **Selected second-floor design (R1-revised):** two redundant floor/commit-intent
   records (`floor.a`/`floor.b`, peers) + the activation-record floor copy, each
   CRC-32C-checksummed (corruption detection, **not** authenticity) and `AtomicWrite`-n.
   The four concerns are separated (floor selection / active-gen selection / resumable
   candidate / live commit point) so a floor number never selects content. Floor =
   numeric `max` over valid, compatible, **non-equivocating** records + compiled
   checkpoint; content = record-driven + **digest-re-verified**. Each record binds the
   candidate `generation_id` + digests, so an S3–S4 interruption is **resumed** (Option
   1: re-verify the exact immutable generation, complete idempotently). Same-version
   different-digest records ⇒ **equivocation ⇒ fail closed + critical**. Write quorum:
   both records + activation record required for a clean activation (any required-write
   failure aborts to LKG); recovery tolerates ≥1 valid record. Chosen over a two-slot
   journal (**equivalent** safety when two physical files — chosen for simplicity, not
   because a journal has "single-file fate"; only a one-file journal does) and the
   derived-from-generations floor (collapses when no generation is on disk). Closes the
   F0 §9 hole for **both** floor and content; keeps the F0 §8 ordering.
5. **Residual risks / guarantees not provided (R1-honest):** the two records are
   **redundant durable records on one filesystem, not independent failure domains** —
   they protect against isolated record loss/corruption + interrupted replacement under
   the `fsync`/FS assumption. **Not** protected: whole-volume FS-snapshot rollback,
   FS-wide corruption, privileged local modification (a CRC is not authenticity),
   loss of the directory/device, and a **malicious system clock** (no trusted-time
   source — only conservative observable behavior, §B.11). All need an external anchor;
   the compiled checkpoint is the only floor none can lower. Fresh-install replay
   bounded ≤30d; honest-`fsync` assumed.
6. **F3 slices:** F3a-1 (schema/ownership/migration), F3a-2 (API/OpenAPI/GUI/export-
   import/CP→DP), F3b-1 (floor storage + state machine), F3b-2 (downloader/verify +
   immutable generations), F3b-3 (activation/recovery/GC), F3b-4 (observability +
   failure injection) — each with files, deps, tests+injection, acceptance, rollback,
   non-goals (Part C).
7. **F5 parallelization (normative constraints):** build/test the dormant publisher
   against the frozen F1/F2 contract only; `FEEDS_PUBLISH_ENABLED` stays fail-closed;
   no R2/DNS/Cloudflare/signing-publication/credential activation; F6/live publication
   waits for both F3b-3 and F5 to merge and pass end-to-end verification (§C.1).
8. **Files changed:** exactly one — `roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md`.
   No implementation code, no dataset edit, no CI/DNS/R2, no commit/push/PR.

**Stop for architecture review. No implementation begins until F3 is approved.**
