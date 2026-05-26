# Category B′ / Finding 10.3 — Decision Spec

**Status:** discovery / decision only. No production behavior changes in this
PR. No capture/apply changes, no `saveConfigVersion` changes, no
ConfigSnapshot/HA changes, no handler changes.

**Question:** what to do with the `configBackup` fields that exist in the
struct (and the export JSON) but are **not** populated by
`captureConfigBackup` nor applied by `applyConfigBackup` — i.e. they are not
on the config-version **rollback** surface even though the struct implies
they are.

Fields in scope (all in `ui_policy.go` `configBackup`):

| Field | Decl |
|---|---|
| `RateLimitExempt []string` | ui_policy.go:646 (`json:"rateLimitExempt,omitempty"`) |
| `AlertWebhooks []AlertWebhook` | ui_policy.go:650 (`omitempty`, `// Finding 10.3`) |
| `BlockPageHTML string` | ui_policy.go:651 (`omitempty`, `// Finding 10.3`) |
| `UpstreamProxies []UpstreamEntry` | ui_policy.go:652 (`omitempty`, `// Finding 10.3`) |
| `ConnLimitEnabled bool` | ui_policy.go:653 (`omitempty`, `// Finding 10.3`) |
| `ConnLimitMaxPerIP int` | ui_policy.go:654 (`omitempty`, `// Finding 10.3`) |

---

## 0. The architectural fact that frames everything

`configBackup` is a **shared struct** serialized by **two distinct
subsystems**:

1. **Export / import** (portability) — `apiConfigExport` (ui_config.go:270)
   and `apiConfigImport` (ui_config.go:372). The full-export ("all") path
   populates **all six** fields (ui_config.go:332–361) and import applies
   **all six** (ui_config.go:473–531).
2. **Config versioning / rollback** (point-in-time revert) —
   `captureConfigBackup` (configversion.go:59–98) and `applyConfigBackup`
   (configversion.go:344–472). Neither references **any** of the six fields.
   `diffConfigs` (configversion.go:499+) likewise does not.

A **third** mechanism, `AdminSettings` / `/data/admin_settings.json`
(admin_settings.go:8 "saved atomically after every API mutation"), is the
**restart-durability** layer and already persists four of the six:
`RateLimitExemptions` (admin_settings.go:29), `ConnLimitMaxPerIP` /
`ConnLimitEnabled` (:30–31), `BlockPageHTML` (:37).

So there are three surfaces with three different memberships. The bug is that
the **struct over-promises** for surface (2): a reader of `configBackup` sees
six populated-looking fields (some tagged `// Finding 10.3`) and reasonably
assumes rollback round-trips them. It does not.

`saveConfigVersion` → `captureConfigBackup` (configversion.go:107) is the only
capture path for rollback, and it sets none of the six. Because the fields are
`omitempty`, a version envelope simply **omits** them; on rollback,
`applyConfigBackup` never reads them, so the live values are **left
untouched** regardless of what the snapshot intended.

---

## 1. Per-field lifecycle map

All claims cite exact code paths.

### 1a. `RateLimitExempt []string`
- **Owning store/global:** `rl` (`*RateLimiter`, security.go). Mutators
  `AddExemption` (security.go:307), `RemoveExemption` (:322); reader
  `ListExemptions` (:336, returns **non-nil** empty slice). Storage is a
  **set** (`exemptIPs` map + `exemptNets`) → `ListExemptions` order is
  nondeterministic.
- **Persistence file:** `/data/admin_settings.json` (`RateLimitExemptions`,
  admin_settings.go:29).
- **Admin handler:** `apiSettingsSecurity` (ui_security.go, the
  `security.update` handler) — mutates IP filter, `RateLimitRPM`, **and**
  exemptions (ui_security.go:199–209).
- **saveConfigVersion today?** **YES** — ui_security.go:217
  (`"security.update"`), alongside `adminSettingsSave()` at :216.
- **On rollback surface?** capture: NO. apply: NO. diff: NO.
- **In export/import?** YES — export ui_config.go:344, import ui_config.go:473.
- **Sensitivity:** low (IPs / CIDRs; no secrets).
- **ConfigSnapshot / HA?** None (not in controlplane.go / enrollment.go).
- **Key observation:** its sibling `RateLimitRPM` **is** on the rollback
  surface (captured configversion.go:74, applied :462–464, diffed :513). So
  the same `security.update` config version captures RPM but silently drops
  the exemption list. This is an **active intra-subsystem inconsistency**, not
  merely a missing feature.

### 1b. `ConnLimitEnabled bool` + `ConnLimitMaxPerIP int`
- **Owning store/global:** `connLimiter` (connlimit.go). `enabled` atomic +
  `MaxPerIP()`.
- **Persistence file:** `/data/admin_settings.json` (admin_settings.go:30–31).
- **Admin handler:** `apiConnLimit` (ui_config.go:950).
- **saveConfigVersion today?** **NO** — only `adminSettingsSave()`
  (ui_config.go:979).
- **On rollback surface?** capture: NO. apply: NO. diff: NO.
- **In export/import?** YES — export ui_config.go:329–330, import :525–531.
- **Sensitivity:** low.
- **ConfigSnapshot / HA?** None.

### 1c. `BlockPageHTML string`
- **Owning store/global:** `blockPageState` (blockpage.go);
  `getBlockPageHTML` (:93) / `setBlockPageHTML` (:80, validates the template).
- **Persistence file:** `/data/admin_settings.json` (admin_settings.go:37).
- **Admin handler:** `apiBlockPage` (ui_config.go:990).
- **saveConfigVersion today?** **NO** — only `adminSettingsSave()`
  (ui_config.go:1017).
- **On rollback surface?** capture: NO. apply: NO. diff: NO.
- **In export/import?** YES — export ui_config.go:321/352, import :513.
- **Sensitivity:** low (HTML template, validated on set).
- **ConfigSnapshot / HA?** None.

### 1d. `UpstreamProxies []UpstreamEntry`
- **Owning store/global:** `upstreamPool` (upstream.go). `UpstreamEntry` has a
  **single `URL` field** (upstream.go:273–275).
- **Persistence file:** `config.yaml` `upstream.proxies` (UpstreamConfig,
  upstream.go:277–285) **at startup only**. Runtime changes via `apiUpstream`
  call `applyUpstreamProxy` (proxy.go:1030), which **only swaps the live
  transport** — no write to admin_settings.json, config.yaml, or config
  versions. (Latent runtime-durability gap, separate from this finding.)
- **Admin handler:** `apiUpstream` (ui_config.go:1028).
- **saveConfigVersion today?** **NO**. `adminSettingsSave`? **NO**.
- **On rollback surface?** capture: NO. apply: NO. diff: NO.
- **In export/import?** YES but **lossy** — export captures only `URL`
  (ui_config.go:325/357); import `upstreamPool.Configure` (:521).
- **Sensitivity:** **HIGH.** A proxy URL can embed inline credentials
  (`http://user:pass@host`). Putting it on the rollback surface would persist
  those credentials **in plaintext at rest** across up to 50
  `/data/config_versions/v{N}.json` files (cf. handoff item CA-3
  plaintext-at-rest concern).
- **ConfigSnapshot / HA?** None.

### 1e. `AlertWebhooks []AlertWebhook`
- **Owning store/global:** `globalAlertStore` (`*AlertStore`, alerts.go:121).
- **Persistence file:** its **own** file (`AlertStore.filePath`, `save()`),
  not admin_settings.json.
- **Admin handler:** `apiAlertsWebhooks` (ui_security.go:30). Add/Update/Delete
  persist via the store's own `save()`.
- **saveConfigVersion today?** **NO**. `adminSettingsSave`? **NO**.
- **On rollback surface?** capture: NO. apply: NO. diff: NO.
- **In export/import?** YES but **lossy in two ways**:
  - `List()` **strips `Secret`** (alerts.go:183 — the HMAC-SHA256 signing
    secret, alerts.go:81, "never returned in list"). Export → import loses the
    secret, so restored webhooks are unsigned/broken.
  - `Add()` **reassigns the ID** from `time.Now().UnixNano()` (alerts.go:190),
    ignoring the imported ID.
- **Sensitivity:** **HIGH.** Faithful capture would require exposing the HMAC
  secret into config-version files (plaintext at rest; also collides with the
  gosec G117 "secret"-pattern convention in CLAUDE.md).
- **ConfigSnapshot / HA?** None.

---

## 2. Why the current state is bad

1. **The struct over-promises rollback support.** Six fields sit in
   `configBackup`, four tagged `// Finding 10.3`, looking like an in-progress
   rollback extension. They are not on the rollback surface. A maintainer (or
   the dry-run consumer) cannot tell intent from the struct alone.
2. **Rollback silently half-reverts.** Because `captureConfigBackup` omits the
   six and `applyConfigBackup` ignores them, rolling back to an earlier
   version **does not** revert webhooks, block page, upstream proxies,
   connection limits, or rate-limit exemptions — they persist at their current
   values. An operator who rolls back expecting a full revert gets a partial
   one, with no signal.
3. **`RateLimitExempt` is an active inconsistency, not just a gap.** Its
   handler already creates a config version (ui_security.go:217) and its
   sibling `RateLimitRPM` is already captured/applied/diffed. So a single
   `security.update` snapshot reverts the RPM but not the exemption list —
   a self-contradictory rollback of one subsystem.
4. **Dry-run/export imply support that does not exist.** Export emits these
   fields, reinforcing the "these are part of the backup" mental model; the
   rollback dry-run diff (post-PR #276) is **silent** on them because they are
   not wired into `diffConfigs`. Export says "backed up", rollback says
   "untouched" — divergent stories from one struct.
5. **`omitempty` on slice fields is a latent trap.** `AlertWebhooks` and
   `UpstreamProxies` are slices carrying `omitempty`, violating the standing
   rule "no `omitempty` on rollback-surface slice fields." They are safe today
   only because they are **not** on the surface; the moment someone wires them
   into capture, the nil-vs-`[]` distinction breaks. The struct should make
   their off-surface status explicit so this never happens by accident.

---

## 3. Decision per field

Decision rule applied: **a field belongs on the rollback surface iff its
mutating handler already calls `saveConfigVersion`** (i.e. it is already a
"versioned" setting, so omission is a real inconsistency) **and** it can be
captured faithfully without exposing secrets. Otherwise: document
out-of-surface and keep export/import as-is. **No field is deleted** — all six
back real, working export/import functionality; deleting them would regress
that feature.

| Field | Handler calls saveCV? | Faithful capture? | **Decision** |
|---|---|---|---|
| `RateLimitExempt` | **Yes** (ui_security.go:217) | Yes (plain `[]string`) | **Complete rollback extension** |
| `ConnLimitEnabled` | No | Yes | **Document out-of-surface** |
| `ConnLimitMaxPerIP` | No | Yes | **Document out-of-surface** |
| `BlockPageHTML` | No | Yes | **Document out-of-surface** |
| `UpstreamProxies` | No | No (inline creds → plaintext at rest) | **Document out-of-surface** |
| `AlertWebhooks` | No | No (secret stripped by `List()`, ID reassigned) | **Document out-of-surface** |

**Rationale for "document out-of-surface" over "complete" for the five:** each
is either (a) already restart-durable via admin_settings.json and managed by a
handler that intentionally does **not** version it (ConnLimit, BlockPage), or
(b) impossible to round-trip faithfully through the existing capture surface
without leaking secrets/credentials (AlertWebhooks, UpstreamProxies). Forcing
them onto the rollback surface would mean **two** coupled changes each (expand
capture/apply **and** add `saveConfigVersion` to the handler) — multiple
concerns, and for the secret-bearing pair, a security regression.

**Rationale for "complete" for `RateLimitExempt`:** single concern, no secret,
handler already versions, sibling already on-surface, diff reuses
`diffStringList`. Leaving it off is the one case that is actively wrong rather
than merely unsupported.

**On "split into smaller groups":** a clean long-term fix is to **split the
struct** — a curated `configBackup` (rollback surface, no `omitempty` on
slices) and a superset export DTO that embeds it plus the export-only fields.
**Not recommended now:** it touches `apiConfigExport`/`apiConfigImport`
serialization and is a larger, riskier refactor than the problem warrants.
Documentation + the targeted `RateLimitExempt` fix resolve the ambiguity at a
fraction of the risk. Record struct-split as a deferred option.

---

## 4. Recommended sequencing (smallest safe PRs first)

> Implementation does **not** happen in this PR.

**PR-1 — docs only, zero behavior change.** Re-comment the five out-of-surface
fields in `configBackup` to state explicitly: *export/import only;
intentionally NOT on the config-version rollback surface; reason (durable via
admin_settings.json / cannot round-trip secret|credential).* Replace the
ambiguous `// Finding 10.3` markers. Add an entry to CLAUDE.md "Architecture
Notes" recording the export-vs-rollback surface split. No tests needed (no
behavior change); `go build` + `go vet` only.

**PR-2 — complete `RateLimitExempt` (single behavioral concern).**
- Remove `omitempty` from the field (rollback-surface slice rule).
- `captureConfigBackup`: set `RateLimitExempt: rl.ListExemptions()` (non-nil
  empty for empty state — contract already met, security.go:339).
- `applyConfigBackup`: nil-skip / `[]`-wipe / populated-replace, mirroring the
  CategoryGroups/URLCategories pattern. **Impl flag:** `RateLimiter` has no
  clear/replace primitive — either add a small `ReplaceExemptions`/`Clear`
  (security.go) or iterate `ListExemptions` + `RemoveExemption` then
  `AddExemption`, mirroring the `ipf` clear-then-add at configversion.go:455–460.
- `diffConfigs`: add `diffStringList("rate_limit_exempt", a.RateLimitExempt,
  b.RateLimitExempt, &changes)`, guarded `if b.RateLimitExempt != nil` to match
  the PR #276 nil-skip diff convention.
- **No handler change** — `apiSettingsSecurity` already calls
  `saveConfigVersion` (ui_security.go:217).
- **Cross-surface flag:** removing `omitempty` makes per-section exports emit
  `"rateLimitExempt":null` (cosmetic; import tolerates nil). Acceptable;
  document in the PR.

**Required tests for PR-2** (each must fail when the production diff/apply is
stashed; order-independent because exemptions are a set):
1. **Round-trip:** set RPM + exemptions, snapshot, mutate both, rollback,
   assert **both** restored (proves the RPM/exempt inconsistency is closed).
2. **Nil-skip:** snapshot with `RateLimitExempt == nil` (pre-extension) →
   apply leaves live exemptions untouched.
3. **Empty wipe:** snapshot with `[]string{}` → apply clears live exemptions.
4. **EmptyMarshalsAsArray:** zero-exemption capture serializes as
   `"rateLimitExempt":[]`, not `null`/absent.
5. **Diff reports:** `diffConfigs` surfaces `rate_limit_exempt` on add/remove;
   nil target → no diff (mirrors apply).

**PR-3 (optional) — connection-limit / block-page out-of-surface note in
CLAUDE.md**, if PR-1's struct comments are judged insufficient. Pure docs.

**Do not bundle** any of these with unrelated rollback items (CategoryGroups,
URL categories, scanner, cluster). One concern per PR.

---

## 5. Out-of-scope observations (logged, not addressed here)

- **Upstream runtime durability gap:** `apiUpstream` changes are not persisted
  anywhere (proxy.go:1030 swaps the transport only); they are lost on restart.
  Separate from Finding 10.3.
- **Export/import lossiness:** `AlertWebhooks` (secret stripped, ID reassigned)
  and `UpstreamProxies` (URL-only) do not faithfully round-trip even through
  export/import. Separate finding.
- **Secrets at rest:** if any secret-bearing field is ever put on the rollback
  surface, the `/data/config_versions/v{N}.json` plaintext-at-rest exposure
  (handoff CA-3) must be resolved first.
