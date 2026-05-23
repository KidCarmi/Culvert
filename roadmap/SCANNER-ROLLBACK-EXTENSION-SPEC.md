# Scanner / Content-Scanning Rollback-Surface Decision/Spec

**Status:** discovery + design-decision document. **No production code changes in this PR.** No test changes. This is the dependency-chain review for the scanner / content-scanning group of admin handlers.

**Cross-discovery reference:** P6.2 SC-1 (`roadmap/SCANNING-DISCOVERY.md` §10): "of the 10 scanner-config mutating handlers, only `apiContentScan` add/remove call `saveConfigVersion`. Eight handlers emit `auditEvent` / `auditEventDiff` but do not snapshot. … Structurally identical to the P6.1 UC-4 asymmetry, just wider in scope." Now that PR #267 (CategoryGroups) and PR #269 (URL Categories) have established the surface-extension pattern, this spec triages the scanner group.

**Scope (deliberate):**

- Discovery / decision doc only.
- No production code changes.
- No `saveConfigVersion` additions or removals.
- No `captureConfigBackup` / `applyConfigBackup` changes.
- No `ConfigSnapshot` changes.
- No scanner runtime refactor.

---

## 1. Current scanner config lifecycle

The "scanner" umbrella spans five distinct stores with independent persistence, audit, and rollback shapes. They are NOT a uniform group; each requires its own direction decision.

### 1.1 dpiScanner (ContentScanner)

| Aspect | Detail |
|---|---|
| Store | `dpiScanner *ContentScanner` (`scanner.go:57`) |
| Fields | `raw []string` (regex patterns) + `compiled []*regexp.Regexp` + `bypassHosts map[string]bool` |
| Persistence | Single JSON file (`/data/content_scan.json`) — envelope `{patterns, bypass_hosts}` OR legacy array of patterns. Via `Save()` (atomic-via-rename, NOT fsync-hardened — pending bucket-4 audit per `CONFIG-VERSIONING-TRIAGE.md` §1). |
| Admin mutators | `apiContentScan` POST/DELETE (`ui_security.go:298-360`) — patterns. `apiContentScanBypass` PUT (`ui_security.go:882-906`) — bypass hosts. |
| ConfigSnapshot interaction | `ConfigSnapshot.DPIPatterns []string` carried; captured at `controlplane.go:1675` via `dpiScanner.List()`, applied at `:1535-1540` via `dpiScanner.Set()` + `Save()`. **BypassHosts NOT in ConfigSnapshot.** |
| Rollback surface today | `configBackup.ContentScanPatterns []string` IS captured (`configversion.go:70`) and applied (`:412-413`). **BypassHosts NOT in rollback surface.** |
| `saveConfigVersion` | `apiContentScan` POST/DELETE: YES. `apiContentScanBypass` PUT: **NO** (gap). |

**Asymmetry:** patterns are fully in the surface (captured + applied + handlers call `saveConfigVersion`); bypass hosts are entirely out (no capture, no apply, no `saveConfigVersion`) — even though they live in the same file and are written atomically as one envelope.

### 1.2 YARA engine settings

| Aspect | Detail |
|---|---|
| Store | Package-globals accessed via `yaraGetEnabled()` / `yaraGetTimeoutSecs()` / `yaraGetMaxInflight()` / `yaraGetOnTimeout()` / `yaraGetOnSaturation()` / `yaraGetAlertDegraded()` (`yara_scan.go`, not detailed here). |
| Persistence | `adminSettings.json` (via `SaveAdminSettings`) — same file as session timeout, log level, UI allow-IPs, etc. (per `admin_settings.go:272-279`). |
| Admin mutators | `apiSecYARASettings` PUT (`ui_security.go:640-678`). |
| ConfigSnapshot interaction | **NONE.** YARA engine settings are per-CP local, not HA-replicated. |
| Rollback surface today | **NONE.** |
| `saveConfigVersion` | NO. Handler emits `auditEventDiff` only. |

### 1.3 YARA rule files

| Aspect | Detail |
|---|---|
| Store | `globalYARA` engine + directory of `.yara`/`.yar` rule files on disk (configured dir, typically `/data/yara/`). |
| Persistence | One file per rule. Compiled at engine load time. |
| Admin mutators | `apiSecYARARules` GET/POST/PUT/DELETE (`ui_security.go:691-788`) — write/delete YARA rule files; `apiSecYARAReload` POST (`:566-597`) — reload rules from disk + clear hash cache. |
| ConfigSnapshot interaction | **NONE.** YARA rule files are per-CP local. |
| Rollback surface today | **NONE.** |
| `saveConfigVersion` | NO. Handlers emit `auditEvent` only. |

### 1.4 Scan exclusions

| Aspect | Detail |
|---|---|
| Store | `globalScanExclusions *ScanExclusionStore` (`security_scan.go:123`). |
| Fields | `hashes map[string]bool` (SHA-256 content hashes — known-good binaries) + `hosts map[string]bool` (hostnames that bypass body scanning). |
| Persistence | `/data/scan_exclusions.json` envelope. Atomic-via-rename Save (`security_scan.go:159+`). |
| Admin mutators | `apiSecScanExclusions` GET/PUT (`ui_security.go:838+`). |
| ConfigSnapshot interaction | **NONE.** Scan exclusions are per-CP local. |
| Rollback surface today | **NONE.** |
| `saveConfigVersion` | NO. Handler emits `auditEvent` only. |

### 1.5 Threat-feed allowlist + cache + runtime triggers (excluded from scope)

`apiSecFeedsSync`, `apiSecYARAReload`, `apiScanCache` (evict/clear), `apiSecYARAValidate`, `apiSecScanStatus` — runtime-only operations (read-only / cache management / dry-run / one-shot reloads). Not config mutations. **Out of scope for rollback-surface decisions** by the same reasoning as `apiBlocklistFeed sync` (E category in the upstream triage).

---

## 2. Current rollback coverage

### 2.1 Triage-doc state (per `CONFIG-VERSIONING-TRIAGE.md` §4.2 prior to this PR)

| Handler | `saveConfigVersion` today | In surface today | Triage classification |
|---|---|---|---|
| `apiContentScan` POST | YES | YES | ✓ Correct |
| `apiContentScan` DELETE | YES | YES | ✓ Correct |
| `apiContentScanBypass` PUT | NO | NO (`bypassHosts` not captured) | (C) Out of surface — flagged P6.2 SC-1 |
| `apiSecYARASettings` PUT | NO | NO | (C) Out of surface — P6.2 SC-1 |
| `apiSecYARARules` POST | NO | NO | (C) Out of surface — P6.2 SC-1 |
| `apiSecYARARules` PUT | NO | NO | (C) Out of surface — P6.2 SC-1 |
| `apiSecYARARules` DELETE | NO | NO | (C) Out of surface — P6.2 SC-1 |
| `apiSecScanExclusions` PUT | NO | NO | (C) Out of surface — P6.2 SC-1 |

### 2.2 The asymmetric `dpiScanner` case (worth highlighting)

Patterns are versioned and rollback-restored; bypass hosts in the same file are not. Sequence to demonstrate:

1. Operator adds bypass host `internal-ci.example.invalid` to dpiScanner via `apiContentScanBypass`.
2. Snapshot v2.
3. Operator removes that host.
4. Operator rolls back v3 → v2.

**Today:** v2 is restored only for patterns; the bypass-host removal persists. The operator's `apiContentScanBypass` mutation is invisible to the version log. The version-log entry is also misleading because `apiContentScanBypass` doesn't call `saveConfigVersion` — no envelope is written at all.

This is the strongest case in the scanner group for direction-B (extend surface): patterns and bypass hosts live in **the same persistence file**, the same admin domain, and are functionally complementary (patterns specify what to look for; bypass hosts specify where NOT to look). Operator-visible asymmetry between them is gratuitous.

---

## 3. Hazards by store

### 3.1 dpiScanner — BypassHosts

**Hazard SCAN-A: rollback restores patterns but not bypass hosts.** Patterns added at v3 are rolled back to v2's set; bypass hosts mutated between v2 and v3 are NOT rolled back. Net: scanner now uses v2 patterns against hosts that the v2-era bypass list would have excluded but the current bypass list does not (or vice-versa). The proxy hot path emits DPI hits / false positives against bypass-list-out-of-sync hosts.

**Severity:** Moderate. False positives on internal-only hosts are operator-visible; security impact is low (DPI is detective, not authoritative).

**Security note:** the bypass list is **trust-elevation** (hosts in it skip DPI). A rollback that re-adds a bypass entry the operator just removed could re-grant trust to a host the operator just decided to scan. **This is the only Category-D-sec angle in the scanner group** — same shape as `auth.password_change` (PR #261), `cdr.instance.revoke_rpc` (PR #263), `apiClusterRevoke` — but with weaker severity because DPI is a defense-in-depth layer, not the auth boundary.

### 3.2 YARA engine settings

**Hazard SCAN-B: rollback restores other policy state but not YARA engine settings.** Settings include security-relevant toggles:

- `yara_enabled` — master switch.
- `yara_timeout_secs` — per-scan timeout. Lowering can cause scans to time out and fall through; raising can DoS the scanner.
- `yara_max_inflight` — concurrency cap. Lowering throttles scans; raising can starve other workers.
- `yara_on_timeout` — `block` vs `pass-through` (the security-relevant one).
- `yara_on_saturation` — `block` vs `pass-through`.
- `yara_alert_degraded` — observability toggle.

If an operator tightens settings at v3 (e.g. flips `yara_on_timeout` from `pass-through` to `block`) and rolls back to v2 (`pass-through`), the rollback silently relaxes a security posture the operator chose to harden. **Category-D-sec.**

**Severity:** Moderate to high depending on which setting flipped.

### 3.3 YARA rule files

**Hazard SCAN-C: rule files are filesystem state, NOT JSON-blob state.** YARA rules are individual `.yar`/`.yara` files in a directory. They are compiled at engine load. A rollback would need to:

- Restore the full set of rule files (with content).
- Delete rule files created after the snapshot.
- Reload the engine.

The snapshot format would need to embed every rule file's full source — likely large (some rule sets are tens of KB per file × hundreds of files).

**Operator-visible problem:** YARA rules are sometimes vendor-shipped, sometimes operator-authored, often under version-control outside Culvert. The expectation that "rollback restores YARA rules" is weak — operators typically manage rules in their own VCS. The Culvert admin API for YARA rules is for emergency edits, not the primary management path.

**Decision input:** YARA rule files are categorically different from JSON-blob admin state. Including them in rollback would be invasive and operationally surprising.

### 3.4 Scan exclusions (hashes + hosts)

**Hazard SCAN-D: scan exclusions are trust-elevation lists.** A SHA-256 hash on the exclusion list means "this binary is known-good, do not scan." A hostname on the exclusion list means "do not scan responses from this host." Both bypass the scanner entirely.

If an operator removes a hash from the exclusion list at v3 (because of a new IoC) and rolls back to v2, the rollback re-adds the hash — silently restoring trust to a binary the operator just decided to scrutinize. **Category-D-sec, same shape as `auth.password_change`.**

**Severity:** High. Re-adding an exclusion is a direct security regression analogous to un-revoking a credential.

### 3.5 Cross-cutting: runtime-only triggers

`apiSecFeedsSync`, `apiSecYARAReload`, `apiScanCache evict/clear`, `apiSecYARAValidate`, `apiSecScanStatus` are **not config mutations**. Rollback semantics for them are meaningless. Same Category-E classification as `apiBlocklistFeed sync` in the upstream triage. No action needed.

---

## 4. Direction per group

### 4.1 Direction matrix

| Store | Direction | Action |
|---|---|---|
| `dpiScanner.patterns` (already in surface) | A (correct) | No change — keep as-is. |
| `dpiScanner.bypassHosts` | **B (extend surface)** | Add `BypassHosts []string` to `configBackup`; capture via `dpiScanner.BypassHosts()`; apply as a **single merged block: `SetBypassHosts(...)` (in-memory) → `Set(patterns)` (in-memory) → ONE `Save()`** — NOT a `SetBypassHosts + Save()` of its own. Both fields share the `content_scan.json` envelope (`scanner.go:124-148`); a separate Save before patterns are restored would write the file twice and persist an intermediate (bypass-restored / patterns-stale) state. See §8 for the exact block. Add `saveConfigVersion` to `apiContentScanBypass` PUT. |
| YARA engine settings | **A (remove misleading) — but there's nothing to remove (handler never called `saveConfigVersion`).** Documented decision: NOT in surface; rollback is dangerous for security-toggle settings. | No code change. Triage doc row updated to mark "(D-sec) Documented out-of-surface — rollback would un-harden security posture". |
| YARA rule files | **A (remove misleading) — same as above, nothing to remove.** Filesystem-shape mismatch + external VCS expectation. | No code change. Triage doc row updated to mark "(D-ops) Documented out-of-surface — filesystem state, VCS-managed outside Culvert". |
| Scan exclusions (hashes + hosts) | **A (remove misleading) — same as above, nothing to remove.** Trust-elevation list; rollback re-adds removed exclusions. | No code change. Triage doc row updated to mark "(D-sec) Documented out-of-surface — re-adding an exclusion is a security regression". |
| Runtime triggers (feeds_sync, yara-reload, scan_cache) | **E (runtime, not config)** | No code change. Already classified correctly. |

### 4.2 Why mixed directions

The scanner group is heterogeneous in ways the prior cross-discovery groups (URL categories, CDR, category groups) were not:

- **dpiScanner bypass hosts** are pure config (host allowlist). Easy direction-B candidate.
- **YARA engine settings** are security-toggle parameters. Direction-D-sec.
- **YARA rule files** are filesystem artifacts often externally managed. Direction-A by external convention.
- **Scan exclusions** are trust-elevation lists. Direction-D-sec, identical shape to `auth.password_change`.

A blanket "extend surface" or "remove versioning" decision would be wrong on at least three of the five. Each store's risk class drives its own direction.

---

## 5. Implementation sequencing

Per `roadmap/CATEGORY-D-PRIME-DIRECTION.md`'s precedent (small, focused PRs, no bundling), the implementation splits into three PRs:

### 5.1 PR #270 (smallest, ships first): dpiScanner BypassHosts surface extension

- `ui_policy.go`: add `BypassHosts []string` to `configBackup` struct, tagged `json:"contentScanBypassHosts"` (no `omitempty`). Same shape as `URLCategories` in PR #269.
- `configversion.go`:
  - `captureConfigBackup`: populate via `dpiScanner.BypassHosts()`.
  - `applyConfigBackup`: replace the existing standalone `dpiScanner.Set(b.ContentScanPatterns)` + `dpiScanner.Save()` pair with ONE merged block — `SetBypassHosts(b.ContentScanBypassHosts)` (in-memory), then `Set(b.ContentScanPatterns)` (in-memory), then a SINGLE `dpiScanner.Save()`. **Do NOT add a second `Save()` for bypass hosts.** Both fields share the `content_scan.json` envelope (`scanner.go:124-148`); two `Save()` calls would write the file twice and the first write would persist an intermediate state (bypass-restored, patterns-stale). The exact block is in §8. (This is a structural change to the existing ContentScanPatterns apply, required by — and scoped to — the surface extension.)
- `ui_security.go`: add `saveConfigVersion(sessionAdmin(r), "security.dpi-bypass")` to `apiContentScanBypass` PUT.
- `CONFIG-VERSIONING-TRIAGE.md`: flip `apiContentScanBypass` row from "(C)" to "✓ Correct"; add `BypassHosts` row to §1 surface table.
- Tests (~5):
  - `TestConfigVersion_DPIBypassHosts_RoundTrip`
  - `TestConfigVersion_DPIBypassHosts_NilSnapshotIsNoOp`
  - `TestConfigVersion_DPIBypassHosts_EmptySnapshotWipes`
  - `TestConfigVersion_DPIBypassHosts_EmptyMarshalsAsArray`
  - `TestAPIContentScanBypass_PUT_CreatesConfigVersion`

**Production diff estimate:** ~15 lines. **Test diff estimate:** ~120 lines.

This is direct mirror of PR #260 + PR #267 + PR #269. Mechanically the safest extension in the scanner group.

### 5.2 PR #271 (medium): documentation-only triage closure for YARA + scan-exclusions

- `CONFIG-VERSIONING-TRIAGE.md`: flip the four "(C) Out of surface — P6.2 SC-1" rows to explicit documented decisions:
  - `apiSecYARASettings` PUT → "(D-sec) Documented out-of-surface — rollback would un-harden security posture (yara_on_timeout, yara_on_saturation)".
  - `apiSecYARARules` POST/PUT/DELETE → "(D-ops) Documented out-of-surface — filesystem state, externally managed in operator VCS".
  - `apiSecScanExclusions` PUT → "(D-sec) Documented out-of-surface — exclusions are trust-elevation lists; rollback re-adds removed exclusions".
- Optional: add a one-line comment near each of the 5 handler bodies explaining the out-of-surface decision. Mirrors PR #265's `cdr_ui.go:22-34` header rewrite, but per-handler since these are heterogeneous.
- No production code changes beyond optional inline comments.
- No tests required (no behavior change).

**Production diff estimate:** 0 (or ~20 lines if inline comments are added). **Doc diff estimate:** ~30 lines in the triage doc.

### 5.3 PR #272 (optional, can be skipped): scanner P6.2 SC-1 explicit closure

If desired, a final doc-only PR closes P6.2 SC-1 in the `SCANNING-DISCOVERY.md` doc:

- Update §10 SC-1 entry from "deferred to triage" to "resolved per PRs #270 + #271 + PR #272".
- Add a §10.x cross-reference table summarizing the per-store decisions.

**Production diff estimate:** 0. **Doc diff estimate:** ~30 lines.

---

## 6. Test strategy

PR #270's tests follow the established pattern (mirror of PR #267 / PR #269 — `*_RoundTrip`, `*_NilSnapshotIsNoOp`, `*_EmptySnapshotWipes`, `*_EmptyMarshalsAsArray`, handler test).

**Specific to dpiScanner's single-file persistence:** the round-trip test must verify that patterns AND bypass hosts in the SAME envelope are both restored correctly. The implementation's apply-ordering correctness is structurally testable by mutating both, snapshotting, mutating both differently, applying the snapshot, and asserting both halves match the v1 state — including the file-on-disk content.

**Helpers required (new for PR #270):**
- `snapshotDPIScanner(t)` — captures + restores `dpiScanner` pointer with a fresh in-test instance, t.TempDir-rooted path. Mirrors `snapshotCatStore` from PR #269.

**Helpers reused:**
- `snapshotConfigVersionsDir(t)` (PR #261).
- `loadAndApplyV1Envelope(t, tmp)` (PR #269).

PR #271 needs no tests (documentation only).

---

## 7. nil / empty / populated snapshot semantics (for PR #270)

Identical to PR #267 / PR #269 contract for `dpiScanner.bypassHosts`:

| Snapshot state | Live state after `applyConfigBackup` |
|---|---|
| `contentScanBypassHosts` absent (old snapshot) | Live `dpiScanner.bypassHosts` untouched |
| `"contentScanBypassHosts": null` | Live `dpiScanner.bypassHosts` untouched |
| `"contentScanBypassHosts": []` | Live `dpiScanner.bypassHosts` wiped |
| `"contentScanBypassHosts": [...]` | Live `dpiScanner.bypassHosts` replaced |

Struct tag: `json:"contentScanBypassHosts"` (NO `omitempty`). `dpiScanner.BypassHosts()` returns a non-nil empty slice for an empty store (`scanner.go:170-186` uses `make([]string, 0, ...)`), so the zero-bypass state serializes as `[]` and round-trips through apply as a wipe.

---

## 8. Apply ordering relative to existing surface (for PR #270)

Current `applyConfigBackup` order (after PR #267 + PR #269):
1. Blocklist + BlocklistMode
2. **URLCategories** (PR #269 — leaf of category dependency chain)
3. **CategoryGroups** (PR #267)
4. PolicyRules
5. RewriteRules
6. SSLBypass
7. ContentScanPatterns ← **merge BypassHosts into this block; one `Save()` (see code below)**
8. FileBlockExtensions
9. IPFilter
10. RateLimitRPM
11. PACConfig

Proposed order:
- Insert "BypassHosts" between ContentScanPatterns and FileBlockExtensions? No — that would Save the dpiScanner file twice (once after BypassHosts, once after patterns).
- Better: combine BypassHosts and ContentScanPatterns into ONE block:

```go
// dpiScanner: bypass hosts + content scan patterns share a single
// file (scanner.go:124-148). Apply in-memory first, then a single
// Save() so the on-disk envelope is consistent.
if b.ContentScanBypassHosts != nil {
    dpiScanner.SetBypassHosts(b.ContentScanBypassHosts)
}
_ = dpiScanner.Set(b.ContentScanPatterns)
dpiScanner.Save()
```

This keeps the existing `_ = dpiScanner.Set(b.ContentScanPatterns)` + `dpiScanner.Save()` pattern but interposes the BypassHosts apply. **Single `Save()` call → single on-disk envelope.** No ordering ambiguity vs URLCategories/CategoryGroups/PolicyRules — dpiScanner is independent of those.

---

## 9. What this PR did NOT do (deliberate)

- No production code changes.
- No `saveConfigVersion` removals or additions.
- No `captureConfigBackup` / `applyConfigBackup` changes.
- No `configBackup` struct changes.
- No `ConfigSnapshot` changes.
- No scanner runtime refactor.
- No tests added or modified.
- No HA / metrics changes.
- **No bundling** — PR #270 (dpiScanner BypassHosts) ships independently of PR #271 (YARA + scan-exclusions documentation closure) and PR #272 (optional SCANNING-DISCOVERY closure).

## 10. No unresolved VERIFY / UNCERTAIN markers

Every claim is grounded in line-numbered evidence:

- `ContentScanner` shape — `scanner.go:35-47`.
- `dpiScanner` global — `scanner.go:57`.
- `Save` / `Load` / `Set` / `SetBypassHosts` — `scanner.go:68-186`.
- `apiContentScan` handler — `ui_security.go:298-360`.
- `apiContentScanBypass` handler — `ui_security.go:882-906`.
- `apiSecYARASettings` handler — `ui_security.go:640-678`.
- `apiSecYARARules` handler — `ui_security.go:691-788`.
- `apiSecScanExclusions` handler — `ui_security.go:838+`.
- `ScanExclusionStore` shape — `security_scan.go:102-126`.
- Existing `ContentScanPatterns` in rollback surface — `configversion.go:70, :412-413`.
- `ConfigSnapshot.DPIPatterns` in HA path — `controlplane.go:1535-1540, :1675`.
- BypassHosts absence from rollback surface AND ConfigSnapshot — verified by absence of any field reference in `configversion.go` and `controlplane.go` (grep).
- YARA settings persisted via `adminSettings.json` — `admin_settings.go:272-279`.
- `saveConfigVersion` call sites — `ui_security.go:217, :339, :355, :396, :411` (only those 5 in this file).
- All audit-event sites in scanner handlers — enumerated via `grep` in §2.1.

No "probably". No "looks like". No `VERIFY:` markers.
