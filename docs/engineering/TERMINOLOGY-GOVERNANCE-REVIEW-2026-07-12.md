# Culvert Language & Terminology Governance Review — 2026-07-12

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Re-verified the six concept clusters most likely to have drifted since the last
> review (decryption/SSL-inspection exclusion, auth default-outcome, HA/fencing lease, release
> catalog/release management, node groups/bandwidth/QoS, config versioning) against the tree at
> `b0dd056`, following up on the prior review at `8e88a40`
> (`TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-10.md`).
> **Companion change:** the prior review's deferred T-10 finding is fixed in this pass, using an
> additive/backward-compatible alias strategy consistent with how T-1 and T-9 were handled.

---

## Executive Summary

All six re-verified concept clusters are clean — no new drift found. Two same-day commits
(`546fb54`, 2026-07-11) had already closed the two genuine drift items open as of the last
review (node-group/bandwidth audit-verb split; HA-panel "node" ambiguity), and both fixes still
hold.

**Terminology Health Score: 9 / 10** (up from 8.5 — T-10, the only outstanding *real* finding
from the prior review, is now fixed; see Findings).

**Fixed in this change:** T-10 — the DPI content-scanning engine's config/API/audit naming now
matches its GUI/log/metrics naming ("DPI"), via additive aliases with zero breaking changes.

---

## Re-verified clean (no new drift since 2026-07-10)

Decryption/SSL-inspection exclusion terminology (GUI "Decryption Exclusions" vs. API
`/api/decryption-exclusions` vs. metrics `culvert_decrypt_autoexclude_*` vs. audit
`decryption.autoexclude.*` — all aligned, and correctly disambiguated in the GUI from the
separate "Decryption Profiles" concept); auth default-outcome terminology (`defaultAuthOutcome`
end-to-end, no "unauth mode" leakage into the GUI); HA/fencing-lease terminology (Term/epoch
equivalence note still accurate and now more precise about the transient no-lease-held case;
Control-Plane/Peer vs. enrolled-node naming fixed on the Cluster panel); release catalog/Release
Management terminology; node groups/bandwidth/QoS terminology (create/delete audit-verb fix
holds); config-versioning three-surface split (export/import, version rollback, CP→DP snapshot)
still cleanly disambiguated in the GUI copy.

---

## Findings

### T-10 — `content_scan_*` config/API naming vs. "DPI" GUI/log/metrics naming (FIXED)

- **Business concept:** the regex-based response-body signature scanning engine.
- **Before:** YAML config (`content_scan_file`, `content_scan_patterns`), the REST API
  (`/api/content-scan`, `/api/content-scan/bypass`), JSON fields (`contentScanPatterns`,
  `contentScanBypassHosts`), and two audit events (`content_scan.add`, `content_scan.remove`)
  all used "content scan," while the GUI ("DPI Signatures," "DPI-Only Bypass Hosts"), logs
  (`DPIScan: ...`, `DPI_BLOCKED`), and metrics (`culvert_dpi_blocked_total`) all used "DPI" — the
  same feature, two names, split exactly at the config/API/audit boundary. An admin editing
  `config.yaml` or grepping the audit log for "dpi" would find nothing.
- **Fix (additive, zero breaking changes):**
  1. **Config:** added canonical `dpi_file` / `dpi_patterns` YAML keys (`config.go`,
     `FileConfig.Proxy.DPIFile`/`DPIPatterns`). The deprecated `content_scan_file` /
     `content_scan_patterns` keys still parse and take effect when the canonical keys are unset,
     logging a one-line startup deprecation notice (`reconcileDeprecatedDPIKeys`). Downstream
     code is unchanged — it keeps reading `ContentScanFile`/`ContentScanPatterns`, which the
     reconciliation step populates from whichever key was set. `config.example.yaml` now shows
     `dpi_file`/`dpi_patterns` as the primary keys.
  2. **REST API:** added canonical `/api/dpi` and `/api/dpi/bypass` routes (same handlers,
     `apiContentScan`/`apiContentScanBypass`); `/api/content-scan` and `/api/content-scan/bypass`
     remain registered as deprecated aliases (`ui_routes_meta.go` route count 138 → 140, mirroring
     the T-1 precedent of adding a canonical route alongside a retained legacy alias).
  3. **Audit events:** renamed `content_scan.add`/`content_scan.remove` to `dpi.add`/`dpi.remove`
     (a straight rename, not aliased — these audit event names are not treated as a stable
     external contract per the 07-10 review's own analysis, and the sibling bypass-list audit
     event was already named `security.dpi_bypass`, so this closes the last inconsistency within
     the audit stream itself).
- **Deliberately NOT touched in this pass:** the `configBackup` JSON field names
  (`contentScanPatterns`/`contentScanBypassHosts`) used by export/import and config-version
  rollback, and the internal `ContentScanFile`/`ContentScanPatterns`/`ContentScanner` Go
  identifiers. These interact with the config-surfaces reflection registry
  (`config_surfaces.go`) and the numbered on-disk version-snapshot format; renaming them safely
  needs the same shadow-type/alias-on-read treatment as T-9's `exportedAt` → `capturedAt` rename,
  which is still open. Left as a smaller, separately-scoped follow-up (Low priority — the
  config/API/audit surface fixed here was the operator-visible half of the drift).
- **Migration risk:** none for this pass — every change is additive or a rename of a
  non-contractual audit string. `TestLoadFileConfig_DPIKeyCanonicalWins` and
  `TestLoadFileConfig_DeprecatedDPIKeyStillWorks` pin the config-alias precedence.

---

## Stop-Condition Assessment

Terminology is now consistent across all six re-verified clusters, with T-10's operator-visible
half fixed. The remaining T-10 residual (JSON API field names on the export/import/rollback
surface) and the carried-over T-9 (`exportedAt` → `capturedAt`) are both Low/Medium priority,
low-urgency, and appropriately sized for a dedicated follow-up rather than a same-day fix — no
further action taken this pass.
