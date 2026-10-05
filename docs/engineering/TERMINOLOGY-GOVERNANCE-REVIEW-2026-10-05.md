# Culvert Language & Terminology Governance Review — 2026-10-05

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope:** audited `6ec745d..3fcc07e` (the end commit of the 2026-09-24 report to the
> `origin/main` HEAD at the time of writing) — 43 first-parent commits. This report makes **no code or
> copy change**; it records one new finding and re-verifies none of the older carried IDs.
> **Method:** added lines only, literal sweeps over `static/index.html`, the OpenAPI bundle, new
> `auditEvent` actions, new `culvert_*` metric names and the new operator docs, compared with the
> canonical glossary (`docs/design/PRODUCT-TERMINOLOGY.md`) and the earlier decisions (T-1…T-63).

## Executive Summary

**One new Low finding (T-64); nothing Critical/High; no rename recommended in this PR.**

New user-visible names in the window are consistent with the glossary: "Live traffic" / "Recent requests"
(Traffic migration finished, #1424), "Default authentication behavior", "Refresh All Now" / "Refresh Feeds
Now" (T-62's GUI half), "Change Password" (self-service, audit `auth.password_change`), "Start Backup"
(on-demand backup), "OCSP revocation", "Stale Episodes" (cluster rate limit) and the new
`culvert_*` series (`*_rejected_total`, `*_failures_total`, `*_binds_total`) follow the established
`noun_verbed_total` shape. The security hardening work (CHAOS-63/69/70, SEC-REQID-1, SEC-RBAC-ROLE-1,
SEC-TOTP-1, SEC-BOOTSTRAP-HOST-1) introduced no competing names for existing concepts.

**Terminology Health Score: 7.4 / 10** — baseline 7.5 (2026-09-24 audited snapshot), −0.1 for the newly
charged T-64. Fixes merged in the interim (T-57, T-58, T-17, T-59 → +0.4) are carried by their own
reports and not re-counted here.

## Canonical Concepts (window)

| Business concept | Canonical name | Where it appears |
|---|---|---|
| Create a backup archive on demand | **Backup** (action verb: *create*) | GUI "Start Backup", agent op kind `backup.create`, API `POST` backups route |
| Change one's own console password | **Change password** | `auth.password_change`, topbar, `/api/auth/change-password` |
| Client tracing header unusable → replaced | **Tracing header** (replaced) | GUI "Tracing Headers Replaced", metric `…_rejected_total` |

## Findings

### T-64 — `backup.trigger` is the only `.trigger` audit action; the same operation is `backup.create` everywhere else (NEW — OPEN, Low)

- **Business concept:** an administrator creates a backup archive on demand (#1468).
- **Current names:** audit action / OpenAPI `x-culvert-audit-event` **`backup.trigger`**
  (`backups_api.go:335`, `api/openapi/openapi.yaml:6795`); the maintenance-agent operation it starts is
  **`backup.create`** (`cmd/culvert-maint/internal/ops/ops.go:73`, `backups_api.go:363` `backupOpKind`);
  GUI tooltip "Create a backup now, without SSH"; code comment "pre-trigger snapshot".
- **Recommended canonical name:** **`backup.create`** (verb *create*). Of ~100 audit verbs the dominant
  creation verb is `create` (9) with `add` (11) for list members; `trigger` appears nowhere else.
- **Why problematic:** one action, two names across audit log and agent op log; a SIEM rule or an operator
  grepping `backup.create` finds the agent record but not the admin's audit entry (and vice versa). The
  audit entry also does not name *who created* vs *what was created* as `*.create` entries do.
- **Why better:** one verb joins admin audit ↔ agent operation ↔ GUI wording ("Create a backup").
- **Affected code:** `backups_api.go:335`. **API:** `x-culvert-audit-event` on the backups POST route
  (OpenAPI yaml/json regeneration via `make api-bundle`). **GUI:** none (copy already says "create").
  **Docs/config:** any runbook quoting `backup.trigger`; none found outside the OpenAPI files.
- **Migration complexity:** Low. **Compatibility risk:** Low–Medium — audit action strings are consumed by
  SIEM filters; the action shipped in #1468 on 2026-09-26, so the installed base is small. If renamed,
  emit the new name only and note it in the CHANGELOG.
- **Estimated PR size:** S (~6 lines + regenerated OpenAPI + one test assertion).
- **Priority: Low.** Not fixed here: renaming a published audit action is a compatibility decision that
  belongs to the owner, and the stop-condition bar ("improves long-term language") is met only
  marginally while the installed base is still small — hence the recommendation to decide soon rather
  than after more SIEM rules exist.

## Considered and rejected (no action)

- **"Tracing Headers Replaced" (GUI) vs `culvert_tracing_header_rejected_total` / `tracingHeaderRejected`.**
  Different vocabulary for one counter, but deliberate: the *decision* is a rejection of the client's value,
  the *effect* is a replacement, and the tooltip states both. Renaming the metric/stat field would break
  dashboards for no product-language gain. No change.
- **"Stale Episodes" label** is already qualified by the Cluster panel's rate-limit section; no collision.
- Casing of new legacy-GUI labels ("Change Password", "Start Backup") is Title Case, matching the
  surrounding `static/index.html` panels; the sentence-case rule in the glossary applies to the new React
  frontend and is not retro-applied to the legacy SPA (see earlier reports).

## Migration Risk / Plan

Only T-64: (1) owner decision on the audit action name; (2) if accepted, one S-sized PR renaming the
string, regenerating OpenAPI, asserting the new name in `backups_api` tests; no GUI work.

## Carried (not re-verified)

T-11, T-12, T-29, T-30, T-54, T-61, T-62 (API/audit half), T-63 and DEBT-014 remain as recorded by earlier
reports; nothing in this window touched their surfaces.
