# Culvert Language & Terminology Governance Review — 2026-10-02

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot:** `origin/main` at `3fcc07e`. **Window:** `45eaf07..3fcc07e` (the merge of the 2026-09-24 report to now;
> 12 first-parent merges, 126 files). Findings and citations describe that snapshot; the one fix below is
> applied by this PR. Carried backlog items are not re-verified here (their owning reports hold the evidence).

## Executive Summary

One new drift found and fixed (**T-64**). Everything else added in the window is consistent with the glossary.

Glossary sweep of the window's added lines (literal patterns, `docs/design/PRODUCT-TERMINOLOGY.md`):
`unauth mode`, `blacklist/whitelist`, `Users & Roles`, `Cluster Nodes`, `Live Feed`, `Recent Requests`,
`threat engine`, `proxy pool`: 0 hits. `appliance`: 4 visible hits — 2 CHANGELOG sentences and 2 OpenAPI
`x-culvert-tenant-scope: appliance` extension values; both are pre-existing vocabulary (the extension is a
published machine-readable enum), so no change is recommended. Audit actions added: `backup.trigger`,
`auth.basic.fail`, `auth.basic.refused` — they follow the established `domain.action[.outcome]` grammar.
The context-sensitive glossary rules (sentence case, "status" vs "health", bare "user") are not decidable by
pattern count and were not swept; the legacy GUI is predominantly Title Case, so new "Backup Now" /
"Change Password" labels match their neighbours.

**Terminology Health Score: 7.9 / 10** (lineage of the 2026-09-24 report's comparison row). T-64 is opened
and closed in this PR, so it nets 0.0.

## Finding

### T-64 — "Admin Users" is a screen that does not exist (Medium · Low risk · XS)

| | |
|---|---|
| **Business concept** | The console-account screen (admin / operator / viewer roles) |
| **Current names** | "Administrators" (sidebar item `static/index.html` nav-users, page header `views` map, React `AppShell.tsx`, glossary); **"Admin Users"** (the panel's own `panel-title`; 12 operator-facing strings in `diagnostics.go` added by #1490; `store.go` role-clamp log line, which also said "Security -> Admin Users") |
| **Canonical name** | **Administrators** (glossary: *"Users & Roles" → "Administrators"; avoids collision with proxy users/identities*; reaffirmed by the 2026-09-09 report) |
| **Why the current naming is a problem** | The `admin_username_length` operator-contract row tells the admin to act "from Admin Users" and to "set its role back … in Admin Users". Nobody can find a nav item with that name; the sidebar says Administrators, and the panel opened from it was titled "Admin Users" — two names for one screen on one page. The role-clamp log line pointed to a "Security" section the item is not in. Remediation text that names a nonexistent screen fails the one reader who must follow it mid-incident. |
| **Why the new name is better** | One name across sidebar, page header, panel title, diagnostics and logs, and it keeps "user" free to mean a proxy identity. |
| **Affected code** | `diagnostics.go` (6 strings + comments), `store.go` (1 log line), `diagnostics_test.go` (assertions) |
| **Affected GUI** | `static/index.html` panel title |
| **Affected API / config / docs** | None. `/api/auth/users`, audit actions (`auth.users.*`) and JSON fields are unchanged — backend identifiers are not renamed. No operator doc quotes the string. |
| **Migration complexity / compatibility risk / PR size** | Trivial / none (human-readable text only; no key, metric, alert name or audit action changes) / XS |

**Fixed in this PR.** Not renamed: the `+ Add User` button inside that panel. The glossary says "user" alone
should not mean a console account, so "Add administrator" would be consistent, but it is a single-button copy
change with no operator-instruction impact; recorded as a low-priority residual (**T-64b**), not charged.

## Carried backlog

Unchanged from the 2026-09-24 report's comparison row (23 IDs / 22 entries open; owners listed there),
plus T-64b (Low). No carried item was opened or closed by the window's merges, which touch no
route, metric, alert name, config key or audit-action rename.

## Stop-condition assessment

Apart from T-64, no production-worthy terminology improvement was identified in this window. No cosmetic
renames proposed.
