# Culvert Language & Terminology Governance Review — 2026-10-06

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review
> **Snapshot:** `origin/main` at `3fcc07e`. Window audited: terminology-bearing changes merged after the
> 2026-09-24 report's snapshot `6ec745d` (GUI copy in `static/index.html` and `frontend/src/features`,
> diagnostics, audit actions, OpenAPI). Method: added-line glossary sweep against
> `docs/design/PRODUCT-TERMINOLOGY.md` plus spot-checks of the new admin surfaces
> (#1425 self-service password change, #1468 on-demand backup, #1490 admin-username diagnostics, #1408 state-file quarantine).

## Executive Summary

One small production-worthy defect found and fixed; no rename of any stable identifier recommended.

1. **T-64 (fixed here).** The `admin_username_length` operator-contract row used two names for two
   different bounds. Its warning names the 64-byte **account limit** (`adminUsernameAccountLimit`), but its
   healthy message said "within the **login** length limit". "Login length limit" is the 256-byte login-API
   bound (`maxUsernameLen`, CHAOS-63) — a different number. An operator reading the OK row would believe 256
   was the threshold being checked. The OK message now states the same bound the warning does:
   "all configured admin usernames are within the 64-byte account limit". Copy only; the check `Code`,
   status values and thresholds are unchanged. Affected: `diagnostics.go` (one string). No test, OpenAPI, GUI or doc
   pins the old string (grep-verified).
2. **New admin surfaces are otherwise consistent.** `Change Password` / `auth.password_change` /
   `/api/auth/change-password` agree; `Backup Now` / `backup.trigger` / `backup.create` agree in
   meaning (`backup.create` is the maintenance-agent operation kind, `backup.trigger` the admin audit action —
   distinct namespaces, not drift). The new GUI text uses the existing legacy Title Case button convention
   (carried legacy style, not new drift).
3. **Carried backlog unchanged.** T-9, T-11, T-12, T-13, T-18, T-21+T-32, T-25, T-29, T-30, T-33, T-34, T-39,
   T-54, T-55, T-56, T-59b/c, T-60, T-61, T-62, T-63 and the T-51 residual remain as recorded by their owning
   reports; not re-verified in full and not re-charged.
4. **Observation (not opened as an ID; owner decision).** Diagnostics copy says "admin account/username"
   (ten Go sites) while the glossary canonical is **Administrator** (console account) and the legacy panel is
   titled "Admin Users". Both the shipped nav label ("Administrators") and the panel title ("Admin Users")
   exist today; aligning them is a GUI-wide decision the glossary already scopes, so no change is proposed
   inside a diagnostics-copy fix.

**Terminology Health Score:** 7.9 → **7.9** (lineage of the 2026-09-24 report's comparison row). T-64 was opened
and closed in the same change, so net 0.0.

## Findings

| ID | Business concept | Current names | Canonical | Priority | Migration | Compat risk | PR size |
|---|---|---|---|---|---|---|---|
| T-64 (fixed) | Maximum supported admin username length | "login length limit" (OK) vs "account limit" (warn) | "account limit" (64 bytes); "login bound" reserved for the 256-byte login-API bound | Low | None | None (copy only) | XS |

## Stop-condition assessment

Beyond T-64, no production-worthy terminology improvement was identified in the window.
