# Category D′ Direction Decision

**Status:** discovery + design-decision document. No production code changes in this PR.

**Subjects:** the three handler groups identified as Category D′ ("misleading — currently has `saveConfigVersion` but mutation NOT in the rollback surface") by `roadmap/CONFIG-VERSIONING-TRIAGE.md`:

1. `apiCategoryGroups` (`ui_policy.go:371,392,417` — POST add / PUT update / DELETE)
2. All six `cdr.*` mutations (`cdr_ui.go`: `cdr.config.toggle`, `cdr.instance.enroll`, `cdr.instance.remove`, `cdr.policy.add`, `cdr.policy.remove`, `cdr.instance.revoke_rpc`)
3. `apiSettingsNetwork` (`ui_config.go:870` — POST)

Each group has the same shape — the handler calls `saveConfigVersion` immediately after `auditEvent`, but the mutated state is NOT in `captureConfigBackup`/`applyConfigBackup`, so rolling back to a prior version does not actually restore the mutation. This document decides direction A (remove the misleading calls) vs direction B (extend the rollback surface) per group.

**Scope (deliberate):**

- Discovery / design-decision documentation only.
- No production code changes.
- No removals or extensions implemented in this PR.
- No bundling — each group ships as its own dedicated follow-up PR.
- No extension of `captureConfigBackup` / `applyConfigBackup` yet.
- No URL category, scanner, or CA work.

---

## 1. The two surface axes

Before the per-group analysis, an important distinction surfaced during this discovery that the triage PR understated: **`saveConfigVersion` and `ConfigSnapshot` are two distinct surfaces.**

| Surface | Used for | Captured by | Restored by |
|---|---|---|---|
| **Rollback surface** | Operator-triggered "rollback to vN" | `captureConfigBackup` (`configversion.go:59-79`) | `applyConfigBackup` (`configversion.go:325-388`) |
| **Cluster-sync surface** | CP→DP / leader→standby state replication on every heartbeat | `CurrentConfigSnapshot` (`controlplane.go:1700-…`) | `applyConfigSnapshot` (`controlplane.go:1457-…`) |

A piece of state can be in either surface, both, or neither. The triage doc focused only on the rollback surface; this discovery makes the cluster-sync surface explicit because **state that is HA-replicated has a stronger argument for being in the rollback surface too** (the new leader's recovery is more meaningful when the rollback log matches what was last replicated).

| Group | In rollback surface? | In cluster-sync surface? | HA-replicated? |
|---|---|---|---|
| Category groups (`globalCategoryGroups`) | NO | **YES** (`ConfigSnapshot.CategoryGroups`, applied at `controlplane.go:1609-1613`; captured at `:1708`) | YES |
| CDR config + instances + policies | NO | NO | NO (per-CP local) |
| Network settings (`proxyExternalBaseURL` etc.) | NO | NO | NO (per-CP local) |

This single axis distinguishes the three groups cleanly.

---

## 2. `apiCategoryGroups`

### What is mutated

`apiCategoryGroups` handles add (POST), update (PUT), delete (DELETE) of named category groups. Each group bundles URL category names under a single label (e.g. `"Prod Allowed"` → `["news","cloud","saas"]`). Mutations land in `globalCategoryGroups` (`categorygroup.go:51`).

### Where it persists

`/data/category_groups.json` via `globalCategoryGroups.Save()`. The save method is invoked from each handler (`ui_policy.go:377`, `:398`, `:423`).

### HA-replication / ConfigSnapshot relationship

**Yes, replicated.** `ConfigSnapshot` (`controlplane.go:116`) declares `CategoryGroups []CategoryGroup`. `CurrentConfigSnapshot` populates it at `controlplane.go:1708` via `globalCategoryGroups.List()`. `applyConfigSnapshot` restores it at `:1609-1613` via `globalCategoryGroups.ReplaceAll(...) + Save()`. So a DP poll or HA-standby sync DOES propagate category-group changes.

### Rollback suitability

**Strong argument for direction B (extend surface).**

Policy rules (which ARE in the rollback surface) reference category groups by name. A rule like `match category-group "Prod Allowed" → allow` depends on the group existing. If the operator:

1. Creates group `"Prod Allowed"` at v3.
2. Creates a policy rule referencing it at v4.
3. Deletes the group at v5.
4. Rolls back from v6 to v3 hoping to restore the original config.

The rollback restores the v3 policy rule set (which doesn't reference the group yet — that's v4) but does NOT restore the v3 group state. If we instead rolled back from v6 to v5 (group deleted, policy still referencing it), the policy is restored in its broken state. Either way the cross-reference is incoherent because the two halves of the same operator-intent move in lockstep at write time but not at rollback time.

The Zero Trust default-deny catches the broken-reference case (a missing group can't match), but the rule INTENT is silently broken. The operator's mental model — "rollback v3 → v2 reverts what v3 changed" — is violated specifically because PolicyRules and CategoryGroups are coupled at the policy-eval layer but decoupled at the rollback layer.

### Operator risk

| Direction | Risk |
|---|---|
| **NOT restored on rollback (today, direction A)** | Policy rules referencing groups become broken on rollback; rule intent silently invalid; default-deny saves correctness but operator is confused. Misleading `saveConfigVersion` call writes a version log entry that doesn't capture the group change. |
| **Restored on rollback (direction B)** | Category groups are pure data; no security implications. Restoring an old group set has the same shape as restoring an old policy set — both are "operator's choice to undo". |

### Recommended direction

**B (extend rollback surface).** The coupling with PolicyRules is the deciding factor — rolling back policies without rolling back their referenced groups is genuinely incoherent. The implementation cost is small (one new struct field + one capture line + one apply block, mirroring how policy rules already work). The existing `saveConfigVersion` calls in `apiCategoryGroups` would then be correct and the version log honest.

### Smallest safe implementation sequence

1. Add `CategoryGroups []CategoryGroup` to the `configBackup` struct (`ui_policy.go:620-643`).
2. Populate it in `captureConfigBackup` (`configversion.go:59-79`): `CategoryGroups: globalCategoryGroups.List()`.
3. Restore it in `applyConfigBackup` (`configversion.go:325-388`): mirror the `policyStore.ReplaceAll(...)` + `Save()` pattern at the same point in the function.
4. Add regression test: mutate category groups → `saveConfigVersion` → wipe in-memory state → `applyConfigBackup(snap)` → assert restored.
5. Update `roadmap/CONFIG-VERSIONING-TRIAGE.md` §4.1 to flip the three category-group rows from "(D) Misleading" to "✓ Correct".
6. No changes to `apiCategoryGroups` handlers — they already call `saveConfigVersion`.

**One PR.** Estimated +30 lines production (struct field + capture line + apply block) + ~80 lines test. Self-contained.

---

## 3. CDR (`cdr.*` handlers — six calls)

CDR is heterogeneous: the six mutations split into THREE risk buckets, not one. The triage PR treated them as a uniform group; this discovery splits them.

### What is mutated (per handler)

| Handler | What is mutated | Persists where |
|---|---|---|
| `cdr.config.toggle` (`cdr_ui.go:127`) | `cdr.enabled` runtime flag | `/data/cdr_enabled` |
| `cdr.instance.enroll` (`cdr_ui.go:334`) | CDR Sluice instance registry (endpoint, token hash, cert FP, name) | `cdr_instances.json` |
| `cdr.instance.remove` (`cdr_ui.go:205`) | Same registry — remove entry | `cdr_instances.json` |
| `cdr.policy.add` (`cdr_ui.go:515`) | CDR file-handling policy rules (separate from main policy rules) | `cdr_policies.json` |
| `cdr.policy.remove` (`cdr_ui.go:537`) | Same | `cdr_policies.json` |
| `cdr.instance.revoke_rpc` (`cdr_ui.go:634`) | Revoke an RPC token for an enrolled instance | `cdr_instances.json` (revocation marker) |

### HA-replication / ConfigSnapshot relationship

**No.** Grepping `controlplane.go` for `CDR` or `cdr` returns no `ConfigSnapshot` fields and no `applyConfigSnapshot` references. CDR state is local to each CP. A standby CP that promotes via HA will have its own local CDR registry, not the leader's.

The file header at `cdr_ui.go:22` documents the expectation that doesn't hold:

> *"Every mutation calls `saveConfigVersion(actor, action)` so the admin can rollback to a known-good cluster baseline."*

The implementation does call `saveConfigVersion`, but the rollback surface does NOT include CDR — so the rollback contract the comment describes is broken.

### Risk split

| Handler | Security sensitivity | Rollback risk |
|---|---|---|
| `cdr.instance.revoke_rpc` | **HIGH** | Same shape as `auth.password_change`: revocation is typically because the credential / endpoint was compromised. Restoring a revocation silently un-revokes it — security regression. |
| `cdr.config.toggle` | Low | Rollback could re-enable an intentionally-disabled feature. Mild risk. |
| `cdr.instance.enroll` / `cdr.instance.remove` | Low | Enroll/remove of an external Sluice. Rolling back has the same shape as any registry mutation — the external endpoint may or may not still accept the restored token. Operationally fine. |
| `cdr.policy.add` / `cdr.policy.remove` | Low | Pure file-handling policy data. Safe. |

### Operator risk per direction

| Direction | Risk |
|---|---|
| **NOT restored on rollback (today, direction A)** | The file header expectation is broken. Operators who read `cdr_ui.go:22` and assume rollback works for CDR are wrong. Misleading version log entries for all six handlers. |
| **Restored on rollback (direction B)** | `cdr.instance.revoke_rpc` becomes a silent un-revocation on rollback — a security regression by definition (Category D-sec). The other five mutations are safe but require extending captureConfigBackup to read three separate CDR files. |

### Recommended direction

**Split:**

1. **`cdr.instance.revoke_rpc` → direction A (remove, security-sensitive).** Identical shape to the `auth.password_change` Category D-sec follow-up (PR #261). Removing the `saveConfigVersion` call here is the security-correct answer; restoring a revocation is never the right rollback semantic.
2. **The other five `cdr.*` → direction A (remove).** CDR is local-only, not HA-replicated. Extending `captureConfigBackup` to read three separate files (cdr_enabled, cdr_instances.json, cdr_policies.json) + extending `applyConfigBackup` to restore them is significantly larger than removing five misleading calls. The file header at `cdr_ui.go:22` should be updated to say "CDR state is NOT in the rollback surface; saveConfigVersion is not called". That keeps the contract honest with minimal change.

Direction A is recommended over B for CDR specifically because the cost-benefit math is the inverse of category groups: there's no cross-reference forcing function (no other rollback-surface state depends on CDR state), and extending the surface is larger than removing the calls.

### Smallest safe implementation sequence

**Two PRs, not one.**

1. **Security PR (mirror PR #261).** Remove `saveConfigVersion(sessionAdmin(r), "cdr.instance.revoke_rpc")` at `cdr_ui.go:634`. Add inline comment explaining that revocation must not silently rollback. Add focused regression test: revoke RPC → assert no envelope with `Action="cdr.instance.revoke_rpc"`. Estimated -1 production line + ~80 lines test.
2. **Hygiene PR.** Remove the other five `saveConfigVersion` calls. Update the `cdr_ui.go:22` file header to document the correct contract (CDR state is local-only and not in the rollback surface). Add a single regression test that exercises all five handlers and asserts none produces a `cdr.*` envelope. Estimated -5 production lines + ~100 lines test.

These must NOT be bundled; the security PR should land independently for a clean security-audit trail.

---

## 4. `apiSettingsNetwork`

### What is mutated

Three package-level variables: `proxyExternalBaseURL`, `uiExtraSANs`, `trustForwardedHeaders` (`ui_config.go:857-859`). Each has distinct downstream effects.

| Variable | Effect |
|---|---|
| `proxyExternalBaseURL` | Reported as the proxy's public URL; used by OIDC redirect URIs, PAC file generation, alert webhook templates |
| `uiExtraSANs` | Additional SANs included when the auto-generated UI cert is regenerated; changing this triggers a cert regeneration |
| `trustForwardedHeaders` | Security flag: do we trust `X-Forwarded-Host` / `X-Forwarded-Proto` headers? |

### Where it persists

`adminSettingsSave()` (`admin_settings.go:296-299`) which goroutine-dispatches `SaveAdminSettings()` writing to `/data/admin_settings.json` via plain `os.WriteFile` + `os.Rename` (non-fsync; tracked as a separate durability item).

### HA-replication / ConfigSnapshot relationship

**No.** Grep `controlplane.go` for `proxyExternalBaseURL`, `BaseURL`, `UISANs`, `TrustForwardedHeaders`, `trust_forwarded` returns no `ConfigSnapshot` fields and no `applyConfigSnapshot` references. Network settings are per-CP local.

### Risk split

- **`trustForwardedHeaders`** is security-sensitive. Flipping from `false` to `true` (which a rollback would do if the operator just disabled it) re-enables trust of forwarded headers — could re-expose a previously-disabled attack vector (header spoofing → wrong client IP → wrong policy decision).
- **`uiExtraSANs`** change triggers UI cert regeneration. Rolling back means either regenerating-back (functional but creates cert churn that breaks browser cert-pin caches) or leaving the cert with extra SANs (mismatched config that's hard to diagnose).
- **`proxyExternalBaseURL`** controls OIDC redirect URIs and PAC generation. Rolling back to an old URL can break OIDC because the registered redirect URI on the IdP side typically doesn't change in sync.

### Operator risk per direction

| Direction | Risk |
|---|---|
| **NOT restored on rollback (today, direction A)** | Misleading version log entry. Operators who roll back expecting network settings to revert will be wrong. |
| **Restored on rollback (direction B)** | `trustForwardedHeaders` flip-back is security-sensitive. `uiExtraSANs` triggers cert churn. `proxyExternalBaseURL` may break OIDC. Each is operationally complicated. |

### Recommended direction

**A (remove the `saveConfigVersion` call).** Network settings are per-node operational config, security-mixed, not HA-replicated. The downstream effects (cert regeneration, OIDC redirect coordination) make automated rollback genuinely dangerous in ways the rollback API doesn't currently communicate. Removing the misleading call keeps the surface honest; operators who need to revert these specific settings should do so explicitly via `POST /api/settings/network` with the old values.

### Smallest safe implementation sequence

1. Remove the single `saveConfigVersion(sessionAdmin(r), "settings.network")` line at `ui_config.go:870`.
2. Add inline comment explaining network settings are operational/per-node and not in the rollback surface — mirror of the comment added to `apiAuthChangePassword` in PR #261.
3. Add focused regression test: mutate network settings → assert no envelope with `Action="settings.network"` (mirror of `TestAPIAuthChangePassword_DoesNotCreateConfigVersion`).
4. **One PR.** Estimated -1 production line + 8 lines comment + ~80 lines test.

---

## 5. Sequencing recommendation

These three groups should ship as **four separate PRs**, not bundled:

1. **`cdr.instance.revoke_rpc` security PR** (direction A, security-sensitive). Independent of everything else; ships first because the security pattern is established (mirror of PR #261).
2. **`apiSettingsNetwork` PR** (direction A). Tiny; independent.
3. **CDR hygiene PR** (direction A for the other five `cdr.*` handlers). Independent.
4. **`apiCategoryGroups` rollback-surface extension** (direction B). Largest of the four; ships last because it actually extends `captureConfigBackup` / `applyConfigBackup`, which is a structural change that should land cleanly without the other PRs reshuffling the same files. The triage doc's surface table will need to gain a row.

The user brief explicitly forbids bundling, and this sequencing matches: each PR has one motivation, one direction, one set of regression tests.

---

## 6. What this PR did NOT do (deliberate)

- No production code changes.
- No `saveConfigVersion` calls removed or added.
- No `captureConfigBackup` / `applyConfigBackup` surface changes.
- No `ConfigSnapshot` changes.
- No HA changes.
- No `cdr_ui.go:22` file header update.
- No URL category, scanner, or CA work.
- No bundling — the four follow-up PRs are explicitly separate above.

## 7. No unresolved VERIFY / UNCERTAIN markers

Every claim in this document is grounded in line-numbered evidence:

- `captureConfigBackup` / `applyConfigBackup` field set verified at `configversion.go:59-79` and `:325-388`.
- `ConfigSnapshot.CategoryGroups` verified at `controlplane.go:116`, captured at `:1708`, applied at `:1609-1613`.
- CDR absence from `ConfigSnapshot` verified by `grep "CDR\|cdr" controlplane.go | grep -i "snapshot\|configsnapshot"` returning no hits.
- Network-settings absence from `ConfigSnapshot` verified by `grep "proxyExternalBaseURL\|BaseURL\|UISANs\|TrustForwardedHeaders\|trust_forwarded" controlplane.go` returning no hits.
- CDR file paths verified at `cdrstore.go:274` and test files.
- All handler line numbers verified by `grep`.

No "probably", no "looks like", no "VERIFY:" markers.
