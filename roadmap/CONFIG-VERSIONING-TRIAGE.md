# Config-Versioning Coverage Triage

**Status:** discovery + triage decision document. No production code changes in this PR.

**Cross-discovery group:** P6.1 UC-4 (URL categories), P6.2 SC-1 (scanner config), P6.3 CA-1 (CA / certs), P6.4 CL-8 (cluster admin). All four name the same shape — admin handlers that emit `auditEvent` but never call `saveConfigVersion` — and all four explicitly defer the decision to "a single triage" (URL-CATEGORIES-DISCOVERY §10 UC-4; SCANNING-DISCOVERY §10 SC-1; ROOT-CA-DISCOVERY §9; CLUSTER-RUNTIME-DISCOVERY §13 CL-8).

This document is that triage.

---

## 1. The actual rollback surface

The rollback system is three pieces:

1. **`captureConfigBackup`** (`configversion.go:59-79`) — point-in-time snapshot creator. Called by `saveConfigVersion` on every mutating admin operation.
2. **`saveConfigVersion`** (`configversion.go:81`) — writes the snapshot to `/data/config_versions/v{N}.json` and rotates older versions (50-version cap per CLAUDE.md).
3. **`applyConfigBackup`** (`configversion.go:325-388`) — the rollback path that restores a snapshot into live state.

### What gets captured AND applied (the "true" rollback surface)

Verified field-by-field by reading both `captureConfigBackup` and `applyConfigBackup`:

| Surface item | Source store | Captured by | Restored by |
|---|---|---|---|
| Blocklist entries | `bl.List()` | `:65` | `:329-334` |
| Blocklist mode | `bl.Mode()` | `:64` | `:336-338` |
| Policy rules | `policyStore.List()` | `:66` | `:341-349` (validated re-add) |
| Default policy action | `defaultPolicyAction()` | `:67` | `:350` |
| Rewrite rules | `rewriter.List()` | `:68` | `:353` |
| SSL bypass patterns | `sslBypass.List()` | `:69` | `:356-357` |
| Content scan patterns | `dpiScanner.List()` | `:70` | `:358-359` |
| File block extensions | `fileBlocker.List()` | `:71` | `:362-367` |
| IP filter mode + list | `ipf.Mode()` / `ipf.List()` | `:72-73` | `:370-376` |
| Rate limit RPM | `rl.Limit()` | `:74` | `:378-380` (only if `> 0`) |
| PAC config | `pacStore.Get()` | `:75-77` | `:383-387` |
| Category groups (added PR #267) | `globalCategoryGroups.List()` | `captureConfigBackup` (CategoryGroups assignment) | `applyConfigBackup` (`ReplaceAll + Save` BEFORE PolicyRules) |
| URL categories — admin Layer 1 (added PR #269) | `catStore.All()` | `captureConfigBackup` (URLCategories assignment) | `applyConfigBackup` (`ReplaceAll + Save` BEFORE CategoryGroups) |

### What is in `configBackup` struct but NOT in capture/apply

The struct (`ui_policy.go:620-643`) has more fields than `captureConfigBackup` populates:

| Struct field | Captured? | Applied? | Source |
|---|---|---|---|
| `RateLimitExempt` | NO | NO | `ui_policy.go:634` |
| `AlertWebhooks` | NO | NO | `ui_policy.go:638` "Finding 10.3" |
| `BlockPageHTML` | NO | NO | `ui_policy.go:639` "Finding 10.3" |
| `UpstreamProxies` | NO | NO | `ui_policy.go:640` "Finding 10.3" |
| `ConnLimitEnabled` | NO | NO | `ui_policy.go:641` "Finding 10.3" |
| `ConnLimitMaxPerIP` | NO | NO | `ui_policy.go:642` "Finding 10.3" |

These fields are populated by the export endpoint (`ui_config.go` `apiConfigExport`) and consumed by import — but NOT by the rollback path. The "Finding 10.3" markers suggest an in-progress surface extension that was never completed. **This is itself a finding (B′ below).**

### What is entirely off the rollback surface

Every other persistent admin-mutated store: `globalThreatFeed`, `globalProfileStore` (file profiles), `globalNodeGroups`, `globalBandwidth`, CDR config, alert webhooks, IdP registry, session HMAC, syslog config, OTLP endpoint, metrics token, UI allow IPs, session timeout, log level, blockpage template, upstream proxies, conn-limiter config, YARA settings + rule files, scan exclusions + DPI bypass, OCSP toggle, MITM/UI cert uploads, cluster state (`globalClusterStore`), enrolled-node certs, cluster-CA material, rolling-update state, HA config.

---

## 2. Critical insight that drives the triage

**Calling `saveConfigVersion` for a handler whose mutation is NOT in the rollback surface produces a misleading snapshot.** The version log gets a new entry. The snapshot file gets written. The audit trail records the mutation. But rolling back to that version restores ONLY the 9 captured items above; the mutation persists. The operator's mental model — "rollback v3 → v2 reverts what v3 changed" — is violated.

This means the triage decision per handler is two-level:

1. **Should rollback restore this mutation?** (operator-policy question — some mutations are dangerous to silently revert)
2. **If yes, is the rollback surface big enough to actually do it?** (engineering-prerequisite question — most "yes" answers require extending `captureConfigBackup`/`applyConfigBackup` first)

Many existing `saveConfigVersion` calls bypass this analysis: they call the function but the mutation isn't captured. The cleanest examples are catalogued below (Category D).

---

## 3. Methodology

Grepped every `auditEvent` / `auditEventDiff` call site across the production codebase (`grep -rn "auditEvent\|auditEventDiff" --include="*.go" | grep -v _test.go`). Cross-referenced each call site with:

- File / line number
- What state is mutated (verified from the surrounding handler code)
- Where that state persists (file path or memory-only)
- Whether the surrounding handler also calls `saveConfigVersion`
- Whether the mutated state is in the rollback surface (table §1)

Final classification is in §4.

---

## 4. Full triage table

Format: `handler` (`file:line`) — mutation — persists where — `auditEvent` — `saveConfigVersion` — rollback suitability — reasoning. **108 audit-event call sites** across mutation handlers; condensed below into 11 logical groups. Where a group has multiple sub-calls in one file the line range is `:NNN-MMM`.

### 4.1 Policy / rules / blocklist (`ui_policy.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiBlocklist` POST add | 112-113 | `bl.Add` | `bl.json` | YES | **YES** | YES | ✓ Correct |
| `apiBlocklist` POST bulk_remove | 138-139 | `bl.Remove` | `bl.json` | YES | **YES** | YES | ✓ Correct |
| `apiBlocklist` POST single remove | 149-150 | `bl.Remove` | `bl.json` | YES | **YES** | YES | ✓ Correct |
| `apiBlocklistMode` POST | 179-180 | `bl.SetMode` | `bl.json` | YES | **NO** | YES (`BlocklistMode`) | **GAP — tiny first case** |
| `apiBlocklistFeed` POST set | 247-248 | feed URL config | `feed_cfg.json` | YES | NO | NO | (C) Out of surface |
| `apiBlocklistFeed` POST sync | 267 | runtime trigger | n/a | YES | NO | n/a | (E) Runtime action, not config |
| `apiBlocklistException` POST add | 315-316 | exception list | `bl.json`, separate set | YES | NO | NO | (C) Out of surface |
| `apiBlocklistException` POST remove | 329-330 | exception list | `bl.json`, separate set | YES | NO | NO | (C) Out of surface |
| `apiCategoryGroups` POST add | 371-372 | `globalCategoryGroups` | `category_groups.json` | YES | **YES** | YES (extended PR #267) | ✓ Correct |
| `apiCategoryGroups` PUT update | 392-393 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiCategoryGroups` DELETE | 417-418 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiURLCat` POST create | 479-480 | `catStore` | `categories.json` | YES | **YES** | YES (extended PR #269) | ✓ Correct |
| `apiURLCat` PUT update | 511-512 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiURLCat` DELETE | 532-533 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiURLCatHost` POST add | 563-564 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiURLCatHost` DELETE | 580-581 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiRewrite` POST add | 663-665 | `rewriter` | `rewrite.json` | YES | **YES** | YES (`RewriteRules`) | ✓ Correct |
| `apiRewrite` DELETE | 683-685 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiPolicyRules` POST add | 731-733 | `policyStore` | `policy.json` | YES | **YES** | YES | ✓ Correct |
| `apiPolicyRules` PUT update | 770-772 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiPolicyRules` bulk_delete | 794-795 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiPolicyRules` DELETE | 826-827 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiPolicyRules` reorder | 858-859 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiPolicyRules` move | 971-972 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiPolicyDefaultAction` PUT | 1083-1085 | global var | n/a | YES | **YES** | YES (`DefaultAction`) | ✓ Correct |
| `apiSSLBypass` POST add | 1175-1177 | `sslBypass` | `ssl_bypass.json` | YES | **YES** | YES | ✓ Correct |
| `apiSSLBypass` DELETE | 1192-1193 | same | same | YES | **YES** | YES | ✓ Correct |

### 4.2 Security / scanning / certs (`ui_security.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiAlertWebhooks` POST | 57 | `globalAlertStore` | `alert_webhooks.json` | YES | NO | NO (B′) | Needs decision — `AlertWebhooks` in struct, not in capture/apply |
| `apiAlertWebhooks` PUT | 84 | same | same | YES | NO | NO (B′) | Same |
| `apiAlertWebhooks` DELETE | 100 | same | same | YES | NO | NO (B′) | Same |
| `apiSecurity` POST | 214-217 | `ipf` + `rl` | n/a, in-memory | YES | **YES** | YES | ✓ Correct |
| `apiCertsUpload` mitm | 283 | MITM CA bundle | encrypted CA bundle | YES | NO | NO | (D-sec) Security-sensitive; rollback dangerous |
| `apiCertsUpload` ui | 293 | UI cert files | TLS material | YES | NO | NO | (D-sec) Security-sensitive |
| `apiContentScan` POST | 337-339 | `dpiScanner` | `content_scan.json` | YES | **YES** | YES (`ContentScanPatterns`) | ✓ Correct |
| `apiContentScan` DELETE | 354-355 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiFileBlock` POST | 395-396 | `fileBlocker` | `fileblock.json` | YES | **YES** | YES (`FileBlockExtensions`) | ✓ Correct |
| `apiFileBlock` DELETE | 410-411 | same | same | YES | **YES** | YES | ✓ Correct |
| `apiFileProfiles` POST | 450 | `globalProfileStore` | `file_profiles.json` | YES | NO | NO | (C) Out of surface |
| `apiFileProfiles` PUT | 474 | same | same | YES | NO | NO | (C) |
| `apiFileProfiles` DELETE | 490 | same | same | YES | NO | NO | (C) |
| `apiSecurityFeedsSync` | 527 | runtime feed sync | n/a | YES | NO | n/a | (E) Runtime action |
| `apiSecurityYARAReload` | 590 | YARA in-memory + hashcache | n/a | YES | NO | n/a | (E) Runtime action |
| `apiSecurityYARASettings` | 675 | YARA settings | `yara_settings.json` | YES | NO | NO | (C) Out of surface (P6.2 SC-1) |
| `apiSecurityYARAWrite` | 753 | YARA rule files | `yara/*.yara` | YES | NO | NO | (C) SC-1; binary files |
| `apiSecurityYARADelete` | 778 | YARA rule files | same | YES | NO | NO | (C) SC-1 |
| `apiSecurityScanExclusions` | 865 | `scan_exclusions.json` | file | YES | NO | NO | (C) SC-1 |
| `apiContentScanBypass` | 902 | DPI bypass | file | YES | NO | NO | (C) SC-1 |
| `apiScanCache` evict | 964 | cache | in-memory | YES | NO | n/a | (E) Runtime |
| `apiScanCache` clear | 968 | cache | in-memory | YES | NO | n/a | (E) Runtime |
| `apiCACacheClear` | 1036 | leaf cert cache | in-memory LRU | YES | NO | n/a | (E) Runtime (P6.3 CA-1) |
| `apiCARotate` request | 1072 | confirmation token | in-memory | YES | NO | n/a | (E) Token-issue ceremony |
| `apiCARotate` confirm | 1108 | Root CA material | encrypted CA bundle | YES | NO | NO | (D-sec) **CRITICAL: rollback would revert CA rotation — never silently** (P6.3 CA-1) |
| `apiOCSPConfig` | 1172 | OCSP toggle | config | YES | NO | NO | (C) Out of surface |

### 4.3 Config / settings (`ui_config.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiConfigExport` | 367 | read-only export | n/a | YES | NO | n/a | (E) Read-only, not a mutation |
| `apiConfigImport` | 537-538 | full config replace | every file in surface | YES | **YES** | YES (whole surface) | ✓ Correct — this IS rollback in inverse |
| `apiSettings` session_secret rotate | 572 | `sessionSecret` | `session_secret.json` | YES | NO | NO | (D-sec) Security-sensitive; rollback re-exposes prior secret |
| `apiSettings` session_timeout | 604 | TTL | settings | YES | NO | NO | (C) Out of surface |
| `apiSettings` ui_allow_ips | 639 | IP allowlist | settings | YES | NO | NO | (D-sec) Rollback could lock out admin |
| `apiSettings` syslog | 691, 701 | syslog config | settings | YES | NO | NO | (C) Out of surface |
| `apiSettings` auth | 761 | UI admin pwd hash | `ui_users.json` | YES | NO | NO | (D-sec) See `auth.password_change` below |
| `apiSettings` unauth_mode | 787, 791 | unauth toggle | `ui_users.json` envelope | YES | NO | NO | (D-sec) Auth posture toggle |
| `apiSettings` log_level | 824 | runtime log level | n/a | YES | NO | n/a | (E) Runtime |
| `apiSettingsNetwork` | 867-870 | network settings | settings | YES | **YES** | NO | (D) Misleading — saveCV but not in capture/apply |
| `apiSettings` metrics_token | 920 | token | settings | YES | NO | NO | (D-sec) Security-sensitive |
| `apiConnLimit` | 960 | conn limiter cfg | settings | YES | NO | NO (B′) | Same as Alert webhooks; struct has fields, capture/apply don't |
| `apiBlockPage` | 998 | block page HTML | settings | YES | NO | NO (B′) | Same |
| `apiUpstreamProxies` | 1030 | upstream proxy list | `upstream.json` | YES | NO | NO (B′) | Same |
| `apiSettings` otlp | 1117, 1135 | OTLP endpoint | settings | YES | NO | NO | (C) Out of surface |

### 4.4 Auth / IdP (`ui_auth.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| login lockout fired | 33 | event | audit ring only | YES | NO | n/a | (E) Event, not mutation |
| totp fail | 72 | event | audit ring | YES | NO | n/a | (E) |
| login success | 96 | event | audit ring | YES | NO | n/a | (E) |
| login fail | 101 | event | audit ring | YES | NO | n/a | (E) |
| logout | 151 | session delete | n/a | YES | NO | n/a | (E) |
| `apiAuthUsers` POST | 209 | user CRUD | `ui_users.json` | YES | NO | NO | (D-sec) Rollback could lock out the only admin |
| `apiAuthUsers` DELETE | 230 | same | same | YES | NO | NO | (D-sec) |
| `apiAuthPasswordChange` | 294-295 | password hash | `ui_users.json` | YES | **YES** | NO | **(D-sec) Critical bug — rollback would restore the OLD password hash; security-sensitive AND not in capture/apply, so the saveCV call is doubly misleading** |
| `apiSetup` complete | 346, 371 | initial bootstrap | `ui_users.json` | YES | NO | n/a | (E) One-time bootstrap |
| `apiIdP*` create/update/delete | 401, 454, 466 | IdP registry | `idp.json` | YES | NO | NO | (D-sec) Rollback could revert IdP and lock out admins |

### 4.5 Cluster / enrollment / nodes (`ui_cluster.go`)

All entries are P6.4 CL-8.

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiClusterTokenCreate` | 208 | token entry | cluster.json | YES | NO | NO | (D-topology) Rollback shouldn't silently revoke a token an operator may have already used |
| `apiClusterRevoke` | 271 | revocation list | cluster.json | YES | NO | NO | (D-sec) Rollback un-revokes a node — never silently |
| `apiClusterCA` POST | 321 | custom cluster CA | cluster CA store | YES | NO | NO | (D-sec) Same as Root CA — never silently revert CA |
| `apiClusterLabels` | 449 | node labels | cluster.json | YES | NO | NO | (C-topology) Topology, not config |
| `apiClusterDrain` | 484 | node draining state | cluster.json | YES | NO | NO | (C-topology) Operational |

### 4.6 PAC (`pac.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiPACConfig` | 223-225 | `pacStore.Set` | `pac.json` | YES | **YES** | YES (`PACProxyHost`/`Port`/`Exclusions`) | ✓ Correct |

### 4.7 Bandwidth (`bandwidth.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiBandwidthPolicies` POST | 374 | `globalBandwidth` | `bandwidth_policies.json` | YES | NO | NO | (C) Operational policy; not in surface |
| `apiBandwidthPolicies` DELETE | 397 | same | same | YES | NO | NO | (C) |

### 4.8 Node groups (`nodegroup.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiNodeGroups` POST | 270 | `globalNodeGroups` | `nodegroups.json` | YES | NO | NO | (C-topology) Topology, not config |
| `apiNodeGroups` DELETE | 284 | same | same | YES | NO | NO | (C-topology) |

### 4.9 CDR (`cdr_ui.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `cdr.config.toggle` | 125-127 | global CDR config | CDR config files | YES | **YES** | NO | (D) Misleading — saveCV but state not captured (the file header at `cdr_ui.go:22` documents the expectation explicitly: "Every mutation calls saveConfigVersion(actor, action) so the admin can rollback" — implementation does not match) |
| `cdr.instance.remove` | 204-205 | CDR registry | CDR files | YES | **YES** | NO | (D) |
| `cdr.instance.enroll` | 331-334 | same | same | YES | **YES** | NO | (D) |
| `cdr.policy.add` | 512-515 | CDR policies | CDR files | YES | **YES** | NO | (D) |
| `cdr.policy.remove` | 536-537 | same | same | YES | **YES** | NO | (D) |
| `cdr.instance.revoke_rpc` | 631-634 | CDR registry | CDR files | YES | **YES** | NO | (D-sec) Misleading AND security-sensitive (revoking RPC) |

### 4.10 Update / cluster update (`update.go`, `update_cluster.go`)

| Handler | Lines | Mutation | Persists | audit | saveCV | In surface? | Suitability |
|---|---|---|---|---|---|---|---|
| `apiUpdate` apply | 528 | system update | binary swap | YES | NO | n/a | (E) Runtime lifecycle, not config |
| `apiUpdate` rollback | 899 | system rollback | binary swap | YES | NO | n/a | (E) Same |
| `apiUpdate` registry settings | 1000 | registry creds | settings | YES | NO | NO | (D-sec) Could leak prior registry creds on rollback |
| `apiClusterUpdate` start | 1133 | rolling update lifecycle | `cluster_update.json` | YES | NO | n/a | (E) Lifecycle, not config |

### 4.11 HA (`ha.go`)

`ha.go:422` uses `auditAdd` directly (system actor pattern, not `auditEvent`). HA enable / promote / demote events are operational topology, NOT config rollback candidates. **Out of surface, (C-topology).**

---

## 5. Category groups (per the brief)

The brief asked for four explicit categories. After the triage:

### Category A — Clear config changes that SHOULD be versioned (already correct)

All 26 handlers in the policy / rules / blocklist / rewrite / SSL bypass / DPI / file-block / IP filter / rate limit / PAC families — **all already call `saveConfigVersion`**. The one exception is `apiBlocklistMode` (the tiny first case below). No new handlers need to be added to this category.

### Category B — Genuine gap (in rollback surface, missing `saveConfigVersion`)

**Exactly one entry: `apiBlocklistMode` POST at `ui_policy.go:179-180`.** `bl.SetMode` is captured (`BlocklistMode` at `:64`) and applied (`:336-338`); the handler is part of the same file and same store family as `apiBlocklist` add/remove which already call `saveConfigVersion`. The omission is a one-line gap.

### Category B′ — Adjacent struct fields not wired to capture/apply (gray zone)

Six fields in `configBackup` struct, populated by export/import but NOT by `captureConfigBackup` / `applyConfigBackup`:

- `RateLimitExempt`
- `AlertWebhooks`
- `BlockPageHTML`
- `UpstreamProxies`
- `ConnLimitEnabled` / `ConnLimitMaxPerIP`

Affected handlers: `apiAlertWebhooks` (3), `apiBlockPage`, `apiUpstreamProxies`, `apiConnLimit`. The "Finding 10.3" comments suggest an in-progress surface extension. **Decision required:** complete the extension (add to capture/apply) OR remove these fields from the struct. Not a unilateral fix; needs design discussion.

### Category C — Outside rollback surface; should NOT have `saveConfigVersion`

(C) = persistent state but not in surface; (C-topology) = operational topology where rollback is conceptually wrong; (C-runtime) folded into Category E below.

Handlers covered: blocklist feed config (2), blocklist exceptions (2), URL categories (5 — P6.1 UC-4), file profiles (3), YARA settings + rules + rule files (4 — P6.2 SC-1), scan exclusions + DPI bypass (2 — SC-1), OCSP toggle, syslog config (2), session timeout, OTLP (2), bandwidth policies (2), node groups (2), cluster labels, cluster drain.

**Decision:** these should NOT be added to the rollback surface unilaterally. Each requires extending `captureConfigBackup`/`applyConfigBackup` to be useful AND requires a design call on whether rolling back is operationally correct. Most are operational topology where rollback is conceptually wrong.

### Category D — Security-sensitive state where rollback may be dangerous

These mutations exist on disk but rolling back to a prior version would create a **security regression**:

- `apiCARotate` (Root CA rotation) — rolling back restores the pre-rotation CA
- `apiCertsUpload` (MITM / UI) — rolling back restores pre-upload certs
- `apiClusterCA` (cluster CA import) — same
- `apiClusterRevoke` (node revoke) — un-revokes a node
- `apiAuthPasswordChange` — **currently has `saveConfigVersion`** but mutation isn't captured; if it WERE captured, rollback would restore the OLD password hash
- `apiAuthUsers` (create / delete) — rollback could lock out the only admin
- `apiSetup` complete (first-time admin password)
- `apiSettings session_secret` — rolling back re-exposes prior HMAC key
- `apiSettings auth` (UI admin password) — same as password_change
- `apiSettings unauth_mode` toggle — silent auth posture flip
- `apiSettings ui_allow_ips` — could lock out admin
- `apiSettings metrics_token`
- `apiIdP*` — rolling back IdP could lock out admins
- `apiUpdate registry settings` — could revert credentials
- `cdr.instance.revoke_rpc` — un-revokes an RPC instance

**Decision:** do not add `saveConfigVersion` to any of these. For the existing `auth.password_change` `saveConfigVersion` call, **remove it** as part of a small security follow-up PR.

### Category D′ — Currently has `saveConfigVersion` but outside surface (misleading bug class)

Three handler groups call `saveConfigVersion` but their mutations are NOT in the rollback surface — the calls create version entries that don't restore the mutated state:

- `apiCategoryGroups` (add/update/delete) — `globalCategoryGroups` not captured
- All six `cdr.*` mutations in `cdr_ui.go` — CDR state not captured; the file header explicitly documents the expectation
- `apiSettingsNetwork` at `ui_config.go:867-870` — network settings not in surface

**Decision:** these are real correctness bugs (the version log lies about what's reversible) but the fix has two possible directions:
1. Remove the `saveConfigVersion` calls — restores honesty, narrows the surface.
2. Extend `captureConfigBackup`/`applyConfigBackup` to include these stores — preserves the documented behavior, widens the surface (touches every cluster sync handler too — `ConfigSnapshot` carries `CategoryGroups`).

Direction 2 is the bigger design discussion (probably right for category-groups since they parallel URL categories; less obvious for CDR and Network settings).

### Category E — Runtime-only actions / events; versioning inappropriate

Handlers covered: feed sync triggers (2), YARA reload, scan cache evict/clear (2), CA cache clear, CA rotate-requested (confirmation token issue), log-level update, auth events (5: lockout, totp_fail, login, login_fail, logout), config export (read-only), update apply/rollback (binary lifecycle, not config), cluster update start (rolling-update lifecycle).

**Decision:** these legitimately do NOT call `saveConfigVersion`. The audit-event trail is the appropriate observability tier. No follow-up needed.

---

## 6. The "tiny, non-controversial first case" per the brief

**`apiBlocklistMode` POST at `ui_policy.go:179-180`** — the only Category B entry. The fix is a single line:

```go
bl.SetMode(body.Mode)
auditEvent(r, "blocklist.mode", body.Mode, "")
saveConfigVersion(sessionAdmin(r), "blocklist.mode")  // <-- add
```

**Why this is tiny and non-controversial:**

1. `BlocklistMode` is in the rollback surface (`configversion.go:64` capture, `:336-338` apply — verified).
2. Sibling handlers in the same file (`apiBlocklist` add / remove at `:113, :139, :150`) already call `saveConfigVersion` for the same store. The omission is structurally inconsistent.
3. No design questions: rolling back the blocklist mode is the same semantic as rolling back blocklist entries — already supported.
4. One-line addition, no struct changes, no new tests required (existing `TestSaveConfigVersion_*` covers it).

This is the only triage outcome where a unilateral fix is appropriate. **Recommended as a separate, single-line PR** per the brief's "split the tiny first case" instruction.

---

## 7. Other recommended follow-ups (DO NOT bundle into this PR)

Per the brief: "Do not implement fixes in this PR." The list below is a sequencing recommendation only; each item is its own design discussion + PR.

1. **Blocklist.mode tiny first case** — single line, see §6. Owns no design questions.

2. **Remove `saveConfigVersion` from `apiAuthPasswordChange` (`ui_auth.go:295`)** — security-sensitive misleading call. Two-line fix (remove the line + add a comment explaining the rollback exclusion). Pairs naturally with a small security-hardening PR.

3. **Decide D′ direction** — design call: remove the `saveConfigVersion` calls from `apiCategoryGroups` (3) + all `cdr.*` (6) + `apiSettingsNetwork` (1), OR extend the rollback surface to include these stores. Direction 1 is faster and safer; direction 2 is more invasive and needs paired changes to `ConfigSnapshot` for HA replication symmetry.

4. **Decide B′ direction** — design call: complete the `AlertWebhooks` / `BlockPageHTML` / `UpstreamProxies` / `ConnLimit*` / `RateLimitExempt` extension started under "Finding 10.3", OR remove those fields from the struct. Independent of #3.

5. **P6.1 UC-4 (URL categories)** — extending the rollback surface to include `catStore` requires paired changes to capture/apply AND adds versioning to all 5 `apiURLCat*` handlers. Group with #3 if direction 2 is chosen there.

6. **P6.2 SC-1 (scanner config)** — extending to YARA settings / rules + scan exclusions + DPI bypass is the largest single addition; should be its own design discussion.

7. **P6.3 CA-1 / CA-related handlers** — explicitly DECIDE these are out-of-surface and document it (mirror of how `apiScanCache` is documented as transient). Not a code change; a comment + a row in the doc.

8. **P6.4 CL-8 (cluster admin)** — same as #7; cluster-topology mutations are explicitly out-of-surface. Document.

---

## 8. No unresolved VERIFY / UNCERTAIN markers

Every classification in §4 is grounded in:

- Line-numbered grep evidence (provided)
- Direct reading of `captureConfigBackup` (`configversion.go:59-79`) and `applyConfigBackup` (`:325-388`)
- Direct reading of the `configBackup` struct (`ui_policy.go:620-643`)

No "probably". No "looks like". The Category D / D′ designations are facts (verified by absence of corresponding fields in capture/apply), not guesses about intent.

---

## 9. What this PR did NOT do (deliberate)

- No production code changes.
- No `saveConfigVersion` calls added or removed.
- No `captureConfigBackup` / `applyConfigBackup` surface extension.
- No HA redesign.
- No metrics.
- No auth / session / TOTP changes.
- No broad config framework refactor.
- No "fix the misleading calls" — Category D′ requires a design decision that is out of triage scope.
