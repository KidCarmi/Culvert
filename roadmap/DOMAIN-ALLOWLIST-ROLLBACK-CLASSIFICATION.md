# Domain Allowlist (threat-feed) — Rollback Classification Spec

**Status:** discovery / classification only. No production behavior changes in
this PR. No capture/apply changes, no `saveConfigVersion` changes, no
ConfigSnapshot/HA changes, no handler changes.

**Question:** how should the threat-feed **domain allowlist**
(`apiDomainAllowlist` / `globalThreatFeed.domainAllowlist`) be classified with
respect to config-version rollback? It was previously (incorrectly) bucketed
under the scanner SC-1 "Category A" group and then removed; this spec gives it
a correct, standalone classification.

**Scope guard:** this is *only* about the threat-feed domain allowlist. It does
**not** touch CA/cluster/security-handler work, and it does not propose
implementation.

---

## 1. Current lifecycle map

All claims cite exact code paths.

| Aspect | Finding |
|---|---|
| **Owning store/global** | `globalThreatFeed` (`*ThreatFeed`, threatfeed.go:64). The allowlist itself is the in-memory set `domainAllowlist map[string]bool` (threatfeed.go:55). |
| **Persistence file** | The **shared threat-feed DB file** (`tf.dbPath`), as `feedDB.DomainAllowlist []string` (threatfeed.go:46, **`omitempty`**). `saveToDisk` writes the whole `feedDB` — auto-synced URLs/Domains **and** the allowlist together (threatfeed.go:416–440, fsync-hardened). Seeded with `defaultDomainAllowlist` (26 hosting domains: github.com, drive.google.com, s3.amazonaws.com, …) on first run / when persisted empty (threatfeed.go:89–93, 223). |
| **Admin handler(s)** | `apiDomainAllowlist` (ui_security.go:534), route `/api/security-scan/feeds/domain-allowlist` (ui_security.go:1237). `GET` = viewer (returns `DomainAllowlist()`); `PUT` = admin → `SetDomainAllowlist(body.Domains)` (full replace + auto-persist, threatfeed.go:255–270). |
| **`saveConfigVersion` today?** | **NO.** The PUT handler does not call it; mutating the allowlist creates no config-version snapshot. |
| **Audit behavior** | **NO `auditEvent`.** The PUT branch only emits `logger.Printf` (ui_security.go:557). `uiRoutes` metadata acknowledges this: the PUT method is `Mutating: true` but **not** `AuditExpected`, with Note `"no direct auditEvent observed (delegated)"` (ui_routes_meta.go:291). Confirmed: no `auditEvent` for the allowlist exists anywhere. (Audit gap — see §3.5.) |
| **ConfigSnapshot / HA** | **YES — on the HA surface.** Field `ThreatDomainAllowlist []string` (controlplane.go:104, `omitempty`). CP captures it `if globalThreatFeed.Enabled()` (controlplane.go:1689). DP applies `if snap.ThreatDomainAllowlist != nil { SetDomainAllowlist(...) }` (controlplane.go:1587–1590) — nil→skip, non-nil(incl `[]`)→replace+persist. Size-capped at `maxSnapDomainAllowlist = 10_000` and validated by `validateConfigSnapshot` (controlplane.go:151, 180). |
| **Rollback capture/apply/diff** | **NONE.** Absent from `configBackup` (ui_policy.go), `captureConfigBackup`, `applyConfigBackup`, and `diffConfigs` (configversion.go). It is **not** on the rollback surface today. |

**One-line summary:** the domain allowlist is **threat-feed-owned, persisted in
the feed DB, and distributed CP→DP via ConfigSnapshot** — it has a complete
ownership + distribution + persistence story that is entirely separate from the
config-version rollback subsystem.

---

## 2. Classification

Of the four candidate buckets:

- **Rollback surface** — ❌ NO. It is not stored in any config-version-captured
  store; it lives in the threat-feed DB. Adding it would create a *second*
  authority over state that already flows via HA ConfigSnapshot (see §3.1).
- **Runtime-only** — ❌ NO. It is persisted (feed DB) and HA-distributed; not
  ephemeral runtime state.
- **Threat-feed-specific separate surface** — ✅ This is the accurate
  description of where it lives (own DB + ConfigSnapshot field).
- **Documented out-of-(rollback)-surface** — ✅ This is the action: record that
  it is intentionally NOT on the config-version rollback surface.

**Decision:** classify the domain allowlist as **threat-feed-owned,
HA-distributed config, documented OUT of the config-version rollback surface.**
This is consistent with the SC-1 scanner triage, which already kept threat-feed
*mechanics* (feed sync, feed data) off the rollback surface — the allowlist is
the admin-managed sibling of that same subsystem and belongs with it, not with
the policy-style config that rollback versions. The earlier SC-1 "Category A"
bucketing was a mis-classification; this corrects it.

This mirrors the Finding 10.3 outcome for `AlertWebhooks`/`UpstreamProxies`:
a field that is real, persisted, and admin-managed but lives on a *different*
surface than config-version rollback, so it is documented off-surface rather
than wired into capture/apply/diff.

---

## 3. Hazards (why on-surface would be wrong, and adjacent risks)

### 3.1 Rollback × HA dual-authority conflict (decisive)
The allowlist is already authoritative via CP→DP ConfigSnapshot
(controlplane.go:1689 capture, :1587 apply). If it were *also* on the rollback
surface:
- On a **CP**, a config-version rollback would mutate the live allowlist; the
  next `ConfigSnapshot` push re-derives it from live state and propagates it to
  **every DP** — a rollback of one node silently rewriting the whole fleet's
  threat exemptions (surprising blast radius).
- On a **DP**, a local rollback would be **silently overwritten** by the next CP
  sync — rollback appears to work, then reverts. Ineffective and confusing.
Two authorities over one piece of distributed state is the core reason to keep
it single-sourced on the HA/threat-feed surface.

### 3.2 Security impact of restoring/erasing the allowlist
The allowlist **exempts domains from domain-level threat blocking**
(`DomainAllowlisted`, threatfeed.go:236; gate at threatfeed.go:342
`if !globalThreatFeed.DomainAllowlisted(host)`). A rollback that restored an
*old* allowlist could silently **re-exempt a domain that was deliberately
removed** because it began hosting malware — re-opening a threat hole as a side
effect of an unrelated config rollback. Conversely it could erase a
freshly-added exemption and over-block a legitimate platform. Allowlist edits
are security-sensitive and should not be swept along by unrelated rollbacks.

### 3.3 Persistence vs live-runtime mismatch (empty-allowlist quirk)
`feedDB.DomainAllowlist` is `omitempty` (threatfeed.go:46) and `loadFromDisk`
restores it **only `if len(db.DomainAllowlist) > 0`** (threatfeed.go:402),
otherwise it keeps the seeded defaults. So an admin who **explicitly empties**
the allowlist (`SetDomainAllowlist([])`) loses that intent on restart — defaults
re-seed. The store therefore does **not** honor a `[]`-means-empty contract,
which is exactly the contract the rollback surface depends on
(CategoryGroups/URLCategories/RateLimitExempt all rely on `[] = explicit wipe`).
Putting this field on the rollback surface would inherit a store that cannot
faithfully represent "empty," compounding the nil-vs-`[]` hazard rollback has
worked to eliminate. (Pre-existing threat-feed bug; see §5.)

### 3.4 HA empty-allowlist propagation gap
The same `omitempty` exists on the ConfigSnapshot field (controlplane.go:104):
an empty allowlist on the CP serializes as **omitted** → DP decodes `nil` →
`SetDomainAllowlist` skipped → DP keeps its own. So "empty" does not propagate
across HA either. Consistent with §3.3; another reason the field's "empty" state
is not faithfully modeled anywhere today.

### 3.5 Audit gap (adjacent, not rollback)
The PUT handler performs a security-relevant, admin-only mutation with **no
`auditEvent`** (ui_security.go:557; metadata Note at ui_routes_meta.go:291).
This is an observability gap independent of rollback classification. Flagged
here; **not** fixed by this spec.

---

## 4. Recommended direction & sequencing

**Direction:** Adopt the classification in §2 — domain allowlist is
threat-feed-owned / HA-distributed and **documented OUT of the config-version
rollback surface.** Do **not** add it to `captureConfigBackup` /
`applyConfigBackup` / `diffConfigs`. No rollback behavioral work is warranted;
the decisive dual-authority hazard (§3.1) and the security-side-effect hazard
(§3.2) make on-surface inclusion actively undesirable, not merely unnecessary.

**Sequencing (spec PR first; implementation only if later desired):**

1. **This spec PR** — records the classification and corrects the SC-1
   mis-bucketing. No code.
2. **Optional docs-only follow-up PR** (mirrors Finding 10.3 PR-1): a short
   comment on `apiDomainAllowlist` / a CLAUDE.md architecture note stating the
   allowlist is threat-feed/HA-owned and intentionally off the rollback surface,
   so a future maintainer does not re-bucket it. Recommended; tiny.
3. **Optional, separate, NOT bundled** — each its own small PR if pursued:
   - Add `auditEvent` to the PUT handler (§3.5 audit gap). Handler change —
     out of scope here.
   - Fix the empty-allowlist persistence/HA `omitempty` quirk (§3.3/§3.4) as a
     threat-feed correctness item — out of scope here, and orthogonal to
     rollback.

No implementation in this PR. Do not bundle with CA/cluster/security-handler
work or with the threat-feed audit/persistence items above.

---

## 5. Out-of-scope observations (logged, not addressed here)

- **Empty-allowlist not durable** (§3.3): explicit `SetDomainAllowlist([])`
  reverts to seeded defaults on restart and does not propagate across HA. A
  threat-feed persistence/semantics bug, separate from rollback.
- **Audit gap** (§3.5): mutating admin PUT with no `auditEvent`.
- **Shared DB file:** the admin-managed allowlist shares `feedDB` with
  auto-synced ephemeral feed data; any future "export the allowlist" feature
  should target the allowlist slice specifically, not the whole feed DB.
