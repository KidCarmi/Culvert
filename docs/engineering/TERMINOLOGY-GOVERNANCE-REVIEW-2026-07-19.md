# Culvert Language & Terminology Governance Review — 2026-07-19

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Two waves of parallel concept-cluster audits against the tree at `6349722`, following
> up on `TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-16.md` (baseline `739bf51`). Wave 1 re-verified the
> five clusters the prior four reviews have already covered (auth/session/RBAC, SSL-inspection/
> decryption/autoexclude, cluster CP-DP/HA, config versioning/export/rollback, release catalog/
> maintenance agent) to confirm no regression. Wave 2 targeted the ~204 commits that landed *after*
> the 07-16 review and have never been through a governance pass: the TAC supportability appliance
> framework (M1–M4), PAC traffic-steering profiles, the ADR-0011 `decryptobs` observability slice,
> and the PR3 traffic-log destination-privacy feature.
> **Companion change:** six zero-risk, copy/doc/comment-only fixes ship with this review (see
> "Fixed in this change"). No REST route, JSON field, CLI flag, config key, audit-event name, or
> exported Go identifier was renamed.

---

## Executive Summary

Wave 1 found nothing new — every cluster the 07-07 through 07-16 reviews already certified clean
(or already tracked as an open, sized finding) still holds. Wave 2, covering genuinely new surface
area that has never been audited, surfaced six real findings: four small enough to fix in this
pass, two sized for a dedicated follow-up (consistent with how T-9 through T-12 continue to be
handled).

**Terminology Health Score: 8.5 / 10** (unchanged from 07-16 — the new-code findings this pass are
exactly the kind of early drift a five-day-old feature is expected to accumulate before its first
governance pass, not a regression in already-reviewed territory; two are genuinely new medium-risk
items requiring a dedicated PR, matching the standing T-9/T-11/T-12 backlog rather than moving the
score).

**Fixed in this change (all copy/comment/doc-only, zero compatibility risk):**
- **T-13 — "SSL inspection" vs "TLS inspection" self-contradiction within `static/index.html`.**
  The DIRECT-bypass-inventory panel, its publish-confirmation dialog, the rule-summary renderer, and
  the SSL-bypass-add dialog each independently drifted to "TLS inspection"/"TLS inspected" even
  though the surrounding screen (panel title "SSL Inspection Bypass", dropdown "SSL Action", dialog
  title "Add SSL-inspection bypass") and the underlying field (`sslAction`) all say "SSL." Normalized
  five strings to "SSL" to match each screen's own established term (`docs/design/PRODUCT-TERMINOLOGY.md`
  already permits "SSL inspection acceptable; be consistent **per screen**" — the bug was a screen
  disagreeing with itself, not the SSL/TLS choice itself). README/enterprise docs' own "TLS
  Inspection" document-level branding is untouched — that's a separate, larger, deliberately-deferred
  question (see T-13 residual below).
- **T-14 — "backup" wording leaking into the config export/import surface.** The GUI's own Config
  Export panel explicitly tells operators *not* to confuse config export with disaster-recovery
  backup ("for full disaster-recovery backup/restore ... see the `cli` service"), yet the import
  preview renderer and two route-registration comments called the exported JSON a "backup" anyway.
  Reworded to "exported"/"export" in `ui_config.go` and `static/index.html` — comments and copy only,
  no field/route renamed.
- **T-19 — "proxy pool" now named two unrelated failover chains.** The new PAC steering-profile
  feature's GUI section "Proxy Pools" (client-facing `PROXY a; PROXY b` chains) landed using the same
  everyday phrase the pre-existing Support Diagnostics card already used, informally, for Culvert's
  own server-side upstream-egress pool. Renamed the Diagnostics card's two strings to "upstream proxy
  chain" (matching its own panel title, "Upstream Proxies") to free "Proxy Pool" as PAC's
  unambiguous term — GUI copy only, no `internal/upstream` or `internal/pac` identifier touched.
- **T-20 — the predicted "fourth Profile" landed with no glossary entry.** The 07-16 review's own
  soft finding said a fourth "Profile" concept (beyond file/decryption/CDR profiles) would be worth a
  glossary callout "if the schema grows a fourth ... concept." The new PAC "steering profile" is
  exactly that concept, and it arrived with no entry in `docs/design/PRODUCT-TERMINOLOGY.md`. Added
  two rows: **Steering profile** and **Proxy pool (PAC)**, the latter cross-referencing the T-19 fix
  so the "Upstream Proxies" vs. "Proxy Pools" distinction is written down once, canonically.
- **Doc gap — `diagnose etcd` missing from the one runbook operators use.** The verb is shipped
  (`diagnose.go:1255`, audited as `diagnose.etcd`), but `docs/operator/support-bundles-and-diagnostics.md`
  §7's verb table enumerated the other eight `diagnose` verbs and not this one — an operator
  correlating a fencing-lease incident via the documented API surface would not know it exists.
  Added the missing table row.
- **ADR-0011 doc/code drift — `dec_fail_reason`.** §2.1 of `docs/adr/0011-decryption-observability.md`
  still listed a `dec_fail_reason` field as shipped; the ADR's own red-team corrections section
  (§ near the end) had already flagged it as underspecified and named two possible resolutions. The
  actual `DecryptionBlock` (`internal/logstore/logstore.go`) took resolution (a) — no `FailReason`
  field exists, only `FailStage`/`FailCategory` — but §2.1's table was never updated to match. Edited
  the ADR text (table row removed, corrections section marked resolved) so the document matches
  shipped behavior; this is documentation only, `internal/logstore`/`internal/decryptobs` are
  untouched.

**Documented, not fixed this pass (sized for a dedicated follow-up, same bar as T-9/T-11/T-12):**
- **T-16 — ADR numbering collision:** two independent ADR sequences (the core proxy/security track
  and the newer Supportability-framework track) both claimed numbers 0008–0011, and both meanings are
  live in active cross-references across 40+ files.
- **T-17 — the traffic-log destination-privacy config key/route still says "decryption" for a
  feature that now redacts every sink**, not just decrypted sessions.
- **T-18 — "seal" now names two different cryptographic operations** (local KEK envelope vs.
  one-way NaCl sealed-box to a third party) with no lexical signal distinguishing them.
- **T-13 residual — "SSL inspection" vs. "TLS inspection" as the product's *document-level* brand
  choice** (README, `docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md` vs. everything else). This is a
  bigger, more visible call than the in-screen fix made in this pass and is left for a deliberate
  decision rather than a same-day rename of customer-facing document titles.

See "Findings" below for full detail on all six, including the two carried-over already-open items
this pass re-confirmed still open (T-9, T-11, T-12).

---

## Wave 1 — Re-verified clean (no new drift since 2026-07-16)

Independently re-audited and confirmed still holding: authentication/session/RBAC/lockout/TOTP/IdP
naming (including the G-1 `DisplayName()` fix); `defaultAuthOutcome`/`UnauthMode` containment;
decryption-profile vs. autoexclude vs. SSL-bypass naming (aside from the in-screen T-13 fix above);
CP/DP/enrollment/node-group/fencing-lease naming; the `ConfigSnapshot`/`configBackup`/numbered
config-version three-surface split (aside from the T-14 "backup" copy fix above); release-catalog
vs. release-index naming, verify-mode constants, and the "host agent" → "Maintenance Agent" cleanup
(G-2). T-9, T-11, and T-12 remain open, unchanged in scope from the 07-16 review (see below).

## Wave 2 — New territory audited this pass (~204 commits since `739bf51`)

TAC supportability appliance framework (M1–M4: diagnose verbs, sealed export, recipient registry,
support-bundle retention); PAC traffic-steering profiles (compilation, simulation, publish, DIRECT
confirmation); ADR-0011 `decryptobs` (`DecryptionOutcome`/`Entry.dec`); the PR3 Option B traffic-log
destination-privacy feature (keyed HMAC). Findings T-13 through T-20 below are new to this pass.

---

## Findings

### T-13 — "SSL inspection" vs "TLS inspection" (FIXED in-screen; residual documented)
- **Business concept:** the TLS MITM decrypt-and-inspect feature (`PRODUCT-TERMINOLOGY.md`:
  "Inspection | TLS MITM (SSL inspect)").
- **Current names:** code/API/GUI panel titles consistently say "SSL" (`healthcheck.go` JSON field
  `ssl_inspection`, `policy.go` `SSLAction`, GUI panel "SSL Inspection Bypass", dropdown "SSL
  Action"). README and the enterprise deployment docs consistently say "TLS Inspection"
  (`README.md`, `docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md`,
  `docs/enterprise/ENTERPRISE-DEPLOYMENT-GUIDE.md`). Within `static/index.html` itself, four separate
  strings had drifted to "TLS inspection"/"TLS inspected" despite sharing a screen with "SSL"-titled
  controls.
- **Why this matters:** `PRODUCT-TERMINOLOGY.md` already licenses per-screen SSL/TLS choice ("SSL
  inspection acceptable; be consistent per screen") — the defect was internal inconsistency *within*
  one screen/dialog, which the glossary rule does not permit, not the SSL-vs-TLS branding choice
  itself.
- **Fix (this pass):** five in-GUI strings (DIRECT-bypass-inventory copy, its publish-confirmation
  dialog, the rule-summary "inspected" chip, the SSL-bypass-add dialog title/body/comment) normalized
  to "SSL" to match their own screen's established term. Zero risk — copy only.
- **Residual (not fixed, documented for a dedicated decision):** whether the *product's* customer-
  facing document brand should be unified to one term across README/enterprise docs vs. code/API/
  in-app copy is a bigger, more visible call (renaming a published doc title like
  "TLS Inspection Deployment Guide" has real external-link/bookmark cost) than an in-app string fix,
  and is out of scope for a same-day pass. **Priority:** Low (in-screen fix closes the actual
  self-contradiction; the document-brand question is cosmetic, not confusing in context).
  (The identical duplicated phrase in `internal/pac/inventory.go`'s package comment was normalized
  the same way, for the same reason.)

### T-14 — "Backup" language leaking into config export/import (FIXED)
- **Business concept:** the config-only JSON produced by `/api/config/export`/`/api/config/import`.
- **Current names before fix:** the GUI panel's own disclaimer already distinguishes config export
  from disaster-recovery backup ("for full disaster-recovery backup/restore of `/data`, see the
  `cli` service"), but `ui_config.go` route comments (`// GET — download backup JSON`, `// POST —
  restore from backup JSON`) and the import-preview renderer (`· backup exported ...`, `"in this
  backup would change"`) called the exact same export/import feature a "backup" — the word its own
  UI copy tells the operator this is *not*.
- **Fix:** reworded six strings/comments to "export"/"exported" — two `ui_config.go` route comments,
  two `ui_config.go` audit-event detail strings (`"from backup exported %s"` → `"from config exported
  %s"`, in both the preview and commit handlers), and two `static/index.html` template strings. No
  JSON field, route, or handler renamed; `b.ExportedAt` (the Go field feeding these strings) is
  untouched — that rename is the separate, already-open T-9.
- **Priority:** Low. **Migration risk:** none — comments and rendered/audited copy only.

### T-16 — ADR numbering collision: 0008–0011 claimed by two independent decision tracks (new — documented, not fixed)
- **Business concept:** the unique identifier for an Architecture Decision Record — the mechanism
  `CLAUDE.md`'s own "Engineering governance" section says derives ADR practice's mandate.
- **Current names:** `docs/adr/` holds two files at each of 0008, 0009, 0010, and 0011 — one from
  the original proxy/security track (`0008-decryption-exclusion-spoofable-evidence.md`,
  `0009-client-cert-origin-fail-open-detection.md`, `0010-decryption-exclusion-runtime-tunables.md`,
  `0011-decryption-observability.md`, ratified 2026-07-16) and one from the newer Supportability-
  framework track (`0008-supportability-framework-collector-model.md` through
  `0011-support-export-consent-and-trust.md`, all dated 2026-07-12, continuing on to unique numbers
  0013–0017 with 0012 unused as an ADR number — it is a *different* document class,
  `docs/support/rfc/0012-cloud-first-support-analysis.md`, an RFC not an ADR).
- **Why this is real drift, not a theoretical collision:** both meanings are actively cross-
  referenced by number throughout the tree today. `ADR-0008` means "decryption-exclusion spoofable
  evidence" in `autoexclude_resolve.go`/`autoexclude_test.go` but "supportability framework" in
  `docs/support/rfc/0012-cloud-first-support-analysis.md`. `ADR-0009` means "client-cert-origin
  fail-open" in `autoexclude_rescue_test.go`/`store.go` but "source-side redaction" in four
  `docs/support/*.md` files. `ADR-0010` splits the same way between `internal/autoexclude/` and
  `docs/support/SUPPORTABILITY-ARCHITECTURE.md`. `ADR-0011` is the most heavily used identifier in
  the whole repo (40+ files — nearly every `decryptobs`/decryption-observability file references it)
  but the support track's own `SECURE-UPLOAD-ARCHITECTURE.md` cites "ADR-0011 (export/consent)" for
  a completely different decision. A reader following either track's own cross-references (e.g.
  ADR-0008's "Relates to: ... ADR-0011 (export/consent)") into `docs/adr/0011-*.md` has a 50/50
  chance of opening the wrong file by name alone.
- **Why it is NOT fixed in this pass:** renumbering touches 40+ files' worth of prose cross-
  references (not a single mechanical identifier — each hit needs a human/agent to confirm *which*
  of the two meanings that specific reference intends before changing its number), which crosses the
  same "needs a deliberate, reviewed pass rather than a same-day background rename" bar the 07-16
  review used for T-9/T-10's on-disk/wire surfaces.
- **Recommendation:** renumber the Supportability-framework track's four colliding files (`0008-`,
  `0009-`, `0010-`, `0011-support-*.md`) to the next unclaimed contiguous block (`0018`–`0021`,
  keeping them ahead of the track's own already-unique `0013`–`0017`) rather than touching the
  original, more heavily-referenced decryption-track ADRs. Update the support track's own internal
  "Relates to" cross-references and the handful of files that cite the support meaning by number
  (`docs/support/rfc/0012-*.md`, `docs/support/COLLECTOR-CONTRACT.md`, `REDACTION-MODEL.md`,
  `SUPPORTABILITY-ARCHITECTURE.md`, `SUPPORTABILITY-THREAT-MODEL.md`, `SECURE-UPLOAD-ARCHITECTURE.md`).
  Leave the decryption-track files' numbers untouched (lower blast radius, more call sites).
- **Priority:** Medium (real risk of a reader/agent citing or acting on the wrong decision record;
  no runtime/functional impact — this is documentation-identifier collision only).
  **Estimated PR size:** Medium (renumber 4 files + update ~6 cross-referencing docs; no code touched).
- **Resolution (2026-08-23, PR #1203):** Fixed per the recommendation above, with two adjustments
  found only during review. First: the original target block (`0018`–`0021`) had since been claimed
  twice over — once by `0018-openapi-contract.md`, and again (unnoticed until a reviewer flagged it)
  by `docs/support/rfc/0019`–`0022`, an exploratory infra-ops RFC series that self-titles its headers
  `# ADR-0019` through `# ADR-0022` despite living outside `docs/adr/` — confirming this program's own
  "repository-wide" numbering discipline (see ADR-0025's numbering note) has to be checked against
  `docs/support/rfc/` too, not just `docs/adr/`. The Supportability-framework track's four colliding
  files were renumbered a second time, to the next block confirmed clean against every `# ADR-NNNN`
  header in the repo AND against all open PRs at landing time: `0008` → `0028`, `0009` → `0029`,
  `0010` → `0030`, `0011` → `0031`. Second: the initial pass missed two more support-track citations
  outside `docs/` — `CONTRACTS-OWNERSHIP.md` (ADR-0011) and `roadmap/PAC-EXCEPTION-INTELLIGENCE.md`
  (ADR-0009/0010) — also flagged by the same reviewer and fixed. Complete list of files updated: the
  four renamed ADRs' own headers/"Relates to" lines, two other ADRs (`0014-*.md`, `0016-*.md`), six
  `docs/support/*` design docs (including the `docs/support/SUPPORTABILITY-ARCHITECTURE.md:6` summary
  line, which cited the range by number rather than by link and was easy to miss), the two files just
  named, and the `/P6`-qualified code comments in `support_upload.go`, `support_telemetry_config.go`,
  their tests, and `internal/redaction/class.go`. The decryption-track files (`0008`–`0011`
  decryption-exclusion/observability) were left untouched, per the recommendation. **Noted but not
  fixed in this pass** (separate concern, needs its own blast-radius analysis): `ADR-0018` is now
  *also* double-claimed — `docs/adr/0018-openapi-contract.md` (30+ call sites) vs.
  `docs/support/rfc/0018-ai-receives-normalized-evidence.md` (self-titled `# ADR-0018`, cited by that
  number in `SUPPORTABILITY-THREAT-MODEL.md` and `TAC-CLOUD-ARCHITECTURE.md`) — same defect class,
  should get its own T-16-style entry.

### T-17 — Traffic-log destination-privacy config key still says "decryption" after its scope expanded (new — documented, not fixed)
- **Business concept:** the destination-privacy (pseudonymization) toggle for traffic-log entries.
- **Current names:** before PR3 Option B, the toggle only redacted `dec.host`/`dec.sni` on decrypted
  sessions. `9f3176a` ("feat(privacy): traffic-log destination privacy via keyed HMAC (PR3 Option
  B)") expanded it to redact `Host`+`URI`+`dec.*` at **every** log sink — plain HTTP and
  `TUNNEL_CLOSED` entries included, not just decrypted ones — but every identifier stayed
  decryption-scoped: `AdminSettings.DecryptionRedactHosts` (`admin_settings.go`), `decRedactHostsFlag`/
  `decRedactHosts()`/`setDecRedactHosts()` (`decryption_redaction.go`), and the route
  `GET/PUT /api/decryption/redaction`.
- **Why this is real drift:** the feature's own design doc, `roadmap/PR3-privacy-posture-v2-DECISION.md`,
  explicitly considered and named this exact problem — "Option A — rename the setting to say what it
  does" — as the honest alternative to Option B (expand scope, keep the name), and the team chose
  Option B without the rename. The GUI label ("Pseudonymize destination in traffic logs") and the
  API's own `scope`/`scope_fields` response value (`"traffic_destination"`) already describe the true,
  now-global scope correctly — only the config key, JSON field, admin-settings field, and route path
  still say "decryption," which an engineer or integrator reading just the config/API surface (not
  the GUI label) would reasonably read as decryption-only.
- **Why it is NOT fixed in this pass:** `decryption_redact_hosts` is a persisted `admin_settings.json`
  field and `/api/decryption/redaction` a live API route — the same external-contract bar that
  deferred T-11/T-12. A rename needs the same alias-on-read/canonical-route-plus-deprecated-alias
  treatment those findings recommend, not a same-day rename.
- **Recommendation:** add canonical `traffic_redact_destination`-style config/route names as aliases
  alongside the existing `decryption_redact_hosts`/`/api/decryption/redaction` (mirrors the T-10 DPI
  precedent exactly — that fix is a template to reuse here), in a dedicated follow-up.
- **Priority:** Medium (real config/API-vs-behavior mismatch for anyone not reading the GUI label;
  correct today only because the GUI label and API `scope` field already say the true thing).
  **Estimated PR size:** Medium (config key alias + route alias + one admin-settings field, plus
  regression tests mirroring `TestLoadFileConfig_DPIKeyCanonicalWins`).

### T-18 — "Seal" now names two unrelated cryptographic operations (new — documented, not fixed)
- **Business concept:** encrypting a secret so only an authorized party can read it. Two genuinely
  different operations now share the verb.
- **Current names:** `internal/secret.Seal`/`Open`/`Sealed` (pre-existing) is a **symmetric envelope
  under a locally-held KEK** — the appliance itself can always decrypt it later (used for CA keys, DP
  node keys, CDR client keys, backups). The new (M4) `internal/sealbox.Seal` is a **one-way NaCl
  sealed-box to a third party's public key** — the appliance that sealed it can *never* decrypt it
  again. Both are surfaced as "Seal"/"Sealed": `support_export.go`'s `sealbox.Seal(...)` call, the
  audit event `support.bundle.download_sealed`, and a GUI button literally labeled "Seal"
  (`static/index.html`), sitting alongside the pre-existing, differently-behaved
  `keySealed.WithPlaintext` local-KEK vocabulary.
- **Why this is real drift:** these are not two names for one concept — they are one name covering
  two operations with opposite trust properties (recoverable-by-us vs. never-recoverable-by-us),
  which is exactly the "different business concepts sharing one name" failure mode this review
  charter exists to catch. The `internal/sealbox` package's own header comment shows the author was
  aware of the collision (contrasts the magic bytes against the "passphrase envelope") but did not
  rename the verb to resolve it. An operator or support engineer reading "Seal" in the GUI or grepping
  logs for `sealed` has no lexical signal which security property applies.
- **Why it is NOT fixed in this pass:** while the code footprint is genuinely small (2–3 call sites,
  all within this one M4 slice), a rename touches an exported Go API (`internal/sealbox.Seal`/`Open`),
  a GUI label, and an audit-event string together — a coordinated three-surface change is better done
  as its own reviewed, tested PR than folded into a terminology-sweep commit, especially given the
  security-sensitivity of getting the two operations' framing right.
- **Recommendation:** rename `internal/sealbox.Seal`/`Open` to something that names the trust
  property directly (e.g. `EncryptToRecipient`/`OpenWithRecipientKey`), keep the on-disk magic bytes
  (`CVRTSB01`) unchanged (format identifier, not the API name), and relabel the GUI button "Encrypt
  for recipient" (or similar) instead of bare "Seal." This is genuinely cheap given the current call-
  site count, and cheapest to do now, before the M5/M6 upload path (noted as future work in
  `docs/support/`) adds more callers.
- **Priority:** Medium (security-relevant naming collision on a young feature — low cost to fix now,
  rising cost the longer it calcifies). **Estimated PR size:** Small (package rename + 3 call sites +
  1 GUI label + 1 audit-event string, with existing tests re-run for behavior parity).

---

## Carried over, still open (re-confirmed this pass, unchanged from 07-16)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. On-disk format + parity-test surface; still correctly deferred. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Touches `/api/default-action` + `admin_settings.json` + config-version/export surfaces. |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Confirmed by this pass's release-catalog re-audit — also newly notes a related, smaller "trust key" (Go type `TrustKey`, env `_TRUST_KEYS`) vs. "trust root" (prose in `release_wiring.go` comments and `CLAUDE.md`) wording inconsistency; judged a soft/no-action item on its own (generic PKI usage of "root of trust," not a competing identifier for the same object), noted here only in case it compounds with T-12's eventual fix. |

## Soft findings — no action recommended

- **Config-version rollback's `saveConfigVersion` action string breaks the `domain.action` convention**
  (`configversion.go`: `fmt.Sprintf("rollback to v%d", req.Version)` vs. every other call site's
  dot-identifier form) — intentional: the human-readable sentence is rendered verbatim in the Config
  Versions table (`static/index.html`), while the paired `auditEvent` call already uses the
  conventional `"config.rollback"`. No change recommended.
- **"Rollback" reused for the TOTP counter-regression guard** (`docs/operator/docker-compose-backup-restore.md`,
  `--allow-counter-rollback`) — same word, unrelated concept, but well-scoped to its own flag name
  with no adjacent config-version "rollback" in the same document to conflict with. Not drift.
- **"Fail-close" (enum literal, `OnInspectError`) vs. "fail-closed" (general security-posture
  adjective, OCSP)** — different subsystems, near-identical spelling. Cosmetic; not worth a rename.
- **"TAC" is never expanded anywhere in the tree** (no file spells out "Technical Assistance Center").
  No competing name exists — just an undefined abbreviation. Informational only.
- **The Supportability framework has an inert alternate name, "CSF"** (`docs/support/SUPPORTABILITY-ARCHITECTURE.md`
  only) that never appears in code, GUI, or the operator runbook. Not actively confusing; worth
  dropping only if that design doc is ever promoted to shipped-status documentation.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-16 (new) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0018–0021) and their cross-references | Low (docs only, but 40+ files to check meaning before touching any) | Medium |
| Medium | T-17 (new) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped canonical names (T-10 DPI pattern) | Medium (config + API + admin-settings field) | Medium |
| Medium | T-18 (new) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI button; rename the audit-event string | Low (young feature, 2–3 call sites) | Small |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low (GUI copy) / Medium-large (schema) | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`; rename packaging/config comments | Medium (agent wire protocol, rolling-update compat window) | Medium |
| Low | T-13 residual (new) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with the in-app "SSL" terminology | Low (doc titles only, but externally linked) | Small |

T-13 (in-screen half), T-14, T-19, T-20, the `diagnose etcd` doc gap, and the ADR-0011
`dec_fail_reason` doc/code mismatch are fixed in this change and require no further action.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed five previously-audited clusters are
still clean, fixed six zero-risk copy/doc issues found in the ~204 commits of new feature work since
the last review (SSL/TLS in-screen self-contradiction, "backup" leakage into config export, the
"proxy pool" collision's pre-existing half, the predicted fourth-Profile glossary gap, a missing
`diagnose etcd` doc row, and an ADR/code mismatch), and surfaced two new Medium-priority findings
(T-16 ADR-number collision, T-17 privacy-toggle scope/name mismatch) plus one already-partially-
covered Medium finding (T-18 "seal" collision) — all three sized for a dedicated follow-up rather
than a same-day fix, consistent with how T-9/T-11/T-12 continue to be handled. No cosmetic or
preference-driven renames were proposed or made in this pass; every fix shipped here closes a
genuine self-contradiction or a documented trigger condition from a prior review, not a stylistic
preference.
