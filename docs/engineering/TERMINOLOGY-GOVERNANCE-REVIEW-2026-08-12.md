# Culvert Language & Terminology Governance Review — 2026-08-12

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `bc67b7b`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 58 commits separate the two
> reviews, dominated by CHAOS-28 root-CA fail-closed/rotation-persistence hardening (`internal/ca/validity.go`,
> `ca_health.go`, the new CA-unusable/CA-persist-degraded GUI banners), CHAOS-47 follow-through (an MCP
> tenant-isolation window doc plus the `idp_unreachable` → `identity_backend_unreachable` legacy-event-name
> migration landing its own test), a `hostutil` fast-path ingress-dedup bound window, an
> attacker-provokable-LDAP-bind DoS gate (`auth_ldap.go`, CHAOS-47-adjacent), the `internal/mcpacceptance`
> authoritative-controls harness (QUAL-6.1), CHAOS-27 alert-storm dedup-window bounding, and a syslog
> panic-loss counter surfaced on the SIEM forwarding panel. Method: (1) diffed the actual cited
> lines/identifiers (not just file touches) for every one of the nineteen carried-over open findings — T-9,
> T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25 residual, T-29 through T-34, T-36, T-37, T-38, T-39
> — against every file each depends on; (2) ran a narrow, targeted follow-up check on the four genuinely new
> surfaces this window (the syslog `panics` counter, the CHAOS-27 dedup-eviction fields, the new CA-usability
> GUI banner's wire-field reads, and the LDAP-bind-DoS-gate naming) end-to-end from Go identifier through
> JSON field through GUI label through metric name; (3) ran three parallel general-purpose sweeps of areas
> the program had not recently covered in depth — GUI-label-vs-API-vs-config drift, audit/alert/metric-name
> drift, and CLI/env-var/doc drift — each instructed to cite exact file:line evidence and to stop rather than
> manufacture findings.
> **Companion change:** T-41 (new — the Root-CA PEM download had silently forked into two independent,
> byte-identical handler implementations behind two GUI buttons) fixed same-day, see Findings.

---

## Executive Summary

**All nineteen carried-over findings re-verified at the cited-line level; all nineteen are unchanged.**
Every finding whose dependent files were touched this window (`config.go` gained an unrelated CDR
fingerprint hex-validation error message; `static/index.html` gained the CA-usability banners, the syslog
panic-count display, the CHAOS-27 dedup-saturation display, and the already-fixed `identity_backend_unreachable`
GUI checkbox value from T-40) had the actual cited identifiers diffed, not just the file — none touched the
lines a finding depends on.

**Two new findings this pass.** **T-41** (new, fixed same-day): `/api/ca-cert` and `/api/ca/download` are
two independently-coded handlers (`apiCACert`, `apiCADownload` in `ui_security.go`) that produce the
byte-identical Root-CA PEM download, reachable from two different GUI panels ("Certificates" and "CA
Management") under two different button labels, with no alias relationship and no comment acknowledging the
duplication — unlike every other deprecated-route pair in this codebase (`/api/content-scan` → `/api/dpi`,
`unauth-mode` → `default-auth-outcome`), which are explicitly documented aliases pointing at one canonical
handler. A support engineer debugging a CA-download issue reported against one endpoint could miss that a
second, separately-maintained implementation exists. Fixed same-day: both handlers now share one
`writeCACertPEM` helper; both routes, both GUI buttons, and both response bytes are unchanged — this
collapses an accidental implementation fork, it does not migrate or remove a public route. **T-42** (new,
queued): `PolicyStore`'s admin audit-action verbs (`"policy.add"`/`"policy.remove"`, `ui_policy.go`) are the
one outlier among this codebase's full-CRUD (create/read/update/**delete**, ID-addressable) admin resources
— every sibling resource of the same shape (`category-group`, `decryption-profile`, `urlcat`, `fileprofile`,
`alert.webhook`, `idp`) uses `.create`/`.update`/`.delete`, and policy rules are themselves backed by Go
methods literally named `PolicyStore.Add`/`.Update`/`.Delete`. Not fixed this pass: policy is this
codebase's single highest-traffic admin resource, so its audit-action strings are a live compliance-log/SIEM
vocabulary — exactly the class of rename this program's own constitution says needs a recorded design
decision, not a drive-by fix (the same posture already taken on T-36/T-37's audit-token findings).

**No new findings met the evidence bar in the CLI-flag/env-var/YAML-key or the alert-event/metric-name
surfaces.** A dedicated sweep of CLI ↔ YAML ↔ doc naming found nothing beyond what T-29/T-30/T-31/T-17
(already open, re-confirmed unchanged above) already cover, and confirmed the one env var it flagged as a
"documentation gap" (`CULVERT_PUBLIC_IP` absent from CLAUDE.md's "Key Environment Variables" list) is not
drift — that list is a curated subset covering ~8 of this codebase's 103 `CULVERT_*` environment variables
(the ones with non-obvious runtime behavior), not an exhaustive index, so a healthy env var's absence from it
is not a finding. A dedicated sweep of the audit/alert/metric surface found the Prometheus metric and
`fireAlert` event-name catalogs clean (no two names for one trigger condition), but did surface one soft
finding (below): the request-log/stats "status" field is set to the literal `"OK"` at every production call
site (plain HTTP, SOCKS5, CONNECT-bypass, CONNECT-inspect), while three independent downstream consumers
(`store.go`, `internal/reqlog`, `internal/otlp/spans.go`) each carry a defensive `status == "POLICY_ALLOW"`
equivalence branch that is dead code today — nothing in the current tree ever produces that literal for the
status field (it is a distinct, legitimate, and unrelated token as the *process-log line prefix*,
`proxy.go:540`, part of the documented `POLICY_ALLOW`/`POLICY_BLOCK`/`POLICY_DROP`/`POLICY_DEFAULT_DENY`
family — this soft finding is only about the status-*field* equivalence checks, not that family). Left
undecided (soft finding, not queued as a numbered item) because collapsing it requires a call this program
doesn't make unilaterally: is the branch genuinely vestigial and safe to delete, or is it there because some
external/legacy producer can still emit the literal into a persisted or replayed status field?

**Terminology Health Score: 8.4 / 10** (unchanged from 08-07 — the carried-over backlog held with zero
regressions across a 58-commit window that included substantial new surface area, all of it internally
consistent when checked end-to-end; offset, as before, by T-39 remaining open at Medium-High and the newly
queued T-42 needing the same kind of design call rather than a mechanical fix).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff d2c5a51..HEAD` (58 commits) was checked against every file each of the nineteen open findings
depends on; every finding whose dependent files *were* touched had the actual cited lines/identifiers
diffed, not just the file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` touched (10 lines) | Touch is a new CDR fingerprint hex-validation error message; zero `rate_limit`-adjacent lines — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies | No | Unchanged |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | No | Unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3/4 config/docs | No | Unchanged |

## Wave 2 — New territory audited this pass (58 commits since `d2c5a51`)

**The four genuinely new naming surfaces this window are each internally consistent end-to-end.** Checked
Go identifier → JSON field → GUI label → metric name for all four:

- The syslog panic-loss counter: `internal/syslog/syslog.go`'s `panics` field/`Panics()` accessor →
  `ui_config.go`'s JSON key `"panics"` → `static/index.html`'s `sl.panics` GUI read. Consistent.
- CHAOS-27's alert-dedup-window bounding: `internal/alerts/store.go`'s `dedupEvicted`/`DedupEvictionsTotal()`/
  `DedupTracked()` → `ui_security.go`'s JSON `dedup_tracked`/`dedup_evictions_total` → `events.go`'s
  `culvert_alert_dedup_evictions_total`/`culvert_alert_dedup_tracked` metrics → `static/index.html`'s
  `d.dedup_evictions_total` GUI read. Consistent.
- The new CHAOS-28 CA-usability GUI banners: every field the GUI reads (`ca.usable`, `ca.unusableReason`,
  `ca.inspectBlocked`, `ca.rotationPersistDegraded`, `ca.rotationPersistError`) is set under the exact same
  name by `apiCAStatus` (`ui_security.go`) — no undefined-field read, no name mismatch introduced while
  wiring a brand-new GUI surface to an already-shipped (CHAOS-28, prior window) Go/metrics layer.
- The attacker-provokable-LDAP-bind DoS gate: `errLDAPAccountRejected`/`ldapUserBindIsUnreachable`
  (`auth_ldap.go`) are each defined once and used identically at every call site; the reachability-clearing
  addition reuses the pre-existing `recordReachable`/`noteAuthBackendReachable` pair symmetrically on both
  the LDAP and OIDC legs — no second name introduced for "clear the cooldown."

**The three parallel general-purpose sweeps of GUI/API/config, audit/alert/metric, and CLI/env/doc drift
surfaced two new findings (T-41, T-42, below) and confirmed the rest of those surfaces clean** — including
re-confirming that the deliberate distinctions CLAUDE.md documents (the four-name "Session Secret" concept,
`defaultAuthOutcome` retiring `UnauthMode`, `identity_backend_unreachable` vs. the separate federated-IdP
registry vocabulary, the `culvert_decrypt_*` metric-prefix abbreviation) are exactly that — deliberate — and
correctly out of scope for this program's findings.

---

## Findings

### T-41 — Root-CA PEM download forked into two independently-maintained handler implementations (new — fixed same-day)

- **Business concept:** downloading the proxy's Root CA certificate (PEM) for OS/browser trust-store
  import — one action, one artifact (`culvert-ca.pem`).
- **Current names / collision (before this fix):** two separately-registered routes each backed by their
  own, independently-coded handler that build the identical response:
  - `ui_routes_meta.go:418` — `Path: "/api/ca-cert", Handler: "apiCACert"`, reached from the Certificates
    panel's `<a id="ca-download-btn" href="/api/ca-cert" ... download="culvert-ca.pem">Download Root CA
    (.pem)</a>` (`static/index.html`).
  - `ui_routes_meta.go:515` — `Path: "/api/ca/download", Handler: "apiCADownload"`, reached from the CA
    Management panel's `<button data-click="downloadCA">Download CA Cert (PEM)</button>`, whose JS sets
    `a.href = '/api/ca/download'`.
  - `apiCACert` (`ui_security.go:242`) and `apiCADownload` (`ui_security.go:1154`, pre-fix) each
    independently called `certMgr.CACertPEM()` and wrote `Content-Type: application/x-pem-file` /
    `Content-Disposition: attachment; filename="culvert-ca.pem"` — byte-identical output from two copies of
    the same eleven lines.
- **Why this is real drift, not cosmetic:** every other deprecated-route pair in this codebase (e.g.
  `/api/content-scan` → `/api/dpi`, `unauth-mode` → `default-auth-outcome`) is an explicit, commented alias
  pointing at *one* canonical implementation. This pair had no alias relationship, no comment acknowledging
  the duplication, and two different GUI button labels for the same action ("Download Root CA (.pem)" vs.
  "Download CA Cert (PEM)") — a support engineer or new contributor fixing a CA-download bug reported
  against one endpoint would have no signal that a second, separately-maintained copy exists and needs the
  identical fix.
- **Why same-day-fixable:** collapsing the duplicate implementation is behavior-preserving by construction —
  both routes stay registered (`ui_routes_meta.go` unchanged), both GUI buttons keep working unmodified,
  and the response bytes for a given CA state are unchanged. This is closing an accidental implementation
  fork, not migrating or removing a public route, so it carries none of the wire-compatibility risk this
  program treats carefully for T-29/T-30/T-38-style renames.
- **Fix applied:** extracted the shared body into `writeCACertPEM(w http.ResponseWriter)`
  (`ui_security.go`), called by both `apiCACert`'s non-JSON GET branch and `apiCADownload`; `apiCADownload`
  is now documented as a back-compat alias of `apiCACert`'s PEM-download branch. Verified via `go build
  ./...`, `go vet ./...`, and the existing `TestAPICACert_*`/`TestAPICADownload_*` suite (`ui_morecoverage_test.go`,
  `ui_security_coverage_test.go`), all passing unchanged.
- **Priority:** Low-cost, real-value cleanup (closes a duplicate-maintenance hazard). **Migration risk:**
  None (both routes/handlers/GUI buttons unchanged; only the internal implementation was de-duplicated).
  **Est. PR size:** Trivial (already applied this pass).

### T-42 — `PolicyStore`'s audit-action verbs (`add`/`remove`) diverge from every sibling full-CRUD resource's `create`/`delete` (new — queued, not fixed)

- **Business concept:** "an admin created or permanently deleted a named, ID-addressable configuration
  resource" — the same shape of event, recorded with the same verb pair everywhere except one resource.
- **Current names / collision:** policy rules are a named, ID-addressable, updatable resource — the Go store
  methods are literally `PolicyStore.Add` (`policy.go:505`), `PolicyStore.Update` (`policy.go:569`),
  `PolicyStore.Delete` (`policy.go:595`) — yet `ui_policy.go`'s audit-action strings are `"policy.add"`
  (`ui_policy.go:1564`), `"policy.update"` (`:1617,1714`), `"policy.remove"` (`:1663,1737`). Every other
  resource of the same shape (named/ID-keyed, has an update endpoint) uses `create`/`update`/`delete`
  instead: `category-group.create/.update/.delete` (`ui_policy.go:485,552,608`),
  `decryption-profile.create/.update/.delete` (`:648,717,773`), `urlcat.create/.update/.delete`
  (`:994,1027,1054`), `fileprofile.create/.update/.delete` (`ui_security.go:474,498,530`),
  `alert.webhook.create/.update/.delete` (`ui_security.go:60,87,103`), `idp.create/.update/.delete`
  (`ui_auth.go:505,567,580`). List-membership actions that genuinely have no update semantics
  (`blocklist.add`/`.remove`, `dpi.add`/`.remove`, `fileblock.add`/`.remove`, `ssl_bypass.add`/`.remove`,
  `urlcat.host.add`/`.remove`) legitimately use `add`/`remove` — that pairing is not flagged. Policy is the
  one resource that has full CRUD, including an update endpoint, but still uses the list-membership verb
  pair for its create/delete actions.
- **Why this trips someone up:** anyone correlating "what happened to this named resource" across the audit
  log, or building tooling/reporting keyed on the `<resource>.<verb>` action-string convention every other
  resource of this shape follows, finds policy as the one silent exception — a `grep`/dashboard rule written
  against `*.create`/`*.delete` misses every policy-rule creation and deletion.
- **Why not fixed this pass:** unlike T-41, this is not a same-day mechanical consolidation — policy rules
  are this codebase's single highest-traffic, most central admin resource, so `"policy.add"`/`"policy.remove"`
  are a live compliance-log vocabulary that any operator's SIEM correlation rule or audit-log tooling may
  already key on. This program's own posture (already applied to T-36/T-37's audit-action findings, and
  explicitly to CLAUDE.md's "never rename stable public APIs unless there is a compelling long-term product
  benefit… always consider migration cost") is that a rename here needs a recorded design decision — whether
  to rename `policy.add`/`.remove` to `.create`/`.delete` outright (breaking any existing correlation rule
  keyed on the old strings) or to dual-emit/alias — not a drive-by fix in a terminology-audit pass.
- **Recommended canonical name / fix:** rename `"policy.add"`/`"policy.remove"` → `"policy.create"`/
  `"policy.delete"` to match every sibling resource's convention, either as a straight rename (if a grep of
  deployed webhook/SIEM configs turns up nothing depending on the old strings, the same verification bar
  T-40 cleared) or via the same `legacyEventNames`-style migration-on-load pattern `internal/alerts/store.go`
  already established for exactly this class of problem (T-40's `idp_unreachable` rename).
- **Priority:** Medium (real, cited drift on the most central admin resource; not urgent — no reported
  confusion, and the audit log itself is still internally queryable by resource name regardless of verb).
  **Migration risk:** Medium (live compliance-log vocabulary; needs the same care as T-40, scaled up because
  policy is far higher-traffic than a brand-new CHAOS-47 alert). **Est. PR size:** Small (the code change is
  a handful of literal-string edits; the risk is entirely in the compatibility analysis, not the diff size).

---

## Carried over, still open (re-confirmed this pass, see Wave 1 table for evidence)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. Unchanged. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Unchanged. |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Unchanged. |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | Open since 07-24 (soft/low). Unchanged. |
| T-16 | ADR numbering collision: 0008–0011 | Open since 07-19. Unchanged. |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19, grew 07-24. Unchanged. |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | Open since 07-24. Unchanged; still compounded by T-32. |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries | Open since 07-24. Unchanged. |
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | Open since 08-01. Unchanged. |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Open since 08-01. Unchanged. |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | Open since 08-01. Unchanged. |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. Unchanged. |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. Unchanged. |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | Open since 08-04. Unchanged. |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | Open since 08-04. Unchanged. |
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06. Unchanged this pass (no fifth stream landed). |
| T-42 | `policy.add`/`.remove` audit verbs diverge from every sibling resource's `create`/`delete` | **New this pass.** |

*T-41 is not listed here — fixed same-day, see Findings.*

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented as a
  deliberate abbreviation in CLAUDE.md.
- Carried over unchanged from 08-06: `drifted_tools`'s absence from the OpenAPI spec; the pre-existing
  "Telemetry (opt-in)" support-panel feature vs. MCP Qualification Telemetry as a third generic sense of
  "telemetry" — no on-screen adjacency, consistent with `PRODUCT-TERMINOLOGY.md`'s tolerance for
  screen-scoped generic-noun reuse.
- Carried over unchanged from 08-07: the new CDR per-instance circuit-breaker fields' ad hoc `cb`-prefix
  wire-key convention vs. the sibling `internal/upstream.Status` breaker fields — same concept, no
  collision, just an inconsistent key-naming convention across two similar endpoints.
- **New this pass:** the request-log/stats `status` field is set to the literal `"OK"` at every production
  call site (`proxy.go:534,538,547,589`, `proxy_tunnel.go:1016`, `proxy_tunnel_h2.go:491`, `socks5.go:359`),
  while `store.go:1107,1142`, `internal/reqlog/reqlog.go:104`, and `internal/otlp/spans.go:301` each carry a
  `status == "POLICY_ALLOW"` equivalence branch that is unreachable in the current tree — no code path ever
  sets the status field to that literal (distinct from, and not to be confused with, `POLICY_ALLOW`'s
  legitimate, documented, and unrelated use as the process-log line prefix at `proxy.go:540`, part of the
  `POLICY_ALLOW`/`POLICY_BLOCK`/`POLICY_DROP`/`POLICY_DEFAULT_DENY` family CLAUDE.md's logsink section
  names). Not queued as a numbered finding because the correct fix depends on intent this program does not
  have visibility into — whether the branch is genuine dead code safe to delete (tightening the status
  vocabulary to just `"OK"`), or a defensive check preserved for a historical/external producer (e.g.
  replaying an older persisted request-log format) that a mechanical deletion would silently break. Worth a
  maintainer decision in a future pass; noted here so the evidence isn't lost.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `review_required_tools` alongside `drifted_tools`; update GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-42 (new) | Decide rename-vs-alias for `policy.add`/`.remove` → `.create`/`.delete`; if renaming, verify no deployed SIEM/webhook config depends on the old strings (T-40's bar) or apply the `legacyEventNames`-style migration pattern | Medium | Small (code) / needs a compatibility decision first |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (carried over) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (carried over) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers) | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

*T-41 is omitted — already fixed this pass.*

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via a cited-line diff against every one of
nineteen previously-open findings, that all nineteen are unchanged across a 58-commit window — including one
finding (T-29) whose dependent file was touched by unrelated code in the same window, verified by reading
the actual diff rather than assuming file-touch implies drift. Three parallel sweeps of surfaces this
program had not recently re-audited in depth (GUI/API/config, audit/alert/metric, CLI/env/doc) found and
same-day-fixed one new finding (T-41, an accidental implementation fork with zero migration risk — the
"catch it, the earlier the cheaper" pattern this program has followed since T-35/T-40) and surfaced one new
finding requiring a design decision before it can be fixed (T-42, queued at Medium priority, same posture as
T-36/T-37/T-39). No cosmetic or preference-driven renames were proposed.
