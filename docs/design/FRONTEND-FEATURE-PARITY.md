# Frontend Feature Parity Matrix

- **Status**: Baseline (2026-08-21). This is the parity gate for the frontend replacement: FE-8
  cutover requires every row DONE or explicitly descoped with sign-off. Measured from
  `static/index.html` (21,565 lines, 38 views), `ui_routes_meta.go` (229 routes / 343 method
  rows — see the generated accounting table in `FRONTEND-SECURITY-CONTRACT.md` §7), and the
  discovery inventory in `FRONTEND-CURRENT-STATE.md`.
- Legend — **Role**: minimum role that sees the panel (`data-min-role` and/or imperative guard;
  backend per-endpoint roles remain authoritative). **Mut**: panel contains mutating calls.
  **Destr**: contains destructive/hard-to-reverse operations (T3 = typed-word tier-3 ceremony,
  2P = two-phase server token, MCP-D = MCP danger dialog). **Audit**: backend marks its
  mutations `AuditExpected`. **Poll/SSE**: live-data dependencies. **Tests**: M = markup-pinned
  Go scan, G = `*_gui_test.go` shell scan, E = playwright-go `uie2e` spec, A = API-level Go
  tests (kept regardless). **Risk**: migration risk (H/M/L).

## A. Views (38)

| ID | View (`data-view`) | Endpoints (families) | Role | Mut | Destr | Audit | Poll/SSE | Tests | Risk |
|---|---|---|---|---|---|---|---|---|---|
| FE-V01 | `dashboard` | `/api/stats`, `/api/timeseries`, `/api/top-hosts`, `/api/country-traffic`, `/api/dashboard/{health,threats,top-rules}`, `/api/health/explain` | viewer | no | — | — | 3 s tick + SSE `/api/events` (counters, countries, LIVE pill) | E (LiveSSEDashboard), A | **H** — SSE lifecycle + tick pause/resume semantics + 2 charts (Chart.js is **conditional on the FE-2 gate** — strict-CSP/no-style-mutation proof, else replaced by an internal SVG/CSS implementation; see ADR-FE-001) + posture strip |
| FE-V02 | `livefeed` (Traffic) | `/api/requests`, `/api/logs{,/retention,/purge}`, `/api/export` | viewer | purge/retention | purge (confirm) | yes | 3 s tick | E (TrafficRuleLink…), A | M — high-churn table, filters, history paging, rule-ID deep link |
| FE-V03 | `audit` | `/api/audit` | viewer | no | — | — | on-view load | E (AuditTrail, AuditLog_Filterable) | L |
| FE-V04 | `decexclusions` | `/api/decryption-exclusions{,/tunables}` | viewer (tunables admin) | yes | evict one / clear all / reset tunables (confirms) | yes | on-view | G (decexcl_tunables), A | L |
| FE-V05 | `dechealth` | `/api/decryption/{health,redaction}` | viewer | no | — | — | on-view | A | L |
| FE-V06 | `policy-tester` | `/api/policy/test` | viewer | no (dry-run) | — | — | — | E (PolicyTester) | L — must preserve per-rule skip-reason trace rendering |
| FE-V07 | `mcp-overview` | `/api/mcp/{overview,health,config}` | viewer | no | — | — | on-view + ticketed refresh | A (ui_mcp tests) | M |
| FE-V08 | `mcp-servers` | `/api/mcp/{servers,tools}` | viewer | no | — | — | on-view | A | M — drawer drill-down w/ frame stack |
| FE-V09 | `mcp-decisions` | `/api/mcp/{decisions,decision-explain}` | viewer | no | — | — | on-view | A | M — evidence drawer, shadow-override rendering |
| FE-V10 | `mcp-policies` | `/api/mcp/{policy,policy-simulate,publications,publication-decision}` | viewer (publish operator+) | yes | publish/discard (native confirm today) | yes | — | A | **H** — candidate draft in memory, validate/simulate/compare, never-persist guarantee |
| FE-V11 | `mcp-approvals` | `/api/mcp/{approvals,approval-decision}` | viewer (decide operator+) | yes | four-eyes decisions (MCP-D; `self_approval` surfaced) | yes | ticketed | A | **H** — four-eyes ceremony correctness |
| FE-V12 | `mcp-health` | `/api/mcp/{health,distribution,distribution/acks}` | viewer | no | — | — | on-view | A | M |
| FE-V13 | `mcp-rollout` | `/api/mcp/rollout{,/scope,/scope/validate,/transition,/emergency,/evidence,/rehearse-rollback}`, `/api/mcp/rollback` | viewer (act admin) | yes | kill switch, emergency, transitions, rollback (**MCP-D**: typed phrase, ticket supersede, UNKNOWN-state copy, `production_locked`) | yes | ticketed poll | A (transaction tests) | **H** — the most safety-critical ceremony in the product |
| FE-V14 | `mcp-management` | `/api/mcp/management-access` | viewer | no (read-only by design, D-13) | — | — | on-view | A | L — must stay visibly read-only |
| FE-V15 | `mcp-settings` | `/api/mcp/config` | admin | yes | — | yes | — | A | L |
| FE-V16 | `policy` (Access Rules) | `/api/policy{,/reorder,/move,/draft,/draft/commit,/draft/revert}`, `/api/default-action`, `/api/objects/references` | operator | yes | delete rule, discard staged, default-action change (T3-adjacent), commit | yes | 3 s tick (guarded render) | E ×5 (draft bar, cross-plane, by-ID, reorder), M ×4 | **H** — draft/commit + staged reorder + shadow warnings + version fencing + render ceiling (~200–300 rules) |
| FE-V17 | `authpolicy` | `/api/authpolicy{,/reorder}`, `/api/settings/default-auth-outcome` | operator | yes | delete rule; default outcome flip (**T3** OPEN/REQUIRE) | yes | — | M ×4 (authpolicy_phase*), A | **H** — SSO/provider-ref semantics byte-pinned today; simulator stage separation |
| FE-V18 | `policylearn` | `/api/policy-learning{,/config,/session,/sessions,/recommendations,/recommendations/generate}` | viewer (ops operator, accept admin) | yes | disable engine; accept-to-draft (armed only) | yes | on-view | M (m5a/m5b wording + role gating), A | M — advisory-only wording is contract; accept/reject fencing (`if_version`) |
| FE-V19 | `blocklist` | `/api/blocklist{,/mode,/feed,/feed/sync,/exceptions}` | operator | yes | mode flip (**T3** ALLOWLIST/BLOCKLIST), bulk delete, feed remove (double confirm) | yes | tick ≥15 s throttle | E (BlocklistCrossPlane), A | M |
| FE-V20 | `security` (Content & Scanning) | `/api/security`, `/api/security-scan/*` (status, YARA rules/settings/validate/reload, feeds sync, domain-allowlist, exclusions), `/api/dpi`, `/api/content-scan/bypass`, `/api/ssl-bypass` | operator | yes | delete YARA rule file; clear lists | yes | on-view | E (SecurityPanel), A | M — many sub-editors (IP filter, rate limit, YARA editor w/ validate) |
| FE-V21 | `fileblock` | `/api/fileblock{,/profiles}` | operator | yes | clear all extensions; delete profile | yes | tick | E (FileBlockCrossPlane) | L |
| FE-V22 | `cdr` | `/api/cdr/{config,instances,instances/enroll,instances/revoke,policies,health,test}` | operator | yes | revoke instance (confirm ×2 paths); disable | yes | on-view | A | M — enrollment w/ token+fingerprint, test upload |
| FE-V23 | `urlcat` | `/api/urlcat{,/host,/lookup,/feed-status}`, `/api/saas-feed/{settings,status,overrides,refresh}` | operator | yes | delete category | yes | on-view | G (saas_feed) | M — feed status/override interplay |
| FE-V24 | `catgroups` | `/api/category-groups` | operator | yes | delete group (ref-guarded) | yes | — | E (CategoryGroupEdit_ByID) | L |
| FE-V25 | `decprofiles` | `/api/decryption-profiles` | operator | yes | delete profile (ref-guarded) | yes | — | E (DecryptionProfileEdit_ByID), M (cert-enum lockstep) | M — `dp-cert` option set must stay lockstepped to runtime enum |
| FE-V26 | `rewrite` | `/api/rewrite` | operator | yes | delete rule | yes | tick | E (HeaderRewriteCrossPlane) | L |
| FE-V27 | `idproviders` | `/api/idp{,/:id,/:id/groups,/discover,/test,/legacy-ldap,/legacy-ldap/import}` | admin | yes | delete IdP | yes | — | E ×2 (LDAP create/edit, viewer-hidden), M (secret redaction) | **H** — write-only secret fields with explicit-clear checkbox semantics (security-pinned) |
| FE-V28 | `certificates` | `/api/ca-cert`, `/api/ca/download`, `/api/certs/upload` | admin | yes | cert upload (**no confirm today** — add one) | yes | — | E (CAPanelShowsRoot) | M — file upload + PEM textareas + OS-instructions modal |
| FE-V29 | `ca-mgmt` | `/api/ca/{status,rotate,cache-clear,key-provider}`, `/api/ocsp` | admin | yes | rotate root (**2P** token ceremony), clear cache | yes | on-view | A | **H** — two-phase rotate must be preserved exactly |
| FE-V30 | `cluster` | `/api/cluster/*` (status, mode, ha, ha/promote, tokens, revoke, revocations, drain, labels, metrics, bandwidth, node-groups, rate-limits, rotation, convergence, audit, ca) | admin | yes | enable CP (**T3**), enable HA (**T3**), promote (**T3**), CA import (**T3**), drain, revoke, token delete | yes | tick | A | **H** — 4 of 9 tier-3 ceremonies live here; enroll modal token display |
| FE-V31 | `upstream` | `/api/upstream{,/health,/settings}` | operator | yes | remove proxy | yes | tick | A | L — direct-fallback red banner is contract |
| FE-V32 | `pac` | `/api/pac/{profiles,pools,simulate,posture/{diff,inventory,exceptions}}`, `/api/pac-config`, `/proxy.pac` | operator | yes | publish DIRECT-bypass profile (**T3**: word = profile id), delete profile/pool, clear governance | yes | — | E ×6 (PAC family), M (uicontract) | **H** — governance/posture-diff workflow + simulator + the T3 bypass ceremony |
| FE-V33 | `releases` | `/api/releases{,/current,/dispatch,/dispatch/status,/dispatch/resume,/catalog-refresh}`, `/api/backups` | viewer (dispatch admin) | yes | **dispatch upgrade — currently NO confirm; add ceremony**; catalog refresh | partial (dispatch audits via service) | 2.5 s recursive poll while dispatched | G (release_gui), A | **H** — async op_id lifecycle, resume, degraded `available:false` states, agent-unknown 404 copy |
| FE-V34 | `diagnostics` | `/api/diagnostics`, `/api/diagnose/{all,cluster,config,dns,etcd,storage,support,tls,upstream}` | admin (contract viewer) | diagnose verbs mutate=audited | — | yes | on-view | E (DiagnosticsPanelRuns) | M — versioned typed results; `operator_action` rendering |
| FE-V35 | `support` | `/api/support/*` (status, bundles + per-bundle approve/upload/validate/manifest/exports/redaction-report/download-sealed/download-encrypted, recipients, retention, debug-level, tac-trust, telemetry/{config,preview}, upload/config, uploads), `/api/backups` | viewer (ops operator/admin) | yes | delete bundle, approve, recipient rotate/remove (**native prompts today — replace**), passphrase entry (**native prompt today — replace**) | yes | tick (support section) | G (support_upload), A | **H** — largest workflow surface; sealed/encrypted downloads via Blob; consent gates |
| FE-V36 | `settings` | `/api/settings{,/network,/log-level}`, `/api/session-{secret,timeout}`, `/api/ui-allow-ips`, `/api/syslog`, `/api/logger`, `/api/metrics-config`, `/api/otlp`, `/api/geoip`, `/api/blockpage`, `/api/connlimit`, `/api/alerts/webhooks{,/test,/history}`, `/api/config/{export,import,versions,diff}` | admin | yes | session-key rotate (**T3**), IP allowlist (**T3**), config import replace (dry-run→confirm), version rollback (confirm; partial-failure + `runtime_only_surfaces` states), webhook delete | yes | 15 s delivery-history poll (view-gated) | E (ConfigVersionRollback), A | **H** — monolith slated for decomposition (IA §5); export/import/rollback truth-telling per config-surface registry |
| FE-V37 | `users` (Administrators) | `/api/auth/{users,lockouts,change-password}` | admin | yes | delete user (revokes sessions), clear lockouts | yes | — | E (RBACNavGating), A | M — no TOTP enrollment UI exists (backend gap GAP-2) |
| FE-V38 | `governance` | `/api/governance/control-plane` | admin | no | — | — | on-view | E (GovernancePanel), A | L |

## B. Cross-cutting workflows (not views)

| ID | Workflow | Endpoints | Notes | Risk |
|---|---|---|---|---|
| FE-X01 | Login / logout / session expiry | `/api/auth/{login,logout,status}` | 2-step TOTP in-band (`totp_required`); 401-anywhere → login overlay; logout revokes; **pre-auth TLS-fallback warning banner** driven by `ui_tls_fallback`/`ui_tls_fallback_reason` on `/api/auth/status` (added on main 2026-08-22) | **H** |
| FE-X02 | First-admin setup | `/api/setup/{status,complete}` | Bootstrap role injection window; complexity mirror; auto-login; **pre-auth TLS-fallback warning banner** driven by `ui_tls_fallback` on `/api/setup/status`. **Setup-time unauth/open mode (`{unauth:true}`) is WITHHELD from the v2 UI (FE-3 decision, 2026-08-22)**: the backend marks the appliance configured (`defaultAuthOutcome=Exempt` ⇒ `IsConfigured()` true, `store.go:596-600`) WITHOUT creating any in-band management identity — `uiAuthMiddleware` then requires credentials no roster can satisfy (`ui_middleware.go:254-296`, `VerifyUIUser` `store.go:943-965`); recovery requires appliance-shell/OOB credentials (`-user/-pass` flags, `auth.user`/`auth.pass` YAML via `auth_startup.go`, or `--reset-password`, `main.go:297`). The legacy browser wizard never exposed this path either (`static/index.html:18560-18580` is credential-only). Backend gap tracked as GAP-9 (SETUP-OPEN-MODE) in FRONTEND-CURRENT-STATE.md — a backend/product decision for later review, not an FE fix. The governed post-setup path (Authentication panel default-auth-outcome, with real credentials existing) is unaffected. | **H** |
| FE-X03 | Theme | `localStorage['culvert-theme']` | Only browser storage in the app — keep as the only persisted client state | L |
| FE-X04 | SSE liveness | `/api/events` | connected handshake, backoff+jitter, 30-retry cap (make resumable), LIVE/STALE pill, 503-at-cap handling | **H** |
| FE-X05 | Global confirm/danger/prompt dialogs | — | 3-tier system + MCP danger dialog; typed words; stack, focus trap, Esc; replace 6 legacy modals + 5 native prompt/confirm sites | **H** |
| FE-X06 | Object references ("where used") | `/api/objects/references` | Generic consumer rendering per DESIGN-SYSTEM §3 contract | M |
| FE-X07 | Downloads/exports | `/api/config/export`, `/api/export`, `/api/ca-cert`, `/api/ca/download`, support downloads, `/proxy.pac` | Blob + `a.download` and direct-href patterns; per-section filenames | M |
| FE-X08 | Role-gated navigation | `/api/auth/status` | 123 `data-min-role` hides + section gating; new app: route guards + nav filtering, server still authoritative | M |
| FE-X09 | Keyboard shortcuts + a11y floor | — | 1–8 view jumps, Esc, `[data-click][role=button]` keydown; extend per UX-PRINCIPLES §12 | M |
| FE-X10 | Rule-ID deep links (traffic→policy, audit filter) | — | Currently no URL routing outside MCP; new router makes these real URLs | M |

## C. Capabilities that must not silently disappear (checklist extras)

- Multi-admin draft actor warning ("opened by <other>") on the policy draft bar.
- Staged-reorder version fencing (silently discards on rulebase movement) and
  `polBlockWhileStaged` mutation blocking.
- Shadowed-rule warnings surfaced at commit time (`st.shadows`).
- Release dispatch: `pre_backup` + `passphrase_ref` (env-ref, never a secret), idempotency key,
  forced status polling, resume-by-`op_id`, "Unknown maintenance agent" 404 copy.
- Support bundle: approve-before-download lifecycle, sealed vs encrypted download variants,
  redaction report, TAC trust, telemetry consent preview.
- Rollback response rendering: dry-run, partial "applied-but-not-persisted", and
  `runtime_only_surfaces` disclosure.
- Export redaction disclosure (webhooks/upstream secrets excluded by construction).
- MCP: ticket/supersede handling, "state is UNKNOWN" network-failure copy, `production_locked`
  and `self_approval` error surfacing, read-only Management posture, candidate-never-persisted
  guarantee.
- Decryption-profile cert-verification option set locked to the runtime enum (re-express
  `decryptprofile_cert_contract_test.go` against the new source of options).
- SSE server contract handling: 503 + `Retry-After` at cap; eviction-close reconnect.
- IdP secret fields: write-only, cleared only when explicitly checked; redaction-safe SAML
  metadata indicator.
- Blocklist feed remove: second confirm for "also remove its entries".
- Two-phase Root-CA rotation token ceremony.
- Pre-auth TLS-fallback warning banners (setup overlay, login overlay, and in-app) driven by
  `ui_tls_fallback`/`ui_tls_fallback_reason` on `/api/setup/status` and `/api/auth/status`
  (main, 2026-08-22 — the credentials-over-plain-HTTP warning must not be lost in migration).
- Security-panel scan-saturation tiles (`stat_clam_saturated`, `scan_inflight`,
  `stat_scan_late_discard` on `/api/security-scan/status`; main, 2026-08-22).
- CA cert-upload persistence disclosure: the MITM-target upload is persisted to the CA bundle
  path (label + confirmation copy fixed on main, 2026-08-22); the UI-target upload is
  validate-only.
- Country flags via Unicode regional indicators (no CDN), theme-aware charts,
  reduced-motion-safe `chart.update('none')` behavior.

## D. Known current-state defects that migration should fix, not reproduce

(From `FRONTEND-CURRENT-STATE.md` GAP table and design-doc backlog: `mcp-rollout` missing
`viewMeta`; dead `'4': 'log'` shortcut; `describeLogPersistence` SVG-in-textContent branch;
6 non-stack modals; 5 native dialogs incl. passphrase prompt; single-entry leave-guard;
background-tab polling; SSE permanent give-up; no dispatch confirm; no cert-upload confirm;
1,999 inline styles / `style-src 'unsafe-inline'`; uncached 4 MB logo.)
