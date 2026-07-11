# Culvert Admin UI — Current-State Audit

Status: Phase 1 deliverable of the GUI redesign program (see `REDESIGN-ROADMAP.md`)
Date: 2026-07-11
Scope: `static/index.html` (the entire frontend), its serving layer (`ui_static.go`,
`ui_middleware.go`), and the admin API surface it consumes (`ui_routes_meta.go`).

---

## 1. Frontend architecture summary

| Aspect | Current state |
|---|---|
| Framework | None — vanilla JS, single-file SPA |
| File | `static/index.html`, **11,964 lines** (~635 KB), embedded via `//go:embed static` (`ui.go:35`) |
| Build system | None. No bundler, no transpiler, no npm. Chart.js 4.4.0 from jsDelivr CDN (line 8) is the only dependency |
| Serving | `serveUIShell` (`ui_static.go:29`) injects a per-request CSP nonce into `__CSP_NONCE__` placeholders; other assets via embedded `http.FileServer` |
| CSP | `script-src 'self' 'nonce-…' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'` (`ui_middleware.go:153`) — same-origin JS/CSS files are permitted |
| Routing | **No URL routing.** `switchView(name)` (line 4284) toggles `.active` on `.nav-item` / `.view` divs. No deep links; refresh always lands on Dashboard |
| State | Module-level globals (`currentView`, `blEntries`, `logEntries`, …) |
| API access | `api()` wrapper (line 5167): JSON bodies, 401 → login overlay, non-OK → thrown text. ~222 call sites; some bypass the wrapper with raw `fetch()` |
| Events | CSP-safe delegation: `data-click`/`data-change`/`data-input`/… attributes dispatched by central listeners (lines 3810–4180). The `data-click` switch has ~250 cases |
| Live data | 3 s polling `tick()` (line 8634, backs off after 20 consecutive errors) + SSE `/api/events` for dashboard counters (reconnect with exponential backoff + jitter, LIVE/STALE pill) |
| RBAC in UI | `applySession()` (line 4423) show/hides every `[data-min-role]` element; roles admin(3) > operator(2) > viewer(1). Display-only; server enforces |
| Theming | `:root` dark tokens + `html[data-theme="light"]` overrides; toggle persisted in `localStorage` |
| Tests pinning the UI | Playwright e2e clicks `.nav-item[data-view=…]` (`ui_*_e2e_test.go`); Go tests read `static/index.html` and assert exact substrings (`authpolicy_phase*_test.go`, `ui_idp_secret_redaction_test.go`) |

**Verdict:** the architecture is unusual but deliberate and internally consistent.
The CSP event-delegation model, the SSE reconnect logic, the `escHtml` discipline
(249 uses), and the two-phase CA-rotation confirm are genuinely good. The debt is
in the *presentation layer* (inline styles, copy-paste renderers, no component
system) and in *consistency* (confirmation coverage, states, terminology) — not in
the plumbing. **An incremental redesign inside the existing architecture is the
correct strategy; a framework rewrite is objectively unsafe** given the embedded
single-file serving contract, CSP nonce pipeline, and the test suites that pin
markup substrings and selectors.

---

## 2. Screen inventory (25 views)

Columns: user goal / primary APIs / operational importance / redesign priority.
Full endpoint-per-action detail lives in §5 of this doc and in `SCREEN-SPECS.md`.

| View (`data-view`) | User goal | Primary APIs | Importance | Priority |
|---|---|---|---|---|
| `dashboard` | Is the proxy healthy, is traffic flowing, anything to act on? | `/api/stats`, `/api/dashboard/*`, `/api/timeseries`, `/api/top-hosts`, `/api/events` (SSE), `/api/ca-cert` | Daily, first screen | **P1** |
| `livefeed` | Watch/triage requests live; search history | `/api/logs` (live/file/store), `/api/logs/retention`, `/api/logs/purge` | Daily | **P1** |
| `policy` | Author/order Stage-2 access rules | `/api/policy` (+`/reorder`, `/move`), `/api/default-action` | Daily | **P1** |
| `authpolicy` | Decide who must authenticate (Stage-1) | `/api/authpolicy` (+`/reorder`), `/api/idp` | Weekly | P2 |
| `blocklist` | Maintain blocked/allowed hosts + feeds | `/api/blocklist` (+`/mode`, `/feed`, `/exceptions`) | Daily | P2 |
| `security` | Scanning engines, IP filter, rate limit, YARA, block page | `/api/security`, `/api/security-scan/*`, `/api/ssl-bypass`, `/api/connlimit`, `/api/blockpage` | Weekly | P2 |
| `urlcat` | Manage category host lists | `/api/urlcat` (+`/host`, `/lookup`) | Weekly | P3 |
| `catgroups` | Bundle categories for policy | `/api/category-groups` | Weekly | P3 |
| `fileblock` | Extension/MIME blocking profiles | `/api/fileblock` (+`/profiles`) | Weekly | P3 |
| `cdr` | Sluice CDR engines, policies, test | `/api/cdr/*` | Weekly | P3 |
| `rewrite` | Header rewrite rules | `/api/rewrite` | Rare | P4 |
| `upstream` | Parent proxy chaining | `/api/upstream` (+`/health`) | Setup | P3 |
| `pac` | PAC file config/preview | `/api/pac-config`, `/proxy.pac` | Setup | P4 |
| `idproviders` | OIDC/SAML provider profiles | `/api/idp` (+`/discover`, `/{id}`) | Setup | P3 |
| `certificates` | Root CA download, custom cert upload, SSL bypass | `/api/ca-cert`, `/api/certs/upload`, `/api/ssl-bypass` | Setup | P3 (merge with `ca-mgmt`) |
| `ca-mgmt` | CA lifecycle, rotation, OCSP, HSM/KMS | `/api/ca/*`, `/api/ocsp` | Break-glass | P3 (merge with `certificates`) |
| `cluster` | CP/DP nodes, HA, tokens, node groups, bandwidth | `/api/cluster/*` | Setup + incident | P2 |
| `settings` | 15+ panels: auth, sessions, network TLS, syslog, webhooks, config versions, … | `/api/settings*`, `/api/config/*`, `/api/session-*`, `/api/syslog`, `/api/otlp`, … | Setup | P2 (split) |
| `updates` | Docker self-update, rollback, cluster rolling update | `/api/update/*` | Break-glass | P3 |
| `releases` | Verified catalog release dispatch | `/api/releases*` | Break-glass | P3 |
| `diagnostics` | Operator contract: readiness + risky-mode warnings | `/api/diagnostics` | Incident | P2 (feeds dashboard) |
| `governance` | Control-plane governance counters | `/api/governance/control-plane` | Rare | P4 |
| `policy-tester` | Simulate a request; trace decision | `/api/policy/test` | Daily (debugging) | **P1** (integrate with policy) |
| `audit` | Config change history + diffs | `/api/audit` | Daily | P2 |
| `users` | Admin users, roles, lockouts | `/api/auth/users`, `/api/auth/lockouts` | Setup | P3 |

---

## 3. Main UX problems (ranked)

1. **Confirmation coverage is inversely correlated with blast radius.**
   Two-phase token confirm exists for CA rotation (`forceRotateCA`, line 10290) —
   but the highest lockout-risk actions have **no confirmation at all**:
   - Default auth outcome flip — `PUT /api/settings/default-auth-outcome` (line 6833)
   - Blocklist↔allowlist mode flip — `POST /api/blocklist/mode` (line 4987)
   - Session-secret regeneration (logs out every admin) — line 6940
   - Admin IP allowlist (can lock the admin out) — line 6990
   - Enable Control Plane / Enable HA / Set Cluster CA (lines 10995 / 11018 / 10683)
   - Upstream proxy list replacement (breaks all egress) — line 10354
2. **A real bug: Auth Policy rule deletion is broken.** `apDeleteRule` (line 9764)
   calls `confirmDialog(…)`, which does not exist (the helper is `confirmAction`).
   The click throws a ReferenceError before the DELETE fires.
3. **No URL routing.** Refresh/deep-link always lands on Dashboard; incident
   handoff ("look at this rule") is impossible by link.
4. **Monitoring is not triage-ready.** The live table is polled (SSE only feeds
   counters); there is no severity dimension beyond INFO/WARN/ERROR; `ruleMatched`
   is truncated text, not a drill-down; the audit filter is client-side only;
   alert history is buried in Settings.
5. **Policy editing has no draft state and no shadow-rule warning.** Every
   create/edit/**drag-reorder** persists immediately; nothing warns that a
   higher-priority rule shadows a lower one.
6. **Dashboard doesn't answer "do I need to act?"** — it's counters + charts.
   Engine degradation, cluster health, catalog staleness, and log-write failures
   (`logWriteErrors`, already in `/api/stats`!) are not surfaced as a posture strip.
7. **Duplicated/confusing surfaces:** two threat-feed systems (blocklist feeds vs
   security-scan feeds), two "skip scanning" vocabularies (bypass/exclusion/
   allowlist/exception), Certificates vs CA Management split, Updates vs Releases
   overlap, Diagnostics vs Governance overlap.
8. **Accessibility is near-zero.** Exactly one `aria-*` attribute in 11,964 lines.
   Nav items are non-focusable `<div>`s; no modal focus trap; no `aria-live` for
   toasts; several color-only status indicators.
9. **Inconsistent empty/loading/error states.** `.spinner`/`.loading-overlay` CSS
   exists but is never used; some tables hand-roll "No X yet" rows, some use
   `.empty-state`; several fetch failures are swallowed silently (`catch(_){}`).
10. **Session expiry is discovered only on the next 401**, losing in-flight form
    state behind the login overlay.

---

## 4. Main frontend technical debt (ranked)

1. **1,386 inline `style="…"` attributes** — global restyling requires touching
   markup everywhere. Utility classes exist (lines 106–118) but are underused.
2. **Undefined-token bugs:** `--card` and `--danger` are defined only under
   `html[data-theme="light"]` but used in dark mode (confirm dialog line 3752,
   release modal, etc.); `--surface1` is referenced (lines 1249, 1374, 8755, …)
   but **never defined**.
3. **Undefined button variants:** `.btn.primary` (3718, 3745, 3790), `.btn.accent`
   (3608), `.btn.warn` (3165) appear in markup but have no CSS — they silently
   render as the base accent button.
4. **No type/spacing/radius scales.** 25+ ad-hoc font sizes (.6rem→3rem), ad-hoc
   paddings, radius values 3–999px; `--radius` covers only cards/panels.
5. **Copy-paste table renderers** — every list view builds `<tr>` strings and
   assigns `tbody.innerHTML` (176 `innerHTML` sites). No shared table helper, no
   shared column/empty-state/badge conventions.
6. **Chart.js colors hardcoded** (lines 4329–4368) — charts don't re-theme.
7. **Three sources of truth for view-entry data loading:** `switchView()`
   (4293–4313), a second nav `forEach` (8695), and the polling `tick()` (8653).
8. **`toast()` injects unescaped `err.message` via innerHTML** (line 8127).
9. **Emoji as icons** — inconsistent cross-platform rendering, no stroke/weight
   control, monochrome impossible.
10. **Native `prompt()`/`confirm()` remnants** (4 sites: 4930, 11034, 11169, 11257)
    against the otherwise-standard `confirmAction` modal.
11. **Inter font is declared but never loaded** (line 58) — silently falls back.
12. **Dead CSS:** `.spinner`, `.loading-overlay` (lines 280–283).
13. **`viewMeta` missing the `governance` entry** — topbar shows the raw string.
14. **Modal placement inconsistent** (some inside `.content` views, some at body
    root) and no shared open/close/focus mechanics.

---

## 5. Dangerous-workflow inventory

| Action | Endpoint | Confirm today | Blast radius |
|---|---|---|---|
| Change default auth outcome | `PUT /api/settings/default-auth-outcome` | ❌ inline banner only | Lock everyone out / open everything |
| Flip blocklist↔allowlist mode | `POST /api/blocklist/mode` | ❌ | Can block all traffic |
| Change global default action | `POST /api/default-action` | ✅ `confirmAction` | Global allow/deny flip |
| Delete auth-policy rule | `DELETE /api/authpolicy` | ⚠️ **broken** (`confirmDialog` undefined, line 9764) | Rule falls back to default gate |
| Regenerate session secret | `POST /api/session-secret` | ❌ | Logs out every admin |
| Admin IP restriction | `POST /api/ui-allow-ips` | ❌ | Admin lockout by source IP |
| Rotate Root CA | `POST /api/ca/rotate` | ✅ two-phase token + warning (model to generalize) | TLS trust break until re-install |
| Enable Control Plane / HA | `POST /api/cluster/mode`, `/api/cluster/ha` | ❌ | Cluster formation / role change |
| Promote standby → leader | `POST /api/cluster/ha/promote` | ✅ native `confirm()` | Split-brain |
| Set cluster CA | `POST /api/cluster/ca` | ❌ | Invalidates node trust |
| Revoke node / drain | `/api/cluster/revoke`, `/drain` | ✅ | Node disconnect |
| Replace upstream proxy list | `POST /api/upstream` | ❌ | Breaks all egress |
| Config rollback / import | `/api/config/versions`, `/import` | ✅ | Replaces/merges all settings |
| Apply update / rollback / rolling | `/api/update/*` | ✅ | Container/fleet restart |
| Purge logs | `POST /api/logs/purge` | ✅ | Data loss |
| Add SSL-bypass pattern | `POST /api/ssl-bypass` | ❌ | Silently disables inspection for hosts |
| Delete admin user | `DELETE /api/auth/users` | ✅ (self-delete blocked in UI) | No visible last-admin guard |

---

## 6. What must be preserved (redesign contracts)

1. **Selectors & mechanics pinned by tests:** `.nav-item[data-view=…]` clicks and
   `[data-view=…]` visibility (Playwright, `ui_*_e2e_test.go`); `data-min-role`
   show/hide semantics (`ui_rbac_e2e_test.go`).
2. **Exact substrings pinned by Go tests** (assert on `static/index.html` bytes):
   the IdP modal field IDs/JS lines (`ui_idp_secret_redaction_test.go:420-500`),
   the auth-policy outcome selector/gating JS (`authpolicy_phase2_slice4_test.go`,
   `authpolicy_phase3_slice6_test.go`, `authpolicy_phase4_slice4_test.go`).
   **Do not reformat those JS regions.**
3. **The single-file + embed + CSP-nonce serving contract** (`__CSP_NONCE__`
   placeholders on every `<script>`; new same-origin assets are allowed by CSP).
4. **Element IDs consumed by JS** (`d-total`, `rateChart`, `top-rules-table`, …) —
   markup can be restructured around them, not renamed casually.
5. **All backend contracts** (`uiRoutes` count is pinned by D0 tests; no route
   changes without metadata + tests).
6. **RBAC defense-in-depth**: client-side hiding stays cosmetic; every server
   handler keeps `requireRole`.

---

## 7. Strengths to build on

- CSP `data-*` event delegation (no inline handlers) — keep and extend.
- `escHtml` discipline; extend to `toast()`.
- SSE hub with slow-client eviction, mid-stream re-auth, LIVE/STALE indicator.
- `confirmAction` promise-based dialog — generalize into typed confirmation with
  impact statements (see `UX-PRINCIPLES.md` §3).
- Method-aware route metadata (`uiRoutes`) + C1–C4 governance test pyramid — the
  backend is *more* mature than the frontend; the redesign brings the UI up to it.
- Dark/light theming via tokens — extend into a full semantic token system.
