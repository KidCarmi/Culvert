# Culvert Admin Console — Information Architecture

Status: Phase 2 deliverable of the GUI redesign program
Date: 2026-07-11
Grounding: every entry below maps to an existing `data-view` and existing
`/api/*` endpoints (see `CURRENT-UI-AUDIT.md` §2). Nothing here invents backend
functionality. Items marked **(merge)** consolidate existing views; items marked
**(relocate)** move existing panels between views.

> **Correction (post-2026-07-11): the `Updates` nav item described below no
> longer exists.** DEBT-008 closed the same day this document was dated,
> deleting the legacy `updater/` module, the 11 `/api/update/*` routes, and
> the Updates admin-UI panel outright (see
> `docs/engineering/TECHNICAL-DEBT-REGISTER.md` DEBT-008). The "Releases and
> Updates stay separate items in M1 ... legacy updater is not demoted yet"
> rationale below and the `Updates → updates` nav/migration rows are
> historical and describe a state that was superseded before this plan
> shipped — `releases` is now the only Platform item for software delivery.
> More broadly, this whole document is a **Phase 2, 2026-07-11 snapshot**
> and predates several nav items shipped since: the MCP Gateway section
> (`mcp-overview`/`mcp-servers`/`mcp-decisions`/`mcp-policies`/
> `mcp-approvals`/`mcp-health`/`mcp-rollout`/`mcp-settings`), the
> `decexclusions`/`dechealth`/`decprofiles` Decryption items, and `support`
> (see `static/index.html`) — none of these appear in the target navigation
> or migration table below. Treat this document as a historical planning
> record of its stated grouping/rationale, not a current inventory of the
> admin console's nav.

---

## 1. Design intent

The current sidebar has 8 sections and 25 flat items, grouped by *implementation
domain* (Control / Network / Certificates / Infrastructure / Tools). The target
IA groups by *administrator intent*, in the order an operator's day actually
flows: **看 → 管 → 配 → 修** (observe → control → configure → maintain):

1. What is happening? (Overview, Monitor)
2. What is allowed? (Policies)
3. What do policies refer to? (Objects)
4. What runs the product? (Platform)
5. Who runs the console? (Administration)

A "Reports" top-level section (à la PAN-OS) is **deliberately omitted**: Culvert
has export endpoints (`/api/logs` CSV/JSON, `/api/config/export`) but no report
generation/scheduling backend. Inventing that section now would be security
theater. It is listed as a *future product concept* in `REDESIGN-ROADMAP.md`.

## 2. Target navigation

Existing `data-view` names are kept verbatim (they are pinned by Playwright
tests and the click-dispatch code); only grouping, order, labels, and icons
change. Minimum role per item is unchanged from today unless noted.

```
OVERVIEW
  Dashboard            → dashboard        (all roles)   posture strip + traffic + actions needed

MONITOR
  Traffic              → livefeed         (all roles)   label change: "Live Feed" → "Traffic"
  Audit Log            → audit            (all roles)   relocated from "Tools"
  Policy Tester        → policy-tester    (all roles)   relocated from "Tools"; long-term: embedded in Policies

POLICIES
  Access Rules         → policy           (operator)    label change: "Policy" → "Access Rules"
  Authentication Rules → authpolicy       (all roles; writes admin)  label: "Auth Policy" → "Authentication Rules"
  Blocklist            → blocklist        (operator)
  Content & Scanning   → security         (operator)    label change: "Security" → "Content & Scanning"
  File Control         → fileblock        (operator)    label change: "File Block" → "File Control"
  CDR                  → cdr              (operator)

OBJECTS
  URL Categories       → urlcat           (operator)
  Category Groups      → catgroups        (operator)
  Header Rewrite       → rewrite          (operator)    relocated from "Network"
  Identity Providers   → idproviders      (admin)

PLATFORM
  Certificates & CA    → certificates + ca-mgmt  (admin)  (merge, M2 — until then both items appear here)
  Cluster              → cluster          (admin)       label: "Cluster Nodes" → "Cluster"
  Network              → upstream + pac   (admin/operator) (merge target, M2 — until then: Upstream Proxies, PAC File)
  Updates              → updates          (admin)
  Releases             → releases         (admin-gated actions)
  Diagnostics          → diagnostics      (admin)
  Settings             → settings         (admin)

ADMINISTRATION
  Administrators       → users            (admin)       label: "Users & Roles" → "Administrators"
  Governance           → governance       (admin)
```

### Rationale for the deviations from the generic template

- **No "Incidents"**: Culvert has alerts-to-webhooks and a blocked-request feed,
  but no incident entity/lifecycle in the backend. Surfacing "Active incidents"
  on the dashboard would be fake. The dashboard's "needs attention" strip is
  computed from real signals only (see `SCREEN-SPECS.md` §Dashboard).
- **Blocklist under Policies, not Objects**: the blocklist *is* an enforcement
  decision (block/allow + mode), not a referenced object. URL categories and
  category groups are referenced *by* rules → Objects.
- **Authentication Rules stays a top-level policy** (not merged into Access
  Rules): the backend models Stage-1 (auth) and Stage-2 (access) as distinct
  evaluations with distinct endpoints (`/api/authpolicy` vs `/api/policy`), and
  the existing UI already learned the hard way that conflating "Exempt" with
  "Allow" confuses users (`static/index.html:9459`).
- **Users (proxy identities) are NOT in Objects**: Culvert has no user directory
  of its own — identities come from IdPs at auth time. Adding a "Users" object
  screen would imply a directory that doesn't exist. `Administrators` = console
  accounts only.
- **Releases and Updates stay separate items in M1** — they are different
  backends (legacy Docker updater vs signed catalog dispatch). The roadmap's M3
  proposes a unified "Software" screen once the catalog path fully supersedes
  the legacy updater (per `roadmap/D1.6d-release-ux-direction.md` the legacy
  updater is not demoted yet).

## 3. Migration mapping (old section → new)

| Old section | Old item | New location | Change |
|---|---|---|---|
| Monitor | Dashboard | Overview → Dashboard | — |
| Monitor | Live Feed | Monitor → Traffic | rename |
| Control | Blocklist | Policies → Blocklist | — |
| Control | Security | Policies → Content & Scanning | rename |
| Control | Policy | Policies → Access Rules | rename |
| Control | Auth Policy | Policies → Authentication Rules | rename |
| Control | URL Categories | Objects | move |
| Control | Category Groups | Objects | move |
| Control | File Block | Policies → File Control | rename |
| Control | CDR | Policies → CDR | — |
| Network | Rewrite | Objects → Header Rewrite | move+rename |
| Network | Upstream Proxies | Platform | move |
| Network | PAC File | Platform | move |
| Identity | Identity Providers | Objects | move |
| Certificates | SSL / TLS | Platform → Certificates & CA | merge (M2) |
| Certificates | CA Management | Platform → Certificates & CA | merge (M2) |
| Infrastructure | Cluster Nodes | Platform → Cluster | rename |
| Infrastructure | Settings | Platform → Settings | — |
| Infrastructure | Updates | Platform → Updates | — |
| Infrastructure | Releases | Platform → Releases | — |
| Infrastructure | Diagnostics | Platform → Diagnostics | — |
| Infrastructure | Governance | Administration → Governance | move |
| Tools | Policy Tester | Monitor → Policy Tester | move |
| Tools | Audit Log | Monitor → Audit Log | move |
| Admin | Users & Roles | Administration → Administrators | rename |

## 4. Role gating (unchanged behavior, one fix)

- Section headers keep `data-min-role` so entire groups collapse for viewers.
- `authpolicy` and `releases` nav items currently have **no** `data-min-role`
  while their sibling content is operator/admin-scoped. This stays as-is in the
  M1 shell change (GET endpoints are viewer-readable, and hiding them would
  change observable RBAC behavior that `ui_rbac_e2e_test.go` doesn't cover) and
  is revisited in M2 with explicit read-only affordances ("view only" badge)
  instead of hiding.

## 5. Settings decomposition (M2+, not M1)

`settings` is 15+ unrelated panels today. Target split (all existing panels,
no new backend):

- **Platform → Settings → General**: proxy info, logging level, GeoIP, logger
- **Platform → Settings → Access & Sessions**: default auth outcome, session
  timeout, session signing key, admin IP restriction, network & TLS
- **Platform → Settings → Integrations**: syslog/SIEM, alert webhooks,
  Prometheus metrics, OTLP
- **Platform → Settings → Configuration**: export/import, config versions
  (rollback), retention

M1 keeps `settings` a single view (renaming/splitting it touches dozens of
pinned element IDs); the split ships with the Settings redesign slice.

## 6. Breadcrumb & title model

- Topbar title = `Section / Item` (e.g. "Policies / Access Rules") sourced from
  the same `viewMeta` table (single source of truth; the missing `governance`
  entry gets fixed in M1).
- Deep-linking (hash-based `#/view/<name>`) is an M2 item: `switchView` gets a
  `location.hash` write + hashchange listener. No server-side routing change
  (the SPA catch-all already serves `/`).
