# MCP Target-UI Prototypes — Rendered Design Mockups

**DESIGN PROTOTYPES — NOT IMPLEMENTED.** These are isolated static HTML/CSS
mockups of the proposed MCP admin surface, rendered to PNG at **1440×900**. They
**do not** modify or import production `static/index.html`, they **never** call a
real API, and they use **synthetic safe fixture data only** (illustrative numbers;
obviously-fake hashes; no tokens, PII, or secrets). Every screen carries a visible
`DESIGN PROTOTYPE — NOT IMPLEMENTED` banner.

They exist so the rendered target can be evaluated for spacing, hierarchy,
density, typography, component placement, status treatment, drawer width, table
readability, modal clarity, and dark/light balance — before any implementation
slice begins. **No implementation slice was started.**

## Files
- `_prototype.css` — shared stylesheet; token values copied field-for-field from
  `static/index.html` (dark `:root` + `html[data-theme="light"]`) so the mockups
  read as an evolved Culvert product.
- `_shell.js` — renders the Culvert sidebar + topbar + prototype banner.
- `command-center.html`, `activity.html`, `rollout.html`, `qualification.html`,
  `emergency.html`, `health.html` — the prototype screens (state via `?state=`,
  modals via `?modal=`/`?dialog=`; theme applied by the renderer).
- `compare-*.html` + `_comparison.css` — current-vs-proposed comparison sheets.
- `renders/` — 18 rendered screens. `comparisons/` — 5 comparison sheets.

## How they were rendered
`ux_prototypes_e2e_test.go` (`//go:build uie2e`, advisory — never a merge gate)
loads each `file://` prototype in headless Chromium at 1440×900 and screenshots
full-page. Same driver setup as the audit harness:
```
CULVERT_PW_DRIVER_DIR=/path/to/pwdriver CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium-*/chrome-linux/chrome \
PLAYWRIGHT_NODEJS_PATH=/usr/bin/node go test -tags uie2e -run TestUXPrototypes -timeout 15m .
```

## Rendered screens (renders/)
| Screen | States (dark) | Light |
|---|---|---|
| **Command Center** | healthy · needs-attention · killswitch · durability · dpincompat · prodlocked | needs-attention |
| **Investigations / Activity** | table · shadow-drawer · hardfail-drawer · dlp-drawer | shadow-drawer |
| **Rollout & Exposure** | main · blast-radius (modal) | — |
| **Production Qualification** | locked (gate checklist) | — |
| **Emergency Response** | hierarchy · typed-confirm (dialog) | — |
| **Health & Distribution** | durability meters + DP ack matrix | — |

## Comparison sheets (comparisons/)
`compare-overview` · `compare-decisions` · `compare-rollout` · `compare-health` ·
`compare-qualification` — each places the **current** product screenshot (from
`../current/admin-dark/`) beside the **proposed** prototype render.

## Assumptions
- All data is synthetic and illustrative. Tenants are safe names; hashes are
  fake; counts are chosen to exercise a state, not to reflect a real fleet.
- **Production stays locked in every prototype** — no issuer exists in the build;
  the prototypes show the locked banner and expose **no** "qualify" control.
- V1 connectivity is **Model A only**; the gateway connector shows `local-client`.
- **Management MCP is non-mutating** (`mutation off`) in every prototype.
- No connector, DMZ, endpoint-bridge, or transparent-discovery surface is shown.
- Prototypes carry small self-contained JS for state switching only — no real
  behavior, no network, no production logic.

## Components supported by **existing** APIs
(Verified against the audit inventory of `ui_mcp.go` / `ui_mcp_rollout.go`.)
- Command Center posture strip, capability cards, needs-attention, recent activity
  — composed from `GET /api/mcp/overview`, `/health`, `/rollout`, `/distribution`.
- Investigations table + detail drawer — `GET /api/mcp/decisions`,
  `/decision-explain` (the `ExplanationView` already carries evaluated action,
  `execution_state`, reason, rule, decisive condition, revisions, snapshot,
  credential-profile ref + power ceiling, DLP disposition, finding classes).
- Rollout ladder, desired/active triplet, scope summary, evidence — `GET
  /api/mcp/rollout`, `/rollout/scope`, `/rollout/evidence`.
- **Scope editor** — the mutating `PUT /api/mcp/rollout/scope` already exists;
  the prototype only adds the missing GUI (a GUI-parity fix, not new behavior).
- Emergency controls, rehearse rollback, rollback — `POST /api/mcp/rollout/emergency`,
  `/rollout/rehearse-rollback`, `/rollback` (all existing).
- Production Qualification checklist + real/synthetic badge — `GET
  /api/mcp/rollout/evidence` (the `origin` field already exists).
- Health durability meters + runtime — `GET /api/mcp/health`.

## Components that require **additive, read-only** API additions
- **DP acknowledgement matrix** (per-node ack state + reject reason): the current
  `mcpDistributionStatus` DTO exposes only aggregate `distribution_state` + per-
  capability status — it does **not** surface per-node ack rows. Needs an additive
  read endpoint over `publication.AckTracker` (e.g. `GET /api/mcp/distribution/acks`).
- **Blast-radius preview counts** (#affected subjects, #DPs, newly-executable ops
  for a *candidate* scope): needs an additive non-mutating preview endpoint (e.g.
  `GET /api/mcp/rollout/scope-preview`) or client-side computation from the current
  scope + inventory.
- **Entity pivots / related-activity**: additive filter params on
  `GET /api/mcp/decisions` (e.g. `tool_fingerprint=`, `principal=`).
- **`effective_action` / `shadow_override`** as first-class fields on the decisions
  **list** projection (`DecisionView`) if not already present — a read-only field
  addition (the underlying data exists in `rollout.Resolution` / `ExecOutput`).

None of these changes MCP admission, policy evaluation, distribution trust, or the
Production lock. Every mutation shown maps to an already-shipped endpoint.
