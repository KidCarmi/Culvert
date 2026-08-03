# MCP UX Production Integration

Real-product integration of the independently-approved MCP UX
(`APPROVED FOR IMPLEMENTATION`, audit branch `e6204d6`). Built on a fresh branch
from main (`e0c2935`), not on the audit branch. The prototypes are a visual and
interaction specification only; no prototype HTML, JS, fixtures, or state-switching
logic is copied into the product.

Non-negotiables held throughout: single binary, no Node runtime, vanilla-JS single
file SPA, CSP nonce model, no inline event handlers (delegated `data-click`),
server-side RBAC (`requireRole`) unchanged, `uiRoutes` and route-count parity,
Playwright-Go, MCP capability separation, and Production stays qualification-locked
(no issuer, no receipt, no enable). No connector, DMZ, or Management mutation added.
No em dash characters in new UI copy or docs.

Scope is strictly the nine MCP views. No non-MCP screen is redesigned.

## Shipped: PR-UX-1 (shared primitives) + PR-UX-2 (Command Center and Activity)

Delivered together because the two safety-critical screens exercise the primitives.

- **PR-UX-1 primitives** (`static/index.html`, namespaced `mcpx-*`): status chips,
  desired/local/fleet triplet, as-of stamp, operator labels for internal
  reason/distribution tokens, non-color severity tokens, honest empty/error/
  permission-denied states, focus-visible ring, `aria-live` regions. CSS reuses the
  existing design tokens; JS builds DOM with `createElement` + `textContent`
  (XSS-safe), reads only `/api/mcp/*`.
- **PR-UX-2 Command Center** (`#view-mcp-overview`): posture strip, Gateway and
  Management capability cards with the state triplet, and a needs-attention list.
  Every value is derived from live `GET /api/mcp/overview`, `/rollout`, and
  `/distribution`. Fleet-effective shows `local only` honestly when
  `distribution_state = local_only`; node counts are never invented.
- **PR-UX-2 Activity** (`#view-mcp-decisions`): a structured activity table from
  `GET /api/mcp/decisions` where a Shadow-executed policy DENY renders as
  `DENY to executed (shadow) ! override` and can never read as a plain ALLOW; a
  right-side evidence drawer from `GET /api/mcp/decision-explain` showing only
  `ExplanationView` fields. `effective_action` and `shadow_override` are derived
  client-side from the stored `action` + `execution_state` (no new telemetry).

### Truthfulness (no-mock proof)
- No fabricated data ships. Latency, upstream HTTP status, DP-node attribution, and
  environment are not shown (the durable event store does not keep them).
- Quarantine and revoke are not offered as actions (no endpoint in V1); the drawer
  says so in disclaimer text but exposes no such button.
- Pending-approval and recent-change feeds, and the per-node DP acknowledgement
  matrix, are intentionally deferred to later slices with their additive read-only
  endpoints; they are not faked here.
- The legacy raw-JSON `<pre>` for each view is retained inside a collapsed
  `<details>` (id preserved) so existing tests keep resolving during migration.

### Preserved selectors and contracts
`.nav-item[data-view="mcp-overview"|"mcp-decisions"]`, `#view-mcp-*`,
`#mcp-overview-out`, `#mcp-decisions-out`, `#mcp-dec-tenant`, `#mcp-dec-event`,
`data-min-role`, delegated `data-click` dispatch (new cases added, none removed).
No routes added or changed in this PR, so `uiRoutes` and route-count parity hold.

### Tests
`ui_mcp_ux_e2e_test.go` (`//go:build uie2e`, advisory): drives the real handler +
render code with synthetic API responses (tests may use fixtures; the shipped UI
may not). Asserts the structured Command Center, the evaluated-to-effective
two-chip model (shadow DENY never reads as ALLOW), the truthful drawer (no
fabricated fields, no quarantine/revoke buttons), the empty and permission-denied
states, and zero uncaught page exceptions. Screenshots: dark and light, 1280 /
1440 / 1920, under `ux-audit-assets/production/`.

Regression: build clean; route/metadata parity (C1, C1.5), RBAC/enforcement (C2,
C4), D0 baseline, and MCP handler tests pass. Em-dash scan of new copy: 0. No
secrets in the diff.

### Rollback
Revert this commit. The change is additive presentation over unchanged handlers
and routes; there is no data migration, no API change, and no behavior change to
MCP admission, policy, distribution, or the Production lock. The legacy raw-JSON
panels remain available under each view's `<details>` immediately on revert.

## Remaining sequence (not yet implemented)
PR-UX-3 entity pivots + evidence-chain (additive decision entity filters);
PR-UX-4 dangerous-action dialog standard; PR-UX-5 rollout ladder + scope editor +
blast-radius preview + DP ack matrix (additive `GET /api/mcp/distribution/acks`,
`POST /api/mcp/rollout/scope-preview`); PR-UX-6 qualification checklist +
publications; PR-UX-7 structured servers/tools/health/management/config; PR-UX-8
deep-linking + a11y + responsive + token alignment. Each ships with its own
tests, screenshots, API/OpenAPI parity where relevant, and an independent review.
