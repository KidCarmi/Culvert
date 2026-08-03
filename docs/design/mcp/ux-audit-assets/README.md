# MCP UX-Audit Assets — Contact Sheet

49 screenshots (4.5 MB, 256-color-quantized PNG) captured against the **real**
`newAdminUIHandler()` middleware chain via the advisory playwright-go harness.
Layout: `current/<role>-<theme>/[responsive/<width>px/]<view>[-<scenario>].png`.

- **admin-dark/** — 33: every MCP view + activity surfaces (baseline, disabled-default)
  and all 15 synthetic operational postures, admin role, dark, 1920×1080 full-page.
- **admin-light/** — 6: light theme for the primary overview + investigation surfaces.
- **operator-dark/** — 3, **viewer-dark/** — 3: RBAC contrast (viewer is denied `mcp-settings`).
- **admin-dark/responsive/1440px, /1280px/** — 2 each: responsive widths.
- **_ledger.json** — per-capture console-error / page-error / failed-request /
  4xx-5xx ledger. **_validate-ledger.json** — the smoke run.

Fixtures are synthetic (safe tenant names, obviously-fake hashes; no tokens/PII/
secrets). See `../PRODUCTION-QUALIFICATION-UX-CURRENT-STATE.md` for the analysis
that cites these files.

## Baseline — admin / dark / 1920 (real, unseeded)
| View | File |
|---|---|
| MCP Overview | admin-dark/mcp-overview.png |
| MCP Servers & Tools | admin-dark/mcp-servers.png |
| MCP Decisions & Explain | admin-dark/mcp-decisions.png |
| MCP Policies & Simulator | admin-dark/mcp-policies.png |
| MCP Approvals | admin-dark/mcp-approvals.png |
| MCP Health & Durability | admin-dark/mcp-health.png |
| MCP Rollout & Execution | admin-dark/mcp-rollout.png |
| Management MCP Access | admin-dark/mcp-management.png |
| MCP Listener Settings | admin-dark/mcp-settings.png |
| Dashboard · Traffic · Audit | admin-dark/dashboard.png · livefeed.png · audit.png |

## Posture scenarios — admin / dark / 1920 (synthetic)
| Scenario | File |
|---|---|
| Healthy install | mcp-overview-healthy.png · mcp-health-healthy.png · mcp-rollout-healthy.png |
| Observe | mcp-rollout-observe.png |
| Shadow + overrides | mcp-rollout-shadow.png · mcp-decisions-shadow.png |
| Canary mixed | mcp-rollout-canary.png · mcp-decisions-canary.png |
| Hard auth failure | mcp-decisions-hardfail.png |
| Unknown/drifted tool | mcp-servers-unknowntool.png |
| Request DLP block | mcp-decisions-dlpblock.png |
| Response DLP redaction | mcp-decisions-dlpredact.png |
| Partial CP→DP ack | mcp-health-partialack.png |
| DP incompatible (min-version) | mcp-health-dpincompat.png |
| Durability degraded | mcp-health-durability.png · mcp-overview-durability.png |
| Emergency kill switch | mcp-rollout-killswitch.png |
| Rollback available | mcp-health-rollback.png |
| Production locked / missing evidence | mcp-rollout-prodlocked.png |
| API failure / degraded backend | mcp-overview-apifail.png |
| Operational approvals (detail) | mcp-approvals-approvals.png |

## RBAC / theme / resolution
| Set | Files |
|---|---|
| Operator | operator-dark/mcp-overview-healthy.png · mcp-rollout-healthy.png · mcp-settings.png |
| Viewer (permission-denied) | viewer-dark/mcp-overview-healthy.png · mcp-rollout-healthy.png · mcp-settings-viewer-denied.png |
| Light theme | admin-light/mcp-overview-healthy.png · mcp-decisions-shadow.png · mcp-rollout-healthy.png · dashboard.png · livefeed.png |
| 1440×900 | admin-dark/responsive/1440px/mcp-overview-healthy.png · mcp-rollout-healthy.png |
| 1280×800 | admin-dark/responsive/1280px/mcp-overview-healthy.png · mcp-rollout-healthy.png |
