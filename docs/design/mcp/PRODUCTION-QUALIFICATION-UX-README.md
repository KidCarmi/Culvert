# Production-Qualification UX Audit — Index

A documentation-only UX reconnaissance of the MCP Gateway admin surface, for the
Production-Qualification program. **No production behavior was changed. Production
remains qualification-locked. No connector, DMZ, Management mutation, or
qualification issuer was added.**

**Baseline:** PR #1027 merged; PR-1…PR-11 complete; V1 connectivity = Model A
(`local-client`) only; Management MCP non-mutating.

## Deliverables
| Doc | Phase | Contents |
|---|---|---|
| [PRODUCTION-QUALIFICATION-UX-CURRENT-STATE.md](PRODUCTION-QUALIFICATION-UX-CURRENT-STATE.md) | 4 | Executive summary · contact sheet · screen inventory · nav/workflow maps · Playwright coverage · browser errors · strengths · defects · dangerous ambiguity · missing pivots · terminology · inaccessible controls · missing states · PQ blockers. Every claim cited. |
| [PRODUCTION-QUALIFICATION-UX-TARGET.md](PRODUCTION-QUALIFICATION-UX-TARGET.md) | 5 | Target information architecture — ten workspaces, each with operator question / objects / metrics / columns / filters / pivots / drawer / actions / RBAC / dangerous-action / empty-loading-error-stale / Playwright acceptance. Culvert-clean, not a SOC clone. |
| [PRODUCTION-QUALIFICATION-UX-WIREFRAMES.md](PRODUCTION-QUALIFICATION-UX-WIREFRAMES.md) | 6 | ASCII wireframes A–E (Command Center · Investigation workbench · Rollout & Exposure · Production Qualification · Emergency response) + the end-to-end drill-down path. |
| [PRODUCTION-QUALIFICATION-UX-BACKLOG.md](PRODUCTION-QUALIFICATION-UX-BACKLOG.md) | 7 | PQ-BLOCKER / P0 / P1 / P2 with current screenshot · operator risk · target · affected views · backend impact · Playwright test · effort · dependency · prod-change flag. |
| [PRODUCTION-QUALIFICATION-UX-IMPLEMENTATION-SLICES.md](PRODUCTION-QUALIFICATION-UX-IMPLEMENTATION-SLICES.md) | 8 | 11 small reviewable slices — files · routes · selectors preserved · Playwright tests · API/OpenAPI/GUI-parity · rollback. No framework rewrite. |
| [ux-audit-assets/README.md](ux-audit-assets/README.md) | 2 | Screenshot contact sheet (49 images) + ledger. |

## Top findings (see current-state §9–§13)
1. Eight of nine MCP views render server JSON into a `<pre>` — a developer console, not a product.
2. Evaluated-vs-effective is invisible: a Shadow-executed DENY looks like a block (`mcp-decisions-shadow.png`).
3. Critical state (kill switch, durability-degraded, incompatible DP) is buried in JSON.
4. No blast-radius preview before promotion; scope editing has no GUI at all.
5. No stale-data indicator; `mcp-rollout` isn't even auto-loaded.
6. No investigation pivots / evidence chain — context is retyped by hand between views.
7. Zero pre-existing E2E coverage for any MCP view.

All fixes are presentation/workflow layers over an already-correct engine.

## The audit screenshot harness (advisory, test-only)
Build-tagged `//go:build uie2e`; **never a merge gate**; uses the real handler +
middleware; synthetic fixtures only.

Files: `ux_audit_screens_e2e_test.go`, `ux_audit_run_e2e_test.go`,
`ux_audit_fixtures_e2e_test.go`, `ux_audit_fixtures_data_e2e_test.go`.

Run (Chromium is pre-provisioned; do **not** run `playwright install`):
```bash
# The playwright-go driver is the playwright-core@1.60.0 npm package assembled
# into a driver dir; browsers come from the pre-installed /opt/pw-browsers.
CULVERT_PW_DRIVER_DIR=/path/to/pwdriver \
CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium-*/chrome-linux/chrome \
PLAYWRIGHT_NODEJS_PATH=/usr/bin/node \
go test -tags uie2e -run TestUXAudit_Matrix -timeout 20m .
```
Output: `docs/design/mcp/ux-audit-assets/current/…` + `_ledger.json`.

## Constraints honored
Single-binary · CSP nonce · server-side RBAC · Playwright-Go · no Node runtime
dependency in the shipped binary · stable `data-view`/selectors preserved by the
implementation plan.
