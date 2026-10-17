# Culvert Language & Terminology Governance Review — 2026-10-17

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot:** `origin/main` at `dec66e1`. Targeted review of the surfaces changed since the
> 2026-09-24 report's snapshot `6ec745d` (128 files, 79 first-parent merges). Backlog IDs T-9..T-63
> remain owned by earlier reports and are not re-verified or re-scored here.

## Executive Summary

The window's new admin-facing names are consistent with existing vocabulary (backups, rollback scope,
SOCKS5 bind-health metrics, DP-bootstrap refusal counters). **One new finding (T-64)**, fixed in this PR:
the legacy GUI still called the deprecated destination-privacy alias after T-17 made
`/api/traffic/redaction` canonical. Terminology Health Score: not re-scored (the series' lineage
figure is disputed between reports); T-64 is opened and closed in the same change, so it adds no open item.

## T-64 — Legacy GUI calls the deprecated alias (Medium / Low migration risk)

| Field | Value |
| --- | --- |
| Business concept | Traffic-log destination privacy (host/SNI pseudonymization posture) |
| Current names | `/api/traffic/redaction` (canonical, T-17), `/api/decryption/redaction` (deprecated alias) |
| Recommended canonical name | `/api/traffic/redaction` (unchanged; callers move to it) |
| Problem | `docs/operator/traffic-log-destination-privacy.md` and `ui_routes_meta.go` call the traffic path canonical, yet the GUI that operators use called the alias. Access logs, API traces and support captures therefore show the deprecated name, and the alias can never be retired. |
| Affected code | `static/index.html` `loadDecRedaction`, `toggleDecRedaction` (**fixed here**); `frontend/src/api/decryption.ts` (3 calls) — **not fixed, see below** |
| Affected API | None; both paths stay served by one handler (`ui_policy.go:3109`) |
| Affected GUI | Legacy decryption-health toggle (fixed); React Decryption page (open) |
| Affected docs / config | None |
| Migration complexity / compat risk | Low / none (same handler, same wire contract; the alias is retained) |
| PR size | Fixed part: 2 lines. Remaining React part: ~3 source lines plus URL assertions in 6 vitest files and 2 e2e specs |

**Open remainder:** `frontend/src/api/decryption.ts` and its tests still use the alias. `frontend/dist/` is
tracked and must be rebuilt with the pinned Node toolchain, which this run did not have, so the React
client is left for a follow-up PR (rebuild dist, update the test and e2e URLs). Once both GUIs use the
canonical path, the alias can be deprecated with a `Deprecation` header per the T-17 plan.

## Checked and left alone

- `/api/config/rollback-scope`, `/api/backups*`: names match their GUI and OpenAPI wording.
- `culvert_socks5_unavailable`, `culvert_socks5_bind_*`: consistent with the existing
  `culvert_socks5_listener_*` family.
- `security.ip_filter_mode` (`allow`/`block`) vs `default_action` (`allow`/`deny`): already tracked as T-11.
- `culvert_auth_backend_*` vs `identity_backend_unreachable`: already tracked as T-61.

Verification: `go test -run 'Redaction|UIRoutes|Parity|StaticIndex|GUI|Legacy' .` passes. No Go code changed.
