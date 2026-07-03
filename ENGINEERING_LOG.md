# Engineering Log — overnight engineering branch

Branch: `claude/overnight-engineering-uc5sld` (based on `main` @ 64363b8).
Newest entry first.

---

## 1. Upstream pool durability: GUI/API changes survive restart

**What changed**
- `UpstreamPool` now retains the raw accepted entries (`Entries()`) and the
  circuit-breaker parameters from the last `Configure`; new `SetProxies`
  replaces the proxy list while keeping those CB params.
- `admin_settings.json` gains `upstream_proxies_saved` (sentinel, mirrors
  `BlocklistFeedsSaved`) + `upstream_proxies`; `applyAdminNetwork` restores the
  pool on startup — including the authoritative empty-list wipe.
- `POST /api/upstream` and the config-import path now call
  `SetProxies` (previously hardcoded CB params `5, 60s`) and persist via
  `adminSettingsSave()`. `apiConfigImport` also gained a single
  `adminSettingsSave()` so ALL imported admin-settings-layer values (rate
  limit, IP filter, block page, conn limit, …) survive restart — import was
  previously runtime-only for that layer.
- `initUpstreamProxy` no longer gated on a non-empty YAML proxy list, so CB
  params and the health-check loop are wired for GUI-added proxies. The
  SIGHUP reload path keeps the non-empty gate (a YAML reload must not wipe
  GUI state) and now shares `resolveUpstreamPoolStartupConfig` instead of
  duplicating the CB-timeout parsing inline.
- `setProxiesLocked` rejects host-less URLs (`parent:3128` without a scheme
  parses opaque and can never be dialed) instead of silently accepting them.

**Why**
Reliability gap logged in `roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md` §5:
upstream changes made in the admin GUI were lost on every container
restart/update, and the API path silently discarded the operator's
circuit-breaker configuration.

**Risks**
- Proxy URLs may embed credentials; they now persist raw in
  admin_settings.json. Deliberate: the file is 0600 and already carries
  secrets (`metrics_token`); display paths keep using redacted `List()`.
- Once any admin API mutation runs, the persisted upstream list becomes
  authoritative over later YAML edits (same semantics as blocklist feeds /
  YARA settings — consistent with the established sentinel design).
- Health-check loop now starts with an empty pool when `health_interval` is
  set (no-op ticks; negligible).

**Validation**
`go build`, `go vet`, full `go test .` (46s) green, full `-race` suite green
(386s), new-issue-scoped golangci-lint (`--new-from-rev=main`) 0 issues,
`-count=2 -shuffle=on` on the touched test surface green. 8 new tests in
`admin_settings_upstream_test.go`.

**Remaining work / follow-ups**
- Cluster `ConfigSnapshot` does not propagate upstream pool config to DP
  nodes (pre-existing; separate design question).
- `apiUpstreamSettings` (GET-only) still exposes no way to edit CB params
  from the GUI — CB stays YAML-owned for now; a GUI-parity endpoint would
  need `saveConfigVersion` + UI panel work.
- Export/import of `UpstreamProxies` remains URL-only and lossy for webhook
  secrets per Finding 10.3 (unchanged surface).
