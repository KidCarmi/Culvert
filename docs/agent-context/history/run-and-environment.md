# Preserved source: Run And Environment

Historical evidence from main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, not current architectural authority.
Read the [current task routes](../README.md) and [verified errata](../errata.md) first.
No benchmark, status, location or instruction in these blocks is independently revalidated by moving it here.
Links inside preserved text retain their original spelling and source-root context; use each pinned source link to follow original references.
Do not import this file into startup instructions.

## Topics

- [Run](#claude-main-l101-l113)
- [Environment](#claude-main-l114-l128)

<a id="claude-main-l101-l113"></a>

## Run

[Original lines 101–113](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L101-L113) · `claude-main-L101-L113`

<!-- BEGIN preserved-block: claude-main-L101-L113 -->
## Run

```bash
# Minimal
./culvert -port 8080 -ui-port 9090

# With SSL inspection
CULVERT_CA_PASSPHRASE=mysecret ./culvert -port 8080 -ui-port 9090 -ca-path /data/ca.bundle

# Docker
docker compose up -d
```

<!-- END preserved-block: claude-main-L101-L113 -->

<a id="claude-main-l114-l128"></a>

## Environment

[Original lines 114–128](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L114-L128) · `claude-main-L114-L128`

<!-- BEGIN preserved-block: claude-main-L114-L128 -->
## Key Environment Variables

- `CULVERT_CA_PASSPHRASE` — CA private key encryption passphrase (required for SSL inspect)
- `CULVERT_DATA_DIR` — startup-scoped override of the persisted-state root (`dataDir`, default `/data`: admin settings, object stores, PAC profiles, CDR state, config versions, audit/log stores, backup/restore/prepare-downgrade). The defaults that were historically literal `/data/...` values — the config-version store, `registry_settings.json`, the CDR certs root and `cdr_enabled` marker, the alert retry queue, the CDR store files, the reset-password roster default — are re-bound to the effective root by `rebindDataDirPaths` in the same step (PR-C1b), so an override moves ALL persisted state, never part of it. Unset/blank ⇒ `/data`, byte-identical to a build without the override; otherwise an ABSOLUTE, cleaned, non-root path (a relative path or `/` is FATAL at boot — booting on the default while the operator asked for another root would persist state where nobody looks). Read ONCE in `main()` before flag parsing and before any one-shot command (`applyDataDirFromEnv`, `data_dir.go`), so every consumer sees one value for the life of the process; logged once at startup when overridden. Env-only and startup-scoped — a recorded GUI-parity deferral of the same class as the HA-lease endpoints (the root cannot be moved by the process persisting into it). Added in the Batch 2 PR correction round (PR-C1): the real-binary browser smoke depended on a writable `/data`, which a CI runner's unprivileged user does not have, so every `/data`-backed mutation answered `persist_failed`/503 while root-run qualification passed; `frontend/scripts/e2e-smoke.sh` now gives each appliance instance its own root under the harness tmp dir (hermetic on any host, for any user).
- `CULVERT_C2_ENFORCE` — C2 metadata-driven RBAC mode. Default = enforce (fail-closed). Set to `false`/`0`/`no`/`off` to revert to shadow (log-only) mode without rebuild. Read once at startup.
- `CULVERT_EXPERIMENTAL_UI` — arms the new React/TypeScript admin frontend (`frontend/`, ADR-FE-001) at `/app/` + `/assets/`. Default OFF (unset ⇒ both routes 404, byte-identical to a build without the feature); the legacy `static/index.html` keeps serving `/` regardless. Read once at startup (`ensureFrontendV2`, `ui.go`); no YAML/CLI equivalent — development/preview flag only, not yet a supported production surface (see `docs/design/FRONTEND-MIGRATION-PLAN.md`). Report-only `frontend_v2` row on `/ready` when armed.
- `CULVERT_CLUSTER_GRPC_COMPRESSION` — opt-in gzip on the CP↔DP config-sync gRPC stream. Default **off** (fail-safe): only `true`/`1`/`yes`/`on` enable it. When off, the raised `maxClusterGRPCMsgSize` (128 MiB) frame alone carries a full ConfigSnapshot uncompressed (a 2 M-host blocklist ≈ 60 MiB), so large snapshots sync without compression. Enabling it makes the DP send every RPC gzip-encoded — safe **only after every CP in the fleet runs a build that registers the gzip codec** (the CP always accepts + echoes gzip but never requires it, so this is a CP-first migration; a DP-first flip against an un-upgraded/rolled-back CP would fail every RPC with `Unimplemented`). Startup-scoped, read once (recorded GUI-parity deferral — same class as the HA-lease endpoints and `-cluster-insecure`). The resolved value is surfaced read-only on `GET /api/cluster/status` (`grpcCompressionEnabled`) and the Cluster panel, same status-only precedent as the HA Fencing Lease card, so an operator can confirm the effective setting without SSH.
- `CULVERT_RELEASE_CATALOG_TRUST_KEYS` — JSON array of **public** ed25519 release-catalog trust roots (`[{"key_id","alg":"ed25519","public_key":"<base64>"}]`) that EXTEND the baked roots (`bakedReleaseTrustKeysJSON`, linker-injected at official-build time). Public keys only — never private signing material.
- `CULVERT_RELEASE_CATALOG_VERIFY` — release-catalog signature mode. Default = enforce whenever any trust root (baked or configured) is present; with no roots and no override Release Management is DISABLED (unsigned catalogs are never auto-trusted). Set to `permissive` (accept unsigned; still reject a present-but-invalid signature) or `disabled` (skip verification) only as a deliberate, logged **break-glass**. Read once at startup.
- `CULVERT_RELEASE_CATALOG_URL` — **operator OVERRIDE** of the catalog origin (M1-2 product revision: the appliance has a CANONICAL BUILT-IN default, `https://catalog.culvertlabs.com/release-catalog` — a normal customer configures nothing). Set it only for air-gapped deployments, internal mirrors, staging/test, or regional/private distribution; empty/unset ⇒ the baked default; `off`/`none`/`disabled` ⇒ NO outbound fetch (the trust-SAFE opt-out — verification stays fully enforced on any on-disk catalog, so silencing the fetch never requires relaxing `CULVERT_RELEASE_CATALOG_VERIFY`), surfaced as `catalog_url_source:"disabled"`. **The origin never affects trust** — verification (baked roots + pinned identity, enforce mode) is identical for default and overridden origins, and changing the URL cannot change trusted signing identities/roots. Effective origin host + source (`default`/`override`/`disabled`) + refresh cadence + last-refresh outcome surfaced read-only on `/api/releases` (`catalog_origin`, `catalog_url_source`; the full URL is shown only for the public default — an override may carry presigned credentials) and in the admin Release Management panel. A boot-time seed failure is folded into `last_refresh` as trigger `startup` (immediate visibility, no ~6h blind window). SSRF guard still rejects private-IP origins (recorded constraint for internal mirrors). In enforce mode, the Control Plane fetches + verifies the signed catalog at startup (signature + freshness + rollback, read-only) and atomically installs it into `<dataDir>/release_catalog/`; any failure leaves the existing catalog untouched (fail closed). Verification is in the binary (`release_autoseed.go`); the installer only forwards the env (never bakes a default). Auto-seed never runs in break-glass permissive/disabled. Read once at startup.
- `CULVERT_RELEASE_REFRESH_INTERVAL` — periodic production catalog-refresh cadence (M1-2). Go duration (default `6h`, ±10% jitter, min clamp `1m`); the loop runs only when a catalog origin is in effect AND in enforce mode, drives the SAME verified auto-seed seam as the manual `POST /api/releases/catalog-refresh` (shared `refreshStatus`; fail-closed — a failed tick leaves the catalog untouched), and stops on shutdown. When the refresh loop does NOT run (fetch disabled via `off`/`none`/`disabled`, or break-glass verify modes), a standalone detection-only stale watchdog (CHAOS-23, `runCatalogStaleWatchdogLoop`) ticks at the same resolved cadence so `release_catalog_stale` stays live at runtime — exactly one watchdog driver per process (`startReleaseDetectionLoop`). Unset/typo ⇒ default (fail-safe: a typo must not disable the freshness loop). Env-only (CULVERT_RELEASE_* family precedent); cadence + `last_refresh` surfaced read-only on `/api/releases`. **M1-3 detection rides this loop** (`release_alerts.go`): alerts `release_catalog_stale` (installed catalog expires <30d — the 180-day freshness watchdog), `release_catalog_refresh_failing` (3 consecutive failures), `release_catalog_recovered` — each fires ONCE per threshold crossing (RT-H2 latches on `releaseManager` under `statusMu`; reset on restart, documented); stale is also evaluated once at startup via `deferStartupAlert`. Metrics: `culvert_release_catalog_refresh_total{result}` + scrape-time `culvert_release_catalog_expires_in_seconds` (omitted when no catalog). `/api/releases` adds `expires_in_days`; the Release panel shows it with warn color inside the 30d threshold. Thresholds are constants (recorded deferral).
- `CULVERT_RELEASE_SIGSTORE_IDENTITY` — OPTIONAL operator override for the pinned **keyless** (Sigstore-identity) trust policy (P2b), JSON `{"issuer","san_regex"}`. Unset ⇒ the baked official identity (issuer = the GitHub Actions OIDC issuer; SAN anchored to a tagged release of this repo's workflow). Break-glass / fork-mirror only; env-only (GUI-parity deferral, same as the other `CULVERT_RELEASE_*` vars). Read once at startup.
- `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT` — OPTIONAL path to a custom Sigstore TUF `trusted_root.json` (P2b). Unset ⇒ the baked embed (`trusted_root.json`, the REAL Sigstore public-good root as of P2b-2a, so the keyless scheme is ACTIVE by default — see the P2b-2a Architecture Note below; point this at an empty file to deactivate). **PUBLIC** trust material only — never private signing keys. Read once at startup.
- `CULVERT_MCP_DISTRIBUTION_TRUST_KEYS` — PR-12 DP verify-trust for the signed MCP CP/DP distribution path (`initMCPDistribution`, `mcp_distribution_startup_config.go`). JSON array of **PUBLIC** ed25519 roots in the SAME shape as `CULVERT_RELEASE_CATALOG_TRUST_KEYS`: `[{"key_id","alg":"ed25519","public_key":"<base64-raw-32-byte-key>"}]`. PUBLIC material only (a private signing key is never provisioned to a DP). Unset or empty ⇒ MCP CP/DP distribution stays DISABLED (no DP applier is composed, `applySnapshotMCP` is a no-op, a received ConfigSnapshot is byte-identical to the pre-PR-10 SWG snapshot). A present-but-invalid value fails CLOSED to disabled (never composes an applier that trusts nothing or the wrong key). When a valid trust store is provisioned, the shim composes the Gateway and Management DP appliers (physically isolated, durable state under `<dataDir>/mcp_distribution/`, `Recover` at startup, then rollout reconciliation), so a signed rollout envelope reaches the durable rollout commit path and an executing-mode transition fails closed at the execution-dependency gate. Env-only crypto trust with a recorded GUI-parity deferral (same precedent as the `CULVERT_RELEASE_*` trust-key vars and the HA-lease endpoints); effective composition state (`dp_composed`, `dp_compose_reason`, PUBLIC `dp_trust_key_ids`) is surfaced READ-ONLY on `GET /api/mcp/distribution`. Read once at startup.

<!-- END preserved-block: claude-main-L114-L128 -->
