# Culvert

Enterprise-grade open-source HTTP/HTTPS/SOCKS5 forward proxy written in Go.
Single binary, zero runtime dependencies.

## Project Structure

```
*.go          — package main: composition roots, HTTP/API handlers, and thin shims over internal/
internal/     — 44 packages (ADR-0002 decomposition, COMPLETE): 39 extracted engines + 4 seams (obs, fileutil, hostutil, ssrf) + halease (ADR-0005 fencing lease). Engines own logic/state/persistence; main keeps singletons, aliases, and wiring. New engines go here with a recorded design; do not re-inline them.
main.go       — Entrypoint, flag parsing, signal handling, graceful shutdown
proxy.go      — HTTP/CONNECT/WebSocket handlers, tunnel relay, upstream transport, sanitizeLog
socks5.go     — SOCKS5 protocol handler (RFC 1928/1929)
policy.go     — Policy engine: rule evaluation, FQDN/category/GeoIP/schedule matching (URL-category store → internal/urlcat, SSL-bypass matcher → internal/sslbypass, FQDN glob → hostutil.MatchFQDN per ADR-0002; two-tier matchCategory/lookupHostCategory fusion stays here)
store.go      — Composition root: stats/ts counters, auth Config, recordRequest* fan-out (blocklist → internal/blocklist, audit → internal/audit, request log → internal/reqlog per ADR-0002; shims/aliases in blocklist_vars.go + the audit/request-log sections)
ca.go         — Root CA management, leaf cert signing, encrypted CA bundle (AES-GCM + PBKDF2), LRU cert cache
ui.go         — startUI bootstrap only (no direct mux.HandleFunc; routes registered via register*Routes helpers)
ui_routes_meta.go — uiRoutes: single source of truth for route metadata (method-aware via Methods []uiRouteMethod)
ui_metadata_enforcement.go — C2 metadata-driven middleware (MinRole enforcement + AuditExpected observability)
ui_auth.go / ui_config.go / ui_policy.go / ui_security.go / ui_cluster.go / ui_static.go / cdr_ui.go / pac.go / update.go / diagnostics.go — per-domain register*Routes helpers + handlers
ui_helpers.go — auditEvent / auditEventDiff / decodeJSON / shared validators
ui_middleware.go / ui_session.go / ui_rbac.go — middleware chain, session cookies, RBAC helpers
session.go    — HMAC-SHA256 signed session cookies, revocation list, dynamic Secure flag
auth.go       — Local bcrypt auth
auth_ldap.go  — LDAP bind + search auth with group resolution
auth_oidc.go  — OIDC token introspection (RFC 7662)
auth_oidc_flow.go — Full OIDC Authorization Code + PKCE flow
auth_saml.go  — SAML 2.0 SP via crewjam/saml
auth_idp.go   — Multi-IdP registry, validateExternalURL
identity.go   — Identity model (Sub, Groups, Source)
clam.go       — ClamAV INSTREAM scanner
yara_scan.go  — Pure-Go YARA rule engine
scanner.go    — Unified DPI + ClamAV + YARA scan coordinator
security.go   — Security helpers: SSRF wrappers over internal/ssrf + IP filter + header scrub
security_scan.go — Scan-orchestrator shim: adapters + wrappers over internal/secscan (ADR-0006)
fileblock.go  — File extension/MIME blocking profiles
fileprofile.go — Named file-type blocking profiles (Executables, Archives, etc.)
geoip.go      — MaxMind GeoLite2 country lookup with background cache
controlplane.go — gRPC-based Control Plane / Data Plane distributed architecture
enrollment.go — Token-based node enrollment, ClusterStore, cluster CA, heartbeat monitor
upstream.go   — Upstream proxy chaining with failover, circuit breaker, round-robin health checks
ocsp.go       — OCSP shim: transport wiring over internal/ocsp (ADR-0002)
metrics.go    — Prometheus metrics (culvert_* namespace, per-rule hit counters, latency histogram)
connlimit.go  — Per-IP connection limiting and X-Request-ID generation
alerts.go     — Alerts shim: aliases + singleton + fireAlert/retry-loop wrappers over internal/alerts (ADR-0002; delivery engine + RISK-003 secret encryption live in the package)
threatfeed.go — Threat-feed shim: alias + singleton over internal/threatfeed (ADR-0002; URLhaus/OpenPhish, domain allowlist)
feedsync.go   — Feedsync shim: aliases over internal/feedsync (ADR-0002)
blocklist_feed.go — Blocklist-feed shim: aliases over internal/blocklistfeed (ADR-0002; Merger iface + ssrf seam)
rewrite.go    — HTTP header rewrite rules (per-host, wildcard)
plugin.go     — Plugin shim: aliases over internal/plugin (ADR-0002)
logger.go     — Rotating file logger with JSON mode
syslog.go     — Syslog SIEM forwarding (UDP/TCP, RFC 3164)
config.go     — YAML + CLI flag configuration (goccy/go-yaml)
pac.go        — PAC shim: handlers + routes over internal/pac (ADR-0002)
hashcache.go  — SHA-256 scan result cache with TTL
lockout.go    — Brute-force lockout (IP + user)
totp.go       — TOTP 2FA (RFC 6238, inline stdlib HMAC-SHA1, no external dep)
tls.go        — UI-TLS shim: uiExtraSANs + wrapper over internal/uitls (ADR-0002)
blockpage.go  — Block page HTML template
events.go     — SSE shim: broadcaster + apiEvents + /metrics exposition over internal/sse (ADR-0002; hub engine lives in the package)
catdb.go      — URL category database
configversion.go — Config versioning, snapshots, diff, rollback (50-version max)
nodegroup.go  — Node group definitions with label selectors, priority-based matching
bandwidth.go  — Per-group bandwidth/QoS policies with token bucket rate limiting
bootstrap.go  — Bootstrap shim: token-gated HTTP handlers over internal/bootstrap (ADR-0002; templates + image refs + URL helpers live in the package)
update.go     — Self-update system (binary + Docker)
update_cluster.go — Rolling cluster update orchestrator (canary, drain, HA sync)
scan_remote.go — Remote scan sidecar for production sandboxing
```

## Build & Test

```bash
go build -o culvert .                       # build binary
go test ./...                               # run all tests
go test -race -count=1 -timeout=15m ./...   # race detector (CI mode)
go test -coverprofile=coverage.out ./...    # coverage report
```

## Run

```bash
# Minimal
./culvert -addr :8080 -ui-addr :9090

# With SSL inspection
CULVERT_CA_PASSPHRASE=mysecret ./culvert -addr :8080 -ui-addr :9090 -ca-bundle /data/ca.bundle

# Docker
docker compose up -d
```

## Key Environment Variables

- `CULVERT_CA_PASSPHRASE` — CA private key encryption passphrase (required for SSL inspect)
- `CULVERT_C2_ENFORCE` — C2 metadata-driven RBAC mode. Default = enforce (fail-closed). Set to `false`/`0`/`no`/`off` to revert to shadow (log-only) mode without rebuild. Read once at startup.
- `CULVERT_RELEASE_CATALOG_TRUST_KEYS` — JSON array of **public** ed25519 release-catalog trust roots (`[{"key_id","alg":"ed25519","public_key":"<base64>"}]`) that EXTEND the baked roots (`bakedReleaseTrustKeysJSON`, linker-injected at official-build time). Public keys only — never private signing material.
- `CULVERT_RELEASE_CATALOG_VERIFY` — release-catalog signature mode. Default = enforce whenever any trust root (baked or configured) is present; with no roots and no override Release Management is DISABLED (unsigned catalogs are never auto-trusted). Set to `permissive` (accept unsigned; still reject a present-but-invalid signature) or `disabled` (skip verification) only as a deliberate, logged **break-glass**. Read once at startup.
- `CULVERT_RELEASE_CATALOG_URL` — OPTIONAL http(s) origin for verified catalog auto-seed (P1.7). When set AND in enforce mode, the Control Plane fetches + verifies the signed catalog at startup (signature + freshness + rollback, read-only) and atomically installs it into `<dataDir>/release_catalog/`; any failure leaves the existing catalog untouched (fail closed). Verification is in the binary (`release_autoseed.go`); the installer only forwards the env (never bakes a default). Auto-seed never runs in break-glass permissive/disabled. Read once at startup.
- `CULVERT_RELEASE_SIGSTORE_IDENTITY` — OPTIONAL operator override for the pinned **keyless** (Sigstore-identity) trust policy (P2b), JSON `{"issuer","san_regex"}`. Unset ⇒ the baked official identity (issuer = the GitHub Actions OIDC issuer; SAN anchored to a tagged release of this repo's workflow). Break-glass / fork-mirror only; env-only (GUI-parity deferral, same as the other `CULVERT_RELEASE_*` vars). Read once at startup.
- `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT` — OPTIONAL path to a custom Sigstore TUF `trusted_root.json` (P2b). Unset ⇒ the baked embed (`trusted_root.json`, EMPTY in the open-source tree, so the keyless scheme is DORMANT until P2b-2 bakes the official root). **PUBLIC** trust material only — never private signing keys. Read once at startup.

## Code Conventions

- **Package**: Everything is `package main` (flat layout)
- **Go version**: 1.25 (go.mod pinned to 1.25.11 for govulncheck — fixes GO-2026-5039 in net/textproto and GO-2026-5037 in crypto/x509; previously 1.25.10 for GO-2026-4982 in html/template)
- **Logging**: Use `logger.Printf()`, never `log.Printf()` or `fmt.Printf()`
- **User input in logs**: Wrap with `sanitizeLog(s)` and use `%q` format verb (CWE-117 prevention; sanitizeLog uses strings.ReplaceAll which CodeQL recognises)
- **CodeQL compliance**: For values that flow through objects (e.g. `rl.Limit()`, `added.Priority`), inline `strings.ReplaceAll` or `fmt.Sprintf` + `strings.ReplaceAll` at the call site so CodeQL sees the sanitiser
- **SSRF guards**: Inline `url.Parse` + scheme check + `isPrivateHost()` before outbound HTTP requests so CodeQL can verify the guard; do not rely solely on wrapper functions like `validateExternalURL()`
- **HTTP contexts**: Use `http.NewRequestWithContext()`, never bare `http.NewRequest()`; use `HandshakeContext()` not `Handshake()`; use `DialContext()` not `DialTimeout()`
- **Errors**: Return `fmt.Errorf("context: %w", err)` for wrapping
- **Concurrency**: Use `sync.RWMutex` for read-heavy stores, `atomic` for counters
- **Security**: SSRF checks via `isPrivateHost()` before any outbound dial
- **Tests**: Test files use `_test.go` suffix, same package (whitebox)
- **Lint suppressions**: Use `//nolint:errcheck` with reason comment; `// #nosec G402` for gosec
- **GUI parity**: Every new CLI flag or config option MUST have a corresponding admin API endpoint AND a UI panel/section so the user can manage it from the GUI. CLI-only features are not acceptable — the admin must have full control from the web interface.
- **API pattern**: Admin API handlers follow `apiXxx(w, r)` naming, registered through `register*Routes` helpers and represented in `uiRoutes` metadata (`ui_routes_meta.go`). Use `requireRole(w, r, "admin")` for write operations, `requireRole(w, r, "viewer")` for reads — handler-level RBAC stays as defense-in-depth even with C2 active.
- **UI pattern**: SPA panels in `static/index.html` use `data-view="name"` attributes. New panels need a nav-item in the sidebar, a view div, and JS load/render functions.
- **Config versioning**: Config-mutating API handlers must call `saveConfigVersion(actor, action)` after `auditEvent()` to create automatic snapshots.
- **Range iteration**: Use index-based range (`for i := range slice`) for large structs (PolicyRule 240 bytes, EnrolledNode 176 bytes) to avoid `rangeValCopy` gocritic warnings.
- **gosec G117**: Avoid struct field names or JSON tags matching secret patterns (e.g. `secret`, `password`, `token`). Rename to non-matching names (e.g. `SessionHMAC` instead of `SessionSecret`).
- **gosec G124**: When cookies use dynamic `Secure` flag (e.g. `isSecureRequest(r)`), suppress with `// #nosec G124 -- dynamic Secure flag`.
- **Cyclomatic complexity**: Keep functions under cyclop threshold of 15. Extract helpers for complex switch/if chains.
- **`upstreamTransport` is read-only after publication**: the shared upstream `*http.Transport` is owned by `upstream_transport.go` (P5.3 / S6). Read via `getUpstreamTransport()`. Mutate via `swapUpstreamTransport(update)` only — the update closure builds a NEW `*http.Transport` (use `cloneTransport` + `cloneTLSConfig`) and MUST NOT mutate its input. Direct field assignment on a loaded transport (`getUpstreamTransport().Proxy = …`, including the local-variable bind form `t := getUpstreamTransport(); t.Proxy = …`) is forbidden — it races against the proxy hot path's reads.

## CI Pipelines

Lane architecture (authority: `roadmap/CI-REDESIGN.md`). **The required merge
checks are `✅ Fast PR Gate — APPROVED` and `✅ Deep PR Gate — APPROVED`** —
if a PR is red, look at those two first. The QA/Security gate check names on
PRs are pass-through shells kept for branch-protection continuity; both run
fully on main pushes (and the Security gate on tags + weekly cron).

- `pr-fast-gate.yml` — **Lane A, required on every PR**: fmt/vet/build (+arm64 compile, static assert, tidy check), diff-scoped golangci-lint, THE single full `-race` run owning both coverage contracts (55% global + per-file floors), benchgate, govulncheck+gosec, gitleaks (even docs-only PRs), path-gated maint-agent checks, advisory traffic smoke
- `pr-deep-gate.yml` — **Lane B, required-if-triggered** (diff-classified): build-image-once → trivy scan + compose validation, hadolint, staticcheck, determinism (any `*_test.go` change), go-licenses on dep changes, packaging (shellcheck/visudo/systemd)
- `ci.yml` — main/tag path: build, compose smoke, multi-arch docker publish + cosign, catalog gate, auto-tag (waits for BOTH gate approvals on the SHA before tagging), release + SLSA provenance. Workflow name `CI` is load-bearing (`publish-catalog-pages.yml` triggers on it — do not rename)
- `qa-gate.yml` / `security-release-gate.yml` — full functional QA / 10-check security scan on main pushes, tags (security), and weekly cron (security); pass-through on PRs
- `codeql.yml` — CodeQL SAST: main pushes, weekly, and PRs touching the proxy/security/release surface
- `code-review.yml` — advisory PR DX: reviewdog inline lint, PR-size, conventional commits
- Nightly/weekly: `fuzz-nightly.yml` (Mon/Wed/Fri coverage-guided fuzzing), `proxy-nightly-e2e.yml` (load), `proxy-weekly-stress.yml`, `proxy-ui-e2e.yml` (playwright), `auth-idp-interop.yml`, `install-lifecycle-e2e.yml` + `maint-agent-*-e2e.yml` (installer/agent e2e — nightly + installer-surface PRs)

## Architecture Notes

- **Default deny**: Policy engine defaults to deny when no rule matches (Zero Trust)
- **SSL inspect**: MITM via on-the-fly leaf certs signed by internal CA (ECDSA P-256)
- **Cert cache**: LRU eviction at 10k entries, 1h TTL
- **Hop-by-hop**: Dynamic stripping per RFC 7230 (parses Connection header for additional hop-by-hop names)
- **Relay pattern**: All tunnel relays (CONNECT, WebSocket, SOCKS5) wait for BOTH goroutines; CloseWrite unblocks peers. Shared `relayCounted`/`bidiRelayCounted` (proxy.go) do the byte-counted bridge for the WS + CONNECT-bypass paths.
- **Raw-tunnel accounting**: WebSocket, CONNECT-bypass, SOCKS5, and the SSL-inspect non-TLS fallback relays emit a `TUNNEL_CLOSED` request-log entry (INFO level) at close — per-connection `BytesSent`/`BytesRecv` + `DurationMs` (new `Entry` field), matched rule, and identity. The bytes/log split is deliberate: `recordTunnelBytes` folds the relayed bytes into `statBytesSent`/`statBytesRecv` **always** (raw tunnels were previously invisible in the bytes dashboard), while `persistTunnelClose` writes the feed entry. `recordTunnelCloseGated` (store.go) counts bytes unconditionally then gates ONLY the feed entry on the per-rule "log traffic" flag — a quiet rule suppresses the entry but still counts bytes. `recordTunnelClose` (SOCKS5 + tests) does both unconditionally. Log-only for stats (the connection was stats-counted at allow time; re-running the fan-out would double-count statTotal/topHosts). `handleWebSocket` also runs `scrubForwardedHeaders` before forwarding (it re-writes the request via `r.Write`, so `X-User-Identity` must be stripped like every other forward path).
- **GeoIP policy**: Fails closed on cache miss (unknown country = rule does not match)
- **Admin RBAC**: Three roles — admin (full), operator (write), viewer (read-only)
- **Session**: HMAC-SHA256 signed cookies with configurable TTL (default 8h); dynamic Secure flag based on TLS state
- **Slowloris**: 60s read deadline on SSL-inspected client connections
- **Audit actor**: Enriched with authenticated admin identity from session cookie
- **Threat feed allowlist**: Popular hosting domains (GitHub, Google Drive, etc.) are exempt from domain-level blocking; URL-level blocking still applies. Managed via admin API + UI, persisted in threat feed DB.
- **Default authentication (`defaultAuthOutcome`)**: the global Stage-1 default (`Default` = require auth on no-match / `Exempt` = open unmatched traffic) is the SOLE source of truth for runtime, UI, API, simulator, cluster, and diagnostics; it survives restarts via the `default_auth_outcome` field in the `ui_users.json` envelope. `UnauthMode` is fully retired (Slice 5): there is no `UnauthMode()`/`SetUnauthMode()` shim. `AuthEnabled()` is credential-only (a local user or external provider exists); `IsConfigured()` (= `AuthEnabled()` OR Exempt) carries "setup complete" for the admin-UI/setup gates, so open mode keeps the admin UI gated and the SOCKS5 gate (which keys on `AuthEnabled()`) negotiates no-auth when Exempt+no-backend. The legacy `unauth_mode` envelope field is a **read-only, one-way migration input** only (consulted at load iff `default_auth_outcome` is absent; `default_auth_outcome` always wins on conflict) and is **never written**.
- **Performance tuning**: Transport pool uses 512 max idle conns, 64 per host, 128KB relay buffers (sync.Pool), sharded rate limiter (64 shards), lock-free latency histogram
- **Top-hosts counter bound**: `topHosts` (store.go) is hard-capped at `topHostsMaxEntries` (10k distinct hosts) — the hostname is attacker-controllable, so the map would otherwise grow unbounded (memory DoS). At capacity a new host triggers a decay pass (halve all counts, drop zeros) that ages out cold/flood entries while continuously-reinforced heavy hitters survive; decay is amortized to once per cap-many new-host drops (amortized O(1) per Record). Counts become approximate lower bounds past the cap; ranking stays correct.
- **Relay buffers**: All tunnel relays (bypass, inspect, WebSocket) use `relayBufPool` (128 KB pooled buffers) via `io.CopyBuffer`
- **Config versioning**: Numbered JSON snapshots in `/data/config_versions/v{N}.json`, 50-version max, auto-created on config mutations via `saveConfigVersion(actor, action)` in 17 API handlers
- **configBackup surfaces (Finding 10.3)**: The `configBackup` struct (`ui_policy.go`) is shared by THREE surfaces with different memberships: (1) export/import (`apiConfigExport`/`apiConfigImport`, ui_config.go) round-trips all fields; (2) config-version rollback (`captureConfigBackup`/`applyConfigBackup`/`diffConfigs`, configversion.go) round-trips only a curated subset; (3) `/data/admin_settings.json` is the restart-durability layer. `AlertWebhooks`, `BlockPageHTML`, `UpstreamProxies`, `ConnLimitEnabled`, `ConnLimitMaxPerIP` are **export/import-only — intentionally OFF the rollback surface** (secret/credential round-trip hazards for webhooks/upstreams; admin_settings-durable + unversioned handlers for the rest). `RateLimitExempt` is slated to JOIN the rollback surface (PR-2). See `roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md`.
- **Upstream pool durability**: GUI/API changes to the upstream pool (`POST /api/upstream`, config import) persist via the `UpstreamProxiesSaved` sentinel in admin_settings.json (mirrors `BlocklistFeedsSaved`: saved list is authoritative, empty-list wipe survives restart; sentinel-less legacy files keep the YAML seed). Entries persist RAW (may embed proxy credentials — 0600 file, same layer as `metrics_token`); `UpstreamPool.Entries()` is the persistence accessor, `List()` stays redacted for display. Circuit-breaker params are YAML-owned (NOT persisted): the pool remembers them from startup `Configure` and `SetProxies` (the API/restore path) reuses them — never hardcode 5/60s. `initUpstreamProxy` runs even with an empty YAML seed so CB params + health loop are wired for GUI-added proxies; the SIGHUP reload path stays gated on a non-empty YAML list so reloads don't wipe GUI state. Still OFF the rollback surface per Finding 10.3.
- **Node groups**: Label selectors (`map[string]string`) for matching enrolled nodes; auto GeoIP labels (`geo:country`, `geo:country_name`) assigned on enrollment/heartbeat
- **Bandwidth/QoS**: Token bucket rate limiting per label group, configurable rates (KB/s, MB/s, GB/s), stored in `/data/bandwidth_policies.json`
- **ConfigSnapshot sync**: CP pushes `ConfigSnapshot` to DP nodes containing policy rules, blocklist, PAC exclusions, threat feed data, session HMAC, bandwidth policies, and node groups
- **Cluster gaps**: All 8 items from CLUSTER-GAPS.md implemented: PAC sync, rolling upgrades, config versioning, geo-aware grouping, bandwidth/QoS, secrets sync, threat feed sync, config diff
- **HA fencing lease (ADR-0005 — PROGRAM COMPLETE S0–S5, closes RISK-001)**: `-ha-etcd-endpoints`/`-ha-etcd-cert`/`-ha-etcd-key`/`-ha-etcd-ca`/`-ha-lease-ttl` (or `cluster.etcd_*`/`lease_ttl_seconds` YAML; read once at startup) arm an etcd fencing lease (`internal/halease`; key `/culvert/ha/leader`, epoch = `create_revision`) via `armHALease` BEFORE any role branch — malformed lease config is FATAL, unreachable etcd = lazily denied leadership (fail-closed). Layers: `ha_lease.go` (S2 — Acquire-gated promotion, keepalive with etcd-as-clock, `selfFence`, `WriteAllowed()`, term = epoch), `ha_fencing.go` (S3 — per-RPC issuance gate, puller-side bundle-epoch verify incl. no-live-holder reject, DP `dpLastSeenEpoch` CAS ratchet), `ha_failover.go` (S4/S5 — `leaseAutoPromote` hysteresis 30s → freshness 10m → Acquire; `enterStandbyResync` demote-and-resync; `acquireLeaseForResume` ghost-lease wait ≤45s for fast leader restarts). In lease mode `--ha-auto-failover` is IGNORED (fence arbitrates; manual promote bypasses freshness/hysteresis as break-glass); nil provider = legacy ADR-0004 byte-identical. `/healthz` + `/api/cluster/ha` expose `lease_mode`/`lease_valid`/`epoch`; the HA panel's Fencing Lease card is STATUS-ONLY (endpoints are startup-scoped — recorded GUI-parity deferral). Compose: profile-gated `etcd` witness (`--profile ha`, LAB ONLY — production wants a third machine + TLS). Bounded-LWW window (≤TTL) on partition is the documented F4 posture. Runbook: `docs/operator/ha-lease-failover.md`.
- **Compose operator contract (D1.5)**: The profile-gated `cli` service in `docker-compose.yml` is the canonical operator path for backup, restore, and cleanup — `docker compose --profile cli run --rm cli <flags>`. Same image as `proxy` (no version-skew). `/backup` (volume `culvert-backups`) is mounted **only** in `cli`; the `proxy` container must not be able to read its own backups. `cli` must not mount `/var/run/docker.sock`. Restore commit is offline-only (`docker compose down` → `run --rm cli --confirm` → `up -d`); backup, restore dry-run, list-leftovers, and cleanup-leftovers (dry-run **and** `--confirm`) are runtime-OK. The legacy `updater` sidecar is documented as superseded by D1.6 but not removed in D1.5. See `roadmap/D1.5-docker-compose-operator-contract.md` for the design and `docs/operator/docker-compose-backup-restore.md` for the operator-facing how-to.
- **Proxy image pin binding (P1.4 — maintenance agent)**: The proxy image is selected at the sudo boundary, NOT by an env var. `CULVERT_PROXY_IMAGE` (and its `env_keep`) are removed. Apply/rollback pull a repo-bound pinned digest (`docker pull <proxy_repo>@sha256:<64hex>`) and retag it to the FIXED local tag `culvert/proxy:pinned` (`docker tag … culvert/proxy:pinned`); `docker-compose.yml` proxy+cli resolve that fixed tag (no `${…}` interpolation). The sudoers entries bind the repo as a rendered literal (`{proxy_repo}`, no wildcard) + an exact 64-class hex digest, retag destination fixed — so a compromised `culvert-maint` user can at most run a digest of the one configured repo. `config.proxy_repo` (default `ghcr.io/kidcarmi/culvert`) MUST match `image_allowlist`; `packaging/culvert-maint/install.sh` seeds `culvert/proxy:pinned` BEFORE installing the new sudoers (keep-old-path-until-seed-succeeds). The tag is LOCAL-ONLY: `scripts/install.sh` (quick-start) also seeds it before its `docker compose up` (precedence: `CULVERT_PROXY_SEED_REF` → running-container image → `ghcr.io/kidcarmi/culvert:latest` → local build), and `deploy_pinned_seed_test.go` pins the compose↔installer contract so the compose file can never again reference the pinned tag without the quick-start installer seeding it. Runner: `ComposePullDigest`/`ComposeTagPinned` (+ `validatePinnedDigestRef`), shared `pullAndTagPinned` used by apply's `pull` and the rollback core's `rollback_pull`; restart uses env-free `ComposeUp`. See `roadmap/D1.6c-pin-value-binding-plan.md`.
- **Startup slices — PROGRAM COMPLETE (24 shipped)**: every fat `init*` in `main.go` is extracted under the `<domain>_startup_config.go` (resolver + DTO) + `<domain>_startup.go` (loader) + `<domain>_startup_test.go` (per-slice tests) layout — the 11 SAFE pilots (`fileblock`, `inspection_rules`, `geoip`, `pac`, `mtls_ocsp`, `ui_extras`, `legacy_auth_providers`, `rewrite_default_action`, `ui_access_policy`, `metrics_token`, `session`), the MEDIUM tranche (`blocklist`, `connlimit`, `observability`, `auth`), and the final sweep (`logstore`, `persistent_admin_state`, `upstream_pool`, `rootca`, `background_services`, `urlcategories`, `cdr`, `scanning`, `cluster`). Each `init*` in `main.go` is a thin shim; **env values and CLI flags are read/packed in the shim and passed to the resolver as params** (value structs like `cdrCLIFlags`/`scanningCLIFlags`/`clusterCLIFlags` for wide flag sets) so resolvers stay pure. `startup_slice_contract_test.go` pins the resolver convention (purity + determinism + no-fc-mutation) — any new slice appends to its table. **Do not re-extract shipped slices.** `startDataPlane` is **deliberately NOT a slice** (params arrive pre-resolved; runtime wiring, not config resolution). The `cluster` loader owns the ADR-0004 HA boot flow (`startHAStandby` shared by join-mode and restart-as-standby; `startControlPlaneWithHAResume`; `resolveDPWiring` 3-priority DP wiring) and arms the ADR-0005 fencing lease (`armHALease`, before any role branch).
- **Release catalog trust (Phase 1 — enforce-by-default)**: Production wiring (`release_wiring.go::loadReleaseManagement`) enters `VerifyEnforce` whenever a trust root is present (baked `bakedReleaseTrustKeysJSON` ∪ `CULVERT_RELEASE_CATALOG_TRUST_KEYS`); with no roots and no override it fails closed → Release Management DISABLED (unsigned catalogs are NEVER auto-trusted). `permissive`/`disabled` are explicit, logged break-glass only via `CULVERT_RELEASE_CATALOG_VERIFY` (resolver `resolveCatalogVerifyMode`). In enforce mode the holder also runs the freshness + rollback gate (`release_catalog_freshness.go`): `expires_at` required and not past (5-min skew; future-dated `generated_at` rejected), `catalog_version` required (≥1) and ≥ the monotonic floor persisted at `<dataDir>/release_catalog_state.json` (corrupt floor fails closed). `expires_at`/`catalog_version` are structurally tolerant at load (`release_catalog.go`) but ENFORCED only in the enforce-mode holder (opt-in `WithFreshnessEnforcement`). `/api/releases` surfaces `verify_mode`/`expires_at`/`catalog_version`. CI wall: `release_catalog_phase1_ci_test.go` (`TestPhase1CI_*`). **Verified auto-seed (P1.7, `release_autoseed.go`)**: when `CULVERT_RELEASE_CATALOG_URL` is set AND in enforce mode, startup fetches the signed catalog via `HTTPCatalogProvider` (two-phase verify + SSRF), runs READ-ONLY verify+freshness+rollback on the staged dir (the real `holder.Reload()` raises the floor, AFTER a move-aside atomic swap into `release_catalog/`), and fails closed leaving the existing catalog untouched on any error. Inline SSRF guard (`url.Parse`+scheme+`isPrivateHost`) at the call site; logs host-only. The installer only forwards the env (`release_management_install_contract_test.go` forbids a baked default URL). The legacy Docker updater stays as fallback until a production catalog-driven update succeeds. See `docs/operator/enterprise-release-catalog-plan.md` and `roadmap/D1.6d-P1.7-catalog-autoseed-plan.md`.
- **Release catalog pipeline (P2a — `release_gen.go`)**: CI generates the official catalog deterministically from release metadata (never hand-edited). `generateReleaseCatalog` produces the exact on-disk shape the P1.2 loader consumes; determinism is load-bearing (compact `json.Marshal`, sorted maps/releases, RFC3339-UTC) because the loader hashes RAW manifest bytes — `TestGenerateReleaseCatalog_Deterministic` is the merge gate. The release-blocking gate `TestReleaseCatalogGate` (env-driven: `CULVERT_RELEASE_GEN_SPEC`/`_OUT`/`CULVERT_RELEASE_EXPECT_DIGEST`) is run by the `catalog-pipeline` job in `ci.yml` against the manifest-list digest the `docker` job pushed; it round-trips the bundle through the REAL `LoadVerifiedCatalog` (no gate/runtime drift), rejects tags, and asserts `list_digest` == pushed digest. The gate signs with an EPHEMERAL in-process ed25519 key (discarded; NOT a trust root) and the attached bundle is UNSIGNED — official keyless (Sigstore-identity) catalog signing + the in-binary verifier are **P2b** (`roadmap/D1.6d-P2-release-pipeline-signing-plan.md`).
- **Release catalog keyless trust (P2b-1 — Sigstore-identity verifier)**: A SECOND catalog-signature scheme (`release_catalog_sigstore.go`) that COEXISTS with the ed25519 scheme — never replaces it. A cosign keyless bundle (`index.json.sigstore`: Fulcio cert + sig + Rekor proof) over the RAW index bytes is verified OFFLINE via `sigstore-go` against a baked Sigstore `trusted_root.json` (`//go:embed`; **as of P2b-2a this is the real Sigstore public-good root ⇒ scheme ACTIVE by default**, override/deactivate via `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT`) + a PINNED identity (`officialSigstoreIssuer` = the GH Actions OIDC issuer; `officialSigstoreSANRegex` anchored to a tagged release of `KidCarmi/Culvert`'s **`ci.yml`** workflow — exact repo+workflow-file+tag, no wildcard). Identity (cert chain + SAN + issuer) is enforced as part of the verify policy, and the verifier uses the bundle's INTEGRATED Rekor timestamp (never wall-clock), so a checked-in fixture verifies indefinitely and nothing reaches sigstore.dev at runtime (air-gap safe). **Scheme selection** (`verifyIndexSignature`, tri-state `schemeOutcome`): Sigstore first, then ed25519, then the mode-based no-artifact decision — but ONLY a true `fs.ErrNotExist` on a scheme's sidecar falls through; a present-but-unreadable/invalid artifact REJECTS without consulting the other scheme (**artifact-owns-outcome**, closes the strip-one-sig downgrade). Enforce-mode non-emptiness is satisfied by EITHER scheme (`NewTrustStoreWithSigstore`). `/api/releases` surfaces `trust_schemes`. Operator overrides `CULVERT_RELEASE_SIGSTORE_IDENTITY`/`_TRUSTED_ROOT` (break-glass/fork-mirror, public material only); an identity set without a root logs a WARNING and stays inactive. Tests use `ca.NewVirtualSigstore()` (offline). **P2b-1 ships the verifier only — nothing publishes a keyless catalog yet**; release-side keyless signing + the baked official root are **P2b-2**. See `roadmap/D1.6d-P2b-sigstore-identity-trust-plan.md`.
- **Release catalog keyless trust (P2b-2a — bake official root + activate)**: The empty `trusted_root.json` embed is replaced with the **real Sigstore public-good `trusted_root.json`** (media type `…trustedroot+json`, NOT TUF `root.json`; 2 Fulcio CAs / 2 Rekor / 2 CT / 1 TSA; PUBLIC material only). Provenance recorded in `trusted_root.provenance.txt`; `TestSigstore_BakedRootCanBeParsed` guards that the embed is non-empty, parses via `root.NewTrustedRootFromJSON`, and carries Fulcio+Rekor material. The pinned SAN is narrowed from a `[^@]+` workflow wildcard to the EXACT signing workflow file — `^https://github\.com/KidCarmi/Culvert/\.github/workflows/ci\.yml@refs/tags/v.*$` (security review P0-1; renaming `ci.yml` needs a coordinated identity update + overlap window). **Default-posture change:** baking the root makes the keyless scheme ACTIVE by default (`resolveSigstoreWiring` → `sig.active`), so a build with no operator trust config now enters **enforce** with the Sigstore scheme — with no signed catalog this is just `available:false` (no dispatch; legacy updater primary). Deactivate by pointing `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT` at an empty file. **P2b-2a activates verification; nothing SIGNS a catalog yet — CI keyless signing + the end-to-end/image-sig gates are P2b-2b.** See `roadmap/D1.6d-P2b2-release-signing-plan.md` and `docs/operator/sigstore-trusted-root-lifecycle.md`.
- **Release catalog keyless signing (P2b-2b — produce + prove the signed catalog)**: The `catalog-pipeline` job (`ci.yml`) gains `id-token: write` and, on the **tag path only** (`refs/tags/v*`), `cosign sign-blob --yes --bundle index.json.sigstore index.json` (keyless Fulcio+Rekor; no private key), then **proves it end-to-end**: `TestReleaseCatalogKeylessVerify` (env-gated `CULVERT_RELEASE_GEN_VERIFY_SIGSTORE=1`) loads the freshly-signed bundle through the REAL in-binary path (baked root + pinned identity, Sigstore-only enforce store) — so a natural OIDC SAN that doesn't match the pinned `ci.yml` identity FAILS the release. Then `cosign verify` checks the pushed image digest carries the SAME identity (catalog↔image parity). The signed `index.json`+`.sigstore` are attached to the GitHub Release and the `release-catalog-bundle` artifact. **Identity single-source-of-truth**: `release_identity.env` (issuer + SAN regex) is sourced by the CI image-sig gate AND pinned byte-equal to the `officialSigstore*` Go constants by `TestReleaseIdentitySSOT` (no CI↔binary drift). The main-push gate stays the P2a ephemeral-ed25519 round-trip (unsigned, no `.sigstore`). Signing is non-deterministic (per-run cert/timestamp) but covers the deterministic index bytes, so `TestGenerateReleaseCatalog_Deterministic` is unaffected. This does NOT demote the legacy updater (Phase 6). See `roadmap/D1.6d-P2b2-release-signing-plan.md`.
- **Roadmap**: See `roadmap/PHASES.md` for development phases (1–6), `roadmap/ROADMAP.md` for production deployment action items, `roadmap/FEATURE-COVERAGE.md` for GUI coverage audit, `roadmap/UI-DESIGN.md` for panel design reference, `roadmap/CLUSTER-GAPS.md` for cluster gap analysis, `roadmap/D1.6-maintenance-agent-design.md` for the Maintenance Agent / host-operations design (supersedes the deprecated `roadmap/docker-system-update.md`), `roadmap/roadmap-day2.md` for day-2 code review findings (108 items across 8 domains), `roadmap/RUNTIME-OWNERSHIP.md` for the Runtime Ownership & Startup Decoupling Program (Phases 0–6, stable SPOF IDs S1–S10), `roadmap/AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md` for the frozen `defaultAuthOutcome` contract that retires global `UnauthMode` (Slices 1–5; authority for that work)

## Admin UI / Control Plane

The admin API is wired in three layers — `startUI()` only composes them, never registers routes itself.

**Route registration**
- `startUI()` MUST NOT contain `mux.HandleFunc` calls. All routes are registered through per-domain `register*Routes(mux, ...)` helpers (e.g. `registerPolicyRoutes`, `registerSecurityRoutes`).
- `uiRoutes` in `ui_routes_meta.go` is the **single source of truth** for route metadata. Adding a route means: (1) register it via a `register*Routes` helper, (2) add a corresponding `uiRouteMetadata` entry to `uiRoutes`.
- Metadata is **method-aware** via `Methods []uiRouteMethod`. Each entry declares `Method`, `MinRole`, `Mutating`, `AuditExpected`, plus an optional note. `MethodAny` (`"*"`) is the catch-all when a handler intentionally treats every method the same.

**Middleware chain (outer → inner)**

```
uiIPGuardMiddleware → securityMiddleware → uiAuthMiddleware → uiMetadataEnforcement → mux
```

- `uiAuthMiddleware` owns the public-route allowlist and injects `uiRoleKey{}` into the request context.
- `uiMetadataEnforcement` (C2) reads that role and gates the request against per-method `MinRole` from `uiRoutes`. **Active by default** — fail-closed.
- `securityMiddleware` still owns CSRF, body-limit, and rate-limit decisions based on the HTTP method. The `Mutating` flag in metadata is **informational only**; it does not alter middleware behavior.

**Kill switch**
- `CULVERT_C2_ENFORCE=false` (or `0`/`no`/`off`) reverts C2 to shadow mode (log-only, never blocks). Read once at startup; admin-API runtime mutation is intentionally not supported.

**AuditExpected (C2c)**
- Pure observability. After a 2xx/3xx response, if metadata says `AuditExpected=true` and no `auditEvent`/`auditEventDiff` ran, the middleware emits one `C2: audit missing ...` log line and increments `c2AuditMissingTotal`. Failed requests, hijacked responses, and public routes are skipped. C2c **never** blocks a request.

**Role-divergence detector (C4 — REPORT-ONLY)**
- Pure observability. When the C2 middleware admits a request whose per-method `MinRole` is *lower* than what the handler-level `requireRole` ultimately demands (e.g. `apiIdPRouter` declares `MethodAny=viewer` but `apiIdPItem`'s PUT branch calls `requireRole(RoleAdmin)`), C4 increments `c2RoleDivergenceTotal` and emits one `C2: role divergence ...` log line. The middleware injects the C2-evaluated `MinRole` into the request context; `requireRole`'s failure branch reads that value and compares against the role it just rejected.
- C4 **never** blocks, allows, or alters the response. The handler's existing `requireRole` writes the 403 itself; C4 only observes the decision after the fact. Defense-in-depth (invariant #6) is preserved; the handler is still the real backstop.
- Audit ring is intentionally untouched — divergence events are governance observability, not admin-action audit. They flow out via the structured logger and the C3 governance endpoint only.

**Governance surface (C3)**
- `GET /api/governance/control-plane` (admin-only) exposes route inventory, C2 mode, the six C2 counters, derived health (four axes), and the parity-test pyramid (D0/C1/C1.5/C2/C2c/C4). Read-only and side-effect-free; no Prometheus exposure, no AST replay, no schema mutation. The kill switch stays env-only and read-once.
- C3 health severity policy (`deriveGovernanceHealth`):
  - `missing_meta > 0` → `metadata_parity = drift`, status = `drift`. C1 reverse-parity should make this impossible at runtime, so any non-zero value is genuine governance/config drift.
  - `no_policy > 0` → `metadata_parity = warn`, status ≥ `warn`. The counter can be triggered by a client sending a method the route does not accept (e.g. PATCH against a GET-only route, scanner probes); reserving drift for `missing_meta` keeps the indicator from flipping to drift on benign client traffic.
  - `audit_missing > 0` → `audit_completion = warn`, status ≥ `warn`.
  - `enforce_denied > 0` while `mode = shadow` → `enforce_consistency = drift`, status = `drift` (the kill-switch contract is read-once at startup).
  - `role_divergence > 0` → `role_divergence = warn`, status ≥ `warn`. Triggered legitimately by viewers probing admin-only sub-actions on dynamic dispatchers; reserved for warn rather than drift to avoid noise on benign client traffic.
- The six C2 counters surfaced by C3 (one-line definitions):
  - `would_deny` — session role was below the per-method `MinRole`. Increments in BOTH shadow and enforce modes; tracks the policy decision regardless of action.
  - `enforce_denied` — request actually got a 403 from the metadata-driven gate. Stays at zero in shadow mode; in enforce mode it moves in lock-step with `would_deny`.
  - `missing_meta` — request path resolved through the mux but had no matching `uiRoutes` entry (the static `/` catch-all absorbs unknown paths, so this is rare in practice). Soft-fail; never blocks a request.
  - `no_policy` — path matched a `uiRoutes` entry but the HTTP method had no exact policy and no `MethodAny` fallback. Soft-fail; never blocks a request. Triggered both by genuine drift and by clients sending unsupported methods (see severity policy above).
  - `audit_missing` — successful request (2xx/3xx) on an `AuditExpected=true` route did not emit an `auditEvent`/`auditEventDiff` call (C2c observability).
  - `role_divergence` — handler-level `requireRole` rejected a request whose C2-evaluated `MinRole` was strictly lower (i.e. metadata was more permissive than the handler's actual contract). Increments at most once per request, on the failure branch of `requireRole`. Observability only; never blocks.

### Admin UI / Control Plane Invariants

These are non-negotiable for any change touching the admin API:

1. **No route without metadata.** Every `mux.HandleFunc` path must have a matching `uiRoutes` entry. C1 forward/reverse parity tests enforce this.
2. **Metadata must never be more permissive than handler behavior.** If the handler enforces admin, metadata cannot say viewer. C1.5 AST parity tests enforce this for directly detectable handler behavior; dynamic/delegated handlers must be documented and reviewed.
3. **Resolution order: specific method > MethodAny > soft-fail.** Don't use `MethodAny` to paper over a method-specific contract.
4. **Missing metadata / no method policy must NEVER block requests.** Both are soft-fail in shadow and enforce mode — they log + count, the handler-level `requireRole` remains the real backstop.
5. **Public routes are owned by `uiAuthMiddleware` only.** C2 stays out (`RolePublic` is documentation, not enforcement). Don't add public-route gates to C2.
6. **Do not remove handler-level `requireRole`.** C2 is an additional gate, not a replacement. Defense-in-depth is the contract.
7. **C2 must never allow what the handler denies.** If they ever disagree, the handler wins by design — C2's role is to add denials, never to widen access.

### Testing Guarantees

Each layer has its own test suite — keep them green when modifying the admin API.

- **D0** (`d0_*_test.go`) — route/auth/security baseline invariants: route inventory pinned at the canonical count, auth allowlist, CSRF, body-limit, and rate-limit checks.
- **C1** (`ui_routes_meta_test.go`) — bidirectional route/metadata parity layer: forward (every `uiRoutes` entry has a matching `mux.HandleFunc`) and reverse (every `mux.HandleFunc` has a matching `uiRoutes` entry), source-scan based.
- **C1.5** (`ui_routes_meta_audit_test.go`) — AST-walk parity between metadata `MinRole`/`Mutating` and the per-method behavior of each handler (`requireRole` calls, method switches).
- **C2** (`ui_metadata_enforcement_test.go`) — middleware enforcement: shadow mode is silent, enforce mode returns 403, kill switch toggles correctly, missing-meta and no-policy stay soft-fail.
- **C2c** (`ui_metadata_enforcement_test.go` — `TestC2c_*`) — audit-completion observability: warns on success without audit, silent on failure / hijacked / public / `AuditExpected=false`, never blocks the request.
- **C4** (`ui_metadata_divergence_test.go` — `TestC4_*`) — report-only role-divergence detector: increments `c2RoleDivergenceTotal` and emits a structured log line when the handler's `requireRole(R)` rejects a request whose C2-evaluated `MinRole` was strictly lower. Tests cover the canonical viewer-on-admin-route case via `apiIdPRouter`, the parity case (no event), the C2-stricter case (no event), and the response-decision invariance proof (C4 cannot change the 403 the handler already wrote).

### Test-authoring pitfalls

- **Audit ring saturation.** The in-memory audit ring is bounded at `maxAuditLogs = 500`. Tests MUST NOT assert on `len(auditGet())` deltas (e.g. `len(after) == len(before)+1`) because under `-count=2 -shuffle=on` the cumulative suite saturates the ring and `len()` stops growing — adding a new entry evicts the oldest. The determinism gate (`QA · Determinism`) re-runs the suite shuffled to flush these out. Instead, assert on entry **content**: scan `auditGet()` for an entry matching a unique discriminator (`Actor` IP from a TEST-NET-2 reserved range, plus `Action`/`Object`, plus a baseline `TS` captured before the call). See `security_feedsync_audit_test.go` for the canonical pattern.
