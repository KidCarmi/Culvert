# Verified Repository Context

This document records exactly what the **current repository** establishes, with evidence, as the factual
baseline for the MCP design package. It is the authority for every "the repository already has / lacks
X" claim made anywhere in this package.

**Claim legend:** **[FACT]** verified by repository read (file · symbol · lines) · **[INFER]**
architectural inference from facts · **[REC]** recommendation · **[EXT]** externally unverified.

---

## 1. Inspection metadata

| Item | Value | Class |
|---|---|---|
| Inspection date | 2026-07-24 | [FACT] |
| Branch | `claude/culvert-mcp-security-gateway-pr0-y75t9k` | [FACT] |
| HEAD SHA | `c0ae2bca274ab8104c65abb629027b9acdb73f08` | [FACT] |
| Working-tree state at inspection | Clean (`git status --porcelain` empty) | [FACT] |
| Default branch | **`main` — VERIFIED** (`git ls-remote --symref origin HEAD` → `ref: refs/heads/main HEAD`; `git remote show origin` → `HEAD branch: main`) | [FACT] |
| Go module | `github.com/KidCarmi/Culvert` (`go.mod:1`) | [FACT] |
| Go version | `go 1.25.12` (`go.mod:3`); toolchain `go1.25.12` | [FACT] |
| Root-level `.go` files | 739 including `_test.go`; **245 non-test** (`ls *.go`) | [FACT] |
| Repository-wide `.go` files | 1008 total; **369 non-test** (`find . -name '*.go' -not -path './vendor/*'`) | [FACT] |
| `internal/` package directories | 57 (`ls internal/`) | [FACT] |
| Existing MCP implementation | **None found in inspected paths** — see §7 | [FACT] |

## 2. Repository instructions examined

- `CLAUDE.md` — authoritative project instructions (package layout, conventions, invariants, admin-API
  rules, config-surface anti-drift, GUI-parity mandate). [FACT]
- `docs/adr/0001-record-architecture-decisions.md` — ADR mandate and six-section format. [FACT]
- `docs/adr/ADR-0007-openapi-contract.md` — CI-enforced OpenAPI contract bound to the live route table. [FACT]
- `docs/engineering/ENGINEERING-CONSTITUTION.md` — governance charter (referenced by `CLAUDE.md`). [FACT]
- `docs/api/API-*` (9 documents) — API style, versioning, deprecation, contributing. [FACT]
- `roadmap/*` — phased design plans (referenced, not exhaustively read this pass). [INFER]

## 3. Reusable primitives (verified)

Each row: what it is, evidence, what the evidence proves, and the reuse classification for MCP.

> **Citation-correction note (PR-1 remediation, findings L-1/L-2).** The overall inspection baseline for
> this document remains HEAD `c0ae2bc` (§1). Rows marked **⟳** had line-range slips or missing symbol·line
> evidence that were **re-verified against `origin/main` `2eef667`** during the PR-1 remediation and updated
> to the current-tree symbols/lines (`newHistogram :360`; `ssrf.go PrivateIP :72-79`, `PrivateHost :86-113`,
> `Control :126-139`; `ui_routes_meta.go uiRoutes` var `:87`; `auth_oidc_flow.go validateIDToken :499-566`;
> `internal/secret` `Provider :64`; `internal/redaction` `DataClass :12`). Non-⟳ rows are unchanged. See
> `PR1-READINESS-REMEDIATION.md`.

| Primitive | Evidence `path · symbol · lines` | Proves | Class for MCP |
|---|---|---|---|
| SSRF peer-IP recheck (TOCTOU) | `internal/ssrf/ssrf.go · Control · 126-139`; `PrivateIP · 72-79`; `PrivateHost · 86-113` ⟳ | Dialer `Control` re-checks the actual peer IP immediately before `connect(2)`, fail-closed on DNS error | **Reusable as-is — low-level primitive only** |
| Header scrub / hop-by-hop strip | `proxy.go · scrubForwardedHeaders · 46-73`; `proxy_tunnel.go · removeHopHeaders · 1288-1304` (deletes `Proxy-Authorization` :1300); `proxy_tunnel_h2.go:80` | SWG strips client `X-User-Identity` and `Proxy-Authorization` before upstream; injects no upstream auth | Reusable as-is (primitive); MCP-level reclassification in §5 |
| HA fencing / epoch | `internal/halease` (etcd lease, epoch = create_revision); `ha_fencing.go · dpObserveEpoch · 122-150`; `ha_lease.go · WriteAllowed · 251-261` | Monotonic epoch ratchet + write-authority gate + stale-CP rejection | Reusable as-is |
| DP fail-static / last-known-good | `controlplane_snapshot.go · applyDPLastGoodConfigSnapshot · 981-997`, `persistDPLastGoodConfigSnapshot · 1013-1037` | DP decides on last valid snapshot; request path needs no per-call CP round-trip | Reusable as-is |
| Config versioning + rollback | `internal/configver/configver.go · Store · DefaultMax=50 :33, SaveWithNote :108-137`; `configversion.go · capture/apply/diff · 43-577` | Numbered `v{N}.json` history + diff + dry-run rollback + re-publish | Engine reusable as-is; typed DTO after refactor |
| Config-surface anti-drift registry | `config_surfaces.go · configSurfaces · 104-455`; `config_surfaces_test.go` (parity) | Declares field membership across 5 hand-maintained surfaces; parity-enforced | Reusable as-is (pattern; MCP must add rows) |
| Admin-API convention | `ui.go · newAdminUIHandler · 64-98`; `ui_routes_meta.go · uiRoutes (var) · 87`; `ui_rbac.go · requireRole · 46-53`; `ui_metadata_enforcement.go · uiMetadataEnforcement · 451` ⟳ | `apiXxx`+`register*Routes`+`uiRoutes`+`requireRole`+C1/C1.5/C2/C2c/C4 parity | Reusable as-is |
| OpenAPI contract + CI gate | `api/openapi/openapi.yaml`; `ADR-0007`; `.github/workflows/pr-api-governance.yml`, `api-contract.yml` | Coverage gate binds spec to the live route table; breaking-change gate merge-blocking | Reusable as-is |
| Metrics | `metrics.go · handleMetrics :431, ruleMetrics :26-78 (maxRuleMetrics=200 :24), newHistogram :360` ⟳ | `culvert_*` namespace, cardinality-capped counters, lock-free histogram | Reusable as-is |
| GUI/SPA panel convention | `static/index.html` nav-item/`view-div`/`data-view`/`data-min-role` (:553-645, :706+) | Deterministic panel pattern used by ~30 panels | Reusable as-is |
| Secret containment / provider seam | `internal/secret/secret.go · Provider · 64` (redacting `Name :70`/`Format`/`String`), `kekSource · 54`; `internal/secret/provider.go · fileProvider · 27-45` (KEK containment; ADR `docs/adr/0007-secret-containment-boundary.md` — **note: the repo has two `0007`-numbered ADRs; this is the secret-containment one, distinct from `docs/adr/ADR-0007-openapi-contract.md`**) ⟳ | Compiler-enforced KEK boundary + provider model | Reusable after refactoring (broker prior art) |
| Redaction taxonomy | `internal/redaction/class.go · DataClass · 12`; `internal/redaction/redactor.go · Redactor · 77` (`Result · 17`); `internal/redaction/scrubber.go · Scrubber · 27` (fail-closed to most-restricted `DataClass`) ⟳ | Structural, fail-closed-to-SENSITIVE redaction at source | Reusable after refactoring (inspection/event prior art) |
| OIDC ID-token validation | `auth_oidc_flow.go · validateIDToken · 499-566` | JWKS RSA signature + issuer + `WithExpirationRequired` (:524) + 60s leeway | Reusable as-is (sig/exp/iss only) |
| Supply chain | `pr-fast-gate.yml` (race, coverage floors, gosec, govulncheck, gitleaks, benchgate); `pr-deep-gate.yml` (staticcheck, trivy, hadolint, go-licenses, determinism); `ci.yml` (cosign keyless, SLSA L3 verifiable, syft SBOM); SHA-pinned actions | Signing/provenance/SBOM/SAST/SCA/secret-scan present, mostly merge-blocking | Reusable as-is |

## 4. Architecturally incompatible components (must NOT reuse)

| Component | Evidence | Why incompatible |
|---|---|---|
| SWG `PolicyRule` | `policy.go · PolicyRule · 91-188` (~34 destination-selector fields); actions `policy.go · 19-27` (`Allow/Drop/Block_Page/Redirect`). Grep for MCP actions (`QUARANTINE`/`REQUIRE_APPROVAL`/…) → 0 matches | Network-destination selector with a 4-verb action model; no tool/method/argument concepts. **Blueprint forbids adding MCP fields.** |
| SWG policy evaluation | `policy.go · Evaluate · 1083-1143`; DNS on GeoIP `DestCountry` at `:1387` → `geoip.go · resolveHost · 125-204`; category rules read BadgerDB | Performs **network + disk I/O during a decision** — violates MCP's "no I/O during eval". |
| SWG OIDC flow as generic MCP auth | `auth_oidc_flow.go:523` (audience = OIDC `client_id`); `auth_oidc.go:247` (optional `RequiredAudience`); no RFC 8707 (0 matches) | Audience = client_id, not an MCP resource/server; **blueprint forbids reusing this flow.** |
| Flat `Identity` | `identity.go · Identity · 9-27` (Sub/Email/Name/Groups/Provider) | No tenant/workload/agent/client/delegation; usable only as the "human" principal after refactor. |
| Session cookie as bearer | `internal/session/session.go · Session · 345-363`; `ui_session.go` | HttpOnly cookie, never issued/parsed as `Authorization: Bearer`, no audience binding. |
| In-memory audit ring as decision pipeline | `internal/audit/audit.go · MaxRing=500 :49`; SSE evict `internal/sse/sse.go:63-78`; syslog drop-on-full `internal/syslog/syslog.go:67,157-171`; OTLP best-effort | No replay-id / delivery cursor / backpressure. **Blueprint forbids reusing the debug ring.** |

## 5. No-token-passthrough — precedent, not implementation

- **[FACT]** SWG strips the client `Proxy-Authorization` (hop-by-hop) and internal `X-User-Identity`, and
  injects no upstream auth header (`proxy.go:46-73`, `proxy_tunnel.go:1288-1304`, `proxy_http.go`).
- **[INFER]** This proves a no-passthrough **posture** for HTTP/CONNECT/WS. It is **not** an MCP
  no-token-passthrough implementation: the SWG path never validates a bearer token's audience/resource
  against an MCP server, and has no credential-broker step selecting a distinct scoped upstream
  credential after policy.
- **Classification:** **Architectural precedent + new MCP implementation required.**
- **[REC]** MCP MUST terminate the client bearer token, validate audience/resource = the MCP server,
  make a policy decision, then select a distinct, scoped, short-lived upstream credential via the broker.

## 6. Replay protection — corrected, per-mechanism

| Mechanism | Evidence `path · symbol · lines` | Proves | Does NOT prove | Class |
|---|---|---|---|---|
| OIDC nonce validation | `auth_oidc_flow.go · validateIDToken · 499-566` ⟳; nonce minted `CaptiveLoginURL:381-392`, checked via `ExchangeCode→validateIDToken(...,entry.nonce):472` | Nonce verified on browser PKCE ID-token flow; `expectedNonce=""` on introspection path is deliberate (comment :359 — access tokens carry no nonce) | Anything about access-token replay | [FACT] R (ID-token flow) |
| Authorization-code replay | `auth_oidc_flow.go · pkceStore.pop · 248-259` (single-use delete); PKCE S256 `:386-388`; `pkceEntryTTL=10m :221` | `state`/code single-use + TTL-bounded; PKCE binds code to verifier | Bearer access-token reuse after exchange | [FACT] R (code flow) |
| ID-token validation | `auth_oidc_flow.go · validateIDToken · 499-566` | Sig/exp/issuer/audience(=client_id) enforced | Audience = an MCP server/resource; no RFC 8707 | [FACT] R (sig/exp/iss) / AI (audience semantics) |
| **Bearer access-token replay** | `auth_oidc.go · introspect/ResolveIdentity · 166-265`; `auth_oidc_flow.go` introspection `617-695` | RFC 7662 introspection: `active` + `exp` + optional `aud`/`scope` | **No** one-time-use, jti tracking, or replay list — an unexpired, un-revoked token replays as active | **[FACT] Missing (no replay defense)** |
| jti / token cache | `auth_oidc.go · oidcCacheEntry/oidcIdentityCacheGet/Set · 114-151,173,282-319` (`key=cacheKey("",token)`, TTL=min(≈2m,exp)); session jti `internal/session.NewJti` | Token cache is a **performance** cache; session `Jti` is a per-login cookie discriminator + revocation | Cache is **not** anti-replay (it accelerates repeat acceptance); session jti is not a bearer jti | [FACT] AI (cache ≠ replay guard) |
| Token TTL | ID: `WithExpirationRequired():524`; access: `parseDeclaredExpiry`+`exp<=now` reject `auth_oidc_flow.go:653-659` | Expiry enforced on both; cache TTL clamps to token exp | TTL is not replay prevention | [FACT] R (TTL enforced) |
| Sender-constrained tokens (mTLS/DPoP, `cnf`) | Repo-wide grep `dpop\|"cnf"\|sender-constrain\|certificate.bound\|token.binding` over `*.go` (non-test) → **0 matches** | Not present in inspected paths | Exhaustive absence (strong indication, not exhaustive proof) | [FACT] Missing (inspected paths) |
| Session binding | `internal/session/session.go · Session · 345-363` (HMAC-SHA256 + jti + exp + revocation) | Binds a browser session cookie with revocation | Does not bind/protect an API bearer token | [FACT] AI (cookie-scoped) |

**Net:** **MCP replay protection is NOT VERIFIED / net-new.** The inspected SWG bearer path provides **no**
access-token replay defense (only expiry, introspection-`active` revocation, optional audience=client_id,
and a non-protective performance cache). Design documents must not imply otherwise.

## 7. Existing MCP implementation — none in inspected paths

- **[FACT]** `grep -i mcp` over `*.go` → one unrelated hit (`support_collectors_runtime.go`).
- **[FACT]** `grep 'jsonrpc\|JSON-RPC\|MCP\|tools/call'` over `*.go` → 0 relevant matches; review of the
  proxy dispatch (`proxy.go · handleRequest · 794-913`) and SOCKS5 handler (`socks5.go`) shows no
  JSON-RPC/MCP handler.
- **Scoped claim:** *No MCP or JSON-RPC listener was found in the inspected repository paths and
  searches.* Absence of MCP code is strongly indicated, not exhaustively proven over non-Go assets.

## 8. Missing infrastructure (net-new for MCP)

- **[FACT]** No durable decision-event pipeline (no replay-id / cursor / backpressure). Nearest durable
  primitive is `internal/reqlog/reqlog.go:38-43` (rotating JSONL) — still lacks those guarantees.
- **[FACT]** No ConfigSnapshot content-hash or signature — `controlplane_snapshot.go · ConfigSnapshot ·
  22-112` has `Version`/`Epoch`/`PolicyVersion` but no `catalog_revision`, `credential_revision`,
  `minimum_dp_version`, `content_hash`, or `signature`; `validateConfigSnapshot · 263-290` is size-caps
  only. ed25519 signing exists only in the release-catalog subsystem (reference prior art).
- **[FACT]** No inbound Origin/Host anti-rebinding guard for an MCP/SSE listener; `isSafeRedirectURL`
  (`proxy_portal.go:152`) is captive-portal-only.
- **[INFER]** Greenfield: MCP protocol kernel/listener, server registry, tool catalog/fingerprint/drift,
  MCP policy engine (I/O-free, nine-action), credential broker, input/output inspection/DLP, durable
  decision events, MCP admin API + GUI, MCP snapshot fields, and MCP-specific CI gates.

## 9. Security blockers (for the intended MCP model)

1. **No durable decision-event pipeline** (audit ring is bounded/best-effort). Must be built; the audit
   ring must not be reused as production evidence.
2. **No ConfigSnapshot content-hash/signature** (integrity rests on mTLS + epoch). Must be built.
3. **No inbound Origin/Host anti-rebinding** for the MCP listener. Must be built.
4. **No bearer access-token replay defense** in the reusable auth path. Must be designed net-new.

## 10. Commands executed and exact results (material subset)

| # | Command | Exact result |
|---|---|---|
| 1 | `git branch --show-current` | `claude/culvert-mcp-security-gateway-pr0-y75t9k` |
| 2 | `git rev-parse HEAD` | `c0ae2bca274ab8104c65abb629027b9acdb73f08` |
| 3 | `git status --porcelain` | *(empty — clean at inspection; later only `docs/design/mcp/` untracked)* |
| 4 | `git ls-remote --symref origin HEAD` | `ref: refs/heads/main	HEAD` + SHA |
| 5 | `git remote show origin \| grep -i 'head branch'` | `HEAD branch: main` |
| 6 | `head -20 go.mod` | module `github.com/KidCarmi/Culvert`; `go 1.25.12` |
| 7 | `go version` | `go version go1.25.12 linux/amd64` |
| 8 | `ls *.go \| wc -l` / non-test | `739` / `245` |
| 9 | `find . -name '*.go' -not -path './vendor/*' \| wc -l` / non-test | `1008` / `369` |
| 10 | `ls internal/ \| wc -l` | `57` |
| 11 | `grep -rli mcp --include=*.go .` | `./support_collectors_runtime.go` (1, unrelated) |
| 12 | `grep 'jsonrpc\|JSON-RPC\|MCP\|tools/call' *.go` | 0 relevant |
| 13 | `find . -iname 'openapi*'` | `api/openapi/openapi.yaml`, `api/openapi/openapi.json`, `scripts/openapi` |
| 14 | `grep -rli 'markdown\|mdlint\|link-check\|lychee' .github/workflows/` | *(no match — no markdown/link CI)* |
| 15 | `go vet ./...` | OK (no output) |
| 16 | `sed -n '205,275p' auth_oidc_flow.go` | pkceStore set/pop/peek; `pkceEntryTTL=10m`; `pkceStoreMax=1000` |
| 17 | `grep -rni 'dpop\|sender-constrain\|token.binding\|"cnf"\|certificate.bound' --include=*.go .` (non-test) | **0 matches** |
| 18 | `sha256sum` (uploaded DOCX vs `source/…docx`) | identical: `7fa2211c312f21d6399a4c7aac9223d90c1311547e125bc48e6c807b3d335537` |
| 19 | `git status --porcelain` (post-setup) | `?? docs/design/mcp/` (no tracked file modified) |

## 11. Commands deliberately NOT executed (and risk)

| Command | Why not run | Risk created |
|---|---|---|
| `go test ./...` / `-race` | Documentation-only phase; no code changed | **Low for the read-only Phase 1 investigation, but the current repository test baseline remains unverified in this session.** Required before any PR-1 code. |
| Re-count of `uiRoutes` entries | Route count is stated by `ADR-0007`/`CLAUDE.md`; not central to PR-0 | "~180 routes" remains a repo-doc claim, flagged `[EXT/repo-doc]`, not independently verified here. |
| Full line-by-line read of `config_surfaces_test.go`, `internal/halease/etcd.go`, `.github/scripts/coverage-floor.sh`, `.gitleaks.toml` | Behavior inferred from callers/ADRs; informs design not PR-0 correctness | **Low for the read-only Phase 1 investigation, but the current repository test baseline remains unverified in this session.** Items relied upon are marked `NOT VERIFIED` where used. |

## 12. Limitations of the investigation

- Negative claims (e.g. "no MCP listener", "no DPoP") are scoped to **inspected paths and searches over
  `*.go`**, not exhaustive proofs over all repository assets.
- Subagent-sourced findings were used for breadth; each is cited inline elsewhere in the package with
  `path · symbol · line-range`, but not every cited line was independently re-opened by the author.
- No build or test was executed; the repository test baseline for this session is **unverified**.
- Protocol/version and external-citation claims require non-repository sources and are marked `[EXT]`.
