# Culvert Supportability — Current-State & Gap Analysis (M0)

- **Status:** Adopted baseline for the Supportability Framework program
- **Date:** 2026-07-12
- **Owner:** Principal Supportability Architect
- **Scope:** Evidence-first audit of what exists in the repository today that a TAC / support framework can reuse, what is unsafe to reuse as-is, and what is missing. This document is the factual foundation for every other doc in `docs/support/`. All claims cite `file:line`.
- **Method:** Six parallel codebase audits (runtime/containers/update, observability, security/redaction, HA/cluster, config/state, CLI/API) plus direct inspection. Findings reconciled against the repo's own registers (`docs/engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md`, `roadmap/D1.0-state-inventory.md`, `roadmap/CLUSTER-RUNTIME-DISCOVERY.md`).

---

## 1. Executive finding

Culvert has **unusually strong primitives** for a product that has never shipped a support framework, but **no assembled supportability product**. The building blocks a mature vendor would need — a side-effect-free diagnostic contract, a declarative config-classification registry with parity tests, a compiler-enforced secret boundary, a hardened manifest-based archive format, and a shell-free privileged host agent — already exist and are individually excellent. What does not exist is the layer that composes them into a versioned, redacted, collectible, explainable support artifact, plus the timeline/history/escalation machinery around it.

The single most important structural fact for this program: **the product's own gap register already specifies this work** (`docs/engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md:490-510`, GAP-MON-01 / FO-2 — "No support bundle exists," target `GET /api/support-bundle` streaming a redacted tar.gz, "endorsed for first enterprise customer"). We are formalizing and hardening an already-endorsed direction, not inventing one.

**Maturity score: 2.1 / 5 (Emerging).** Primitives at 4/5; assembled supportability at 1/5. See §6.

---

## 2. Deployment & runtime reality (constrains everything)

| Fact | Evidence | Consequence for support framework |
|---|---|---|
| Delivery is **Docker Compose on a customer Linux host** — no OS image, no OVA/ISO | `Dockerfile`, `docker-compose.yml`; `ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md:72-77` (GAP-APP-01) | The framework must be runtime-agnostic and must **not** assume an appliance OS it can freely read. |
| Proxy runs **non-root `proxy:proxy`**, single `/data` volume, `/health` HEALTHCHECK | `Dockerfile:84-102,128,135-136` | The proxy process is the natural home for the *application-layer* collectors; it already has everything except host/container facts. |
| Proxy process has **no shell, no `exec`, no host visibility** | Only production `exec.Command` in the tree is the maintenance agent's runner (`cmd/culvert-maint/internal/runner/runner.go`); proxy knows only `os.Hostname()` + optional `CULVERT_PUBLIC_IP` | Good security posture. But there is **no existing supported host-access surface** — host/container/system-log facts require a privileged helper. |
| **Maintenance agent** is the only privileged host actor: UDS-only (`0660`), `SO_PEERCRED` UID allowlist, fixed-argv template registry, no `sh -c`, closed env allowlist, per-op ULID audit | `cmd/culvert-maint/internal/server/server.go:167-325`, `runner.go:213,448,531-561` | This is the **canonical "restricted command without shell" model** to extend for host-level collection — never a new shell. |
| Container hardening (read-only rootfs, cap-drop, seccomp) is **advisory only**, not enforced by shipped compose | `Dockerfile:75-83` | The framework cannot assume hardening is in effect; it must be safe even on a permissive host. |
| Future models (OVA/ISO, air-gap bundle, k8s/Helm) are **documented but not built**; HA (etcd fencing lease) **is** built | `ENTERPRISE-FEATURE-OPPORTUNITIES.md` FO-9/FO-6; ADR-0005; `docker-compose.yml` `--profile ha` | Design for multi-runtime now (collector abstraction), build for Compose+HA first. |

---

## 3. What exists and is directly reusable (the assets)

### 3.1 Diagnostic contract — `OperatorContract` (the anchor)
`diagnostics.go:31-48,137-177,988-1008`. `GET /api/diagnostics` (viewer role) returns a top-level `Verdict` (ok/warn/fail) + `[]OperatorContractCheck{Code, Status, Message, OperatorAction}`. ~20 checks (storage writability, policy, root CA, session secret, CDR, cluster posture, DP last-good snapshot, SAML posture, default-auth, YARA posture, config-snapshot validator, config-version present/readable/rollback-validity, key-at-rest, auth-exempt/CR/SSO risk). **Side-effect-free by contract** (cached/atomic/RLock reads + one bounded config-version file read), **deliberately omits secrets/URLs/paths/fingerprints** (`diagnostics.go:982-996`), and **explicitly designed to be extended by appending checks**. This is the seed of the Health & Explainability model — it already has status + remediation, and lacks only severity/confidence/evidence/timing/collector-linkage.

### 3.2 Config-classification registry — `config_surfaces.go` (the anti-drift wall)
`config_surfaces.go:59-394`. A declarative registry mapping each logical setting to the surfaces it lives on, carrying a **`Sensitive bool`** ("may carry secret material") and per-binding **`Redacted bool`** ("accessor strips secrets"), enforced bidirectionally by `config_surfaces_test.go` (every struct field claimed by exactly one row; every binding resolves to a real field). Sensitive rows already enumerated: `alert_webhooks`, `upstream_proxies`, `otlp_headers`, `metrics_token`, `session_hmac`, `idp_profiles`. This is the **template for the data-classification taxonomy and its CI parity gate** — extend the pattern to cover all of `/data`, logs, and traffic metadata.

### 3.3 Secret containment — `internal/secret` (ADR-0007)
`internal/secret/secret.go`. Opaque `*Provider`/`*Sealed` handles; the raw-KEK source is an unexported method so no code outside the package can obtain KEK bytes; **all fmt verbs render `REDACTED`** (`secret.go:37,80-88,127-136`); `WithPlaintext` zeroizes on return. This is the enforcement primitive for "material that must never leave the appliance" — the redaction model's `NEVER_EXPORT` class maps onto it directly.

### 3.4 Archive & encryption — `backup.go` + `internal/backupcrypt`
`backup.go:24-87` (manifest-first gzipped tar; per-file SHA-256/size/octal-mode; deterministic ordering; atomic write + parent fsync; `..`-traversal reject; symlink skip; KEK exclusion; schema-versioned). `internal/backupcrypt/backupcrypt.go` (AES-256-GCM, PBKDF2-SHA256 600k iters, AAD-bound header → downgrade-proof, opaque decrypt error, `enc:v1` magic that can't collide with gzip). **Reuse the tar/manifest/crypto machinery; do NOT reuse `defaultBackupArtifacts` and do NOT ship a raw backup** — a backup is a full secret export (§4.1).

### 3.5 Restricted-command host model — the maintenance agent
`cmd/culvert-maint`. UDS + `SO_PEERCRED` peer-UID allowlist; fixed argv template registry (never operator input, `runner.go:448`); no `sh -c`; closed env allowlist (`os.Environ()` not inherited); sudoers scoped per-command (repo literal + exact hex digest, no wildcard); async ops with ULID IDs, per-op logs, idempotency cache, single-flight lock, bounded output capture (1 MiB), parse-only field-allowlist capture (`capture_running.go`). Read-only verbs already exist (`GET /v1/status`, `/v1/audit`, `/v1/operations/{id}/logs`). This is exactly the pattern for privileged, shell-free host collection.

### 3.6 API/route pattern + RBAC + parity gates
`register*Routes` helpers compose into `startUI`; `uiRoutes` (`ui_routes_meta.go`) is the single source of truth for route metadata; `requireRole(w,r,role)` handler-level RBAC (admin/operator/viewer, `store.go:308-327`); C1/C1.5/C2 parity tests forbid a route without metadata or metadata more permissive than the handler. A `support` domain slots in as `registerSupportRoutes` + `uiRoutes` rows + a `data-view="support"` SPA panel (mandatory GUI parity, CLAUDE.md).

### 3.7 Observability surfaces that a bundle can harvest
- **Request-log history store** `internal/logstore` (Badger, **encrypted at rest**, two-dimensional retention, deep time-window pagination) — the strongest observability surface; `logstore.Entry` deliberately excludes query strings and identity from the SIEM `auth_*` block (`logstore.go:60-92`).
- **Audit** `internal/audit` — bounded ring (`MaxRing=500`) + append-only JSONL; actor enrichment with authenticated admin identity (`ui_helpers.go:27-41`); before/after diffs.
- **Metrics** — Prometheus `culvert_*` (`metrics.go`) + OTLP push (metrics + spans, `otlp.go`); lock-free latency histogram; per-rule hit counters; 60-minute request-rate ring (`store.go:54-123`).
- **Health/readiness** — `/healthz` (liveness + CA/SSL degradation visibility), `/readyz` (per-subsystem gating), `/api/dashboard/health` (goroutines + memstats via `runtime.ReadMemStats`).
- **Config export** — `apiConfigExport` (`ui_config.go:517`) already builds a redacted JSON envelope via `List()`/`Redacted()` accessors and is governed by `config_surfaces.go`.
- **Config versions + diff** — `internal/configver` history (actor/action/timestamp) + `diffConfigs` for "what changed."
- **SSRF guard** — `internal/ssrf.SafeDialContext` (post-resolution, closes DNS-rebind TOCTOU, fails closed) for any future upload path.
- **Governance C3** — `/api/governance/control-plane` (read-only inventory + counters + derived health) is a second precedent for "read process state, no side effects."

---

## 4. What exists but is UNSAFE to reuse as-is

| # | Unsafe thing | Evidence | Why it's a trap |
|---|---|---|---|
| 4.1 | **Raw backup = full secret export** | `backup.go`; agent §5 | Byte-faithful `/data` copy contains bcrypt hashes + TOTP secrets (`ui_users.json`), plaintext cluster CA key (`cluster-ca.key` unless `CULVERT_CLUSTER_CA_ENCRYPT`), MITM root CA key (`ca.bundle`), metrics token + raw upstream-proxy creds + session HMAC (`admin_settings.json`), webhook secrets. **Never hand a backup to TAC.** |
| 4.2 | **`sanitizeLog`/`obs.Sanitize` are NOT value redaction** | `proxy.go:798-828`, `internal/obs/obs.go:74` | They only neutralize control chars (CWE-117). They will pass a secret value through unredacted. Log-value redaction is a *convention*, not enforced. |
| 4.3 | **Raw `docker inspect`/`docker logs` is a secret-leak vector** | `packaging/sudoers/culvert-maint:171-249` | `Config.Env`/labels carry CA passphrase, session HMAC, IdP secrets. The sudoers file already enumerates `inspect --format {{json .Image}}` per-container-id-length specifically to prevent a compromised agent appending `--format {{json .Config.Env}}`. A naive log/inspect dump reintroduces the exact hole. |
| 4.4 | **No top-level panic recovery in the request path** | no recovery middleware in `proxy.go`/`proxy_tunnel.go`/`ui_middleware.go`/`socks5.go` | A panic drops the connection with a stderr stack — no metric, structured log, event, or crash artifact. Crash-data collection has nothing to collect today. |
| 4.5 | **`docker_group_lab` privilege mode is root-equivalent** | `cmd/culvert-maint/config.example.toml:56-66` | Warns only. Any host-collection design must assume the strict (sudoers) mode and never require the lab mode. |
| 4.6 | **Redaction is siloed per-call-site** | §3.2/§3.3 vs logs/reqlog | Correctness depends on every author calling the right accessor (`List()` not `Entries()`, `URL.Redacted()` not raw). No central "redact this structure" function. A new collector that reaches into a store directly bypasses all of it. |

---

## 5. What is MISSING (the build list)

**Bundle & collection**
1. No support-bundle assembly — the pieces (`/api/diagnostics`, `/api/config/export`, `/api/audit`, `/api/logs`) exist only piecemeal; nothing composes them into one versioned artifact.
2. No collector framework — no plugin interface, isolation, timeout, or per-collector test contract.
3. No bundle manifest / "safe-to-share" attestation / integrity hashes over a support artifact (only over backups).

**Redaction & governance**
4. No centralized redaction engine (given a struct/file/stream, classify + mask).
5. No data-classification taxonomy spanning `/data` + logs + traffic (the registry covers only 3 config DTOs).
6. No free-form (key-name/regex) secret scrubber for log content.
7. No asymmetric "encrypt-to-TAC" recipient model (backup crypto is passphrase-only).

**Health, timeline, incident**
8. No explainable health beyond status+action — no severity, confidence, last-success, failure-duration, user-impact, probable-cause, evidence, or collector linkage.
9. No health-transition history ("since when degraded" is unanswerable in-product).
10. No operational timeline correlating config/policy changes, restarts, upgrades, failovers, cert changes, resource pressure, dependency failures, alerts, admin actions, crashes — **no shared correlation ID** across audit / reqlog / syslog / health.
11. No incident scopes (targeted collector sets per incident type).
12. No debug escalation levels (L0–L4) with duration/disk/consent/auto-rollback guarantees.

**Runtime introspection**
13. No live pprof / goroutine / heap-dump capture (only test-tagged); no crash/panic telemetry.
14. No system-log query API (`/api/logs` is request-log only; process log reachable only via stdout/file/syslog).
15. Shallow file-log retention — rotating logger keeps only ONE `.1` archive (`internal/fileutil/rotating.go:48-51`); no dated series, no compression → a busy node loses system logs fast.
16. No historical metrics (60-minute ring is the only in-process series).

**Cluster correlation (local-vs-cluster fault isolation)**
17. CP has **zero visibility into per-DP applied config version** — `MetricsReport` carries only counters (`controlplane.go:73-79`); no lag table, no drift reconciliation.
18. `EnrolledNode.Version` field exists but is **never populated** — version skew is not observable.
19. No failover/self-fence/election **history ring** (only a counter, `culvert_ha_failovers_total`); `lastSelfFence`/`lastSyncOK` are in-memory, unexposed.
20. No clock-skew detection between nodes; no in-band split-brain alarm in legacy (no-lease) mode; no etcd member-health/quorum visibility.

**Export & transport**
21. No support-bundle download API/UI, no CLI `support`/`diagnose` verb, no maintenance-agent collect verb.
22. No secure upload (offline or online); no remote-support model.

---

## 6. Maturity scorecard

Scale: 1 Absent · 2 Emerging (primitives, no product) · 3 Functional · 4 Mature · 5 Best-in-class.

| Capability area | Score | Basis |
|---|---|---|
| Health & readiness signals | 3 | `/healthz`+`/readyz`+`/api/diagnostics` are genuinely good; no history/severity/timeline |
| Diagnostic explainability | 3 | `OperatorContract` remediation actions are TAC-grade; snapshot-only |
| Config/state introspection | 3 | `config_surfaces` + `configver` + export are strong; no unified state manifest |
| Secret handling primitives | 4 | `internal/secret` boundary + at-rest engines are excellent |
| Centralized redaction | 1 | Does not exist; siloed conventions only |
| Support bundle | 1 | Does not exist |
| Collector architecture | 1 | Does not exist |
| Event timeline / correlation | 1 | No shared correlation ID; SSE is a stats firehose |
| Debug escalation levels | 1 | Does not exist |
| Runtime introspection (pprof/crash) | 1 | Not exposed; no panic telemetry |
| Cluster diagnostics | 2 | Per-node signals good; cross-node correlation under-instrumented |
| Secure export / upload | 1 | Backup crypto reusable; no bundle/upload/remote |
| Restricted command surface (no-shell) | 4 | Maintenance-agent model is best-in-class; lacks a collect verb |
| **Weighted overall** | **2.1** | Strong primitives (avg ~3.2), near-zero assembled product (avg ~1.1) |

---

## 7. Reuse decision matrix (what the program will build on)

| Need | REUSE (verbatim / extend) | DO NOT reuse | BUILD new |
|---|---|---|---|
| Bundle container | `backup.go` tar/manifest/atomic-write; `backupcrypt` | `defaultBackupArtifacts`; raw backup | `csb/1` manifest schema; collector-driven contents |
| Redaction | `config_surfaces.Sensitive/Redacted`; `internal/secret`; `List()`/`Redacted()` accessors | `sanitizeLog` as a redactor | central `Redactor` + `DataClass` registry + free-form scrubber |
| Diagnostics | `OperatorContract` schema + checks | — | `ComponentHealthRecord` extension (severity/evidence/collectors) |
| Command surface | `register*Routes`+`uiRoutes`+`requireRole`; one-shot flag dispatch (`main.go:319`) | any shell | `registerSupportRoutes`, `apiSupport*`, `data-view="support"`, `culvert support` verbs |
| Host collection | maintenance-agent UDS+peercred+argv-registry; read-only `/v1/status`,`/v1/audit`; `capture_running.go` field-allowlist | raw `docker inspect`/`logs` | `POST /v1/collect` read-only op; narrow whitespace-safe sudoers reads if logs required |
| Upload | `internal/ssrf.SafeDialContext` | auto/background transfer | opt-in resumable upload (post-MVP) |

---

## 8. Verdict for M0

The foundation is strong enough that an MVP support bundle is a **composition problem, not a greenfield build** — but the two hardest requirements (centralized redaction with a fail-closed default, and an explainable health/timeline model) are genuinely absent and must be designed before code. The gap register's endorsed direction (`GET /api/support-bundle`, redacted, secret-leak test) is correct but under-specified; this program supplies the missing contracts, threat model, and escalation/lifecycle machinery. Proceed to architecture (`SUPPORTABILITY-ARCHITECTURE.md`) with the reuse matrix above as fixed constraints.
