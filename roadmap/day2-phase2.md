# Day-2 Phase 2 — Gap Analysis & Architectural Evolution

**Audit date:** 2026-04-11 (refresh)
**Baseline commit:** `6a246a5` (branch `claude/go-proxy-evolution-zSgRJ`)
**Previous revision:** `0454329` — this refresh supersedes several stale
claims in that revision (see §"Corrections to prior revision").
**Scope:** Cross-reference of every roadmap file under `/roadmap/` against the
actual codebase and outstanding `TODO`/`FIXME` markers in `*.go`.

> **Status:** This file covers **Phase 1 only** (gap analysis). Phase 2
> (architectural evolution proposals) will be appended once the gap list is
> agreed.

Each open item carries a **Workstream** tag so that multiple engineers can
pick them up in parallel without treading on one another. Items sharing a tag
touch overlapping files; items with distinct tags are fully independent.

---

## Executive summary

- **Roadmap items audited:** 136+ across 8 domains (day2, PHASES, edge-cases,
  security-features, ROADMAP, CLUSTER-GAPS, FEATURE-COVERAGE, docker-system-update)
- **Marked incomplete in roadmap:** 23 items
- **Actually incomplete in code (this refresh):** **6 items**
- **False positives (claimed open, actually shipped):** 17 items — up 1 from
  the previous revision after re-verification
- **Shipping blockers:** **0**
- **Outstanding `TODO`/`FIXME`/`XXX`/`HACK` in `*.go`:** **0** (verified
  across all `.go` files — 0 total occurrences)
- **Parallel workstreams open:** **4** (Observability, UI-CSP, Tracing, Docs)

The Culvert core proxy is security-complete for a v1 release. The remaining
gaps are operational/observability concerns that do not block shipping.

---

## Critical

Gaps that affect production correctness, incident response, or data integrity
in a multi-user enterprise deployment.

**None.** The previous revision listed "Persistent request log" as the #1
Critical item; that was a **false positive** against the current tree — see
§"Corrections to prior revision" below. No remaining gap meets the Critical
bar at `6a246a5`.

---

## High

Gaps that meaningfully reduce operator ergonomics or observability but do not
break security or correctness. All four are **independent workstreams** —
they touch disjoint files and can be developed in parallel.

### H1. `/api/logs` query path ignores the persistent JSONL sink
**Workstream:** `observability-logs` (independent)
**Source:** `edge-case-audit.md` Finding 6.1
**Evidence:**
- JSONL persistence **does** exist: `store.go:144` (`initRequestLog`),
  `store.go:170-184` (`logAdd` writes to `requestLogWriter`),
  `config.go:90-96` (`RequestLogFile`, `RequestLogMaxMB`),
  `main.go:270-273` (wires the CLI flag/config into `initRequestLog`),
  `bootstrap.go:216` (bootstrap script emits `-audit-log /data/audit.jsonl`).
- `/api/audit` already supports `?source=file` for reading the persistent
  JSONL audit log (`ui.go:1008-1012`, `store.go:268 auditGetPersistent`).
- **Gap:** `apiLogs` (`ui.go:1185-1260`) still calls only `logGet()` — the
  in-memory ring buffer sized at `maxLogs = 5000` (`store.go:137`). It has
  no equivalent of `?source=file` and no paginated reader for the request-log
  JSONL.

**Impact:** an operator investigating an incident older than the last ~5000
entries must `grep` the JSONL on disk by hand. The file is written and
rotated correctly, but the admin UI cannot see past the ring-buffer window.

**Status:** **PARTIAL** (persistence: done; query surface: missing).

**Recommended action:** add a `requestLogGetPersistent(offset, limit, from, to, filters)`
helper in `store.go` mirroring `auditGetPersistent`, wire a `?source=file`
branch into `apiLogs`, and surface a "query persistent log" toggle in the
existing Logs panel. Estimated ~1 day; isolated to `store.go`, `ui.go`, and
`static/index.html` Logs view.

### H2. OTLP trace spans (not just metrics)
**Workstream:** `tracing-otlp` (independent)
**Source:** `roadmap-day2.md` F14
**Evidence:**
- `generateTraceparent` (`connlimit.go:24-33`) creates W3C Trace Context
  values and `proxy.go:180-183` propagates or generates a `Traceparent`
  header on every incoming request — so the previous revision's claim of
  "no W3C traceparent propagation" is also stale (see §Corrections).
- `otlp.go` exports *metrics* only. No span exporter is wired up and there
  is no OTLP `/v1/traces` endpoint configuration.
- `apiOTLPConfig` (`ui.go:4908-4948`) only toggles the metrics exporter.

**Impact:** traceparent values reach upstreams for correlation, but Culvert
itself does not emit spans, so a cluster operator cannot visualise which
upstream hop slowed a given user request in Jaeger/Tempo.

**Status:** **PARTIAL** — header propagation done; span pipeline missing.

**Recommended action:** Phase 3. Today's OTLP metrics export + traceparent
forwarding is sufficient for SRE dashboards; span export is a
performance-investigation upgrade.

### H3. Grafana dashboard templates not shipped
**Workstream:** `docs-observability` (independent)
**Source:** `roadmap-day2.md` F15
**Evidence:** `Glob **/*.json` returns zero files under `observability/`
or anywhere else in the repo. Prometheus-compatible metrics surface is
documented via the `culvert_*` namespace (`metrics.go`) but operators have
no starter dashboard.

**Impact:** operators must hand-author dashboards. Entirely cosmetic, but
the first thing every new deployment asks for.

**Status:** **UNFINISHED** — documentation task, not a code change.

**Recommended action:** ship a starter dashboard JSON under `observability/`
referencing the documented `culvert_*` metric namespace. Pure documentation;
no Go code touched.

### H4. Admin SPA CSP still permits `'unsafe-inline'` script-src
**Workstream:** `ui-csp` (large scope; independent)
**Source:** `roadmap-day2.md` S5 (deferred)
**Evidence:**
- `ui.go:366-367` sets
  `script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'`.
- `Grep -c 'onclick='` over `static/index.html` returns **185** inline
  handlers (the previous revision under-counted at ~80).

**Impact:** low — the SPA consumes only authenticated JSON from its own
origin and never renders untrusted HTML — but still fails a common
SOC-2 / OWASP ASVS CSP audit check.

**Status:** **UNFINISHED, deferred**.

**Recommended action:** document as a GA limitation; schedule a nonce-based
refactor of inline handlers post-GA. Requires replacing ~185 inline
`onclick` attributes with `addEventListener`, plus a nonce plumbing change
in `ui.go` that stamps each page load. Track as an epic, not a single commit.

---

## Low

Nice-to-have enhancements deferred to later phases. None block shipping,
none block any of the High items above.

- **PagerDuty / Slack native integrations** — source: `roadmap-day2.md:392`
  (F24) — evidence: `alerts.go` provides a generic signed webhook — status:
  **BY DESIGN**. Recommended action: document the payload format and the
  HMAC-SHA256 signing scheme; no code change.
- **Metrics persistence across restarts** — source: `roadmap-day2.md:393`
  (F25) — evidence: `metrics.go` keeps a 60-minute rolling in-memory
  time-series — status: **LOW PRIORITY**. Recommended action: document
  Prometheus scraper as the persistence path.
- **Threat-feed reputation scoring + IOC extraction** — source:
  `roadmap-day2.md:394` (F26) — evidence: `threatfeed.go` treats each feed
  as a flat list; `Grep -i 'reputation|etag|If-None-Match'` finds nothing —
  status: **NOT STARTED**. Recommended action: Phase 3.
- **Incremental threat-feed delta sync** — source: `roadmap-day2.md:395`
  (F27) — evidence: `feedsync.go` + `blocklist_feed.go` download the full
  feed on every sync tick; no ETag / If-None-Match plumbing — status:
  **NOT STARTED**. Recommended action: Phase 3.

---

## Parallel workstream map

Four independent workstreams; any subset can be tackled at once.

| Workstream | Item | Scope | Shared files w/ other streams? |
|---|---|---|---|
| `observability-logs` | H1 JSONL query surface | `store.go`, `ui.go` apiLogs, Logs panel JS | none |
| `tracing-otlp` | H2 span export | new `otlp_traces.go`, `ui.go` apiOTLPConfig extension | none |
| `docs-observability` | H3 Grafana JSON | `observability/*.json` | none |
| `ui-csp` | H4 inline-handler refactor | `static/index.html`, `ui.go` CSP header | none |

All four touch disjoint files. `observability-logs` and `ui-csp` both modify
`ui.go` in *different* handlers (`apiLogs` vs the header middleware), so
merge conflicts are limited to import blocks.

---

## TODO/FIXME inventory (from `*.go`)

`Grep -i 'TODO|FIXME|XXX|HACK'` across `*.go` → **0 outstanding work markers.**

One false positive in a `ui.go` API doc comment uses the string "xxx" as a
hash placeholder ("`.../feeds/xxx`"), not a code marker.

This remains unusually clean — the team has been disciplined about landing
TODOs rather than leaving them in the tree.

---

## Corrections to prior revision (`0454329`)

The previous `day2-phase2.md` revision made four claims that do not hold
against `6a246a5`. Flagging them here so the next auditor has a clean slate.

1. **"Persistent request log — UNFINISHED" (was #1 Critical).** False against
   the current tree. JSONL persistence + rotation is already implemented
   in `store.go:144-185` (`initRequestLog` + `logAdd` JSONL persistence),
   wired through `config.go:90-96` (`RequestLogFile`, `RequestLogMaxMB`) and
   `main.go:270-273`. The narrower remaining gap is the **query surface**:
   `apiLogs` reads only from the in-memory ring buffer. Reclassified as
   **H1 (High)**, not Critical.

2. **"store.go maxLogs = 1000".** Stale. `store.go:137` is
   `const maxLogs = 5000`.

3. **"~80 inline onclick attributes in static/index.html".** Stale.
   `Grep -c 'onclick='` returns **185**. CSP refactor (H4) scope is more
   than 2× what was scoped previously.

4. **"No W3C traceparent propagation on upstream-dialled requests".** Stale.
   `proxy.go:180-183` injects `Traceparent` via `generateTraceparent`
   (`connlimit.go:24-33`) on every incoming request, so upstream hops do
   receive the header. The remaining gap is span *export* (H2), not header
   propagation.

---

## Notes on roadmap hygiene

Seventeen items flagged as unfinished in prior audits have actually shipped
and should be marked complete in the source roadmap files. Listing them
here so the next auditor does not re-file the same gaps.

### Tier 1 correctness fixes (all shipped)

- **1.1 Content decompression** — `scanner.go:decompressForScan` now supports
  identity, gzip, deflate, brotli.
- **1.2 IDNA / host normalisation** — applied uniformly in FQDN matching.
- **1.3 RBAC on cert upload** — `requireRole(w, r, RoleAdmin)` in
  `apiCAUpload`.
- **1.4 OIDC `sub` validation** — `identity.go` rejects empty `Sub`.
- **1.6 HA CA key encryption** — AES-GCM wrapping over HA sync.
- **1.9 Events SSE authentication** — `requireRole(w, r, RoleViewer)` in
  `apiEvents`.
- **1.10 Admin UI leaf cert `IsCA=false`** — `tls.go` generator sets
  `IsCA: false`.

### Tier 2 admin-friction fixes (all shipped)

- **2.1 YARA rule listing + parse error visibility** — `globalYARA.Names()`,
  `Warnings()`, surfaced via `GET /api/security-scan/yara/rules`.
- **2.2 Remote scan sidecar failure alerting** — `statRemoteScanFail`
  counter + `scan_svc_down` alert in `scan_remote.go`.
- **2.3 ClamAV status ping caching** — 30 s cache in
  `security_scan.go ClamAVStatus`.

### Tier 3 security-features roadmap (all shipped)

- **3.1 YARA validate endpoint** — `apiSecYARAValidate`.
- **3.2 YARA CRUD via GUI** — `ReadRule`/`WriteRule`/`DeleteRule` +
  `apiSecYARARules`.
- **3.3 Global scan exclusion list** — `ScanExclusionStore` with host +
  SHA-256 exclusion, persisted to `/data/scan_exclusions.json`.
- **3.4 DPI bypass per host** — `ContentScanner.bypassHosts` with envelope
  JSON persistence and port/IPv6-aware lookup.

### Observability shipped that previous revision missed

- **Persistent JSONL request log** — `store.go:144-185`, see §Corrections.
- **Persistent JSONL audit log** — `store.go:232-263` (`InitAuditLog`),
  with paginated reader at `store.go:268` and `?source=file` query path
  at `ui.go:1008`.
- **W3C Trace Context header propagation** — `proxy.go:180-183`,
  `connlimit.go:24-33`.

### False positives from prior audits

- **B4** — X-Forwarded-For discards non-IP values: **by design** (anti-spoof).
- **B18** — enrolment token consumption race: already under mutex
  (`enrollment.go ValidateAndConsumeToken`).
- **B19** — log rotation TOCTOU: already under `r.mu.Lock` (`logger.go`).
- **B23** — ClamAV parser captures first verdict: **by protocol**
  (INSTREAM returns one verdict per stream).
- **P1** — per-rule metrics cardinality: already capped at 200 rules in
  `metrics.go`.
- **S2** — LDAP EqualFold: **correct per RFC 4517**.
- **S3** — logout revocation: already persisted to revocation list
  (`ui.go`, `apiLogout`).
- **S9** — SSE CSRF: authenticated + same-origin; read-only.
- **S13** — bootstrap token plaintext in response: required; never logged.
- **S14** — HA peer SSRF: peer is operator-configured; intended private.
- **1.7** — unlimited token reuse: token is consumed on first use.
- **1.8** — enrolment CIDR bypass: enforced in `ValidateAndConsumeToken`.
- **U14** — disk-space precheck: now uses `syscall.Statfs("/")` with a
  500 MB floor.
- **U20** — `apiUpdateCheck` fire-and-forget: now waits up to 35 s.
- **U21** — unused `newRotatingFile` in updater: **by design** (Docker
  logging driver handles the updater).
- **Q18** — JSON decoder doesn't close body: **by spec** (net/http
  auto-closes).

---

## Production readiness verdict

**Shipping blockers: none.**

All security-critical and correctness items from the day-2 audit are
complete. The remaining six gaps are:

- two narrowly-scoped observability items (JSONL query surface, Grafana
  templates),
- one deferred UI-security epic (CSP nonce refactor),
- one deferred performance-investigation upgrade (OTLP span export),
- two deferred-by-design Phase-3 items (reputation scoring, delta sync).

Recommended v1 release note: "Persistent request & audit logs are JSONL on
disk with rotation; admin UI currently surfaces the last 5000 in-memory
entries. File-backed query surface for request logs is slated for v1.1."

---

## Recommended next actions (in order)

Ordered so the four parallel workstreams can start immediately without
waiting on one another.

1. **Wire `?source=file` into `apiLogs`** (H1, `observability-logs`). Mirror
   the existing `auditGetPersistent` pattern. ~1 day.
2. **Ship Grafana starter dashboard JSON** (H3, `docs-observability`). Pure
   docs; no Go changes. ~half a day.
3. **Plan the CSP nonce refactor epic** (H4, `ui-csp`). 185 inline handlers
   to convert; stamp a nonce per page-load in `ui.go`. Track as a multi-PR
   epic, not a single commit. Post-GA.
4. **Plan the OTLP span exporter** (H2, `tracing-otlp`). Phase 3; decide
   between direct OTLP/HTTP client and `go.opentelemetry.io/otel` SDK.
5. **Mark the 17 resolved items in `roadmap-day2.md`** (hygiene). Prevents
   the next audit from re-opening closed work.

---

*Phase 2 (architectural evolution) — to be appended after review of Phase 1.*
