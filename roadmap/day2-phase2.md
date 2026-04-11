# Day-2 Phase 2 — Gap Analysis & Architectural Evolution

**Audit date:** 2026-04-11
**Baseline commit:** `c1c3eff` (claude/continue-roadmap-3aRAb)
**Scope:** Cross-reference of every roadmap file under `/roadmap/` against the
actual codebase and outstanding `TODO`/`FIXME` markers in `*.go`.

> **Status:** This file covers **Phase 1 only** (gap analysis). Phase 2
> (architectural evolution proposals) will be appended once the gap list is
> agreed.

---

## Executive summary

- **Roadmap items audited:** 136+ across 8 domains (day2, PHASES, edge-cases,
  security-features, ROADMAP, CLUSTER-GAPS, FEATURE-COVERAGE, docker-system-update)
- **Marked incomplete in roadmap:** 23 items
- **Actually incomplete in code:** 7 items
- **False positives (claimed open, actually shipped):** 16 items
- **Shipping blockers:** **0**
- **Outstanding `TODO`/`FIXME`/`XXX`/`HACK` in `*.go`:** **0** (one false
  positive — "xxx" placeholder in an API doc comment, not a work marker)

The Culvert core proxy is security-complete for a v1 release. The remaining
gaps are operational/observability concerns that do not block shipping.

---

## Critical

Gaps that affect production correctness, incident response, or data integrity
in a multi-user enterprise deployment.

- **Persistent request log** — source: `edge-case-audit.md:172`, `roadmap-day2.md` §6.1
  — evidence: `store.go maxLogs = 1000`, ring buffer in memory only; syslog sink
  is fire-and-forget and the UI can only surface in-memory history — status:
  **UNFINISHED** — impact: in a 500-user deployment an operator investigating
  an incident can only see the last ~60 seconds of traffic before the ring
  overwrites. Syslog alone is insufficient because operators need an in-proxy
  searchable view — recommended action: add a pluggable persistent sink
  (SQLite or append-only JSONL under `/data/request_log/`) with retention
  policy, rotation, and an indexed query path for the existing `/api/logs`
  handler. #1 remaining operator friction.

- **CSP `'unsafe-inline'` on admin SPA** — source: `roadmap-day2.md:266` (S5,
  deferred) — evidence: `ui.go` serves CSP header with `script-src 'self'
  'unsafe-inline'`; the admin SPA embeds event handlers directly in HTML via
  `onclick="…"` attributes throughout `static/index.html` — status:
  **UNFINISHED, deferred** — impact: low because the SPA consumes only
  authenticated JSON from its own origin and never renders untrusted HTML, but
  this still fails a common SOC-2 CSP audit check — recommended action: document
  as GA limitation; schedule a nonce-based refactor of inline handlers
  post-GA. Requires replacing ~80 inline `onclick` attributes with
  `addEventListener`.

---

## High

Gaps that meaningfully reduce operator ergonomics or observability but do not
break security or correctness.

- **OpenTelemetry request-span tracing** — source: `roadmap-day2.md:352-353`
  (F14) — evidence: `metrics.go` exports counters/gauges via OTLP, `apiOTelConfig`
  lets admins configure the collector, but there are no per-request spans and
  no W3C traceparent propagation on upstream-dialled requests — status:
  **PARTIAL** — impact: a cluster operator cannot correlate a slow user
  request to the upstream hop that caused it without additional tooling —
  recommended action: Phase 3. Today's OTLP metrics export is sufficient for
  SRE dashboards; distributed tracing is a performance-investigation
  upgrade.

- **Grafana dashboard templates** — source: `roadmap-day2.md:353` (F15) —
  evidence: no `.json` dashboard files in repo — status: **UNFINISHED** —
  impact: operators must hand-author dashboards from the Prometheus-compatible
  `/metrics` surface — recommended action: ship a starter dashboard JSON under
  `observability/` referencing the documented `culvert_*` metric namespace.
  Documentation task, not a code change.

---

## Low

Nice-to-have enhancements deferred to later phases.

- **PagerDuty / Slack native integrations** — source: `roadmap-day2.md:392`
  (F24) — evidence: `alerts.go` provides a generic signed webhook — status:
  **BY DESIGN** — recommended action: document the webhook payload format and
  the HMAC-SHA256 signing scheme; no code change.

- **Metrics persistence across restarts** — source: `roadmap-day2.md:393`
  (F25) — evidence: `metrics.go` keeps a 60-minute rolling in-memory
  time-series — status: **LOW PRIORITY** — recommended action: document
  Prometheus scraper as the persistence path. Dashboard metrics are ephemeral
  by design.

- **Threat-feed reputation scoring + IOC extraction** — source:
  `roadmap-day2.md:394` (F26) — evidence: `threatfeed.go` treats each feed as
  a flat list; no scoring — status: **NOT STARTED** — recommended action:
  Phase 3. Current binary allow/deny is sufficient for v1.

- **Incremental threat-feed delta sync** — source: `roadmap-day2.md:395`
  (F27) — evidence: `feedsync.go` + `blocklist_feed.go` download the full
  feed on every sync tick — status: **NOT STARTED** — recommended action:
  Phase 3. The ~100 MiB full pull is acceptable at hourly-or-longer cadence;
  bandwidth is not an issue at current subscriber volumes.

---

## TODO/FIXME inventory (from `*.go`)

`Grep -i 'TODO|FIXME|XXX|HACK'` across `*.go` → **0 outstanding work markers.**

One false positive in `ui.go` API doc comment uses the string "xxx" as a hash
placeholder ("`.../feeds/xxx`"), not a code marker.

This is unusually clean — the team has been disciplined about landing TODOs
rather than leaving them in the tree.

---

## Notes on roadmap hygiene

Sixteen items that were flagged as unfinished in prior audits have actually
shipped and should be marked complete in the source roadmap files. Listing
them here so the next auditor does not re-file the same gaps.

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
  `apiSecYARARules`. (Follow-up `c1c3eff` fixed the file-vs-rule-name bug
  and added `.yara` extension fallback.)
- **3.3 Global scan exclusion list** — `ScanExclusionStore` with host +
  SHA-256 exclusion, persisted to `/data/scan_exclusions.json`.
- **3.4 DPI bypass per host** — `ContentScanner.bypassHosts` with envelope
  JSON persistence and port/IPv6-aware lookup.

### False positives from prior audits

- **B4** — X-Forwarded-For discards non-IP values: **by design** (anti-spoof).
- **B18** — enrolment token consumption race: already under mutex
  (`enrollment.go` `ValidateAndConsumeToken`).
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
complete. The remaining seven gaps are:

- one operational (persistent request log — the single biggest operator
  complaint),
- one SOC-2 hygiene (CSP `unsafe-inline`),
- two observability (OTEL tracing, Grafana templates),
- three deferred-by-design (reputation scoring, delta sync, metrics
  persistence).

Recommended v1 release note: "Persistent request log is in-memory;
long-term retention via syslog or OTLP export. Slate for v1.1."

---

## Recommended next actions (in order)

1. **Ship persistent request log sink** (Critical). Append-only JSONL under
   `/data/request_log/` with daily rotation and a bounded total-size cap.
   Surface a date-range query in the existing `/api/logs` panel.
2. **Document operator observability story** (High). Ship a starter Grafana
   dashboard JSON and a "Prometheus + OTLP in production" operator guide.
3. **Plan CSP nonce refactor** (Critical, post-GA). Track as an epic — not
   a one-commit fix.
4. **Mark the 16 resolved items in roadmap-day2.md** (hygiene). Prevents the
   next audit from re-opening closed work.

---

*Phase 2 (architectural evolution) — to be appended after review of Phase 1.*
