# Frontend Batch 1 — Closeout Record

- **Status**: Closed (2026-08-22). Batch 1 of the frontend modernization program
  (FE-1A → FE-4 plus two qualification-hardening rounds) is merged into `main`
  and externally accepted. This document is the auditable closeout record: what
  was delivered, the evidence chain, the actual GitHub gate conclusions, and the
  known deferred work Batch 2 inherits.
- **Scope discipline**: this record contains no raw CI logs. Every claim
  references a durable artifact — a commit SHA, a tree hash, a PR, or a named
  workflow run — that can be re-verified from the repository and its GitHub
  project.

## 1. Delivery

| Fact | Value |
|---|---|
| Delivery commit | `c1d3db57879be883668392299dd2169535c5f270` — `feat(ui): add modern admin frontend and query-driven monitor` (one squash commit, 139 files, +39,323/−8; `go.mod`/`go.sum` untouched) |
| Pull request | #1194 "Frontend Platform Batch 1 — Modern Admin UI & Query-Driven Monitor" |
| Merged | 2026-08-22T16:12:45Z by the repository owner (KidCarmi), merge commit `fdad525419081f853bfecd8fb441d75fea056904` on `main` |
| Pre-merge base | `2517c8d2b1df42bbff914ecfbc88474c7b6ccd3a` (no other commits landed on `main` between base and merge) |
| Delivery tree | `703cece0178691e679deb7b05d9b6eaf31152d15` |
| Evidence branch | `claude/culvert-frontend-modernization-qnyqb6` @ `d021589064c2d9cc1bae3a8cfc6cf8af3c5bc54f` |
| Evidence tree | `703cece0178691e679deb7b05d9b6eaf31152d15` |
| Tree equality | **PASS** — delivery tree ≡ reviewed evidence tree ≡ post-merge `origin/main` tree (all three `703cece0…`); `git diff --exit-code` between the evidence branch and the delivery commit is empty (byte-identical) |

The merge was a true merge commit of the unchanged reviewed head: `origin/main`'s
root tree after merge equals the delivery commit's tree exactly, so **what runs on
`main` is byte-for-byte what was reviewed**.

## 2. Program history (frozen checkpoints, all externally reviewed)

| Checkpoint | SHA | Content |
|---|---|---|
| FE-1A | (granular history on evidence branch) | Build foundation: pinned toolchain, committed deterministic dist, drift/tamper/determinism lanes |
| FE-1B | (granular history) | `ui_frontend_v2.go` embedded serving: flag-gated `/app`, strict nonce-free CSP, 503-degrade validation |
| FE-2 FROZEN | `ecc2df1` | Design system + shell (internal SVG charts, no Chart.js; native `<dialog>`; 16-icon set; theme) |
| FE-3 FROZEN | `20ffe8353e8c5990cc144141727d8e1ace658378` | Setup/auth/session/RBAC: boot machine, in-band TOTP, collapsed auth boundary, identity continuity, boundary unification |
| FE-4 FROZEN | `105874e302fb80058a7b61343e6e36815d99437e` | Snapshot operations + query-driven Monitor (ADR-FE-002): Overview, Traffic keyset-cursor console, Audit, Diagnostics, Governance |
| FE-4 hardening FROZEN | `240f91053cd27d39f98e7fe70942c5641ccb0242` | Scan-budget continuation, nine per-verb diagnose decoders, network-layer auth cancellation, Overview time-scope truthfulness |
| Batch-1 final reviewed | `d021589064c2d9cc1bae3a8cfc6cf8af3c5bc54f` | + review-round fixes B1.1 (lint decomposition), B1.2 (governance health vocabulary), B1.3 (named results) |

Two review-driven correction rounds were executed via the evidence-branch →
re-freeze → re-squash → `--force-with-lease` → requalify discipline; superseded
PR heads `34d7388a…` and `7bb5a960…` are recorded in the PR history.

## 3. Architectural decisions of record

- **ADR-FE-001 (Accepted)** — frontend platform: React 19 / TypeScript strict /
  Vite (Rolldown), committed deterministic `frontend/dist` embedded via
  `go:embed`, exact dependency pins, no chart/icon/overlay dependency, strict
  nonce-free CSP for the v2 surface.
- **ADR-FE-002 (Accepted, amended in the hardening round)** — the Monitor is
  QUERY-DRIVEN, not stream-driven: zero `/api/events` consumption in v2, bounded
  keyset/cursor pagination with a fingerprint-bound stateless cursor,
  scan-budget continuation (`scan_limited` + last-scanned cursor, guaranteed
  forward progress under sparse filters), frozen per-applied-query time windows.
  Backend SSE is retained untouched for the legacy UI.
- **FE-3 auth boundary** — one collapsed authentication boundary owns teardown
  (cancel in-flight requests at the network layer, clear cache, run registered
  owner cleanups) at most once per authenticated episode; revalidation on route
  transitions and focus restoration; setup-time open mode withheld (GAP-9).
- **FE-1B serving** — routes registered unconditionally (deterministic C1/D0
  walls, 229→232), default-off gate inside handlers; invalid embedded artifact
  degrades the v2 UI to 503 and never the proxy.

## 4. Final qualification summary (recorded at `d0215890…` / `c1d3db57…`)

- Canonical-container verify (digest-pinned Node 24.19.0 image): lint,
  typecheck, **141 unit tests**, build, drift gate, tamper harness (A–D fail,
  E pass), frontend byte-determinism ×5 (root hash
  `90cbe82d63f9fb41d92963c64d02be17f1d14a3fe4cd67e5d0e494779a09a260`).
- Real-binary Playwright: **36 specs passed** (+3 evidence-gated) across three
  appliance states (seeded-history AUTH, fresh, setup-fail), zero unexpected
  console/page errors, zero external-origin requests, zero `/api/events`
  requests.
- `go test -race -count=1 -timeout=15m ./...`: all 103 packages ok.
- Binary determinism ×2 identical; arm64 compile green; gofmt/vet clean.
- Security invariant sweep: no inline styles/scripts, no `style={}`, no
  EventSource or `/api/events` consumer, no CSS-in-JS/devtools/chart.js;
  browser storage = exactly `localStorage['culvert-theme']`; exact pins.

## 5. GitHub gate conclusions (actual, recorded — not re-run)

On the merged head `c1d3db57…` (PR #1194, final check set — all green):

- **✅ Fast PR Gate — APPROVED** (2026-08-22T16:11:17Z) and
  **✅ Deep PR Gate — APPROVED** (16:02:23Z) — the two required merge checks.
- Fast lane: fmt/vet/build, `Gate · golangci-lint`, `Gate · go test -race +
  coverage floors`, `Gate · frontend / verify+determinism`, `Gate · frontend /
  real-binary browser smoke`, perf-regression, gitleaks, govulncheck+gosec, MCP
  predicates, diff classification — all success.
- Deep lane: determinism (shuffle ×2), staticcheck, hadolint, build-image,
  trivy, compose validation — all success.
- Pass-through shells on the PR: ✅ QA Gate, ✅ Security Gate, ✅ Code Review —
  Complete. SAST: CodeQL + Advanced Security suite success. API governance:
  breaking-change / client-generation / verify-contract success. Admin-UI RBAC
  playwright-go success. Review hygiene (commit messages, PR size) success.
- **Gate wiring proof**: the two superseded heads (`34d7388a…`, `7bb5a960…`)
  each had a real `Gate · golangci-lint` failure that correctly failed the Fast
  Gate aggregate — the frontend/lint lanes are load-bearing, not decorative.
- External review: Codex re-review concluded "Didn't find any major issues";
  its one accepted P2 finding (governance health vocabulary) was fixed in B1.2.

Post-merge `main` push (`fdad5254…`) ran the full main-path workflows —
**all three concluded success**: CI run 3774 (16:34:40Z), QA Gate run 2991
(16:34:16Z), Security Release Gate run 3639 (16:27:59Z). Relevant base
context: the previous `main` push (`2517c8d2…`, PR #1189 — **before**
Batch 1) had QA Gate red, which made CI's Auto-Tag job fail its "Require
Security + QA gate approval" step; that pre-existing condition cleared with
this push — `main` is greener after the Batch 1 merge than before it.

## 6. Known deferred work (inherited by Batch 2+)

- **OPEN MODE / GAP-9 (SETUP-OPEN-MODE)** — unresolved backend/product
  decision; the setup-time `{unauth:true}` path stays withheld from v2
  (FRONTEND-FEATURE-PARITY.md FE-X02, FRONTEND-CURRENT-STATE.md GAP-9).
- **GAP-2** — no TOTP enrollment API; the enrollment screen stays descoped, not
  faked.
- **Legacy frontend still ships**: `static/index.html` serves `/` unchanged;
  the v2 app is embedded under `/app` behind `CULVERT_EXPERIMENTAL_UI`
  (**default OFF**, opt-in parser, read once at startup). Legacy cutover and
  removal belong exclusively to FE-8; no `/legacy/` route will ever exist.
- **SEC-C2 / SEC-PATCH / SEC-PROXY / SEC-HSTS** — separate backend security
  work items (FRONTEND-MIGRATION-PLAN.md §3); FE-8 cutover requires SEC-C2.
- FE-5..FE-8 not started. `CHANGELOG.md` deliberately not updated for the
  squash (recorded in the PR checklist). `internal/yara` per-pattern regex
  harness fix remains deferred (pre-existing). Audit "persistent file" source
  not browser-exercised (API-tested only).

## 7. Evidence-branch retention policy

`claude/culvert-frontend-modernization-qnyqb6` is the **forensic evidence
branch**: it holds the full granular, externally-reviewed commit history
(FE-1A → B1.3) whose final tree is byte-identical to the merged delivery. It is
**retained**: not deleted, not tagged, not renamed, not rewritten. Deletion is
an owner decision that may be taken only after this closeout record and the
qualification evidence are judged durably archived; nothing in Batch 2 depends
on removing it.
