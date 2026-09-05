# Culvert Engineering Dashboard

> **Owner:** Chief Engineering Advisor (standing role)
> **Status:** Living document — re-validated against the repository, not assumed.
> **Last full review:** 2026-06-28 · **Last drift sync:** 2026-07-05 (registers + tree re-checked; scores moved on evidence below)
> **Next scheduled re-validation:** 2026-09-28 (quarterly) or on any change to architecture, HA, auth, or the release pipeline.
> **Drift flagged 2026-08-18, re-verified 2026-08-24, partially resolved 2026-08-25**
> (documentation-governance passes, fact-check only — **no maturity score has been re-judged**).
> Both halves of the 08-18 note have now moved, and this note states what is true of the tree as
> merged, not what either branch found in isolation:
>
> - **Package count — CORRECTED.** `ls internal | wc -l` = **65** (63 on 08-18; 48 before that).
>   §1 "Maintainability" and §2's ADR-0002 row are updated to 65.
> - **Register MCP-blindness — CLOSED.** The 2026-08-24/25 MCP backend security review
>   (`security-reviews/2026-08-24-mcp-backend-full-review.md` and the `2026-08-25` overnight
>   hardening run) entered RISK-026/027/028 and DEBT-011/012/013, so
>   `TECHNICAL-RISK-REGISTER.md` and `TECHNICAL-DEBT-REGISTER.md` are no longer MCP-blind. The
>   "zero matches for MCP in either" finding recorded in the 08-24 pass below is superseded.
> - **ADR-0024 index entry — PRESENT.** It is listed in the §2 governance artifact index.
> - **Still open:** the §4 specialized re-validation pass has not run since 2026-07-05. Closing
>   defects is not evidence of a higher maturity band, so no score moves here on the strength of
>   the MCP review; that judgement belongs to the specialized pass.

This is the single entry point for Culvert's engineering governance. It is intentionally short:
a scorecard, an index, and the rules that keep these documents *alive* rather than stale.

The **repository is the source of truth**. Every score and risk here is backed by a `file:line`
reference in the linked registers. When the code and a document disagree, the code wins and the
document is wrong — fix the document.

---

## 1. Maturity scorecard

Scores are 0–5. They are judgments backed by evidence in the linked registers, not metrics.
A score only moves when the underlying evidence changes in the repository.

| Dimension | Score | Trend | Basis (see registers for evidence) |
|---|:---:|:---:|---|
| Security | 4.3 | ↑ | The MEDIUM/LOW auth-surface risks closed 2026-07-05 (RISK-012 two-tier lockout, RISK-013 fail-closed host gate, RISK-019 trusted-proxy client IP — each adversarially reviewed). RISK-010 CLOSED 2026-07-11 (legacy updater removed under DEBT-008; successor is digest-pinned + Sigstore-verified) and RISK-011 re-pointed/closed the same day. **Not yet reflected in this score:** a 2026-07-11 failure-mode audit opened two new HIGH risks — RISK-021 (fresh/unconfigured proxy runs default-allow + no-auth) and RISK-022 (maintenance-agent death mid-apply is unrecoverable) — so "All non-accepted HIGH risks closed" no longer holds; this dimension needs re-validation against the register before the score is trusted. |
| Testing | 4.3 | ↑ | Behavioral suite, race+shuffle determinism gate. DEBT-007 closed (`mitm_inspect_e2e_test.go`, trust-asymmetry proof). Config-surface parity walls extended to the CP→DP `ConfigSnapshot` DTO (capture/apply/redaction/wire-wipe/owner, DEBT-006) — each proven to bite by negative test. |
| CI/CD & Release | 4.2 | ↑ | SHA-pinned actions, cosign keyless, SLSA L3, signed catalog (P2b-2b). Gate hardening landed 2026-07-04: per-module govulncheck, unmasked-vuln advisory report, self-expiring `.trivyignore`, all scanners version-pinned. Open: RISK-015 (LOW), CodeQL-as-required-check (maintainer branch-protection toggle). |
| Documentation | 4.0 | ↑ | Strong `CLAUDE.md` + roadmap + governance layer. Both formerly-missing runbooks now exist: `docs/operator/ha-lease-failover.md`, backup-restore §8b recovery. |
| Operability (single-CP) | 3.5 | → | Fail-static confirmed, atomic restore + interrupted-restore boot guard (RISK-005), OTLP traces, alert webhooks now durable (RISK-017). A distinct readiness probe exists on the proxy server (`/ready` → `handleReady`, config-snapshot-gated); the admin/LB probe `/healthz` still has no readiness sibling. |
| HA / DR readiness | 3.5 | ↑ | RISK-001 CLOSED: ADR-0005 etcd fencing lease — split-brain structurally prevented in lease mode (pinned by `TestCL4_*`), safe auto-failover, runbook. Residual: bounded LWW ≤TTL on partition; legacy (no-etcd) mode stays safe-manual. |
| Maintainability | 3.5 | ↑ | ADR-0002 decomposition COMPLETE (65 `internal/` packages as of 2026-08-24, up from 48 — count corrected, score not re-judged; the MITM trust core behind a compiler boundary); startup slices complete (24, contract-tested); DEBT-003 CLOSED — the three god-files (`controlplane.go`/`proxy.go`/`main.go`) split into cohesive same-package files + `handleHTTP`/`handleTunnelInspect` decomposed. Residual: root files still share one namespace (DEBT-001). |
| Architecture | 3.4 | ↑ | Engines own logic/state/persistence behind compiler-enforced `internal/` boundaries; `main` reduced to composition roots + shims. Config-surface drift (DEBT-004/006) CLOSED — the shared config DTOs are walled by the `config_surfaces` registry + reflection parity. Residual: the flat root namespace and its globals remain the tax (DEBT-001). |

**Headline:** The two items that blocked the enterprise claim in June — HA split-brain and the
un-decomposed flat package — are both resolved with evidence, and the **config-surface drift**
front is now essentially closed (DEBT-004 + DEBT-006 walled by the `config_surfaces` registry;
DEBT-009's ownership half declared, only its effective-config-visibility half open). The MEDIUM/LOW
auth-surface risks closed 2026-07-05 (RISK-012/013/019). **Update 2026-07-11:** the
**update/supply-chain trust chain** (RISK-010/011), previously the one material open front, is now
CLOSED — DEBT-008 removed the legacy updater sidecar entirely, RISK-010 closed by removal, and
RISK-011 was re-pointed to its successor (RISK-022). A 2026-07-11 failure-mode audit found two new
HIGH-severity open risks not yet triaged into this dashboard's priority ranking — RISK-021
(default-allow + no-auth on a fresh/unconfigured proxy) and RISK-022 (unrecoverable agent death
mid-apply on the new update path) — see §3 below and the register for detail; this headline needs
a maintainer re-validation pass to re-rank the current material front.

---

## 2. Governance artifact index

| Artifact | Location | Status |
|---|---|---|
| Engineering Constitution | `docs/engineering/ENGINEERING-CONSTITUTION.md` | ✅ Adopted (governing charter for this dashboard and the registers) |
| Engineering Dashboard | `docs/engineering/ENGINEERING-DASHBOARD.md` | ✅ Live (this file) |
| Technical Risk Register | `docs/engineering/TECHNICAL-RISK-REGISTER.md` | ✅ Live (last review 2026-07-05) |
| Technical Debt Register | `docs/engineering/TECHNICAL-DEBT-REGISTER.md` | ✅ Live (drift-synced 2026-07-04) |
| ADR practice | `docs/adr/0001-record-architecture-decisions.md` | ✅ Live |
| ADR-0002: package decomposition | `docs/adr/0002-flat-package-to-internal-decomposition.md` | ✅ Implemented (65 packages as of 2026-08-24, was 48; program complete) |
| ADR-0003: shared foundation seam | `docs/adr/0003-shared-foundation-seam.md` | ✅ Implemented |
| ADR-0004/0005: HA fencing + lease failover | `docs/adr/0004-*.md`, `docs/adr/0005-*.md` | ✅ Implemented (S0–S5 shipped; closed RISK-001) |
| ADR-0006: security-scanner DI | `docs/adr/0006-security-scanner-di.md` | ✅ Implemented |
| ADR-0024: MCP Agent Security Gateway trust boundary | `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md` | ✅ Accepted 2026-07-31; implemented PR-1..PR-12 (`internal/mcp`, 27 subpackages as of 2026-08-29 — ADR-0035 added `internal/mcp/canary`, was 25 as of 2026-08-24, disabled-by-default). **Register drift CLOSED 2026-08-24** by a full backend security review (`security-reviews/2026-08-24-mcp-backend-full-review.md`): 15 findings, 1 reachable-today P0 (assurance escalation via an unverified `DPoP:` header) fixed, 11 fixed in total; RISK-026/027/028 and DEBT-011/012/013 registered. **§1 scores NOT re-judged** — the review removed defects, which is not by itself evidence of a higher maturity band; the specialized re-validation pass described in §4 still has not run |
| MCP backend security review (2026-08-24) | `docs/engineering/security-reviews/2026-08-24-mcp-backend-full-review.md` | ✅ Complete. Establishes the shipped **reachability matrix** (Gateway/Observe only; Management, guarded execution, credential broker, upstream client and inspection are composed **nowhere** in production — `internal/mcp/execution` has zero importers in the tree). Verdict: **READY FOR SEPARATE SHADOW ACTIVATION REVIEW** for the code, with RISK-026 (no per-source admission) a blocker for exposing a listener beyond a controlled host |
| MCP protocol migration (frozen V1 → `2026-07-28`) | `docs/design/mcp/PROTOCOL-MIGRATION-2026-07-28.md` | 📝 Design only, 2026-08-24. `2026-07-28` is the FINAL MCP specification (the code comment had it as a non-final RC); the V1 allowlist is deliberately unchanged. Records the staged additive-adapter plan and the blocking ADR: a stateless core removes the substrate for session-identity binding, lifecycle admission and the session cap |
| Runbooks / Recovery Procedures | `docs/operator/` | ✅ HA failover + backup/restore/interrupted-restore covered; keep growing per feature |
| Enterprise Readiness Assessment | _(deferred)_ | ⏳ **Unblocked** (RISK-001 closed) — create at the next full review |
| Operational Readiness Assessment | _(deferred)_ | ⏳ Create alongside the Enterprise Readiness Assessment |
| Engineering Standards | `CLAUDE.md` (de-facto) | 🟡 Exists informally; promote when patterns stabilize |

**Why some are deferred, not stubbed:** an empty governance template is debt, not governance.
The deferred artifacts will be created when there is validated content to put in them
(Constitution: *never guess*).

---

## 3. Current engineering priority (Advisor's standing recommendation)

> **The 2026-06-28 feature freeze is LIFTED** — its justification (RISK-001 BLOCKER + the
> hours-to-fix security gaps) no longer exists; all of those items shipped with evidence.
>
> **Update 2026-07-11 — the update-trust gap is CLOSED.** DEBT-008 removed the legacy updater
> sidecar entirely; the maintenance-agent path is now the sole day-2 update mechanism and it *is*
> digest-pinned + Sigstore-verified (closing RISK-010 by removal and RISK-ACC-1's dependency tree
> with it). RISK-011's concern was resolved in the successor (`inline_rollback.go` verifies the
> revert); its residual is re-pointed to RISK-022.
>
> **This recommendation has not yet been re-issued for what replaced it.** The same 2026-07-11
> audit that closed this front also opened two new HIGH risks on the register — RISK-021
> (fresh/unconfigured proxy runs default-allow + no-auth, silent) and RISK-022 (maintenance-agent
> death mid-apply is unrecoverable, no op journal) — neither has been triaged into a standing
> priority call here. Treat this section as stale until a maintainer re-validates against
> `TECHNICAL-RISK-REGISTER.md` and issues the next recommendation.

Sequenced backlog (full detail in the registers):

1. ~~**This week:** gate hardening~~ ✅ **DONE 2026-07-04** — RISK-014 (per-module govulncheck),
   RISK-006 (unmasked advisory report + self-expiring `.trivyignore`), RISK-016 pins (found
   already fixed in tree), DEBT-010 (found already resolved by CI-REDESIGN step 7).
   **Remaining from this batch, maintainer-only:** add CodeQL to the required status checks
   (branch-protection setting — not expressible in repo code).
2. ~~**The one material front — the update-trust chain**~~ ✅ **DONE 2026-07-11** — DEBT-008
   removed the legacy `updater/` (closed RISK-ACC-1, the Dependabot banner, and RISK-010 all at
   once); RISK-011 resolved in the successor and re-pointed to RISK-022. **Needs a follow-up
   entry:** RISK-021 (HIGH, default-allow + no-auth on fresh install) and RISK-022 (HIGH,
   unrecoverable agent death mid-apply) are open on the register but not yet sequenced here.
3. ~~**Config-surface drift** (DEBT-004/006)~~ ✅ **DONE 2026-07-05** — walled by the
   `config_surfaces` registry + reflection parity (configBackup **and** the CP→DP ConfigSnapshot
   DTO). The recommended "per-surface membership table" shipped and is CI-enforced.
4. **Low-priority residuals (no compelling driver):** DEBT-009 — effective-config diagnostics
   endpoint (ownership half already registry-declared); a `/readyz` sibling for the admin/LB
   `/healthz` probe (a distinct `/ready` already exists on the proxy server); RISK-015/016 —
   scanner-source divergence + CodeQL-as-required-check (maintainer branch-protection toggle);
   DEBT-001 residual (flat namespace — diminishing returns, leave unless a concrete pain point
   drives it); failback UX for lease-mode HA.

---

## 4. How these documents stay alive (operating model)

1. **Re-validation over assumption.** At each quarterly review — and whenever a PR touches
   architecture, HA, auth, the proxy hot path, or the release pipeline — the affected register
   entries are re-checked against the code. Stale entries are corrected or closed with evidence.
2. **Specialized review only when it adds value.** Deep dives use independent sub-reviewers
   (architecture, security, CI/CD, testing, operations, performance, docs, enterprise readiness).
   Disagreements between reviewers are resolved *before* a recommendation is recorded here.
3. **Evidence or it didn't happen.** Every register entry carries a `file:line` or
   `workflow:job` reference. Claims without repository evidence are marked `UNVERIFIED`.
4. **Scores move only on evidence.** A dimension's score changes when a linked risk/debt item
   opens, closes, or materially changes — never on vibes.
5. **ADRs for anything that changes long-term architecture.** See ADR-0001.

---

## 5. Method note (honesty about this review's limits)

The 2026-06-28 baseline was produced by **source-read audit only**. The build, test suite, and
security scanners (`go test -race`, `govulncheck`, `gocyclo`, `gosec`) were **not executed** in
this environment. Complexity figures are branch-count/line-span proxies; security findings are
static, not dynamically confirmed. The three highest-stakes findings (RISK-001 HA split-brain,
RISK-002 OIDC SSRF, DEBT-002 `handleRequest` size) were hand-verified against source; the
remainder rest on sub-reviewer `file:line` evidence. Re-validate with the toolchain when CI access
is available.

**2026-07-04 drift sync:** score moves were verified against the tree, not the registers'
prose — `ls internal | wc -l` = 44 packages; `wc -l` on the four god-files; read of
`mitm_inspect_e2e_test.go` confirming a real TLS client through the inspect branch; presence of
both operator runbooks. The risk register (2026-07-03) was already current; the debt register was
drift-synced in the same pass (DEBT-005/007 closed, DEBT-001/003 progress recorded).

**2026-07-05 drift sync:** re-verified against the tree after a productive week of merges. Facts
checked: `ls internal | wc -l` = **48 packages** (was 44); root non-test `.go` = **184** (↑ from
172 — the DEBT-003 god-file splits trade huge files for cohesive ones, cohesion up not debt up);
`config_surfaces_test.go` carries **11 parity walls** incl. the new ConfigSnapshot
capture/apply/redaction/wire-wipe/owner tests; `/ready`→`handleReady` and `/health`→`handleHealth`
wired on the proxy server (`main.go`), `/healthz`→`apiHealthz` on the admin server. Closed this
week with evidence: **DEBT-003** (god-file splits + handler decomposition), **DEBT-004** +
**DEBT-006** (config-surface + ConfigSnapshot walls), **RISK-012/013/019** (auth-surface, each
adversarially reviewed). DEBT-009 downgraded (ownership half now registry-declared). RISK-010
resolution clarified: it closes via the DEBT-008 updater retirement, not a patch on `update.go`.
Net effect: the config-surface-drift front is closed; Security/Maintainability/Architecture/Testing
scores nudged up on evidence; the update-trust chain is now the sole material open front.

**2026-08-24 documentation-governance pass (fact-check only, no scores re-judged):** re-verified
the 2026-08-18 drift note against the current tree. `ls internal | wc -l` =
**65 packages** (was 63 on 08-18, 48 before that) — the count had already drifted again six days
after its last correction; §1 "Maintainability", §2's ADR-0002 row, and this note are now updated
to 65. **ADR-0024 is still not entered** in `TECHNICAL-DEBT-REGISTER.md` or
`TECHNICAL-RISK-REGISTER.md` (zero matches for "MCP" in either, confirmed again this pass) — that
gap is unchanged from 08-18 and is deliberately left open here rather than filled with an
unreviewed entry: populating it requires the specialized review pass described in §4 (independent
sub-reviewer read of the ~55k-LOC `internal/mcp` tree), which has not run since 2026-07-05, not a
one-line addition. Recommend scheduling that pass as the next §4 specialized review.

**Superseded 2026-08-25 (the register half only).** The "ADR-0024 is still not entered / zero
matches for MCP" finding above was accurate when that pass ran and is kept as written, but it no
longer describes the tree: the MCP backend security review entered RISK-026/027/028 and
DEBT-011/012/013 in the two registers. It was closed by exactly the route the entry asked for — a
review of the `internal/mcp` tree that produced reviewed entries — not by a one-line addition. The
**score** half stands unchanged: the §4 specialized re-validation pass still has not run since
2026-07-05, and no maturity band has moved.
