# Culvert Engineering Dashboard

> **Owner:** Chief Engineering Advisor (standing role)
> **Status:** Living document — re-validated against the repository, not assumed.
> **Last full review:** 2026-06-28 · **Last drift sync:** 2026-07-05 (registers + tree re-checked; scores moved on evidence below)
> **Next scheduled re-validation:** 2026-09-28 (quarterly) or on any change to architecture, HA, auth, or the release pipeline.

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
| Security | 4.3 | ↑ | All non-accepted HIGH risks closed; the MEDIUM/LOW auth-surface risks closed 2026-07-05 (RISK-012 two-tier lockout, RISK-013 fail-closed host gate, RISK-019 trusted-proxy client IP — each adversarially reviewed). Open: RISK-010/011 (update image verify + rollback — resolve via the DEBT-008 updater retirement, not a patch). |
| Testing | 4.3 | ↑ | Behavioral suite, race+shuffle determinism gate. DEBT-007 closed (`mitm_inspect_e2e_test.go`, trust-asymmetry proof). Config-surface parity walls extended to the CP→DP `ConfigSnapshot` DTO (capture/apply/redaction/wire-wipe/owner, DEBT-006) — each proven to bite by negative test. |
| CI/CD & Release | 4.2 | ↑ | SHA-pinned actions, cosign keyless, SLSA L3, signed catalog (P2b-2b). Gate hardening landed 2026-07-04: per-module govulncheck, unmasked-vuln advisory report, self-expiring `.trivyignore`, all scanners version-pinned. Open: RISK-015 (LOW), CodeQL-as-required-check (maintainer branch-protection toggle). |
| Documentation | 4.0 | ↑ | Strong `CLAUDE.md` + roadmap + governance layer. Both formerly-missing runbooks now exist: `docs/operator/ha-lease-failover.md`, backup-restore §8b recovery. |
| Operability (single-CP) | 3.5 | → | Fail-static confirmed, atomic restore + interrupted-restore boot guard (RISK-005), OTLP traces, alert webhooks now durable (RISK-017). A distinct readiness probe exists on the proxy server (`/ready` → `handleReady`, config-snapshot-gated); the admin/LB probe `/healthz` still has no readiness sibling. |
| HA / DR readiness | 3.5 | ↑ | RISK-001 CLOSED: ADR-0005 etcd fencing lease — split-brain structurally prevented in lease mode (pinned by `TestCL4_*`), safe auto-failover, runbook. Residual: bounded LWW ≤TTL on partition; legacy (no-etcd) mode stays safe-manual. |
| Maintainability | 3.5 | ↑ | ADR-0002 decomposition COMPLETE (48 `internal/` packages; the MITM trust core behind a compiler boundary); startup slices complete (24, contract-tested); DEBT-003 CLOSED — the three god-files (`controlplane.go`/`proxy.go`/`main.go`) split into cohesive same-package files + `handleHTTP`/`handleTunnelInspect` decomposed. Residual: root files still share one namespace (DEBT-001). |
| Architecture | 3.4 | ↑ | Engines own logic/state/persistence behind compiler-enforced `internal/` boundaries; `main` reduced to composition roots + shims. Config-surface drift (DEBT-004/006) CLOSED — the shared config DTOs are walled by the `config_surfaces` registry + reflection parity. Residual: the flat root namespace and its globals remain the tax (DEBT-001). |

**Headline:** The two items that blocked the enterprise claim in June — HA split-brain and the
un-decomposed flat package — are both resolved with evidence, and the **config-surface drift**
front is now essentially closed (DEBT-004 + DEBT-006 walled by the `config_surfaces` registry;
DEBT-009's ownership half declared, only its effective-config-visibility half open). The MEDIUM/LOW
auth-surface risks closed 2026-07-05 (RISK-012/013/019). The remaining risk mass is now
concentrated almost entirely in the **update/supply-chain trust chain** (RISK-010/011) — and its
resolution is the DEBT-008 updater retirement, not a code patch on the dying path. That is the one
material open front; everything else on the board is LOW.

---

## 2. Governance artifact index

| Artifact | Location | Status |
|---|---|---|
| Engineering Constitution | `docs/engineering/ENGINEERING-CONSTITUTION.md` | ✅ Adopted (governing charter for this dashboard and the registers) |
| Engineering Dashboard | `docs/engineering/ENGINEERING-DASHBOARD.md` | ✅ Live (this file) |
| Technical Risk Register | `docs/engineering/TECHNICAL-RISK-REGISTER.md` | ✅ Live (last review 2026-07-05) |
| Technical Debt Register | `docs/engineering/TECHNICAL-DEBT-REGISTER.md` | ✅ Live (drift-synced 2026-07-04) |
| ADR practice | `docs/adr/0001-record-architecture-decisions.md` | ✅ Live |
| ADR-0002: package decomposition | `docs/adr/0002-flat-package-to-internal-decomposition.md` | ✅ Implemented (48 packages; program complete) |
| ADR-0003: shared foundation seam | `docs/adr/0003-shared-foundation-seam.md` | ✅ Implemented |
| ADR-0004/0005: HA fencing + lease failover | `docs/adr/0004-*.md`, `docs/adr/0005-*.md` | ✅ Implemented (S0–S5 shipped; closed RISK-001) |
| ADR-0006: security-scanner DI | `docs/adr/0006-security-scanner-di.md` | ✅ Implemented |
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
> **New standing recommendation: before the next feature, close the update-trust gap.** Culvert
> now verifies what it *advertises* (signed catalog, P2b) but not what it *runs* (RISK-010: the
> applied image is never signature/digest-verified in-binary) and not what it *undoes* (RISK-011:
> auto-rollback never confirms the node actually reverted). For a security product whose update
> path is the highest-value supply-chain target, that asymmetry is the most important open item.
> Removing the legacy updater (DEBT-008) is part of the same move — it deletes the entire
> vulnerable dependency tree behind RISK-ACC-1 (all 5 open Dependabot alerts) at once.

Sequenced backlog (full detail in the registers):

1. ~~**This week:** gate hardening~~ ✅ **DONE 2026-07-04** — RISK-014 (per-module govulncheck),
   RISK-006 (unmasked advisory report + self-expiring `.trivyignore`), RISK-016 pins (found
   already fixed in tree), DEBT-010 (found already resolved by CI-REDESIGN step 7).
   **Remaining from this batch, maintainer-only:** add CodeQL to the required status checks
   (branch-protection setting — not expressible in repo code).
2. **The one material front — the update-trust chain (currently on hold):** DEBT-008 — finish
   removing the legacy `updater/` (closes RISK-ACC-1, the Dependabot banner, and RISK-010 all at
   once — RISK-010's fix is this migration, since the catalog/agent path already digest-pins +
   Sigstore-verifies the image, P2b-2b). RISK-011 — post-rollback health verification + failure-path
   tests, which is testable **independent** of the updater/catalog cutover. Gating item is the
   production catalog-driven-update proof, not a code task.
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
