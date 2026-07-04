# Culvert Engineering Dashboard

> **Owner:** Chief Engineering Advisor (standing role)
> **Status:** Living document — re-validated against the repository, not assumed.
> **Last full review:** 2026-06-28 · **Last drift sync:** 2026-07-04 (registers + tree re-checked; scores moved on evidence below)
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
| Security | 4.2 | ↑ | All non-accepted HIGH risks closed (RISK-002/003 fixed; RISK-008 timing oracle; RISK-017 alert persistence). Open: RISK-010 (update image verify), gate blind spots. |
| Testing | 4.2 | ↑ | Behavioral suite, race+shuffle determinism gate. DEBT-007 closed: `mitm_inspect_e2e_test.go` drives real TLS through the inspect path (trust-asymmetry proof). |
| CI/CD & Release | 4.2 | ↑ | SHA-pinned actions, cosign keyless, SLSA L3, signed catalog (P2b-2b). Gate hardening landed 2026-07-04: per-module govulncheck, unmasked-vuln advisory report, self-expiring `.trivyignore`, all scanners version-pinned. Open: RISK-015 (LOW), CodeQL-as-required-check (maintainer branch-protection toggle). |
| Documentation | 4.0 | ↑ | Strong `CLAUDE.md` + roadmap + governance layer. Both formerly-missing runbooks now exist: `docs/operator/ha-lease-failover.md`, backup-restore §8b recovery. |
| Operability (single-CP) | 3.5 | → | Fail-static confirmed, atomic restore + interrupted-restore boot guard (RISK-005), OTLP traces, alert webhooks now durable (RISK-017). No distinct `/readyz`. |
| HA / DR readiness | 3.5 | ↑ | RISK-001 CLOSED: ADR-0005 etcd fencing lease — split-brain structurally prevented in lease mode (pinned by `TestCL4_*`), safe auto-failover, runbook. Residual: bounded LWW ≤TTL on partition; legacy (no-etcd) mode stays safe-manual. |
| Maintainability | 3.3 | ↑ | ADR-0002 decomposition COMPLETE (48 `internal/` packages; `upstream`+`session`+`configver`+`ca` extracted 2026-07-04 — the MITM trust core now behind a compiler boundary); startup slices complete (24, contract-tested); `store.go` halved. Residual: root files still share one namespace (DEBT-001/003). |
| Architecture | 3.2 | ↑ | Engines own logic/state/persistence behind compiler-enforced `internal/` boundaries; `main` reduced to composition roots + shims. Residual: the flat root namespace and its globals remain the tax (DEBT-001). |

**Headline:** The two items that blocked the enterprise claim in June — HA split-brain and the
un-decomposed flat package — are both resolved with evidence. The remaining risk mass has moved
to the **update/supply-chain trust chain** (RISK-010/011, gate hardening) and to
**config-surface drift** (DEBT-004/006/009). That is where attention should go next.

---

## 2. Governance artifact index

| Artifact | Location | Status |
|---|---|---|
| Engineering Constitution | `docs/engineering/ENGINEERING-CONSTITUTION.md` | ✅ Adopted (governing charter for this dashboard and the registers) |
| Engineering Dashboard | `docs/engineering/ENGINEERING-DASHBOARD.md` | ✅ Live (this file) |
| Technical Risk Register | `docs/engineering/TECHNICAL-RISK-REGISTER.md` | ✅ Live (last review 2026-07-03) |
| Technical Debt Register | `docs/engineering/TECHNICAL-DEBT-REGISTER.md` | ✅ Live (drift-synced 2026-07-04) |
| ADR practice | `docs/adr/0001-record-architecture-decisions.md` | ✅ Live |
| ADR-0002: package decomposition | `docs/adr/0002-flat-package-to-internal-decomposition.md` | ✅ Implemented (44 packages; program complete) |
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
2. **This month:** DEBT-008 — finish removing the legacy `updater/` (closes RISK-ACC-1 and the
   standing Dependabot banner); RISK-011 — post-rollback health verification + failure-path tests.
3. **This quarter:** RISK-010 — in-binary digest/signature verification of the applied image
   (natural extension of the P2b Sigstore machinery from catalogs to images);
   DEBT-004/006 — explicit per-surface config types to stop membership drift.
4. **Roadmap:** `/readyz` distinct from `/healthz`; DEBT-009 effective-config diagnostics
   endpoint; failback UX for lease-mode HA.

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
