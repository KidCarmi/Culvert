# Culvert Engineering Dashboard

> **Owner:** Chief Engineering Advisor (standing role)
> **Status:** Living document — re-validated against the repository, not assumed.
> **Last full review:** 2026-06-28
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
| Security | 4.0 | → | Fail-closed RBAC, 600k PBKDF2, DNS-rebind-safe SSRF. Open: RISK-002, RISK-003. |
| Testing | 4.0 | → | Behavioral suite, race+shuffle determinism gate. Gap: DEBT-007 (no e2e MITM test). |
| CI/CD & Release | 4.0 | → | SHA-pinned actions, cosign keyless, SLSA L3. Open: RISK-006. |
| Documentation | 3.5 | ↑ | Strong `CLAUDE.md` + roadmap; governance layer seeded 2026-06-28. Gaps: missing runbooks. |
| Operability (single-CP) | 3.5 | → | Fail-static confirmed, atomic restore, OTLP traces. No distinct `/readyz`. |
| Maintainability | 2.5 | → | God-files, 497-line `handleRequest`, ~359 globals. See DEBT-001..005. |
| Architecture | 2.5 | → | Flat `package main`, no compiler-enforced boundaries. See ADR-0002. |
| HA / DR readiness | 2.0 | → | Split-brain-capable, no quorum/fencing. See RISK-001 (BLOCKER). |

**Headline:** Quality is real but increasingly *carried by tests compensating for structure the
language could enforce for free*. The flat package (ADR-0002) is the tax that makes the lower
scores hard to raise; the HA design (RISK-001) is the one item that blocks an enterprise claim.

---

## 2. Governance artifact index

| Artifact | Location | Status |
|---|---|---|
| Engineering Dashboard | `docs/engineering/ENGINEERING-DASHBOARD.md` | ✅ Live (this file) |
| Technical Risk Register | `docs/engineering/TECHNICAL-RISK-REGISTER.md` | ✅ Live |
| Technical Debt Register | `docs/engineering/TECHNICAL-DEBT-REGISTER.md` | ✅ Live |
| ADR practice | `docs/adr/0001-record-architecture-decisions.md` | ✅ Live |
| ADR-0002: package decomposition | `docs/adr/0002-flat-package-to-internal-decomposition.md` | 🟡 Proposed |
| Enterprise Readiness Assessment | _(deferred)_ | ⏳ Create when RISK-001 has a decided direction |
| Operational Readiness Assessment | _(deferred)_ | ⏳ Create alongside the first recovery runbook |
| Engineering Standards | `CLAUDE.md` (de-facto) | 🟡 Exists informally; promote when patterns stabilize |
| Runbooks / Recovery Procedures | `docs/operator/` (partial) | ⏳ Missing: HA split-brain recovery, interrupted-restore recovery |

**Why some are deferred, not stubbed:** an empty governance template is debt, not governance.
The deferred artifacts will be created when there is validated content to put in them — a recovery
runbook must be traced against the real recovery code path, not guessed (Constitution: *never guess*).
The two missing runbooks are tracked as committed actions in the Risk Register (RISK-001, RISK-005).

---

## 3. Current engineering priority (Advisor's standing recommendation)

> **Recommendation: do not start new feature work until the "this-week" security fixes land and
> RISK-001 (HA split-brain) has a decided direction.** The marginal value of another feature is
> lower than the marginal value of closing a BLOCKER that invalidates the enterprise-HA claim and
> a set of hours-to-fix security gaps. This is a deliberate call to slow feature velocity in favor
> of foundational health, per the Engineering Constitution.

Sequenced backlog (full detail in the registers):

1. **This week (hours each):** RISK-002 (OIDC SSRF one-liner), RISK-003 (webhook secret at rest),
   RISK-008 (username timing oracle), RISK-009 (`InsecureSkipVerify` warning), RISK-006 (pin CI scanners).
2. **This month:** RISK-001 mitigation (fencing token + honest HA docs + split-brain runbook),
   DEBT-007 (e2e MITM test), add CodeQL to the merge-blocking set.
3. **This quarter (ADR-gated):** DEBT-002 (decompose `handleRequest`), then begin ADR-0002
   leaf-cluster `internal/` extraction.
4. **Roadmap:** real HA consensus, self-update in-binary verification, rollback verification.

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
