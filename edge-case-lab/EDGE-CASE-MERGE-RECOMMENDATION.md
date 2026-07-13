# Culvert Edge-Case Validation Lab — Merge Recommendation

## Verdict

# ACCEPT_WITH_REQUIRED_FIXES

## Rationale

The lab is a genuinely useful differential-testing instrument: it converts realistic enterprise
intent into real, traced, cryptographically-verified enforcement checks, and it surfaced findings
that matter — most importantly a **SECURITY_BYPASS on the advertised SOCKS5 interface**. Mutation
testing shows it reliably catches 7 of 8 injected enforcement regressions.

It is **not** yet trustworthy as a **blocking PR gate**, for concrete, evidence-based reasons:

1. This adversarial review found **two HIGH-severity harness defects** (zombie-process cross-scenario
   leakage; blocked-origin-as-Culvert-block) that silently produced wrong verdicts in the original
   campaign. They are fixed, but their existence proves the harness needs its own regression
   discipline before it can gate others.
2. The campaign **mis-classified** its most important finding (SOCKS5: MISSING_CAPABILITY → should be
   SECURITY_BYPASS) and **overstated** two others (persistence was the harness's own missing
   `-policy`; external-redirect rejection is correct behavior).
3. Mutation testing found an **escaped fault class** (policy **persistence** is never validated) and
   **scenario-quality defects** (weak negative vectors; thin precedence/ssl-bypass coverage).
4. Effective coverage is **51 distinct behaviors, not 215** (4.2× inflation); the headline metric is
   misleading.
5. Committing **13 MB / 645 evidence files** per run is unsustainable for the product repo.

None of these are fatal — the core is sound and the fixes are targeted — so the correct disposition
is **ACCEPT_WITH_REQUIRED_FIXES**, merging the harness + review artifacts as a **nightly/release
instrument** (not a blocking PR gate) and gating on the small derived Go tests instead.

## Required fixes (blocking — must land before the lab is used as any gate)

| # | Fix | Owner surface | Done-when (testable) |
|---|---|---|---|
| R1 | Reclassify SOCKS5 as **SECURITY_BYPASS** in the shipped campaign reports; file it as a product security issue with the disable-default + unmanaged-warning + parity options. | reports + issue | reports show SECURITY_BYPASS; product issue exists |
| R2 | Correct the **persistence** finding to TEST_INFRA and the **redirect** finding to EXPECTED_LIMITATION in the shipped reports. | reports | reclassification reflected in RESULTS.md |
| R3 | Close the **persistence mutation escape**: add a scenario that runs with `-policy /data/policy.json`, creates via API, restarts, asserts survival; and a Go `TestPolicyPersistence_WithPolicyFile`. | harness + Go test | a `Save()`-disabling mutation flips the scenario |
| R4 | Fix **weak negative vectors**: wildcard-allow-list "denied" probes must target a host outside the permit's wildcard (M7 detail). | scenarios_full.py | M7 mutation flips those scenarios |
| R5 | **Stop committing raw evidence**: `.gitignore` `evidence/` + per-run `scenarios/*.json`; keep harness + docs + summary JSON; publish evidence as CI artifacts. | repo hygiene | `git status` clean after a run except summary |
| R6 | Add **harness self-tests** (oracle unit tests + 2-scenario smoke + single-fixture health gate) so a broken harness fails fast, not silently. | harness | self-test catches T4/T5-class regressions |
| R7 | **Derive deterministic Go regression tests** from each confirmed finding (SOCKS5 parity, priority-0, permissive, persistence) so the gate never depends on the 215-scenario campaign. | Go tests | tests run in the `-race` suite |

## Recommended (non-blocking) improvements

- R8 Migrate the fixture transport to a **network namespace / build-tagged test CIDR** to decouple
  from the production SSRF blocklist (the added `edge_case_lab_ssrf_guard_test.go` is the interim
  guard).
- R9 Add **overlapping 3-rule precedence** scenarios and **≥2 ssl-bypass-list** scenarios.
- R10 Add an **IdP mock** to cover identity/group matching and the auth-timeout / IdP-down failure
  modes; add **CDR**, **PAC**, **client-cert**, **IPv6**, and **CP/DP-failover** coverage over time.
- R11 Inject a **frozen clock** for schedule scenarios to remove wall-clock boundary flakiness.
- R12 Report **distinct-behavior count**, not raw scenario count, as the coverage metric.

## Scope guardrails honored by this review
- No product fixes implemented. No product mutations committed or pushed (all applied only in the
  `/tmp/mut-tree` worktree, restored after each, worktree removed).
- Pushed artifacts: this review's `EDGE-CASE-*.md`/JSON, the harness-trust improvements
  (`CULVERT_LAB_BIN` override, 502/upstream-fail guard, `subset_run.py`, `scenario_uniqueness.py`,
  `retriage.py`), and the **test-only** `edge_case_lab_ssrf_guard_test.go` (no product behavior
  change).
- The reclassification and escaped-fault findings are recorded honestly, including where the
  original campaign was wrong.
