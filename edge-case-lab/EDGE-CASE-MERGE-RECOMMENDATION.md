# Culvert Edge-Case Validation Lab — Merge Recommendation

## Verdict

# ACCEPT

The required hardening phase closed every R1–R7 requirement with direct evidence
(`EDGE-CASE-REQUIRED-FIXES-CLOSURE.md`). All eight ACCEPT preconditions are satisfied. The lab is
trustworthy, reproducible, and safe to merge as a **nightly and release-certification instrument**,
with the PR-smoke tier as a fast blocking gate. No Culvert product behavior was changed in this
phase; the SOCKS5 SECURITY_BYPASS and the other findings remain for the product team to fix.

## ACCEPT preconditions — all met

| Precondition | Status | Evidence |
|---|---|---|
| All R1–R7 requirements closed | ✅ | `EDGE-CASE-REQUIRED-FIXES-CLOSURE.md` |
| Persistence mutation detected | ✅ | mutation gate M4 → SWG-0124 (`reports/mutation-gate.jsonl`) |
| All eight mutations detected | ✅ | 8/8 in `reports/mutation-gate.jsonl` |
| Process isolation is deterministic | ✅ | `test_harness.py` `ownership.refuses_unmanaged`, `zombie.reaped_and_clean` |
| Block attribution no longer relies on status codes | ✅ | R3 `_attribute()`; `test_harness.py` `attr.*`, `upstream.not_policy_block` |
| Canonical behavior suite passes | ✅ | `suite_tiers.py nightly` (per-behavior representatives) all PASS |
| Raw evidence no longer committed by default | ✅ | `.gitignore` + `git rm --cached` (861 files); `sanitize_check.py` OK |
| All reports use corrected classifications | ✅ | regenerated `EDGE-CASE-RESULTS.*` + reclassification; SOCKS5=SECURITY_BYPASS |

## What changed since `REJECT`/`ACCEPT_WITH_REQUIRED_FIXES`

- **R1 Persistence:** harness runs the shipped `-policy` durable store; SWG-0124 verifies
  post-restart **enforcement** (decision trace), and the persistence mutation is now detected (was
  the sole mutation escape).
- **R2 Process ownership:** deterministic — tracks PID/PGID/commit/config, refuses to start over an
  unmanaged port owner, reaps strays, proves port release; the T4 zombie condition is a passing
  regression test.
- **R3 Attribution:** a BLOCK requires an authoritative Culvert marker; the full failure taxonomy is
  differentiated; upstream-fail-vs-policy-block is a live regression test.
- **R4 Canonical:** 215 raw → **49 canonical behaviors**; the 4 misleading weak-negative scenarios
  were fixed (now 0 invalid); registry + mapping shipped.
- **R5/R6:** explicit tiers (smoke ~40 s, nightly, full, release) with the required smoke contracts;
  raw evidence removed from git + sanitization gate.
- **R7:** classifications corrected and consistent across all reports; the "0 product bugs"
  conclusion is explicitly superseded (SOCKS5 → SECURITY_BYPASS; two findings downgraded).

## Standing gates (post-merge)
- PR smoke (blocking, ~40 s): 14 contracts + harness self-tests.
- Nightly canonical + 8/8 mutation floor (advisory → opens issues).
- Release certification (blocking): full campaign + canonical + 8/8 mutation gate + SSRF guard test,
  against the release image digest; blocks on any SECURITY_BYPASS/PRODUCT_BUG regression vs baseline.

## Residual (non-blocking) follow-ups
- Product: fix the SOCKS5 SECURITY_BYPASS (disable-default + unmanaged warning → policy parity),
  decide `priority:0` and `certVerification=permissive` contracts. (Out of scope for this branch.)
- Lab: add an IdP mock (identity/group + auth-timeout/IdP-down), CDR/PAC/client-cert/IPv6/CP-DP
  coverage; a frozen clock for schedule determinism; containerized isolation to allow parallelism.
- Derive small deterministic Go regression tests from each confirmed finding so the product gate
  never depends on the AI campaign (the SSRF guard test is the first).

## Scope guardrails honored
No product fixes implemented. Product mutations applied only in throwaway worktrees, restored after
each, worktrees removed; no `//MUT` markers remain in the tree. Pushed: harness hardening + review
artifacts + the test-only SSRF guard. **No pull request opened.**
