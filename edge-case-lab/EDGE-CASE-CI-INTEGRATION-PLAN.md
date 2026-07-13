# Culvert Edge-Case Lab — CI Integration & Evidence-Retention Plan

Goal: extract durable value from the lab **without** bloating the repo or slowing the PR gate,
and without letting a 215-scenario AI campaign become a permanent load-bearing test.

## Guiding principle
**Every confirmed product finding must become a small, deterministic Go regression test.** The
215-scenario campaign is a *discovery and coverage* instrument, not a merge gate. The gate is a
handful of fast, hermetic tests derived from what the campaign found.

## Tiered suites

| Tier | Trigger | Scope | Budget | Blocking? |
|---|---|---|---|---|
| **PR smoke** | every PR touching `proxy*.go`, `policy.go`, `socks5.go`, `ui_policy.go`, `internal/{ssrf,decryptprofile,catgroup}` | ~12 scenarios: 1 per critical behavior (first-match, default-deny, category, source/tenant, TLS inspect-vs-bypass, ssl-bypass-list, threat-intel, schedule, file-block, redirect, drop, SOCKS5-parity) + the mutation-critical **default-deny** and **source-match** cases | ≤ 3 min | **Yes** (fast, high-signal) |
| **Nightly** | cron | Full 215 campaign + the 8-mutation validation (must keep 7/8+ detection) | ≤ 30 min | No (advisory; opens issues) |
| **Full campaign** | manual / weekly | 215 + retriage + coverage & uniqueness reports | ~40 min | No |
| **Release certification** | tag `v*` | Full campaign **plus** mutation validation **plus** the SSRF-guard regression test, on the release image digest; must show 0 unresolved PRODUCT_BUG/SECURITY_BYPASS regressions vs the last release baseline | ~45 min | **Yes** (release blocker) |
| **Manual reproduction** | on demand | `repro_one.py <ID>` against any build | seconds | n/a |

The PR smoke suite must be **derived deterministic Go tests where possible** (see below), falling
back to the Python harness only for scenarios that genuinely need the full proxy + TLS-interception
proof. Health-gate the harness (probe the fixture returns 200 before running; single-fixture
invariant) so infra flakiness reports TEST_INFRA, never a red gate.

## Convert confirmed findings to deterministic Go tests (do this before merge)
These replace the "permanent 215-scenario dependency" with cheap guards:
1. `TestSOCKS5_PolicyParity` — SOCKS5 CONNECT to a policy-blocked host is blocked (currently would
   FAIL → documents the SECURITY_BYPASS; mark `t.Skip` with a TODO until the product fix lands, or
   assert the current unmanaged behavior + a startup-warning is emitted).
2. `TestPriorityZero_Coercion` — POST a rule with `priority:0`, assert the API either rejects it or
   the read-back priority + a warning make the coercion explicit.
3. `TestDecryptProfile_PermissiveSemantics` — assert `permissive` either allows+logs or is rejected
   (pins the contract once decided).
4. `TestPolicyPersistence_WithPolicyFile` — with `-policy`, create via API, restart, assert rules
   survive (closes the mutation-validation M4 escape).
5. `TestSSRFGuard_NoTestExemptionActive` / `_TestNetRemainsAllowed` — **already added** in
   `edge_case_lab_ssrf_guard_test.go` (this review).
These are hermetic (`startTestProxy` + in-process fixtures already exist in the repo) and run in
the normal `-race` suite, not the AI campaign.

## Repository size & evidence retention
Current footprint committed by the campaign: **13 MB** — `evidence/` 8.4 MB / **645 files**,
`scenarios/` 2.2 MB / 215 files. This is too much churn for the product repo (every run rewrites
645 files, polluting diffs and history).

**Recommendation:**
- **Do NOT commit** `evidence/` or per-run `scenarios/*.json`. Add them to `.gitignore`.
- **Commit** (small, stable): the harness code, the schema, the capability matrix, the design docs,
  and the machine-readable `reports/EDGE-CASE-RESULTS.json` **summary** (counts + per-scenario
  classification, no bodies) — a few hundred KB, changes rarely.
- **CI artifacts** (nightly/release): upload the full `evidence/` + manifests as a build artifact
  with 30–90 day retention; attach the release-certification evidence bundle (compressed
  `.tar.gz`) to the GitHub Release.
- **External retention** for long-term trend analysis (coverage %, mutation-detection rate over
  time): push the summary JSON to an object store / dashboard, not git.

Net: the repo keeps ~1–2 MB of stable harness + docs + summary; raw evidence lives in CI
artifacts / releases.

## Ownership & drift control
- The lab has its OWN regression risk (this review found 2 HIGH-severity harness defects). Add a
  tiny `harness_selftest` (oracle unit tests + a 2-scenario smoke) to the harness so a broken
  harness fails fast instead of silently mis-verdicting.
- Pin the mutation-detection floor (≥7/8) as a nightly assertion; a drop means the harness or
  scenarios regressed.
- Re-baseline the campaign classification set on each release; treat any NEW non-PASS vs baseline
  as an issue to triage, not an auto-fail.
