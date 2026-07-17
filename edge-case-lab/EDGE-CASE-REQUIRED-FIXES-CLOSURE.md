# Culvert Edge-Case Lab — Required-Fixes Closure (R1–R7)

Each required fix from `EDGE-CASE-MERGE-RECOMMENDATION.md` with its acceptance criteria and direct
evidence. No Culvert product behavior was changed in this phase (SOCKS5 and all product defects are
left unfixed by design).

Reproduce all of this with:
```
python3 edge-case-lab/harness/test_harness.py          # 22 harness unit/regression tests
python3 edge-case-lab/harness/suite_tiers.py smoke      # PR smoke tier
python3 edge-case-lab/harness/canonical.py             # canonical registry + mapping
python3 edge-case-lab/harness/sanitize_check.py edge-case-lab/scenarios edge-case-lab/evidence
bash /tmp/mutgate.sh                                    # 8/8 mutation acceptance gate (worktree)
```

---

## R1 — Persistence-path coverage ✅

**Change.** `Culvert.start()` now launches with the shipped durable-store flag
`-policy /data/policy.json` (`harness.py`, `POLICY_STORE`). The persistence scenario (SWG-0124)
creates policy via the Admin API, restarts the proxy **without wiping `/data`**, and asserts the
rule is both **present** (read-back) and **enforced** (post-restart decision trace).

**Evidence.**
- `repro_one.py SWG-0124` → `persistence after restart: {persisted_rules: 1, mismatches: []}`; the
  post-restart traces are authoritative: `POLICY_ALLOW rule="permit-app"` (permitted host still
  allowed) and `POLICY_DEFAULT_DENY` (unmatched host still denied). VERDICT PASS on both vectors —
  i.e. enforcement, not just a config read-back.
- **Fails if the store is omitted/broken:** the mutation `Save()→no-op` (M4) is now **detected** by
  SWG-0124 (mutation gate `M4 detected=yes`). Previously M4 escaped because the lab ran without
  `-policy`. (Store *corruption/replacement* is additionally covered by the fail-closed `Load`
  path; a corrupt/hand-edited store drops offending rules — documented in `policy.go Load`.)

Acceptance criteria met: durable config used; create→restart→verify enforcement; fails when the
store is disabled (M4 detected); post-restart decision trace + effective rule confirmed.

## R2 — Process ownership & isolation ✅

**Change.** `Culvert.start()` tracks the exact PID/PGID/start-time/commit/config
(`Culvert.info()`), reaps its own process group **and** strays, proves the ports are released
(`_await_ports_released` + robust `_port_in_use` connect-or-bind probe), and **refuses to start**
(`OwnershipError`) when an unmanaged process still owns the ports. `_await_ready` also fails fast if
the child exits during startup.

**Evidence** (`test_harness.py`):
- `ownership.refuses_unmanaged` — binds a non-culvert holder to the proxy port; `start()` raises
  `OwnershipError`. PASS.
- `zombie.reaped_and_clean` — **reproduces the original T4 stale-proxy condition**: starts an
  instance, creates a rule, spawns a stray culvert on the same ports, then a fresh `start()` reaps
  the stray and comes up with an empty rule-set (clean). PASS.
- PID/start-time/commit/config recorded in `Culvert.info()` (written to evidence per scenario).

Acceptance criteria met: exact PID tracked; refuses second instance over unmanaged ports; reaps
children; confirms port release; fails when cleanup unprovable; detects zombies pre-scenario;
records provenance; zombie regression test added.

## R3 — Enforcement attribution ✅

**Change.** A BLOCK/DROP/REDIRECT disposition now **requires an authoritative Culvert decision-trace
marker** (`_attribute()`); a status code alone can never be scored as a policy block. Failure modes
are differentiated into: `policy_block`, `default_deny`, `policy_drop`, `policy_redirect`,
`file_block`, `threat_block`, `auth_challenge`, `tls_validation_fail`, `upstream_fail`, `dns_fail`,
`fixture_fail`, `client_trust_fail`, `tls_handshake_fail`, `timeout`, `conn_reset`,
`unattributed_blockish`.

**Evidence** (`test_harness.py`):
- `attr.upstream_not_block` — a 502 after `POLICY_ALLOW` attributes to `upstream_fail`
  (disposition `conn_fail`), **never** a policy block. PASS.
- `attr.unattributed_blockish` — a 403 block-page with **no** Culvert marker is NOT trusted as a
  policy block. PASS.
- `attr.policy_block / default_deny / policy_drop / file_block` require their specific markers.
- `attr.dns_fail / timeout / client_trust_fail` differentiate client-side failures.
- **Live regression** `upstream.not_policy_block` — allow-all policy + dead upstream port → attributed
  upstream/fixture failure, not a policy block. PASS.

Acceptance criteria met: block requires authoritative evidence; failure taxonomy differentiated;
upstream-failure-not-policy-block regression added.

## R4 — Canonical scenario normalization ✅

**Change.** `canonical.py` emits `EDGE-CASE-CANONICAL-BEHAVIORS.json` (registry with behavior-id,
capability, policy dimension, protocol, positive/negative/boundary vector, failure mode, expected
decision, required evidence, mapped scenarios) and `EDGE-CASE-SCENARIO-MAPPING.json` (all 215 →
behavior id + validity). It also detects and (after fixes) reports **0** misleading scenarios whose
negative vector is accidentally permitted.

**Evidence.**
- Registry counts: **raw 215 → 49 canonical behaviors**, **166 parameter-only variations**,
  **0 invalid/misleading** (the M7-class weak-negative scenarios SWG-0037/0039/0041/0127 were
  *fixed*: negative vector now targets a host outside the wildcard permit; the carve-out exception
  moved above the broad permit). Verified live: SWG-0037 and SWG-0127 now PASS with correct
  enforcement, and M7 detects them in the mutation gate.
- `reports/canonical-summary.json` records `behavioral_collapse_ratio: 4.22`.

Acceptance criteria met: machine-readable registry with all required fields; 215 mapped; weak
negatives removed (fixed); raw/canonical/effective/param-only/invalid reported; raw count is not the
headline metric.

## R5 — Suite tiers ✅

`suite_tiers.py {smoke|nightly|full}` + release path. Tiers, membership, and measured runtimes in
`EDGE-CASE-SUITE-TIERS.md`.
- **PR smoke** = 14 curated deterministic scenarios (first-match, default-deny, tenant isolation,
  TLS inspect, ssl-bypass, file-block-under-TLS, threat-intel, schedule, durable restart, auth
  boundary, decision-trace attribution, category, wildcard boundary) **+ the harness self-tests**
  (upstream-vs-block + attribution). Measured **~25 s** scenarios + self-tests. All 14 PASS.
- **Nightly** = one representative per canonical behavior (49). **Full** = 215. **Release** =
  canonical + fresh campaign + 8/8 mutation floor + SSRF guard test.

Acceptance criteria met: explicit tiers, required smoke contracts covered (upstream-vs-policy-block
via self-test), runtime/resource documented.

## R6 — Evidence retention ✅

**Change.** `edge-case-lab/evidence/` and `edge-case-lab/scenarios/` are git-ignored and removed
from the index (`git rm --cached`, **861 files / ~13 MB** off the branch, kept on disk). Committed:
schema, canonical manifests, summaries, fixtures (cert only), `representative_evidence/`, harness +
docs. `sanitize_check.py` gates any evidence commit/upload against Authorization headers, cookies,
session tokens, private keys, and the lab's own credentials/passphrases.

**Evidence.**
- `.gitignore` updated; `git rm --cached` staged 861 deletions.
- `sanitize_check.py edge-case-lab/scenarios edge-case-lab/evidence` → **SANITIZATION OK**.
- Retention matrix per tier in `EDGE-CASE-EVIDENCE-RETENTION.md`.

Acceptance criteria met: raw success evidence no longer committed; retention defined per tier;
sanitization checks added; generated raw evidence removed from the branch (source manifests +
representative reproductions preserved).

## R7 — Report correction ✅

All reports regenerated/updated so classifications are consistent (see the regenerated
`EDGE-CASE-RESULTS.md/json`, `EDGE-CASE-MISSING-CAPABILITIES.md`, `EDGE-CASE-UX-AND-CONTRACT-GAPS.md`,
`EDGE-CASE-COVERAGE-REPORT.md`, and `EDGE-CASE-FINDING-RECLASSIFICATION.md`):
- **SOCKS5 = SECURITY_BYPASS** (scenario triage + severity ordering updated; reports surface it as a
  dedicated section).
- **Persistence = TEST_INFRA in the original run** (harness omitted `-policy`); now a **passing**
  durable-restart scenario after R1.
- **External redirect = EXPECTED_LIMITATION** (correct security control).
- **priority-0 and permissive = CONFIGURATION_CONTRACT_GAP** (retained).
- Campaign executed **215 scenarios representing 49 canonical behaviors** (originally reported 51;
  reduced to 49 after fixing the misleading scenarios).
- The original **"0 product bugs"** conclusion is stated as **materially corrected** by the
  adversarial review (SOCKS5 elevated to SECURITY_BYPASS; two findings downgraded).
- Historical/original reports are marked **SUPERSEDED** where they retain the old classifications.

## Mutation acceptance gate ✅ — 8 / 8

`reports/mutation-gate.jsonl` (worktree, restored, nothing pushed):

| Mutation | Detected | Detecting scenarios |
|---|---|---|
| M1 first-match→last-match | yes | SWG-0007, SWG-0057 |
| M2 TLS file-block skipped | yes | SWG-0074, SWG-0075 |
| M3 source/tenant ignored | yes | SWG-0006, SWG-0121 |
| M4 persistence disabled | **yes** (was the escape) | SWG-0124 |
| M5 threat-intel bypassed | yes | SWG-0013, SWG-0088 |
| M6 schedule inverted | yes | SWG-0019, SWG-0020 |
| M7 default-deny→allow | yes | SWG-0009, SWG-0037 |
| M8 ssl-bypass-list ignored | yes | SWG-0011 |

Clean-tree restoration verified after each mutation; the throwaway worktree was removed; no `//MUT`
markers remain in the main tree.

---

## Validation results (exact commands + outcomes)

| Command | Result |
|---|---|
| `python3 harness/test_harness.py` | **22 passed, 0 failed** (oracle, R3 attribution, schema, R2 ownership+zombie, upstream-fail, deterministic replay) |
| `python3 harness/suite_tiers.py smoke` | 14 scenarios **14 PASS**, 0 unexpected-fail, ~25 s + 22 self-tests |
| `python3 harness/suite_tiers.py nightly` | 49 canonical representatives, **0 unexpected regressions**, 73 s |
| `python3 harness/run_campaign.py --per 30` | 215 scenarios: **PASS 201 (93.5%)**, SECURITY_BYPASS 2, CONFIG_CONTRACT_GAP 5, EXPECTED_LIMITATION 6, TEST_INFRA 1 |
| `python3 harness/canonical.py` | 215 raw → **49 canonical behaviors**, **0 invalid/misleading**, 166 param-only |
| `python3 harness/sanitize_check.py …` | **SANITIZATION OK** on scenarios, evidence, representative_evidence, reports |
| `bash /tmp/mutgate.sh` | **8 / 8 mutations detected**, clean restore, worktree removed, no `//MUT` in tree |
| `go test -run TestSSRFGuard .` | **ok** — no test SSRF exemption active; TEST-NET stays dialable |
| deterministic replay (`replay.deterministic`) | same scenario twice → identical PASS |
| zombie regression (`zombie.reaped_and_clean`) | stray proxy reaped; fresh instance comes up clean |

All eight ACCEPT preconditions satisfied → `EDGE-CASE-MERGE-RECOMMENDATION.md` verdict = **ACCEPT**.
