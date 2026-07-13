# Culvert Edge-Case Validation Lab — Adversarial Acceptance Review

**Question:** Is the campaign evidence, classification, and harness trustworthy enough to merge and
use as a long-term product gate?

**Answer (summary):** The lab's core mechanism is sound and it found genuine, valuable results —
but this adversarial review found **two HIGH-severity harness defects that made parts of the
original campaign untrustworthy**, **one under-classified security finding**, **two overstated
findings** (one caused by the harness's own misconfiguration), a **4.2× coverage inflation**, and
**one escaped fault class (persistence)**. It is **not** yet fit as a *blocking PR gate*, but it is
valuable as a nightly/release instrument once the required fixes land. **Verdict:
`ACCEPT_WITH_REQUIRED_FIXES`** (see `EDGE-CASE-MERGE-RECOMMENDATION.md`).

Companion documents: `EDGE-CASE-FINDING-RECLASSIFICATION.md`, `EDGE-CASE-HARNESS-THREAT-MODEL.md`,
`EDGE-CASE-MUTATION-VALIDATION.md`, `EDGE-CASE-SCENARIO-UNIQUENESS.md`,
`EDGE-CASE-CI-INTEGRATION-PLAN.md`.

---

## 1. Challenging "0 confirmed product bugs"

The claim survives in the **strict PRODUCT_BUG** sense, but it is **misleading as stated**:

- **SOCKS5 was under-classified.** Labeled MISSING_CAPABILITY; the evidence supports
  **SECURITY_BYPASS** — an advertised proxy interface that, when enabled, bypasses the entire PBAC
  policy engine (authz, categories, source/tenant, schedules, TLS inspection, rule-attributed
  audit), retaining only blocklist/SSRF/optional-auth. "0 product bugs" hid a security-relevant
  enforcement-boundary gap behind a benign-sounding label.
- **Two findings were overstated.** "Policy lost on restart" is a **harness-configuration artifact**
  (the lab omitted `-policy`, which the shipped compose file sets; every API mutation calls
  `policyStore.Save()`). "External redirect rejected" is **correct anti-open-redirect behavior**,
  not a gap. Both are downgraded.
- **Two hold, softened:** priority-0 coercion (documented behavior; a real UX/documentation footgun
  with latent fail-open) and permissive-cert-verification (fail-closed; low severity).

Full evidence and reclassification table in `EDGE-CASE-FINDING-RECLASSIFICATION.md`.

## 2. SOCKS5 policy-boundary review (as requested)

| Question | Finding |
|---|---|
| Advertised/exposed as a supported interface? | **Yes** — README masthead + feature table; RFC 1928/1929. |
| Would admins reasonably expect access policy to apply? | **Yes** — no doc places it outside the managed boundary. |
| Auth/authz/tenant/URL/threat/logging bypassed? | **PBAC authz, URL/category, source-IP tenant isolation, schedules, TLS inspection, and rule-attributed logging are bypassed.** Retained: RFC-1929 auth (if configured), manual blocklist, plugin, SSRF. |
| Enabled by default? | **No** — `-socks5-port 0` (disabled). |
| Reachable outside management network? | Listener binds **all interfaces** (`:port`) when enabled. |
| Correct immediate mitigation | Keep disabled-by-default; on enable emit an explicit **"unmanaged mode"** warning (startup + UI/health); offer allowlist-only mode; ultimately route SOCKS5 through `policyStore.Evaluate` for full parity. |

**Classification: SECURITY_BYPASS** (latent/opt-in). Per the review instruction, MISSING_CAPABILITY
is not defensible — there is no explicit product contract placing SOCKS5 outside the security
boundary; it is advertised *inside* the proxy feature set.

## 3. Harness trust review (false passes / false failures)

Two **HIGH-severity** harness defects were found — both latent false-verdict generators the
campaign itself did not catch:

- **T4 — zombie-process leakage (fixed):** the persistence scenario's `start(fresh=False)` spawned a
  second proxy without killing the first; ~90 later scenarios ran against a stale zombie
  (`"priority already in use"`, wrong verdicts). `start()` now always stops + kills strays.
- **T5 — blocked-origin ≠ Culvert-block (fixed):** a 502 (upstream unreachable) after a
  `POLICY_ALLOW` was misclassified as a policy block. Now reclassified TEST_INFRA via decision-trace
  cross-check. This review reproduced it live (container restart + duplicate fixtures).

Verified-good properties: Oracle independence (imports no Culvert code; evaluated *before* the
traffic call; Operator never sees its output), cryptographic TLS-interception proof (CA trust
asymmetry, not HTTP inference), fresh-`/data` reset per scenario, and clean-env re-confirmation of
bug candidates. **Caveat (T1):** the Oracle was tuned twice during the campaign to match Culvert's
documented contract — a controlled independence erosion whose backstop is mutation testing. Full
model in `EDGE-CASE-HARNESS-THREAT-MODEL.md`.

## 4. TEST-NET architecture review (as requested)

- **Isolation:** the `192.0.2.0/24` dependency is an explicit **lab mechanism**; production code
  adds **no** exemption — the lab exploits that TEST-NET is already outside the SSRF blocklist.
- **Does production rely on TEST-NET being unblocked?** No product code or policy depends on it;
  only the lab's fixtures do.
- **Future SSRF hardening risk:** if TEST-NET is added to the blocklist, every fixture dial fails
  and the lab silently goes red. Mitigated by the added regression test
  (`edge_case_lab_ssrf_guard_test.go`): `TestSSRFGuard_NoTestExemptionActive` proves no loopback
  exemption is active in a normal build, and `TestSSRFGuard_TestNetRemainsAllowed` fails loudly if
  TEST-NET is ever blocked — forcing a deliberate lab migration.
- **Safer long-term boundary:** a **network namespace** or a **build-tagged, test-only fixture
  CIDR/transport** would decouple the lab from the production SSRF blocklist entirely. Recommended
  before promoting the lab to a blocking gate.

## 5. Mutation validation (does the lab catch real regressions?)

**7 / 8 mutations detected** (first-match, TLS file-block, source/tenant, threat-intel, schedule,
default-deny, ssl-bypass-list). **1 escaped: policy persistence** — the lab never runs with
`-policy`, so a `Save()`-disabling mutation changes nothing. Partial detections exposed real
**scenario-quality defects** (wildcard allow-lists with a negative vector accidentally inside the
permit; only one ssl-bypass-*list* scenario; precedence resting on ~4 clean cases). All worktree
mutations were restored; nothing was pushed. Details + required new scenarios in
`EDGE-CASE-MUTATION-VALIDATION.md`.

## 6. Scenario-quality review

**215 raw scenarios collapse to 51 distinct behavioral fingerprints (4.2× multiplier; 24%
behaviorally distinct).** 405 vectors (194 positive / 211 negative) — decent polarity balance, but
protocol diversity is http-heavy (http 314 / https 89 / socks5 2), tenant diversity is minimal
(2 source classes), and identity/group behavior is absent (no IdP). The raw count must **not** be
the success metric. Full analysis in `EDGE-CASE-SCENARIO-UNIQUENESS.md`.

## 7. Repository / CI integration

Committed evidence is **13 MB / 645 files** — too much churn for the product repo. Recommendation:
`.gitignore` the raw evidence + per-run manifests, keep only harness + docs + the summary JSON,
publish full evidence as CI artifacts / release attachments, and **convert each confirmed finding to
a small deterministic Go test** so the gate never depends permanently on the AI campaign. Tiering
(PR smoke ≤3 min / nightly full / release certification) in `EDGE-CASE-CI-INTEGRATION-PLAN.md`.

## 8. What must change before this is a trusted gate (required fixes)
See `EDGE-CASE-MERGE-RECOMMENDATION.md` for the enumerated, testable list. Headline items:
reclassify SOCKS5 as SECURITY_BYPASS in the shipped reports; correct the persistence + redirect
overstatements; close the persistence mutation escape; fix weak negative vectors; stop committing
raw evidence; add harness self-tests; and derive deterministic Go regression tests from confirmed
findings.
