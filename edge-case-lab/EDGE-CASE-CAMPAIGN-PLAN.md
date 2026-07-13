# Culvert Edge-Case Validation Lab — Campaign Plan

## Objective
Produce trustworthy evidence about whether Culvert can convert realistic enterprise SWG
intent into **correct, persistent, enforceable, and explainable** behavior — across ≥210
accepted, deterministic, deduplicated scenarios covering the capability matrix.

## Method (per the five-role model)
1. **Generate** enterprise-realistic requirements as product-neutral `intent` + deterministic
   `vectors` (positive / negative / boundary), dedup'd by semantic fingerprint.
2. **Configure** each via the supported admin API only (no direct DB writes); read back and
   export the effective config to detect silent drops / coercion.
3. **Predict** the expected disposition with an independent Oracle (general SWG semantics +
   Culvert's documented contract), *before* the runtime result exists.
4. **Execute** real traffic (HTTP / HTTPS-CONNECT / SOCKS5) through the proxy to local TEST-NET
   fixtures; capture status, block page, TLS-interception proof, decision trace, stats deltas.
5. **Classify** each scenario into exactly one of ten categories; **re-confirm** every
   PRODUCT_BUG in a second fresh instance.

## Scenario quality gate (enforced by the Generator)
Every accepted scenario: represents a realistic enterprise admin requirement; is supportable by
a mature SWG; has a **deterministic** expected outcome; defines all identities/networks/
destinations/schedules/files/failures explicitly (no subjective terms — "streaming", "guest
network", "corporate subnet 192.0.2.0/24", ".exe", "untrusted upstream cert" are all concrete);
makes precedence explicit; is reproducible with local fixtures; does not depend on unstable
public internet; tests real product behavior; is not semantically equivalent to an accepted
scenario (16-hex fingerprint over identity + source + destination + schedule + auth + TLS +
content-control + failure + action); and includes positive/negative/boundary vectors where
applicable.

## Duplicate prevention
Semantic fingerprint dimensions: `match-dimension + destination + action + ssl-behavior +
precedence-shape + failure-mode + source-scope`. A candidate whose fingerprint already exists is
**rejected** and a fresh candidate generated. All 215 accepted scenarios have unique
fingerprints; the generator rejected duplicate candidates during matrix expansion.

## Batch structure
- **Target:** 7 batches × 30 = 210; **accepted:** 215 (extra to exceed the floor).
- **Isolation:** every scenario runs in a **fresh `/data` + restarted process** (strongest
  isolation: no config/cache/auto-learn/session/rate-limiter leakage; auth scenarios that leave
  the instance configured cannot pollute the next open-mode scenario). Batches are a reporting
  grouping; isolation is per-scenario.
- **Confirmation:** each PRODUCT_BUG candidate re-runs in a second fresh instance before report.

## Capability coverage plan
Families map onto the capability matrix (see `EDGE-CASE-CAPABILITY-MATRIX.md`): URL/domain
objects, categories & groups, source/zone, rule ordering & first-match, default-deny, TLS
inspect/bypass & precedence, certificate-validation failure, decryption profiles, file/MIME
download control, threat-intel/blocklist, redirect & drop actions, rule lifecycle, schedules,
compound conditions, streaming/chunked/large/redirect integrity, multi-tenant isolation,
object lifecycle & referential integrity, policy conflicts, observability/decision-trace,
concurrency, configuration persistence, and the SOCKS5 / identity-scrub / open-redirect
gap-finding families. Genuinely-untestable dimensions (GeoIP, IPv6, DNS-rebinding, WebSocket,
partial-content, client-cert origins, CDR, PAC, IdP/CP unavailability) are **recorded honestly**
rather than faked.

## Failure taxonomy (exactly one primary class per scenario)
`PASS` · `PRODUCT_BUG` · `MISSING_CAPABILITY` · `CONFIGURATION_CONTRACT_GAP` · `UX_GAP` ·
`OBSERVABILITY_GAP` · `DOCUMENTATION_GAP` · `EXPECTED_LIMITATION` · `TEST_INFRA_FAILURE` ·
`INVALID_SCENARIO`.

**PRODUCT_BUG only when** the scenario is valid, the required config is supported and accepted,
the expected outcome is deterministic, the observed enforcement differs, and it reproduces in a
clean environment. **MISSING_CAPABILITY** when a valid enterprise requirement cannot be
represented in Culvert. **CONFIGURATION_CONTRACT_GAP** when behavior may exist but can't be
configured safely/predictably. **TEST_INFRA_FAILURE** when the fixture/harness/Oracle is the
likely cause. The Failure Reviewer never files a PRODUCT_BUG on an `uncertain` Oracle
expectation.

## Pilot-first discipline (completed before scale-up)
A 5-scenario pilot (wildcard FQDN block, category-group block, source-subnet restriction, TLS
inspect/bypass, default-deny) was executed and its evidence reviewed for: independent-oracle
correctness, isolation integrity, decision-trace richness, and taxonomy application. Three
harness defects were found and fixed *before* scaling — (a) an Operator ordering bug where
setting `default-auth=Exempt` dropped the instance out of open mode and 401'd later config; (b)
cross-scenario auth-state leakage; (c) the admin-API 60/min rate limiter throttling back-to-back
config. The final campaign runs only after the pilot gate passed.

## Deliverables
`EDGE-CASE-LAB-ARCHITECTURE.md`, `EDGE-CASE-SCENARIO-SCHEMA.json`,
`EDGE-CASE-CAPABILITY-MATRIX.md`, this plan, `reports/EDGE-CASE-RESULTS.json`,
`EDGE-CASE-RESULTS.md`, `EDGE-CASE-BUG-CANDIDATES.md`, `EDGE-CASE-MISSING-CAPABILITIES.md`,
`EDGE-CASE-UX-AND-CONTRACT-GAPS.md`, `EDGE-CASE-COVERAGE-REPORT.md`, `scenarios/<ID>.json`
(per-scenario manifests + `evidence/<ID>/`), and `repro_one.py` reproduction driver.
