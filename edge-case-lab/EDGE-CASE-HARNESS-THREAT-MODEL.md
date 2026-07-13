# Culvert Edge-Case Lab — Harness Threat Model

The lab is a differential oracle. Its verdicts are only as trustworthy as its ability to
(a) compute expectations independently of Culvert, (b) observe real enforcement, and
(c) never confuse an unrelated effect for a policy decision. This document threat-models the
**harness itself** and states residual risks and mitigations.

## Trust properties (asserted + how verified)

| Property | Status | Verification |
|---|---|---|
| Oracle computes expectations independently | **Holds, with a caveat** | `lab/oracle.py` imports no Culvert code; `run_scenario` calls `oracle.evaluate(intent, vec)` **before** `Executor.run(vec)` and passes it only the neutral `intent` + `vector`. Caveat below (T1). |
| Operator cannot read Oracle output | Holds | `Operator.apply` receives only `intent`; the Oracle result is a separate local variable never passed to it. |
| Runtime results cannot influence expected results | Holds | `oracle.evaluate` is a pure function of `(intent, vector)`; it is invoked before the traffic call; no actual-result argument exists in its signature. |
| Per-scenario state reset | Holds (after fix) | Every scenario does `cv.start(fresh=True)` → SIGTERM old proc + wipe `/data` + restart. The **zombie-process defect (T4)** was found and fixed during this review. |
| A blocked origin ≠ a Culvert block | **Holds (after fix)** | The Executor cross-checks the decision trace: a 502/504 after a `POLICY_ALLOW` line is reclassified `CONN_FAIL`/TEST_INFRA, never `BLOCK_PAGE` (T5, fixed in this review). |
| A success response ≠ successful enforcement | Holds | An `allow` verdict requires 2xx **and** the origin body (`origin:<host>`) **and** a `POLICY_ALLOW`/default-allow decision-trace line; a bare 200 from elsewhere would not carry the origin marker. |
| TLS-inspection proof is cryptographic, not inferred | Holds | Interception is decided by **CA trust asymmetry**: the client trusting Culvert's MITM CA completes the handshake while the client trusting only the origin CA fails (the proxy substituted a leaf it signed). Corroborated by the `SSL_INNER` trace line. Not inferred from HTTP status. |
| Lab cannot weaken production SSRF | Holds | The lab adds **no** exemption to Culvert; it binds fixtures to `192.0.2.2` (TEST-NET-1), which the production SSRF blocklist already treats as public. See TEST-NET review + the added regression test (T6). |

## Threats (ranked)

### T1 — Oracle/Culvert co-drift (independence erosion). Severity: MEDIUM
The Oracle encodes *general SWG semantics + Culvert's documented contract*. During the campaign
two Oracle bugs were corrected to match Culvert's **documented** behavior (global executable
blocklist; decryption-profile `certVerification` parsing). Each correction narrows the gap
between oracle and implementation.
- **Risk:** a wrong assumption shared by both the Oracle author and Culvert would produce a
  false PASS (the differential cannot catch a bug both sides agree on).
- **Mitigation:** corrections were anchored to *documentation/source contracts*, not to observed
  runtime; the **mutation-validation** suite is the independent check that the Oracle+assertions
  actually detect real enforcement regressions (see `EDGE-CASE-MUTATION-VALIDATION.md`).
- **Residual:** capabilities with no mutation coverage (persistence, auth, tenant-cross beyond
  source-IP) are not proven detectable — treated as coverage gaps, not passes.

### T2 — Fixture flakiness → false failures. Severity: MEDIUM
A degraded fixture (or a container under load) returns 502/timeout on allowed requests. Before
the T5 fix this surfaced as spurious `PRODUCT_BUG`s. During this review a **container restart mid-run**
plus **duplicate fixture instances** produced exactly this noise.
- **Mitigation:** T5 classifies allow-then-upstream-fail as TEST_INFRA; a single-fixture invariant
  and a pre-run health probe are recommended (see CI plan). PRODUCT_BUG candidates are always
  re-confirmed in a fresh instance.
- **Residual:** transient infra can still add TEST_INFRA noise; it never converts to a false PASS.

### T3 — Non-determinism from wall-clock schedules. Severity: LOW
Schedule scenarios anchor windows to `now` at generation time; a scenario generated seconds
before a window boundary could evaluate differently at execution time.
- **Mitigation:** windows are ±1h around now (wide margin). **Residual:** boundary flakiness is
  possible under extreme delay between generation and execution; a frozen-clock injection would
  remove it (recommended hardening).

### T4 — Cross-scenario leakage via zombie processes. Severity: HIGH (found + FIXED)
The persistence scenario's `start(fresh=False)` originally spawned a second proxy without killing
the first; the zombie held the ports with stale rules, and ~90 subsequent scenarios silently ran
against it (`"priority already in use"`, wrong verdicts).
- **Fix:** `start()` now ALWAYS stops the existing process and additionally kills any stray proxy
  bound to the lab ports before starting. This class of bug is the strongest argument that the
  harness needs its own regression discipline.

### T5 — Blocked-origin mistaken for Culvert block. Severity: HIGH (found + FIXED)
Documented above; the Executor previously mapped any `status >= 400` to `BLOCK_PAGE`, so a 502
(upstream unreachable) after an ALLOW was misread as a policy block.
- **Fix:** 502/504 with an ALLOW trace → `CONN_FAIL` + `upstream_fail` probe → TEST_INFRA.

### T6 — TEST-NET dependency / future SSRF hardening. Severity: MEDIUM
The lab depends on `192.0.2.0/24` remaining outside Culvert's SSRF blocklist. If SSRF is hardened
to also block TEST-NET, every fixture dial fails and the lab silently goes red.
- **Mitigation:** documented as an explicit lab mechanism; a Go regression test asserts no
  test-only loopback/SSRF exemption is active in a production build (so the lab never relies on a
  weakened production guard). A dedicated network namespace or an explicit, build-tagged test CIDR
  is the recommended long-term boundary. See `EDGE-CASE-ACCEPTANCE-REVIEW.md` §TEST-NET.

### T7 — Single global `/data` forces serial execution. Severity: LOW (design constraint)
Culvert hardcodes `dataDir=/data`, so only one instance runs at a time; the lab cannot parallelize
and a leftover instance poisons the next run. Mitigated by the T4 stray-kill; a per-run data dir
(product change) or containerized isolation would lift this.

### T8 — Harness runs as root and pattern-kills processes. Severity: LOW
Process cleanup greps `ps` for `culvert -port 18080`; a pattern that matched the harness's own
command line once self-terminated a shell during development. Now bracket-escaped / PID-scoped, but
running the harness as root against a shared host is a blast-radius risk — CI should sandbox it.

## Bottom line
The two HIGH-severity harness defects (T4 zombie leakage, T5 blocked-origin confusion) were both
**latent false-verdict generators** and were found only by adversarial review + mutation testing —
not by the campaign itself. They are fixed, but their existence is the central reason the lab must
carry its **own** regression tests and a health-gated CI harness before it is trusted as a product
gate.
