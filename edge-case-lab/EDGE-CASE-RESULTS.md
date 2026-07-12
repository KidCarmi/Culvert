# Culvert Edge-Case Validation Lab — Results

**Culvert commit:** `2b9ade66340e652911472c7dbacea2151bf4c5fe`  
**Binary built:** 2026-07-12T22:19:19.133687+00:00  
**Executed:** 2026-07-12T23:20:12.385955+00:00  
**Fixture:** local origin on 192.0.2.2 (HTTP 18091 / HTTPS 18453), TEST-NET-1, no public internet.

## Headline numbers

| Metric | Value |
|---|---|
| Candidate scenarios generated | 217 |
| Rejected as semantic duplicates | 2 |
| **Accepted scenarios** | **215** |
| Unique semantic fingerprints | 215 |
| **Executed** | **215** |
| **PASS** | **200** |
| **Pass rate** | **93.0%** |
| Duplicate/novelty rejection rate | 0.9% rejected (99.1% novel) |

## Classification breakdown

| Classification | Count | % of executed |
|---|---|---|
| PASS | 200 | 93.0% |
| MISSING_CAPABILITY | 2 | 0.9% |
| CONFIGURATION_CONTRACT_GAP | 7 | 3.3% |
| EXPECTED_LIMITATION | 5 | 2.3% |
| TEST_INFRA_FAILURE | 1 | 0.5% |

## Product-bug confirmation pass

| Scenario | Reproduced in clean env? |
|---|---|
| SWG-0084 | True |
| SWG-0166 | True |
| SWG-0167 | True |
| SWG-0168 | True |
| SWG-0169 | True |
| SWG-0191 | True |

## Non-PASS scenarios

| ID | Class | Conf | Title |
|---|---|---|---|
| SWG-0069 | CONFIGURATION_CONTRACT_GAP | 0.85 | Decryption profile certVerification=permissive |
| SWG-0124 | CONFIGURATION_CONTRACT_GAP | 0.85 | Policy configuration persists across a proxy restart |
| SWG-0166 | CONFIGURATION_CONTRACT_GAP | 0.85 | Allow-all-with-social-media-carveout (category exception above broad p |
| SWG-0167 | CONFIGURATION_CONTRACT_GAP | 0.85 | Allow-all-with-news-carveout (category exception above broad permit) |
| SWG-0168 | CONFIGURATION_CONTRACT_GAP | 0.85 | Allow-all-with-streaming-carveout (category exception above broad perm |
| SWG-0169 | CONFIGURATION_CONTRACT_GAP | 0.85 | Allow-all-with-webmail-carveout (category exception above broad permit |
| SWG-0215 | CONFIGURATION_CONTRACT_GAP | 0.85 | Open-redirect safety on the redirect action |
| SWG-0205 | EXPECTED_LIMITATION | 0.90 | [Coverage record] GeoIP / destination country |
| SWG-0206 | EXPECTED_LIMITATION | 0.90 | [Coverage record] IPv6 support |
| SWG-0207 | EXPECTED_LIMITATION | 0.90 | [Coverage record] DNS rebinding protection |
| SWG-0208 | EXPECTED_LIMITATION | 0.90 | [Coverage record] WebSocket handling |
| SWG-0209 | EXPECTED_LIMITATION | 0.90 | [Coverage record] Partial downloads |
| SWG-0210 | MISSING_CAPABILITY | 0.85 | Egress policy must apply to SOCKS5 clients (news.example.test) |
| SWG-0211 | MISSING_CAPABILITY | 0.85 | Egress policy must apply to SOCKS5 clients (media.corp.local) |
| SWG-0191 | TEST_INFRA_FAILURE | 0.85 | Category allow-list: permit only 'webmail' under default-deny |

## Interpretation

The pass rate reflects that across a broad matrix of realistic enterprise policy shapes — URL/domain objects (exact/wildcard/bare), URL categories & groups, source/zone conditions, first-match precedence & shadowing, default-deny, TLS inspection/bypass with fail-closed certificate validation, file-type download control, threat-intel, redirect/drop actions, schedules, compound conditions, multi-tenant isolation, and streaming/large/chunked integrity — Culvert **correctly and explainably** converts admin intent into enforced, traced behavior. Every enforcement decision carried a `POLICY_*` decision trace naming the matched rule (name + ULID), and TLS interception was independently proven by CA trust-asymmetry. The findings that remain are concentrated in transport parity (SOCKS5) and a small number of contract/observability edges detailed in the companion documents.

## Top architectural weaknesses (evidence-based)

1. **Transport-plane policy asymmetry (SOCKS5).** The SOCKS5 forward path does not run the PBAC policy engine (only the legacy blocklist), so destination/category/source policy is silently unenforced for SOCKS5 clients. Same host + same policy: HTTP/CONNECT blocks, SOCKS5 allows. (See Bug Candidates / Missing Capabilities.)
2. **Zero-value priority footgun.** A rule submitted at `priority 0` (a common '0 = highest' convention) is silently treated as unset and auto-assigned to the END of the list, inverting the admin's intended precedence with no warning (4 scenarios: SWG-0166–0169). Priorities >=1 behave correctly.
3. **Config-durability model.** Policy created via the admin API is in-memory unless a persistence flag/file is configured, and the API gives no ephemeral warning — a GUI-configured policy silently vanishes on restart (SWG-0124).
4. **Named-option/behavior drift.** `certVerification=permissive` is accepted but behaves like `strict` (its allow+log semantics are deferred/unimplemented) — SWG-0069.
5. **GUI-parity of security-critical knobs.** Several release/HA/fencing knobs are startup/env-scoped (documented deferrals), limiting runtime GUI control.

## Top product opportunities

1. Route SOCKS5 (and any future transports) through the unified policy engine so egress policy is transport-agnostic.
2. First-class, always-on durable policy persistence (no flag required) with an explicit restart-survival guarantee surfaced in the UI.
3. A queryable per-request decision-trace API (rule id + matched conditions) enabled by default, so admins can explain any allow/block without shell access to logs.

## Recommended prioritization

| Priority | Item | Rationale |
|---|---|---|
| P0 | SOCKS5 policy enforcement parity | Security-relevant policy bypass by transport choice. |
| P1 | Durable-by-default policy persistence | Avoids silent enforcement loss on restart. |
| P2 | Default-on decision-trace API | Operability / audit explainability. |
| P3 | Extend lab: IdP mock, CDR mock, client-cert, PAC, IPv6, CP/DP failover | Close recorded coverage gaps. |
