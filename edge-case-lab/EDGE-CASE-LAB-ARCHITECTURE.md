# Culvert Edge-Case Validation Lab — Architecture

**Purpose.** An autonomous lab that evaluates whether Culvert can *represent, configure,
enforce, and explain* realistic enterprise Secure-Web-Gateway (SWG) requirements. It drives
the complete lifecycle for every scenario:

```
administrator requirement
  → configuration discovery (available Culvert interfaces)
  → configuration creation (admin API)
  → policy validation (read-back + effective-config export)
  → traffic execution (real HTTP/HTTPS/SOCKS5 through the proxy, local fixtures)
  → enforcement result (allow / block page / drop / redirect / 407 / TLS intercept)
  → observability & decision trace (POLICY_* log lines, stats deltas, MITM proof)
  → failure classification (10-class taxonomy)
```

The primary success criterion is **trustworthy evidence**, not a high pass rate.

---

## 1. The five roles

The roles are implemented as isolated code paths so that no role can see another's private
state (in particular, the Operator never sees the Oracle's answer, and the Oracle never sees
the live result before computing its own).

| Role | Module | Responsibility | Isolation guarantee |
|---|---|---|---|
| **Manager / Scenario Generator** | `lab/scenarios.py`, `lab/scenarios_full.py` | Emits enterprise-realistic requirements as machine-readable scenarios (abstract `intent` + deterministic `vectors` + dedup fingerprint + capability tags). | Produces *product-neutral* intent; contains no Culvert enforcement knowledge. |
| **Culvert Operator** | `lab/harness.py::Operator` | Translates the abstract `intent` into Culvert admin-API calls, applies them, reads the config back, exports the effective config, and reports silent drops / coercion / errors. | Receives only the requirement + Culvert interfaces. Never receives the Oracle's expected result. |
| **Traffic Executor** | `lab/harness.py::Executor` | Drives real traffic (HTTP forward, HTTPS CONNECT, SOCKS5) through the proxy to local fixtures; captures status, body, block-page detection, **TLS-interception detection** (CA trust asymmetry), per-request decision trace, and stats deltas. | Observes runtime only; does not know the expected outcome. |
| **Independent Expected-Behavior Oracle** | `lab/oracle.py` | Computes the expected disposition from the requirement + general mature-SWG semantics + Culvert's documented contract — **before** the actual result exists. | Imports no Culvert code, reads no live result, never sees the Operator's translation. |
| **Failure Reviewer & Triage Lead** | `lab/harness.py::Reviewer`, `run_campaign.py` | Compares Oracle-expected vs actual, assigns exactly one of ten classifications, and re-confirms every PRODUCT_BUG candidate in a fresh clean instance. | Sees both sides only *after* both are fixed. |

**Why this is a genuine differential test.** The Generator emits one abstract intent. Two
*independent* code paths consume it: the Operator (`intent → Culvert config`) and the Oracle
(`intent → expected disposition`, via a from-scratch SWG simulator). If Culvert's runtime
enforcement disagrees with the Oracle, that divergence is a candidate finding — it cannot be
a tautology because the Oracle never consulted Culvert.

---

## 2. Test infrastructure

### 2.1 Deterministic local fixtures (no public internet)
`fixtures/origin_server.py` serves many virtual hosts on **one** HTTP port (18091) and **one**
HTTPS port (18453), bound to `192.0.2.2`. Endpoints: `/`, `/echo` (header echo), `/status/<c>`,
`/redirect?to=&n=` (chains), `/size/<n>`, `/chunked?n=&delay=`, `/slow`, `/file/<name>` (typed
downloads incl. a fake PE `malware.exe`), `/large/<mb>`, `/upload`, `/setcookie`.

### 2.2 The SSRF / TEST-NET insight (key enabler)
Culvert's forward path enforces an SSRF guard (`isPrivateHost` + connect-time `ssrfControl`)
that blocks **loopback and RFC-1918** destinations — so `127.0.0.1` fixtures are rejected by
the proxy. The guard's blocklist does **not** include the **TEST-NET-1** range `192.0.2.0/24`,
and the container already has `192.0.2.2` assigned to an interface. The lab therefore:
* binds all fixtures to **`192.0.2.2`** (treated as "public" by the SSRF guard → dialable), and
* routes realistic hostnames (`app.corp.local`, `social.example.test`, …) to `192.0.2.2` via
  `/etc/hosts`, so realistic FQDN/category policy can be exercised end-to-end.

This gives fully hermetic, deterministic traffic with realistic hostnames and **no** relaxation
of Culvert's security posture.

### 2.3 Client source-IP control
The proxy binds `0.0.0.0:18080`. The Executor selects the client source IP per vector:
* **`192.0.2.2`** ("corporate LAN", matches `192.0.2.0/24`) via `curl --interface 192.0.2.2`
  reaching the proxy on `192.0.2.2:18080`;
* **`127.0.0.1`** ("guest / unmanaged") via the loopback proxy address.

These two controllable sources support positive/negative source-subnet vectors. (Only two
non-conflicting local source IPs are available — a documented infra limit; see §5.)

### 2.4 TLS-interception detection (MITM proof)
For every HTTPS(CONNECT) vector the Executor runs **two probes** — one trusting Culvert's MITM
CA, one trusting the fixture's own CA:
* Culvert-CA succeeds **and** fixture-CA fails ⇒ **`tls_intercepted`** (proxy substituted a
  leaf it signed — decryption is happening).
* fixture-CA succeeds **and** Culvert-CA fails ⇒ **`tls_passthrough`** (opaque tunnel — bypass).
* neither ⇒ blocked CONNECT or `conn_fail`.

This is corroborated by the `SSL_INNER` log line (only present when the inner request is
actually decrypted).

### 2.5 Decision trace
Per request the Executor captures the appended `POLICY_*` / `SSL_*` / `AUTH_*` / `FILE_*` log
lines (rule name, rule ULID, matched conditions, action), the `/api/stats` blocked/allowed
delta, and the two TLS probes. Every scenario's full admin-API request/response log and the
`GET /api/config/export` output are saved as evidence.

---

## 3. Isolation model

Culvert hardcodes `dataDir = /data` (no `-data-dir` flag), so filesystem isolation is achieved
by **wiping `/data` and restarting the process before every scenario**. This guarantees:
* no policy/object/config leakage across scenarios,
* no shared cert-cache / adaptive-decryption auto-learn / session reuse,
* the admin-API per-IP rate limiter (60 mutations/min) resets each scenario,
* auth-family scenarios (which create an admin and drop the instance out of "open mode") cannot
  pollute the following open-mode scenario.

Every apparent **PRODUCT_BUG** is additionally **re-confirmed in a second fresh instance**
(`confirm_bug`) before it is reported, satisfying the clean-environment reproduction contract.

The admin API is driven in Culvert's **open mode** (first-run, unconfigured) for the bulk of
scenarios — the middleware grants admin to all `/api/` calls and no CSRF token is required for
`Origin`-less clients — while auth-family scenarios complete first-run setup and authenticate
with HTTP Basic. No database is ever mutated directly; only supported admin APIs are used.

---

## 4. Data flow (one scenario)

```
Generator ─ intent ─┬──────────────► Operator ─ POST /api/{policy,urlcat,...} ─► Culvert
                    │                    │  ◄─ GET /api/policy, /api/config/export (read-back)
                    │                    ▼
                    │              apply_report (errors / silent drops / persistence)
                    │
                    └──────────────► Oracle ─ evaluate(intent, vector) ─► Expectation (independent)
                                                                              │
Executor ─ curl via proxy/SOCKS5 ─► Culvert ─ enforcement ─► ActualResult ───┤
   (status, block page, TLS probes, decision trace, stats delta)             ▼
                                                        Reviewer.classify(expected, actual)
                                                                              │
                                                        manifest + evidence + classification
```

---

## 5. Honest limitations (recorded, not hidden)

| Dimension | Limitation | Handling |
|---|---|---|
| GeoIP / destination country | Cache-only fail-closed; requires GeoLite2 DB + public IPs; TEST-NET fixtures cannot populate the geo cache. | Recorded as `EXPECTED_LIMITATION` coverage records (SWG-0205). |
| IPv6 egress | SSRF blocks `::1`/ULA; no public IPv6 assignable to a fixture. | Recorded (SWG-0206). |
| DNS-rebinding | Full TTL-flip harness out of scope; Culvert's connect-time `ssrfControl` re-check verified by code review. | Recorded (SWG-0207). |
| WebSocket / partial-content | Fixture stubs exist; deterministic frame/range assertions deferred. | Recorded (SWG-0208/0209). |
| Source IPs | Only two locally-bindable, non-conflicting source addresses (`192.0.2.2`, `127.0.0.1`). | Source scenarios use "corporate vs guest" polarity. |
| Identity / IdP groups | Real group/identity matching needs an IdP or proxy credentials; open-mode traffic is unauthenticated. | Auth-policy tested via the 407-challenge family; identity/group left to a future IdP-mock extension. |

---

## 6. Files

```
edge-case-lab/
  harness/
    lab/oracle.py            independent SWG simulator (Oracle)
    lab/harness.py           Culvert lifecycle, Operator, Executor, Reviewer
    lab/scenarios.py         base validated families (Generator)
    lab/scenarios_full.py    parametric matrices + gap-finding families
    lab/knowledge/           captured API + policy-semantics ground truth
    run_campaign.py          Runner (orchestration, manifests, confirmation)
    repro_one.py             single-scenario reproduction driver
  fixtures/origin_server.py  deterministic local origins (HTTP+HTTPS)
  fixtures/certs/            fixture TLS cert (SANs for all fixture hosts + 192.0.2.2)
  scenarios/<ID>.json        per-scenario manifests (schema v1)
  evidence/<ID>/             api_log, effective_config, vectors evidence
  reports/EDGE-CASE-RESULTS.json  machine-readable campaign results
  EDGE-CASE-*.md / *.json    deliverables (this file + schema + matrix + plan + reports)
```

## 7. Reproducing

```bash
# 1. build
go build -o culvert .
# 2. fixtures (bind TEST-NET, both HTTP+HTTPS)
python3 edge-case-lab/fixtures/origin_server.py --bind 192.0.2.2 \
    --http-port 18091 --https-port 18453 \
    --cert edge-case-lab/fixtures/certs/fixture.crt \
    --key edge-case-lab/fixtures/certs/fixture.key --files-dir edge-case-lab/fixtures/files &
# 3. /etc/hosts: point app.corp.local, social.example.test, ... at 192.0.2.2
# 4. run
python3 edge-case-lab/harness/run_campaign.py --pilot     # 5-scenario pilot
python3 edge-case-lab/harness/run_campaign.py --per 30     # full campaign
python3 edge-case-lab/harness/repro_one.py SWG-0210        # reproduce one finding
```
