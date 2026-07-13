# Culvert Edge-Case Validation Lab

An autonomous lab that evaluates whether Culvert can **represent, configure, enforce, and
explain** realistic enterprise Secure-Web-Gateway requirements — driving the full lifecycle
(requirement → config → validation → traffic → enforcement → decision trace → classification)
for 215 deterministic, deduplicated, enterprise-realistic scenarios against a live Culvert
instance with hermetic local fixtures.

## Deliverables (read in this order)

| # | File | What it is |
|---|---|---|
| 1 | `EDGE-CASE-LAB-ARCHITECTURE.md` | The five-role design, fixtures, SSRF/TEST-NET enabler, isolation, TLS-interception detection. |
| 2 | `EDGE-CASE-SCENARIO-SCHEMA.json` | Versioned JSON Schema (v1) every scenario manifest validates against. |
| 3 | `EDGE-CASE-CAPABILITY-MATRIX.md` | Coverage of the mandated capability areas (covered / partial / recorded / not-covered). |
| 4 | `EDGE-CASE-CAMPAIGN-PLAN.md` | Method, quality gate, dedup, batch structure, taxonomy, pilot discipline. |
| 5 | `reports/EDGE-CASE-RESULTS.json` | Machine-readable campaign results (counts, per-scenario, confirmations). |
| 6 | `EDGE-CASE-RESULTS.md` | Human-readable results: headline numbers, breakdown, weaknesses, opportunities, prioritization. |
| 7 | `EDGE-CASE-BUG-CANDIDATES.md` | Product-bug triage narrative (and why divergences were/weren't bugs). |
| 8 | `EDGE-CASE-MISSING-CAPABILITIES.md` | Missing capabilities + honest recorded coverage limitations. |
| 9 | `EDGE-CASE-UX-AND-CONTRACT-GAPS.md` | Configuration-contract / UX / observability gaps. |
| 10 | `EDGE-CASE-COVERAGE-REPORT.md` | Coverage by capability tag; novelty / duplicate rate. |
| 11 | `scenarios/<ID>.json` + `evidence/<ID>/` | Per-scenario manifests and their evidence (API log, effective config, vectors). |
| 12 | `harness/repro_one.py` | Reproduction driver for any single scenario/finding. |

## Harness

```
harness/lab/oracle.py          independent SWG simulator (Expected-Behavior Oracle)
harness/lab/harness.py         Culvert lifecycle + Operator + Executor + Reviewer
harness/lab/scenarios.py       base validated families (Scenario Generator)
harness/lab/scenarios_full.py  parametric matrices + gap-finding families (215 total)
harness/lab/knowledge/         captured API + policy-semantics ground truth
harness/run_campaign.py        Runner: orchestration, manifests, bug confirmation
harness/gen_reports.py         emits the results-dependent deliverables
harness/retriage.py            Failure-Reviewer confirmation + final triage
harness/repro_one.py           single-scenario reproduction
fixtures/origin_server.py      deterministic local origins (HTTP 18091 / HTTPS 18453 on 192.0.2.2)
```

## Run

```bash
go build -o culvert .                                   # build under test
python3 edge-case-lab/fixtures/origin_server.py --bind 192.0.2.2 \
   --http-port 18091 --https-port 18453 \
   --cert edge-case-lab/fixtures/certs/fixture.crt \
   --key  edge-case-lab/fixtures/certs/fixture.key \
   --files-dir edge-case-lab/fixtures/files &           # fixtures
# /etc/hosts: route app.corp.local, social.example.test, ... -> 192.0.2.2
python3 edge-case-lab/harness/run_campaign.py --pilot   # 5-scenario pilot
python3 edge-case-lab/harness/run_campaign.py --per 30  # full 215 campaign
python3 edge-case-lab/harness/gen_reports.py            # regenerate result docs
python3 edge-case-lab/harness/repro_one.py SWG-0210     # reproduce a finding
```

## Trust posture

The Oracle imports no Culvert code and never sees the live result before computing its own; the
Operator never sees the Oracle's answer. Every scenario runs in a fresh `/data` + restarted
process (no cross-scenario leakage), and every product-bug candidate is re-confirmed in a second
clean instance. Genuinely-untestable dimensions (GeoIP, IPv6, DNS-rebinding, CDR, PAC,
client-cert origins, IdP/CP unavailability) are **recorded honestly**, not faked. The primary
output is trustworthy evidence — not a high pass rate.
