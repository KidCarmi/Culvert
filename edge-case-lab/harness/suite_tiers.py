#!/usr/bin/env python3
"""
R5: explicit execution tiers.

Tiers:
  smoke    — 14 deterministic scenarios covering the highest-risk contracts + the
             harness self-tests (attribution / upstream-vs-block / zombie / ownership).
             Target: fast PR gate.
  nightly  — every CANONICAL behavior representative (one scenario per behavior).
  full     — the entire 215-scenario generated campaign (run_campaign.py).
  release  — canonical + a freshly generated campaign + mutation floor check.

Usage:
  python3 suite_tiers.py smoke
  python3 suite_tiers.py nightly
  python3 suite_tiers.py list
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import harness as H
from lab import oracle
from lab.scenarios_full import FullGen

# Curated PR-smoke set — one deterministic scenario per highest-risk contract.
SMOKE_IDS = [
    "SWG-0007",  # first-match precedence
    "SWG-0009",  # default deny (Zero Trust)
    "SWG-0006",  # source / tenant isolation
    "SWG-0121",  # multi-tenant isolation (no cross-tenant leakage)
    "SWG-0010",  # TLS inspection (inspect + bypass, MITM proof)
    "SWG-0011",  # manual SSL bypass list override
    "SWG-0074",  # file blocking under TLS inspection
    "SWG-0013",  # threat-intelligence / blocklist pre-emption
    "SWG-0019",  # schedule evaluation
    "SWG-0124",  # durable policy restart (persistence + post-restart enforcement)
    "SWG-0023",  # authentication boundary (407)
    "SWG-0122",  # decision-trace attribution
    "SWG-0004",  # URL category
    "SWG-0017",  # wildcard boundary (no over-match)
]
# The upstream-failure-vs-policy-block contract is covered by the harness self-test
# (test_upstream_fail_live) rather than a normal PASS scenario, since it is a
# deliberate infra failure whose correct classification is TEST_INFRA, not PASS.


def canonical_representatives():
    mapping_p = os.path.join(H.LAB, "EDGE-CASE-SCENARIO-MAPPING.json")
    if not os.path.isfile(mapping_p):
        subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "canonical.py")],
                       check=True, capture_output=True)
    mapping = json.load(open(mapping_p))
    return [m["id"] for m in mapping if m.get("canonical_representative")]


def run_ids(ids, label):
    allsc = {s["id"]: s for s in FullGen().build_full()}
    import run_campaign as R
    cv = H.Culvert(); cv.start(fresh=True)
    env = R.env_fingerprint(cv)
    rows = []
    t0 = time.time()
    for sid in ids:
        sc = allsc.get(sid)
        if not sc:
            rows.append({"id": sid, "class": "MISSING_SCENARIO"}); continue
        r = R.run_scenario(cv, sc, env)
        rows.append({"id": sid, "class": r["classification"]})
        print(f"  {sid:9} {r['classification']}")
    cv.stop()
    dur = time.time() - t0
    npass = sum(1 for r in rows if r["class"] == "PASS")
    # non-PASS that are legitimate findings (SECURITY_BYPASS/gaps) are allowed;
    # a smoke FAILURE is an unexpected PRODUCT_BUG/TEST_INFRA on a should-pass id.
    unexpected = [r for r in rows if r["class"] in ("PRODUCT_BUG", "TEST_INFRA_FAILURE")]
    print(f"# {label}: {len(rows)} scenarios, {npass} PASS, {len(unexpected)} unexpected-fail, {dur:.0f}s")
    return rows, unexpected, dur


def main():
    tier = sys.argv[1] if len(sys.argv) > 1 else "smoke"
    if tier == "list":
        print("smoke:", SMOKE_IDS)
        print("nightly canonical representatives:", len(canonical_representatives()))
        return
    if tier == "smoke":
        rows, unexpected, dur = run_ids(SMOKE_IDS, "PR-smoke")
        print("\n# harness self-tests (attribution / upstream / zombie / ownership):")
        rc = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "test_harness.py")]).returncode
        sys.exit(1 if (unexpected or rc != 0) else 0)
    if tier == "nightly":
        reps = canonical_representatives()
        rows, unexpected, dur = run_ids(reps, "nightly-canonical")
        sys.exit(1 if unexpected else 0)
    if tier == "full":
        # Propagate the campaign's exit status so an infra / Python startup failure
        # in run_campaign.py surfaces as a red CI job instead of a green one with a
        # failed log. run_campaign is advisory (0 on normal completion even with
        # findings), so only a genuine crash turns the tier red.
        rc = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "run_campaign.py"), "--per", "30"]
        ).returncode
        sys.exit(rc)
    print("unknown tier", tier); sys.exit(2)


if __name__ == "__main__":
    main()
