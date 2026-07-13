#!/usr/bin/env python3
"""
Minimal reproduction driver: re-run a single scenario in a fresh, clean Culvert
instance and print the per-vector expected/actual/verdict. Used to confirm any
candidate finding independently of the batch run.

Usage:
  python3 repro_one.py SWG-0210          # by scenario id
Prereqs (see EDGE-CASE-LAB-ARCHITECTURE.md):
  - culvert binary built at repo root
  - fixtures/origin_server.py running on 192.0.2.2 (18091/18453)
  - /etc/hosts routing the corp/test hostnames to 192.0.2.2
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import harness as H
from lab import oracle
from lab.scenarios_full import FullGen


def main():
    if len(sys.argv) < 2:
        print("usage: repro_one.py <SCENARIO-ID>")
        sys.exit(2)
    sid = sys.argv[1]
    sc = next((s for s in FullGen().build_full() if s["id"] == sid), None)
    if not sc:
        print(f"unknown scenario {sid}")
        sys.exit(2)

    print(f"# {sc['id']}: {sc['title']}")
    print(f"# requirement: {sc['requirement']}")
    intent = sc["intent"]
    cv = H.Culvert()
    cv.start(fresh=True)
    if sc.get("requires_auth"):
        cv.configure_admin()
    if intent.get("limitation"):
        print(f"# coverage record — {intent.get('triage', {}).get('note', '')}")
        cv.stop()
        return

    op = H.Operator(cv)
    ex = H.Executor(cv)
    rv = H.Reviewer()
    report = op.apply(intent)
    print(f"# apply errors: {report['errors']}")
    print(f"# readback: {report['readback']}")
    if intent.get("persistence_check"):
        cv.start(fresh=False)
        print(f"# persistence after restart: {op.verify(intent)}")

    for vec in sc["vectors"]:
        exp = oracle.evaluate(intent, vec)
        act = ex.run(vec)
        verdict = rv.classify_vector(exp, act, report, sc)
        print(f"\n[{vec['id']}] {vec['scheme']} {vec['host']} src={vec.get('client_ip')}")
        print(f"  expected: {exp.disposition} tls={exp.tls}  ({exp.rationale})")
        print(f"  actual:   {act.disposition} tls={act.tls} status={act.http_status}")
        print(f"  trace:    {act.decision_trace[:2]}")
        if act.probes:
            print(f"  probes:   {json.dumps(act.probes)[:300]}")
        print(f"  VERDICT:  {verdict['verdict']} ({verdict['confidence']}) — {verdict['reason'][:160]}")
    cv.stop()


if __name__ == "__main__":
    main()
