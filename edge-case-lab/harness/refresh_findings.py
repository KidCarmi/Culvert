#!/usr/bin/env python3
"""
Re-run a specified list of scenarios with the CURRENT harness/triage and patch their
entries in EDGE-CASE-RESULTS.json + rewrite their manifests. Used after a triage
change made mid-campaign, so all reports reflect the corrected classification.

Usage: python3 refresh_findings.py SWG-0215 [SWG-....]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_campaign as R
from lab import harness as H
from lab.scenarios_full import FullGen

RESULTS = os.path.join(R.REPORT_DIR, "EDGE-CASE-RESULTS.json")


def main():
    ids = set(sys.argv[1:])
    if not ids:
        print("usage: refresh_findings.py <ID> [<ID>...]"); sys.exit(2)
    summary = json.load(open(RESULTS))
    by_id = {s["id"]: s for s in FullGen().build_full()}
    cv = H.Culvert(); cv.start(fresh=True)
    env = R.env_fingerprint(cv)
    for sid in ids:
        sc = by_id.get(sid)
        if not sc:
            print("unknown", sid); continue
        old = next((e["classification"] for e in summary["results"] if e["id"] == sid), None)
        new = R.run_scenario(cv, sc, env)
        for e in summary["results"]:
            if e["id"] == sid:
                e["classification"] = new["classification"]
                e["confidence"] = new["confidence"]
                e["refreshed_from"] = old
        print(f"{sid}: {old} -> {new['classification']}")
    cv.stop()
    # recompute counts
    counts = {}
    for e in summary["results"]:
        counts[e["classification"]] = counts.get(e["classification"], 0) + 1
    counts["total"] = len(summary["results"])
    counts["pass_rate"] = round(counts.get("PASS", 0) / max(1, len(summary["results"])), 3)
    summary["counts"] = counts
    json.dump(summary, open(RESULTS, "w"), indent=2)
    print("counts:", json.dumps(counts))


if __name__ == "__main__":
    main()
