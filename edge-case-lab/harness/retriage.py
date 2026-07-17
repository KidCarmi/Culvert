#!/usr/bin/env python3
"""
Failure-Reviewer confirmation + final-triage pass.

Re-runs every scenario the automated campaign flagged PRODUCT_BUG, in a FRESH
clean instance, using the current (reviewed) Oracle + triage rules, and rewrites
its manifest + its entry in EDGE-CASE-RESULTS.json with the final classification.
The original automated verdict is preserved as `automated_classification` for
transparency. This satisfies the clean-environment reproduction contract and keeps
the published classification consistent with the reviewed evidence.
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
    summary = json.load(open(RESULTS))
    scen_by_id = {s["id"]: s for s in FullGen().build_full()}
    to_review = [r for r in summary["results"]
                 if r["classification"] in (H.PRODUCT_BUG,)]
    if not to_review:
        print("no PRODUCT_BUG candidates to retriage")
        return

    cv = H.Culvert()
    cv.start(fresh=True)
    env = R.env_fingerprint(cv)
    updated = {}
    for r in to_review:
        sc = scen_by_id.get(r["id"])
        if not sc:
            continue
        print(f"retriage {r['id']} (was {r['classification']}) ...")
        new = R.run_scenario(cv, sc, env)   # fresh restart inside, rewrites manifest
        new["automated_classification"] = r["classification"]
        updated[r["id"]] = new["classification"]
        print(f"   -> {new['classification']}")
        # patch summary entry
        for i, e in enumerate(summary["results"]):
            if e["id"] == r["id"]:
                e["automated_classification"] = r["classification"]
                e["classification"] = new["classification"]
                e["confidence"] = new["confidence"]
                e["retriaged"] = True
    cv.stop()

    # recompute counts
    counts = {}
    for r in summary["results"]:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1
    counts["total"] = len(summary["results"])
    counts["pass_rate"] = round(counts.get("PASS", 0) / max(1, len(summary["results"])), 3)
    summary["counts"] = counts
    summary["retriage"] = {"reviewed": list(updated.keys()), "final": updated}
    json.dump(summary, open(RESULTS, "w"), indent=2)
    print("counts after retriage:", json.dumps(counts))


if __name__ == "__main__":
    main()
