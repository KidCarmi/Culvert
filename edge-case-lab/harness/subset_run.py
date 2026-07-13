#!/usr/bin/env python3
"""
Run a subset of scenarios (by id or capability) against the binary currently
pointed to by CULVERT_LAB_BIN, and print per-scenario classification. Does NOT
write the real scenario manifests — used by mutation validation to detect whether
a deliberately-broken build flips the relevant scenarios to non-PASS.

Usage:
  CULVERT_LAB_BIN=/path/to/mutated/culvert python3 subset_run.py --ids SWG-0001,SWG-0009
  CULVERT_LAB_BIN=... python3 subset_run.py --cap rule_first_match --limit 8
"""
import argparse
import json
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import harness as H
from lab import oracle
from lab.scenarios_full import FullGen


def run_subset(scenarios):
    cv = H.Culvert()
    cv.start(fresh=True)
    rows = []
    for sc in scenarios:
        intent = sc["intent"]
        if intent.get("limitation"):
            continue
        if sc.get("requires_auth"):
            cv.start(fresh=True); cv.configure_admin()
        else:
            cv.start(fresh=True)
        op = H.Operator(cv); ex = H.Executor(cv); rv = H.Reviewer()
        rep = op.apply(intent)
        if intent.get("persistence_check"):
            cv.start(fresh=False)
            rep["persistence_after_restart"] = op.verify(intent)
        vclasses = []
        vdetail = []
        for vec in sc["vectors"]:
            exp = oracle.evaluate(intent, vec)
            act = ex.run(vec)
            verdict = rv.classify_vector(exp, act, rep, sc)
            vclasses.append(verdict["verdict"])
            vdetail.append((vec.get("id"), exp.disposition, act.disposition, verdict["verdict"]))
        cls = "PASS" if all(c == "PASS" for c in vclasses) else next(
            (c for c in vclasses if c != "PASS"), "PASS")
        rows.append({"id": sc["id"], "class": cls, "vectors": vdetail, "title": sc["title"]})
    cv.stop()
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default="")
    ap.add_argument("--cap", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    allsc = FullGen().build_full()
    if args.ids:
        want = set(args.ids.split(","))
        scen = [s for s in allsc if s["id"] in want]
    elif args.cap:
        scen = [s for s in allsc if args.cap in s["capabilities"]]
        if args.limit:
            scen = scen[:args.limit]
    else:
        print("specify --ids or --cap"); sys.exit(2)
    rows = run_subset(scen)
    if args.json:
        print(json.dumps(rows))
    else:
        for r in rows:
            print(f"  {r['id']:9} {r['class']:26} {r['title'][:50]}")
    npass = sum(1 for r in rows if r["class"] != "PASS")
    print(f"# {len(rows)} scenarios, {npass} non-PASS")


if __name__ == "__main__":
    main()
