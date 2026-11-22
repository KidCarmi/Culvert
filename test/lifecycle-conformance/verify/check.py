#!/usr/bin/env python3
"""Deterministic property gate. No AI, no network, stdlib only.

  python3 verify/check.py --model model/culvert_apply.py --props model/properties.json [--include-proposed]
Exit: 0 all enforced properties pass | 1 a property fails | 2 incomplete exploration, vacuous property,
      or the property file changed during the run."""
import argparse
import hashlib
import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proplang import Incomplete, check  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--model", required=True)
ap.add_argument("--props", required=True)
ap.add_argument("--include-proposed", action="store_true")
ap.add_argument("--max-states", type=int, default=200_000)
ap.add_argument("--max-seconds", type=float, default=60.0)
ap.add_argument("--json", help="write full results to this file")
a = ap.parse_args()

digest = hashlib.sha256(open(a.props, "rb").read()).hexdigest()
allp = json.load(open(a.props))
enforced = [p for p in allp if p.get("status") == "approved" or (a.include_proposed and p.get("status") == "proposed")]
known_open = [p for p in allp if p.get("status") == "open"]
spec = importlib.util.spec_from_file_location("model_under_check", a.model)
mod = importlib.util.module_from_spec(spec)
sys.path.insert(0, os.path.dirname(os.path.abspath(a.model)))
spec.loader.exec_module(mod)

try:
    results, stats = check(mod.MODEL, enforced + known_open, a.max_states, a.max_seconds)
except Incomplete as e:
    print(f"INCOMPLETE: {e} -- refusing to report a pass")
    sys.exit(2)

fail = vac = 0
for r in results:
    opn = r["status"] == "open"
    tag = {"PASS": "ok     ", "FAIL": "OPEN   " if opn else "FAIL   ", "VACUOUS": "VACUOUS"}[r["verdict"]]
    print(f"{tag} {r['id']:5s} [{r['kind']:10s}] {r['text']}")
    if r["verdict"] == "FAIL":
        print(f"        trace: {' -> '.join(r['trace'])}")
        fail += not opn
    vac += r["verdict"] == "VACUOUS"
if not enforced:
    print("NOTE: no property is enforced (none approved). Use --include-proposed to evaluate proposals.")
print(f"{stats['states']} states, {stats['transitions']} transitions, {len(enforced)} enforced, "
      f"{len(known_open)} open (reported, never gating), {fail} failed, {vac} vacuous; props sha256 {digest[:16]}")
if a.json:
    json.dump({"props_sha256": digest, "stats": stats, "results": results}, open(a.json, "w"), indent=1, default=str)
if hashlib.sha256(open(a.props, "rb").read()).hexdigest() != digest:
    print("ERROR: property file changed during the run")
    sys.exit(2)
sys.exit(1 if fail else (2 if vac else 0))
