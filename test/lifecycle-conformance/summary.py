#!/usr/bin/env python3
"""Render the shadow run as Markdown for the GitHub step summary.  usage: summary.py <report dir>"""
import json
import os
import sys

d = sys.argv[1]
print("### Lifecycle conformance (shadow, non-blocking)\n")
print("Verified against the real maintenance-agent code through a **fake** exec layer. "
      "The model check alone verifies the abstraction, not the product.\n")
try:
    mc = json.load(open(os.path.join(d, "model_check.json")))
    st = mc.get("stats", {})
    print(f"**Model check** — {st.get('states', '?')} states, {st.get('transitions', '?')} transitions\n")
    print("| Property | Status | Verdict | Shortest counterexample |")
    print("|---|---|---|---|")
    for x in mc["results"]:
        trace = " → ".join(x.get("trace") or []) if x["verdict"] != "PASS" else ""
        print(f"| {x['id']} {x['text']} | {x.get('status', '?')} | {x['verdict']} | {trace} |")
    print("\nA failing *proposed* or *open* property is reported for the owner; it does not fail this job.\n")
except (OSError, ValueError, KeyError) as e:
    print(f"**Model check produced no usable result ({e}). Treat this run as INCOMPLETE.**\n")
print("**Conformance against real code**\n")
found = 0
for name in ("apply", "crash", "reconcile"):
    try:
        r = json.load(open(os.path.join(d, f"conformance_{name}.json")))
    except (OSError, ValueError):
        print(f"- `{name}`: **no report — suite did not complete**")
        continue
    found += 1
    nums = ", ".join(f"{k}={v}" for k, v in sorted(r.items()) if isinstance(v, (int, float, str)))
    print(f"- `{name}`: {nums}")
if found != 3:
    print("\n**INCOMPLETE: fewer than three conformance suites reported. This is not a pass.**")
