"""Summarise fp2-isolated.py records into the attribution questions.

fp2-isolated-report.py REQUESTS_JSONL OUT_MD

For every EICAR stream answered with a bare "stream: OK" (a wrong clean):
was there ANY fault reply earlier in the same fill cycle, how long before,
how many requests were in flight at the same time, and how much space the
temp filesystem had. A wrong clean with NO earlier fault in its cycle is the
case the Culvert quarantine cannot catch.
"""
import collections
import json
import sys

rows, events = [], []
for line in open(sys.argv[1]):
    d = json.loads(line)
    (events if "event" in d else rows).append(d)


def cls(r):
    if r["client_error"]:
        return "client_error"
    parts = [p.strip() for p in r["reply"].split("\x00") if p.strip()]
    if not parts:
        return "empty"
    if any(p.endswith(" FOUND") for p in parts):
        return "FOUND"
    if any(p.endswith(" ERROR") for p in parts):
        return "ERROR" + ("+OK" if any(p.endswith(" OK") for p in parts) else "")
    if parts == ["stream: OK"]:
        return "OK"
    return "other"


def fault(c):
    return c.startswith("ERROR") or c in ("empty", "client_error", "other")


out = []
w = out.append
w("# F-P2 isolated reproduction — attribution summary\n")
by = collections.defaultdict(list)
for r in rows:
    r["cls"] = cls(r)
    by[r["variant"]].append(r)
w("| variant | requests | EICAR replies | clean replies | wrong clean (EICAR → bare OK) | with NO earlier fault in its cycle |")
w("|---|---|---|---|---|---|")
wrong_all = []
for v, rs in by.items():
    ec = collections.Counter(r["cls"] for r in rs if r["eicar"])
    cc = collections.Counter(r["cls"] for r in rs if not r["eicar"])
    wrong = [r for r in rs if r["eicar"] and r["cls"] == "OK"]
    first = []
    for r in wrong:
        prior = [x for x in rs if x["cycle"] == r["cycle"] and x["t0"] + x["dur_ms"] / 1000 <= r["t0"] and fault(x["cls"])]
        inflight = [x for x in rs if x is not r and x["t0"] < r["t0"] + r["dur_ms"] / 1000 and x["t0"] + x["dur_ms"] / 1000 > r["t0"]]
        r["prior_faults_in_cycle"] = len(prior)
        r["since_last_fault_s"] = round(r["t0"] - max(x["t0"] + x["dur_ms"] / 1000 for x in prior), 3) if prior else None
        r["inflight"] = len(inflight)
        if not prior:
            first.append(r)
        wrong_all.append(r)
    w(f"| {v} | {len(rs)} | {dict(sorted(ec.items()))} | {dict(sorted(cc.items()))} | {len(wrong)} | {len(first)} |")
w("")
w("## Every wrong clean\n")
if not wrong_all:
    w("None observed. Absence over these samples is not proof the defect cannot occur.")
else:
    w("| variant | seq | cycle | wire bytes | wire sha256 | dur ms | tmp free before | prior faults in cycle | s since last fault | in flight |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    for r in wrong_all:
        w(f"| {r['variant']} | {r['seq']} | {r['cycle']} | {r['wire_bytes']} | `{r['wire_sha256'][:16]}…` | {r['dur_ms']} | {r['tmp_free_before']} | "
          f"{r['prior_faults_in_cycle']} | {r['since_last_fault_s']} | {r['inflight']} |")
w("")
w("## Fill events\n")
for e in events:
    w(f"- {e['variant']} cycle {e['cycle']}: headroom target {e['headroom_target']}, temp free after fill {e['tmp_free']}")
open(sys.argv[2], "w").write("\n".join(out) + "\n")
print("\n".join(out[:4 + len(by)]))
