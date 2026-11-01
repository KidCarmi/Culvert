"""Static routing over EVERY workflow that a push to test/appliance-lab fires.
Usage: route_matrix.py WF_DIR "<actual commit message>" [BASE_WF_DIR]
Cases: the actual message; [build-only] alone; [build-only] with every other
known tag in both orders, with and without [lab-skip]; [build-only] with an
unknown tag (expression selects it; the runtime guard must refuse — reported);
every known tag alone (and with [lab-skip]) must route exactly as in the base."""
import fnmatch, glob, itertools, os, re, sys, yaml
sys.path.insert(0, os.path.dirname(__file__))
from route_eval import evaluate

BR = "test/appliance-lab"
def push_workflows(d):
    out = {}
    for f in sorted(glob.glob(os.path.join(d, "*.yml"))):
        w = yaml.safe_load(open(f)); on = w.get(True, w.get("on"))
        if isinstance(on, str): on = {on: None}
        if isinstance(on, list): on = {k: None for k in on}
        if "push" not in on: continue
        p = on["push"] or {}
        br, ign, tags = p.get("branches"), p.get("branches-ignore"), p.get("tags")
        if br is None and ign is None and tags is not None: continue  # tag-only push filter
        if br is not None and not any(fnmatch.fnmatch(BR, b) for b in br): continue
        if ign and any(fnmatch.fnmatch(BR, b) for b in ign): continue
        out[os.path.basename(f)] = w["jobs"]
    return out

def jobs_run(wfs, msg):
    ctx = {"github.event_name": "push", "github.event.head_commit.message": msg, "inputs.route": None,
           "github.ref": "refs/heads/" + BR}
    ran = []
    for wf, jobs in wfs.items():
        done = []
        for j, v in jobs.items():
            cond = re.sub(r"^\$\{\{\s*|\s*\}\}$", "", (v.get("if") or "success()").strip())
            needs = v.get("needs"); needs = [needs] if isinstance(needs, str) else (needs or [])
            ok = cond == "success()" or evaluate(cond, ctx)
            if ok and any(n not in done for n in needs): ok = False
            if ok: done.append(j)
        ran += [f"{wf}:{j}" for j in done]
    return ran

def tags_of(wfs_dir):
    t = set()
    for f in glob.glob(os.path.join(wfs_dir, "*.yml")):
        t |= set(re.findall(r"'(\[[a-z0-9-]+\])'", open(f).read()))
    return sorted(t)

new = push_workflows(sys.argv[1]); msg = sys.argv[2]
base = push_workflows(sys.argv[3]) if len(sys.argv) > 3 else None
print("push-triggered workflows:", list(new))
known = [t for t in tags_of(sys.argv[1]) if t != "[build-only]"]

# The commit under review is a skip-only push: its own message must run nothing.
cases = [("actual commit message (skip-only review push)", msg, [])]
cases.append(("[build-only] alone", "lab: x [build-only]", ["appliance-lab.yml:build-only"]))
cases.append(("[build-only] [lab-skip]", "x [build-only] [lab-skip]", []))
for t in known:
    for m in (f"x [build-only] {t}", f"x {t} [build-only]", f"x [build-only] {t} [lab-skip]", f"X [BUILD-ONLY] {t.upper()}"):
        cases.append((f"mixed: {m}", m, []))
bad = 0
for name, m, want in cases:
    got = jobs_run(new, m)
    ok = sorted(got) == sorted(want); bad += not ok
    if not ok or not name.startswith("mixed"):
        print(f"{'PASS' if ok else 'FAIL'} {name}: {got or 'nothing'}")
mixed = sum(1 for n, *_ in cases if n.startswith("mixed"))
print(f"mixed-tag cases: {mixed} ({len(known)} known tags x 4 forms), failures so far: {bad}")
got = jobs_run(new, "x [build-only] [new-future-tag]")
print(f"INFO [build-only] + unknown tag: expression selects {got}; the runtime guard must refuse it (tested separately)")
if base is not None:
    diff = 0
    for t in known:
        for m in (f"x {t}", f"x {t} [lab-skip]", "x untagged"):
            a, b = sorted(jobs_run(base, m)), sorted(jobs_run(new, m))
            if a != b:
                diff += 1; print(f"CHANGED vs base for {m!r}: base={a} new={b}")
    print(f"non-build-only routing vs base: {3*len(known)} cases, {diff} changed")
    bad += diff
print("RESULT", "PASS" if not bad else f"FAIL ({bad})"); sys.exit(1 if bad else 0)
