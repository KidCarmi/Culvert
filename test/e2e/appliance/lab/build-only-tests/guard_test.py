"""Offline tests for build-only-route-guard.py. Usage: guard_test.py GUARD_SCRIPT."""
import os, subprocess, sys
g = sys.argv[1]
P = "e18277a48938537f68985dd55fc05ade3081f939"; T = "c3486c780e52e8ae424baa39b0b7366b65404ad1"
good = dict(GUARD_EVENT="push", GUARD_REF="refs/heads/test/appliance-lab",
            GUARD_MESSAGE="lab: build the FB-1 replacement OVA from 0981ff3d [build-only]",
            GUARD_BEFORE=P, GUARD_PARENT=P, GUARD_HEAD_TREE=T, GUARD_PARENT_TREE=T)
cases = [("control: exact trigger", {}, 0),
 ("uppercase tag", {"GUARD_MESSAGE": "lab: build [BUILD-ONLY]"}, 0),
 ("no tag", {"GUARD_MESSAGE": "lab: build"}, 1),
 ("tag twice", {"GUARD_MESSAGE": "[build-only] lab [build-only]"}, 1),
 ("+ [lab-skip]", {"GUARD_MESSAGE": "lab [build-only] [lab-skip]"}, 1),
 ("+ [boot-console]", {"GUARD_MESSAGE": "lab [build-only] [boot-console]"}, 1),
 ("+ unknown future tag", {"GUARD_MESSAGE": "lab [build-only] [new-route]"}, 1),
 ("+ tag in body", {"GUARD_MESSAGE": "lab [build-only]\n\nsee [sidecar-scan]"}, 1),
 ("+ empty brackets", {"GUARD_MESSAGE": "lab [build-only] []"}, 1),
 ("dispatch event", {"GUARD_EVENT": "workflow_dispatch"}, 1),
 ("other ref", {"GUARD_REF": "refs/heads/main"}, 1),
 ("two commits pushed (parent != before)", {"GUARD_BEFORE": "1"*40}, 1),
 ("new branch push (before all zeros)", {"GUARD_BEFORE": "0"*40}, 1),
 ("non-empty commit (tree differs)", {"GUARD_HEAD_TREE": "2"*40}, 1),
 ("missing tree", {"GUARD_HEAD_TREE": ""}, 1),
 ("missing parent and before", {"GUARD_PARENT": "", "GUARD_BEFORE": ""}, 1),
 ("missing message", {"GUARD_MESSAGE": ""}, 1)]
bad = 0
for n, over, want in cases:
    e = {k: v for k, v in os.environ.items() if not k.startswith("GUARD_")}; e.update(good); e.update(over)
    r = subprocess.run([sys.executable, "-I", g], env=e, capture_output=True, text=True)
    ok = r.returncode == want; bad += not ok
    first = (r.stdout.strip().splitlines() or [""])[0]
    print(f"{'PASS' if ok else 'WRONG'} {n}: exit={r.returncode} {first[:110]}")
print(f"{len(cases)-bad}/{len(cases)}"); sys.exit(bad > 0)
