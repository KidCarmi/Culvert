#!/usr/bin/env python3
"""Real-Docker crash trials for the maintenance agent's restart stage.

One trial: start from a healthy proxy on image v1, ask the real agent (installed
by the real installer, run by a real systemd unit, calling docker through the
real sudoers file) to upgrade to v2, SIGKILL the agent at one exact Docker API
request (dkproxy.py), let systemd restart it, optionally run the operator's next
operation, wait for rest, and compare what the agent reports with what dockerd
says.

The oracle (`truth`) asks dockerd directly and never goes through the agent or
the kill proxy.

  rig.py run <slice> <none|rollback|apply|converge> <stop_delay_s> <k,k,...> [reps]
  rig.py judge [--trials=N] [--expect-fence-violation]

Environment: PROBE_DIR (work dir), PROBE_SYSD (systemd container), PROBE_REAL_SOCK,
PROBE_APP_PORT, PROBE_PROJECT, PROBE_CNAME, PROBE_DRAIN.
"""
import itertools
import json
import os
import subprocess
import sys
import time

R = os.environ["PROBE_DIR"]
P = R + "/p"
SYSD = os.environ["PROBE_SYSD"]
PORT = os.environ["PROBE_APP_PORT"]
PROJECT = os.environ["PROBE_PROJECT"]
CNAME = os.environ["PROBE_CNAME"]
# What the probe proxy does between SIGTERM and exit: "serving" (answers 200 on
# /health and /ready, as Culvert's proxy does today), "notready" (/ready 503),
# "closed" (listener closed at once).
DRAIN = os.environ.get("PROBE_DRAIN", "serving")
REAL = dict(os.environ, DOCKER_HOST="unix://" + os.environ["PROBE_REAL_SOCK"])
SOCK = "/run/culvert-maint/culvert-maint.sock"
STATE = "/var/lib/culvert-maint"


def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, env=REAL, check=False, **k)


def dx(cmd):
    return sh("docker", "exec", SYSD, "sh", "-c", cmd)


def ref(v):
    with open(f"{R}/ref-{v}") as f:
        return f.read().strip()


def iid(r):
    return sh("docker", "image", "inspect", r, "--format", "{{.Id}}").stdout.strip()


_img = {}


def images():
    """The two probe images: registry refs and local ids (read once, on first use,
    so `judge` can run on saved records without Docker)."""
    if not _img:
        _img.update(V1=ref("v1"), V2=ref("v2"))
        _img.update(I1=iid(_img["V1"]), I2=iid(_img["V2"]))
    return _img


def ver(i):
    m = images()
    return "v1" if i == m["I1"] else "v2" if i == m["I2"] else "?"


def api(method, path, body=None, t=20):
    c = f"curl -s -m {t} --unix-socket {SOCK} -X {method} "
    if body is not None:
        c += f"-H 'Content-Type: application/json' -d '{json.dumps(body)}' "
    r = dx(c + f"'http://localhost{path}'").stdout
    try:
        return json.loads(r)
    except ValueError:
        return {"_raw": r[:300]}


def truth():
    """What dockerd says: where the fixed tag is, every container of the
    project (name kind, state, image), and which version answers on the port."""
    cs = []
    ps = sh("docker", "ps", "-a", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}",
            "--format", "{{.Names}}|{{.State}}|{{.ID}}")
    for line in ps.stdout.split():
        n, s, i = line.split("|")
        img = sh("docker", "inspect", i, "--format", "{{.Image}}").stdout.strip()
        cs.append(f"{'canonical' if n == CNAME else 'tempname'}:{s}:{ver(img)}")
    serving = sh("curl", "-s", "-m", "2", f"http://127.0.0.1:{PORT}/health").stdout.strip() or "down"
    return {"tag": ver(iid("culvert/proxy:pinned")), "containers": sorted(cs), "serving": serving}


def mainpid():
    return dx("systemctl show culvert-maint -p MainPID --value").stdout.strip()


def wait_agent(t=120):
    for _ in range(t * 5):
        if dx("systemctl is-active culvert-maint").stdout.strip() == "active" and "agent_version" in api("GET", "/v1/status"):
            return True
        time.sleep(0.2)
    return False


def status():
    s = api("GET", "/v1/status")
    keep = ("op_id", "journal_phase", "docker_state", "running_image", "docker_reconciled", "reconcile_outcome")
    return {
        "interrupted": [{k: o.get(k) for k in keep if k in o} for o in (s.get("interrupted_operations") or [])],
        "pinned_tag": s.get("pinned_tag"),
        "running_image": ver((s.get("running_image") or {}).get("image_id", "")),
        "stack_up": s.get("compose_stack_up"),
        "recovery_required": s.get("recovery_required"),
        "reconcile": s.get("reconcile"),
    }


def reset(stop_delay):
    dx(f"ln -sfn /dk/real.sock /run/docker.sock; systemctl stop culvert-maint; systemctl reset-failed culvert-maint; "
       f"find {STATE} -mindepth 1 -delete; mkdir -p {STATE}/operations; chown -R culvert-maint:culvert-maint {STATE}")
    ids = sh("docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}").stdout.split()
    if ids:
        sh("docker", "rm", "-f", *ids)
    sh("docker", "tag", images()["V1"], "culvert/proxy:pinned")
    with open(R + "/srv/.env", "w") as f:
        f.write(f"STOP_DELAY={stop_delay}\nAPP_PORT={PORT}\nSTOP_SERVE={DRAIN}\n")
    sh("docker", "compose", "-f", "docker-compose.yml", "up", "-d", cwd=R + "/srv")
    dx("systemctl start culvert-maint")
    if not wait_agent(60):
        raise RuntimeError("agent did not start")
    t = truth()
    if t != {"tag": "v1", "containers": ["canonical:running:v1"], "serving": "v1"}:
        raise RuntimeError(f"bad start state {t}")


def run_op(path, body, timeout=240):
    r = api("POST", path, body)
    op = r.get("op_id")
    if not op:
        return {"admitted": False, "resp": r}
    t0, d = time.time(), {}
    while time.time() - t0 < timeout:
        d = api("GET", f"/v1/operations/{op}")
        if d.get("state") in ("succeeded", "failed", "cancelled"):
            break
        time.sleep(0.5)
    res = d.get("result") or {}
    return {"admitted": True, "op": op, "state": d.get("state"), "reason": d.get("failure_reason"),
            "secs": round(time.time() - t0, 1),
            "result": {k: res[k] for k in ("superseded_interrupted_ops", "already_current", "rolled_back") if k in res},
            "truth_at_terminal": truth()}


# Reconcile states (startup_reconcile.go). Anything not listed as still-working
# is an end state for this start.
RECONCILE_WORKING = (None, "", "not_started", "in_progress")


def wait_converge(timeout=300):
    """Waits for the startup reconcile to reach an end state for this start.
    Returns (seconds, last status, finished). A reconcile still working at the
    timeout is NOT finished and the trial is invalid."""
    t0, s, finished = time.time(), {}, False
    while time.time() - t0 < timeout:
        s = status()
        state = (s.get("reconcile") or {}).get("state")
        if state not in RECONCILE_WORKING:
            finished = True
            break
        time.sleep(0.5)
    return round(time.time() - t0, 1), s, finished


def stale_cli():
    """Fence check, from the kernel: the new agent is idle here, so any docker or
    wrapper process still alive was started by the dead agent. It is taken once
    the new agent answers, several seconds after the kill, so it can only catch
    a command that is slow to finish: in practice the trials with a container
    stop in flight. The systemd control in probe.sh covers the general case."""
    out = dx("ps -eo pid,ppid,etimes,args | grep -E '[c]ompose-cli|/usr/bin/[d]ocker( |$)|[d]ocker-compose'").stdout
    return [line.strip()[:100] for line in out.splitlines()]


_ids = itertools.count()


def trial(k, stop_delay, follow):
    tid = f"{os.getpid()}-{next(_ids)}"
    rec = {"k": k, "stop_delay": stop_delay, "follow": follow, "drain": DRAIN}
    reset(stop_delay)
    pid = mainpid()
    dx("ln -sfn /dk/p/dk.sock /run/docker.sock")
    with open(P + "/arm.json", "w") as f:
        json.dump({"id": tid, "k": k, "pid": int(pid)}, f)
    time.sleep(0.05)
    rec["apply_op"] = api("POST", "/v1/upgrades/apply", {"image_ref": images()["V2"]}).get("op_id")
    fired_path, t0 = f"{P}/fired-{tid}.json", time.time()
    while time.time() - t0 < 40 and not os.path.exists(fired_path):
        time.sleep(0.02)
    if not os.path.exists(fired_path):
        rec.update(valid=False, why="kill point not reached")
        return rec
    with open(fired_path) as f:
        fired = json.load(f)["t"]
    time.sleep(1.0)
    rec["truth_1s_after_kill"] = truth()
    ok = wait_agent()
    rec["new_agent_after_s"] = round(time.time() - fired, 1)
    rec["stale_cli_at_restart"] = stale_cli()
    newpid = mainpid()
    rec["valid"] = bool(ok and newpid not in (pid, "0", ""))
    with open(f"{P}/log-{tid}.jsonl") as f:
        log = [json.loads(line) for line in f]
    ki = next(i for i, e in enumerate(log) if e.get("event") == "KILL")
    after = [e for e in log[ki + 1:] if "req" in e and e["t"] - fired < 4.5]
    reached = [e["req"] for e in log[:ki] if e.get("n") is not None] + [e["req"] for e in after if e.get("n") is None]
    rec["held"] = next((e for e in log if e.get("event") == "held_request"), None)
    if rec["held"] and not rec["held"]["forwarded"]:
        reached = reached[:-1]
    rec["last_request_daemon_saw"] = reached[-1] if reached else None
    rec["requests_after_kill"] = [(round(e["t"] - fired, 2), e["req"]) for e in after]
    rec["truth_at_restart"] = truth()
    if follow != "converge":
        rec["status_at_restart"] = status()
    if follow == "rollback":
        rec["follow_op"] = run_op("/v1/rollbacks", {"mode": "image", "image_ref": images()["V1"]})
    elif follow == "apply":
        rec["follow_op"] = run_op("/v1/upgrades/apply", {"image_ref": images()["V2"]})
    elif follow == "converge":
        rec["converge_secs"], rec["status_after_converge"], rec["converge_finished"] = wait_converge()
        rec["truth_after_converge"] = truth()
    time.sleep(stop_delay + 6)
    rec["truth_at_rest"] = truth()
    rec["status_at_rest"] = status()
    time.sleep(3)
    rec["truth_at_rest2"] = truth()
    return rec


# ── judging ─────────────────────────────────────────────────────────────────

def leftovers(t):
    """Never-started containers `compose up` created under a temporary name and
    did not get to rename. They serve nothing; the next `up` removes them."""
    return [c for c in t["containers"] if c.startswith("tempname:created:")]


def healthy(t, want=None):
    """One canonical running container, the tag on its image, the port answering.
    A never-started leftover is tolerated here and reported as a note."""
    cs = [c for c in t["containers"] if c not in leftovers(t)]
    if len(cs) != 1 or not cs[0].startswith("canonical:running:"):
        return False
    v = cs[0].rsplit(":", 1)[1]
    return t["tag"] == v == t["serving"] and (want is None or v == want)


def judge(rec):
    """Returns (verdict, notes). Verdicts: INVALID, VIOLATION, OK."""
    if "exception" in rec or not rec.get("valid"):
        return "INVALID", [rec.get("exception") or rec.get("why") or "agent did not come back"]
    bad, notes = [], []
    if rec["truth_at_rest"] != rec["truth_at_rest2"]:
        return "INVALID", ["not at rest: the state was still changing when it was read"]
    # With converge the new agent runs docker commands of its own at startup,
    # so a process seen then is not evidence of a survivor.
    if rec["stale_cli_at_restart"] and rec["follow"] != "converge":
        bad.append("fence: a docker command of the dead agent was alive when the new agent started")
    rest, st = rec["truth_at_rest"], rec["status_at_rest"]
    op = rec.get("follow_op")
    if rec["follow"] == "converge" and not rec.get("converge_finished"):
        return "INVALID", [f"the startup reconcile had not finished: {(rec['status_after_converge'].get('reconcile') or {}).get('state')!r}"]
    if rec["follow"] in ("rollback", "apply") and not (op and op.get("admitted") and op.get("state") in ("succeeded", "failed")):
        # The trial is about what the next operation does. One that was refused,
        # unreadable or still running exercised nothing.
        return "INVALID", [f"the follow-up operation did not run to an end: {op}"]
    op_ok = bool(op and op.get("admitted") and op.get("state") == "succeeded")
    if op_ok:
        want = "v1" if rec["follow"] == "rollback" else "v2"
        if not healthy(op["truth_at_terminal"], want):
            bad.append(f"false success: the operation reported succeeded with Docker at {op['truth_at_terminal']}")
        if op["truth_at_terminal"] != rest:
            bad.append("late mutation: Docker changed after an operation reported success")
    reported = bool(st["interrupted"]) or bool(st.get("recovery_required")) or bool(op and not op_ok)
    if not healthy(rest) and not reported:
        bad.append(f"silent divergence: Docker at rest is {rest} and nothing reports it")
    if healthy(rest) and leftovers(rest):
        notes.append("a never-started temporary container was left behind")
    if rec["truth_at_restart"]["serving"] != "down" and rest["serving"] == "down":
        notes.append("the proxy stopped serving AFTER the new agent had started")
    elif rest["serving"] == "down":
        notes.append("proxy down at rest")
    if rec["truth_at_restart"] != rest and not op and rec["follow"] != "converge":
        notes.append("Docker changed after the restart with no operation running (daemon-side completion)")
    return ("VIOLATION", bad + notes) if bad else ("OK", notes)


def fmt(t):
    cs = "+".join(c.replace("canonical:", "C:").replace("tempname:", "T:") for c in t["containers"]) or "none"
    return f"tag={t['tag']} {cs} serving={t['serving']}"


def judge_all(expect_fence_violation, want_trials):
    counts = {"OK": 0, "VIOLATION": 0, "INVALID": 0}
    fence_hits = 0
    files = sorted(f for f in os.listdir(R + "/ev") if f.endswith(".jsonl"))
    for name in files:
        with open(f"{R}/ev/{name}") as f:
            recs = [json.loads(line) for line in f]
        for rec in recs:
            verdict, notes = judge(rec)
            counts[verdict] += 1
            fence_hits += any(n.startswith("fence:") for n in notes)
            line = f"PROBE {name[:-6]} k={rec['k']} verdict={verdict}"
            if verdict != "INVALID":
                op = rec.get("follow_op")
                line += (f" last={rec['last_request_daemon_saw']!r} restart_after={rec['new_agent_after_s']}s"
                         f" at_restart[{fmt(rec['truth_at_restart'])}]"
                         + (f" op={op.get('state') if op.get('admitted') else 'refused'}" if op else "")
                         + (f" converge={[(x.get('decision'), x.get('outcome')) for x in ((rec['status_after_converge'].get('reconcile') or {}).get('records') or [])]}" if rec['follow'] == 'converge' else "")
                         + f" at_rest[{fmt(rec['truth_at_rest'])}] records={len(rec['status_at_rest']['interrupted'])}")
            print(line)
            for n in notes:
                print(f"PROBE   - {n}")
    print(f"PROBE-SUMMARY trials={sum(counts.values())} ok={counts['OK']} violations={counts['VIOLATION']} invalid={counts['INVALID']}")
    total = sum(counts.values())
    if counts["INVALID"] or not total:
        return 2
    if want_trials is not None and total != want_trials:
        print(f"PROBE-INCOMPLETE {total} trials recorded, {want_trials} expected")
        return 2
    if expect_fence_violation:
        # Sensitivity control: with the fence removed the probe must see a docker
        # command of the dead agent alive at the restart. Any other violation
        # does not count: the same slice violates for another reason with the
        # fence in place.
        return 0 if fence_hits else 2
    return 1 if counts["VIOLATION"] else 0


def main():
    if sys.argv[1] == "judge":
        want = next((int(a.split("=")[1]) for a in sys.argv if a.startswith("--trials=")), None)
        sys.exit(judge_all("--expect-fence-violation" in sys.argv, want))
    name, follow, sd = sys.argv[2], sys.argv[3], int(sys.argv[4])
    ks = [int(x) for x in sys.argv[5].split(",")]
    reps = int(sys.argv[6]) if len(sys.argv) > 6 else 1
    os.makedirs(R + "/ev", exist_ok=True)
    with open(f"{R}/ev/{name}.jsonl", "a") as out:
        for _ in range(reps):
            for k in ks:
                try:
                    rec = trial(k, sd, follow)
                except Exception as e:  # a broken trial is INVALID, never a pass
                    rec = {"k": k, "follow": follow, "stop_delay": sd, "exception": repr(e)[:400]}
                out.write(json.dumps(rec) + "\n")
                out.flush()


if __name__ == "__main__":
    main()
