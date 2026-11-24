#!/usr/bin/env python3
"""Real-Docker probe of restore.commit through the maintenance agent.

Manual; never a PR gate. Runs the real culvert-maint binary and the real
Culvert proxy binary against a real dockerd, on the shipped topology (the named
volume proxy-data mounted at /data), and checks every claim against dockerd and
the volume, read directly. Nothing the agent reports is taken as evidence of
what happened.

It moves the fixed tag culvert/proxy:pinned and deletes its own volumes:
disposable daemon only (--i-own-this-daemon), and it must run as root on the
daemon's host, because the volume is read and written through
/var/lib/docker/volumes.

What it checks:

  success         a restore brings back the bytes that were backed up, keeps the
                  previous content complete, leaves ownership and modes as the
                  proxy writes them, and ends with the proxy answering ready
  refused         a restore the preflight refuses never stops the proxy: same
                  container, same start time
  commit_fails    a commit that fails after the stack was stopped leaves the
                  previous content untouched and the proxy serving again
  kill_sweep      the restore process is SIGKILLed during the swap, at a moment
                  taken from the volume; the next proxy start must end with all
                  of the previous content or all of the restored content, never
                  a mixture, and must say which
  agent_crash     the agent is killed between stages of restore.commit; after
                  the restart the operation must be reported as failed and
                  listed as interrupted, its statement about the data must not
                  contradict the volume, and the agent must not have touched
                  the stack on its own

Process death only. No host power loss, no dockerd crash, no storage fault.
No systemd here: the unit's control-group kill is emulated (SIGKILL the agent,
SIGTERM what it started, SIGKILL after 10 s). See README.md.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = "culvertrestoreprobe"
COMPOSE = "docker-compose.yml"
READY = "http://127.0.0.1:18080/ready"
DOCKER = "/usr/bin/docker"

SHIM = r"""#!/bin/bash
# Kill-point shim: logs every docker invocation of the agent; when the argv
# contains the pattern in $D/hold it parks BEFORE running docker until
# $D/release exists. It never changes argv or the exit code.
D=@@DIR@@
echo "$(date +%s.%N) START $$ $*" >> "$D/log"
if [ -f "$D/hold" ]; then
  pat="$(cat "$D/hold")"
  if [ -n "$pat" ] && [[ "$*" == *"$pat"* ]]; then
    echo "$(date +%s.%N) HELD $$ $*" >> "$D/log"
    while [ ! -f "$D/release" ]; do sleep 0.05; done
  fi
fi
@@DOCKER@@ "$@"; rc=$?
echo "$(date +%s.%N) END $$ rc=$rc $*" >> "$D/log"
exit $rc
"""


def sh(cmd, timeout=120, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


class Rig:
    def __init__(self, work, agent_bin):
        self.work = Path(work)
        self.agent_bin = agent_bin
        self.proj = self.work / PROJECT
        self.shim_dir = self.work / "shim"
        self.agent = None
        self.gen = 0

    # ---- independent oracle: dockerd and the volumes, never the agent ----
    def compose(self, *args, timeout=180):
        return sh([DOCKER, "compose", "-f", str(self.proj / COMPOSE), *args], timeout=timeout, cwd=self.proj)

    def containers(self):
        out = sh([DOCKER, "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
                  "--format", "{{.Label \"com.docker.compose.service\"}}|{{.Label \"com.docker.compose.oneoff\"}}|{{.State}}|{{.ID}}|{{.Command}}"]).stdout
        rows = []
        for line in out.splitlines():
            svc, oneoff, state, cid, cmd = line.split("|", 4)
            rows.append({"service": svc, "oneoff": oneoff == "True", "state": state, "id": cid, "command": cmd})
        return rows

    def proxy_state(self):
        rows = [r for r in self.containers() if r["service"] == "proxy" and not r["oneoff"]]
        return rows[0]["state"] if rows else "absent"

    def ready_code(self):
        return sh(["curl", "-s", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}", READY]).stdout

    def backups(self):
        out = sh([DOCKER, "run", "--rm", "-v", f"{PROJECT}_culvert-backups:/backup", "alpine:3.24",
                  "sh", "-c", "cd /backup && ls -1A"]).stdout
        return sorted(x for x in out.splitlines() if x)

    def oracle(self):
        cs = self.containers()
        return {"proxy": self.proxy_state(), "ready": self.ready_code(),
                "oneoff": [{"state": c["state"], "command": c["command"]} for c in cs if c["oneoff"]],
                "backups": self.backups()}

    # ---- lifecycle of the rig ----
    def reset(self):
        self.stop_agent()
        if self.proj.exists():
            self.compose("--profile", "cli", "down", "-v", "--remove-orphans")
            for c in self.containers():
                sh([DOCKER, "rm", "-f", c["id"]])
        shutil.rmtree(self.work, ignore_errors=True)
        self.proj.mkdir(parents=True)
        self.shim_dir.mkdir()
        shutil.copy(HERE / COMPOSE, self.proj / COMPOSE)
        shim = self.shim_dir / "docker"
        shim.write_text(SHIM.replace("@@DIR@@", str(self.shim_dir)).replace("@@DOCKER@@", DOCKER))
        shim.chmod(0o755)
        (self.work / "state").mkdir()
        cfg = (HERE / "config.toml.tmpl").read_text()
        for k, v in {"PROJECT_DIR": self.proj, "SOCK_PATH": self.work / "agent.sock",
                     "STATE_DIR": self.work / "state", "UID": os.getuid()}.items():
            cfg = cfg.replace(f"@@{k}@@", str(v))
        (self.work / "config.toml").write_text(cfg)
        r = self.compose("up", "-d")
        if r.returncode != 0:
            raise RuntimeError("compose up failed: " + r.stderr[-400:])
        self.wait(lambda: self.ready_code() == "200", 60, "proxy ready")

    def wait(self, cond, seconds, what):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if cond():
                return
            time.sleep(0.2)
        raise RuntimeError("timeout waiting for " + what)

    def start_agent(self):
        self.gen += 1
        sock = self.work / "agent.sock"
        if sock.exists():
            sock.unlink()
        env = dict(os.environ, PATH=f"{self.shim_dir}:{os.environ['PATH']}")
        log = open(self.work / f"agent-{self.gen}.log", "w")
        self.agent = subprocess.Popen([self.agent_bin, "-config", str(self.work / "config.toml")],
                                      stdout=log, stderr=subprocess.STDOUT, env=env, cwd=self.work)
        self.wait(lambda: self.api("GET", "/v1/health")[0] == 200, 30, "agent health")

    def stop_agent(self):
        if self.agent and self.agent.poll() is None:
            self.agent.terminate()
            try:
                self.agent.wait(20)
            except subprocess.TimeoutExpired:
                self.agent.kill()
        self.agent = None

    def descendants(self, root):
        kids = {}
        for p in Path("/proc").iterdir():
            if p.name.isdigit():
                try:
                    stat = (p / "stat").read_text()
                    ppid = int(stat.rsplit(")", 1)[1].split()[1])
                    kids.setdefault(ppid, []).append(int(p.name))
                except (OSError, ValueError, IndexError):
                    pass
        out, todo = [], [root]
        while todo:
            for k in kids.get(todo.pop(), []):
                out.append(k)
                todo.append(k)
        return out

    def crash_agent(self):
        """SIGKILL the agent only, then emulate the unit's control-group kill on what it started."""
        left = self.descendants(self.agent.pid)
        self.agent.send_signal(signal.SIGKILL)
        status = self.agent.wait(10)
        alive = lambda: [p for p in left if Path(f"/proc/{p}").exists()]
        for p in alive():
            try:
                os.kill(p, signal.SIGTERM)
            except ProcessLookupError:
                pass
        end = time.monotonic() + 10
        while alive() and time.monotonic() < end:
            time.sleep(0.1)
        hard = alive()
        for p in hard:
            try:
                os.kill(p, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.agent = None
        return {"agent_wait_status": status, "children_at_kill": len(left), "children_needing_sigkill": len(hard)}

    # ---- agent API (the system under test's own reports) ----
    def api(self, method, path, body=None):
        cmd = ["curl", "-s", "-m", "60", "--unix-socket", str(self.work / "agent.sock"), "-X", method,
               "-w", "\n%{http_code}", "http://agent" + path]
        if body is not None:
            cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
        r = sh(cmd)
        text, _, code = r.stdout.rpartition("\n")
        try:
            return int(code), json.loads(text) if text.strip() else None
        except ValueError:
            return 0, text

    def wait_terminal(self, op_id, seconds=180):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            code, body = self.api("GET", f"/v1/operations/{op_id}")
            if code == 200 and body.get("state") in ("succeeded", "failed"):
                return body
            time.sleep(0.3)
        raise RuntimeError("operation did not finish: " + op_id)

    def reports(self, op_id):
        code, op = self.api("GET", f"/v1/operations/{op_id}")
        _, status = self.api("GET", "/v1/status")
        _, audit = self.api("GET", "/v1/audit")
        events = audit.get("events", audit) if isinstance(audit, dict) else audit
        mine = [{"kind": e.get("kind"), "outcome": e.get("outcome")} for e in (events or [])
                if isinstance(e, dict) and e.get("op_id") == op_id]
        return {"operation_http": code, "operation_state": (op or {}).get("state") if code == 200 else None,
                "status_keys": sorted(status.keys()) if isinstance(status, dict) else None,
                "interrupted_operations": (status or {}).get("interrupted_operations") if isinstance(status, dict) else None,
                "recovery_required": (status or {}).get("recovery_required") if isinstance(status, dict) else None,
                "status": status, "audit_for_op": mine}

    def hold(self, pattern):
        (self.shim_dir / "release").unlink(missing_ok=True)
        (self.shim_dir / "hold").write_text(pattern)

    def held(self):
        log = self.shim_dir / "log"
        return log.exists() and " HELD " in log.read_text()

    def unhold(self):
        (self.shim_dir / "hold").unlink(missing_ok=True)
        (self.shim_dir / "release").write_text("x")

    def shim_calls(self):
        log = self.shim_dir / "log"
        if not log.exists():
            return []
        return [" ".join(l.split()[1:2] + l.split()[3:]) for l in log.read_text().splitlines()
                if " START " in l or " HELD " in l]


VOLROOT = Path("/var/lib/docker/volumes")
PROXY_UID_GID = (100, 101)  # the image's `proxy` user; checked against the image at start
FILLERS = 4000


class Vol:
    """The two named volumes, through the daemon host's filesystem."""

    def __init__(self):
        self.data = VOLROOT / f"{PROJECT}_proxy-data" / "_data"
        self.backup = VOLROOT / f"{PROJECT}_culvert-backups" / "_data"
        self.work = self.data / ".restore"

    def intent(self):
        try:
            return json.loads((self.work / "intent.json").read_text())
        except (OSError, ValueError):
            return None

    def outcome(self):
        try:
            return json.loads((self.work / "last-outcome.json").read_text()).get("outcome")
        except (OSError, ValueError):
            return None

    def baks(self):
        return sorted(p for p in self.work.glob("*.bak.*")) if self.work.is_dir() else []

    def fillers_in(self, d):
        try:
            return sum(1 for n in os.listdir(d) if n.startswith("filler-"))
        except OSError:
            return 0

    def seed_fillers(self, n):
        for i in range(n):
            p = self.data / f"filler-{i:05d}"
            p.write_text(str(i))
            os.chown(p, *PROXY_UID_GID)
            os.chmod(p, 0o600)

    def foreign_owned(self):
        """Paths under /data not owned by the proxy user, or a regular file wider than 0640."""
        bad = []
        for root, dirs, files in os.walk(self.data):
            for n in dirs + files:
                p = Path(root) / n
                st = p.lstat()
                if (st.st_uid, st.st_gid) != PROXY_UID_GID:
                    bad.append(f"{p}: {st.st_uid}:{st.st_gid}")
                elif p.is_file() and not p.is_symlink() and st.st_mode & 0o027:
                    bad.append(f"{p}: mode {st.st_mode & 0o777:o}")
        return bad[:10]


def backed_up_files(vol, archive):
    """name -> sha256 of every data/ file inside the (unencrypted) archive."""
    import hashlib, tarfile
    out = {}
    with tarfile.open(vol.backup / archive) as tf:
        for m in tf.getmembers():
            if m.isfile() and m.name.startswith("data/"):
                out[m.name[5:]] = hashlib.sha256(tf.extractfile(m).read()).hexdigest()
    return out


def on_disk(vol, names):
    import hashlib
    out = {}
    for n in names:
        try:
            out[n] = hashlib.sha256((vol.data / n).read_bytes()).hexdigest()
        except OSError:
            out[n] = None
    return out


def proxy_identity(rig):
    r = sh([DOCKER, "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.State.Running}}", "culvert-restore-probe"])
    return r.stdout.strip() if r.returncode == 0 else "absent"


def backup_via_agent(rig, name):
    code, body = rig.api("POST", "/v1/backups", {"filename": name, "encrypt": False})
    if code != 202:
        raise RuntimeError(f"backup admission {code}: {body}")
    op = rig.wait_terminal(body["op_id"])
    if op["state"] != "succeeded":
        raise RuntimeError(f"backup did not succeed: {op.get('failure_reason')}")


def restore_via_agent(rig, name):
    code, body = rig.api("POST", "/v1/restores/commit", {"path": f"/backup/{name}", "mode": "full"})
    if code != 202:
        raise RuntimeError(f"restore admission {code}: {body}")
    op = rig.wait_terminal(body["op_id"])
    return body["op_id"], {"state": op["state"], "failure_reason": op.get("failure_reason"),
                           "stages": [(s.get("stage"), s.get("state")) for s in op.get("progress") or []]}


def mutate_after_backup(vol):
    """Change a backed-up file's bytes (still valid JSON) and add a file no backup carries."""
    p = vol.data / "policy.json"
    p.write_bytes(p.read_bytes() + b"\n\n")
    extra = vol.data / "added-after-backup.txt"
    extra.write_text("not in the archive\n")
    os.chown(extra, *PROXY_UID_GID)
    os.chmod(extra, 0o600)


def check(violations, cond, text):
    if not cond:
        violations.append(text)


def scenario_success(rig):
    rig.reset(); rig.start_agent(); vol = Vol()
    backup_via_agent(rig, "s.tar.gz")
    want = backed_up_files(vol, "s.tar.gz")
    mutate_after_backup(vol)
    before = on_disk(vol, want)
    op_id, op = restore_via_agent(rig, "s.tar.gz")
    after = on_disk(vol, want)
    baks = vol.baks()
    v = []
    check(v, op["state"] == "succeeded", f"operation {op}")
    check(v, before != want, "control: the mutation did not change a backed-up file")
    check(v, after == want, "restored files differ from the archive: " +
          ", ".join(n for n in want if after[n] != want[n]))
    check(v, not (vol.data / "added-after-backup.txt").exists(), "a file that is not in the archive survived a full restore")
    check(v, len(baks) == 1 and (baks[0] / "added-after-backup.txt").exists(), "the previous content was not kept")
    check(v, len(baks) == 1 and all(_sha(baks[0] / n) == before[n] for n in want if before[n]),
          "the kept previous content is not what was there before")
    check(v, vol.intent() is None and vol.outcome() == "committed", f"records: intent={vol.intent()} outcome={vol.outcome()}")
    check(v, rig.ready_code() == "200" and rig.proxy_state() == "running", "proxy is not serving after the restore")
    check(v, not vol.foreign_owned(), f"ownership or mode changed: {vol.foreign_owned()}")
    rig.stop_agent()
    return {"operation": op, "files_checked": len(want), "violations": v}


def _sha(p):
    import hashlib
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return None


def scenario_refused(rig):
    rig.reset(); rig.start_agent(); vol = Vol()
    backup_via_agent(rig, "r.tar.gz")
    archive = vol.backup / "r.tar.gz"
    archive.write_bytes(archive.read_bytes()[:200])  # truncated: the dry-run must refuse it
    ident = proxy_identity(rig)
    names = sorted(p.name for p in vol.data.iterdir())
    op_id, op = restore_via_agent(rig, "r.tar.gz")
    calls = rig.shim_calls()
    v = []
    check(v, op["state"] == "failed", f"operation {op}")
    check(v, proxy_identity(rig) == ident, "the proxy container was stopped or replaced")
    check(v, not any(c.startswith("START") and (" down" in c or " up -d" in c or "--confirm" in c) for c in calls),
          "a refused preflight still ran a stack command")
    check(v, rig.ready_code() == "200", "proxy not ready")
    check(v, sorted(p.name for p in vol.data.iterdir()) == names, "the data directory gained or lost an entry")
    rig.stop_agent()
    return {"operation": op, "violations": v}


def scenario_commit_fails(rig):
    rig.reset(); rig.start_agent(); vol = Vol()
    backup_via_agent(rig, "f.tar.gz")
    want = backed_up_files(vol, "f.tar.gz")
    mutate_after_backup(vol)
    before = on_disk(vol, want)
    # Park the agent just before the commit command (the preflight has passed and
    # the stack is down), damage the archive, let the commit run.
    rig.hold("--confirm")
    code, body = rig.api("POST", "/v1/restores/commit", {"path": "/backup/f.tar.gz", "mode": "full"})
    rig.wait(rig.held, 120, "the commit command")
    down_at_commit = rig.proxy_state()
    archive = vol.backup / "f.tar.gz"
    archive.write_bytes(archive.read_bytes()[:200])
    rig.unhold()
    op = rig.wait_terminal(body["op_id"])
    v = []
    check(v, down_at_commit in ("absent", "exited"), f"control: the stack was not down at the commit ({down_at_commit})")
    check(v, op["state"] == "failed", f"operation state {op['state']}")
    check(v, on_disk(vol, want) == before, "a failed commit changed backed-up files")
    check(v, (vol.data / "added-after-backup.txt").exists(), "a failed commit removed a file")
    check(v, vol.intent() is None and not vol.baks(), f"a failed commit left records: intent={vol.intent()} baks={vol.baks()}")
    check(v, rig.ready_code() == "200" and rig.proxy_state() == "running", "the proxy was left down after a failed restore")
    rig.stop_agent()
    return {"operation_state": op["state"], "failure_reason": op.get("failure_reason"), "violations": v}


def scenario_kill_sweep(rig, trials, seed):
    """No agent: the restore command exactly as the agent's template runs it, SIGKILLed mid-swap."""
    import random
    rnd = random.Random(seed)
    rig.reset(); vol = Vol()
    r = rig.compose("--profile", "cli", "run", "--rm", "cli", "--backup", "/backup/k.tar.gz")
    if r.returncode != 0:
        raise RuntimeError("backup failed: " + r.stderr[-300:])
    rows, v = [], []
    for i in range(trials):
        rig.compose("down")
        # previous content for this trial: FILLERS files the archive does not carry
        for p in vol.data.glob("filler-*"):
            p.unlink()
        for b in vol.baks():
            shutil.rmtree(b)
        vol.seed_fillers(FILLERS)
        delay = rnd.choice([0.0, 0.002, 0.005, 0.01, 0.015, 0.02, 0.025, 0.03, 0.035, 0.04, 0.05, 0.08])
        proc = subprocess.Popen([DOCKER, "compose", "-f", str(rig.proj / COMPOSE), "--profile", "cli", "run", "--rm",
                                 "--name", f"restore-kill-{i}", "-e", "CULVERT_BACKUP_PASSPHRASE", "cli",
                                 "--restore", "/backup/k.tar.gz", "--mode", "full", "--confirm"],
                                cwd=rig.proj, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.monotonic() + 30
        while time.monotonic() < end and proc.poll() is None and not (vol.work / "intent.json").exists():
            pass  # busy-wait on the volume: the swap lasts milliseconds
        time.sleep(delay)
        killed = sh([DOCKER, "kill", f"restore-kill-{i}"]).returncode == 0
        proc.wait(60)
        sh([DOCKER, "rm", "-f", f"restore-kill-{i}"])
        intent = vol.intent()
        live, kept = vol.fillers_in(vol.data), sum(vol.fillers_in(b) for b in vol.baks())
        row = {"trial": i, "delay_s": delay, "kill_landed": killed,
               "phase_at_death": intent["phase"] if intent else ("committed" if vol.outcome() == "committed" and live == 0 else "no_record"),
               "previous_files_live": live, "previous_files_set_aside": kept}
        check(v, live + kept == FILLERS, f"trial {i}: previous files lost at death: {live}+{kept} of {FILLERS}")
        # the next start of the real proxy
        up = rig.compose("up", "-d")
        try:
            rig.wait(lambda: rig.ready_code() == "200", 60, "proxy ready after the kill")
            row["proxy_ready"] = True
        except RuntimeError:
            row["proxy_ready"] = False
            row["proxy_log_tail"] = sh([DOCKER, "logs", "--tail", "5", "culvert-restore-probe"]).stderr[-400:]
        live2 = vol.fillers_in(vol.data)
        row.update(previous_files_live_after_start=live2, outcome_after_start=vol.outcome(),
                   intent_after_start=vol.intent() is not None)
        check(v, row["proxy_ready"], f"trial {i}: the proxy did not come up")
        check(v, not row["intent_after_start"], f"trial {i}: intent record still present after a start")
        if intent:  # died mid-swap: the start must have put everything back
            check(v, live2 == FILLERS and row["outcome_after_start"] == "rolled_back",
                  f"trial {i}: mid-swap death ({intent['phase']}) not undone: {live2} of {FILLERS}, outcome {row['outcome_after_start']}")
        else:       # died before the record or after the commit: one whole state or the other
            check(v, live2 in (0, FILLERS), f"trial {i}: a mixture after start: {live2} of {FILLERS}")
        rows.append(row)
    phases = {}
    for r_ in rows:
        phases[r_["phase_at_death"]] = phases.get(r_["phase_at_death"], 0) + 1
    return {"trials": rows, "phases_hit": phases, "violations": v}


def scenario_agent_crash(rig, pattern, label):
    rig.reset(); rig.start_agent(); vol = Vol()
    backup_via_agent(rig, "a.tar.gz")
    rig.hold(pattern)
    code, body = rig.api("POST", "/v1/restores/commit", {"path": "/backup/a.tar.gz", "mode": "full"})
    op_id = body["op_id"]
    rig.wait(rig.held, 120, "kill point " + label)
    out = {"kill_point": label, "docker_at_kill": rig.proxy_state()}
    calls_at_kill = len(rig.shim_calls())
    rig.crash_agent(); rig.unhold(); rig.start_agent()
    time.sleep(5)
    rep = rig.reports(op_id)
    out.update(docker_at_rest=rig.proxy_state(), ready_at_rest=rig.ready_code(),
               operation_http=rep["operation_http"], operation_state=rep["operation_state"],
               interrupted_operations=rep["interrupted_operations"], audit_for_op=rep["audit_for_op"],
               compose_stack_up=(rep["status"] or {}).get("compose_stack_up"),
               data_intent=vol.intent() is not None, data_outcome=vol.outcome())
    # Judged against what the volume and Docker say, never against itself.
    mine = [i for i in (rep["interrupted_operations"] or []) if i.get("op_id") == op_id]
    entry = mine[0] if mine else {}
    out["reported"] = {k: entry.get(k) for k in ("kind", "restore_stage", "stack_touched", "data_changed", "previous_state")}
    v = []
    check(v, rep["operation_http"] == 200 and rep["operation_state"] == "failed",
          f"the interrupted operation is not reported as failed: http {rep['operation_http']} state {rep['operation_state']}")
    check(v, len(mine) == 1, f"interrupted_operations lists {len(mine)} entries for the operation")
    check(v, entry.get("stack_touched") is True, "the report does not say the stack was stopped, and Docker shows it down")
    committed = vol.outcome() == "committed"
    check(v, not (entry.get("data_changed") == "no" and committed),
          "the report says the data did not change; the volume says the restore committed")
    check(v, not (entry.get("data_changed") == "yes" and not committed),
          "the report says the data changed; the volume has no committed restore")
    check(v, out["docker_at_rest"] == out["docker_at_kill"], "the restarted agent changed the stack on its own")
    restarted_calls = [c for c in rig.shim_calls()[calls_at_kill:] if c.startswith("START") and (" down" in c or " up -d" in c or "--restore" in c)]
    check(v, not restarted_calls, f"the restarted agent ran {restarted_calls}")
    out["violations"] = v
    rig.stop_agent()
    return out


SCENARIOS = {
    "success": scenario_success,
    "refused": scenario_refused,
    "commit_fails": scenario_commit_fails,
    "agent_crash_after_down": lambda r: scenario_agent_crash(r, "--confirm", "after stop_stack, before the commit"),
    "agent_crash_before_up": lambda r: scenario_agent_crash(r, "up -d", "after the commit, before start_stack"),
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", required=True, help="culvert-maint binary under test")
    ap.add_argument("--work", default="/tmp/culvert-restore-probe", help="scratch directory (recreated per scenario)")
    ap.add_argument("--out", required=True, help="JSON evidence file")
    ap.add_argument("--repeat", type=int, default=2)
    ap.add_argument("--sweep", type=int, default=40, help="kill_sweep trials (0 skips it)")
    ap.add_argument("--seed", type=int, default=20260421)
    ap.add_argument("--only", nargs="*", default=list(SCENARIOS))
    ap.add_argument("--i-own-this-daemon", action="store_true",
                    help="confirm dockerd is disposable: the probe moves culvert/proxy:pinned and deletes volumes")
    a = ap.parse_args()
    if not a.i_own_this_daemon:
        sys.exit("refusing: pass --i-own-this-daemon on a disposable Docker daemon only")
    if os.geteuid() != 0 or not VOLROOT.is_dir():
        print("INCOMPLETE: needs root on the daemon host (reads the volumes under /var/lib/docker/volumes)")
        sys.exit(2)
    ids = sh([DOCKER, "run", "--rm", "--entrypoint", "id", "culvert/proxy:pinned", "-u"]).stdout.strip(), \
        sh([DOCKER, "run", "--rm", "--entrypoint", "id", "culvert/proxy:pinned", "-g"]).stdout.strip()
    if ids != tuple(str(x) for x in PROXY_UID_GID):
        print(f"INCOMPLETE: culvert/proxy:pinned runs as {ids}, the probe expects {PROXY_UID_GID}")
        sys.exit(2)
    rig = Rig(a.work, a.agent)
    results = {"docker": sh([DOCKER, "version", "--format", "{{.Server.Version}}"]).stdout.strip(),
               "compose": sh([DOCKER, "compose", "version", "--short"]).stdout.strip(), "runs": []}
    unknown = [n for n in a.only if n not in SCENARIOS and n != "kill_sweep"]
    if unknown:
        sys.exit(f"unknown scenario(s): {unknown}; known: {list(SCENARIOS) + ['kill_sweep']}")
    jobs = [(n, SCENARIOS[n]) for n in a.only if n in SCENARIOS for _ in range(a.repeat)]
    if a.sweep > 0 and (a.only == list(SCENARIOS) or "kill_sweep" in a.only):
        jobs.append(("kill_sweep", lambda r: scenario_kill_sweep(r, a.sweep, a.seed)))
    invalid = violations = 0
    for name, fn in jobs:
        t0 = time.monotonic()
        try:
            rec = {"scenario": name, "valid": True, "observations": fn(rig)}
            violations += len(rec["observations"].get("violations", []))
        except Exception as e:  # an incomplete trial is recorded, never counted as a pass
            rec = {"scenario": name, "valid": False, "error": repr(e)}
            invalid += 1
            rig.stop_agent()
        rec["elapsed_s"] = round(time.monotonic() - t0, 1)
        results["runs"].append(rec)
        print(json.dumps({"scenario": name, "valid": rec["valid"], "elapsed_s": rec["elapsed_s"],
                          "violations": rec.get("observations", {}).get("violations", rec.get("error"))}), flush=True)
        Path(a.out).write_text(json.dumps(results, indent=1) + "\n")
    rig.stop_agent()
    rig.compose("--profile", "cli", "down", "-v", "--remove-orphans")
    # Exit codes as the orphan probe: 0 every property held, 1 a property was
    # violated, 2 incomplete (a scenario did not run to its end).
    print(f"restore probe: {len(jobs)} scenario runs, {invalid} incomplete, {violations} violation(s)")
    sys.exit(2 if invalid else 1 if violations else 0)
