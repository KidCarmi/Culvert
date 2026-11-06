#!/usr/bin/env python3
"""Q7 direct-ClamAV observer for appliance-lab.sh (LAB_Q7_FULL_JOINT=1).

  q7-probe-session.py --sock S --secrets DIR --out JSONL --stop FILE
                      [--max-s 300] [--interval 0.8] [--trace T] [--console-log LOG]

Holds ONE authenticated console session for the duration of a maintenance
recovery, so each per-sample privileged observation costs one short scripted
command instead of a fresh console login (console-session.py's settle wait and
PAM login per call would not fit the 5 s sample cadence). It types nothing
while the guest boots: it waits until a new kernel banner and then a login
prompt have appeared, and only then logs in through console-session.py's own
ensure_shell/login/run, the same PAM login + sudo path every privileged lab
step uses. Then, as root, it repeatedly runs a read-only probe:

  * the culvert-clamav container's address, then a DIRECT clamd TCP 3310
    zPING, expecting PONG (the protocol the proxy itself uses);
  * the running culvert container's image ID.

One JSON line per observation, with the host CLOCK_MONOTONIC at its start and
end, so the harness binds an observation to the sample it falls in. Nothing on
the guest is changed. It stops when FILE exists or after --max-s seconds.
"""
import argparse
import importlib.util
import io
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("lab_console_session", os.path.join(HERE, "console-session.py"))
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)

PROBE = r"""ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' culvert-clamav 2>/dev/null | awk '{print $1}')
img=$(docker inspect -f '{{.Image}}' culvert 2>/dev/null)
p=none
if [ -n "$ip" ]; then
  p=$(timeout 2 bash -c 'exec 3<>"/dev/tcp/$0/3310" && printf "zPING\0" >&3 && head -c 16 <&3' "$ip" 2>/dev/null | tr -d '\0\r\n')
fi
printf 'LABQ7 pong=%s image=%s ip=%s\n' "${p:-none}" "${img:-none}" "${ip:-none}"
"""
RESULT = re.compile(r"LABQ7 pong=(\S+) image=(\S+) ip=(\S+)")
BOOT = "Linux version"
PROMPT = re.compile(r"login:")


def run_captured(c, args, script, timeout):
    """console-session.run() writes the script's output to stdout: capture it."""
    old = sys.stdout
    buf = io.BytesIO()
    w = io.TextIOWrapper(buf, encoding="utf-8")
    sys.stdout = w
    try:
        rc = cs.run(c, args, script, timeout, root=True)
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 99
    finally:
        sys.stdout = old
        # Detach before the wrapper is collected: closing it would close buf.
        w.flush()
        w.detach()
    return rc, buf.getvalue().decode("utf-8", "replace")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sock", required=True)
    p.add_argument("--secrets", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--stop", required=True)
    p.add_argument("--max-s", type=float, default=300)
    p.add_argument("--interval", type=float, default=0.8)
    p.add_argument("--trace")
    p.add_argument("--console-log", default="", help="console log, for the one-time password if no current one is stored")
    args = p.parse_args()
    trace = open(args.trace, "a", encoding="utf-8") if args.trace else None
    out = open(args.out, "a", encoding="utf-8")
    end = time.monotonic() + args.max_s
    seq = 0

    def rec(**kw):
        out.write(json.dumps(kw, sort_keys=True) + "\n")
        out.flush()

    def stopped():
        return os.path.exists(args.stop) or time.monotonic() > end

    c = None
    booted = ready = False
    while not stopped():
        if c is None:
            try:
                c = cs.Console(args.sock, trace)
                rec(event="connected", mono=time.monotonic())
            except OSError as e:
                rec(event="connect-failed", mono=time.monotonic(), error=str(e)[:120])
                time.sleep(1)
                continue
        try:
            if not ready:
                # Passive until the NEW boot's login prompt: nothing is typed
                # into the console while firmware, kernel and systemd run.
                c._pump(0.3)
                if not booted:
                    i = c.buf.rfind(BOOT)
                    if i >= 0:
                        booted = True
                        c.buf = c.buf[i:]
                        rec(event="kernel", mono=time.monotonic())
                    else:
                        c.buf = c.buf[-4096:]
                    continue
                if PROMPT.search(c.buf):
                    try:
                        cs.ensure_shell(c, args)
                        ready = True
                        rec(event="login", mono=time.monotonic())
                    except SystemExit as e:
                        rec(event="login-failed", mono=time.monotonic(), code=e.code if isinstance(e.code, int) else 99)
                        c.take()
                        time.sleep(1)
                continue
            seq += 1
            m0 = time.monotonic()
            rc, text = run_captured(c, args, PROBE, 4)
            m1 = time.monotonic()
            m = RESULT.search(text)
            rec(seq=seq, mono_start=m0, mono_end=m1, rc=rc,
                pong=m.group(1) if m else "none", image=m.group(2) if m else "none", ip=m.group(3) if m else "none")
            if rc >= 90 and not m:
                # Transport trouble (timeout, sudo, console state): re-establish
                # the shell before the next observation; never type blindly.
                ready = False
                booted = True
                c.take()
                c.send("\r")
            time.sleep(args.interval)
        except ConnectionError as e:
            rec(event="console-closed", mono=time.monotonic(), error=str(e)[:120])
            c = None
            ready = False
            time.sleep(1)
    rec(event="stop", mono=time.monotonic(), observations=seq)
    if trace:
        trace.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
