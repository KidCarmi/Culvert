#!/usr/bin/env python3
"""Wire-level kill proxy between the agent's docker CLI and dockerd.

A byte pump on a unix socket. When armed (arm.json), it SIGKILLs the AGENT, and
only the agent, at an exact Docker API request of upgrades.apply's restart
stage. Numbering: the fixed-tag POST is request 0, the requests of
`docker compose up -d` follow as 1..N, and -1 means "before the tag POST is
passed on". systemd, sudo, the CLI and dockerd then do whatever they really do.

While the kill is being delivered (tens of ms), new requests from the CLI are
held and then passed on, as bytes a client wrote before dying would be. So the
daemon may see one request more than k; the log records every request, and
rig.py describes a kill point by the last request that reached the daemon, not
by k. For k = -1 the held tag request is dropped if the client is dead by then.

Limits: a request line split across two reads is not counted, and a request
that was already past the gate on another connection is not held. Neither can
make a trial pass: the kill is confirmed from the log and from the new main PID,
and the state is read from dockerd.

usage: dkproxy.py <dir> <real docker socket> <systemd container name>
"""
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

P, REAL, SYSD = sys.argv[1], sys.argv[2], sys.argv[3]
SOCK = P + "/dk.sock"
REQ = re.compile(rb"(GET|POST|PUT|DELETE|HEAD) (/\S*) HTTP/1\.1\r\n")
lock = threading.Lock()
gate = threading.Event()
gate.set()
st = {"mtime": 0, "arm": None, "c": None, "fired": False}


def log(rec):
    a = st["arm"]
    if a:
        with open(f"{P}/log-{a['id']}.jsonl", "a") as f:
            f.write(json.dumps(rec) + "\n")


def load():
    try:
        m = os.stat(P + "/arm.json").st_mtime_ns
    except OSError:
        return
    if m != st["mtime"]:
        with open(P + "/arm.json") as f:
            st.update(mtime=m, arm=json.load(f), c=None, fired=False)


def kill_agent():
    a = st["arm"]
    t = time.time()
    r = subprocess.run(["docker", "exec", SYSD, "kill", "-9", str(a["pid"])], capture_output=True, text=True,
                       env=dict(os.environ, DOCKER_HOST="unix://" + REAL), check=False)
    st["fired"] = True
    log({"t": time.time(), "event": "KILL", "at": a["k"], "rc": r.returncode, "took_ms": round((time.time() - t) * 1000)})
    with open(f"{P}/fired-{a['id']}.json", "w") as f:
        json.dump({"t": time.time(), "rc": r.returncode}, f)


def short(path):
    path = re.sub(r"[0-9a-f]{64}", "<id>", path.split("?")[0])
    path = re.sub(r"^/v1\.\d+", "", path)
    return re.sub(r"/images/.*/tag$", "/images/<ref>/tag", path)


def down(d, c):
    try:
        while True:
            b = d.recv(65536)
            if not b:
                break
            c.sendall(b)
    except OSError:
        pass
    try:
        c.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def classify(b):
    """Log the request heads in b; return 'before', 'after' or None."""
    act = None
    load()
    for m in REQ.finditer(b):
        meth, path = m.group(1).decode(), short(m.group(2).decode())
        a, n = st["arm"], None
        if a and not st["fired"]:
            if st["c"] is None and meth == "POST" and path.endswith("/tag"):
                st["c"] = 0
            elif st["c"] is not None:
                st["c"] += 1
            n = st["c"]
            if n is not None and act is None:
                if a["k"] == -1 and n == 0:
                    act = "before"
                elif a["k"] == n:
                    act = "after"
        log({"t": time.time(), "n": n, "req": meth + " " + path})
    return act


def client_dead(c):
    c.setblocking(False)
    try:
        dead = c.recv(1, socket.MSG_PEEK) == b""
    except BlockingIOError:
        dead = False
    except OSError:
        dead = True
    c.setblocking(True)
    return dead


def handle(c):
    d = socket.socket(socket.AF_UNIX)
    d.connect(REAL)
    threading.Thread(target=down, args=(d, c), daemon=True).start()
    try:
        while True:
            b = c.recv(65536)
            if not b:
                break
            gate.wait()
            with lock:
                act = classify(b)
                if act:
                    gate.clear()
            if act == "before":
                try:
                    kill_agent()
                    time.sleep(0.4)
                    dead = client_dead(c)
                    log({"t": time.time(), "event": "held_request", "client_dead": dead, "forwarded": not dead})
                finally:
                    gate.set()
                if dead:
                    break
                d.sendall(b)
            else:
                d.sendall(b)
                if act == "after":
                    try:
                        kill_agent()
                    finally:
                        gate.set()
    except OSError:
        pass
    try:
        d.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def main():
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o666)
    srv.listen(128)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
