#!/usr/bin/env python3
"""SIGTERM timeline of the real Culvert proxy binary, without Docker.

Starts the binary, waits until /ready answers, optionally leaves a request to
the admin UI unfinished, sends SIGTERM, and prints every change of what /ready
and /health answer until the process exits.

  usage: sigterm-timeline.py <culvert binary> <idle|ui-conn|ui+socks> [work dir]
"""
import subprocess, time, sys, os, signal, socket, urllib.request, json, shutil
binp, mode = sys.argv[1], sys.argv[2]
import tempfile
d = sys.argv[3] if len(sys.argv) > 3 else tempfile.mkdtemp(prefix="culvert-sigterm-")
os.makedirs(d, exist_ok=True)
env = dict(os.environ, CULVERT_SESSION_SECRET="0123456789abcdef"*4, NO_PROXY="*", no_proxy="*")
for k in ("HTTPS_PROXY","https_proxy","HTTP_PROXY","http_proxy"): env.pop(k, None)
args = [binp, "-port", "18080", "-ui-port", "19090", "-ui-no-tls", "-ca-path", d+"/ca.bundle", "-policy", d+"/policy.json", "-logfile", d+"/proxy.log",
        "-audit-log", d+"/audit.jsonl", "-request-log", d+"/requests.jsonl", "-threat-feed-db", d+"/tf.json", "-ui-users-file", d+"/ui_users.json", "-socks5-port", "11080"]
p = subprocess.Popen(args, cwd=d, env=env, stdout=open(d+"/out.log","w"), stderr=subprocess.STDOUT)
def get(path):
    try:
        r = urllib.request.build_opener(urllib.request.ProxyHandler({})).open("http://127.0.0.1:18080"+path, timeout=1); return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception as e: return "refused"
for _ in range(100):
    if get("/ready") in (200, 503): break
    time.sleep(0.2)
print("before SIGTERM: /ready", get("/ready"), "/health", get("/health"))
held = []
if mode == "ui+socks":
    s5 = socket.create_connection(("127.0.0.1", 11080)); s5.sendall(b"\x05"); held.append(s5)   # SOCKS5 greeting started, connection open
if mode in ("ui-conn", "ui+socks"):
    for _ in range(2):
        s = socket.create_connection(("127.0.0.1", 19090)); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n"); held.append(s)   # request in flight, never completed
t0 = time.time(); p.send_signal(signal.SIGTERM); last = None; tl = []
while p.poll() is None and time.time() - t0 < 70:
    cur = (get("/ready"), get("/health"))
    if cur != last: tl.append((round(time.time() - t0, 2), cur)); last = cur
    time.sleep(0.05)
print("exit after", round(time.time() - t0, 2), "s rc", p.returncode)
for t, (r, h) in tl: print(f"  t+{t:>5}s  /ready={r} /health={h}")
if p.poll() is None: p.kill()
