#!/usr/bin/env python3
"""SIGTERM timeline of a Culvert proxy IMAGE under real Docker.

Runs the image as docker-compose.yml does (host network, a /data volume, the
image's own command), waits until /ready answers 200, leaves two requests to the
admin UI unfinished so that the shutdown is held open (as a browser tab with a
pending request would), asks Docker to stop the container, and records every
change of what /ready and /health answer until the container is gone.

  usage: image-sigterm-timeline.py <image> <expect> [-- extra container args]
    expect = not-ready : after SIGTERM /ready must never answer 200 again
             observe   : report only (the contrast: an image without the change)

  env: TIMELINE_PORT (8080), TIMELINE_UI_PORT (PORT+1010 = 9090), TIMELINE_UI_TLS (1),
       TIMELINE_STOP_GRACE (60)

Exit: 0 held (or observe), 1 /ready answered 200 during shutdown, 2 invalid (the
shutdown was not held open long enough to observe anything, or setup failed).
Removes the container and its anonymous volume on exit.
"""
import os, socket, ssl, subprocess, sys, time, urllib.request, urllib.error

if len(sys.argv) < 3 or sys.argv[2] not in ("not-ready", "observe"):
    sys.exit(__doc__)
image, expect = sys.argv[1], sys.argv[2]
extra = sys.argv[4:] if len(sys.argv) > 3 and sys.argv[3] == "--" else []
PORT = int(os.environ.get("TIMELINE_PORT", "8080"))
UI_PORT = int(os.environ.get("TIMELINE_UI_PORT", str(PORT + 1010)))
UI_TLS = os.environ.get("TIMELINE_UI_TLS", "1") == "1"
GRACE = os.environ.get("TIMELINE_STOP_GRACE", "60")
NAME = "culvert-sigterm-timeline-%d" % os.getpid()
GRACE_AFTER = 0.5   # /ready may be mid-answer when the signal lands
MIN_HELD = 2.0      # the shutdown must stay observable at least this long


def sh(*a, **kw):
    return subprocess.run(a, capture_output=True, text=True, **kw)


def get(path):
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return op.open("http://127.0.0.1:%d%s" % (PORT, path), timeout=1).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return "refused"


def ui_request():
    c = socket.create_connection(("127.0.0.1", UI_PORT), timeout=5)
    if UI_TLS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c = ctx.wrap_socket(c)
    c.sendall(b"GET / HTTP/1.1\r\nHost: timeline\r\n")  # headers never finished
    return c


def cleanup():
    sh("docker", "rm", "-f", "-v", NAME)


rc = 2
try:
    r = sh("docker", "run", "-d", "--name", NAME, "--network", "host", "-v", "/data",
           "-e", "CULVERT_SESSION_SECRET=" + os.urandom(32).hex(), image, *extra)
    if r.returncode != 0:
        print("INVALID: docker run failed:", r.stderr.strip()[-300:])
        sys.exit(2)
    for _ in range(300):
        if get("/ready") == 200:
            break
        time.sleep(0.2)
    before = (get("/ready"), get("/health"))
    print("image %s: before SIGTERM /ready=%s /health=%s" % (image, *before))
    if before[0] != 200:
        print("INVALID: the proxy never became ready")
        print(sh("docker", "logs", "--tail", "30", NAME).stdout[-1500:])
        sys.exit(2)
    try:
        held = [ui_request(), ui_request()]  # young connections: Go's Shutdown waits for them
    except OSError as e:
        print("INVALID: could not open the admin-UI requests on port %d: %s" % (UI_PORT, e))
        sys.exit(2)
    t0 = time.time()
    stop = subprocess.Popen(["docker", "stop", "-t", GRACE, NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    timeline, last, ready_200_after, answered_until = [], None, [], 0.0
    while stop.poll() is None and time.time() - t0 < float(GRACE) + 30:
        t = time.time() - t0
        cur = (get("/ready"), get("/health"))
        if cur != last:
            timeline.append((round(t, 2), cur))
            last = cur
        if cur[0] != "refused":
            answered_until = t
        if cur[0] == 200 and t > GRACE_AFTER:
            ready_200_after.append(round(t, 2))
        time.sleep(0.05)
    gone = round(time.time() - t0, 2)
    for c in held:
        try:
            c.close()
        except OSError:
            pass
    code = sh("docker", "inspect", "-f", "{{.State.ExitCode}}", NAME).stdout.strip()
    print("container gone after %.2fs (exit code %s); /ready or /health still answered until t+%.2fs" % (gone, code, answered_until))
    for t, (rd, hl) in timeline:
        print("  t+%6.2fs  /ready=%s /health=%s" % (t, rd, hl))
    if answered_until < MIN_HELD:
        print("TIMELINE INVALID: the listener answered for only %.2fs after SIGTERM (need %.1fs); nothing was observed" % (answered_until, MIN_HELD))
        rc = 2
    elif expect == "observe":
        print("TIMELINE OBSERVED: /ready answered 200 during shutdown at %d sample(s)%s" % (
            len(ready_200_after), (" (first t+%.2fs, last t+%.2fs)" % (ready_200_after[0], ready_200_after[-1])) if ready_200_after else ""))
        rc = 0
    elif ready_200_after:
        print("TIMELINE VIOLATION: /ready answered 200 after SIGTERM at t+%s (%d samples)" % (ready_200_after[0], len(ready_200_after)))
        rc = 1
    else:
        print("TIMELINE OK: /ready never answered 200 after t+%.1fs, over %.2fs of observable shutdown" % (GRACE_AFTER, answered_until))
        rc = 0
finally:
    cleanup()
sys.exit(rc)
