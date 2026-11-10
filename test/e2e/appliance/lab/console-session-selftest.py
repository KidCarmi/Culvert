#!/usr/bin/env python3
"""Self-test of console-session.py's transfer path against a fake guest.

The fake guest is a real bash on a pty behind an AF_UNIX socket (the shape of
QEMU's chardev socket). Its guest->host direction can be throttled to a byte
rate, reproducing the console leg's virtio console (hvc0), which sustained only
tens of bytes per second for large output in QEMU campaign 5 (run 42815909646):
the ~60 KB M2 transcript could not cross it within 600 s.

Cases, at 10x the real rate and 1/40 of the real deadline (2000 B/s, 15 s):
  plain 60 KB, throttled       -> exit 98 (deadline), as campaign 5 saw
  --gzip 60 KB, throttled      -> exit 0, stdout byte-identical to the file
  --gzip, script exit 7        -> exit 7, output intact (status preserved)
  --gzip, guest gzip broken    -> exit 90, no output (fails closed)
  --gzip, gzip stream truncated -> exit 90, no output (CRC/length check)
  --gzip, script prints nothing -> exit 0, empty output (valid empty stream)
  plain small, unthrottled     -> exit 0, identical (default path unchanged)
Usage: console-session-selftest.py   (stdlib only; needs bash, gzip, base64)
"""
import os
import pty
import random
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "console-session.py")


def transcript(path, size=60000):
    # M2-shaped text: repetitive keys, varying values (gzip ratio about 8:1,
    # like the real transcripts).
    r = random.Random(1528)
    out, n = [], 0
    while n < size:
        l = "m2-out host netns-census| ns net:[%d] %d\n" % (4026531833 + r.randrange(4), r.randrange(4000))
        if r.random() < 0.2:
            l = "m2-obs host %s rc=0 lines=%d\n" % (r.choice(["sysctl", "ordering", "mdb", "nics", "fds"]), r.randrange(200))
        out.append(l)
        n += len(l)
    data = "".join(out).encode()
    open(path, "wb").write(data)
    return data


class FakeGuest:
    """bash on a pty; one client at a time on SOCK; guest->host throttled."""

    def __init__(self, sock, rate=None, path_prefix=None):
        self.sock, self.rate = sock, rate
        env = {"PATH": (path_prefix + ":" if path_prefix else "") + os.environ["PATH"], "PS1": "", "PS2": "",
               "HOME": tempfile.gettempdir(), "TERM": "dumb", "LANG": "C.UTF-8"}
        pid, fd = pty.fork()
        if pid == 0:
            os.execve("/bin/bash", ["bash", "--norc", "--noprofile", "-c", "stty -echo; exec bash --norc --noprofile -i"], env)
        self.pid, self.fd = pid, fd
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(sock)
        self.srv.listen(1)
        self.stop = False
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            budget, t0 = 0.0, time.time()
            while not self.stop:
                rl, _, _ = select.select([conn, self.fd], [], [], 0.05)
                if conn in rl:
                    b = conn.recv(65536)
                    if not b:
                        break
                    os.write(self.fd, b)
                if self.fd in rl:
                    if self.rate:
                        budget = min(self.rate, budget + (time.time() - t0) * self.rate)
                        t0 = time.time()
                        n = int(budget)
                        if n <= 0:
                            time.sleep(0.05)
                            continue
                        b = os.read(self.fd, n)
                        budget -= len(b)
                    else:
                        b = os.read(self.fd, 65536)
                    try:
                        conn.sendall(b)
                    except OSError:
                        break
            conn.close()

    def close(self):
        self.stop = True
        self.srv.close()
        try:
            os.kill(self.pid, 9)
        except OSError:
            pass


def helper(sock, d, script, timeout, gz):
    cmd = [sys.executable, "-I", HELPER, "--sock", sock, "--secrets", d, "--console-log", d + "/console.log",
           "--as-user", "--timeout", str(timeout)] + (["--gzip"] if gz else [])
    p = subprocess.run(cmd, input=script.encode(), capture_output=True, timeout=timeout + 60)
    return p.returncode, p.stdout


def main():
    d = tempfile.mkdtemp(prefix="cs-selftest-")
    big = d + "/big.txt"
    want = transcript(big)
    stub = d + "/stub"
    os.mkdir(stub)
    open(stub + "/gzip", "w").write("#!/bin/sh\nexit 1\n")
    os.chmod(stub + "/gzip", 0o755)
    # A gzip that emits only the first half of the real stream.
    trunc = d + "/trunc"
    os.mkdir(trunc)
    real = subprocess.run(["sh", "-c", "command -v gzip"], capture_output=True, text=True).stdout.strip()
    open(trunc + "/gzip", "w").write('#!/bin/sh\n%s "$@" > "$0.out"; n=$(wc -c < "$0.out"); head -c $((n / 2)) "$0.out"\n' % real)
    os.chmod(trunc + "/gzip", 0o755)
    bad = 0

    def case(name, rate, prefix, script, timeout, gz, want_rc, want_out):
        nonlocal bad
        sock = "%s/%s.sock" % (d, name)
        g = FakeGuest(sock, rate, prefix)
        try:
            t = time.time()
            rc, out = helper(sock, d, script, timeout, gz)
            el = time.time() - t
        finally:
            g.close()
        ok = rc == want_rc and (want_out is None or out == want_out)
        bad += not ok
        print("%s console-session %s: exit %d (want %d), %d bytes out%s, %.1fs" % (
            "ok" if ok else "FAILED", name, rc, want_rc, len(out),
            "" if want_out is None else (" identical" if out == want_out else " DIFFERENT"), el))

    rate, tmo = 2000, 15
    case("plain-throttled", rate, None, "cat %s\n" % big, tmo, False, 98, None)
    case("gzip-throttled", rate, None, "cat %s\n" % big, tmo, True, 0, want)
    case("gzip-status", rate, None, "cat %s; exit 7\n" % big, tmo, True, 7, want)
    case("gzip-broken", rate, stub, "cat %s\n" % big, tmo, True, 90, b"")
    case("gzip-truncated", rate, trunc, "cat %s\n" % big, tmo, True, 90, b"")
    case("gzip-empty", rate, None, "true\n", tmo, True, 0, b"")
    case("plain-small", None, None, "printf 'hello\\n'\n", tmo, False, 0, b"hello\n")
    print("console-session selftest: %s" % ("PASS" if bad == 0 else "%d FAILED" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
