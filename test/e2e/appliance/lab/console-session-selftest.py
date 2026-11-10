#!/usr/bin/env python3
"""Self-test of console-session.py's receive loop and transfer path.

Campaign 5 (run 42815909646) lost the console leg to the helper's receive loop:
it slept 0.3 s before each drain, and QEMU's virtio console (hvc0, a socket
chardev) stops forwarding for good once its socket backs up between reads. The
helper received 10,661 bytes per connection and then nothing, although QEMU's
logfile shows the guest sent everything. The fix waits on select() and drains
as soon as bytes arrive. QEMU itself cannot run here, so this test checks the
property the fix rests on, plus the end-to-end transfer against a fake guest:

  drain-prompt   _pump(5) returns as soon as data arrives (< 2 s), not after 5 s
  settle-kept    read_for(1) still waits the full second (settle semantics)
  plain-60k      60 KB through a real bash on a pty: exit 0, byte-identical
  status-kept    script exit 7: helper exit 7, output intact
  plain-small    a one-line script: exit 0, identical
Usage: console-session-selftest.py   (stdlib only; needs bash)
"""
import importlib.util
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
_spec = importlib.util.spec_from_file_location("lab_console_session_selftest", HELPER)
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)


def transcript(path, size=60000):
    r = random.Random(1528)
    out, n = [], 0
    while n < size:
        l = "m2-out host netns-census| ns net:[%d] %d\n" % (4026531833 + r.randrange(4), r.randrange(4000))
        out.append(l)
        n += len(l)
    data = "".join(out).encode()
    open(path, "wb").write(data)
    return data


class FakeGuest:
    """A real bash on a pty, one client at a time on SOCK (QEMU chardev shape)."""

    def __init__(self, sock):
        env = {"PATH": os.environ["PATH"], "PS1": "", "PS2": "", "HOME": tempfile.gettempdir(),
               "TERM": "dumb", "LANG": "C.UTF-8"}
        pid, fd = pty.fork()
        if pid == 0:
            os.execve("/bin/bash", ["bash", "--norc", "--noprofile", "-c", "stty -echo; exec bash --norc --noprofile -i"], env)
        self.pid, self.fd, self.stop = pid, fd, False
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(sock)
        self.srv.listen(1)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            while not self.stop:
                rl, _, _ = select.select([conn, self.fd], [], [], 0.05)
                if conn in rl:
                    b = conn.recv(65536)
                    if not b:
                        break
                    os.write(self.fd, b)
                if self.fd in rl:
                    try:
                        conn.sendall(os.read(self.fd, 65536))
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


def main():
    d = tempfile.mkdtemp(prefix="cs-selftest-")
    bad = 0

    def report(ok, name, detail):
        nonlocal bad
        bad += not ok
        print("%s console-session %s: %s" % ("ok" if ok else "FAILED", name, detail))

    # drain-prompt / settle-kept: the receive loop itself.
    path = d + "/pump.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    c = cs.Console(path, None)
    conn, _ = srv.accept()
    threading.Timer(0.1, lambda: conn.sendall(b"x" * 1000)).start()
    t = time.time()
    c._pump(5.0)
    el = time.time() - t
    report(el < 2.0 and len(c.buf) == 1000, "drain-prompt", "_pump(5) returned after %.2fs with %d bytes" % (el, len(c.buf)))
    t = time.time()
    c.read_for(1.0)
    el = time.time() - t
    report(el >= 1.0, "settle-kept", "read_for(1) took %.2fs" % el)
    conn.close()
    srv.close()

    # End to end through the real helper against a fake guest.
    big = d + "/big.txt"
    want = transcript(big)

    def case(name, script, want_rc, want_out):
        sock = "%s/%s.sock" % (d, name)
        g = FakeGuest(sock)
        try:
            t = time.time()
            p = subprocess.run([sys.executable, "-I", HELPER, "--sock", sock, "--secrets", d,
                                "--console-log", d + "/console.log", "--as-user", "--timeout", "30"],
                               input=script.encode(), capture_output=True, timeout=90)
            el = time.time() - t
        finally:
            g.close()
        ok = p.returncode == want_rc and p.stdout == want_out
        report(ok, name, "exit %d (want %d), %d bytes out%s, %.1fs" % (
            p.returncode, want_rc, len(p.stdout), " identical" if p.stdout == want_out else " DIFFERENT", el))

    case("plain-60k", "cat %s\n" % big, 0, want)
    case("status-kept", "cat %s; exit 7\n" % big, 7, want)
    case("plain-small", "printf 'hello\\n'\n", 0, b"hello\n")
    print("console-session selftest: %s" % ("PASS" if bad == 0 else "%d FAILED" % bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
