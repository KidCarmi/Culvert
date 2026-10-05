#!/usr/bin/env python3
"""Run a script on the appliance through an AUTHENTICATED local console login.

The appliance's access boundary (docs/appliance/ssh-access-boundary.md) gives
SSH only to the read-only `culvert-operator`; every privileged operation needs
a PAM login as the local administrator `culvert` and `sudo` with its password.
QEMU's ttyS0 is that local console here: this helper drives the real getty and
PAM on it (one-time password -> forced change -> sudo password), never a key or
a bypass. Stdlib only.

  console-session.py --sock S --secrets DIR --console-log LOG [--as-user] [--timeout N] [--nowait] < script

Credentials live in DIR (never printed): `console-pass` holds the CURRENT
password; on first use it is taken from the one-time password first boot
printed on the console (LOG), and the forced change writes the new one there.
The script is sent base64-encoded and run as root through `sudo` (or as
`culvert` with --as-user); its combined output comes back base64-encoded
between split markers, so serial echo, prompts and kernel console messages are
never mistaken for output. Exit status = the script's exit status; 90-99 are
helper failures (no login, no marker, timeout).
"""
import argparse
import base64
import os
import re
import secrets
import socket
import string
import sys
import time

USER = "culvert"
ONE_TIME = re.compile(r"One-time console login:\s+user '" + USER + r"'\s+password:\s+(\S+)")
LOGIN = re.compile(r"login:\s*$")
PASSWORD = re.compile(r"[Pp]assword:\s*$")
CURRENT = re.compile(r"Current password:\s*$")
NEW = re.compile(r"New password:\s*$")
RETYPE = re.compile(r"Retype new password:\s*$")
SUDO = "LABSUDO:"


class Console:
    def __init__(self, path, trace):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.s.setblocking(False)
        self.buf = ""
        self.trace = trace

    def send(self, text):
        self.s.sendall(text.encode())

    def read_for(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self._pump(0.2)
        return self.buf

    def _pump(self, wait):
        time.sleep(wait)
        try:
            while True:
                chunk = self.s.recv(65536)
                if not chunk:
                    raise ConnectionError("console closed")
                text = chunk.decode("utf-8", "replace").replace("\r", "")
                self.buf += text
                if self.trace:
                    self.trace.write(text)
        except BlockingIOError:
            pass

    def expect(self, patterns, timeout):
        """Wait until the buffer TAIL matches one of patterns; return its index."""
        end = time.time() + timeout
        while time.time() < end:
            tail = self.buf[-400:]
            for i, p in enumerate(patterns):
                if (p.search(tail) if hasattr(p, "search") else p in tail):
                    return i
            self._pump(0.2)
        return -1

    def take(self):
        b, self.buf = self.buf, ""
        return b


def secret_path(d, name):
    return os.path.join(d, name)


def read_secret(d, name):
    try:
        with open(secret_path(d, name), encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def write_secret(d, name, value):
    p = secret_path(d, name)
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value)
    os.replace(p + ".tmp", p)


def new_password():
    # Letters, digits and two punctuation classes: satisfies pam_unix/pwquality
    # defaults without characters a tty line discipline would interpret.
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(20))
    return core[:7] + "-" + core[7:14] + "_" + core[14:] + "9a"


def current_password(args):
    pw = read_secret(args.secrets, "console-pass")
    if pw:
        return pw
    try:
        with open(args.console_log, encoding="utf-8", errors="replace") as f:
            found = ONE_TIME.findall(f.read())
    except FileNotFoundError:
        found = []
    if not found:
        return ""
    write_secret(args.secrets, "console-onetime", found[-1])
    write_secret(args.secrets, "console-pass", found[-1])
    return found[-1]


def sync(c, timeout=15):
    tag = secrets.token_hex(4)
    c.take()
    c.send("printf '%s%s\\n' LABSY NC" + tag + "\r")
    return c.expect(["LABSYNC" + tag], timeout) == 0


def login(c, args):
    pw = current_password(args)
    if not pw:
        raise SystemExit(91)
    c.send(USER + "\r")
    if c.expect([PASSWORD], 20) != 0:
        raise SystemExit(92)
    c.take()
    c.send(pw + "\r")
    i = c.expect([CURRENT, "Login incorrect", re.compile(r"[$#] ?$"), "Last login", "Welcome"], 45)
    if i == 1:
        raise SystemExit(93)
    if i == 0:
        # Forced change (chage -d 0): the one-time password must be replaced.
        fresh = new_password()
        c.send(pw + "\r")
        if c.expect([NEW], 20) != 0:
            raise SystemExit(94)
        c.send(fresh + "\r")
        if c.expect([RETYPE], 20) != 0:
            raise SystemExit(94)
        c.send(fresh + "\r")
        write_secret(args.secrets, "console-pass", fresh)
        with open(secret_path(args.secrets, "console-events"), "a", encoding="utf-8") as f:
            f.write("forced-change %s\n" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        c.read_for(4)
    # Quiet, wide, history-free shell; nothing typed afterwards is echoed.
    c.send("stty -echo cols 400 rows 50; export TERM=dumb LANG=C.UTF-8 HISTFILE=/dev/null; "
           "PS1=; PS2=; PROMPT_COMMAND=; unset TMOUT; umask 077; mkdir -p /tmp/.lab\r")
    if not sync(c, 20):
        raise SystemExit(95)
    with open(secret_path(args.secrets, "console-events"), "a", encoding="utf-8") as f:
        f.write("login %s\n" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def ensure_shell(c, args):
    c.send("\r")
    c.read_for(2)
    for _ in range(4):
        tail = c.buf[-300:]
        if LOGIN.search(tail):
            c.take()
            login(c, args)
            # Kernel console messages would interleave with serial output:
            # errors only, for this boot (runtime setting, reset at reboot).
            run(c, args, "dmesg -n 3\n", 60, root=True, quiet=True)
            return
        if sync(c, 6):
            return
        # Unknown state (half-typed login, pager...): interrupt, try again.
        c.send("\x03\r")
        c.read_for(3)
    raise SystemExit(96)


def run(c, args, script, timeout, root, quiet=False, nowait=False):
    tag = secrets.token_hex(5)
    b64 = base64.b64encode(script.encode()).decode()
    c.take()
    c.send("base64 -d > /tmp/.lab/c%s <<'LABEOF'\r" % tag)
    for i in range(0, len(b64), 76):
        c.send(b64[i:i + 76] + "\r")
    c.send("LABEOF\r")
    runner = ("sudo -p '%s' bash" % SUDO) if root else "bash"
    if nowait:
        c.send("%s /tmp/.lab/c%s\r" % (runner, tag))
    else:
        c.send(("%s /tmp/.lab/c%s > /tmp/.lab/o%s 2>&1 < /dev/null; r=$?; printf 'LAB%%s%%s\\n' BEGIN %s; "
                "base64 -w 76 /tmp/.lab/o%s; printf 'LAB%%s%%s %%s\\n' END %s \"$r\"; rm -f /tmp/.lab/c%s /tmp/.lab/o%s\r")
               % (runner, tag, tag, tag, tag, tag, tag, tag))
    end_re = re.compile(r"LABEND%s (\d+)" % tag)
    # A --nowait script that prints LABACCEPT <guest epoch> (as root, i.e.
    # after PAM login AND sudo succeeded) is ACCEPTED at that moment: return
    # then, reporting the host clock at detection, instead of after a fixed
    # wait. The recovery timer starts here, never after the 8 s grace.
    accept_re = re.compile(r"LABACCEPT (\d+\.\d+)")
    deadline = time.time() + timeout
    answered = 0
    while time.time() < deadline:
        if root and SUDO in c.buf[-200:]:
            if answered >= 2:
                raise SystemExit(97)
            c.buf = c.buf.replace(SUDO, "")
            c.send(read_secret(args.secrets, "console-pass") + "\r")
            answered += 1
        if nowait:
            a = accept_re.search(c.buf)
            if a:
                sys.stdout.write("ACCEPTED host_epoch=%.3f guest_epoch=%s\n" % (time.time(), a.group(1)))
                sys.stdout.flush()
                return 0
            if time.time() > deadline - timeout + 8 and "LABACCEPT" not in script:
                return 0
        m = end_re.search(c.buf)
        if m:
            begin = c.buf.find("LABBEGIN" + tag)
            body = c.buf[begin + len("LABBEGIN" + tag):m.start()] if begin >= 0 else ""
            lines = [l.strip() for l in body.split("\n")]
            data = "".join(l for l in lines if re.fullmatch(r"[A-Za-z0-9+/=]+", l))
            if not quiet:
                sys.stdout.buffer.write(base64.b64decode(data + "=" * (-len(data) % 4)))
                sys.stdout.flush()
            return int(m.group(1))
        c._pump(0.3)
    raise SystemExit(98)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sock", required=True)
    p.add_argument("--secrets", required=True)
    p.add_argument("--console-log", required=True)
    p.add_argument("--as-user", action="store_true", help="run as culvert, without sudo")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--nowait", action="store_true", help="start the script and return (reboot)")
    p.add_argument("--trace", help="append the raw session (prompts only, no secrets typed are echoed) here")
    args = p.parse_args()
    script = sys.stdin.read()
    trace = open(args.trace, "a", encoding="utf-8") if args.trace else None
    try:
        c = Console(args.sock, trace)
        ensure_shell(c, args)
        rc = run(c, args, script, args.timeout, root=not args.as_user, nowait=args.nowait)
    except (ConnectionError, OSError):
        return 99
    finally:
        if trace:
            trace.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
