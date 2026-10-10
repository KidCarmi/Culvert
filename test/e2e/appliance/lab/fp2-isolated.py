"""Isolated F-P2 reproduction client: clamd INSTREAM under temp-dir exhaustion.

fp2-isolated.py ADDR PORT TMPDIR OUT_JSONL VARIANT CYCLES BURST CONCURRENCY HEADROOMS

No Culvert involved: one TCP connection per scan, framing written by hand
(zINSTREAM\\0, ONE 4-byte big-endian length + body, zero terminator), every
conversation recorded with the sha256 of the COMPLETE byte stream sent, the
verbatim reply, the timing, and the free bytes of clamd's temp filesystem
just before and after. TMPDIR is the host path of the loop filesystem that
is bind-mounted over the container's /tmp (clamd's TemporaryDirectory), so
filling it exhausts clamd's spool and nothing else.

Each cycle: release the fill, fill TMPDIR to HEADROOM free bytes, then send
BURST EICAR and BURST clean bodies, alternating (CONCURRENCY workers; 1 is
strictly serial). EICAR bodies are the 68-byte test string plus 56 bytes of
unique space/tab padding (the shape the appliance lab sends, 142 bytes on
the wire); clean bodies are 47 bytes. Bodies are fresh per request so no
result can be a reply to an earlier body.
"""
import concurrent.futures as cf
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
assert len(EICAR) == 68

addr, port, tmpdir, out, variant = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
cycles, burst, conc = int(sys.argv[6]), int(sys.argv[7]), int(sys.argv[8])
headrooms = [int(x) for x in sys.argv[9].split(",")]
lock = threading.Lock()
seq = [0]
fh = open(out, "a")


def free():
    st = os.statvfs(tmpdir)
    return st.f_bavail * st.f_frsize


def body(eicar, n):
    h = int.from_bytes(hashlib.sha256(f"{variant}-{n}".encode()).digest()[:8], "big")
    if eicar:
        return EICAR + "".join(" \t"[(h >> i) & 1] for i in range(56)).encode()
    return (f"culvert fp2 isolated clean {h:016x}".ljust(46, ".") + "\n").encode()


def scan(eicar, cycle, tag):
    with lock:
        seq[0] += 1
        n = seq[0]
    b = body(eicar, n)
    wire = b"zINSTREAM\0" + struct.pack(">I", len(b)) + b + struct.pack(">I", 0)
    f0 = free()
    t0 = time.time()
    reply, err = b"", ""
    try:
        s = socket.create_connection((addr, port), timeout=30)
        s.sendall(wire)
        while True:
            c = s.recv(4096)
            if not c:
                break
            reply += c
        s.close()
    except OSError as e:
        err = f"{type(e).__name__}: {e}"
    t1 = time.time()
    rec = {"variant": variant, "seq": n, "cycle": cycle, "tag": tag, "eicar": eicar,
           "t0": round(t0, 6), "dur_ms": round((t1 - t0) * 1000, 2),
           "wire_bytes": len(wire), "wire_sha256": hashlib.sha256(wire).hexdigest(),
           "body_sha256": hashlib.sha256(b).hexdigest(),
           "reply": reply.decode("latin-1"), "client_error": err,
           "tmp_free_before": f0, "tmp_free_after": free()}
    with lock:
        fh.write(json.dumps(rec) + "\n")
        fh.flush()
    return rec


def fill(headroom):
    p = os.path.join(tmpdir, "zz-fill")
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass
    os.sync()
    fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o600)
    off = max(free() - headroom - (4 << 20), 0)
    try:
        os.posix_fallocate(fd, 0, off) if off else None
    except OSError:
        off = os.fstat(fd).st_size
    for step in (1 << 20, 1 << 16, 4096):
        while free() > headroom:
            try:
                os.posix_fallocate(fd, off, step)
                off += step
            except OSError:
                break
    os.close(fd)
    return free()


def release():
    try:
        os.unlink(os.path.join(tmpdir, "zz-fill"))
    except FileNotFoundError:
        pass
    os.sync()


for c in range(1, cycles + 1):
    h = headrooms[(c - 1) % len(headrooms)]
    release()
    got = fill(h) if h >= 0 else free()
    fh.write(json.dumps({"variant": variant, "cycle": c, "event": "filled", "headroom_target": h,
                         "tmp_free": got, "t": round(time.time(), 6)}) + "\n")
    fh.flush()
    jobs = [(i % 2 == 0, c, f"c{c}-h{h}") for i in range(2 * burst)]
    if conc <= 1:
        for j in jobs:
            scan(*j)
    else:
        with cf.ThreadPoolExecutor(conc) as ex:
            list(ex.map(lambda j: scan(*j), jobs))
release()
fh.close()
