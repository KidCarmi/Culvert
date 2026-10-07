#!/usr/bin/env python3
"""Record the guest's VGA screen through boot transitions. Stdlib only.

  vga-capture.py --mon SOCK --out DIR --stop FILE [--interval 0.5] [--cmds FILE]

Every INTERVAL seconds: `screendump` over the QEMU monitor; a frame whose pixels
differ from the previous one is kept as DIR/NNNNN_T.png and listed in
DIR/frames.tsv (index, seconds since start, wall clock, WxH, pixel sha256
prefix). Lines appended to --cmds (e.g. `sendkey esc`, or `mark first-boot
complete`) are executed in order between frames and logged to DIR/events.tsv
with the same clock, so a frame and an action can be put side by side.
Exits when --stop exists or the monitor goes away (VM powered off — a reboot
keeps the same QEMU process and monitor).
"""
import argparse
import hashlib
import os
import socket
import struct
import sys
import time
import zlib


def png(ppm, dst):
    with open(ppm, "rb") as f:
        d = f.read()
    p = d.split(b"\n", 3)
    w, h = map(int, p[1].split())
    px = p[3][: w * h * 3]
    raw = b"".join(b"\x00" + px[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def c(t, b):
        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF)

    with open(dst, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + c(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + c(b"IDAT", zlib.compress(raw, 6)) + c(b"IEND", b""))
    return w, h, hashlib.sha256(px).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mon", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--stop", required=True)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--cmds")
    a = ap.parse_args()
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    s = socket.socket(socket.AF_UNIX)
    for _ in range(300):
        try:
            s.connect(a.mon)
            break
        except OSError:
            time.sleep(0.1)
    else:
        sys.exit("monitor unavailable")
    s.settimeout(0.2)

    def drain():
        try:
            while s.recv(65536):
                pass
        except (socket.timeout, BlockingIOError):
            pass

    drain()
    t0 = time.time()
    frames = open(os.path.join(out, "frames.tsv"), "a", buffering=1)
    events = open(os.path.join(out, "events.tsv"), "a", buffering=1)
    ppm = os.path.join(out, ".cur.ppm")
    done_cmds, last, n = 0, None, 0
    while not os.path.exists(a.stop):
        tick = time.time()
        if a.cmds and os.path.exists(a.cmds):
            with open(a.cmds) as f:
                lines = f.read().splitlines()
            for line in lines[done_cmds:]:
                t = time.time() - t0
                if line.startswith("mark "):
                    events.write(f"{t:.2f}\t{time.strftime('%H:%M:%S')}\t{line[5:]}\n")
                    continue
                try:
                    s.sendall((line + "\n").encode())
                    drain()
                    events.write(f"{t:.2f}\t{time.strftime('%H:%M:%S')}\tmonitor: {line}\n")
                except OSError as e:
                    events.write(f"{t:.2f}\t{time.strftime('%H:%M:%S')}\tmonitor failed ({e}): {line}\n")
            done_cmds = len(lines)
        try:
            if os.path.exists(ppm):
                os.remove(ppm)
            s.sendall(f"screendump {ppm}\n".encode())
            for _ in range(40):
                drain()
                if os.path.exists(ppm) and os.path.getsize(ppm) > 32:
                    break
            t = tick - t0
            dst = os.path.join(out, f"{n:05d}_{t:08.2f}.png")
            w, h, digest = png(ppm, dst)
            if digest == last:
                os.remove(dst)
            else:
                frames.write(f"{n}\t{t:.2f}\t{time.strftime('%H:%M:%S')}\t{w}x{h}\t{digest[:16]}\n")
                n, last = n + 1, digest
        except (BrokenPipeError, ConnectionResetError):
            break
        except Exception as e:  # a frame taken mid-mode-switch can be short; keep going
            events.write(f"{time.time() - t0:.2f}\t{time.strftime('%H:%M:%S')}\tcapture error: {e}\n")
        time.sleep(max(0.0, a.interval - (time.time() - tick)))
    events.write(f"{time.time() - t0:.2f}\t{time.strftime('%H:%M:%S')}\tcapture stopped ({n} distinct frames)\n")


if __name__ == "__main__":
    main()
