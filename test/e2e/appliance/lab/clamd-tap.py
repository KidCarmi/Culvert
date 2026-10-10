#!/usr/bin/env python3
"""clamd-tap.py IFACE OUT.jsonl — record every clamd (TCP 3310) conversation.

Lab-only (F-P2 attribution, #1528). Runs as root inside the disposable guest,
bound with AF_PACKET to the HOST side of the ClamAV container's veth, so each
frame is seen exactly once. Writes to tmpfs (the caller passes a /run path),
so it keeps recording while the root filesystem is full.

One JSON line per connection, written when clamd closes it (FIN or RST from
port 3310) or the client resets it:
  t        guest epoch seconds of the close
  cmd      first bytes Culvert sent (zINSTREAM / zPING / zVERSION)
  up       payload bytes Culvert sent (INSTREAM framing included)
  eicar    whether Culvert's bytes contained the EICAR test string
  reply    clamd's reply, verbatim (NULs kept as \\u0000), first 512 bytes
  close    which side closed and how
No configuration of the appliance changes; nothing is sent.
"""
import json
import socket
import struct
import sys
import time

iface, out_path = sys.argv[1], sys.argv[2]
out = open(out_path, "a", buffering=1)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind((iface, 0))
conns = {}
EICAR = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
while True:
    pkt, addr = s.recvfrom(65535)
    if iface == "lo" and addr[2] == socket.PACKET_OUTGOING:
        continue  # loopback shows every frame twice; a veth shows it once
    if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
        continue
    ip = pkt[14:]
    ihl = (ip[0] & 15) * 4
    if ip[9] != 6:
        continue
    tot = struct.unpack("!H", ip[2:4])[0]
    tcp = ip[ihl:tot]
    sp, dp = struct.unpack("!HH", tcp[:4])
    if 3310 not in (sp, dp):
        continue
    flags = tcp[13]
    pl = tcp[(tcp[12] >> 4) * 4:]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    key = (src, sp) if dp == 3310 else (dst, dp)
    if flags & 0x02 and not flags & 0x10:  # SYN from the client: a new conversation
        conns[key] = {"t0": time.time(), "cmd": b"", "up": 0, "eicar": False, "tail": b"", "reply": b""}
    c = conns.get(key)
    if c is None:
        continue
    if dp == 3310:
        if len(c["cmd"]) < 12:
            c["cmd"] += pl[: 12 - len(c["cmd"])]
        c["up"] += len(pl)
        if EICAR in c["tail"] + pl:
            c["eicar"] = True
        c["tail"] = (c["tail"] + pl)[-40:]
    elif len(c["reply"]) < 512:
        c["reply"] += pl[: 512 - len(c["reply"])]
    closing = (sp == 3310 and flags & 0x05) or (dp == 3310 and flags & 0x04)
    if closing:
        rec = {"t": round(time.time(), 3), "dur": round(time.time() - c["t0"], 3),
               "cmd": c["cmd"].split(b"\x00")[0].decode("latin-1"), "up": c["up"], "eicar": c["eicar"],
               "reply": c["reply"].decode("latin-1"),
               "close": ("clamd-" if sp == 3310 else "client-") + ("rst" if flags & 0x04 else "fin")}
        out.write(json.dumps(rec) + "\n")
        del conns[key]
