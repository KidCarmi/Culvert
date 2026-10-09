#!/usr/bin/env python3
"""Bounded passive clamd RESPONSE evidence, never a proxy/clamd relay.

Linux guest only when explicitly started. Packet fragments are evidence, not
reassembled commands or proof that every proxy transaction was captured.
"""
import hashlib
import ipaddress
import json
import os
import socket
import struct
import threading
import time


def response_fragment(frame, sidecar, proxy):
    """Accept IPv4/TCP server replies for only the two inspected containers."""
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], 'big')
    if ip[0] >> 4 != 4 or ihl < 20 or ip[9] != 6 or len(ip) < total or total < ihl + 20:
        return None
    if int.from_bytes(ip[6:8], 'big') & 0x3fff:  # no inference from IP fragments
        return None
    if ip[12:16] != ipaddress.IPv4Address(sidecar).packed or ip[16:20] != ipaddress.IPv4Address(proxy).packed:
        return None
    tcp = ip[ihl:total]
    sport, dport, sequence = struct.unpack('!HHI', tcp[:8])
    offset = (tcp[12] >> 4) * 4
    if sport != 3310 or offset < 20 or offset > len(tcp):
        return None
    payload = tcp[offset:]
    if not payload:
        return None
    return {'source_port': sport, 'destination_port': dport, 'sequence': sequence,
            'tcp_flags': tcp[13], 'payload_bytes': len(payload),
            'payload_sha256': hashlib.sha256(payload).hexdigest(),
            'response_fragment_hex': payload[:512].hex(), 'fragment_truncated': len(payload) > 512}


class ReplyCapture:
    def __init__(self, sidecar, proxy, path, max_bytes=1024 * 1024):
        self.sidecar = str(ipaddress.IPv4Address(sidecar))
        self.proxy = str(ipaddress.IPv4Address(proxy))
        self.path = path
        self.limit = max_bytes
        self.stop_event = threading.Event()
        self.summary = {'available': False, 'fragments': 0, 'packets_examined': 0,
                        'output_limit': False, 'packet_limit': False, 'error': None,
                        'semantics': 'passive response fragments; duplicates, missing packets and missing stream reassembly are possible'}

    def start(self):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.socket.settimeout(0.5)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.output = os.fdopen(fd, 'wb', buffering=0)
        self.summary['available'] = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        written = 0
        try:
            while not self.stop_event.is_set():
                try:
                    frame = self.socket.recv(65535)
                except socket.timeout:
                    continue
                self.summary['packets_examined'] += 1
                if self.summary['packets_examined'] > 100000:
                    self.summary['packet_limit'] = True
                    break
                row = response_fragment(frame, self.sidecar, self.proxy)
                if row is None:
                    continue
                row.update(monotonic_ns=time.monotonic_ns(), realtime_ns=time.time_ns())
                data = (json.dumps(row, sort_keys=True) + '\n').encode()
                if written + len(data) > self.limit:
                    self.summary['output_limit'] = True
                    break
                self.output.write(data)
                written += len(data)
                self.summary['fragments'] += 1
        except Exception:
            self.summary['error'] = 'capture_failed'

    def close(self):
        self.stop_event.set()
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)
        if hasattr(self, 'socket'):
            self.socket.close()
        if hasattr(self, 'output'):
            self.output.close()
        return dict(self.summary)
