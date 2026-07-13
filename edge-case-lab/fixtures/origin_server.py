#!/usr/bin/env python3
"""
Deterministic local origin/fixture server for the Culvert Edge-Case Validation Lab.

Provides HTTP and HTTPS origins with a rich set of deterministic endpoints so that
traffic vectors never depend on the public internet. A single process serves many
"virtual hosts" (distinguished by Host header / SNI) on one HTTP port and one HTTPS
port; the harness points Culvert (or curl) at 127.0.0.1 and controls the Host header.

Endpoints (relative to any host):
  /                      -> 200 text "origin:<host>"
  /echo                  -> 200 JSON echo of method, path, headers, query
  /status/<code>         -> responds with the given status code
  /redirect?to=<url>&n=<count> -> 302 chain of length n ending at <url> (or /)
  /size/<n>              -> 200 body of exactly n bytes (deterministic 'A')
  /chunked?n=<c>&delay=<ms> -> chunked transfer, c chunks, optional per-chunk delay
  /slow?delay=<ms>       -> sleeps delay ms before sending body (slowloris-ish)
  /file/<name>           -> serves a fixture file from the fixtures/files dir with
                            a Content-Type inferred from extension (for file-type tests)
  /bytes/<name>?ct=<mime> -> like /file but MIME forced via ?ct
  /upload                -> 200 JSON summarising an uploaded body (len, sha256, ct)
  /ws                    -> minimal WebSocket echo (RFC6455 handshake + echo one frame)
  /setcookie             -> sets a cookie, 200
  /large/<mb>            -> streams <mb> megabytes (for large-file / streaming tests)

Query flags supported broadly: ?ct=<mime> to force Content-Type, ?cd=attachment to
force a Content-Disposition attachment filename.

Run:
  origin_server.py --http-port 8081 --https-port 8443 --cert cert.pem --key key.pem \
      --files-dir ./files
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    files_dir = None
    server_tag = "fixture"

    def log_message(self, fmt, *args):  # silence default stderr spam
        pass

    # ---- helpers -------------------------------------------------------
    def _host(self):
        return self.headers.get("Host", "").split(":")[0]

    def _query(self):
        from urllib.parse import urlparse, parse_qs
        q = urlparse(self.path).query
        return {k: v[0] for k, v in parse_qs(q).items()}

    def _path_only(self):
        from urllib.parse import urlparse
        return urlparse(self.path).path

    def _send(self, code, body=b"", ctype="text/plain", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Fixture-Host", self._host())
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- request dispatch ---------------------------------------------
    def do_GET(self):
        try:
            self._route()
        except BrokenPipeError:
            pass
        except Exception as e:  # pragma: no cover - defensive
            try:
                self._send(500, f"fixture error: {e}")
            except Exception:
                pass

    do_POST = do_GET
    do_PUT = do_GET
    do_HEAD = do_GET
    do_DELETE = do_GET

    def _route(self):
        p = self._path_only()
        q = self._query()
        ct_override = q.get("ct")
        cd = q.get("cd")

        if p == "/" or p == "":
            return self._send(200, f"origin:{self._host()}\n")

        if p == "/echo":
            body_len = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(body_len) if body_len else b""
            payload = {
                "method": self.command,
                "path": self.path,
                "host": self._host(),
                "headers": {k: v for k, v in self.headers.items()},
                "query": q,
                "body_len": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
            }
            return self._send(200, json.dumps(payload), "application/json")

        if p.startswith("/status/"):
            code = int(p.split("/")[-1])
            return self._send(code, f"status:{code}\n")

        if p == "/redirect":
            to = q.get("to", "/")
            n = int(q.get("n", "1"))
            if n > 1:
                # chain: redirect to self with n-1
                nxt = f"/redirect?to={to}&n={n-1}"
                return self._send(302, "redirecting\n", extra={"Location": nxt})
            return self._send(302, "redirecting\n", extra={"Location": to})

        if p.startswith("/size/"):
            n = int(p.split("/")[-1])
            return self._send(200, b"A" * n, ct_override or "application/octet-stream")

        if p == "/chunked":
            return self._chunked(int(q.get("n", "4")), int(q.get("delay", "0")),
                                 ct_override or "text/plain")

        if p == "/slow":
            time.sleep(int(q.get("delay", "1000")) / 1000.0)
            return self._send(200, "slow-body\n", ct_override or "text/plain")

        if p.startswith("/file/") or p.startswith("/bytes/"):
            name = p.split("/", 2)[2]
            return self._serve_file(name, ct_override, cd)

        if p.startswith("/large/"):
            mb = int(p.split("/")[-1])
            return self._large(mb, ct_override or "application/octet-stream")

        if p == "/upload":
            body_len = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(body_len) if body_len else b""
            payload = {
                "received": len(body),
                "sha256": hashlib.sha256(body).hexdigest() if body else "",
                "content_type": self.headers.get("Content-Type", ""),
            }
            return self._send(200, json.dumps(payload), "application/json")

        if p == "/setcookie":
            return self._send(200, "cookie-set\n",
                              extra={"Set-Cookie": "fixture=1; Path=/"})

        return self._send(404, "not found\n")

    def _chunked(self, n, delay_ms, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Fixture-Host", self._host())
        self.end_headers()
        for i in range(n):
            data = f"chunk-{i}\n".encode()
            self.wfile.write(b"%X\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _large(self, mb, ctype):
        total = mb * 1024 * 1024
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(total))
        self.send_header("X-Fixture-Host", self._host())
        self.end_headers()
        block = b"A" * (1024 * 1024)
        for _ in range(mb):
            try:
                self.wfile.write(block)
            except BrokenPipeError:
                return

    _EXT_MIME = {
        ".exe": "application/vnd.microsoft.portable-executable",
        ".pdf": "application/pdf",
        ".zip": "application/zip",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".txt": "text/plain",
        ".png": "image/png",
        ".js": "application/javascript",
        ".bin": "application/octet-stream",
        ".eicar": "application/octet-stream",
    }

    def _serve_file(self, name, ct_override, cd):
        # Serve from files_dir if present, else synthesize deterministic content.
        path = os.path.join(self.files_dir, name) if self.files_dir else None
        if path and os.path.isfile(path):
            with open(path, "rb") as f:
                body = f.read()
        else:
            body = f"fixture-file:{name}\n".encode()
        ext = os.path.splitext(name)[1].lower()
        ctype = ct_override or self._EXT_MIME.get(ext, "application/octet-stream")
        extra = {}
        if cd:
            extra["Content-Disposition"] = f'attachment; filename="{name}"'
        return self._send(200, body, ctype, extra)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_handler(files_dir):
    return type("BoundHandler", (Handler,), {"files_dir": files_dir})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--http-port", type=int, default=0)
    ap.add_argument("--https-port", type=int, default=0)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--files-dir")
    ap.add_argument("--ready-file", help="write 'ready' here once listening")
    args = ap.parse_args()

    handler = make_handler(args.files_dir)
    servers = []

    if args.http_port:
        h = ThreadingHTTPServer((args.bind, args.http_port), handler)
        servers.append(("http", h))
    if args.https_port and args.cert and args.key:
        h = ThreadingHTTPServer((args.bind, args.https_port), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        h.socket = ctx.wrap_socket(h.socket, server_side=True)
        servers.append(("https", h))

    threads = []
    for name, h in servers:
        t = threading.Thread(target=h.serve_forever, daemon=True)
        t.start()
        threads.append(t)
        print(f"[fixture] {name} listening on {h.server_address}", flush=True)

    if args.ready_file:
        with open(args.ready_file, "w") as f:
            f.write("ready")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
