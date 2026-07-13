#!/usr/bin/env python3
"""
R6: sanitization guard. Scans a directory tree for secrets that must never be
committed to git or uploaded as CI artifacts: Authorization headers, cookies,
session tokens, private keys, and the lab's own credentials/passphrases.

Exit 0 = clean; exit 1 = secrets found (prints locations, redacted).
Use as a pre-commit / pre-upload gate:
    python3 sanitize_check.py edge-case-lab/scenarios edge-case-lab/representative_evidence
"""
import os
import re
import sys

PATTERNS = [
    ("authorization_header", re.compile(r"[Aa]uthorization\"?\s*[:=]\s*\"?(Basic|Bearer)\s+\S+")),
    ("basic_creds_inline", re.compile(r"Basic\s+[A-Za-z0-9+/=]{8,}")),
    ("cookie_header", re.compile(r"(Set-)?[Cc]ookie\"?\s*[:=]")),
    ("session_token", re.compile(r"ps_ui_session|sessionHmac|SessionHMAC")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("lab_admin_password", re.compile(r"LabPass123!")),
    ("ca_passphrase", re.compile(r"labtest123")),
    ("generic_secret_kv", re.compile(r"\"(password|passwd|secret|api[_-]?key|token)\"\s*:\s*\"[^\"]{4,}\"", re.I)),
]
# JSON keys that are legitimately present as EMPTY strings in redacted config export.
ALLOW_EMPTY = re.compile(r"\"(password|secret|token|clientSecret|SessionHMAC)\"\s*:\s*\"\"")


def scan_file(path):
    hits = []
    try:
        text = open(path, "r", errors="replace").read()
    except OSError:
        return hits
    for name, pat in PATTERNS:
        for m in pat.finditer(text):
            frag = m.group(0)
            if ALLOW_EMPTY.search(frag):
                continue
            # ignore harness SOURCE files that legitimately reference the constants
            if path.endswith(".py") and name in ("lab_admin_password", "ca_passphrase"):
                continue
            hits.append((name, path, frag[:40]))
    return hits


def main():
    roots = sys.argv[1:] or ["."]
    all_hits = []
    for root in roots:
        if os.path.isfile(root):
            all_hits += scan_file(root)
            continue
        for dp, _, fs in os.walk(root):
            for f in fs:
                if f.endswith((".json", ".jsonl", ".log", ".md", ".txt")):
                    all_hits += scan_file(os.path.join(dp, f))
    if all_hits:
        print(f"SANITIZATION FAILED — {len(all_hits)} secret(s) found:")
        for name, path, frag in all_hits[:50]:
            red = re.sub(r"(Basic|Bearer)\s+\S+", r"\1 <REDACTED>", frag)
            red = re.sub(r"LabPass123!|labtest123", "<REDACTED>", red)
            print(f"  [{name}] {path}: {red}")
        sys.exit(1)
    print(f"SANITIZATION OK — scanned {roots}, no secrets found")


if __name__ == "__main__":
    main()
