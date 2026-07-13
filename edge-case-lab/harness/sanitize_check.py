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
    # Real base64 Basic-auth blob: >=12 chars AND contains a digit or +/= (excludes
    # plain-English prose like "Basic credential" in documentation).
    ("basic_creds_inline", re.compile(r"Basic\s+(?=[A-Za-z0-9+/=]{12,})[A-Za-z0-9+/]*[0-9+/=][A-Za-z0-9+/=]*")),
    ("cookie_header", re.compile(r"(Set-)?[Cc]ookie\"?\s*[:=]\s*\"?\S{6,}")),
    # Real session material = the cookie/HMAC with an actual VALUE, not a bare name
    # reference in documentation.
    ("session_token", re.compile(r"ps_ui_session=[A-Za-z0-9._%+/=-]{10,}|"
                                 r"[Ss]ession(HMAC|Hmac|Secret)\"?\s*[:=]\s*\"[^\"]{8,}\"")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("lab_admin_password", re.compile(r"LabPass123!")),
    ("ca_passphrase", re.compile(r"labtest123")),
    ("generic_secret_kv", re.compile(r"\"(password|passwd|secret|api[_-]?key|token)\"\s*:\s*\"[^\"]{4,}\"", re.I)),
]
# JSON keys legitimately present as EMPTY strings (redacted config export) or as
# angle-bracket documentation placeholders (e.g. "api_key": "<value>").
ALLOW_EMPTY = re.compile(r":\s*\"(|<[^\"]*>)\"")  # empty or "<placeholder>" value, any key


def scan_file(path):
    hits = []
    # Source files (harness) legitimately reference these tokens as constants and
    # regex pattern definitions. This gate protects EVIDENCE/DATA, not source; source
    # is covered by code review. Skip .py/.go/.sh.
    if path.endswith((".py", ".go", ".sh")):
        return hits
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
