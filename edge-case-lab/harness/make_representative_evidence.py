#!/usr/bin/env python3
"""
Assemble a small, sanitized set of confirmed-finding + representative-PASS manifests
into edge-case-lab/representative_evidence/ (committed), so the branch keeps proof of
each finding without the full raw evidence tree. Runs sanitize_check afterwards.
"""
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import harness as H

SRC = os.path.join(H.LAB, "scenarios")
DST = os.path.join(H.LAB, "representative_evidence")
# one representative per finding class + a clean PASS exemplar
KEEP = ["SWG-0210",  # SECURITY_BYPASS (SOCKS5)
        "SWG-0166",  # CONFIG_CONTRACT_GAP (priority-0 coercion)
        "SWG-0069",  # CONFIG_CONTRACT_GAP (permissive)
        "SWG-0215",  # EXPECTED_LIMITATION (external redirect)
        "SWG-0124",  # PASS (durable persistence + restart enforcement)
        "SWG-0007",  # PASS (first-match precedence)
        "SWG-0010"]  # PASS (TLS inspect/bypass MITM proof)


def main():
    os.makedirs(DST, exist_ok=True)
    kept = []
    for sid in KEEP:
        p = os.path.join(SRC, f"{sid}.json")
        if os.path.isfile(p):
            shutil.copy(p, os.path.join(DST, f"{sid}.json"))
            kept.append(sid)
    # README index
    idx = ["# Representative Evidence (sanitized)\n",
           "A small committed subset of confirmed-finding and representative-PASS scenario",
           "manifests. Full raw evidence is a CI artifact (see EDGE-CASE-EVIDENCE-RETENTION.md).\n"]
    for sid in kept:
        m = json.load(open(os.path.join(DST, f"{sid}.json")))
        idx.append(f"- **{sid}** [{m['result_classification']}] — {m['title']}")
    open(os.path.join(DST, "README.md"), "w").write("\n".join(idx) + "\n")
    print("kept:", kept)
    # sanitize
    rc = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "sanitize_check.py"), DST]).returncode
    if rc != 0:
        print("SANITIZATION FAILED — not committing representative evidence"); sys.exit(1)


if __name__ == "__main__":
    main()
