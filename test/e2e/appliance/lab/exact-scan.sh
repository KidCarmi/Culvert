#!/usr/bin/env bash
# test/e2e/appliance/lab/exact-scan.sh — exact-byte vulnerability evidence for
# one candidate: the OVA's guest filesystem (Ubuntu packages, kernel, every
# host binary) and the application image, at EVERY severity, unfixed findings
# included, with NO ignore file — plus govulncheck in BINARY mode on every Go
# binary the candidate ships, and the compiler each was built with.
#
#   exact-scan.sh rootfs  ROOTFS_DIR EVIDENCE_DIR      Trivy rootfs + SBOM
#   exact-scan.sh image   IMAGE_TAR  EVIDENCE_DIR      Trivy image + SBOM
#   exact-scan.sh gobins  EVIDENCE_DIR NAME=PATH...    govulncheck -mode=binary
#   exact-scan.sh table   EVIDENCE_DIR                 findings.tsv + counts
#
# Policy is deliberately NOT applied here: this is the record a reviewer
# dispositions, so nothing is filtered (no --severity, no --ignore-unfixed,
# --ignorefile /dev/null so a repo .trivyignore cannot hide a finding).
set -euo pipefail

trivy_all() { # $1 = trivy subcommand args..., output prefix in $OUTP
  "$TRIVY" "$@" --scanners vuln --ignorefile /dev/null --skip-db-update --format json --output "$OUTP-all.json"
  "$TRIVY" "$@" --ignorefile /dev/null --skip-db-update --format cyclonedx --output "$OUTP-sbom.cdx.json"
}

cmd_rootfs() {
  local root="$1" ev="$2"; mkdir -p "$ev"; OUTP="$ev/rootfs"
  trivy_all rootfs "$root"
  # The package database the scan read, so every finding can be tied to it.
  dpkg-query --admindir="$root/var/lib/dpkg" -W -f '${Package}\t${Version}\t${Architecture}\n' | sort > "$ev/rootfs-dpkg.tsv"
  find "$root/boot" -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' | sort > "$ev/rootfs-kernels.txt"
}

cmd_image() {
  local tar="$1" ev="$2"; mkdir -p "$ev"; OUTP="$ev/image"
  trivy_all image --input "$tar"
}

cmd_gobins() {
  local ev="$1"; shift; mkdir -p "$ev/govulncheck"
  local spec name path
  : > "$ev/go-binaries.tsv"
  for spec in "$@"; do
    name="${spec%%=*}"; path="${spec#*=}"
    if ! go version "$path" > "$ev/govulncheck/$name.version.txt" 2>&1; then
      printf '%s\t%s\tnot-a-go-binary\t-\n' "$name" "$path" >> "$ev/go-binaries.tsv"; continue
    fi
    go version -m "$path" > "$ev/govulncheck/$name.buildinfo.txt" 2>&1 || true
    local rc=0
    govulncheck -mode=binary -format json "$path" > "$ev/govulncheck/$name.json" 2>"$ev/govulncheck/$name.stderr" || rc=$?
    govulncheck -mode=binary -show verbose "$path" > "$ev/govulncheck/$name.txt" 2>&1 || true
    printf '%s\t%s\t%s\t%s\n' "$name" "$path" "$(awk '{print $2}' "$ev/govulncheck/$name.version.txt")" "$(sha256sum "$path" | cut -d' ' -f1)" >> "$ev/go-binaries.tsv"
    echo "$name rc=$rc" >> "$ev/govulncheck/exit-codes.txt"
  done
}

cmd_table() {
  local ev="$1"
  python3 -I - "$ev" <<'PY'
import collections, glob, json, os, sys
ev = sys.argv[1]
rows = []
for f in sorted(glob.glob(os.path.join(ev, "*-all.json"))):
    src = os.path.basename(f)[:-len("-all.json")]
    d = json.load(open(f))
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            rows.append((src, r.get("Target", ""), r.get("Type", ""), v.get("PkgName", ""), v.get("InstalledVersion", ""),
                         v.get("FixedVersion", "") or "-", v.get("Severity", ""), v.get("Status", "") or "-", v.get("VulnerabilityID", "")))
# govulncheck binary findings: symbol-level (called) vs module-level
for f in sorted(glob.glob(os.path.join(ev, "govulncheck", "*.json"))):
    name = os.path.basename(f)[:-5]
    osv, found = {}, collections.defaultdict(set)
    text, pos, dec = open(f).read(), 0, json.JSONDecoder()
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        m, pos = dec.raw_decode(text, pos)  # a stream of JSON objects
        if "osv" in m:
            osv[m["osv"]["id"]] = m["osv"]
        if "finding" in m:
            fd = m["finding"]; tr = fd.get("trace") or [{}]
            level = "symbol" if tr[0].get("function") else ("package" if tr[0].get("package") else "module")
            found[fd["osv"]].add((level, tr[0].get("module", ""), tr[0].get("version", ""), fd.get("fixed_version", "") or "-"))
    for vid, levels in found.items():
        for level, mod, ver, fixed in sorted(levels):
            rows.append(("govulncheck:" + name, name, "gobinary-" + level, mod, ver, fixed, "-", level, vid))
rows.sort()
with open(os.path.join(ev, "findings.tsv"), "w") as o:
    o.write("source\ttarget\ttype\tpackage\tinstalled\tfixed\tseverity\tstatus\tid\n")
    for r in rows:
        o.write("\t".join(r) + "\n")
summ = collections.Counter((r[0], r[6], "fixable" if r[5] != "-" else "no-fix") for r in rows)
with open(os.path.join(ev, "counts.txt"), "w") as o:
    for k in sorted(summ):
        o.write("%-34s %-9s %-8s %d\n" % (k[0], k[1], k[2], summ[k]))
print(open(os.path.join(ev, "counts.txt")).read())
PY
}

TRIVY="${TRIVY:-trivy}"
case "${1:-}" in
  rootfs) cmd_rootfs "${2:?ROOTFS}" "${3:?EVIDENCE}" ;;
  image)  cmd_image "${2:?IMAGE_TAR}" "${3:?EVIDENCE}" ;;
  gobins) shift; cmd_gobins "$@" ;;
  table)  cmd_table "${2:?EVIDENCE}" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
