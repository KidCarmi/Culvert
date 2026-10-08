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
#                         (+ linked functions per vulnerable package when
#                          PCLNFUNCS points at the built pclnfuncs tool)
#   exact-scan.sh table   EVIDENCE_DIR                 findings.tsv + counts
#   exact-scan.sh engsrc  EVIDENCE_DIR NAME=PATH...    govulncheck SOURCE mode on the
#                         exact upstream revision each third-party binary records
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
    # Linked-function count per vulnerable package, read from this binary's
    # pclntab: binary mode cannot tell a wildcard OSV symbol ("pkg/*") from a
    # linked one, so the table reports what is actually in the bytes.
    if [[ -n "${PCLNFUNCS:-}" ]]; then
      local pkgs; pkgs="$(osv_pkgs "$ev/govulncheck/$name.json")"
      # shellcheck disable=SC2086 # one argument per package path
      [[ -z "$pkgs" ]] || "$PCLNFUNCS" "$path" $pkgs > "$ev/govulncheck/$name.pcln.tsv" 2>&1 || true
    fi
    echo "$name rc=$rc" >> "$ev/govulncheck/exit-codes.txt"
  done
}

# engsrc EVIDENCE NAME=PATH... — reachability for third-party binaries.
# Binary mode only proves a vulnerable function is LINKED. For each binary this
# reads its build info (main package, module version or VCS revision, build
# tags), fetches that exact source from the Go module proxy, REFUSES unless the
# proxy's commit equals the binary's vcs.revision, and runs govulncheck in
# source mode with the same tags, so "called" means a call path from main.
cmd_engsrc() {
  local ev="$1"; shift; mkdir -p "$ev/engsrc"
  local work spec name path bi main mod ver rev tags dir got rc
  work="$(mktemp -d)"
  : > "$ev/engsrc/index.tsv"
  for spec in "$@"; do
    name="${spec%%=*}"; path="${spec#*=}"
    bi="$(go version -m "$path")"
    main="$(awk '$1=="path"{print $2; exit}' <<<"$bi")"
    mod="$(awk '$1=="mod"{print $2; exit}' <<<"$bi")"; ver="$(awk '$1=="mod"{print $3; exit}' <<<"$bi")"
    rev="$(sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.revision=//p' <<<"$bi" | head -1)"
    tags="$(sed -n 's/^[[:space:]]*build[[:space:]]*-tags=//p' <<<"$bi" | head -1)"
    if [[ -z "$ver" || "$ver" == "(devel)" ]]; then
      local short; short="$(sed -n 's/.*GitCommit=\([0-9a-f]\{7,40\}\).*/\1/p' <<<"$bi" | head -1)"
      ver="${rev:-$short}"
    fi
    got="$(cd "$work" && GOFLAGS=-mod=mod go mod download -json "$mod@$ver" 2>&1)" || { printf '%s\t%s@%s\tdownload-failed\n' "$name" "$mod" "$ver" >> "$ev/engsrc/index.tsv"; continue; }
    dir="$(python3 -I -c 'import json,sys;print(json.load(sys.stdin)["Dir"])' <<<"$got")"
    local hash; hash="$(python3 -I -c 'import json,sys;print((json.load(sys.stdin).get("Origin") or {}).get("Hash",""))' <<<"$got")"
    if [[ -n "$rev" && "$hash" != "$rev"* && "$rev" != "$hash"* ]] || [[ -z "$hash" ]]; then
      printf '%s\t%s@%s\trevision-mismatch binary=%s proxy=%s\n' "$name" "$mod" "$ver" "${rev:-?}" "${hash:-?}" >> "$ev/engsrc/index.tsv"; continue
    fi
    rm -rf "$work/src"; cp -r "$dir" "$work/src"; chmod -R u+w "$work/src"
    local pkg="./${main#"$mod"/}"; [[ "$main" == "$mod" ]] && pkg=.
    rc=0
    (cd "$work/src" && GOFLAGS=-mod=mod CGO_ENABLED=1 govulncheck ${tags:+-tags "$tags"} -format json "$pkg") > "$ev/engsrc/$name.json" 2> "$ev/engsrc/$name.stderr" || rc=$?
    printf '%s\t%s@%s\tcommit=%s tags=%s rc=%s\n' "$name" "$mod" "$ver" "$hash" "${tags:--}" "$rc" >> "$ev/engsrc/index.tsv"
  done
  rm -rf "$work"
}

osv_pkgs() { # every package path an OSV entry in a govulncheck JSON stream names
  python3 -I - "$1" <<'PY2'
import json, sys
t, p, dec, out = open(sys.argv[1]).read(), 0, json.JSONDecoder(), set()
while True:
    while p < len(t) and t[p].isspace():
        p += 1
    if p >= len(t):
        break
    m, p = dec.raw_decode(t, p)
    for a in (m.get("osv") or {}).get("affected") or []:
        for i in (a.get("ecosystem_specific") or {}).get("imports") or []:
            if i.get("path"):
                out.add(i["path"] + ".")
print(" ".join(sorted(out)))
PY2
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
            fn = tr[0].get("function") or ""
            level = "symbol" if fn and "*" not in fn else ("package" if tr[0].get("package") else "module")
            found[fd["osv"]].add((level, tr[0].get("module", ""), tr[0].get("version", ""), fd.get("fixed_version", "") or "-"))
    pcln = {}
    pf = os.path.join(ev, "govulncheck", name + ".pcln.tsv")
    if os.path.exists(pf):
        for ln in open(pf):
            parts = ln.rstrip("\n").split("\t")
            if len(parts) == 3 and parts[1].isdigit():
                pcln[parts[0]] = int(parts[1])
    for vid, levels in found.items():
        paths = sorted({i["path"] + "." for a in (osv.get(vid, {}).get("affected") or [])
                        for i in (a.get("ecosystem_specific") or {}).get("imports") or [] if i.get("path")})
        linked = "?" if not pcln else str(sum(pcln.get(x, 0) for x in paths))
        for level, mod, ver, fixed in sorted(levels):
            rows.append(("govulncheck:" + name, name, "gobinary-" + level, mod, ver, fixed, "-", level + "/linked=" + linked, vid))
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
  engsrc) shift; cmd_engsrc "$@" ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
