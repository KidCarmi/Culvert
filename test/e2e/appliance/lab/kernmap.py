"""Kernel CVE triage on the exact shipped disk.

kernmap.py TRIVY_ROOTFS_JSON ROOTFS ABSENT_REVIEW_TSV OUT_TSV

Every distinct CRITICAL/HIGH CVE reported against the kernel packages gets
one class, decided only from the scanned disk:

  absent   the subsystem is in the reviewed table (kernel-absent-review.tsv)
           AND this disk agrees: CONFIG_<sym> is =m and the build produced the
           module (modules.order), or CONFIG_<sym> is unset; and no .ko for it
           is under /lib/modules. The code is not on the appliance.
  denied   the module is on the disk but /etc/modprobe.d/culvert-unused.conf
           makes it unloadable (install <mod> /bin/false).
  present  everything else, i.e. the kernel image or a loadable module may
           contain the vulnerable code.

The "hint" column is a heuristic location (module/directory whose path best
matches the advisory's subsystem prefix). It is informational only and never
decides "absent".
"""
import collections, glob, json, os, re, sys

src, root, review_f, out = sys.argv[1:5]
kernels = sorted(glob.glob(os.path.join(root, "boot", "vmlinuz-*")))
if len(kernels) != 1:
    sys.exit(f"expected exactly one kernel in /boot, found {kernels}")
kver = os.path.basename(kernels[0])[len("vmlinuz-"):]
kdir = os.path.join(root, "lib", "modules", kver)
config = {}
for line in open(os.path.join(root, "boot", "config-" + kver)):
    m = re.match(r"CONFIG_([A-Za-z0-9_]+)=(.*)", line)
    if m:
        config[m.group(1)] = m.group(2)
norm = lambda t: t.lower().replace("-", "_")
rel = lambda p: p.strip().replace(".ko.zst", ".ko").replace(".ko.xz", ".ko")
order = {rel(l) for l in open(os.path.join(kdir, "modules.order")) if l.strip()}
builtin = {rel(l) for l in open(os.path.join(kdir, "modules.builtin")) if l.strip()}
ondisk = set()
for d, _, files in os.walk(os.path.join(kdir, "kernel")):
    for f in files:
        if ".ko" in f:
            ondisk.add(rel(os.path.relpath(os.path.join(d, f), kdir)))
stem = lambda p: norm(os.path.basename(p)[:-3])
ondisk_stems = {stem(p) for p in ondisk}
order_stems = {stem(p) for p in order}
denied = set()
deny_f = os.path.join(root, "etc", "modprobe.d", "culvert-unused.conf")
if os.path.exists(deny_f):
    for line in open(deny_f):
        m = re.match(r"\s*install\s+(\S+)\s+/bin/false\s*$", line)
        if m:
            denied.add(norm(m.group(1)))
review = []
for line in open(review_f):
    if line.startswith("#") or not line.strip():
        continue
    rx, sym, mod = line.rstrip("\n").split("\t")
    val = config.get(sym, "unset")
    ok = norm(mod) not in ondisk_stems and (val == "unset" or (val == "m" and norm(mod) in order_stems))
    review.append((re.compile(rx), sym, mod, val, ok))
DENY_MAP = [(r"^sctp\b", "sctp"), (r"^NFSD\b|^nfsd\b", "nfsd"), (r"^KVM\b", "kvm"), (r"^tipc\b", "tipc"),
            (r"^dccp\b", "dccp"), (r"^ksmbd\b|^smb: server\b", "ksmbd"), (r"^smb: client\b|^cifs\b", "cifs"),
            (r"^can\b", "can"), (r"^pppoe\b", "pppoe"), (r"^RDMA$|^RDMA/(core|nldev|cma|uverbs|umad)\b", "ib_core")]
GENERIC = {"core", "main", "common", "api", "base", "ops", "sys", "dev", "lib", "util", "utils",
           "debug", "fix", "net", "fs", "mm", "block", "driver", "drivers"}
pcomps = {}
for p in order | builtin | ondisk:
    parts = [norm(x) for x in p.split("/")]
    s = parts[-1][:-3] if parts[-1].endswith(".ko") else parts[-1]
    pcomps[p] = (set(parts[:-1]) | {s}, set(s.split("_")) - set(parts[:-1]) - {s})
def hint(label):
    words = {norm(t) for t in re.split(r"[/\s,:]+", label) if t}
    toks = (words | {x for w in words for x in w.split("_")}) - GENERIC
    best, hits = (0, 0), set()
    for p, (strong, weak) in pcomps.items():
        sc = (len(toks & strong), len(toks & weak))
        if sc > best:
            best, hits = sc, {p}
        elif sc == best and sc != (0, 0):
            hits.add(p)
    if best == (0, 0):
        return "-"
    on = hits & ondisk
    pick = sorted(on or hits & builtin or hits)[0]
    where = "on-disk" if on else ("built-in" if hits & builtin else "not-on-disk")
    return f"{where}:{pick}" + ("" if len(hits) == 1 else f"(+{len(hits) - 1})")
seen = {}
d = json.load(open(src))
for r in d.get("Results") or []:
    for v in r.get("Vulnerabilities") or []:
        if not v.get("PkgName", "").startswith("linux-") or v["Severity"] not in ("CRITICAL", "HIGH"):
            continue
        vid = v["VulnerabilityID"]
        if vid in seen:
            continue
        desc = (v.get("Description") or "").replace("\n", " ")
        i = desc.find("resolved:")
        head = desc[i + 9:].strip() if i >= 0 else desc
        m = re.match(r"((?:[A-Za-z0-9_./ -]{1,40}:\s*){1,3})", head)
        label = m.group(1).strip().rstrip(":") if m else "-"
        cls, why = "present", ""
        for rx, sym, mod, val, ok in review:
            if label != "-" and rx.search(label):
                if ok:
                    cls, why = "absent", f"CONFIG_{sym}={val}; {mod}.ko not on disk"
                else:
                    why = f"review entry {rx.pattern} does NOT hold on this disk (CONFIG_{sym}={val})"
                break
        if cls == "present":
            for rx, mod in DENY_MAP:
                if re.search(rx, label) and norm(mod) in denied:
                    cls, why = "denied", f"{mod}: install /bin/false in culvert-unused.conf"
                    break
        seen[vid] = (v["Severity"], label, cls, why, hint(label) if label != "-" else "-")
with open(out, "w") as o:
    o.write(f"# kernel {kver}\nid\tseverity\tsubsystem\tclass\tevidence\thint\n")
    for vid in sorted(seen, key=lambda k: (seen[k][0] != "CRITICAL", seen[k][2], seen[k][1], k)):
        o.write("\t".join((vid,) + seen[vid]) + "\n")
c = collections.Counter((s[0], s[2]) for s in seen.values())
print(f"kernel {kver}: " + ", ".join(f"{k[0]} {k[1]} {c[k]}" for k in sorted(c)))
broken = [x for x in review if not x[4]]
if broken:
    print("REVIEW ENTRIES NOT HOLDING ON THIS DISK: " + ", ".join(x[2] for x in broken))
