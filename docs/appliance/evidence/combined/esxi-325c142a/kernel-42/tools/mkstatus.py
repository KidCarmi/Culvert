import sys, glob, re
inv = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
want = {(n, v, a) for n, v, a in inv}
holds = {"docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"}
stanzas = {}
for f in sorted(glob.glob(sys.argv[2] + "/*.Packages")):
    for st in open(f, encoding="utf-8").read().split("\n\n"):
        m = re.search(r"^Package: (.+)$", st, re.M); v = re.search(r"^Version: (.+)$", st, re.M); a = re.search(r"^Architecture: (.+)$", st, re.M)
        if m and v and a and (m.group(1), v.group(1), a.group(1)) in want:
            stanzas.setdefault((m.group(1), v.group(1), a.group(1)), st)
out, missing = [], []
for n, v, a in inv:
    st = stanzas.get((n, v, a))
    if st is None:
        if n in holds:
            st = "Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Docker\nDescription: held docker package" % (n, v, a)
        else:
            missing.append((n, v, a)); continue
    keep = [l for l in st.split("\n") if not re.match(r"^(Filename|Size|MD5sum|SHA1|SHA256|SHA512|Description-md5|Task|Supported|Phased-Update-Percentage|Origin|Bugs):", l)]
    status = "hold ok installed" if n in holds else "install ok installed"
    keep.insert(1, "Status: " + status)
    out.append("\n".join(keep))
open(sys.argv[3], "w").write("\n\n".join(out) + "\n")
print("installed=%d written=%d missing=%d" % (len(inv), len(out), len(missing)))
for m in missing: print("MISSING", *m)
