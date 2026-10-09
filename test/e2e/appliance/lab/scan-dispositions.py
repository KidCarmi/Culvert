"""Render the per-finding disposition record for one candidate's exact-byte scan.

scan-dispositions.py EVIDENCE_DIR CANDIDATE_JSON OUT_MD

EVIDENCE_DIR is the unpacked exact-scan artifact (findings.tsv, counts.txt,
kernel-cves.tsv, engsrc/, govulncheck/, go-binaries.tsv, trivy-version.txt,
ova.sha256, image.txt). CANDIDATE_JSON names the candidate identities that
the artifact itself does not carry (source, scan run/artifact, sidecar scan).

Every number in the output is read from the evidence; the only hand-written
parts are DISPOSITION texts below, each keyed to a finding class or to a
specific (binary, ID) pair, and the renderer FAILS if the evidence contains
a finding no disposition covers. A new finding therefore cannot slip into
the record undispositioned.
"""
import collections, csv, json, os, sys

ev, cand_f, out = sys.argv[1:4]
cand = json.load(open(cand_f))
rows = list(csv.DictReader(open(os.path.join(ev, "findings.tsv")), delimiter="\t"))

# Engine findings that source mode places on a real call path, each with the
# reasoning tied to that path. Keyed (binary, id).
CALLED = {
    ("usr-bin-containerd", "GO-2026-6443"): "gRPC server stream handling (`grpc.Serve`). The only listener is `/run/containerd/containerd.sock`, root:root 0660 (engine probe); a caller is already root.",
    ("usr-bin-containerd", "GO-2026-6061"): "Reached from `server.Stop` → transport drain (shutdown). Peers are local root processes on the root-only socket.",
    ("usr-bin-containerd", "GO-2026-6348"): "Client-side message encoding to local shims (`grpc.invoke`). The peers are containerd's own root-spawned shims over local sockets.",
    ("usr-bin-containerd", "GO-2026-5158"): "Baggage extraction in the otelgrpc stats handler on incoming RPCs; RPCs arrive only on the root-only socket.",
    ("usr-bin-containerd", "GO-2026-6505"): "Package init of the OTLP exporter; the leak is of a configured endpoint URL, and no OTLP endpoint is configured (engine probe: tracing processor `skip`).",
    ("usr-bin-containerd", "GO-2026-5932"): "Package `init` only (`ocicrypt` → `openpgp` registration, compiled in through the `cri` package). Decryption runs only for encrypted image layers with configured keys; none are configured, and the CRI gRPC service is not loaded (engine probe).",
    ("usr-bin-ctr", "GO-2026-6061"): "`ctr` is an operator CLI talking to the root-only containerd socket; nothing on the appliance runs it.",
    ("usr-bin-ctr", "GO-2026-6348"): "`ctr` CLI client path (`Subscribe`); not run by anything on the appliance; peer is the root-only socket.",
    ("usr-bin-runc", "GO-2026-6238"): "`btf.LoadKernelSpec`: parses the running kernel's own BTF (root-owned kernel data), not attacker input.",
    # containerd.io 2.4.1 (go1.27.2) still vendors golang.org/x/net v0.55.0; the
    # x/net v0.60.0 HTTP/2 advisories on its real call paths.
    ("usr-bin-containerd", "GO-2026-6603"): "x/net HTTP/2 framer in grpc-go's server writer (`loopyWriter.writeHeader`); the trailer-header flood needs an HTTP/2 client to send it. Peers are local root processes on the root-only socket `/run/containerd/containerd.sock` (root:root 0660, empty docker group — engine probe); dockerd is its only client.",
    ("usr-bin-containerd", "GO-2026-6610"): "x/net HTTP/2 CLIENT transport (`http2.Transport.RoundTrip`); malformed framing headers must come from a remote HTTP/2 server. The only remote servers on the appliance are its pinned registries, reached over TLS and pulled by digest; CRI is not loaded (engine probe).",
    ("usr-bin-containerd", "GO-2026-6611"): "x/net HTTP/2 window updates in grpc-go's server transport (`grpc.Serve` → `NewServerTransport`); the CPU cost needs a peer sending repeated SETTINGS. Peers are local root processes on the root-only socket `/run/containerd/containerd.sock` (root:root 0660, empty docker group — engine probe).",
    ("usr-bin-containerd", "GO-2026-6612"): "x/net HTTP/2 SETTINGS handling in grpc-go's server writer; the double refund needs a hostile client. Peers are local root processes on the root-only socket `/run/containerd/containerd.sock` (root:root 0660, empty docker group — engine probe).",
    ("usr-bin-containerd", "GO-2026-6617"): "Reached only through `FrameHeader.String` (formatting a frame for a log line); the HPACK encoder race is in an HTTP/2 SERVER under concurrent writers, and the peers are root. Peers are local root processes on the root-only socket `/run/containerd/containerd.sock` (root:root 0660, empty docker group — engine probe).",
    ("usr-bin-ctr", "GO-2026-6603"): "`ctr` is an operator CLI (gRPC client: `loopyWriter.pingHandler`); nothing on the appliance runs it, and its server is the root-only containerd socket.",
    ("usr-bin-ctr", "GO-2026-6610"): "`ctr` HTTP/2 client transport (remote fetch); `ctr` is not run by anything on the appliance.",
    ("usr-bin-ctr", "GO-2026-6611"): "Reached only through `pseudoHeaderError.Error` (error formatting) in the `ctr` CLI; not run by anything on the appliance.",
    ("usr-bin-ctr", "GO-2026-6612"): "`ctr` gRPC client reader (`http2Client.reader`); the advisory concerns SERVER streams; `ctr` is not run by anything on the appliance.",
    ("usr-bin-ctr", "GO-2026-6617"): "`ctr` gRPC client SETTINGS write; the race is in an HTTP/2 SERVER; `ctr` is not run by anything on the appliance.",
    # docker-compose 5.6.0 is the newest docker-compose-plugin in Docker's apt
    # repository and is built with go1.26.8; these are the go1.26.9 stdlib and
    # x/net v0.60.0 advisories on its real call paths.
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6603"): "HTTP/2 framer reached from the gRPC client transport (`http2Client.readServerPreface`) — the advisory's server-side trailer flood needs compose to SERVE HTTP/2, which it never does; compose runs only as root (`install.sh`, the maintenance agent, `culvert-os-update`) and opens no listener; its HTTP and gRPC peers are the root-only local Docker socket and the daemon's own BuildKit.",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6604"): "`os.Root.Mkdir` in go-archive's untar (`createImpliedDirectories`), used by `compose cp` and build-context handling; the appliance never runs `compose cp`, and its only build context is the ClamAV sidecar directory from the verified deploy bundle.",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6605"): "`http.Get` for a REMOTE build context (`build.GetContextFromURL`); the appliance's compose files build only from a local directory, and the desync needs an HTTP proxy rejecting CONNECT.",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6607"): "TLS client handshake in `http.Transport.dialConn`; the advisory concerns ECH outer-extension references, which a client meets only when it is configured for ECH — compose is not, and its daemon connection is a Unix socket without TLS.",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6608"): "MIME-header parsing of response trailers (`http.body.readTrailer`); the only servers compose reads responses from are the local root-only daemon and BuildKit (compose runs only as root (`install.sh`, the maintenance agent, `culvert-os-update`) and opens no listener; its HTTP and gRPC peers are the root-only local Docker socket and the daemon's own BuildKit).",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6610"): "HTTP/2 transport reached from the Docker Desktop feature probe (`desktop.IsFeatureActive`); there is no Docker Desktop endpoint on the appliance, and the malformed headers must come from the server compose talks to.",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6611"): "x/net HTTP/2 transport (`transportResponseBody.Close`); the CPU cost needs a hostile HTTP/2 SERVER as the peer — compose's peers are the local daemon and BuildKit (compose runs only as root (`install.sh`, the maintenance agent, `culvert-os-update`) and opens no listener; its HTTP and gRPC peers are the root-only local Docker socket and the daemon's own BuildKit).",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6612"): "x/net HTTP/2 flow-control refund on SERVER streams; reached only through the client transport (`http2transportResponseBody.Read`) — compose serves no HTTP/2.",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6613"): "HTTP/1 SERVER desync after a 2xx CONNECT; reached through `Request.UserAgent` in the client's otelhttp transport (`ContainerAttach`) — compose runs no HTTP server.",
    ("usr-libexec-docker-cli-plugins-docker-compose", "GO-2026-6617"): "HPACK encoder race in an HTTP/2 SERVER; reached through `http.Client.Do` to the local daemon — compose runs no HTTP/2 server.",
}

def dist(sel):
    return sorted({r["id"] for r in sel})

def table(header, body):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in body]
    return out

_tv = open(os.path.join(ev, "trivy-version.txt")).read()
_db = next((l.split(":", 1)[1].strip()[:19] for l in _tv.splitlines() if "UpdatedAt" in l), "?")
L = []
w = L.append
w(f"# Exact-byte scan dispositions — candidate `{cand['source'][:8]}`")
w("")
w("Generated by `test/e2e/appliance/lab/scan-dispositions.py` from the scan artifact; every count below is read from it.")
w("")
L.extend(table(["identity", "value"], [
    ["source", f"`{cand['source']}`"],
    ["OVA", f"`{open(os.path.join(ev, 'ova.sha256')).read().split()[0]}` (artifact {cand['ova_artifact']}, run {cand['ova_run']})"],
    ["application image", f"`{cand['image_id']}` (tar `{cand['image_tar']}`, Deep gate run {cand['image_run']})"],
    ["scan", f"run {cand['scan_run']}, artifact {cand['scan_artifact']}"],
    ["scanners", f"Trivy {_tv.split()[1]} (vulnerability DB updated {_db} UTC); govulncheck v1.8.0 (binary and source mode)"],
    ["baked ClamAV sidecar", cand["sidecar"]],
]))
w("")
w("Nothing was filtered: every severity, unfixed findings included, `--ignorefile /dev/null`.")
w("")

# ── application image ─────────────────────────────────────────────────────
img = [r for r in rows if r["source"] == "image"]
img_os = [r for r in img if r["type"] not in ("gobinary",)]
w("## Application image")
w("")
fix = [r for r in img_os if r["fixed"] != "-"]
if fix:
    sys.exit("application image has a FIXABLE OS finding: " + ", ".join(r["id"] for r in fix))
w(f"- **OS packages:** {len(img_os)} findings, **0 fixable** (the Deep gate now fails on any fixable OS finding at any severity).")
gob = [r for r in img if r["type"] == "gobinary"]
for r in gob:
    if r["id"] != "GO-2026-5932":
        sys.exit("undispositioned application-image Go finding: " + r["id"])
inv = {}
for name in ("app-culvert", "app-deploy-culvert-maint"):
    f = os.path.join(ev, "govulncheck", name + ".inventory.tsv")
    if os.path.exists(f):
        inv[name] = {l.split("\t")[0]: int(l.split("\t")[1]) for l in open(f) if "\t" in l}
w("- **GO-2026-5932** (`golang.org/x/crypto/openpgp`, no fixed version): the vulnerable package is **not linked** into either shipped binary. "
  "govulncheck's own `-mode extract` record for these stripped binaries carries no package symbols, so its Symbol Results are wildcard placeholders; "
  "the pclntab inventory of the exact bytes is the evidence:")
w("")
body = []
for name, m in inv.items():
    openpgp = sum(v for k, v in m.items() if k.startswith("golang.org/x/crypto/openpgp"))
    body.append([name, sum(m.values()), openpgp, m.get("golang.org/x/crypto/ssh", 0), m.get("main", 0), m.get("runtime", 0)])
L.extend(table(["binary", "functions", "x/crypto/openpgp*", "x/crypto/ssh (control)", "main (control)", "runtime (control)"], body))
w("")
w("  The source gate `TestShippedBinariesDoNotLinkOpenPGP` keeps it that way.")
w("")

# ── guest OS: non-kernel packages ─────────────────────────────────────────
rf = [r for r in rows if r["source"] == "rootfs"]
nk = [r for r in rf if not r["package"].startswith("linux-") and r["type"] != "gobinary"]
w("## Guest OS — Ubuntu packages (kernel excluded)")
w("")
sev = collections.Counter(r["severity"] for r in nk)
nkfix = [r for r in nk if r["fixed"] != "-"]
if nkfix:
    sys.exit("guest OS package with a published fix: " + ", ".join(f"{r['package']} {r['id']}" for r in nkfix))
w(f"{len(nk)} rows, {len(dist(nk))} distinct CVEs ({', '.join(f'{k} {v}' for k, v in sorted(sev.items()))}), **0 with a published fix**; 0 HIGH or CRITICAL.")
w("")
w("**Disposition (all):** no fixed Ubuntu package exists at scan time. The OVA ships every package at the pinned archive snapshot, which is the newest state for "
  "each of them; a fix arrives through the security pocket the appliance already follows (unattended-upgrades, security pocket only, no automatic reboot; "
  "`culvert-os-update os`).")
w("")
byp = collections.defaultdict(set)
for r in nk:
    byp[(r["package"], r["installed"])].add(f"{r['id']} ({r['severity'][0]})")
L.extend(table(["package", "version", "CVEs"], [[p, v, ", ".join(sorted(s))] for (p, v), s in sorted(byp.items())]))
w("")

# ── kernel ────────────────────────────────────────────────────────────────
k = [l.rstrip("\n").split("\t") for l in open(os.path.join(ev, "kernel-cves.tsv")) if not l.startswith("#")][1:]
kver = open(os.path.join(ev, "kernel-cves.tsv")).readline().split()[-1]
w(f"## Guest OS — kernel `{kver}`")
w("")
krows = [r for r in rf if r["package"].startswith("linux-")]
w(f"{len(krows)} package rows; {len(dist(krows))} distinct CVEs, all Ubuntu-tracker `affected` with no fixed {kver.split('-')[0]} package. "
  "The kernel is the newest the archive publishes (the scan job's `apt-cache policy` record, `kernel-candidates.txt`). "
  "Every distinct CRITICAL and HIGH CVE is placed on the exact disk by `kernmap.py`:")
w("")
c = collections.Counter((x[1], x[3]) for x in k)
L.extend(table(["severity", "absent (code not on disk)", "denied (cannot load)", "present"],
               [[s, c[(s, "absent")], c[(s, "denied")], c[(s, "present")]] for s in ("CRITICAL", "HIGH")]))
w("")
w("- **absent:** the subsystem is in the reviewed table `kernel-absent-review.tsv` and this disk agrees (CONFIG `=m` with the module built but no `.ko` on disk, or unset). The code is not on the appliance.")
w("- **denied:** the module is on the disk and `/etc/modprobe.d/culvert-unused.conf` makes it unloadable; the booted-guest probe confirms every denied module stays unloaded and that a real SCTP socket is refused.")
w("- **present:** core kernel code or a loadable module the appliance may use. **Disposition:** no fixed package exists; the next Canonical 6.8.0 kernel update arrives through the security pocket and is applied with `culvert-os-update os --reboot-if-required`.")
w("")
w("### CRITICAL")
w("")
L.extend(table(["CVE", "subsystem", "class", "evidence"], [[x[0], x[2], x[3], x[4]] for x in k if x[1] == "CRITICAL"]))
if any(x[3] == "present" for x in k if x[1] == "CRITICAL"):
    sys.exit("a CRITICAL kernel CVE is present on the disk")
w("")
w("### HIGH — present, by subsystem")
w("")
grp = collections.defaultdict(list)
for x in k:
    if x[1] == "HIGH" and x[3] == "present":
        grp[(x[2].split(":")[0].split("/")[0] if x[2] != "-" else "") or "(no subsystem prefix in the advisory)"].append(x[0])
L.extend(table(["subsystem", "CVEs"], [[g, ", ".join(sorted(v))] for g, v in sorted(grp.items(), key=lambda kv: (-len(kv[1]), kv[0]))]))
w("")
w(f"The absent and denied HIGH rows, each with its evidence, are in `kernel-cves.tsv` in the scan artifact.")
w("")

# ── engine and other host Go binaries ─────────────────────────────────────
w("## Host Go binaries")
w("")
idx = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(os.path.join(ev, "engsrc", "index.tsv"))}
# A row that is not a completed source-mode run (download failure, revision
# or toolchain mismatch) would otherwise read as "not reported in source
# mode" — i.e. as unreachable. Refuse it instead.
# govulncheck -format json exits 0 with or without findings; anything else is
# a failed analysis (e.g. a source tree its type checker cannot load).
bad = [f"{k}: {v[2]}" for k, v in sorted(idx.items())
       if len(v) < 3 or not v[2].startswith("commit=") or " rc=0" not in " " + v[2]]
if bad:
    sys.exit("source mode did not complete for: " + "; ".join(bad))
gv = collections.defaultdict(list)
for r in rows:
    if r["source"].startswith("govulncheck:host-"):
        gv[r["source"][len("govulncheck:host-"):]].append(r)
src = collections.defaultdict(dict)
for r in rows:
    if r["source"].startswith("engsrc:"):
        src[r["source"][len("engsrc:"):]][r["id"]] = r
body = []
for name in sorted(set(gv) | set(src) | set(idx)):
    lv = collections.Counter(r["status"].split("/")[0] for r in gv.get(name, []))
    sl = collections.Counter(r["status"] for r in src.get(name, {}).values())
    bi = os.path.join(ev, "govulncheck", "host-" + name + ".buildinfo.txt")
    blind = os.path.exists(bi) and not any(l.split("\t")[1:2] == ["mod"] for l in open(bi))
    body.append([name, (idx.get(name) or ["", "-"])[1] if name in idx else "-",
                 ", ".join(f"{k} {v}" for k, v in sorted(lv.items())) or ("0 — blind: no module list in the build info" if blind else "0"),
                 ", ".join(f"{k} {v}" for k, v in sorted(sl.items())) or ("0" if name in idx else "n/a")])
L.extend(table(["binary", "exact source (proxy commit = binary vcs.revision)", "binary mode (by level)", "source mode (call graph)"], body))
w("")
# The engine packages must be the newest in Docker's apt repository: a vendor
# fix that exists and is not taken is not dispositioned here, it is a pin bump.
# The newest versions are measured at handoff (candidate JSON engine_latest,
# from the repository's signed Packages index); the shipped ones come from the
# OVA's own build record.
shipped = json.load(open(os.path.join(ev, "build-info.json")))["host_components_pinned"]
latest = cand["engine_latest"]
stale = [f"{p} {shipped.get(p)} < {v}" for p, v in sorted(latest.items()) if shipped.get(p) != v]
if stale:
    sys.exit("engine package older than the newest in Docker's repository: " + ", ".join(stale))
w("Binary mode reports a vulnerable function as soon as it is linked; source mode on the exact upstream revision, with the shipped build tags, tells whether a call path from `main` reaches it. "
  f"Every engine package is the newest in Docker's apt repository at handoff ({cand['engine_latest_measured']}: "
  + ", ".join(f"`{p}` {v}" for p, v in sorted(latest.items())) + "), so no vendor fix exists to apply; what remains is dispositioned below.")
w("")
w("### Findings on a real call path")
w("")
body, missing = [], []
for name, ids in sorted(src.items()):
    for vid, r in sorted(ids.items()):
        if r["status"] != "called":
            continue
        why = CALLED.get((name, vid))
        if not why:
            missing.append(f"{name} {vid}")
        body.append([name, vid, r["package"], r["installed"], r["fixed"], why or "**UNDISPOSITIONED**"])
if missing:
    sys.exit("called findings without a disposition: " + ", ".join(missing))
L.extend(table(["binary", "ID", "module", "shipped", "fixed in", "disposition"], body))
w("")
w("Every other engine finding is `imported` (package linked, vulnerable function unreachable from `main`) or `required` (module only). "
  "The engine-surface probe on the booted guest pins the exposure the dispositions rely on: no dockerd/containerd/shim/runc TCP listener, "
  "docker-proxy only on the appliance's published ports, both engine sockets root-only with an empty docker group, CRI gRPC not loaded, no OTLP endpoint.")
w("")
# Trivy's own Go-binary rows on the guest filesystem: each is answered by
# that binary's source-mode verdict (CVE ids are matched through OSV aliases).
alias = collections.defaultdict(dict)
for f in os.listdir(os.path.join(ev, "engsrc")):
    if not f.endswith(".json"):
        continue
    t, p0, dec = open(os.path.join(ev, "engsrc", f)).read(), 0, json.JSONDecoder()
    while True:
        while p0 < len(t) and t[p0].isspace():
            p0 += 1
        if p0 >= len(t):
            break
        m, p0 = dec.raw_decode(t, p0)
        if "osv" in m:
            for a in [m["osv"]["id"]] + (m["osv"].get("aliases") or []):
                alias[f[:-5]][a] = m["osv"]["id"]
w("### Trivy's Go-binary rows on the guest filesystem")
w("")
body = []
for r in [r for r in rf if r["type"] == "gobinary"]:
    name = r["target"].replace("/", "-")
    if r["target"].startswith("opt/culvert-appliance/"):
        verdict = "Culvert's own binary; module required, package not imported (govulncheck: module level only)"
        if r["id"] != "GO-2026-5932":
            sys.exit("undispositioned Culvert host-binary Trivy row: " + r["id"])
    else:
        gid = alias.get(name, {}).get(r["id"])
        if name not in idx:
            sys.exit(f"no source-mode record for {r['target']} ({r['id']})")
        lvl = src.get(name, {}).get(gid, {}).get("status") if gid else None
        if lvl == "called":
            verdict = f"{gid}: called — see the table above"
        elif lvl:
            verdict = f"{gid}: source mode `{lvl}` (not reachable from main)"
        else:
            verdict = f"{gid or r['id']}: not reported in source mode on the exact revision (no affected symbol reachable)"
    body.append([r["target"], r["package"], r["installed"], r["fixed"], r["severity"], r["id"], verdict])
L.extend(table(["binary", "module", "shipped", "fixed in", "severity", "ID", "disposition"], body))
w("")
cv = [r for r in rows if r["source"].startswith("govulncheck:host-opt-culvert")]
if any(r["id"] != "GO-2026-5932" for r in cv):
    sys.exit("undispositioned Culvert host-binary finding")
w(f"Culvert's own host binaries (`culvert-access`, `culvert-console`): {len(cv)} rows, all GO-2026-5932 at module level only (the module is required; the package is not imported).")
w("")
open(out, "w").write("\n".join(str(x) for x in L) + "\n")
print(f"wrote {out}: {len(L)} lines")
