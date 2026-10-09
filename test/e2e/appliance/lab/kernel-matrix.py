"""Disposition matrix for the kernel HIGH CVEs ASTRA's 7c round left open.

kernel-matrix.py BASELINE_KERNEL_CVES UCT_ACTIVE_DIR PREREQS OUT_MD [CANDIDATE.json]

BASELINE_KERNEL_CVES  kernel-cves.tsv of the scanned baseline (7c7b29ee, GA
                      6.8.0-146): the "present" HIGH rows are the population.
UCT_ACTIVE_DIR        ubuntu-cve-tracker/active at a recorded commit.
PREREQS               kernel-cve-prereqs.tsv (hand-reviewed prerequisites and
                      the residual dispositions with their evidence).
CANDIDATE.json        optional: {"source", "kernel_version" (dpkg version of the
                      shipped HWE image), "kernel_cves" (the corrected
                      candidate's own kernel-cves.tsv: findings on the shipped
                      kernel's OWN packages only), "kernel_cves_userspace"
                      (kernmap's -userspace.tsv: kernel CVEs reported only
                      against linux-libc-dev / linux-tools-common),
                      "kernel_config" (the shipped /boot/config-*), "checks"
                      (its lab checks.jsonl), "uct_commit", "scan_run",
                      "lab_run", "ova"}.

A CVE's disposition on the corrected candidate is:
  FIXED          Canonical lists it released in linux-hwe-7.0 at a version
                 <= the shipped one (dpkg comparison, not the word "released")
  NOT AFFECTED   Canonical lists linux-hwe-7.0 not-affected; or, for a residual,
                 a configuration determination recorded in PREREQS
  MITIGATED      residual whose prerequisite the candidate removes (PREREQS)
  OPEN / UNDETERMINED  residual PREREQS leaves so
With a candidate, its own scan adds a second population: every HIGH/CRITICAL
finding on the shipped kernel's own packages (any class: present, denied or
absent) that is not among the baseline's findings needs a PREREQS row and a
disposition too. A residual citing "config:CONFIG_X=<y|m|unset>" is checked
against the shipped kernel config; a mismatch refuses the matrix.
Fails if: a population CVE has no PREREQS row; a PREREQS row is in neither
population; a residual has no disposition; with a candidate, a
FIXED/vendor-NOT-AFFECTED CVE still appears in the candidate's own scan, or
a lab check a disposition cites did not pass.
"""
import csv, json, os, re, subprocess, sys

base_f, uct, pre_f, out = sys.argv[1:5]
cand = json.load(open(sys.argv[5])) if len(sys.argv) > 5 else None
GA, HWE = "noble_linux", "noble_linux-hwe-7.0"
shipped = cand["kernel_version"] if cand else "7.0.0-38.38~24.04.4"

pop = [l.split("\t") for l in open(base_f) if l.startswith("CVE-")]
pop = sorted(r[0] for r in pop if r[1] == "HIGH" and r[3] == "present")
pop2 = []
uspace, kconf = {}, {}
if cand:
    pop2 = sorted(l.split("\t")[0] for l in open(cand["kernel_cves"]) if l.startswith("CVE-")
                  and l.split("\t")[1] in ("HIGH", "CRITICAL") and l.split("\t")[0] not in pop)
    if cand.get("kernel_cves_userspace"):
        uspace = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(cand["kernel_cves_userspace"]) if l.startswith("CVE-")}
    if cand.get("kernel_config"):
        for l in open(cand["kernel_config"]):
            m = re.match(r"(CONFIG_[A-Za-z0-9_]+)=(\S+)", l) or re.match(r"# (CONFIG_[A-Za-z0-9_]+) is not set", l)
            if m:
                kconf[m.group(1)] = m.group(2) if m.lastindex == 2 else "unset"
pre = {r["cve"]: r for r in csv.DictReader((l for l in open(pre_f) if not l.startswith("#")), delimiter="\t")}
missing = [c for c in pop + pop2 if c not in pre]
if missing:
    sys.exit("no prerequisite row for: " + ", ".join(missing))
extra = sorted(set(pre) - set(pop) - set(pop2))
if extra:
    sys.exit("prerequisite rows outside both populations: " + ", ".join(extra))

def vle(a, b):
    return subprocess.run(["dpkg", "--compare-versions", a, "le", b]).returncode == 0

def status(text, pkg):
    m = re.search(r"^" + re.escape(pkg) + r": (\S+)(?: \(([^)]*)\))?", text, re.M)
    return (m.group(1), m.group(2) or "") if m else ("DNE", "")

checks = {}
if cand:
    for l in open(cand["checks"]):
        d = json.loads(l)
        checks[f'{d["step"]}/{d["check"]}'] = d["result"]
    cscan = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(cand["kernel_cves"]) if l.startswith("CVE-")}

rows, bad = [], []
for c in pop + pop2:
    t = open(os.path.join(uct, c), errors="replace").read()
    title = next((x.strip() for x in t.split("Description:\n", 1)[1].split("\n")[1:]
                  if x.strip() and "following vulnerability" not in x), "")
    fix = re.findall(r"break-fix: \S+ (\S+)", t)
    ga, gav = status(t, GA)
    hw, hwv = status(t, HWE)
    p = pre[c]
    if hw == "released" and hwv and vle(hwv, shipped):
        disp, ev = "FIXED", f"Canonical: {HWE} released ({hwv}) <= shipped {shipped}"
    elif hw == "not-affected":
        disp, ev = "NOT AFFECTED", f"Canonical: {HWE} not-affected ({hwv})"
    else:
        if p["residual"] in ("", "-"):
            bad.append(f"{c}: Canonical {HWE} is '{hw} {hwv}' but no residual disposition is recorded")
            disp, ev = "UNDETERMINED", "no disposition recorded"
        else:
            disp, ev = p["residual"].split("|", 1)
            ev = f"Canonical: {HWE} {hw} {('(' + hwv + ')') if hwv else ''}; " + ev
    if cand:
        if disp in ("FIXED",) or (disp == "NOT AFFECTED" and hw == "not-affected"):
            if c in cscan:
                bad.append(f"{c}: {disp} by Canonical, yet the candidate's own scan still lists it ({cscan[c][3]})")
        for cid in re.findall(r"lab ([A-Z0-9]+/[a-z0-9-]+)", ev):
            if checks.get(cid) != "pass":
                bad.append(f"{c}: cites lab check {cid}, which is {checks.get(cid, 'absent')} on the candidate")
        for sym, want in re.findall(r"config:(CONFIG_[A-Za-z0-9_]+)=(\w+)", ev):
            got = kconf.get(sym, "unset") if kconf else None
            if got is None:
                bad.append(f"{c}: cites config:{sym}={want} but the candidate's kernel config was not supplied")
            elif got != want:
                bad.append(f"{c}: cites config:{sym}={want}, shipped config has {sym}={got}")
        if c in cscan:
            ev += f"; candidate scan: shipped-kernel package, class {cscan[c][3]}"
        elif c in uspace:
            ev += f"; candidate scan: reported only against {uspace[c][2]} ({uspace[c][3]}: userspace packages from the GA linux source, not the running kernel)"
        else:
            ev += "; candidate scan: not reported"
    rows.append((c, p["group"] + ("" if c in pop else " (candidate scan)"), title, f"{ga} {('(' + gav + ')') if gav else ''}".strip(),
                 f"{hw} {('(' + hwv + ')') if hwv else ''}".strip(), p["prereq"], p["appliance"], disp, ev,
                 ", ".join(f"[{x[:12]}](https://git.kernel.org/linus/{x})" for x in fix) or "-"))
if bad:
    sys.exit("matrix refused:\n  " + "\n  ".join(bad))

from collections import Counter
cnt = Counter(r[7] for r in rows)
L = [f"# Kernel HIGH CVE dispositions — {len(pop)} findings present on the GA kernel 6.8.0-146 (7c7b29ee)"
     + (f" + {len(pop2)} further findings on the corrected candidate's own kernel packages" if pop2 else ""), "",
     "Generated by `test/e2e/appliance/lab/kernel-matrix.py`. Population: every HIGH kernel CVE the 7c7b29ee exact-byte scan",
     "classed `present` (ASTRA's 7c round, remaining work item 1). Canonical status is read from `ubuntu-cve-tracker/active`",
     f"(commit `{cand['uct_commit'] if cand else '?'}`) for the GA source (`{GA}`) and the HWE source the corrected candidate ships",
     f"(`{HWE}`, shipped version `{shipped}`). \"Released\" counts only at a version <= the shipped one (dpkg comparison).", ""]
if cand:
    L += [f"Corrected candidate: source `{cand['source']}`, OVA `{cand['ova']}`, lab run {cand['lab_run']}, scan run {cand['scan_run']}.", "",
          "Scanner attribution: a kernel CVE counts against the running kernel only when the scanner reports it on the shipped",
          "kernel's OWN packages (names carrying the running version). Kernel CVEs reported only against `linux-libc-dev` (UAPI",
          "headers) and `linux-tools-common` (wrappers that exec `/usr/lib/linux-tools/$(uname -r)/<tool>`, none installed) are",
          f"listed separately by the scan ({len(uspace)} CVEs, each proven on the disk to carry no kernel code); a row below says",
          "which kind of report, if any, the candidate's scan made.", ""]
L += ["| disposition | count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(cnt.items())] + [""]
L += ["Dispositions: FIXED = Canonical's fixed package is the shipped kernel; NOT AFFECTED = Canonical's determination for",
      "linux-hwe-7.0, or a configuration determination with the evidence named; MITIGATED = the prerequisite is removed on the",
      "candidate (not a patch: the code is still present and the fix still arrives through the kernel update path). No row is",
      "risk-accepted.", "",
      "| CVE | group | title | Canonical GA 6.8 | Canonical HWE 7.0 | prerequisites | on the appliance | disposition | evidence | fix |",
      "|---|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    L.append("| " + " | ".join(x.replace("|", "/") for x in r) + " |")
open(out, "w").write("\n".join(L) + "\n")
print(f"wrote {out}: " + ", ".join(f"{k} {v}" for k, v in sorted(cnt.items())))
