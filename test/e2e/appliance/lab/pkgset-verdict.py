#!/usr/bin/env python3
"""Package-set / kernel checkpoint verdict for appliance-lab.sh (fails closed).

  pkgset-verdict.py OUT RC EXPECT_DPKG EXPECT_KERNEL

OUT is the console-session transcript of the guest script

  dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n' 2>/dev/null; echo "LABRC=$?"
  echo "LABUNAME=$(uname -r)"

(the dpkg-query format is the one prepare-guest.sh wrote dpkg-list.txt with),
RC the transport exit status, EXPECT_DPKG the build's dpkg-list.txt (or "" to
skip), EXPECT_KERNEL the expected `uname -r` (or "" to skip). Prints one
"result<TAB>name<TAB>detail" line per verdict: pkgset, kernel. Anything not
positively observed (transport failure, missing marker, unparseable row, a
reference too small to be real, the running kernel's image missing) is a FAIL,
never "unchanged". Rows are compared as a set: sort order is locale-dependent.
"""
import re
import sys

ROW = re.compile(r"[^\t\s]+\t[^\t\n]*\t[^\t\s]+")
MIN_ROWS = 100  # a usable reference: the shipped guest has 680 rows


def rows(lines):
    ok, bad = set(), []
    for line in lines:
        if not line.strip():
            continue
        (ok.add(line) if ROW.fullmatch(line) else bad.append(line))
    return ok, bad


def run(out_path, rc, expect_dpkg, expect_kernel):
    res = []
    try:
        text = open(out_path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        text = None
        err = "no checkpoint output: %s" % e
    if text is not None:
        lines = [line.rstrip("\r") for line in text.split("\n")]
        m_rc = [line for line in lines if line.startswith("LABRC=")]
        m_un = [line for line in lines if line.startswith("LABUNAME=")]
        body = [line for line in lines if not line.startswith(("LABRC=", "LABUNAME="))]
        if rc != "0":
            err = "transport exit %s" % rc
        elif len(m_rc) != 1 or len(m_un) != 1:
            err = "markers missing or repeated (LABRC %d, LABUNAME %d)" % (len(m_rc), len(m_un))
        else:
            err = ""
    running = m_un[0][len("LABUNAME="):] if text is not None and not err else ""
    if expect_dpkg:
        if err:
            res.append(("fail", "pkgset", err))
        elif m_rc[0] != "LABRC=0":
            res.append(("fail", "pkgset", "dpkg-query %s" % m_rc[0]))
        else:
            got, bad = rows(body)
            try:
                want, wbad = rows(open(expect_dpkg, encoding="utf-8").read().split("\n"))
            except OSError as e:
                want, wbad = set(), ["reference unreadable: %s" % e]
            if wbad or len(want) < MIN_ROWS:
                res.append(("fail", "pkgset", "reference %s unusable (%d rows, %d bad)" % (expect_dpkg, len(want), len(wbad))))
            elif bad:
                res.append(("fail", "pkgset", "%d unparseable line(s), first %r" % (len(bad), bad[0][:120])))
            elif running and not any(r.startswith("linux-image-%s\t" % running) for r in got):
                res.append(("fail", "pkgset", "the running kernel's linux-image-%s is not in the observed set (positive control)" % running))
            elif got != want:
                added, removed = sorted(got - want), sorted(want - got)
                res.append(("fail", "pkgset", "differs from the build's dpkg-list.txt: +%d -%d; added %s; removed %s" % (
                    len(added), len(removed), [a.replace("\t", " ") for a in added[:10]], [r.replace("\t", " ") for r in removed[:10]])))
            else:
                res.append(("pass", "pkgset", "%d packages identical to the build's dpkg-list.txt" % len(got)))
    if expect_kernel:
        if err:
            res.append(("fail", "kernel", err))
        elif running != expect_kernel:
            res.append(("fail", "kernel", "running %r, expected %r" % (running, expect_kernel)))
        else:
            res.append(("pass", "kernel", "running %s" % running))
    return res


if __name__ == "__main__":
    out, rc, exp, kern = (sys.argv[1:5] + [""] * 4)[:4]
    for st, name, detail in run(out, rc, exp, kern):
        print("%s\t%s\t%s" % (st, name, detail.replace("\t", " ").replace("\n", " ")))
