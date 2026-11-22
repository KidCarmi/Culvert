#!/usr/bin/env python3
"""Mutation testing of the REAL maintenance-agent code (isolated copies only; nothing is pushed).
For every mutant: (1) Culvert's existing tests, (2) the model-conformance tests.
  usage: mutate.py <culvert checkout> --out results.json [--cap N] [--workers N]
Scheduled campaign only: far too slow for a pull request (about 1h40m on 4 cores for 350 mutants)."""
import argparse
import concurrent.futures as cf
import json
import os
import re
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = tempfile.mkdtemp(prefix="vec")
FILES = ["internal/server/reconcile_decision.go", "internal/server/reconcile_validate.go",
         "internal/server/journal_phases.go", "internal/server/inline_rollback.go",
         "internal/server/rollback_stages.go", "internal/server/handlers_upgrade_apply.go",
         "internal/ops/orchestrator.go"]
PKGS = ["./internal/server/", "./internal/ops/", "./internal/journal/"]
SWAPS = [(r"==", "!="), (r"!=", "=="), (r"&&", "||"), (r"\|\|", "&&"), (r"\btrue\b", "false"), (r"\bfalse\b", "true"),
         (r">=", ">"), (r"(?<![-=<>])>(?!=)", ">="), (r"(?<![<=])<(?![-=<])", "<=")]
DELETABLE = re.compile(r"^\s*(acc\.\w+ = .*|rec\.\w+ = .*|racc\.\w+ = .*|s\.advanceJournalPhaseBestEffort\(.*\)|"
                       r"\*failedPostRestart = true|step\.\w+ = .*|promotedReason = .*|firstReason = .*|"
                       r"finalState = .*|finalReason = .*)$")


def code_part(line):
    """Text before any // comment, with string literals blanked (so we never mutate inside them)."""
    out, i, q = [], 0, None
    while i < len(line):
        c = line[i]
        if q:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 1
            elif c == q:
                q = None
        elif c in "\"`'":
            q = c
            out.append(" ")
        elif line.startswith("//", i):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def mutants(root):
    out = []
    for f in FILES:
        lines = open(os.path.join(root, f)).read().split("\n")
        for ln, line in enumerate(lines):
            code = code_part(line)
            if not code.strip() or code.strip().startswith(("import", "package")) or "nolint" in line:
                continue
            for pat, rep in SWAPS:
                for m in re.finditer(pat, code):
                    out.append({"file": f, "line": ln + 1, "op": f"{m.group(0)} -> {rep}",
                                "new": line[:m.start()] + rep + line[m.end():], "old": line})
            m = re.match(r"^(\s*)if (.+) \{\s*$", code)
            if m and ":=" not in m.group(2) and ";" not in m.group(2):
                out.append({"file": f, "line": ln + 1, "op": "negate condition",
                            "new": f"{m.group(1)}if !({line.strip()[3:-2]}) {{", "old": line})
            if DELETABLE.match(code.rstrip()):
                out.append({"file": f, "line": ln + 1, "op": "delete statement",
                            "new": re.match(r"^\s*", line).group(0) + "// mutant: deleted", "old": line})
    return out


def go(cwd, args, env=None, timeout=240):
    try:
        p = subprocess.run(["go", "test", "-count=1"] + args, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env={**os.environ, **(env or {})})
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def existing(cwd):
    return go(cwd, ["-timeout", "200s"] + PKGS)   # no build tag: the conformance file is not compiled


def conformance(cwd, report=None):
    env = {"CULVERT_CONFORMANCE_VECTORS": VEC}
    return go(cwd, ["-tags", "lifecycle_conformance", "-run", "TestModelConformance", "-timeout", "200s",
                    "./internal/server/"], env)


def run_mutant(args):
    cwd, m = args
    path = os.path.join(cwd, m["file"])
    orig = open(path).read()
    lines = orig.split("\n")
    lines[m["line"] - 1] = m["new"]
    open(path, "w").write("\n".join(lines))
    try:
        rc, out = existing(cwd)
        if "[build failed]" in out or "[setup failed]" in out:
            return {**m, "status": "does_not_compile"}
        rc2, out2 = conformance(cwd)
        first = next((l.strip() for l in out2.split("\n") if "MISMATCH" in l or "PROPERTY" in l or "never reached" in l
                      or "journal" in l and "Errorf" not in l and "---" not in l), "")
        return {**m, "status": "tested", "killed_by_existing": rc != 0, "killed_by_conformance": rc2 != 0,
                "conformance_signal": first[:160]}
    finally:
        open(path, "w").write(orig)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("culvert")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cap", type=int, default=240)
    ap.add_argument("--workers", type=int, default=os.cpu_count())
    a = ap.parse_args()
    src = os.path.join(a.culvert, "cmd", "culvert-maint")
    subprocess.run(["python3", "-B", os.path.join(HERE, "..", "gen_vectors.py"), VEC], check=True)
    work = tempfile.mkdtemp(prefix="mut")
    dirs = []
    for w in range(a.workers):
        d = os.path.join(work, f"w{w}")
        shutil.copytree(src, d)
        dirs.append(d)
    allm = mutants(dirs[0])
    step = max(1, -(-len(allm) // a.cap))
    chosen = allm[::step]                                    # deterministic stride sample
    base = [(existing(dirs[0])[0], conformance(dirs[0])[0]) for _ in range(3)]
    assert all(b == (0, 0) for b in base), f"baseline not green: {base}"
    print(f"{len(allm)} candidate mutants, testing {len(chosen)} (every {step}th); baseline green 3/3", flush=True)
    res = []
    # one worker dir per thread, sequential within a thread
    chunks = [chosen[i::a.workers] for i in range(a.workers)]
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for part in ex.map(lambda t: [run_mutant((t[0], m)) for m in t[1]], zip(dirs, chunks)):
            res += part
    # Confirmation pass, serial and unloaded: a kill seen by only one suite must reproduce, so that a
    # timing flake under parallel load is never counted as a detection.
    disputed = [r for r in res if r["status"] == "tested" and r["killed_by_existing"] != r["killed_by_conformance"]]
    print(f"confirming {len(disputed)} single-suite kills serially", flush=True)
    for r in disputed:
        again = run_mutant((dirs[0], {k: r[k] for k in ("file", "line", "op", "new", "old")}))
        r["killed_by_existing"] = r["killed_by_existing"] and again["killed_by_existing"]
        r["killed_by_conformance"] = r["killed_by_conformance"] and again["killed_by_conformance"]
        r["confirmed_serially"] = True
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(VEC, ignore_errors=True)
    res.sort(key=lambda r: (r["file"], r["line"], r["op"]))
    tested = [r for r in res if r["status"] == "tested"]
    summ = {"candidates": len(allm), "sampled": len(chosen), "do_not_compile": len(res) - len(tested), "tested": len(tested),
            "killed_by_existing_tests": sum(r["killed_by_existing"] for r in tested),
            "killed_by_conformance": sum(r["killed_by_conformance"] for r in tested),
            "killed_by_both": sum(r["killed_by_existing"] and r["killed_by_conformance"] for r in tested),
            "killed_only_by_existing": sum(r["killed_by_existing"] and not r["killed_by_conformance"] for r in tested),
            "killed_only_by_conformance": sum(r["killed_by_conformance"] and not r["killed_by_existing"] for r in tested),
            "survived_both": sum(not r["killed_by_existing"] and not r["killed_by_conformance"] for r in tested)}
    per = {}
    for r in tested:
        d = per.setdefault(r["file"], {"tested": 0, "existing": 0, "conformance": 0, "only_conformance": 0, "survived": 0})
        d["tested"] += 1
        d["existing"] += r["killed_by_existing"]
        d["conformance"] += r["killed_by_conformance"]
        d["only_conformance"] += r["killed_by_conformance"] and not r["killed_by_existing"]
        d["survived"] += not r["killed_by_existing"] and not r["killed_by_conformance"]
    json.dump({"summary": summ, "per_file": per, "mutants": res},
              open(a.out, "w"), indent=1)
    print(json.dumps(summ, indent=1))
    print(json.dumps(per, indent=1))
