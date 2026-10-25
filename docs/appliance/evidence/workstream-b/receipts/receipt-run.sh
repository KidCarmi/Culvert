#!/usr/bin/env bash
# receipt-run.sh WORKTREE OUTDIR CMDFILE
# Runs each line of CMDFILE (one shell command per line, run from WORKTREE)
# and writes OUTDIR/receipt.json plus OUTDIR/<n>.log per command. The receipt
# binds every result to the exact commit/tree, records clean-before/after,
# the toolchain and environment, and each command's exit code, duration and
# output SHA-256. Nothing is summarised: the raw output sits beside it.
set -uo pipefail
WT="$1" OUT="$2" CMDS="$3"
mkdir -p "$OUT"
cd "$WT" || exit 2
before="$(git status --porcelain)"
commit="$(git rev-parse HEAD)" tree="$(git rev-parse 'HEAD^{tree}')"
n=0
: > "$OUT/results.tsv"
while IFS= read -r cmd; do
  [[ -z "$cmd" || "$cmd" == \#* ]] && continue
  n=$((n + 1))
  t0="$(date -u +%s.%N)"
  bash -c "$cmd" > "$OUT/$n.log" 2>&1
  rc=$?
  t1="$(date -u +%s.%N)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$rc" "$t0" "$t1" "$cmd" >> "$OUT/results.tsv"
done < "$CMDS"
after="$(git status --porcelain)"
python3 -I - "$OUT" "$commit" "$tree" "$before" "$after" <<'EOF'
import hashlib, json, os, platform, subprocess, sys
out, commit, tree, before, after = sys.argv[1:6]
def run(*a):
    try:
        return subprocess.run(a, capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        return ""
cmds = []
for line in open(os.path.join(out, "results.tsv")):
    n, rc, t0, t1, cmd = line.rstrip("\n").split("\t", 4)
    log = os.path.join(out, n + ".log")
    data = open(log, "rb").read()
    cmds.append({"n": int(n), "command": cmd, "exit": int(rc),
                 "seconds": round(float(t1) - float(t0), 3),
                 "log": n + ".log", "log_sha256": hashlib.sha256(data).hexdigest(),
                 "log_bytes": len(data)})
receipt = {
    "commit": commit, "tree": tree,
    "clean_before": before == "", "clean_after": after == "",
    "status_before": before, "status_after": after,
    "go_version": run("go", "version"),
    "go_env": {k: run("go", "env", k) for k in ("GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOTOOLCHAIN")},
    "host": {"kernel": platform.release(), "machine": platform.machine(), "cpus": os.cpu_count()},
    "commands": cmds,
    "all_exit_zero": all(c["exit"] == 0 for c in cmds),
}
json.dump(receipt, open(os.path.join(out, "receipt.json"), "w"), indent=2)
print(json.dumps({"commit": commit, "tree": tree, "all_exit_zero": receipt["all_exit_zero"],
                  "clean": receipt["clean_before"] and receipt["clean_after"],
                  "exits": [c["exit"] for c in cmds]}))
EOF
