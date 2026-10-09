#!/usr/bin/env bash
# repin-candidate.sh HEAD_SHA [--require-green]
#
# Repins the lab's candidate, adoption and F-DISK legs to a #1528 head, from
# GitHub's own records instead of by hand (resolve-lab-pins.sh: Deep gate run
# for that exact head SHA -> deep-gate-image artifact, zip digest checked ->
# tar sha256 + OCI image id). It can run as soon as the Deep gate has UPLOADED
# the image (~3 min after the push), before either gate finishes: the gate
# results are printed here and must still be green before any handoff.
#
# Only the header region of appliance-lab.yml is touched (everything before the
# guest-boot job's env block — the top env + the guest-boot matrix), and only
# the CURRENT candidate's values are replaced, so retained-OVA pins (e.g. the
# 2e3bcc2a adoption source) are never rewritten. Prints a diff summary; does
# not commit or push.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../../.." && pwd)"
wf="$root/.github/workflows/appliance-lab.yml"
pins="$("$here/resolve-lab-pins.sh" "$@")"
get() { sed -n "s/^$1=//p" <<<"$pins"; }
echo "$pins" | sed 's/^/  resolved /'
python3 -I - "$wf" "$(get SOURCE_SHA)" "$(get IMAGE_RUN)" "$(get IMAGE_TAR_SHA256)" "$(get IMAGE_ID)" <<'PY'
import re, sys
wf, sha, run, tar, iid = sys.argv[1:6]
L = open(wf).read().split("\n")
end = next(i for i, l in enumerate(L) if l.startswith("    env:") and i > 60)
head = "\n".join(L[:end])
def one(rx, what):
    m = re.findall(rx, head, re.M)
    if len(set(m)) != 1:
        sys.exit(f"cannot identify the current {what} uniquely (found {sorted(set(m))})")
    return m[0]
cur_sha = one(r'^  SOURCE_IMAGE_SHA: ([0-9a-f]{40})$', "source SHA")
cur_run = one(r'^  SOURCE_IMAGE_RUN_ID: "([0-9]+)"$', "Deep gate run")
cur_tar = one(r'^  SOURCE_IMAGE_TAR_SHA256: ([0-9a-f]{64})$', "image tar sha256")
blk = re.search(r'source_sha: "' + cur_sha + r'"\n(?:.*\n){0,6}?\s+expect_image_id: "(sha256:[0-9a-f]{64})"', head)
if not blk: sys.exit("cannot find the current candidate's expect_image_id")
cur_iid = blk.group(1)
if cur_sha == sha: sys.exit(f"already pinned to {sha}")
rep = [(cur_sha, sha), (cur_run, run), (cur_tar, tar), (cur_iid, iid),
       ("candidate-" + cur_sha[:12], "candidate-" + sha[:12]), (cur_sha[:8], sha[:8])]
n = 0
for i in range(end):
    o = L[i]
    for a, b in rep: L[i] = L[i].replace(a, b)
    n += L[i] != o
open(wf, "w").write("\n".join(L))
print(f"repinned {n} line(s): {cur_sha[:12]} -> {sha[:12]}, run {cur_run} -> {run}")
print("note: the free-text description of what the head contains is NOT rewritten; update it if the head's content changed")
PY
