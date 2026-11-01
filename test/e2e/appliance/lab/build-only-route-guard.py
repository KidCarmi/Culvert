#!/usr/bin/env python3
"""build-only-route-guard.py — the build-only job's first step. Fails closed.

The job-level `if:` excludes every tag the lab workflows know today; this
guard covers the rest at run time, before anything is fetched or built:

  1. the event is a push to refs/heads/test/appliance-lab;
  2. the head commit message carries exactly ONE bracket tag, [build-only]
     (any other bracket token — a future tag, a typo, [lab-skip] — refuses);
  3. the push is exactly one commit on top of the previous branch head
     (head^ == github.event.before), so the reviewed head is its parent;
  4. that commit is EMPTY (its tree equals its parent's), so the workflow and
     harness that run are byte-for-byte the reviewed ones.

Inputs come from the environment (never interpolated into a shell):
GUARD_EVENT, GUARD_REF, GUARD_MESSAGE, GUARD_BEFORE, GUARD_PARENT,
GUARD_HEAD_TREE, GUARD_PARENT_TREE. Exit 0 = proceed, 1 = refuse.
"""
import os
import re
import sys

BRACKET = re.compile(r"\[[^\[\]\s]*\]")


def problems(env):
    out = []
    if env.get("GUARD_EVENT") != "push":
        out.append(f"event is {env.get('GUARD_EVENT')!r}, not push")
    if env.get("GUARD_REF") != "refs/heads/test/appliance-lab":
        out.append(f"ref is {env.get('GUARD_REF')!r}, not refs/heads/test/appliance-lab")
    tags = [t.lower() for t in BRACKET.findall(env.get("GUARD_MESSAGE") or "")]
    if tags != ["[build-only]"]:
        out.append(f"the message must carry exactly one bracket tag, [build-only]; found {tags}")
    before, parent = env.get("GUARD_BEFORE") or "", env.get("GUARD_PARENT") or ""
    if not re.fullmatch(r"[0-9a-f]{40}", parent) or parent != before:
        out.append(f"the push must be exactly one commit on the previous head: parent {parent!r}, before {before!r}")
    ht, pt = env.get("GUARD_HEAD_TREE") or "", env.get("GUARD_PARENT_TREE") or ""
    if not re.fullmatch(r"[0-9a-f]{40}", ht) or ht != pt:
        out.append(f"the trigger commit must be empty: tree {ht!r}, parent tree {pt!r}")
    return out


def main():
    bad = problems(os.environ)
    for p in bad:
        print(f"::error::build-only route refused: {p}")
    if bad:
        sys.exit(1)
    print("build-only route: push to test/appliance-lab, exactly [build-only], one empty commit on "
          f"{os.environ['GUARD_PARENT']} (tree {os.environ['GUARD_HEAD_TREE']})")


if __name__ == "__main__":
    main()
