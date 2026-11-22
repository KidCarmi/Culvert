#!/usr/bin/env python3
"""Derive deterministic conformance vectors from the model (no randomness).
  usage: gen_vectors.py <output dir>
  vectors_apply.json     every fault path of the apply flow to a terminal state, with the expected outcome
  vectors_crash.json     every executable crash point, with the expected journal record and reconcile verdict
  vectors_reconcile.json the full bounded input space of the reconcile decision, with the expected verdict"""
import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "model"))
import culvert_apply as C  # noqa: E402

M = C.MODEL
PARAMS = ("prior", "same", "backup", "rb", "th", "ph")


def commands(s, e, n):
    """Docker commands the stage issues for outcome e, plus fault-plan entries. n counts occurrences."""
    cmds, plan = [], []

    def do(tok, mode=None):
        base = tok.split(":")[0]
        key = "ps" if base == "capture" else base
        n[key] = n.get(key, 0) + 1
        cmds.append(tok)
        if mode:
            plan.append({"cmd": key, "n": n[key], "mode": mode})
    pc = s.pc
    if e == "skip":
        return cmds, plan
    if pc == "capture_before":
        do("capture")
    elif pc == "resolve_target":
        do("manifest", "fail" if e == "fail" else None)
    elif pc == "pre_backup":
        do("backup", "fail" if e == "fail" else None)
    elif pc in ("pull", "rb_pull"):
        do("pull:" + ("T" if pc == "pull" else "P"), "fail" if e == "fail" else None)
    elif pc in ("restart", "rb_restart"):
        img = "T" if pc == "restart" else "P"
        if e == "barrier_fail":
            plan.append({"cmd": "pull", "n": n["pull"], "mode": "corrupt_journal"})
        elif e == "tag_fail":
            do("tag:" + img, "fail")
        else:
            do("tag:" + img)
            do("up", {"up_fail_stale": "fail_stale", "up_fail_recreated": "fail_recreated", "ok_stale": "ok_stale"}.get(e))
            if pc == "restart":
                do("capture")                      # success: journal the target id; failure: AGT-002 re-read
                if e == "up_fail_stale" and s.prior == "valid":
                    do("tag:P")                    # AGT-002: container never moved, tag goes back
    elif pc in ("verify", "rb_verify"):
        do("capture", "fail" if e == "capture_fail" else None)
    return cmds, plan


def collapse(cmds):
    out = []
    for c in cmds:
        if not (c == "capture" and out and out[-1] == "capture"):
            out.append(c)
    return out


def skipped_reason(s):
    if s.rb_att or s.op == "succeeded":
        return ""
    if s.post_fail:
        return "disabled" if not s.rb else "no_prior_digest"
    return "pre_restart_failure"


def block_point(s, e, n):
    """Where a real run can be frozen to emulate this crash, or None if not executable."""
    nxt = lambda k: {"cmd": k, "n": n.get(k, 0) + 1}  # noqa: E731
    if e == "crash_after_barrier" or e == "crash_before_tag":
        return nxt("tag")
    if e == "crash_after_tag":
        return {"cmd": "up", "n": n.get("up", 0) + 1, "after_tag": True}
    if e == "crash_after_up":
        return {"cmd": "ps", "n": n.get("ps", 0) + 1, "after_up": True} if s.pc == "restart" else \
            {"cmd": "health", "n": n.get("up", 0) + 1, "after_up": True}
    first = M._outcomes(s)[0]
    if first == "skip" or s.pc in ("restart", "rb_restart", "report"):
        return None
    if s.pc in ("health_gate", "rb_health"):
        return {"cmd": "health", "n": n.get("up", 0)}
    return nxt({"capture_before": "ps", "resolve_target": "manifest", "pre_backup": "backup", "pull": "pull",
                "verify": "ps", "rb_pull": "pull", "rb_verify": "ps"}[s.pc])


def walk():
    apply_v, crash_v = {}, {}

    def rec(s, script, cmds, plan, n):
        for e in M.events(s):
            if e.startswith("crash"):
                bp = block_point(s, e, n)
                if bp is None:
                    continue
                n2 = dict(n)
                extra, extra_plan = [], []
                if e in ("crash_after_tag", "crash_after_up"):       # the stage got as far as tag / up
                    img = "T" if s.pc == "restart" else "P"
                    for tok in ["tag:" + img] + (["up"] if e == "crash_after_up" else []):
                        n2[tok.split(":")[0]] = n2.get(tok.split(":")[0], 0) + 1
                        extra.append(tok)
                t = M.step(s, e)
                r = C.record_for_state(t)
                act, why = C.reconcile_for_state(t)
                v = {"params": {k: getattr(s, k) for k in PARAMS}, "script": script + [[s.pc, e]],
                     "plan": plan + extra_plan, "block": bp,
                     "expect": {"phase": t.jr, "tag": t.tag, "running": t.running, "record": r,
                                "reconcile_action": act, "reconcile_reason": why,
                                "cmds_before_block": collapse(cmds + extra)}}
                key = json.dumps([v["params"]["prior"], v["params"]["same"], v["script"], v["plan"], v["block"], v["expect"]], sort_keys=True)
                crash_v.setdefault(key, v)
                continue
            c, p = commands(s, e, n2 := dict(n))
            t = M.step(s, e)
            if t.pc == "done":
                v = {"params": {k: getattr(s, k) for k in PARAMS}, "script": script + [[s.pc, e]], "plan": plan + p,
                     "expect": {"op": t.op, "reason": t.reason, "running": t.running, "tag": t.tag,
                                "journal_empty": True, "cmds": collapse(cmds + c),
                                "upgrade_succeeded": t.op == "succeeded", "rollback_attempted": t.rb_att,
                                "rollback_succeeded": t.rb_ok, "rollback_skipped_reason": skipped_reason(t),
                                "tag_ahead": t.tag == "T" and t.running != "T" and not t.same}}
                key = json.dumps([v["params"]["prior"], v["params"]["same"], v["plan"], v["expect"]], sort_keys=True)
                apply_v.setdefault(key, v)
            else:
                rec(t, script + [[s.pc, e]], cmds + c, plan + p, n2)
    for s0 in M.inits():
        rec(s0, [], [], [], {})
    return list(apply_v.values()), list(crash_v.values())


REASONS = ["data_window_manual", "invalid_record_ref", "reconcile_exhausted", "live_target_prior_equals_target",
           "live_target", "tag_advanced_container_stale", "already_on_prior", "safe_boundary_confirmed",
           "indeterminate_restore_prior", "no_recovery_target"]
DOMAINS = [("kind_mode", [["upgrades.apply", ""], ["rollbacks.create", "image"], ["rollbacks.create", "data"], ["upgrades.apply", "data"]]),
           ("phase", ["admitted", "captured", "resolved", "pulled", "restarting", "restarted", "verified"]),
           ("attempts", [[0, 0], [0, 3], [3, 3]]), ("ref_valid", [True, False]),
           ("running_id", ["", "P", "T", "X"]), ("target_id", ["", "T", "P"]), ("prior_id", ["", "P", "T"]),
           ("running_digests", [[], ["P"], ["T"], ["X"]]), ("target_digests", [[], ["T"]]),
           ("prior_digests", [[], ["P"], ["T"]]), ("tag_digests", [[], ["P"], ["T"]])]


def reconcile_vectors():
    out = []
    for combo in itertools.product(*(d for _, d in DOMAINS)):
        i = dict(zip((k for k, _ in DOMAINS), combo))
        i["kind"], i["mode"] = i["kind_mode"]
        i["attempts"], i["max_attempts"] = i["attempts"]
        out.append(str(REASONS.index(C.reconcile_spec(i)[1])))
    return {"order": "itertools.product over domains, last domain varies fastest", "reasons": REASONS,
            "domains": [{"name": k, "values": d} for k, d in DOMAINS], "expected": "".join(out)}


if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else HERE
    a, c = walk()
    r = reconcile_vectors()
    for name, obj in (("vectors_apply.json", a), ("vectors_crash.json", c), ("vectors_reconcile.json", r)):
        json.dump(obj, open(os.path.join(out_dir, name), "w"), separators=(",", ":"), sort_keys=True)
    print(f"apply vectors: {len(a)}   crash vectors: {len(c)}   reconcile vectors: {len(r['expected'])}")
