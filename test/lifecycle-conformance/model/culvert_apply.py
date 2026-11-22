"""Model of Culvert's maintenance-agent `upgrades.apply` flow, its crash journal, and the
(not wired) startup reconcile decision.  Source of truth: cmd/culvert-maint/internal/{server,journal,ops}.

Fault outcomes are what the FAKE exec layer can be told to do. `ok_stale` (`compose up` exits 0
without recreating the container although the tag moved to a different image) was NOT observed on
real Docker 29.10 / Compose v5.7.1; it is kept as a robustness input, not as a claim about Docker.

Culvert has no boot slots: an upgrade pulls an image, moves one fixed tag (culvert/proxy:pinned) and recreates the container.

Abstraction: two images, P (prior) and T (target). Docker world = (running, tag).
`compose up` makes the container run whatever the tag points at.
Each event is the outcome of the stage about to run; "crash" kills the agent process."""
from collections import namedtuple

S = namedtuple("S", "prior same backup rb th ph pc running tag jr fail_stage reason post_fail "
                    "rb_att rb_failed rb_restarted rb_ok op tid")
# prior : valid | nodigest (running image has no registry digest) | down (no container)
# same  : target already running          backup/rb: request flags     th/ph: is T / P healthy
# jr    : last durable journal phase, or "removed"      tid: image id stored as TargetImageID
STAGES = ("capture_before", "resolve_target", "pre_backup", "pull", "restart", "health_gate", "verify",
          "rb_pull", "rb_restart", "rb_health", "rb_verify", "report")
SAFE = ("admitted", "captured", "resolved", "pulled")
REASON = {"resolve_target": "command_error", "pre_backup": "cli_error", "pull": "command_error",
          "restart": "command_error", "health_gate": "health_failed", "verify": "health_failed"}


def healthy(s, img):
    return {"T": s.th, "P": s.ph}.get(img, False)


def rollback_armed(s):
    return s.post_fail and s.rb and s.prior == "valid"


class ApplyModel:
    def inits(self):
        out = []
        for prior, same in (("valid", False), ("valid", True), ("nodigest", False), ("down", False)):
            for backup in (False, True):
                for rb in (True, False):
                    for th in (True, False):
                        for ph in (True, False):
                            out.append(S(prior, same, backup, rb, th, ph, "capture_before",
                                         "none" if prior == "down" else "P", "P", "admitted", "", "", False,
                                         False, False, False, False, "running", ""))
        return out

    # ---- which outcomes can the next stage have?
    def events(self, s):
        if s.pc == "crashed":
            return ["restart_agent"]
        if s.pc in ("done", "recovered"):
            return []
        ev = self._outcomes(s)
        if s.pc in ("restart", "rb_restart") and "skip" not in ev:
            ev += ["crash_after_barrier" if s.pc == "restart" else "crash_before_tag", "crash_after_tag", "crash_after_up"]
        return ev + ["crash"]

    def _outcomes(self, s):
        pc = s.pc
        if pc in ("capture_before", "report"):
            return ["ok"]
        if pc in STAGES[1:7]:
            if pc in ("pull", "restart", "health_gate", "verify") and s.same:
                return ["skip"]
            if pc == "resolve_target":
                return ["ok", "fail"]
            if pc == "pre_backup":
                return ["ok", "fail"] if (s.backup and not s.same) else ["skip"]
            if pc == "pull":
                return ["ok", "fail"]
            if pc == "restart":
                return ["ok", "ok_stale", "barrier_fail", "tag_fail", "up_fail_stale", "up_fail_recreated"]
            if pc == "health_gate":
                return ["ok"] if healthy(s, s.running) else ["fail"]
            return ["ok", "capture_fail"] if s.running == "T" else ["mismatch"]
        if not rollback_armed(s) or s.rb_failed:
            return ["skip"]
        if pc == "rb_pull":
            return ["ok", "fail"]
        if pc == "rb_restart":
            return ["ok", "ok_stale", "tag_fail", "up_fail_stale", "up_fail_recreated"]
        if pc == "rb_health":
            return ["ok"] if healthy(s, s.running) else ["fail"]
        return ["ok", "capture_fail"] if s.running == "P" else ["mismatch"]

    def step(self, s, e):
        pc = s.pc
        if e == "restart_agent":             # main.go initJournal: mark interrupted, nothing else
            return s._replace(pc="recovered", op="interrupted")
        if e.startswith("crash"):
            if e == "crash_after_barrier":
                s = s._replace(jr="restarting")
            elif e == "crash_after_tag":
                s = s._replace(tag="T" if pc == "restart" else "P", jr="restarting" if pc == "restart" else s.jr)
            elif e == "crash_after_up":
                img = "T" if pc == "restart" else "P"
                s = s._replace(tag=img, running=img, jr="restarting" if pc == "restart" else s.jr)
            return s._replace(pc="crashed")
        nxt = STAGES[STAGES.index(pc) + 1] if pc != "report" else "done"
        if pc == "report":
            failed = s.fail_stage != ""
            return s._replace(pc="done", jr="removed", op="failed" if failed else "succeeded",
                              reason=("rollback_failed" if s.rb_failed else s.reason) if failed else "")
        if pc == "capture_before":
            return s._replace(pc=nxt, jr="captured")
        if pc in STAGES[1:7]:
            if e == "skip":
                return s._replace(pc=nxt)
            bad = lambda **kw: s._replace(pc="rb_pull", fail_stage=pc, reason=REASON[pc], **kw)  # noqa: E731
            if pc == "resolve_target":
                return s._replace(pc=nxt, jr="resolved") if e == "ok" else bad()
            if pc == "pre_backup":
                return s._replace(pc=nxt) if e == "ok" else bad()
            if pc == "pull":
                return s._replace(pc=nxt, jr="pulled") if e == "ok" else bad()
            if pc == "restart":
                if e == "barrier_fail":
                    return bad()
                if e == "tag_fail":
                    return bad(jr="restarting")
                if e == "up_fail_stale":
                    # AGT-002 (realignPinnedTagAfterFailedUp): the container provably still runs the
                    # prior image, so the tag is moved back -- but only when the prior image has an
                    # allow-listed registry ref to name it by. Stack down or no such ref: tag stays.
                    return bad(jr="restarting", tag="P" if s.prior == "valid" else "T", post_fail=True)
                if e == "up_fail_recreated":
                    return bad(jr="restarting", tag="T", running="T", post_fail=True)
                run = "T" if e == "ok" else s.running
                return s._replace(pc=nxt, tag="T", running=run, jr="restarted", tid=run if run != "none" else "")
            if pc == "health_gate":
                return s._replace(pc=nxt) if e == "ok" else bad(post_fail=True)
            return s._replace(pc="rb_pull", jr="verified", tid="T") if e == "ok" else bad(post_fail=True)
        # ---- inline rollback stages (ContinueOnError)
        if e == "skip":
            return s._replace(pc=nxt)
        s = s._replace(rb_att=True)
        rbfail = lambda **kw: s._replace(pc=nxt, rb_failed=True, **kw)  # noqa: E731
        if pc == "rb_pull":
            return s._replace(pc=nxt) if e == "ok" else rbfail()
        if pc == "rb_restart":
            if e == "tag_fail":
                return rbfail()
            if e == "up_fail_stale":
                return rbfail(tag="P")
            if e == "up_fail_recreated":
                return rbfail(tag="P", running="P")
            return s._replace(pc=nxt, tag="P", running="P" if e == "ok" else s.running, rb_restarted=True)
        if pc == "rb_health":
            return s._replace(pc=nxt) if e == "ok" else rbfail()
        return s._replace(pc=nxt, rb_ok=True) if e == "ok" else rbfail()

    def observe(self, s):
        o = s._asdict()
        o["terminal"] = s.pc == "done"
        o["danger_phase"] = s.jr in ("restarting", "restarted", "verified")
        o["rollback_armed"] = rollback_armed(s)
        o["tag_ahead"] = s.tag == "T" and s.running != "T" and not s.same
        o["serving_healthy"] = healthy(s, s.running)
        o["jr_rank"] = STAGES_SEEN[s.jr] + (s.jr == "restarting") * 0.5
        o["rb_resolved"] = s.rb_ok or s.rb_failed or s.pc == "crashed"
        o["stopped"] = s.pc in ("done", "crashed", "recovered")
        o["reconcile"] = reconcile_for_state(s)[0] if s.pc in ("crashed", "recovered") else "n/a"
        return o


# ------------------------------------------------------------------ journal record + reconcile spec
def record_for_state(s):
    """Fields the real journal record would hold at this point (journal_phases.go foldIdentifiers)."""
    seen = STAGES_SEEN[s.jr]
    return {"phase": s.jr,
            "prior_ref": seen >= 1 and s.prior == "valid",
            "prior_id": "P" if seen >= 1 and s.prior != "down" else "",
            "target_ref": seen >= 2,
            "target_id": s.tid}


STAGES_SEEN = {"admitted": 0, "captured": 1, "resolved": 2, "pulled": 3, "restarting": 3, "restarted": 4,
               "verified": 5, "removed": 9}


def reconcile_inputs_for_state(s):
    """How a startup caller would populate reconcileInputs from the record plus Docker truth.
    ASSUMPTION: no such caller exists on main (contract AGT-900); this mapping is ours."""
    r = record_for_state(s)
    target_ref_present = r["target_ref"]
    return {"kind": "upgrades.apply", "mode": "", "phase": s.jr, "attempts": 0, "max_attempts": 3,
            "ref_valid": bool(r["prior_ref"] or target_ref_present),
            "running_id": "" if s.running == "none" else s.running, "target_id": r["target_id"],
            "prior_id": r["prior_id"],
            "running_digests": [] if s.running == "none" or (s.running == "P" and s.prior != "valid") else [s.running],
            "target_digests": ["T"] if target_ref_present else [],
            "prior_digests": ["P"] if r["prior_ref"] else [],
            "tag_digests": [s.tag]}


def reconcile_spec(i):
    """Reference decision table, transcribed from roadmap/RISK-022-PR-E design section 0 (v2)."""
    def same(a, b, da, db):
        return (a != "" and a == b) or bool(set(da) & set(db))
    if i["kind"] == "rollbacks.create" and i["mode"] == "data":
        return "data_manual", "data_window_manual"
    if not i["ref_valid"]:
        return "loud_stop", "invalid_record_ref"
    if i["max_attempts"] > 0 and i["attempts"] >= i["max_attempts"]:
        return "loud_stop", "reconcile_exhausted"
    live_t = same(i["running_id"], i["target_id"], i["running_digests"], i["target_digests"])
    live_p = same(i["running_id"], i["prior_id"], i["running_digests"], i["prior_digests"])
    p_eq_t = same(i["prior_id"], i["target_id"], i["prior_digests"], i["target_digests"])
    tag_t = bool(set(i["tag_digests"]) & set(i["target_digests"]))
    if live_t:
        return "verify_adopt_else_rollback", "live_target_prior_equals_target" if p_eq_t else "live_target"
    if tag_t:
        return "reup", "tag_advanced_container_stale"
    if live_p:
        return "noop", "already_on_prior"
    if i["phase"] in SAFE:
        return "noop", "safe_boundary_confirmed"
    if i["prior_id"] != "" or i["prior_digests"]:
        return "rollback_to_prior", "indeterminate_restore_prior"
    return "loud_stop", "no_recovery_target"


def reconcile_for_state(s):
    return reconcile_spec(reconcile_inputs_for_state(s))


MODEL = ApplyModel()
