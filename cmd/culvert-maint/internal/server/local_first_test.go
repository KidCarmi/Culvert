// Local-first rollback / pull (RISK-022 PR-E design §4 — the no-offline floor).
package server

import (
	"strings"
	"testing"
)

// (1) Rollback target already local ⇒ the pull template is NEVER invoked,
// the op succeeds, and the op log records the skip.
func TestRollback_LocalFirst_SkipsPullWhenImagePresent(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.localImages = map[string]bool{digNew: true}

	target := repo + "@sha256:" + digNew
	op, opID := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": target})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded; op=%+v", op["state"], op)
	}
	if rig.sawCommand("pull") {
		t.Error("image present locally: the pull template must not be invoked")
	}
	if !rig.pinnedFor("tag", digNew) || !rig.sawCommand("up") {
		t.Error("local-first rollback must still retag + up")
	}
	if logStr := rig.opLog(t, opID); !strings.Contains(logStr, "rollback_pull: skipped (image present locally)") {
		t.Errorf("op-log must record the skip:\n%s", logStr)
	}
}

// (2) Rollback target absent ⇒ pulls exactly as before.
func TestRollback_LocalFirst_PullsWhenAbsent(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.localImages = map[string]bool{digOld: true} // target digNew NOT local

	target := repo + "@sha256:" + digNew
	op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": target})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded; op=%+v", op["state"], op)
	}
	if !rig.pinnedFor("pull", digNew) {
		t.Error("image absent locally: the pull must run")
	}
}

// (3) Registry unreachable + image present ⇒ rollback still succeeds (the
// pre-change behaviour was failed(command_error) with the bad image running).
func TestRollback_LocalFirst_RegistryDownWithImagePresentSucceeds(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.localImages = map[string]bool{digNew: true}
	rig.failFor = []string{"pull"} // registry unreachable

	target := repo + "@sha256:" + digNew
	op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": target})
	if op["state"] != "succeeded" {
		t.Fatalf("registry down must not fail a rollback whose image is local; op=%+v", op)
	}
	if rig.sawCommand("pull") {
		t.Error("pull must never have been attempted")
	}
}

// Inline auto-rollback inherits the floor: an unhealthy new image rolls back
// to the (locally present) prior with the registry dead.
func TestUpgradeApply_InlineRollback_LocalFirst_RegistryDownForPrior(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.localImages = map[string]bool{digOld: true} // prior local, target must be pulled
	rig.unhealthyDigests = map[string]bool{digNew: true}
	rig.failFn = func(argv, _ []string) bool { // registry refuses the PRIOR only
		return argvHas(argv, "pull") && strings.Contains(strings.Join(argv, " "), digOld)
	}

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("expected failed(health_failed) with service restored; op=%+v", op)
	}
	res := resultMap(t, op)
	if res["rollback_succeeded"] != true || res["final_running_digest"] != "sha256:"+digOld {
		t.Fatalf("inline rollback must succeed from the local prior: %+v", res)
	}
	if rig.pinnedFor("pull", digOld) {
		t.Error("the prior must not be pulled when it is present locally")
	}
	if !strings.Contains(rig.opLog(t, opID), "rollback_pull: skipped (image present locally)") {
		t.Error("op-log must record the local-first skip on the inline path")
	}
}

// The upgrade `pull` stage applies the same floor: a target already local is
// not re-pulled, and the upgrade still restarts + verifies.
func TestUpgradeApply_PullSkippedWhenTargetPresentLocally(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.localImages = map[string]bool{digNew: true}

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v; op=%+v", op["state"], op)
	}
	if rig.sawCommand("pull") {
		t.Error("target present locally: pull must be skipped")
	}
	if !rig.pinnedFor("tag", digNew) || !rig.sawCommand("up") {
		t.Error("upgrade must still retag + up")
	}
	if !strings.Contains(rig.opLog(t, opID), "pull: skipped (image present locally)") {
		t.Error("op-log must record the skip")
	}
}

// Fail-safe parse: an inspect that succeeds but does not name the ref is NOT
// "present".
func TestRepoDigestsFromInspect_StrictPresence(t *testing.T) {
	ref := repo + "@sha256:" + digNew
	if containsString(repoDigestsFromInspect([]byte(`[{"RepoDigests":["`+repo+`@sha256:`+digOld+`"]}]`)), ref) {
		t.Error("a record naming another digest must not count as present")
	}
	if repoDigestsFromInspect([]byte(`not json`)) != nil {
		t.Error("unparseable output must yield nil")
	}
	if got := imageIDFromInspect([]byte(`[{"Id":"sha256:` + cfgNew + `"}]`)); got != "sha256:"+cfgNew {
		t.Errorf("Id: got %q", got)
	}
	if got := imageIDFromInspect([]byte(`[{"Id":"garbage"}]`)); got != "" {
		t.Errorf("malformed Id must be rejected, got %q", got)
	}
}
