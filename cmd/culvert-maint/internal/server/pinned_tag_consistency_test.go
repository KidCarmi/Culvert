// Regression tests for the fixed-tag ⇄ running-container consistency of
// upgrades.apply, and for rollback-target selection.
//
// The invariant under test (docker-compose.yml `proxy:`/`cli:` comments,
// roadmap/D1.6c-pin-value-binding-plan.md §9 F5): while the agent is alive, an
// apply must not END with culvert/proxy:pinned pointing at an image the proxy
// container is not running when the agent can prove which image runs and can
// name it at the sudo boundary. The `cli` (backup/restore) service and every
// later `docker compose up -d` resolve that tag, so a tag left ahead of the
// container is a pending, un-health-gated upgrade.
//
// These tests use the applyRig in dockerModel mode. The model encodes behaviour
// OBSERVED ON A REAL DAEMON (Docker 29.10 / Compose v5.7.1), not assumed:
//
//   - `docker compose up -d` recreates the proxy container whenever the tag
//     resolves to a different image id, and leaves it alone when it does not;
//   - an `up` that fails while loading the project (bad compose/override file)
//     or while pulling another service's image leaves the old container
//     running, with the tag already moved;
//   - an `up` that fails after recreating (start error, unhealthy dependency,
//     port conflict) leaves a non-running container on the NEW image;
//   - the containerd image store lists `culvert/proxy@sha256:…` in RepoDigests
//     for the image carrying the local tag, sorted before the registry repo.
package server

import (
	"strings"
	"sync"
	"testing"

	"culvert-maint/internal/journal"
)

// modelRig is an applyRig whose fake Docker tracks the fixed tag and the
// running container separately.
func modelRig(t *testing.T) *applyRig {
	t.Helper()
	rig := startApplyRig(t)
	rig.dockerModel = true
	return rig
}

// failUpgradeUpBeforeRecreate fails the `up` that would bring up the NEW image
// without changing the container — the project could not even be loaded.
func failUpgradeUpBeforeRecreate(rig *applyRig) func(argv, env []string) bool {
	return func(argv, _ []string) bool { return argvHas(argv, "up") && rig.tag() == digNew }
}

// failUpgradeUpAfterRecreate fails the `up` for the NEW image AFTER compose
// replaced the container: the container now carries the new image but is not
// running.
func failUpgradeUpAfterRecreate(rig *applyRig) func(argv, env []string) bool {
	return func(argv, _ []string) bool {
		if !argvHas(argv, "up") || rig.tag() != digNew {
			return false
		}
		rig.mu.Lock()
		rig.runningDigest = digNew
		rig.containerDown = true
		rig.mu.Unlock()
		return true
	}
}

func assertTagAndRunning(t *testing.T, rig *applyRig, wantTag, wantRunning string) {
	t.Helper()
	if got := rig.tag(); got != wantTag {
		t.Errorf("culvert/proxy:pinned points at %s, want %s", short(got), short(wantTag))
	}
	if got := rig.currentRunning(); got != wantRunning {
		t.Errorf("container runs %s, want %s", short(got), short(wantRunning))
	}
}

func short(d string) string {
	switch d {
	case digOld:
		return "OLD"
	case digNew:
		return "NEW"
	}
	return d
}

func assertJournalEmpty(t *testing.T, rig *applyRig) {
	t.Helper()
	recs, err := rig.journal.List()
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("journal: %d record(s) left at terminal, want 0", len(recs))
	}
}

// Successful upgrade: tag and container both end on the new image.
func TestApply_PinnedTag_SuccessfulUpgrade(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded", op["state"])
	}
	assertTagAndRunning(t, rig, digNew, digNew)
	assertJournalEmpty(t, rig)
	if n := rig.countCommand("tag"); n != 1 {
		t.Errorf("a clean upgrade must tag exactly once; got %d", n)
	}
}

// Unchanged image: nothing is retagged or restarted.
func TestApply_PinnedTag_AlreadyCurrent_TagUntouched(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.targetDigest = digOld

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + ":same"})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded", op["state"])
	}
	if rig.sawCommand("tag") || rig.sawCommand("up") {
		t.Error("already-current apply must not tag or restart")
	}
	assertTagAndRunning(t, rig, digOld, digOld)
}

// THE DEFECT: `up` fails before recreating the container and inline rollback is
// disabled. The old image keeps running; the fixed tag must not be left on the
// new one once the journal record is retired.
func TestApply_PinnedTag_UpFailsBeforeRecreate_RollbackDisabled_TagRestored(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFn = failUpgradeUpBeforeRecreate(rig)

	op, opID := rig.acceptAndWait(t, map[string]interface{}{
		"image_ref": repo + "@sha256:" + digNew, "rollback_on_failure": false,
	})
	if op["state"] != "failed" || op["failure_reason"] != "command_error" {
		t.Fatalf("want failed/command_error; got %v/%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_attempted"] != false || res["rollback_skipped_reason"] != "disabled" {
		t.Errorf("rollback contract changed: %v", res)
	}
	assertTagAndRunning(t, rig, digOld, digOld)
	assertJournalEmpty(t, rig)
	if got := res["final_running_digest"]; got != "sha256:"+digOld {
		t.Errorf("final_running_digest = %v, want the prior digest (the old container never stopped)", got)
	}
	if rig.countCommand("pull") != 1 {
		t.Errorf("restoring the tag must not pull (the prior image is local); pulls=%d", rig.countCommand("pull"))
	}
	if rig.countCommand("up") != 1 {
		t.Errorf("restoring the tag must not restart anything; up=%d", rig.countCommand("up"))
	}
	if log := rig.opLog(t, opID); !strings.Contains(log, "culvert/proxy:pinned restored to prior") {
		t.Errorf("op log must record the tag restore; log:\n%s", log)
	}
}

// Same failure, rollback enabled but its pull fails (registry unreachable): the
// rollback never reaches its own retag, so the tag restore must not depend on it.
func TestApply_PinnedTag_UpFailsBeforeRecreate_RollbackPullFails_TagRestored(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	up := failUpgradeUpBeforeRecreate(rig)
	rig.failFn = func(argv, env []string) bool {
		return up(argv, env) || (argvHas(argv, "pull") && envContains(argv, digOld))
	}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "rollback_failed" {
		t.Fatalf("want failed/rollback_failed; got %v/%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_attempted"] != true || res["rollback_succeeded"] != false {
		t.Errorf("want attempted=true succeeded=false; got %v", res)
	}
	assertTagAndRunning(t, rig, digOld, digOld)
	if got := res["final_running_digest"]; got != "sha256:"+digOld {
		t.Errorf("final_running_digest = %v, want the prior digest", got)
	}
}

// Same failure with rollback enabled and working: the outcome contract is
// unchanged (rollback still fires and succeeds) and the tag ends on prior.
func TestApply_PinnedTag_UpFailsBeforeRecreate_RollbackSucceeds(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFn = failUpgradeUpBeforeRecreate(rig)

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "command_error" {
		t.Fatalf("want failed/command_error; got %v/%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_attempted"] != true || res["rollback_succeeded"] != true {
		t.Errorf("a restart failure must still trigger rollback; got %v", res)
	}
	assertTagAndRunning(t, rig, digOld, digOld)
	assertJournalEmpty(t, rig)
}

// No restorable prior ref (image without a registry digest): the agent cannot
// name the prior image at the sudo boundary, so the tag stays on the target —
// the residual. It must say so, and must not report the new image as running.
func TestApply_PinnedTag_UpFailsBeforeRecreate_NoPriorRef_ReportedNotGuessed(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.noPriorDigest = true
	rig.failFn = failUpgradeUpBeforeRecreate(rig)

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "command_error" {
		t.Fatalf("want failed/command_error; got %v/%v", op["state"], op["failure_reason"])
	}
	res := resultMap(t, op)
	if res["rollback_skipped_reason"] != "no_prior_digest" {
		t.Errorf("want skipped=no_prior_digest; got %v", res)
	}
	if n := rig.countCommand("tag"); n != 1 {
		t.Errorf("no prior ref → no second tag; got %d tag commands", n)
	}
	assertTagAndRunning(t, rig, digNew, digOld) // documented residual
	if got := res["final_running_digest"]; got == "sha256:"+digNew {
		t.Errorf("final_running_digest claims the NEW image runs; the old container never stopped")
	}
	if log := rig.opLog(t, opID); !strings.Contains(log, "culvert/proxy:pinned LEFT at the target") {
		t.Errorf("op log must warn that the tag is ahead of the container; log:\n%s", log)
	}
}

// `up` fails AFTER recreating: the container carries the new image. Restoring
// the tag to prior here would put the tag BEHIND the container — must not happen.
func TestApply_PinnedTag_UpFailsAfterRecreate_RollbackDisabled_TagNotMoved(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFn = failUpgradeUpAfterRecreate(rig)

	op, _ := rig.acceptAndWait(t, map[string]interface{}{
		"image_ref": repo + "@sha256:" + digNew, "rollback_on_failure": false,
	})
	if op["state"] != "failed" || op["failure_reason"] != "command_error" {
		t.Fatalf("want failed/command_error; got %v/%v", op["state"], op["failure_reason"])
	}
	if n := rig.countCommand("tag"); n != 1 {
		t.Errorf("indeterminate container → the tag must not be moved again; got %d tag commands", n)
	}
	assertTagAndRunning(t, rig, digNew, digNew)
	// The container carries the new image but is NOT running, so no capture can establish
	// what runs. The result used to assert the upgrade digest here (an inference); evidence-
	// based reporting says unverified instead of guessing (owner decision 2).
	res := resultMap(t, op)
	if res["final_running_state"] != finalRunningUnverified || res["final_running_digest"] != "" || res["final_running_image_id"] != "" {
		t.Errorf("no running container could be captured: want unverified with empty digest and image id; got state=%v digest=%v image_id=%v",
			res["final_running_state"], res["final_running_digest"], res["final_running_image_id"])
	}
}

// `up` fails after recreating and rollback is enabled: rollback recreates the
// container on prior; tag and container agree on prior.
func TestApply_PinnedTag_UpFailsAfterRecreate_RollbackRestores(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFn = failUpgradeUpAfterRecreate(rig)

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	res := resultMap(t, op)
	if op["state"] != "failed" || res["rollback_succeeded"] != true {
		t.Fatalf("want failed + rollback_succeeded; got %v %v", op["state"], res)
	}
	assertTagAndRunning(t, rig, digOld, digOld)
	if got := res["final_running_digest"]; got != "sha256:"+digOld {
		t.Errorf("final_running_digest = %v, want the prior digest", got)
	}
}

// Health gate fails on the new image, rollback disabled: the new image IS
// running, so tag == container and nothing is retagged.
func TestApply_PinnedTag_HealthFails_RollbackDisabled_TagFollowsContainer(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{
		"image_ref": repo + "@sha256:" + digNew, "rollback_on_failure": false,
	})
	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("want failed/health_failed; got %v/%v", op["state"], op["failure_reason"])
	}
	if n := rig.countCommand("tag"); n != 1 {
		t.Errorf("got %d tag commands, want 1", n)
	}
	assertTagAndRunning(t, rig, digNew, digNew)
}

// Health gate fails, rollback succeeds: tag and container both back on prior.
func TestApply_PinnedTag_HealthFails_RollbackSucceeds(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	res := resultMap(t, op)
	if op["state"] != "failed" || res["rollback_succeeded"] != true {
		t.Fatalf("want failed + rollback_succeeded; got %v %v", op["state"], res)
	}
	assertTagAndRunning(t, rig, digOld, digOld)
	assertJournalEmpty(t, rig)
}

// Health gate fails, rollback's own `up` fails before recreating: the tag is on
// the last known-good (prior) image while the unhealthy new container still
// runs. This direction is deliberately left alone — the tag names the image the
// operator is being paged to converge on, never an un-gated one.
func TestApply_PinnedTag_RollbackUpFails_TagStaysOnKnownGood(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	rig.failFn = func(argv, _ []string) bool { return argvHas(argv, "up") && rig.tag() == digOld }

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "rollback_failed" {
		t.Fatalf("want failed/rollback_failed; got %v/%v", op["state"], op["failure_reason"])
	}
	assertTagAndRunning(t, rig, digOld, digNew)
}

// Interrupted operation: the tag restore runs INSIDE the write-ahead window —
// the PhaseRestarting record is still on disk while the compensating tag
// executes, so an agent death at any point of the sequence
// (barrier → tag target → up fails → tag prior) leaves a durable record for
// startup reconciliation. The record is retired only at terminal.
func TestApply_PinnedTag_RestoreHappensInsideJournalWindow(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFn = failUpgradeUpBeforeRecreate(rig)

	var (
		pmu    sync.Mutex
		phases []journal.Phase
	)
	rig.onCommand = func(argv []string) {
		if !argvHas(argv, "tag") {
			return
		}
		pmu.Lock()
		defer pmu.Unlock()
		recs, err := rig.journal.List()
		if err != nil || len(recs) != 1 {
			phases = append(phases, "MISSING")
			return
		}
		phases = append(phases, recs[0].Phase)
	}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{
		"image_ref": repo + "@sha256:" + digNew, "rollback_on_failure": false,
	})
	if op["state"] != "failed" {
		t.Fatalf("state: got %v want failed", op["state"])
	}
	pmu.Lock()
	defer pmu.Unlock()
	if len(phases) != 2 {
		t.Fatalf("want 2 tag commands (advance + restore), got %d (%v)", len(phases), phases)
	}
	for i, p := range phases {
		if p != journal.PhaseRestarting {
			t.Errorf("tag #%d ran with journal phase %q, want %q (write-ahead barrier must cover it)", i+1, p, journal.PhaseRestarting)
		}
	}
	assertJournalEmpty(t, rig)
}

// Rollback-target selection: on the containerd image store the running image's
// RepoDigests also list the local `culvert/proxy@sha256:…` entry, sorted first.
// That entry is not a registry reference and fails image_allowlist; it must not
// hide the valid registry ref beside it and silently disable auto-rollback.
func TestApply_RollbackTarget_IgnoresLocalTagRepoDigest(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.localTagRepoDigest = true
	rig.unhealthyDigests = map[string]bool{digNew: true}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	res := resultMap(t, op)
	if res["rollback_attempted"] != true || res["rollback_succeeded"] != true {
		t.Fatalf("auto-rollback must fire with a valid registry prior ref present; result=%v", res)
	}
	if res["rollback_skipped_reason"] != "" {
		t.Errorf("rollback_skipped_reason = %v, want empty", res["rollback_skipped_reason"])
	}
	assertTagAndRunning(t, rig, digOld, digOld)
	if !rig.pinnedFor("pull", repo+"@sha256:"+digOld) {
		t.Error("rollback must pull the allow-listed registry ref of the prior image")
	}
}
