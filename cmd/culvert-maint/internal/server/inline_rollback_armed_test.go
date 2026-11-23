package server

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// armedAtTag observes the journal record at the moment each `docker tag` runs
// and returns, per tagged digest, whether RollbackArmed was already durable.
type armedAtTag struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (a *armedAtTag) hook(t *testing.T, rig *applyRig) func(argv []string) {
	return func(argv []string) {
		if !argvHas(argv, "tag") {
			return
		}
		recs, err := rig.journal.List()
		if err != nil || len(recs) != 1 {
			t.Errorf("journal at `tag`: %d records, err=%v", len(recs), err)
			return
		}
		for _, arg := range argv {
			if d := digestRE.FindString(arg); d != "" {
				a.mu.Lock()
				a.seen[strings.TrimPrefix(d, "sha256:")] = recs[0].RollbackArmed
				a.mu.Unlock()
			}
		}
	}
}

// TestInlineRollback_ArmedDurablyBeforeRollbackTag: the forward `docker tag`
// (to the target) runs with RollbackArmed unset; the rollback's `docker tag`
// (back to the prior image) runs only after RollbackArmed is durable in the
// record. This is the evidence a startup reconcile needs to never adopt the
// target of an interrupted rollback (N3).
func TestInlineRollback_ArmedDurablyBeforeRollbackTag(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	obs := &armedAtTag{seen: map[string]bool{}}
	rig.onCommand = obs.hook(t, rig)

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if res := resultMap(t, op); res["rollback_succeeded"] != true {
		t.Fatalf("rollback did not succeed: %+v", res)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	armed, sawForward := obs.seen[digNew]
	if !sawForward || armed {
		t.Errorf("forward tag: seen=%v armed=%v, want seen and NOT armed", sawForward, armed)
	}
	armed, sawRollback := obs.seen[digOld]
	if !sawRollback || !armed {
		t.Errorf("rollback tag: seen=%v armed=%v, want seen and armed", sawRollback, armed)
	}
}

// TestInlineRollback_ArmWriteFailureStillRollsBack: when the armed marker
// cannot be written (here the record is corrupted while the rollback pull
// runs), the rollback still moves the tag back and restarts the prior image.
// The marker only feeds the opt-in startup reconcile, which never acts on an
// unarmed record (TestReconcileDecisionV2 "tag_on_prior_rollback_unproven"), so
// refusing the rollback would only leave the failed target running.
func TestInlineRollback_ArmWriteFailureStillRollsBack(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	rig.onCommand = func(argv []string) {
		if !argvHas(argv, "pull") || !strings.Contains(strings.Join(argv, " "), digOld) {
			return
		}
		recs, err := rig.journal.List()
		if err != nil || len(recs) != 1 {
			t.Errorf("journal at rollback pull: %d records, err=%v", len(recs), err)
			return
		}
		p := filepath.Join(rig.journal.Dir(), recs[0].OpID+".json")
		if werr := os.WriteFile(p, []byte("{not json"), 0o600); werr != nil {
			t.Errorf("corrupt record: %v", werr)
		}
	}

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if !rig.pinnedFor("tag", digOld) {
		t.Error("the rollback did not move the tag back to the prior image")
	}
	if got := rig.currentRunning(); got != digOld {
		t.Errorf("the world runs %s after rollback, want the prior %s", short(got), short(digOld))
	}
	res := resultMap(t, op)
	if res["rollback_succeeded"] != true {
		t.Errorf("rollback_succeeded = %v, want true (state=%v failure_reason=%v)", res["rollback_succeeded"], op["state"], op["failure_reason"])
	}
}
