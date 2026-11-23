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

// TestInlineRollback_ArmFailClosed: when the armed marker cannot be written
// (here the record is corrupted while the rollback pull runs), the rollback
// refuses to move the tag: no `docker tag` to the prior image, and the op fails
// rollback_failed.
func TestInlineRollback_ArmFailClosed(t *testing.T) {
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
	if op["state"] != "failed" || op["failure_reason"] != "rollback_failed" {
		t.Errorf("want failed/rollback_failed, got %v/%v", op["state"], op["failure_reason"])
	}
	if rig.pinnedFor("tag", digOld) {
		t.Error("the rollback moved the tag although RollbackArmed could not be recorded")
	}
	if res := resultMap(t, op); res["rollback_succeeded"] != false {
		t.Errorf("rollback_succeeded = %v, want false", res["rollback_succeeded"])
	}
}
