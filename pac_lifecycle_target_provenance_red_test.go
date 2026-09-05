// 2F-E correction round 7 — RED proof, written and executed on the untouched
// round-6 candidate b1495ea8 BEFORE any product change.
//
// Round 6 keeps a commit's per-profile provenance across writes of OTHER
// profiles and pools. It is still last-writer provenance: a later legitimate
// write of the SAME target profile — before X's pending lifecycle record is
// reconciled — replaces X's identity, and the historical fact already proven
// to the client (X performed the authoritative commit) is lost:
//
//	Z1: the target stays on the later content → pac.ClassifyOutcome is
//	    ambiguous → X is recorded as AMBIGUOUS, never as the commit it was;
//	Z2: a replace-import returns the target to X's exact revision/spec under
//	    another writer identity → content says committed, provenance says
//	    someone else → X is recorded as REFUSED (concurrent_write);
//	Z3: the same via the config-version rollback path.
//
// In every case X's history revision, success audit and operation-keyed
// config version are never completed. Channel/fault controlled (a stage hook
// arms the committed-write fault, no sleeps), through the production
// handlers, restarting from the durable files. X1 stays the false-attribution
// control; Y1/Y2 stay the unrelated-write controls.
package main

import (
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

const pacTargetLaterName = "Later by someone else"

func TestPACBoundary_Z1_GenuineCommitSurvivesLaterTargetWrite(t *testing.T) {
	opX, spec := pacTargetGenuineCommit(t)
	pacTargetPutLater(t)
	pacTargetRestartAndAssert(t, opX, spec, func(t *testing.T, stage string, g map[string]any) {
		t.Helper()
		if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Name != pacTargetLaterName || p.Revision != 3 {
			t.Errorf("%s: the later target write must stay authoritative: %+v ok=%v", stage, p, ok)
		}
		// currentlyActive is derived from the committed identity against the
		// authoritative active identity (round 2): X's revision is recorded
		// at store revision 2 / its spec digest, while the active store is
		// at revision 3 with a different spec — so X is committed, not active.
		op, _ := g["operation"].(map[string]any)
		if op == nil || op["storeRevision"] != float64(2) || op["specDigest"] != pac.ProfileSpecDigest(spec) {
			t.Errorf("%s: X's committed identity must be revision 2 / its spec digest: %v", stage, op)
		}
		if g["activeRevision"] == float64(2) || g["activeSpecDigest"] == pac.ProfileSpecDigest(spec) {
			t.Errorf("%s: X must not read as currently active: activeRevision=%v activeSpecDigest=%v", stage, g["activeRevision"], g["activeSpecDigest"])
		}
	})
}

func TestPACBoundary_Z2_GenuineCommitSurvivesReplaceImportRestoringItsSpec(t *testing.T) {
	opX, spec := pacTargetGenuineCommit(t)
	pacTargetPutLater(t)
	pacTransitionReplaceImport(t, spec)
	pacTargetRestartAndAssert(t, opX, spec, pacTargetAssertRestored(spec))
}

func TestPACBoundary_Z3_GenuineCommitSurvivesRollbackRestoringItsSpec(t *testing.T) {
	opX, spec := pacTargetGenuineCommit(t)
	pacTargetPutLater(t)
	pacTransitionRollback(t, spec)
	pacTargetRestartAndAssert(t, opX, spec, pacTargetAssertRestored(spec))
}

// pacTargetGenuineCommit publishes X for real (active_committed reached),
// with its committed lifecycle write failing, and asserts the truthful
// published:true / pending_reconciliation answer. It returns X's operationId
// and the committed spec (revision 2).
func pacTargetGenuineCommit(t *testing.T) (opX string, spec pac.Profile) {
	t.Helper()
	pacBoundaryEnv(t)
	opX = uuid.NewString()
	committed := make(chan struct{}, 1)
	pacLifecycleStageHook = func(stage string) {
		if stage == "active_committed" {
			pacLifecyclePersistHook = func(string) error { return errPACTransitionInjected }
			select {
			case committed <- struct{}{}:
			default:
			}
		}
	}
	rec := pacIntentPublish(t, opX, 1, pacIntentDraft("Committed for real", false), "")
	pacLifecycleStageHook, pacLifecyclePersistHook = nil, nil
	select {
	case <-committed:
	default:
		t.Fatalf("active_committed never reached: %d %s", rec.Code, rec.Body.String())
	}
	m := pacIntentJSON(t, rec)
	if rec.Code != http.StatusOK || m["published"] != true || m["historyState"] != pac.HistoryStatePendingReconciliation || m["operationId"] != opX {
		t.Fatalf("a proven commit whose committed marker could not be persisted must positively report published:true pending_reconciliation: %d %s", rec.Code, rec.Body.String())
	}
	spec = pacTransitionSpec("Committed for real", 2)
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || pac.ProfileSpecDigest(p) != pac.ProfileSpecDigest(spec) || p.Revision != 2 {
		t.Fatalf("X's candidate must be the active profile: %+v ok=%v", p, ok)
	}
	if pacIntentAudits(opX, "pac.profile_publish") != 0 || pacIntentVersionsFor(opX) != 0 {
		t.Fatal("no post-commit effect may land before the committed progress is durable")
	}
	return opX, spec
}

// pacTargetPutLater is a legitimate later write of the SAME target through
// the production PUT (revision 2 → 3, a different spec).
func pacTargetPutLater(t *testing.T) {
	t.Helper()
	body := `{"id":"branch-il","name":"` + pacTargetLaterName + `","enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[],"revision":2}`
	if rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", body, pacIntentIP); rec.Code != http.StatusOK {
		t.Fatalf("later target PUT: %d %s", rec.Code, rec.Body.String())
	}
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Name != pacTargetLaterName || p.Revision != 3 {
		t.Fatalf("the later write must be active: %+v ok=%v", p, ok)
	}
}

func pacTargetAssertRestored(spec pac.Profile) func(t *testing.T, stage string, g map[string]any) {
	return func(t *testing.T, stage string, g map[string]any) {
		t.Helper()
		if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Revision != 2 || pac.ProfileSpecDigest(p) != pac.ProfileSpecDigest(spec) {
			t.Errorf("%s: the restored target (X's exact revision/spec) must stay authoritative: %+v ok=%v", stage, p, ok)
		}
	}
}

// pacTargetRestartAndAssert restarts from the durable files and requires X
// to be reconciled as COMMITTED exactly once — never ambiguous, never
// concurrent_write — with no duplicate across a repeated GET/restart.
func pacTargetRestartAndAssert(t *testing.T, opX string, spec pac.Profile, extra func(t *testing.T, stage string, g map[string]any)) {
	t.Helper()
	pacIntentRestartComplete(t)
	for _, stage := range []string{"after restart", "after repeated GET", "after second restart"} {
		if stage == "after second restart" {
			pacIntentRestartComplete(t)
		}
		g := pacEvidenceGet(t, "?operationId="+opX)
		pacProvenanceAssertCommittedOnce(t, opX)
		if g["ambiguous"] != nil {
			t.Errorf("%s: X must never be settled as ambiguous: %v", stage, g["ambiguous"])
		}
		if op, _ := g["operation"].(map[string]any); op != nil && (op["state"] == pac.OpAborted || op["status"] == float64(http.StatusConflict)) {
			t.Errorf("%s: X must never be settled as refused/concurrent_write: %v", stage, op)
		}
		extra(t, stage, g)
	}
	_ = spec
}
