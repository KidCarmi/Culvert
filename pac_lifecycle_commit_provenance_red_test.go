// 2F-E correction round 6 — RED proof, written and executed on the untouched
// round-5 candidate 51ee2549 BEFORE any product change.
//
// Round 5 (`lastWriteId`) attributes a content-level "committed" verdict to
// an intent only when the store's writer identity is the intent's
// operationId. That identity belongs to the ENTIRE profiles document: a
// legitimate later write of an UNRELATED profile or pool preserves X's
// active profile byte-for-byte but replaces the document-level identity
// with a random one, so a reconciliation of X (whose committed marker could
// not be persisted — the truthful published:true / pending_reconciliation
// answer) sees "target content present, written by someone else" and
// records X as REFUSED (concurrent_write): the proven commit is
// contradicted and X's history revision, success audit and config version
// are lost.
//
// Y1 mutates an unrelated PROFILE after the commit; Y2 mutates only a POOL.
// Both go through the production admin handlers (which serialize on
// pacProfilesAPIMu themselves — no test-side synchronization), are
// channel/fault controlled (a stage hook arms the committed-write fault, no
// sleeps), and restart from the durable files. X1 (round 5) stays as the
// opposite control: another writer that actually installs X's target is
// never attributed to X.
package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

func TestPACBoundary_Y1_GenuineCommitSurvivesUnrelatedProfileWrite(t *testing.T) {
	pacProvenanceGenuineCommit(t, func(t *testing.T) {
		t.Helper()
		body := `{"id":"other","name":"Other renamed after the commit","enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[],"revision":1}`
		if rec := pacFenceReq(t, "PUT", "/api/pac/profiles/other", body, pacIntentIP); rec.Code != http.StatusOK {
			t.Fatalf("unrelated profile PUT: %d %s", rec.Code, rec.Body.String())
		}
	}, func(t *testing.T, stage string) {
		t.Helper()
		if o, ok := pacBoundaryProfile(t, "other"); !ok || o.Name != "Other renamed after the commit" || o.Revision != 2 {
			t.Errorf("%s: the unrelated profile mutation must survive: %+v ok=%v", stage, o, ok)
		}
	})
}

func TestPACBoundary_Y2_GenuineCommitSurvivesPoolOnlyWrite(t *testing.T) {
	pacProvenanceGenuineCommit(t, func(t *testing.T) {
		t.Helper()
		spare, ok := pacProfiles.PoolByID("spare")
		if !ok {
			t.Fatal("fixture pool spare missing")
		}
		body := fmt.Sprintf(`{"id":"spare","name":"Spare renamed after the commit","endpoints":[{"host":"proxy-spare.example","port":8080}],"etag":%q}`, pac.PoolETag(spare))
		if rec := pacFenceReq(t, "PUT", "/api/pac/pools/spare", body, pacIntentIP); rec.Code != http.StatusOK {
			t.Fatalf("pool-only PUT: %d %s", rec.Code, rec.Body.String())
		}
	}, func(t *testing.T, stage string) {
		t.Helper()
		if p, ok := pacProfiles.PoolByID("spare"); !ok || p.Name != "Spare renamed after the commit" {
			t.Errorf("%s: the pool-only mutation must survive: %+v ok=%v", stage, p, ok)
		}
	})
}

// pacProvenanceGenuineCommit is the shared Y proof: X commits for real
// (active_committed reached), its committed lifecycle write fails, the
// response positively reports the commit as pending reconciliation, the
// unrelated mutation lands, and a restart from the durable files must
// reconcile X as COMMITTED exactly once — history revision, success audit
// and operation-keyed config version completed — with the unrelated
// mutation intact.
func pacProvenanceGenuineCommit(t *testing.T, mutate func(t *testing.T), assertMutation func(t *testing.T, stage string)) {
	t.Helper()
	pacBoundaryEnv(t)
	pacBoundarySeedOther(t, "Other")
	opX := uuid.NewString()
	committed := make(chan struct{}, 1)
	pacLifecycleStageHook = func(stage string) {
		if stage == "active_committed" {
			// The authoritative write landed; the committed marker cannot.
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
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Name != "Committed for real" || p.Revision != 2 {
		t.Fatalf("X's candidate must be the active profile: %+v ok=%v", p, ok)
	}
	if pacIntentAudits(opX, "pac.profile_publish") != 0 || pacIntentVersionsFor(opX) != 0 {
		t.Fatal("no post-commit effect may land before the committed progress is durable")
	}
	// A legitimate, unrelated write after the handler released the boundary.
	mutate(t)
	assertMutation(t, "after the unrelated write")
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Name != "Committed for real" || p.Revision != 2 {
		t.Fatalf("the unrelated write must not touch X's active profile: %+v ok=%v", p, ok)
	}
	// Restart from the durable files: the lifecycle record still carries the
	// pre-commit pending intent; the active store carries X's commit.
	pacIntentRestartComplete(t)
	assertMutation(t, "after restart")
	if pacIntentActiveName(t) != "Committed for real" {
		t.Fatal("the active store must still be X's committed candidate after restart")
	}
	pacProvenanceAssertCommittedOnce(t, opX)
	// Repeated reconciliation, GET and restart change nothing further.
	pacIntentGet(t)
	pacIntentRestartComplete(t)
	assertMutation(t, "after second restart")
	pacProvenanceAssertCommittedOnce(t, opX)
}

// pacProvenanceAssertCommittedOnce requires X to be reconciled as committed
// exactly once: one history revision naming it, one success audit, one
// operation-keyed config version, the operation found as a recorded commit
// (never aborted/concurrent_write), historyState recorded.
func pacProvenanceAssertCommittedOnce(t *testing.T, opX string) {
	t.Helper()
	g := pacEvidenceGet(t, "?operationId="+opX)
	revs := 0
	for _, r := range g["revisions"].([]any) {
		if r.(map[string]any)["operationId"] == opX {
			revs++
		}
	}
	if revs != 1 {
		t.Errorf("exactly one history revision must name X, got %d", revs)
	}
	if n := pacIntentAudits(opX, "pac.profile_publish"); n != 1 {
		t.Errorf("exactly one success audit for X, got %d", n)
	}
	if n := pacIntentVersionsFor(opX); n != 1 {
		t.Errorf("exactly one operation-keyed config version for X, got %d", n)
	}
	op, _ := g["operation"].(map[string]any)
	if op == nil || op["found"] != true || op["state"] == pac.OpAborted {
		t.Errorf("X must be found as a commit, never aborted/concurrent_write: %v", g["operation"])
	}
	if g["historyState"] != pac.HistoryStateRecorded {
		t.Errorf("historyState = %v, want recorded", g["historyState"])
	}
}
