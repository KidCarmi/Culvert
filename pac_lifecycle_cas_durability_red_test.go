package main

// pac_lifecycle_cas_durability_red_test.go — 2F-E CORRECTION ROUND 5 RED
// proof (external freeze review of 3f9877fe: the durability of the
// compare-and-swap refusal decision).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// it fails there. The candidate answers a CAS refusal (`409 concurrent_write`)
// as a TERMINAL decision even when the lifecycle write that records it
// fails: the durable file then still carries the ORIGINAL pending intent,
// the browser clears its marker, and the next reconciliation — which
// classifies the intent from the active revision + candidate digest alone —
// attributes the operation as COMMITTED whenever the intervening writer
// installed the candidate's exact target content beside its own unrelated
// change, minting history, audit and config-version effects for an
// operation that never performed the active write.
//
//   X1  intent persisted → parked before the CAS commit → an
//       out-of-boundary writer installs the candidate's exact target
//       revision/spec PLUS an unrelated profile rename (generation
//       advanced) → the lifecycle write recording the refusal is forced to
//       fail → the response must be a NON-TERMINAL structured outcome that
//       keeps the browser marker (500 outcome_unknown, state pending), never
//       the terminal 409 → restart from the durable files with persistence
//       still failing → the operation is never attributed as committed (no
//       history revision, no success audit, no config version) and the
//       intervening change stays intact → persistence recovers → the
//       refusal becomes DURABLE (decided aborted, 409) and a repeat of the
//       operationId replays it.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

func TestPACBoundary_X1_UndurableCASRefusalIsNonTerminalAndNeverBecomesACommit(t *testing.T) {
	pacBoundaryEnv(t)
	pacBoundarySeedOther(t, "Other")
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	versions := len(configVersions.List())
	release, publishDone, _, _ := pacBoundaryParkedPublish(t, "never")
	// the out-of-boundary writer installs EXACTLY the candidate's target
	// (the v2 draft at revision 2) and renames the unrelated profile
	var target pac.Profile
	if err := json.Unmarshal([]byte(pacIntentDraft("v2", false)), &target); err != nil {
		t.Fatal(err)
	}
	target.Revision = 2
	cfg := pacProfiles.Get()
	for i := range cfg.Profiles {
		switch cfg.Profiles[i].ID {
		case "branch-il":
			cfg.Profiles[i] = target
		case "other":
			cfg.Profiles[i].Name = "Other renamed outside the boundary"
		}
	}
	if err := pacProfiles.Set(cfg); err != nil {
		t.Fatal(err)
	}
	// the lifecycle write that would record the refusal (the record without
	// the pending intent) cannot land; the intent stays the durable truth
	pac.LifecycleWriteHook = func(_ string, next map[string]*pac.ProfileLifecycle) error {
		if r := next["branch-il"]; r != nil && r.PendingOp == nil {
			return errPACTransitionInjected
		}
		return nil
	}
	release()
	pub := <-publishDone
	m := pacIntentJSON(t, pub)
	opX, _ := m["operationId"].(string)
	if opX == "" {
		t.Fatalf("the response must name the operation: %s", pub.Body.String())
	}
	// 4. not a terminal refusal: the browser must keep its marker
	if pub.Code != http.StatusInternalServerError || m["code"] != "outcome_unknown" || m["state"] != pac.OpPending {
		t.Errorf("a refusal that could not be made durable must be a NON-TERMINAL outcome_unknown (500, state pending), got %d %s", pub.Code, pub.Body.String())
	}
	assertNotCommitted := func(stage string) {
		t.Helper()
		g := pacEvidenceGet(t, "?operationId="+opX)
		for _, r := range g["revisions"].([]any) {
			if r.(map[string]any)["operationId"] == opX {
				t.Errorf("%s: the operation must never be attributed as committed (history revision recorded)", stage)
			}
		}
		if n := pacIntentAudits(opX, "pac.profile_publish"); n != 0 {
			t.Errorf("%s: no success audit may exist for the refused operation (got %d)", stage, n)
		}
		if n := len(configVersions.List()); n != versions {
			t.Errorf("%s: no config version may be captured for the refused operation (%d → %d)", stage, versions, n)
		}
		if o, ok := pacBoundaryProfile(t, "other"); !ok || o.Name != "Other renamed outside the boundary" {
			t.Errorf("%s: the intervening change must stay intact: %+v ok=%v", stage, o, ok)
		}
		if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Revision != 2 || pac.ProfileSpecDigest(p) != pac.ProfileSpecDigest(target) {
			t.Errorf("%s: the active store must be exactly what the intervening writer installed: %+v ok=%v", stage, p, ok)
		}
	}
	assertNotCommitted("before restart")
	// 5. restart from the durable files, persistence still failing
	pacIntentRestartComplete(t)
	assertNotCommitted("after restart (persistence failing)")
	// 7. persistence recovers: the refusal becomes durable and replays
	pac.LifecycleWriteHook = nil
	g := pacEvidenceGet(t, "?operationId="+opX)
	assertNotCommitted("after recovery")
	op, _ := g["operation"].(map[string]any)
	if op == nil || op["found"] != true || op["state"] != pac.OpAborted {
		t.Fatalf("the refusal must become the durable decided outcome: %v", g["operation"])
	}
	if g["historyState"] != pac.HistoryStateRecorded {
		t.Fatalf("historyState = %v, want recorded once the refusal is durable", g["historyState"])
	}
	again := pacTransitionPublishAt(t, opX, 1, pacIntentDraft("v2", false), "", "")
	if again.Code != http.StatusConflict || pacIntentJSON(t, again)["code"] != "concurrent_write" {
		t.Fatalf("a repeat of the operationId must replay the durable refusal: %d %s", again.Code, again.Body.String())
	}
	assertNotCommitted("after replay")
}
