package main

// pac_lifecycle_evidence_red_test.go — 2F-E CORRECTION RED matrix (backend
// half of findings 1 and 5 from the external freeze review of 39e2cfdb).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// every test fails there:
//
//   E1  the lifecycle GET states its recovery-evidence LIMITS — how many
//       decided operations it retains (operationsRetained) against its cap
//       (operationsCap = pac.MaxDecidedOps) — and the digest of the saved
//       draft (draftSpecDigest), so a client can bind a dispatch to the
//       candidate it reviewed and know when absence proves nothing.
//   E2  `GET …/lifecycle?operationId=<uuid>` looks ONE operation up in the
//       FULL retained ring and the revision history (not the 20 shown):
//       found ⇒ its decided state/status and the history revision it
//       produced; unknown ⇒ found:false. Never a mutation.
//   E3  the contract documents the lifecycle GET (the new page depends on
//       it), validates a real publish request body, and states the DELETE
//       responses the handlers actually answer (204, no body) for profiles,
//       pools and posture exceptions.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

func pacEvidenceGet(t *testing.T, query string) map[string]any {
	t.Helper()
	rec := pacFenceReq(t, "GET", "/api/pac/profiles/branch-il/lifecycle"+query, "", pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("lifecycle GET %q: %d %s", query, rec.Code, rec.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPACEvidence_E1_LifecycleGetStatesItsLimitsAndDraftDigest(t *testing.T) {
	pacIntentEnv(t)
	// a saved draft
	draft := pacIntentDraft("Branch IL v2", false)
	before := pacEvidenceGet(t, "")
	dr, _ := before["draftRevision"].(float64)
	rec := pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle", fmt.Sprintf(`{"action":"save_draft","draftRevision":%d,"draft":%s}`, int64(dr), draft), pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("save_draft: %d %s", rec.Code, rec.Body.String())
	}
	m := pacEvidenceGet(t, "")
	var want pac.Profile
	if err := json.Unmarshal([]byte(draft), &want); err != nil {
		t.Fatal(err)
	}
	want.ID = "branch-il"
	if got, _ := m["draftSpecDigest"].(string); got != pac.ProfileSpecDigest(want) {
		t.Fatalf("draftSpecDigest = %v, want the ProfileSpecDigest of the saved draft %s", m["draftSpecDigest"], pac.ProfileSpecDigest(want))
	}
	if got, _ := m["operationsRetained"].(float64); int(got) != 0 {
		t.Fatalf("operationsRetained = %v, want 0 before any decision", m["operationsRetained"])
	}
	if got, _ := m["operationsCap"].(float64); int(got) != pac.MaxDecidedOps {
		t.Fatalf("operationsCap = %v, want %d", m["operationsCap"], pac.MaxDecidedOps)
	}
}

func TestPACEvidence_E2_OperationLookupCoversTheFullRetainedRing(t *testing.T) {
	pacIntentEnv(t)
	first := uuid.NewString()
	rec := pacIntentPublish(t, first, 1, pacIntentDraft("v2", false), "")
	if rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	// push the first decision beyond the 20 the GET lists (but inside the
	// retained ring of MaxDecidedOps)
	rev := int64(2)
	for i := 0; i < 25; i++ {
		r := pacIntentPublish(t, uuid.NewString(), rev, pacIntentDraft(fmt.Sprintf("v%d", i+3), false), "")
		if r.Code != 200 {
			t.Fatalf("publish %d: %d %s", i, r.Code, r.Body.String())
		}
		rev++
	}
	m := pacEvidenceGet(t, "")
	ops, _ := m["operations"].([]any)
	if len(ops) != 20 {
		t.Fatalf("the GET lists %d operations, want the 20 most recent", len(ops))
	}
	for _, o := range ops {
		if om, _ := o.(map[string]any); om["operationId"] == first {
			t.Fatalf("the first decision must have fallen out of the 20 shown")
		}
	}
	if got, _ := m["operationsRetained"].(float64); int(got) != 26 {
		t.Fatalf("operationsRetained = %v, want 26", m["operationsRetained"])
	}
	// the lookup still finds it — with the history revision it produced
	lm := pacEvidenceGet(t, "?operationId="+first)
	op, _ := lm["operation"].(map[string]any)
	if op == nil || op["found"] != true || op["operationId"] != first {
		t.Fatalf("lookup of a retained-but-unlisted operation must be found: %v", lm["operation"])
	}
	if op["state"] != pac.OpRecorded || op["status"] != float64(200) {
		t.Fatalf("lookup must carry the decided state/status: %v", op)
	}
	if n, _ := op["revisionN"].(float64); int64(n) != 1 {
		t.Fatalf("lookup must name the history revision the operation produced (1), got %v", op["revisionN"])
	}
	// an unknown id is found:false — and the GET is still a pure read
	unknown := uuid.NewString()
	um := pacEvidenceGet(t, "?operationId="+unknown)
	uop, _ := um["operation"].(map[string]any)
	if uop == nil || uop["found"] != false || uop["operationId"] != unknown {
		t.Fatalf("lookup of an unknown id must answer found:false: %v", um["operation"])
	}
	if got, _ := um["operationsRetained"].(float64); int(got) != 26 {
		t.Fatalf("a lookup must not change the retained count: %v", um["operationsRetained"])
	}
	// a malformed id is refused, never guessed
	bad := pacFenceReq(t, "GET", "/api/pac/profiles/branch-il/lifecycle?operationId=not-a-uuid", "", pacIntentIP)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("malformed operationId: %d, want 400", bad.Code)
	}
}

func TestPACEvidence_E3_ContractDocumentsWhatThePageDependsOn(t *testing.T) {
	pacIntentEnv(t)
	spec := loadContract(t)
	const path = "/api/pac/profiles/{name}/lifecycle"
	if spec.FindOp("GET", path) == nil {
		t.Fatalf("the contract must document GET %s (the 2F-E page reads it)", path)
	}
	rec := pacFenceReq(t, "GET", "/api/pac/profiles/branch-il/lifecycle?operationId="+uuid.NewString(), "", pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("lifecycle GET: %d %s", rec.Code, rec.Body.String())
	}
	if err := spec.ValidateJSONResponse("GET", path, 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("lifecycle GET response violates the contract: %v\nbody: %s", err, rec.Body.String())
	}
	publish := fmt.Sprintf(`{"action":"publish","operationId":%q,"expectedActiveRevision":1,"reason":"r","draft":%s}`, uuid.NewString(), pacIntentDraft("v2", false))
	if err := spec.ValidateJSONRequest("POST", path, []byte(publish)); err != nil {
		t.Fatalf("a real publish request must validate against the documented request schema: %v", err)
	}
	for _, p := range []string{"/api/pac/profiles/{name}", "/api/pac/pools/{name}", "/api/pac/posture/exceptions/{name}"} {
		op := spec.FindOp("DELETE", p)
		if op == nil || op.Responses == nil {
			t.Fatalf("DELETE %s undocumented", p)
		}
		if op.Responses.Map()["204"] == nil {
			t.Fatalf("DELETE %s: the handler answers 204 (no body) but the contract does not document it", p)
		}
		if op.Responses.Map()["200"] != nil {
			t.Fatalf("DELETE %s: the contract documents a 200 body the handler never sends", p)
		}
	}
}
