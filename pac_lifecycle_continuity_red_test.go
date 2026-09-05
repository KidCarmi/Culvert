package main

// pac_lifecycle_continuity_red_test.go — 2F-E CORRECTION ROUND 2 RED matrix
// (backend half of findings 1 and 2 from the external freeze review of
// db6f4d35).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// every E-test below fails there (E8 is a CONTROL that passes on both sides):
//
//   E5  HISTORY CONTINUITY IDENTITY: the lifecycle GET carries a durable
//       `historyIncarnation` (a UUID) — the identity of this profile's
//       node-local history epoch. It is STABLE across draft saves and
//       publishes, and ROTATES when the history is discarded: a profile
//       DELETE + recreate under the same id, and a history reset
//       (quarantined file). Revision numbers restart at 1 on a recreated
//       profile, so numbers alone cannot tell the epochs apart.
//   E6  DISPATCH FENCE: a publish/rollback that names the history epoch it
//       was reviewed in (`expectedHistoryIncarnation`) is REFUSED (409
//       history_incarnation_mismatch, the current identity named) when the
//       appliance's epoch differs — the delete/recreate counterexample:
//       the profile is recreated at the ORIGINAL base revision and spec, the
//       same draft is restored, and the ORIGINAL operationId is re-sent. The
//       old decision record is gone, so without the fence the appliance
//       would run the operation AGAIN. Nothing is committed on refusal; the
//       same request against the current epoch lands.
//   E7  CURRENT-ACTIVE TRUTH: after a publish, a direct profile PUT advances
//       the authoritative active revision (and replaces the spec) WITHOUT
//       moving the history pointer activeN. The lifecycle GET must let a
//       client tell "committed historically" from "currently active": every
//       revision carries the store revision it produced (`storeRevision`)
//       and the operation lookup carries the committed identity
//       (`specDigest`, `storeRevision`) beside activeRevision /
//       activeSpecDigest.
//   E8  CONTROL: within ONE epoch, a repeated operationId is still replayed
//       byte-for-byte (at-most-once is unchanged by the fence).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

func pacContinuityIncarnation(t *testing.T) string {
	t.Helper()
	m := pacEvidenceGet(t, "")
	s, _ := m["historyIncarnation"].(string)
	if _, err := uuid.Parse(s); err != nil {
		t.Fatalf("historyIncarnation must be a UUID naming the history epoch, got %v", m["historyIncarnation"])
	}
	return s
}

func pacContinuityProfile(t *testing.T) pac.Profile {
	t.Helper()
	rec := pacFenceReq(t, "GET", "/api/pac/profiles/branch-il", "", pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("profile GET: %d %s", rec.Code, rec.Body.String())
	}
	var p pac.Profile
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func pacContinuityCollectionEtag(t *testing.T) string {
	t.Helper()
	rec := pacFenceReq(t, "GET", "/api/pac/profiles", "", pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("profiles GET: %d %s", rec.Code, rec.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	etag, _ := m["collectionEtag"].(string)
	return etag
}

// pacContinuityBaseSpec is a DIRECT-free spec for branch-il so create/update
// need no typed confirmation (the DIRECT-delta guard is not under test).
const pacContinuityBaseSpec = `{"id":"branch-il","name":"Branch IL base","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"balanced","rules":[]}`

// pacContinuityPut replaces the active spec directly (the CRUD path, NOT the
// lifecycle) and returns the new active revision.
func pacContinuityPut(t *testing.T, name string) int64 {
	t.Helper()
	cur := pacContinuityProfile(t)
	body := fmt.Sprintf(`{"id":"branch-il","name":%q,"enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"balanced","rules":[],"revision":%d}`, name, cur.Revision)
	rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", body, pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("profile PUT: %d %s", rec.Code, rec.Body.String())
	}
	return pacContinuityProfile(t).Revision
}

// pacContinuityDeleteAndRecreate deletes branch-il (its node-local history
// with it) and recreates it under the SAME id from the DIRECT-free base spec.
func pacContinuityDeleteAndRecreate(t *testing.T) {
	t.Helper()
	cur := pacContinuityProfile(t)
	rec := pacFenceReq(t, "DELETE", fmt.Sprintf("/api/pac/profiles/branch-il?revision=%d", cur.Revision), "", pacIntentIP)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("profile DELETE: %d %s", rec.Code, rec.Body.String())
	}
	etag := pacContinuityCollectionEtag(t)
	create := pacContinuityBaseSpec[:len(pacContinuityBaseSpec)-1] + fmt.Sprintf(`,"revision":1,"collectionEtag":%q}`, etag)
	rec = pacFenceReq(t, "POST", "/api/pac/profiles", create, pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("profile recreate: %d %s", rec.Code, rec.Body.String())
	}
}

func pacContinuitySaveDraft(t *testing.T, draft string) {
	t.Helper()
	m := pacEvidenceGet(t, "")
	dr, _ := m["draftRevision"].(float64)
	rec := pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle", fmt.Sprintf(`{"action":"save_draft","draftRevision":%d,"draft":%s}`, int64(dr), draft), pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("save_draft: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPACContinuity_E5_HistoryIncarnationIsDurableStableAndRotatesWithTheHistory(t *testing.T) {
	pacIntentEnv(t)
	inc0 := pacContinuityIncarnation(t)
	// stable across a draft save and a publish
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	if got := pacContinuityIncarnation(t); got != inc0 {
		t.Fatalf("a draft save must not rotate the history epoch: %s → %s", inc0, got)
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("v2", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	if got := pacContinuityIncarnation(t); got != inc0 {
		t.Fatalf("a publish must not rotate the history epoch: %s → %s", inc0, got)
	}
	// a restart keeps it (durable, not process-local)
	pacIntentRestartComplete(t)
	if got := pacContinuityIncarnation(t); got != inc0 {
		t.Fatalf("a restart must not rotate the history epoch: %s → %s", inc0, got)
	}
	// delete + recreate under the same id: revision numbering restarts at 1,
	// the epoch identity must NOT be reused
	pacContinuityDeleteAndRecreate(t)
	inc1 := pacContinuityIncarnation(t)
	if inc1 == inc0 {
		t.Fatalf("delete + recreate must rotate the history epoch (still %s)", inc0)
	}
	if p := pacContinuityProfile(t); p.Revision != 1 {
		t.Fatalf("recreated profile must restart at revision 1, got %d", p.Revision)
	}
	// a history reset (quarantined file) rotates it again
	pacContinuitySaveDraft(t, pacIntentDraft("v3", false))
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("v3", false), ""); rec.Code != 200 {
		t.Fatalf("publish after recreate: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentCorruptLifecycle(t)
	m := pacEvidenceGet(t, "")
	if m["historyState"] != pac.HistoryStateReset {
		t.Fatalf("expected history_reset after the quarantine, got %v", m["historyState"])
	}
	inc2, _ := m["historyIncarnation"].(string)
	if _, err := uuid.Parse(inc2); err != nil || inc2 == inc1 || inc2 == inc0 {
		t.Fatalf("a history reset must rotate the history epoch: before %s, after %v", inc1, m["historyIncarnation"])
	}
}

func TestPACContinuity_E6_DispatchAgainstAnotherEpochIsRefusedAndCommitsNothing(t *testing.T) {
	pacIntentEnv(t)
	// the base the operation is reviewed against: a DIRECT-free spec at
	// revision 2 (create is revision 1, one PUT makes it 2)
	rev := pacContinuityPut(t, "Branch IL base")
	if rev != 2 {
		t.Fatalf("base revision = %d, want 2", rev)
	}
	baseDigest := pac.ProfileSpecDigest(pacContinuityProfile(t))
	incOld := pacContinuityIncarnation(t)
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	opX := uuid.NewString()
	rec := pacIntentPublish(t, opX, 2, pacIntentDraft("v2", false), fmt.Sprintf(`,"expectedHistoryIncarnation":%q`, incOld))
	if rec.Code != 200 {
		t.Fatalf("publish X in its own epoch: %d %s", rec.Code, rec.Body.String())
	}
	if p := pacContinuityProfile(t); p.Revision != 3 {
		t.Fatalf("active revision after X = %d, want 3", p.Revision)
	}
	// delete, recreate under the same id, bring it back to EXACTLY the
	// reviewed base (revision 2, same spec) and restore the same draft
	pacContinuityDeleteAndRecreate(t)
	if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
		t.Fatalf("recreated base revision = %d, want 2", rev)
	}
	if d := pac.ProfileSpecDigest(pacContinuityProfile(t)); d != baseDigest {
		t.Fatalf("recreated base digest %s != original %s", d, baseDigest)
	}
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	incNew := pacContinuityIncarnation(t)
	if incNew == incOld {
		t.Fatalf("recreate must rotate the history epoch (still %s)", incOld)
	}
	// the ORIGINAL operationId, re-sent with the epoch it was reviewed in
	rec = pacIntentPublish(t, opX, 2, pacIntentDraft("v2", false), fmt.Sprintf(`,"expectedHistoryIncarnation":%q`, incOld))
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-send against another epoch: want 409 history_incarnation_mismatch, got %d %s", rec.Code, rec.Body.String())
	}
	m := pacIntentJSON(t, rec)
	if m["code"] != "history_incarnation_mismatch" {
		t.Fatalf("code = %v, want history_incarnation_mismatch: %s", m["code"], rec.Body.String())
	}
	cur, _ := m["current"].(map[string]any)
	if cur == nil || cur["historyIncarnation"] != incNew {
		t.Fatalf("the refusal must name the current epoch %s: %s", incNew, rec.Body.String())
	}
	// nothing committed: the base is untouched and the new epoch holds no
	// revision and no decision for X
	if p := pacContinuityProfile(t); p.Revision != 2 || pac.ProfileSpecDigest(p) != baseDigest {
		t.Fatalf("a refused dispatch must commit nothing: revision %d digest %s", p.Revision, pac.ProfileSpecDigest(p))
	}
	g := pacEvidenceGet(t, "?operationId="+opX)
	if revs, _ := g["revisions"].([]any); len(revs) != 0 {
		t.Fatalf("a refused dispatch must record no revision: %v", g["revisions"])
	}
	if op, _ := g["operation"].(map[string]any); op == nil || op["found"] != false {
		t.Fatalf("a refused dispatch must record no decision: %v", g["operation"])
	}
	// the same request reviewed in the CURRENT epoch lands
	rec = pacIntentPublish(t, opX, 2, pacIntentDraft("v2", false), fmt.Sprintf(`,"expectedHistoryIncarnation":%q`, incNew))
	if rec.Code != 200 {
		t.Fatalf("publish in the current epoch: %d %s", rec.Code, rec.Body.String())
	}
	if p := pacContinuityProfile(t); p.Revision != 3 {
		t.Fatalf("active revision after the epoch-matched publish = %d, want 3", p.Revision)
	}
}

func TestPACContinuity_E7_LifecycleGetCarriesTheCommittedIdentityBesideTheAuthoritativeActive(t *testing.T) {
	pacIntentEnv(t)
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	opX := uuid.NewString()
	rec := pacIntentPublish(t, opX, 1, pacIntentDraft("v2", false), "")
	if rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	committedDigest := pac.ProfileSpecDigest(pacContinuityProfile(t))
	if p := pacContinuityProfile(t); p.Revision != 2 {
		t.Fatalf("active revision after the publish = %d, want 2", p.Revision)
	}
	// a direct profile PUT replaces the spec: store revision 3, activeN
	// still 1 (the history pointer does not move)
	if rev := pacContinuityPut(t, "Branch IL renamed by PUT"); rev != 3 {
		t.Fatalf("active revision after the PUT = %d, want 3", rev)
	}
	g := pacEvidenceGet(t, "?operationId="+opX)
	if n, _ := g["activeN"].(float64); int64(n) != 1 {
		t.Fatalf("activeN = %v, want 1 (the history pointer is untouched by a PUT)", g["activeN"])
	}
	if r, _ := g["activeRevision"].(float64); int64(r) != 3 {
		t.Fatalf("activeRevision = %v, want 3 (the authoritative store moved)", g["activeRevision"])
	}
	if d, _ := g["activeSpecDigest"].(string); d == committedDigest {
		t.Fatalf("activeSpecDigest must reflect the PUT spec, still %s", d)
	}
	revs, _ := g["revisions"].([]any)
	if len(revs) != 1 {
		t.Fatalf("want exactly one history revision, got %v", g["revisions"])
	}
	r0, _ := revs[0].(map[string]any)
	if sr, _ := r0["storeRevision"].(float64); int64(sr) != 2 {
		t.Fatalf("revisions[0].storeRevision = %v, want 2 (the store revision the commit produced)", r0["storeRevision"])
	}
	op, _ := g["operation"].(map[string]any)
	if op == nil || op["found"] != true {
		t.Fatalf("lookup must find X: %v", g["operation"])
	}
	if n, _ := op["revisionN"].(float64); int64(n) != 1 {
		t.Fatalf("lookup.revisionN = %v, want 1", op["revisionN"])
	}
	if op["specDigest"] != committedDigest {
		t.Fatalf("lookup.specDigest = %v, want the committed digest %s", op["specDigest"], committedDigest)
	}
	if sr, _ := op["storeRevision"].(float64); int64(sr) != 2 {
		t.Fatalf("lookup.storeRevision = %v, want 2", op["storeRevision"])
	}
}

func TestPACContinuity_E8_ControlRepeatedOperationIsStillReplayedWithinOneEpoch(t *testing.T) {
	pacIntentEnv(t)
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	inc := pacEvidenceGet(t, "")["historyIncarnation"]
	extra := ""
	if s, ok := inc.(string); ok && s != "" {
		extra = fmt.Sprintf(`,"expectedHistoryIncarnation":%q`, s)
	}
	opX := uuid.NewString()
	first := pacIntentPublish(t, opX, 1, pacIntentDraft("v2", false), extra)
	if first.Code != 200 {
		t.Fatalf("publish: %d %s", first.Code, first.Body.String())
	}
	again := pacIntentPublish(t, opX, 1, pacIntentDraft("v2", false), extra)
	// the replay writes the recorded bytes verbatim; jsonOK appends the
	// encoder's newline — compare the JSON text, not the trailing whitespace
	if again.Code != 200 || strings.TrimSpace(again.Body.String()) != strings.TrimSpace(first.Body.String()) {
		t.Fatalf("a repeated operationId within one epoch must replay the recorded response: %d %s vs %s", again.Code, again.Body.String(), first.Body.String())
	}
	if p := pacContinuityProfile(t); p.Revision != 2 {
		t.Fatalf("at-most-once: active revision %d, want 2", p.Revision)
	}
}
