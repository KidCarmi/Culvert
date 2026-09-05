package main

// pac_lifecycle_writer_boundary_test.go — 2F-E correction round 4 walls
// (green on the corrected tree; the RED matrix lives in
// pac_lifecycle_writer_boundary_red_test.go).
//
//   W1  the compare-and-swap wall: a writer OUTSIDE the shared boundary
//       (a direct ProfileStore.Set, which no production caller performs
//       any more) lands while a publish is parked at intent_persisted; the
//       release is REFUSED (409 concurrent_write), the intervening change
//       survives, nothing is recorded as a revision, the refusal is the
//       decided outcome of the operationId (a re-send replays it), and a
//       fresh review publishes normally.
//   W2  the CP→DP snapshot apply (the third bulk writer) waits at the
//       production serialization point while a publish is parked, and both
//       changes survive.

import (
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

func TestPACBoundary_W1_WriterOutsideTheBoundaryIsDetectedAtCommitAndRefused(t *testing.T) {
	pacBoundaryEnv(t)
	pacBoundarySeedOther(t, "Other")
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	release, publishDone, _, _ := pacBoundaryParkedPublish(t, "never")
	// an out-of-boundary writer (no production caller does this any more)
	pacBoundarySeedOther(t, "Other changed outside the boundary")
	release()
	pub := <-publishDone
	if pub.Code != http.StatusConflict {
		t.Fatalf("a candidate built on a superseded generation must be refused: %d %s", pub.Code, pub.Body.String())
	}
	m := pacIntentJSON(t, pub)
	if m["code"] != "concurrent_write" {
		t.Fatalf("code = %v, want concurrent_write: %s", m["code"], pub.Body.String())
	}
	opID, _ := m["operationId"].(string)
	if o, ok := pacBoundaryProfile(t, "other"); !ok || o.Name != "Other changed outside the boundary" {
		t.Fatalf("the intervening change must survive: %+v ok=%v", o, ok)
	}
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Revision != 1 {
		t.Fatalf("nothing may have been written by the refused publish: %+v ok=%v", p, ok)
	}
	g := pacEvidenceGet(t, "?operationId="+opID)
	if revs, _ := g["revisions"].([]any); len(revs) != 0 {
		t.Fatalf("a refused commit must record no revision: %v", g["revisions"])
	}
	op, _ := g["operation"].(map[string]any)
	if op == nil || op["found"] != true || op["state"] != pac.OpAborted {
		t.Fatalf("the refusal must be the decided outcome of the operation: %v", g["operation"])
	}
	// a re-send of the same operationId replays the refusal, commits nothing
	again := pacTransitionPublishAt(t, opID, 1, pacIntentDraft("v2", false), "", "")
	if again.Code != http.StatusConflict {
		t.Fatalf("re-send must replay the refusal: %d %s", again.Code, again.Body.String())
	}
	// a fresh review lands
	cur := pacContinuityProfile(t)
	rec := pacTransitionPublishAt(t, uuid.NewString(), cur.Revision, pacIntentDraft("v2", false), pacContinuityIncarnation(t), pac.ProfileSpecDigest(cur))
	if rec.Code != 200 {
		t.Fatalf("fresh publish: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPACBoundary_W2_SnapshotApplyAcrossAParkedPublishKeepsBothChanges(t *testing.T) {
	pacBoundaryEnv(t)
	pacBoundarySeedOther(t, "Other")
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	const renamed = "Other renamed by snapshot"
	incBefore := pacContinuityIncarnation(t)
	release, publishDone, waiting, wrote := pacBoundaryParkedPublish(t, renamed)
	cfg := pacProfiles.Get()
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID == "other" {
			cfg.Profiles[i].Name = renamed
			cfg.Profiles[i].Revision = 2
		}
	}
	applied := make(chan error, 1)
	go func() {
		snap := ConfigSnapshot{PACProfiles: cfg.Profiles, PACPools: cfg.Pools}
		applied <- applyConfigSnapshot(snap)
	}()
	select {
	case <-wrote:
	case <-waiting:
	}
	release()
	pub := <-publishDone
	if err := <-applied; err != nil {
		t.Fatalf("snapshot apply: %v", err)
	}
	if pub.Code != 200 {
		t.Fatalf("publish: %d %s", pub.Code, pub.Body.String())
	}
	// a valid SERIAL outcome: the publish committed (200) and the snapshot
	// — a WHOLESALE, authoritative writer — then installed its complete set,
	// which rewinds branch-il to the snapshot's revision; the snapshot's
	// change survives, and the rewind is observed as an epoch rotation
	if o, ok := pacBoundaryProfile(t, "other"); !ok || o.Name != renamed {
		t.Fatalf("the snapshot's completed change was lost: %+v ok=%v", o, ok)
	}
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Revision != 1 {
		t.Fatalf("the wholesale snapshot must be authoritative after the publish: %+v ok=%v", p, ok)
	}
	if got := pacContinuityIncarnation(t); got == incBefore {
		t.Fatalf("the observed rewind must rotate the epoch (still %s)", incBefore)
	}
}
