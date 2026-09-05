package main

// pac_lifecycle_transition_red_test.go — 2F-E CORRECTION ROUND 3 RED matrix
// (backend half of findings 1 and 2 from the external freeze review of
// 33f6f21c: does the history-continuity guarantee survive EVERY state
// transition that can replace or rewind the active profile, and are the
// epoch transitions themselves crash-safe?).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// every F-test below fails there. The only product change in the same commit
// is the TEST-ONLY fault-injection seam pac.LifecycleWriteHook (nil in
// production; the sibling of the accepted pac.ResetWriteHook).
//
//   F1  SAME-REVISION REPLACEMENT (finding 1, case A): a publish reviewed
//       against epoch E, revision N, spec A is delayed; a replace-mode config
//       IMPORT installs spec B at the SAME revision N without changing the
//       epoch. The delayed request passes the epoch check and the revision
//       fence, so the appliance runs it against a base the operator never
//       reviewed. It must be REFUSED (409) and commit nothing — both when the
//       caller names the epoch (F1a) and when it names only the reviewed spec
//       digest (F1b: the spec digest must be an INDEPENDENT fence).
//   F2  EVICTED COMMIT + ROLLBACK TO ITS BASE (finding 1, case B): an
//       operation commits, enough later operations evict it from BOTH bounded
//       histories (the decided ring and the revision list), and a config
//       ROLLBACK restores its original base revision/spec without changing
//       the epoch. Re-sending the ORIGINAL operationId then passes every
//       check and commits a SECOND time. It must be refused; the historical
//       evidence (revisions, retained operations) must survive the refusal.
//   F3  ACTIVE DELETE SUCCEEDS, LIFECYCLE DELETE FAILS (finding 2): the
//       record — and with it the old epoch — survives the profile. A
//       recreate under the same id then inherits the OLD epoch, so a request
//       reviewed before the delete is accepted. The old epoch must never be
//       valid for the recreated profile; while the profile is gone the GET
//       must not advertise it; the DELETE must still report the active
//       mutation that committed (204).
//   F4  RESTART BETWEEN THOSE WRITES (finding 2): same durable state as F3
//       followed by a process restart (F4a), and the mirror crash — the
//       transition began but the active delete never happened (F4b): a
//       record flagged for deletion beside a still-present profile must not
//       keep exposing the old epoch as valid.
//   F5  MIGRATION WRITE FAILURE (finding 2): a record that predates the epoch
//       identity is minted one at boot; if that write fails the minted
//       identity is NOT durable and must not be advertised (GET reports "");
//       once the write can land, the GET mints a durable one that survives
//       a restart.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

// pacTransitionEnv is pacIntentEnv plus the lifecycle write seam, restored on
// cleanup.
func pacTransitionEnv(t *testing.T) {
	t.Helper()
	pacIntentEnv(t)
	prev := pac.LifecycleWriteHook
	t.Cleanup(func() { pac.LifecycleWriteHook = prev })
	pac.LifecycleWriteHook = nil
}

// pacTransitionSpec is a DIRECT-free branch-il spec with the given name.
func pacTransitionSpec(name string, revision int64) pac.Profile {
	return pac.Profile{
		ID: "branch-il", Name: name, Enabled: true, PoolID: "il",
		PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced,
		Rules: []pac.Rule{}, Revision: revision,
	}
}

// pacTransitionReplaceImport installs spec at its own revision through the
// exact replace-mode import path (importPACProfilesCandidate + the tolerant
// Set), keeping the pools.
func pacTransitionReplaceImport(t *testing.T, spec pac.Profile) {
	t.Helper()
	b := configBackup{Version: configBackupVersion, PACProfiles: []pac.Profile{spec}}
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	if err := pacProfiles.Set(importPACProfilesCandidate(pacProfiles.Get(), &b, true)); err != nil {
		t.Fatalf("replace import: %v", err)
	}
}

// pacTransitionRollback restores spec (at its own revision) through the exact
// config-rollback path (applyPACFromBackup), keeping the pools.
func pacTransitionRollback(t *testing.T, spec pac.Profile) {
	t.Helper()
	cur := pacProfiles.Get()
	b := configBackup{Version: configBackupVersion, PACProfiles: []pac.Profile{spec}, PACPools: cur.Pools,
		PACProxyHost: pacStore.Get().ProxyHost, PACProxyPort: pacStore.Get().ProxyPort, PACExclusions: pacStore.Get().Exclusions}
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	applyPACFromBackup(&b)
}

func pacTransitionPublishAt(t *testing.T, opID string, rev int64, draft, inc, specDigest string) *httptest.ResponseRecorder {
	t.Helper()
	extra := ""
	if inc != "" {
		extra += fmt.Sprintf(`,"expectedHistoryIncarnation":%q`, inc)
	}
	if specDigest != "" {
		extra += fmt.Sprintf(`,"expectedActiveSpecDigest":%q`, specDigest)
	}
	return pacIntentPublish(t, opID, rev, draft, extra)
}

// pacTransitionAssertRefused asserts a 409 refusal that commits nothing:
// the active profile is byte-identical to wantActive and no revision or
// decision for opID exists.
func pacTransitionAssertRefused(t *testing.T, rec *httptest.ResponseRecorder, opID string, wantActive pac.Profile, wantCodes ...string) map[string]any {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 refusal, got %d %s", rec.Code, rec.Body.String())
	}
	m := pacIntentJSON(t, rec)
	okCode := false
	for _, c := range wantCodes {
		if m["code"] == c {
			okCode = true
		}
	}
	if !okCode {
		t.Fatalf("refusal code = %v, want one of %v: %s", m["code"], wantCodes, rec.Body.String())
	}
	got := pacContinuityProfile(t)
	if got.Revision != wantActive.Revision || pac.ProfileSpecDigest(got) != pac.ProfileSpecDigest(wantActive) {
		t.Fatalf("a refused dispatch must commit nothing: active revision %d digest %s, want %d %s", got.Revision, pac.ProfileSpecDigest(got), wantActive.Revision, pac.ProfileSpecDigest(wantActive))
	}
	g := pacEvidenceGet(t, "?operationId="+opID)
	for _, r := range g["revisions"].([]any) {
		if r.(map[string]any)["operationId"] == opID {
			t.Fatalf("a refused dispatch must record no revision for %s", opID)
		}
	}
	if op, _ := g["operation"].(map[string]any); op == nil || op["found"] != false {
		t.Fatalf("a refused dispatch must record no decision: %v", g["operation"])
	}
	return m
}

// ── F1 ──────────────────────────────────────────────────────────────────────

func TestPACTransition_F1_DelayedPublishAcrossSameRevisionReplaceImportIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name        string
		nameEpoch   bool
		nameSpec    bool
		wantCodes   []string
		wantCurrent string
	}{
		{name: "a_epoch_and_spec", nameEpoch: true, nameSpec: true, wantCodes: []string{"history_incarnation_mismatch", "stale"}, wantCurrent: ""},
		{name: "b_spec_digest_only", nameEpoch: false, nameSpec: true, wantCodes: []string{"stale"}, wantCurrent: "expectedActiveSpecDigest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pacTransitionEnv(t)
			// the reviewed base: epoch E, revision 2, spec A
			if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
				t.Fatalf("base revision = %d, want 2", rev)
			}
			specA := pacContinuityProfile(t)
			digestA := pac.ProfileSpecDigest(specA)
			incE := pacContinuityIncarnation(t)
			pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
			// the request is delayed; a replace-mode import installs spec B
			// at the SAME revision 2 (positive imported revisions are kept)
			specB := pacTransitionSpec("Branch IL replaced by import", 2)
			pacTransitionReplaceImport(t, specB)
			if got := pacContinuityProfile(t); got.Revision != 2 || pac.ProfileSpecDigest(got) == digestA {
				t.Fatalf("fixture: replace import must keep revision 2 and change the spec (got %d %s)", got.Revision, pac.ProfileSpecDigest(got))
			}
			inc, spec := "", ""
			if tc.nameEpoch {
				inc = incE
			}
			if tc.nameSpec {
				spec = digestA
			}
			opX := uuid.NewString()
			rec := pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v2", false), inc, spec)
			m := pacTransitionAssertRefused(t, rec, opX, pacContinuityProfile(t), tc.wantCodes...)
			if tc.wantCurrent != "" {
				cur, _ := m["current"].(map[string]any)
				if cur == nil || cur[tc.wantCurrent] != pac.ProfileSpecDigest(pacContinuityProfile(t)) {
					t.Fatalf("the refusal must name the CURRENT %s: %s", tc.wantCurrent, rec.Body.String())
				}
			}
			// a request reviewed against the CURRENT state lands
			cur := pacContinuityProfile(t)
			rec = pacTransitionPublishAt(t, uuid.NewString(), cur.Revision, pacIntentDraft("v2", false), pacContinuityIncarnation(t), pac.ProfileSpecDigest(cur))
			if rec.Code != 200 {
				t.Fatalf("publish reviewed against the current state: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// ── F2 ──────────────────────────────────────────────────────────────────────

// pacTransitionEvict publishes enough operations to evict every earlier one
// from both bounded histories (the decided ring, pac.MaxDecidedOps, and the
// revision list).
func pacTransitionEvict(t *testing.T) {
	t.Helper()
	for i := 0; i < pac.MaxDecidedOps+2; i++ {
		name := fmt.Sprintf("evict %d", i)
		pacContinuitySaveDraft(t, pacIntentDraft(name, false))
		cur := pacContinuityProfile(t)
		rec := pacTransitionPublishAt(t, uuid.NewString(), cur.Revision, pacIntentDraft(name, false), "", "")
		if rec.Code != 200 {
			t.Fatalf("evicting publish %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestPACTransition_F2_EvictedCommitThenRollbackToItsBaseRefusesTheReplay(t *testing.T) {
	pacTransitionEnv(t)
	// the reviewed base: epoch E, revision 2, spec A
	if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
		t.Fatalf("base revision = %d, want 2", rev)
	}
	specA := pacContinuityProfile(t)
	digestA := pac.ProfileSpecDigest(specA)
	incE := pacContinuityIncarnation(t)
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	opX := uuid.NewString()
	rec := pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v2", false), incE, digestA)
	if rec.Code != 200 {
		t.Fatalf("publish X: %d %s", rec.Code, rec.Body.String())
	}
	if p := pacContinuityProfile(t); p.Revision != 3 {
		t.Fatalf("active revision after X = %d, want 3", p.Revision)
	}
	// X is evicted from BOTH bounded histories
	pacTransitionEvict(t)
	g := pacEvidenceGet(t, "?operationId="+opX)
	if op, _ := g["operation"].(map[string]any); op == nil || op["found"] != false {
		t.Fatalf("fixture: X must be evicted from the decided ring: %v", g["operation"])
	}
	for _, r := range g["revisions"].([]any) {
		if r.(map[string]any)["operationId"] == opX {
			t.Fatal("fixture: X must be evicted from the revision list")
		}
	}
	retained, _ := g["operationsRetained"].(float64)
	revisionsKept := len(g["revisions"].([]any))
	if int(retained) != pac.MaxDecidedOps || revisionsKept == 0 {
		t.Fatalf("fixture: ring full (%v) and revisions retained (%d)", retained, revisionsKept)
	}
	// config rollback restores X's ORIGINAL base (revision 2, spec A) without
	// touching the epoch; the same draft is still saved
	pacTransitionRollback(t, specA)
	if got := pacContinuityProfile(t); got.Revision != 2 || pac.ProfileSpecDigest(got) != digestA {
		t.Fatalf("fixture: rollback must restore revision 2 spec A (got %d %s)", got.Revision, pac.ProfileSpecDigest(got))
	}
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	// the ORIGINAL operationId, re-sent with everything it was reviewed with
	rec = pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v2", false), incE, digestA)
	pacTransitionAssertRefused(t, rec, opX, specA, "history_incarnation_mismatch", "stale")
	// the node-local historical evidence survives the refusal
	g = pacEvidenceGet(t, "")
	if r, _ := g["operationsRetained"].(float64); int(r) != pac.MaxDecidedOps {
		t.Fatalf("historical evidence must be preserved: operationsRetained %v, want %d", g["operationsRetained"], pac.MaxDecidedOps)
	}
	if n := len(g["revisions"].([]any)); n != revisionsKept {
		t.Fatalf("historical evidence must be preserved: %d revisions, want %d", n, revisionsKept)
	}
}

// ── F3 / F4 ─────────────────────────────────────────────────────────────────

var errPACTransitionInjected = errors.New("injected lifecycle write failure")

// pacTransitionFailRecordRemoval arms the seam so that any lifecycle write
// that would REMOVE branch-il's record fails; every other write lands.
func pacTransitionFailRecordRemoval() {
	pac.LifecycleWriteHook = func(_ string, next map[string]*pac.ProfileLifecycle) error {
		if _, ok := next["branch-il"]; !ok {
			return errPACTransitionInjected
		}
		return nil
	}
}

// pacTransitionDeleteWithFailedRecordRemoval deletes branch-il while the
// lifecycle record removal fails: the active mutation commits and the
// DELETE must still report it (204).
func pacTransitionDeleteWithFailedRecordRemoval(t *testing.T) {
	t.Helper()
	cur := pacContinuityProfile(t)
	pacTransitionFailRecordRemoval()
	rec := pacFenceReq(t, "DELETE", fmt.Sprintf("/api/pac/profiles/branch-il?revision=%d", cur.Revision), "", pacIntentIP)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("profile DELETE must report the committed active mutation: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := pacProfiles.ProfileByID("branch-il"); ok {
		t.Fatal("fixture: the active profile must be gone")
	}
}

func pacTransitionRecreate(t *testing.T) {
	t.Helper()
	etag := pacContinuityCollectionEtag(t)
	create := pacContinuityBaseSpec[:len(pacContinuityBaseSpec)-1] + fmt.Sprintf(`,"revision":1,"collectionEtag":%q}`, etag)
	rec := pacFenceReq(t, "POST", "/api/pac/profiles", create, pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("profile recreate: %d %s", rec.Code, rec.Body.String())
	}
}

// pacTransitionAssertOldEpochInvalid brings the recreated profile to the
// reviewed base and asserts a request reviewed in incOld is refused, while
// the current epoch differs and accepts the same request.
func pacTransitionAssertOldEpochInvalid(t *testing.T, incOld string) {
	t.Helper()
	if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
		t.Fatalf("recreated base revision = %d, want 2", rev)
	}
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	incNew := pacContinuityIncarnation(t)
	if incNew == incOld {
		t.Fatalf("the recreated profile must not expose the old epoch %s", incOld)
	}
	opX := uuid.NewString()
	rec := pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v2", false), incOld, "")
	pacTransitionAssertRefused(t, rec, opX, pacContinuityProfile(t), "history_incarnation_mismatch")
	rec = pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v2", false), incNew, "")
	if rec.Code != 200 {
		t.Fatalf("publish in the current epoch: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPACTransition_F3_ActiveDeleteSucceedsRecordDeleteFails_OldEpochNeverValidForTheRecreate(t *testing.T) {
	pacTransitionEnv(t)
	if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
		t.Fatalf("base revision = %d, want 2", rev)
	}
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	incOld := pacContinuityIncarnation(t)
	pacTransitionDeleteWithFailedRecordRemoval(t)
	// while the profile is gone, the surviving record's epoch is not
	// continuity evidence for anything: the GET must not advertise it
	if m := pacEvidenceGet(t, ""); m["activeExists"] != false || m["historyIncarnation"] != "" {
		t.Errorf("a deleted profile's leftover record must not advertise its epoch: activeExists=%v historyIncarnation=%v", m["activeExists"], m["historyIncarnation"])
	}
	pacTransitionRecreate(t)
	pacTransitionAssertOldEpochInvalid(t, incOld)
}

func TestPACTransition_F4a_RestartBetweenTheDeleteWrites_OldEpochNeverValidForTheRecreate(t *testing.T) {
	pacTransitionEnv(t)
	if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
		t.Fatalf("base revision = %d, want 2", rev)
	}
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	incOld := pacContinuityIncarnation(t)
	pacTransitionDeleteWithFailedRecordRemoval(t)
	// the process dies here; the next boot must finish (or fence) the
	// transition from the durable state alone
	pac.LifecycleWriteHook = nil
	pacIntentRestartComplete(t)
	if m := pacEvidenceGet(t, ""); m["activeExists"] != false || m["historyIncarnation"] != "" {
		t.Errorf("after the restart the deleted profile's epoch must not be advertised: activeExists=%v historyIncarnation=%v", m["activeExists"], m["historyIncarnation"])
	}
	pacTransitionRecreate(t)
	pacTransitionAssertOldEpochInvalid(t, incOld)
}

func TestPACTransition_F4b_DeleteBegunButActiveNeverRemoved_RestartRotatesTheEpoch(t *testing.T) {
	pacTransitionEnv(t)
	if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
		t.Fatalf("base revision = %d, want 2", rev)
	}
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	incOld := pacContinuityIncarnation(t)
	// the durable state of a crash AFTER the delete transition was recorded
	// and BEFORE the active profile was removed: the record is flagged for
	// deletion, the profile is still there
	raw, err := os.ReadFile(pacFencePaths.lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]map[string]any
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file["branch-il"] == nil {
		t.Fatal("fixture: no record on disk")
	}
	file["branch-il"]["deletePending"] = true
	out, _ := json.Marshal(file) //nolint:errcheck // plain map
	if err := os.WriteFile(pacFencePaths.lifecycle, out, 0o600); err != nil {
		t.Fatal(err)
	}
	pacIntentRestartComplete(t)
	if _, ok := pacProfiles.ProfileByID("branch-il"); !ok {
		t.Fatal("fixture: the active profile must still exist")
	}
	incNow := pacContinuityIncarnation(t)
	if incNow == incOld {
		t.Fatalf("an incomplete delete transition must not keep exposing the old epoch %s as valid", incOld)
	}
	opX := uuid.NewString()
	rec := pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v2", false), incOld, "")
	pacTransitionAssertRefused(t, rec, opX, pacContinuityProfile(t), "history_incarnation_mismatch")
	// the record's evidence (the saved draft) survives the fence
	if m := pacEvidenceGet(t, ""); m["draftDirty"] != true {
		t.Fatalf("historical evidence must be preserved across the fence: %v", m["draft"])
	}
}

// ── F5 ──────────────────────────────────────────────────────────────────────

func TestPACTransition_F5_MigrationWriteFailure_UnpersistedEpochIsNotAdvertised(t *testing.T) {
	pacTransitionEnv(t)
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("v2", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	// a record that predates the epoch identity
	raw, err := os.ReadFile(pacFencePaths.lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]map[string]any
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	delete(file["branch-il"], "historyIncarnation")
	out, _ := json.Marshal(file) //nolint:errcheck // plain map
	if err := os.WriteFile(pacFencePaths.lifecycle, out, 0o600); err != nil {
		t.Fatal(err)
	}
	// the boot mints one, but no lifecycle write can land
	pac.LifecycleWriteHook = func(string, map[string]*pac.ProfileLifecycle) error { return errPACTransitionInjected }
	pacIntentRestartComplete(t)
	m := pacEvidenceGet(t, "")
	if m["historyIncarnation"] != "" {
		t.Fatalf("an identity that is not durable must not be advertised: historyIncarnation=%v", m["historyIncarnation"])
	}
	if revs, _ := m["revisions"].([]any); len(revs) != 1 {
		t.Fatalf("the migrated history itself must be served: %v", m["revisions"])
	}
	// nothing can be proven against an unpersisted identity: a dispatch
	// naming ANY epoch is refused, nothing commits
	opX := uuid.NewString()
	rec := pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v3", false), uuid.NewString(), "")
	pacTransitionAssertRefused(t, rec, opX, pacContinuityProfile(t), "history_incarnation_mismatch")
	// once writes land again, the GET mints a DURABLE identity that a
	// restart keeps
	pac.LifecycleWriteHook = nil
	incDurable := pacContinuityIncarnation(t)
	pacIntentRestartComplete(t)
	if got := pacContinuityIncarnation(t); got != incDurable {
		t.Fatalf("the durable identity must survive a restart: %s → %s", incDurable, got)
	}
	rec = pacTransitionPublishAt(t, opX, 2, pacIntentDraft("v3", false), incDurable, "")
	if rec.Code != 200 {
		t.Fatalf("publish in the durable epoch: %d %s", rec.Code, rec.Body.String())
	}
}
