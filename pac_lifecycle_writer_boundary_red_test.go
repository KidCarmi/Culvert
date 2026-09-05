package main

// pac_lifecycle_writer_boundary_red_test.go — 2F-E CORRECTION ROUND 4 RED
// matrix (external freeze review of d510d6c1, blockers 1 and 2).
//
// Written and executed on the UNTOUCHED candidate before any product change;
// every case below fails there. The only product change in the same commit
// is the TEST-ONLY observation seam pac.ProfileSetHook (nil in production;
// invoked at the entry of every ProfileStore.Set with the candidate, so a
// proof can observe which writer reached the authoritative store and when —
// it adds no synchronization).
//
// BLOCKER 1 — the production writer boundary. The lifecycle publish builds a
// whole-config candidate under pacProfilesAPIMu, persists its intent, and
// then writes that candidate to the active store. The production config
// IMPORT (apiConfigImport) and the production config-version ROLLBACK
// (rollbackConfigVersion → applyConfigBackup → applyPACFromBackup) write the
// active store WITHOUT that mutex, so their completed changes to UNRELATED
// profiles/pools can be overwritten by a publish that was parked between
// its validation and its commit. These proofs go through the PRODUCTION
// entry points and are channel-controlled (no sleeps): the publish is parked
// at the accepted "intent_persisted" stage seam, the competing writer is
// started, and the publish is released only once the writer has either
// REACHED the authoritative store (pac.ProfileSetHook) or is WAITING at the
// production serialization point ("pac_writer_waiting" stage — absent on
// the candidate, present after the correction). Either way the final state
// must be a valid SERIAL outcome: both changes present.
//
//   H1  import (merge) of an unrelated profile rename + a new pool, across a
//       parked publish: the import's changes must survive the release.
//   H2  config-version rollback restoring an unrelated profile, across a
//       parked publish: the rollback's restore must survive the release.
//
// BLOCKER 2 — the create transition. The create handler replaced the whole
// lifecycle record (Recreate) BEFORE the active create, so a refused or
// crashed active creation had already destroyed the prior evidence (draft,
// revisions, decided operations) that legitimately exists beside an absent
// profile (a rollback removed it; a draft saved before first publication).
//
//   G1  evidence beside an absent profile; the active-create write is forced
//       to fail: the create is a truthful failure, no success audit, no
//       config-version advance, and the evidence and the epoch identity are
//       UNCHANGED.
//   G2  a crash between the epoch preparation and the active create (the
//       handler goroutine exits at the "create_prepared" stage — absent on
//       the candidate, present after the correction): after a restart the
//       profile is absent, the evidence is intact, the durable transition
//       is recorded; a later successful create still mints a NEW epoch and
//       refuses a request reviewed against the old one (G3), keeping the
//       evidence.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

func pacBoundaryEnv(t *testing.T) {
	t.Helper()
	pacTransitionEnv(t)
	prev := pac.ProfileSetHook
	t.Cleanup(func() { pac.ProfileSetHook = prev })
	pac.ProfileSetHook = nil
}

// pacBoundarySeedOther adds an unrelated profile "other" (revision 1) beside
// branch-il — sequential fixture setup, not a competing writer.
func pacBoundarySeedOther(t *testing.T, name string) {
	t.Helper()
	cfg := pacProfiles.Get()
	kept := cfg.Profiles[:0]
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID != "other" {
			kept = append(kept, cfg.Profiles[i])
		}
	}
	kept = append(kept, pac.Profile{ID: "other", Name: name, Enabled: true, PoolID: "spare",
		PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Rules: []pac.Rule{}, Revision: 1})
	cfg.Profiles = kept
	if err := pacProfiles.Set(cfg); err != nil {
		t.Fatal(err)
	}
}

func pacBoundaryProfile(t *testing.T, id string) (pac.Profile, bool) {
	t.Helper()
	return pacProfiles.ProfileByID(id)
}

func pacBoundaryHasPool(id string) bool {
	_, ok := pacProfiles.PoolMap()[id]
	return ok
}

// pacBoundaryParkedPublish dispatches a publish of branch-il on its own
// goroutine and returns once it is parked at "intent_persisted" (intent
// durable, active store untouched). The returned release function lets it
// continue; waiting is signalled when a production writer reaches the
// serialization stage, wrote when any writer's candidate carrying
// `otherName` for profile "other" reaches the authoritative store.
func pacBoundaryParkedPublish(t *testing.T, otherName string) (release func(), done <-chan *httptest.ResponseRecorder, waiting, wrote <-chan struct{}) {
	t.Helper()
	parked := make(chan struct{}, 1)
	rel := make(chan struct{})
	wait := make(chan struct{}, 1)
	wr := make(chan struct{}, 1)
	pacLifecycleStageHook = func(stage string) {
		switch stage {
		case "intent_persisted":
			parked <- struct{}{}
			<-rel
		case "pac_writer_waiting":
			select {
			case wait <- struct{}{}:
			default:
			}
		}
	}
	pac.ProfileSetHook = func(cfg pac.ProfilesConfig) {
		for i := range cfg.Profiles {
			if cfg.Profiles[i].ID == "other" && cfg.Profiles[i].Name == otherName {
				select {
				case wr <- struct{}{}:
				default:
				}
			}
		}
	}
	out := make(chan *httptest.ResponseRecorder, 1)
	cur := pacContinuityProfile(t)
	inc := pacContinuityIncarnation(t)
	go func() {
		out <- pacTransitionPublishAt(t, uuid.NewString(), cur.Revision, pacIntentDraft("v2", false), inc, pac.ProfileSpecDigest(cur))
	}()
	<-parked
	return func() { close(rel) }, out, wait, wr
}

// ── H1 ──────────────────────────────────────────────────────────────────────

func TestPACBoundary_H1_ImportAcrossAParkedPublishKeepsBothChanges(t *testing.T) {
	pacBoundaryEnv(t)
	pacBoundarySeedOther(t, "Other")
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	const renamed = "Other renamed by import"
	release, publishDone, waiting, wrote := pacBoundaryParkedPublish(t, renamed)
	// the PRODUCTION import, merge mode: renames "other" and adds pool p2
	body := fmt.Sprintf(`{"version":%d,"pacProfiles":[{"id":"other","name":%q,"enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[]}],"pacPools":[{"id":"p2","name":"P2","endpoints":[{"host":"proxy-p2.example","port":8080}]}]}`, configBackupVersion, renamed)
	importDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		apiConfigImport(w, adminRequest("POST", "/api/config/import?mode=merge", body))
		importDone <- w
	}()
	// the writer either reached the authoritative store while the publish was
	// parked (the candidate) or is waiting at the production serialization
	// point (the correction) — only then is the publish released
	select {
	case <-wrote:
	case <-waiting:
	}
	release()
	pub := <-publishDone
	imp := <-importDone
	if pub.Code != 200 {
		t.Fatalf("publish: %d %s", pub.Code, pub.Body.String())
	}
	if imp.Code != 200 {
		t.Fatalf("import: %d %s", imp.Code, imp.Body.String())
	}
	// a valid SERIAL outcome: the publish landed AND the import's completed
	// changes to the unrelated profile and pool survived
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Name != "v2" {
		t.Fatalf("the publish must have landed: %+v %v", p, ok)
	}
	if o, ok := pacBoundaryProfile(t, "other"); !ok || o.Name != renamed || o.Revision != 2 {
		t.Fatalf("the import's completed change to the unrelated profile was lost: %+v ok=%v", o, ok)
	}
	if !pacBoundaryHasPool("p2") {
		t.Fatal("the import's added pool p2 was lost")
	}
}

// ── H2 ──────────────────────────────────────────────────────────────────────

func TestPACBoundary_H2_RollbackAcrossAParkedPublishKeepsItsRestore(t *testing.T) {
	pacBoundaryEnv(t)
	pacBoundarySeedOther(t, "Other")
	// the version the rollback restores: "other" named "Other"
	saveConfigVersion("boundary-fixture", "seed")
	target := 0
	for _, m := range configVersions.List() {
		if m.Version > target {
			target = m.Version
		}
	}
	if target == 0 {
		t.Fatal("fixture: no config version captured")
	}
	// meanwhile "other" moved on
	pacBoundarySeedOther(t, "Other changed")
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	release, publishDone, waiting, wrote := pacBoundaryParkedPublish(t, "Other")
	rollbackDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		rollbackConfigVersion(w, adminRequest("POST", "/api/config/versions/rollback", fmt.Sprintf(`{"version":%d}`, target)))
		rollbackDone <- w
	}()
	select {
	case <-wrote:
	case <-waiting:
	}
	release()
	pub := <-publishDone
	rb := <-rollbackDone
	if pub.Code != 200 {
		t.Fatalf("publish: %d %s", pub.Code, pub.Body.String())
	}
	if rb.Code != 200 {
		t.Fatalf("rollback: %d %s", rb.Code, rb.Body.String())
	}
	// the rollback's completed restore of the unrelated profile must survive
	if o, ok := pacBoundaryProfile(t, "other"); !ok || o.Name != "Other" {
		t.Fatalf("the rollback's completed restore of the unrelated profile was lost: %+v ok=%v", o, ok)
	}
}

// ── G1 ──────────────────────────────────────────────────────────────────────

// pacBoundaryEvidenceBesideAbsentProfile publishes once (revision 1 + a
// decided operation), then removes the active profile the way a config
// rollback can (the lifecycle record stays). Returns the operationId and the
// epoch identity of the surviving evidence.
func pacBoundaryEvidenceBesideAbsentProfile(t *testing.T) (opX, inc string) {
	t.Helper()
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	opX = uuid.NewString()
	if rec := pacIntentPublish(t, opX, 1, pacIntentDraft("v2", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	inc = pacContinuityIncarnation(t)
	cfg := pacProfiles.Get()
	kept := cfg.Profiles[:0]
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID != "branch-il" {
			kept = append(kept, cfg.Profiles[i])
		}
	}
	cfg.Profiles = kept
	if err := pacProfiles.Set(cfg); err != nil {
		t.Fatal(err)
	}
	m := pacEvidenceGet(t, "?operationId="+opX)
	if m["activeExists"] != false || len(m["revisions"].([]any)) != 1 {
		t.Fatalf("fixture: evidence beside an absent profile expected: %v", m)
	}
	return opX, inc
}

func pacBoundaryAssertEvidence(t *testing.T, opX, inc string, wantInc bool) {
	t.Helper()
	m := pacEvidenceGet(t, "?operationId="+opX)
	if n := len(m["revisions"].([]any)); n != 1 {
		t.Errorf("prior evidence must be preserved: %d revisions, want 1", n)
	}
	if op, _ := m["operation"].(map[string]any); op == nil || op["found"] != true {
		t.Errorf("prior evidence must be preserved: decided operation %s not found", opX)
	}
	if d, _ := m["draft"].(map[string]any); d == nil || d["name"] != "v2" {
		t.Errorf("prior evidence must be preserved: draft %v", m["draft"])
	}
	if wantInc && m["historyIncarnation"] != inc {
		t.Errorf("the epoch identity must be unchanged: %v, want %s", m["historyIncarnation"], inc)
	}
}

func pacBoundaryCreateAudits(since int64) int {
	n := 0
	ring := auditGet()
	for i := range ring {
		if ring[i].TS >= since && ring[i].Action == "pac.profile_create" && ring[i].Object == "branch-il" {
			n++
		}
	}
	return n
}

func pacBoundaryCreate(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	etag := pacContinuityCollectionEtag(t)
	create := pacContinuityBaseSpec[:len(pacContinuityBaseSpec)-1] + fmt.Sprintf(`,"revision":1,"collectionEtag":%q}`, etag)
	return pacFenceReq(t, "POST", "/api/pac/profiles", create, pacIntentIP)
}

func TestPACBoundary_G1_RefusedActiveCreatePreservesPriorEvidence(t *testing.T) {
	pacBoundaryEnv(t)
	opX, inc := pacBoundaryEvidenceBesideAbsentProfile(t)
	versions := len(configVersions.List())
	since := time.Now().UnixMilli()
	// the active store cannot be written (persist-before-swap: memory and
	// file stay as they are), so the create is refused
	profilesPath := pacFencePaths.profiles
	pacProfiles.Restore(pac.ProfileState{Cfg: pacProfiles.Get(), Path: filepath.Join(t.TempDir(), "missing", "pac_profiles.json")})
	rec := pacBoundaryCreate(t)
	pacProfiles.Restore(pac.ProfileState{Cfg: pacProfiles.Get(), Path: profilesPath})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a refused active create must be reported as a failure: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := pacBoundaryProfile(t, "branch-il"); ok {
		t.Fatal("the profile must not exist after the refused create")
	}
	if n := pacBoundaryCreateAudits(since); n != 0 {
		t.Errorf("a refused create must emit no success audit (got %d)", n)
	}
	if n := len(configVersions.List()); n != versions {
		t.Errorf("a refused create must not advance the config version (%d → %d)", versions, n)
	}
	pacBoundaryAssertEvidence(t, opX, inc, true)
}

// ── G2 / G3 ─────────────────────────────────────────────────────────────────

func TestPACBoundary_G2_CrashBetweenEpochPreparationAndActiveCreateIsRecoverable(t *testing.T) {
	pacBoundaryEnv(t)
	opX, inc := pacBoundaryEvidenceBesideAbsentProfile(t)
	// the process dies right after the create transition is recorded and
	// before the active create: the handler goroutine exits at that stage
	// (its deferred unlocks run, exactly as a crash leaves no lock behind)
	pacLifecycleStageHook = func(stage string) {
		if stage == "create_prepared" {
			runtime.Goexit()
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pacBoundaryCreate(t)
	}()
	<-done
	pacLifecycleStageHook = nil
	if _, ok := pacBoundaryProfile(t, "branch-il"); ok {
		t.Fatal("the crash happened before the active create: the profile must be absent")
	}
	// the durable transition is recorded beside the untouched evidence
	raw, err := os.ReadFile(pacFencePaths.lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]map[string]any
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file["branch-il"] == nil || file["branch-il"]["createPending"] != true {
		t.Errorf("the create transition must be durably recorded: %v", file["branch-il"])
	}
	if revs, _ := file["branch-il"]["revisions"].([]any); len(revs) != 1 {
		t.Errorf("prior evidence must be preserved on disk across the crash: %v", file["branch-il"]["revisions"])
	}
	// the next boot recovers: evidence intact, identity unchanged, no profile
	pacIntentRestartComplete(t)
	if _, ok := pacBoundaryProfile(t, "branch-il"); ok {
		t.Fatal("the profile must still be absent after the restart")
	}
	pacBoundaryAssertEvidence(t, opX, inc, true)
	// G3: a later successful recreation still starts a NEW epoch, refuses a
	// request reviewed against the old one, and keeps the evidence
	if rec := pacBoundaryCreate(t); rec.Code != 200 {
		t.Fatalf("recreate: %d %s", rec.Code, rec.Body.String())
	}
	if rev := pacContinuityPut(t, "Branch IL base"); rev != 2 {
		t.Fatalf("recreated base revision = %d, want 2", rev)
	}
	pacContinuitySaveDraft(t, pacIntentDraft("v2", false))
	incNew := pacContinuityIncarnation(t)
	if incNew == inc {
		t.Fatalf("a successful recreation must start a new epoch (still %s)", inc)
	}
	opY := uuid.NewString()
	rec := pacTransitionPublishAt(t, opY, 2, pacIntentDraft("v2", false), inc, "")
	pacTransitionAssertRefused(t, rec, opY, pacContinuityProfile(t), "history_incarnation_mismatch")
	pacBoundaryAssertEvidence(t, opX, incNew, true)
	if !strings.Contains(pacEvidenceGet(t, "")["historyIncarnation"].(string), "-") {
		t.Fatal("identity must be a UUID")
	}
}
