package main

// refs_by_id_decryptprofile_test.go — rule→decryption-profile references-by-id
// + rename (S1, OBJECT-REFERENCES-BY-ID.md): ID-authoritative match with name
// fallback, write-path stamp, rename cascade (hit-preserving), ID-first
// delete-block, and the handler rename flow.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveDecryptionProfile_IDFirstWithFallback(t *testing.T) {
	snapshotDecProfilesForTest(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "prof", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	// ID-authoritative even when the denormalized name is stale.
	if got := resolveDecryptionProfile(&PolicyMatch{Rule: &PolicyRule{
		DecryptionProfileID: p.ID, DecryptionProfile: "stale-name"}}); got == nil || got.ID != p.ID {
		t.Fatalf("ID-first resolution failed: %+v", got)
	}
	// Un-migrated rule (name only) still resolves.
	if got := resolveDecryptionProfile(&PolicyMatch{Rule: &PolicyRule{
		DecryptionProfile: "prof"}}); got == nil || got.ID != p.ID {
		t.Fatalf("name-fallback failed: %+v", got)
	}
	// Dangling ID falls back to the name.
	if got := resolveDecryptionProfile(&PolicyMatch{Rule: &PolicyRule{
		DecryptionProfileID: "deadbeef0000", DecryptionProfile: "prof"}}); got == nil || got.ID != p.ID {
		t.Fatalf("dangling-id name-fallback failed: %+v", got)
	}
	// No reference at all → nil.
	if got := resolveDecryptionProfile(&PolicyMatch{Rule: &PolicyRule{}}); got != nil {
		t.Errorf("no-ref rule should resolve nil, got %+v", got)
	}
}

func TestStampObjectRefIDs_DecryptionProfile(t *testing.T) {
	snapshotDecProfilesForTest(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "prof", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	// A client-supplied ID is discarded and re-derived from the name.
	r := PolicyRule{DecryptionProfile: "prof", DecryptionProfileID: "client-bogus"}
	stampObjectRefIDs(&r)
	if r.DecryptionProfileID != p.ID {
		t.Errorf("stamp did not derive id from name: got %q want %q", r.DecryptionProfileID, p.ID)
	}
	// Unknown name → empty ID (fail-safe).
	r2 := PolicyRule{DecryptionProfile: "nope"}
	stampObjectRefIDs(&r2)
	if r2.DecryptionProfileID != "" {
		t.Errorf("unknown name should leave id empty, got %q", r2.DecryptionProfileID)
	}
}

func TestCascadeDecryptionProfileRename(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotDecProfilesForTest(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "old", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "migrated", DecryptionProfile: "old", DecryptionProfileID: p.ID, Action: ActionAllow},
		{Name: "nameonly", DecryptionProfile: "old", Action: ActionAllow}, // un-migrated
		{Name: "unrelated", DecryptionProfile: "other", Action: ActionAllow},
	})
	if n := policyStore.CascadeDecryptionProfileRename(p.ID, "old", "new"); n != 2 {
		t.Fatalf("cascade touched %d rules, want 2", n)
	}
	rules := policyStore.List()
	for i := range rules {
		switch rules[i].Name {
		case "migrated", "nameonly":
			if rules[i].DecryptionProfile != "new" {
				t.Errorf("%s: name not cascaded (%q)", rules[i].Name, rules[i].DecryptionProfile)
			}
			if rules[i].DecryptionProfileID != p.ID {
				t.Errorf("%s: id not stamped (%q)", rules[i].Name, rules[i].DecryptionProfileID)
			}
		case "unrelated":
			if rules[i].DecryptionProfile != "other" || rules[i].DecryptionProfileID != "" {
				t.Errorf("unrelated rule was touched: %+v", rules[i])
			}
		}
	}
}

func TestObjectReferences_DecryptionProfileIDFirst(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotDecProfilesForTest(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "prof", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	// Rule links by ID but its denormalized name is STALE (partial-cascade case).
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "r1", DecryptionProfile: "STALE", DecryptionProfileID: p.ID, Action: ActionAllow},
	})
	found, refs := objectReferences("decryption-profile", "prof")
	if !found || len(refs) != 1 || refs[0].Name != "r1" {
		t.Fatalf("ID-first delete-block did not find the stale-named referencing rule: %+v", refs)
	}
}

// TestObjectReferences_DecryptionProfileDanglingIDFallsBackToName pins the
// walk↔match parity fix: a rule with a DANGLING DecryptionProfileID whose name
// resolves to a live profile is enforcing that profile at eval time
// (resolveDecryptionProfile falls back to the name), so the delete-block walk
// must attribute it too — else the profile (carrying a strict cert posture)
// is deletable while a rule still relies on it.
func TestObjectReferences_DecryptionProfileDanglingIDFallsBackToName(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotDecProfilesForTest(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "live", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "dangler", DecryptionProfile: "live", DecryptionProfileID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Action: ActionAllow},
	})
	_, refs := objectReferences("decryption-profile", "live")
	if len(refs) != 1 || refs[0].Name != "dangler" {
		t.Errorf("dangling-ID rule enforcing by name must block the profile's delete: %+v", refs)
	}
	_ = p
}

func TestApiDecryptionProfile_RenameCascades(t *testing.T) {
	snapshotDecProfilesForTest(t)
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "old", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "r1", DecryptionProfile: "old", DecryptionProfileID: p.ID, Action: ActionAllow},
	})

	body := `{"name":"new","certVerification":"strict"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/decryption-profiles?id="+p.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiDecryptionProfiles(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("rename PUT = %d (%s)", w.Code, w.Body.String())
	}
	if globalDecryptionProfiles.GetByName("new") == nil {
		t.Error("profile was not renamed to 'new'")
	}
	if globalDecryptionProfiles.GetByName("old") != nil {
		t.Error("old profile name still resolves")
	}
	// The referencing rule's denormalized name followed the rename, and matching
	// still resolves (by ID).
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].DecryptionProfile != "new" {
		t.Errorf("referencing rule's name not cascaded: %+v", rules)
	}
	if got := resolveDecryptionProfile(&PolicyMatch{Rule: &rules[0]}); got == nil || got.Name != "new" {
		t.Errorf("rule no longer resolves its profile after rename: %+v", got)
	}
}

// TestApiDecryptionProfile_RenameCascadesDraft pins Finding 2: a profile rename
// during an ACTIVE draft must also refresh the candidate's denormalized names,
// so a later commit does not write stale names back over running.
func TestApiDecryptionProfile_RenameCascadesDraft(t *testing.T) {
	draftTestSetup(t)
	snapshotDecProfilesForTest(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "old", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	// Open a draft and stage a rule that references the profile by ID.
	setRequireCommit(true)
	cand := policyDraft.stageTarget("admin@test")
	cand.Add(PolicyRule{Name: "cr", DecryptionProfile: "old", DecryptionProfileID: p.ID, Action: ActionAllow})

	body := `{"name":"new","certVerification":"strict"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/decryption-profiles?id="+p.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiDecryptionProfiles(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("rename PUT = %d (%s)", w.Code, w.Body.String())
	}
	crules := policyDraft.candidateList()
	if len(crules) != 1 || crules[0].DecryptionProfile != "new" {
		t.Errorf("draft candidate's denormalized name not cascaded: %+v", crules)
	}
}

// TestApiDecryptionProfile_RenameCollision409 pins Finding 3's pre-check: a
// rename onto a name owned by a DIFFERENT profile is rejected with 409 and
// mutates nothing (neither profile content nor name).
func TestApiDecryptionProfile_RenameCollision409(t *testing.T) {
	snapshotDecProfilesForTest(t)
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "a", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "b", CertVerification: "strict"}); err != nil {
		t.Fatal(err)
	}
	// Try to rename "a" → "b" while ALSO changing content (skip verify).
	body := `{"name":"b","certVerification":"skip"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/decryption-profiles?id="+p.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiDecryptionProfiles(w, adminCtx(req))
	if w.Code != http.StatusConflict {
		t.Fatalf("collision rename = %d (%s), want 409", w.Code, w.Body.String())
	}
	// Nothing changed: "a" keeps its name AND its original content (not "skip").
	if g := globalDecryptionProfiles.GetByID(p.ID); g == nil || g.Name != "a" || g.CertVerification != "strict" {
		t.Errorf("collision must not mutate the profile: %+v", g)
	}
}
