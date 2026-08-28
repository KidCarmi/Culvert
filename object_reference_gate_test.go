package main

// object_reference_gate_test.go — Blocker B proofs (2D-B final correction
// §§4–8): the reference-integrity mutation gate makes each shared-object
// delete's "scan says unreferenced" verdict ATOMIC with the durable deletion,
// serialized against every reference-creating/changing writer.
//
// Structure of the proof (deterministic — channels + the established
// Gosched/select technique, no sleeps as synchronization):
//
//   1. STRUCTURAL mutual exclusion through the REAL handlers, both
//      directions: an object delete must wait while a reference writer holds
//      the gate's shared side, and every reference writer must wait while the
//      exclusive side is held. Together with the RWMutex semantics this IS
//      the TOCTOU closure: a writer that committed (left the shared side)
//      before a delete acquires the exclusive side is fully visible to the
//      delete's scan, and a writer arriving during the delete waits until
//      after the deletion — so the scan's verdict is still true when the
//      delete lands. These fail against the prior frozen candidate (the
//      handlers there never consult the gate).
//   2. SEMANTIC pins (§7 A–E): a committed reference — running rule by
//      category / group / decryption profile, group membership, and an
//      ACTIVE DRAFT candidate rule — always blocks the delete with the
//      structured 409; never both-2xx with the referenced object gone.

import (
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// refGateSetup isolates every store the gate proofs touch: running policy +
// draft coordinator + RequireCommit (draftTestSetup), catStore, category
// groups, and decryption profiles.
func refGateSetup(t *testing.T) {
	t.Helper()
	draftTestSetup(t)
	snapshotCatStore(t)
	snapshotGlobalCategoryGroups(t)
	origProfiles := globalDecryptionProfiles
	globalDecryptionProfiles = decryptprofile.New()
	t.Cleanup(func() { globalDecryptionProfiles = origProfiles })

	catStore.ReplaceAll([]CategoryEntry{{Name: "gate-cat", Hosts: []string{"gc.example.com"}}})
	globalCategoryGroups.ReplaceAll([]CategoryGroup{{Name: "gate-group", Categories: []string{"gate-cat"}}})
	globalDecryptionProfiles.ReplaceAll([]DecryptionProfile{{Name: "gate-prof"}})
}

// assertGateBlocked asserts that done has NOT closed yet (the handler is
// waiting on the gate), then releases the gate via unlock and joins.
func assertGateBlocked(t *testing.T, what string, done chan struct{}, unlock func()) {
	t.Helper()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	escaped := false
	select {
	case <-done:
		escaped = true
	default:
	}
	unlock() // always release before reporting, so a failure never wedges the gate
	<-done
	if escaped {
		t.Fatalf("%s completed while the reference-integrity gate was held against it — the scan-vs-mutation TOCTOU is open", what)
	}
}

func TestRefGate_DeletesBlockWhileReferenceWriterHoldsGate(t *testing.T) {
	cases := []struct {
		name     string
		dispatch func(w *httptest.ResponseRecorder)
		wantCode int
	}{
		{"category-delete", func(w *httptest.ResponseRecorder) {
			apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		}, 204},
		{"category-group-delete", func(w *httptest.ResponseRecorder) {
			apiCategoryGroups(w, jsonReq("DELETE", "/api/category-groups?name=gate-group", nil))
		}, 200},
		{"decryption-profile-delete", func(w *httptest.ResponseRecorder) {
			apiDecryptionProfiles(w, jsonReq("DELETE", "/api/decryption-profiles?name=gate-prof", nil))
		}, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refGateSetup(t)
			// The group references gate-cat; delete the group first in the
			// category case so the category delete is unblocked semantically
			// and only the GATE can make it wait.
			if tc.name == "category-delete" {
				globalCategoryGroups.ReplaceAll(nil)
			}
			refWriteLock() // simulated in-flight reference writer
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.dispatch(w)
			}()
			assertGateBlocked(t, tc.name, done, refWriteUnlock)
			if w.Code != tc.wantCode {
				t.Fatalf("%s after release: got %d (%s), want %d", tc.name, w.Code, w.Body.String(), tc.wantCode)
			}
		})
	}
}

func TestRefGate_ReferenceWritersBlockWhileDeleteHoldsGate(t *testing.T) {
	cases := []struct {
		name     string
		dispatch func(w *httptest.ResponseRecorder)
	}{
		{"rule-create-dest-category", func(w *httptest.ResponseRecorder) {
			apiPolicyCreate(w, jsonReq("POST", "/api/policy",
				map[string]any{"name": "gate-r-cat", "action": "Allow", "destCategory": "gate-cat"}))
		}},
		{"rule-create-dest-group", func(w *httptest.ResponseRecorder) {
			apiPolicyCreate(w, jsonReq("POST", "/api/policy",
				map[string]any{"name": "gate-r-grp", "action": "Allow", "destCategoryGroup": "gate-group"}))
		}},
		{"rule-create-decryption-profile", func(w *httptest.ResponseRecorder) {
			apiPolicyCreate(w, jsonReq("POST", "/api/policy",
				map[string]any{"name": "gate-r-prof", "action": "Allow", "decryptionProfile": "gate-prof"}))
		}},
		{"group-membership-create", func(w *httptest.ResponseRecorder) {
			apiCategoryGroups(w, jsonReq("POST", "/api/category-groups",
				map[string]any{"name": "gate-group-2", "categories": []string{"gate-cat"}}))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refGateSetup(t)
			refScanDeleteLock() // simulated delete mid scan-and-delete decision
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.dispatch(w)
			}()
			assertGateBlocked(t, tc.name, done, refScanDeleteUnlock)
			if w.Code != 200 {
				t.Fatalf("%s after release: got %d (%s), want 200", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestRefGate_CommittedReferenceAlwaysBlocksDelete pins the §7 A–E semantic
// half: once a reference is committed (running rule, group membership, or an
// ACTIVE DRAFT candidate rule), the object delete is refused 409 and the
// object survives — never both-2xx with the referenced object gone.
func TestRefGate_CommittedReferenceAlwaysBlocksDelete(t *testing.T) {
	mustCreateRule := func(t *testing.T, body map[string]any) {
		t.Helper()
		w := httptest.NewRecorder()
		apiPolicyCreate(w, jsonReq("POST", "/api/policy", body))
		if w.Code != 200 {
			t.Fatalf("seed rule: %d %s", w.Code, w.Body.String())
		}
	}
	assertDelete409 := func(t *testing.T, dispatch func(w *httptest.ResponseRecorder), stillThere func() bool, what string) {
		t.Helper()
		w := httptest.NewRecorder()
		dispatch(w)
		if w.Code != 409 {
			t.Fatalf("%s: delete of a referenced object must be 409, got %d (%s)", what, w.Code, w.Body.String())
		}
		if !stillThere() {
			t.Fatalf("%s: object gone despite the 409", what)
		}
	}
	catPresent := func() bool {
		for _, e := range catStore.All() {
			if e.Name == "gate-cat" {
				return true
			}
		}
		return false
	}

	t.Run("A-category-vs-rule", func(t *testing.T) {
		refGateSetup(t)
		globalCategoryGroups.ReplaceAll(nil)
		mustCreateRule(t, map[string]any{"name": "r-a", "action": "Allow", "destCategory": "gate-cat"})
		assertDelete409(t, func(w *httptest.ResponseRecorder) {
			apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		}, catPresent, "A")
	})
	t.Run("B-category-vs-group-membership", func(t *testing.T) {
		refGateSetup(t)
		// gate-group already references gate-cat (setup seed).
		assertDelete409(t, func(w *httptest.ResponseRecorder) {
			apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		}, catPresent, "B")
	})
	t.Run("C-group-vs-rule", func(t *testing.T) {
		refGateSetup(t)
		mustCreateRule(t, map[string]any{"name": "r-c", "action": "Allow", "destCategoryGroup": "gate-group"})
		assertDelete409(t, func(w *httptest.ResponseRecorder) {
			apiCategoryGroups(w, jsonReq("DELETE", "/api/category-groups?name=gate-group", nil))
		}, func() bool { return globalCategoryGroups.GetByName("gate-group") != nil }, "C")
	})
	t.Run("D-profile-vs-rule", func(t *testing.T) {
		refGateSetup(t)
		mustCreateRule(t, map[string]any{"name": "r-d", "action": "Allow", "decryptionProfile": "gate-prof"})
		assertDelete409(t, func(w *httptest.ResponseRecorder) {
			apiDecryptionProfiles(w, jsonReq("DELETE", "/api/decryption-profiles?name=gate-prof", nil))
		}, func() bool { return globalDecryptionProfiles.GetByName("gate-prof") != nil }, "D")
	})
	t.Run("E-category-vs-active-draft-candidate", func(t *testing.T) {
		refGateSetup(t)
		globalCategoryGroups.ReplaceAll(nil)
		setRequireCommit(true) // staged mode: the create lands in the DRAFT candidate
		mustCreateRule(t, map[string]any{"name": "r-e", "action": "Allow", "destCategory": "gate-cat"})
		if !policyDraft.active() {
			t.Fatal("staged create must open the draft")
		}
		if len(policyStore.List()) != 0 {
			t.Fatal("staged create must not touch the running store")
		}
		assertDelete409(t, func(w *httptest.ResponseRecorder) {
			apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		}, catPresent, "E")
	})
}
