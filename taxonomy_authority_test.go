package main

// taxonomy_authority_test.go — Blocker C proofs (§§12–16): a v2 BuiltIn
// mutation's ownership decision participates in its linearization against
// signed authority transitions, and the state GET's ownership fields derive
// from ONE captured fact.
//
// The transition seam is feedLiveStore.Swap (the one production publish
// point — activation cutover, recovery install, override recompose), which
// holds taxonomyAuthorityGate exclusively; beginV2CategoryMutation holds the
// shared side across [ownership read → durable catStore mutation]. §14: one
// truthful serial result — signed ownership active before the mutation
// linearizes ⇒ structured 409 and no local mutation; local ownership wins
// first ⇒ durable success, with any later cutover a legitimately ordered
// supersession.
//
// Red-before against e221106d: the structural tests run with an inert gate
// shim (the var did not exist there); the GET-tear test is red without any
// shim. Deterministic — channels + the established Gosched/select technique.

import (
	"encoding/json"
	"net/http/httptest"
	"runtime"
	"testing"
)

// TestOwnershipLinearization_TransitionWaitsForInFlightBuiltInMutation is the
// §16 A–D script: a v2 BuiltIn mutation is past its ownership decision
// (local) — represented by the shared gate hold, the exact section
// beginV2CategoryMutation occupies — when a signed cutover starts. The
// cutover must WAIT; afterwards a new v2 mutation sees signed ownership.
func TestOwnershipLinearization_TransitionWaitsForInFlightBuiltInMutation(t *testing.T) {
	rev := ownershipSetup(t)
	installView(t, nil) // local authority; cleanup restores the pre-test view

	taxonomyAuthorityGate.RLock() // in-flight BuiltIn mutation, ownership decided = local
	swapDone := make(chan struct{})
	go func() {
		defer close(swapDone)
		saasEffectiveView.Swap(downloadedView()) // the production transition seam
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	escaped := false
	select {
	case <-swapDone:
		escaped = true
	default:
	}
	taxonomyAuthorityGate.RUnlock()
	<-swapDone
	if escaped {
		t.Fatal("signed authority transition completed while a v2 BuiltIn mutation was between its ownership decision and its durable mutation — the check said local, the cutover won, and the mutation would return normal success for an edit the now-serving signed view ignores")
	}
	// Post-transition truth: the next v2 mutation is refused.
	w := doURLCat(t, "PUT", "/api/urlcat?name=Social%20Media&ifRevision="+rev,
		map[string]any{"hosts": []string{"late.example.com"}})
	if w.Code != 409 {
		t.Fatalf("post-transition v2 BuiltIn mutation must be 409, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOwnershipLinearization_BuiltInMutationWaitsDuringTransition is the
// reverse direction: a transition holds the exclusive side; the v2 BuiltIn
// mutation must wait, then observe the POST-transition ownership (409, no
// local mutation) — never a success claimed across the cutover.
func TestOwnershipLinearization_BuiltInMutationWaitsDuringTransition(t *testing.T) {
	rev := ownershipSetup(t)
	installView(t, nil)
	fpBefore := catStore.ContentFingerprint()

	taxonomyAuthorityGate.Lock() // transition in progress
	w := httptest.NewRecorder()
	putDone := make(chan struct{})
	go func() {
		defer close(putDone)
		apiURLCat(w, jsonReq("PUT", "/api/urlcat?name=Social%20Media&ifRevision="+rev,
			map[string]any{"hosts": []string{"during.example.com"}}))
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	escaped := false
	select {
	case <-putDone:
		escaped = true
	default:
	}
	// Complete the transition INSIDE the exclusive section (what the real
	// Swap does under the gate), then release.
	saasEffectiveView.ptr.Store(downloadedView())
	taxonomyAuthorityGate.Unlock()
	<-putDone
	if escaped {
		t.Fatalf("v2 BuiltIn mutation completed while an authority transition held the gate (got %d) — the ownership check and the mutation did not linearize against the cutover", w.Code)
	}
	if w.Code != 409 {
		t.Fatalf("mutation waking after the cutover must see signed ownership (409), got %d: %s", w.Code, w.Body.String())
	}
	if got := catStore.ContentFingerprint(); got != fpBefore {
		t.Fatalf("the refused mutation must change nothing durable: %q -> %q", fpBefore, got)
	}
}

// TestOwnershipLinearization_AdminRowNeverSerializedAgainstTransition pins
// §13: an admin-created (BuiltIn=false) mutation is never feed-owned and
// deliberately does NOT serialize against signed activation.
func TestOwnershipLinearization_AdminRowNeverSerializedAgainstTransition(t *testing.T) {
	rev := ownershipSetup(t)
	installView(t, nil)

	taxonomyAuthorityGate.Lock()
	w := httptest.NewRecorder()
	putDone := make(chan struct{})
	go func() {
		defer close(putDone)
		apiURLCat(w, jsonReq("PUT", "/api/urlcat?name=Custom&ifRevision="+rev,
			map[string]any{"hosts": []string{"custom-during.example.com"}}))
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	completed := false
	select {
	case <-putDone:
		completed = true
	default:
	}
	taxonomyAuthorityGate.Unlock()
	<-putDone
	if !completed {
		t.Fatal("an admin-created mutation must not wait on the authority transition gate (§13)")
	}
	if w.Code != 200 {
		t.Fatalf("admin-created mutation: got %d: %s", w.Code, w.Body.String())
	}
}

// TestOwnership_SerialOutcomesAreTruthful pins the §14 serial contract in
// both orders: local-first mutation succeeds durably; after the cutover the
// same mutation is the structured 409.
func TestOwnership_SerialOutcomesAreTruthful(t *testing.T) {
	rev := ownershipSetup(t)
	installView(t, nil)

	w := doURLCat(t, "PUT", "/api/urlcat?name=Social%20Media&ifRevision="+rev,
		map[string]any{"hosts": []string{"local-first.example.com"}})
	if w.Code != 200 {
		t.Fatalf("local-first mutation: %d %s", w.Code, w.Body.String())
	}
	saasEffectiveView.Swap(downloadedView()) // later, legitimately ordered supersession
	rev2 := catStore.ContentFingerprint()
	w = doURLCat(t, "PUT", "/api/urlcat?name=Social%20Media&ifRevision="+rev2,
		map[string]any{"hosts": []string{"after-cutover.example.com"}})
	if w.Code != 409 {
		t.Fatalf("post-cutover mutation must be the structured 409, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOwnership_StateFieldsNeverTearAcrossTransition is the §15 proof: the
// page-level builtInAuthority and every row.writable must derive from ONE
// captured ownership fact — under a continuous authority flipper, a response
// may never pair authority=local with an unwritable built-in row (or the
// reverse). Red against e221106d, where the handler read ownership twice.
func TestOwnership_StateFieldsNeverTearAcrossTransition(t *testing.T) {
	ownershipSetup(t)
	installView(t, nil)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		signed := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			if signed {
				saasEffectiveView.Swap(downloadedView())
			} else {
				saasEffectiveView.Swap(nil)
			}
			signed = !signed
		}
	}()
	defer func() { close(stop); <-done }()

	const reads = 600
	for i := 0; i < reads; i++ {
		w := httptest.NewRecorder()
		apiURLCatState(w, getReq("/api/urlcat/state"))
		var resp struct {
			Categories []struct {
				Name     string `json:"name"`
				BuiltIn  bool   `json:"builtIn"`
				Writable bool   `json:"writable"`
			} `json:"categories"`
			BuiltInAuthority string `json:"builtInAuthority"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("read %d: decode: %v", i, err)
		}
		signed := resp.BuiltInAuthority == "signed-feed"
		for _, c := range resp.Categories {
			wantWritable := !(c.BuiltIn && signed)
			if c.Writable != wantWritable {
				t.Fatalf("read %d: TORN OWNERSHIP: builtInAuthority=%q but row %q (builtIn=%t) writable=%t — the two fields derive from different ownership reads", i, resp.BuiltInAuthority, c.Name, c.BuiltIn, c.Writable)
			}
		}
	}
}
