package main

// ha_term_test.go — Slice 1c (ADR-0004): leadership term/epoch lifecycle and
// the split-brain-visible /healthz surface. The term is plumbing + visibility;
// cross-side term ARBITRATION (which side wins on heal) is deferred to the
// failover-mechanism slice (ADR-0004 F7).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func tempHADir(t *testing.T) {
	t.Helper()
	orig := clusterDBPathGlobal
	clusterDBPathGlobal = t.TempDir() + "/cluster.json"
	t.Cleanup(func() { clusterDBPathGlobal = orig })
}

// EnableAsLeader starts term 1; promote bumps it; ResumeAsLeader preserves it.
func TestHA_Term_Lifecycle(t *testing.T) {
	tempHADir(t)

	h := &HAState{}
	_, _ = h.EnableAsLeader("cp1:50051", false)
	if got := h.Status().Term; got != 1 {
		t.Fatalf("EnableAsLeader term = %d, want 1", got)
	}

	// promote (standby→leader) bumps the epoch.
	h.mu.Lock()
	h.role = "standby"
	h.term = 5
	h.promoted.Store(false)
	h.pc = promoteContext{onPromote: func() error { return nil }, set: true}
	h.mu.Unlock()
	h.promote("test")
	if got := h.Status().Term; got != 6 {
		t.Fatalf("promote term = %d, want 6 (5+1)", got)
	}
	if !h.IsLeader() {
		t.Error("promote should leave role=leader")
	}

	// ResumeAsLeader (restart) restores the persisted term WITHOUT bumping.
	h2 := &HAState{}
	h2.ResumeAsLeader(&haConfig{Enabled: true, Token: "tok", PeerAddr: "cp1:50051", Role: "leader", Term: 9})
	if got := h2.Status().Term; got != 9 {
		t.Fatalf("ResumeAsLeader term = %d, want 9 (no bump)", got)
	}
	if !h2.IsLeader() {
		t.Error("ResumeAsLeader should set role=leader")
	}
}

// Codex P2: a standby seeds its epoch from the leader's term so a later
// promotion yields a strictly-higher epoch (the /healthz split-brain signal).
func TestHA_SeedTermFromLeader(t *testing.T) {
	tempHADir(t)
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.term = 0
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{onPromote: func() error { return nil }, set: true}
	h.mu.Unlock()

	h.seedTermFromLeader(7) // leader is at epoch 7
	if got := h.Status().Term; got != 7 {
		t.Fatalf("seeded term = %d, want 7", got)
	}
	// Never lowers.
	h.seedTermFromLeader(3)
	if got := h.Status().Term; got != 7 {
		t.Errorf("seed must not lower the term: got %d, want 7", got)
	}
	// A promotion now produces a strictly-higher epoch than the leader's 7.
	h.promote("test")
	if got := h.Status().Term; got != 8 {
		t.Errorf("post-promotion term = %d, want 8 (7+1, > leader's 7)", got)
	}

	// Once leader, seeding is a no-op (does not get dragged backward/forward).
	h.seedTermFromLeader(99)
	if got := h.Status().Term; got != 8 {
		t.Errorf("leader term must not be reseeded: got %d, want 8", got)
	}
}

// /healthz exposes term + write_authority so an external monitor can detect a
// double-leader by scraping both CPs.
func TestHA_Healthz_ExposesTermAndWriteAuthority(t *testing.T) {
	defer swapGlobalHA(t)()

	// Leader side: 200 + write_authority true + term.
	leader := &HAState{}
	leader.mu.Lock()
	leader.role = "leader"
	leader.term = 3
	leader.mu.Unlock()
	globalHA = leader

	w := httptest.NewRecorder()
	apiHealthz(w, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if w.Code != http.StatusOK {
		t.Fatalf("leader /healthz = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["term"].(float64) != 3 {
		t.Errorf("leader term = %v, want 3", body["term"])
	}
	if body["write_authority"] != true {
		t.Errorf("leader write_authority = %v, want true", body["write_authority"])
	}

	// Standby side: 503 + write_authority false + its own term.
	standby := &HAState{}
	standby.mu.Lock()
	standby.role = "standby"
	standby.term = 1
	standby.mu.Unlock()
	globalHA = standby

	w2 := httptest.NewRecorder()
	apiHealthz(w2, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("standby /healthz = %d, want 503", w2.Code)
	}
	var body2 map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &body2); err != nil {
		t.Fatalf("decode standby: %v", err)
	}
	if body2["write_authority"] != false {
		t.Errorf("standby write_authority = %v, want false", body2["write_authority"])
	}

	// Detection material: two nodes both leader at different terms is the
	// operator-visible split-brain signal (the higher term promoted later).
	if body["role"] != "leader" {
		t.Errorf("leader role = %v", body["role"])
	}
}

// Standalone (HA disabled) stays healthy with write authority.
func TestHA_Healthz_StandaloneHasWriteAuthority(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA = &HAState{} // role "" → not enabled

	w := httptest.NewRecorder()
	apiHealthz(w, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if w.Code != http.StatusOK {
		t.Fatalf("standalone /healthz = %d, want 200", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["role"] != "standalone" || body["write_authority"] != true {
		t.Errorf("standalone health = %v; want role=standalone write_authority=true", body)
	}
}
