package main

// ha_promote_test.go — ADR-0004 Slice 1e: the explicit promote primitive
// (manual failover + coordinated planned handoff). Covers PromoteManually, the
// promote() idempotency guard, the admin endpoint, and the planned-promotion
// flag plumbing.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// standbyWith returns a standby HAState whose onPromote just records that it ran.
func standbyWith(onPromote func() error) *HAState {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.term = 4
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{onPromote: onPromote, set: true}
	h.mu.Unlock()
	return h
}

func TestPromoteManually_StandbyBecomesLeader(t *testing.T) {
	tempHADir(t)
	h := standbyWith(func() error { return nil })
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	if !h.IsLeader() {
		t.Error("expected role=leader after manual promotion")
	}
	if got := h.Status().Term; got != 5 {
		t.Errorf("term = %d, want 5 (4+1)", got)
	}
}

func TestPromoteManually_RejectsNonStandby(t *testing.T) {
	tempHADir(t)
	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.mu.Unlock()
	if err := h.PromoteManually(); err == nil {
		t.Error("expected error promoting a node that is already leader")
	}
}

func TestPromoteManually_NoContext(t *testing.T) {
	tempHADir(t)
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby" // standby but pc not set (never started via StartAsStandby)
	h.mu.Unlock()
	if err := h.PromoteManually(); err == nil {
		t.Error("expected error promoting a standby with no promote context")
	}
}

// promote() runs onPromote at most once even under repeated triggers.
func TestPromote_Idempotent(t *testing.T) {
	tempHADir(t)
	var calls atomic.Int32
	h := standbyWith(func() error { calls.Add(1); return nil })
	h.promote("first")
	h.promote("second") // already promoted → no-op
	if got := calls.Load(); got != 1 {
		t.Errorf("onPromote ran %d times, want 1 (idempotency guard)", got)
	}
}

// A failed onPromote resets the guard so a later attempt can retry.
func TestPromote_RetryAfterFailure(t *testing.T) {
	tempHADir(t)
	var calls atomic.Int32
	failFirst := true
	h := standbyWith(func() error {
		calls.Add(1)
		if failFirst {
			failFirst = false
			return errTestPromoteFail
		}
		return nil
	})
	h.promote("attempt-1") // fails → stays standby, guard reset
	if h.IsLeader() {
		t.Fatal("must stay standby after a failed promote")
	}
	h.promote("attempt-2") // retry succeeds
	if !h.IsLeader() {
		t.Error("retry should promote to leader")
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("onPromote ran %d times, want 2", got)
	}
}

func TestApiClusterHAPromote_Success(t *testing.T) {
	defer swapGlobalHA(t)()
	tempHADir(t)
	globalHA = standbyWith(func() error { return nil })

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/ha/promote", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHAPromote(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("promote = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !globalHA.IsLeader() {
		t.Error("node should be leader after promote endpoint")
	}
}

func TestApiClusterHAPromote_RejectsNonStandby(t *testing.T) {
	defer swapGlobalHA(t)()
	tempHADir(t)
	leader := &HAState{}
	leader.mu.Lock()
	leader.role = "leader"
	leader.mu.Unlock()
	globalHA = leader

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/ha/promote", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHAPromote(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("promote of a leader = %d, want 409", w.Code)
	}
}

func TestApiClusterHAPromote_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/ha/promote", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHAPromote(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", w.Code)
	}
}

// The leader-side planned-promotion flag arms/disarms and is what the HASync
// bundle reports to the standby for a coordinated handoff.
func TestPlannedPromotion_Flag(t *testing.T) {
	h := &HAState{}
	if h.plannedPromotion.Load() {
		t.Fatal("planned promotion should default off")
	}
	h.RequestPlannedPromotion()
	if !h.plannedPromotion.Load() {
		t.Error("RequestPlannedPromotion should arm the flag")
	}
	h.ClearPlannedPromotion()
	if h.plannedPromotion.Load() {
		t.Error("ClearPlannedPromotion should disarm the flag")
	}
}

// leaderWith returns a leader HAState for exercising the planned-handoff endpoint.
func leaderWith() *HAState {
	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.mu.Unlock()
	return h
}

func plannedHandoffRequest(armed bool) *http.Request {
	body := `{"armed":false}`
	if armed {
		body = `{"armed":true}`
	}
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/ha/planned-handoff", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	return req
}

// Before this endpoint existed, RequestPlannedPromotion/ClearPlannedPromotion
// had no caller anywhere in the binary — the coordinated-handoff design was
// fully wired end to end (leader stamps PromoteRequested into the HASync
// bundle, standby consumes it in syncFromLeader) but unreachable from any
// admin surface. These tests pin the endpoint that closes that gap.
func TestApiClusterHAPlannedHandoff_ArmsOnLeader(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA = leaderWith()

	w := httptest.NewRecorder()
	apiClusterHAPlannedHandoff(w, plannedHandoffRequest(true))

	if w.Code != http.StatusOK {
		t.Fatalf("arm = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !globalHA.plannedPromotion.Load() {
		t.Error("expected plannedPromotion armed after arm request")
	}
	if got := globalHA.Status().PlannedHandoff; !got {
		t.Error("Status().PlannedHandoff should reflect the armed flag")
	}
}

func TestApiClusterHAPlannedHandoff_Disarms(t *testing.T) {
	defer swapGlobalHA(t)()
	h := leaderWith()
	h.RequestPlannedPromotion()
	globalHA = h

	w := httptest.NewRecorder()
	apiClusterHAPlannedHandoff(w, plannedHandoffRequest(false))

	if w.Code != http.StatusOK {
		t.Fatalf("disarm = %d, want 200: %s", w.Code, w.Body.String())
	}
	if globalHA.plannedPromotion.Load() {
		t.Error("expected plannedPromotion disarmed after disarm request")
	}
}

func TestApiClusterHAPlannedHandoff_RejectsNonLeader(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA = standbyWith(func() error { return nil })

	w := httptest.NewRecorder()
	apiClusterHAPlannedHandoff(w, plannedHandoffRequest(true))

	if w.Code != http.StatusConflict {
		t.Fatalf("arm on a standby = %d, want 409", w.Code)
	}
	if globalHA.plannedPromotion.Load() {
		t.Error("a standby must not be able to arm planned handoff")
	}
}

func TestApiClusterHAPlannedHandoff_RejectsHADisabled(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA = &HAState{}

	w := httptest.NewRecorder()
	apiClusterHAPlannedHandoff(w, plannedHandoffRequest(true))

	if w.Code != http.StatusConflict {
		t.Fatalf("arm with HA disabled = %d, want 409", w.Code)
	}
}

func TestApiClusterHAPlannedHandoff_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/ha/planned-handoff", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHAPlannedHandoff(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", w.Code)
	}
}

func TestApiClusterHAPlannedHandoff_RequiresAdmin(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA = leaderWith()

	req := httptest.NewRequest(http.MethodPost, "/api/cluster/ha/planned-handoff", strings.NewReader(`{"armed":true}`))
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
	w := httptest.NewRecorder()
	apiClusterHAPlannedHandoff(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer role = %d, want 403", w.Code)
	}
	if globalHA.plannedPromotion.Load() {
		t.Error("a viewer must not be able to arm planned handoff")
	}
}
