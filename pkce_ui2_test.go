package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/authstate"
)

// ─── pkceStore ────────────────────────────────────────────────────────────────

func TestPKCEStore_SetPeekPop(t *testing.T) {
	s := newPKCEStore()

	e := &pkceEntry{providerID: "test-provider"}
	s.Set("state1", "203.0.113.5", e)

	got, ok := s.Peek("state1")
	if !ok {
		t.Fatal("peek should find entry after set")
	}
	if got.providerID != "test-provider" {
		t.Errorf("peek providerID = %q, want test-provider", got.providerID)
	}

	popped, ok := s.Pop("state1")
	if !ok {
		t.Fatal("pop should find entry")
	}
	if popped.providerID != "test-provider" {
		t.Errorf("pop providerID = %q, want test-provider", popped.providerID)
	}

	_, ok = s.Peek("state1")
	if ok {
		t.Error("peek after pop should not find entry")
	}
}

func TestPKCEStore_Pop_Missing(t *testing.T) {
	s := newPKCEStore()
	if _, ok := s.Pop("nonexistent"); ok {
		t.Error("pop nonexistent should return false")
	}
}

func TestPKCEStore_Peek_Missing(t *testing.T) {
	s := newPKCEStore()
	if _, ok := s.Peek("nonexistent"); ok {
		t.Error("peek nonexistent should return false")
	}
}

// expiredPKCEStore returns a store holding one entry created outside the TTL.
// The store owns entry creation time (internal/authstate), so expiry is driven
// through an injected clock rather than by back-dating a struct field.
func expiredPKCEStore(t *testing.T) *pkceStore {
	t.Helper()
	clock := time.Now().Add(-(pkceEntryTTL + time.Second))
	s := authstate.NewWithClock[*pkceEntry](pkceEntryTTL, pkceStoreMax, func() time.Time { return clock })
	s.Set("expired", "203.0.113.5", &pkceEntry{providerID: "test"})
	clock = time.Now()
	return s
}

func TestPKCEStore_Pop_Expired(t *testing.T) {
	s := expiredPKCEStore(t)
	if _, ok := s.Pop("expired"); ok {
		t.Error("pop expired entry should return false")
	}
}

func TestPKCEStore_Peek_Expired(t *testing.T) {
	s := expiredPKCEStore(t)
	if _, ok := s.Peek("expired"); ok {
		t.Error("peek expired entry should return false")
	}
}

func TestPKCEStore_Set_Eviction(t *testing.T) {
	s := newPKCEStore()
	for i := 0; i < pkceStoreMax; i++ {
		s.Set(fmt.Sprintf("state-%d", i), "203.0.113.5", &pkceEntry{providerID: "p"})
	}
	s.Set("overflow-state", "203.0.113.6", &pkceEntry{providerID: "overflow"})
	if size := s.Len(); size > pkceStoreMax {
		t.Errorf("pkceStore grew too large: %d entries (max %d)", size, pkceStoreMax)
	}
}

// ─── apiSetupComplete ─────────────────────────────────────────────────────────

func TestAPISetupComplete_AlreadySetup(t *testing.T) {
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	// Set auth so AuthEnabled() = true
	_ = cfg.SetAuth("setupuser", "setuppass123")
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "admin",
		"pass": "password123",
	})
	apiSetupComplete(w, r)
	assertStatus(t, w, http.StatusForbidden)
}

func TestAPISetupComplete_BadJSON(t *testing.T) {
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	// Make sure auth is not enabled
	_ = cfg.SetAuth("", "")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/setup/complete", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	apiSetupComplete(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPISetupComplete_EmptyUser(t *testing.T) {
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	_ = cfg.SetAuth("", "")

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "",
		"pass": "strongpassword",
	})
	apiSetupComplete(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiTopHosts ──────────────────────────────────────────────────────────────

func TestAPITopHosts_Default(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/top-hosts", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTopHosts(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPITopHosts_WithN(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/top-hosts?n=5", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTopHosts(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPITopHosts_BadN(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/top-hosts?n=badvalue", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTopHosts(w, r)
	assertStatus(t, w, http.StatusOK) // falls back to default n=20
}

// ─── apiSyslogConfig ──────────────────────────────────────────────────────────

func TestAPISyslogConfig_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/syslog", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSyslogConfig(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPISyslogConfig_Post_EmptyAddr(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/syslog", map[string]any{
		"addr": "",
	})
	r = adminCtx(r)
	apiSyslogConfig(w, r)
	assertStatus(t, w, http.StatusOK)
}
