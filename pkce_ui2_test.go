package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ─── pkceStore ────────────────────────────────────────────────────────────────

func TestPKCEStore_SetPeekPop(t *testing.T) {
	s := &pkceStore{entries: make(map[string]*pkceEntry)}

	e := &pkceEntry{createdAt: time.Now(), providerID: "test-provider"}
	s.set("state1", e)

	got, ok := s.peek("state1")
	if !ok {
		t.Fatal("peek should find entry after set")
	}
	if got.providerID != "test-provider" {
		t.Errorf("peek providerID = %q, want test-provider", got.providerID)
	}

	popped, ok := s.pop("state1")
	if !ok {
		t.Fatal("pop should find entry")
	}
	if popped.providerID != "test-provider" {
		t.Errorf("pop providerID = %q, want test-provider", popped.providerID)
	}

	_, ok = s.peek("state1")
	if ok {
		t.Error("peek after pop should not find entry")
	}
}

func TestPKCEStore_Pop_Missing(t *testing.T) {
	s := &pkceStore{entries: make(map[string]*pkceEntry)}
	_, ok := s.pop("nonexistent")
	if ok {
		t.Error("pop nonexistent should return false")
	}
}

func TestPKCEStore_Peek_Missing(t *testing.T) {
	s := &pkceStore{entries: make(map[string]*pkceEntry)}
	_, ok := s.peek("nonexistent")
	if ok {
		t.Error("peek nonexistent should return false")
	}
}

func TestPKCEStore_Pop_Expired(t *testing.T) {
	s := &pkceStore{entries: make(map[string]*pkceEntry)}
	// Set an entry with a past creation time (expired)
	s.entries["expired"] = &pkceEntry{
		createdAt:  time.Now().Add(-(pkceEntryTTL + time.Second)),
		providerID: "test",
	}
	_, ok := s.pop("expired")
	if ok {
		t.Error("pop expired entry should return false")
	}
}

func TestPKCEStore_Peek_Expired(t *testing.T) {
	s := &pkceStore{entries: make(map[string]*pkceEntry)}
	s.entries["expired"] = &pkceEntry{
		createdAt:  time.Now().Add(-(pkceEntryTTL + time.Second)),
		providerID: "test",
	}
	_, ok := s.peek("expired")
	if ok {
		t.Error("peek expired entry should return false")
	}
}

func TestPKCEStore_Set_Eviction(t *testing.T) {
	s := &pkceStore{entries: make(map[string]*pkceEntry)}
	// Fill up to max
	for i := 0; i < pkceStoreMax; i++ {
		state := "state" + string(rune('a'+i%26)) + string(rune('0'+i%10))
		s.entries[state+string(rune(i))] = &pkceEntry{
			createdAt:  time.Now(),
			providerID: "p",
		}
	}
	// Adding one more should trigger eviction
	s.set("overflow-state", &pkceEntry{createdAt: time.Now(), providerID: "overflow"})
	s.mu.Lock()
	size := len(s.entries)
	s.mu.Unlock()
	if size > pkceStoreMax+1 {
		t.Errorf("pkceStore grew too large: %d entries (max %d)", size, pkceStoreMax)
	}
}

// ─── apiSetupComplete ─────────────────────────────────────────────────────────

func TestAPISetupComplete_AlreadySetup(t *testing.T) {
	// Set auth so AuthEnabled() = true
	_ = cfg.SetAuth("setupuser", "setuppass123")
	defer cfg.SetAuth("", "") //nolint:errcheck

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "admin",
		"pass": "password123",
	})
	apiSetupComplete(w, r)
	assertStatus(t, w, http.StatusForbidden)
}

func TestAPISetupComplete_BadJSON(t *testing.T) {
	// Make sure auth is not enabled
	_ = cfg.SetAuth("", "")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/setup/complete", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiSetupComplete(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPISetupComplete_EmptyUser(t *testing.T) {
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
	r := httptest.NewRequest(http.MethodGet, "/api/top-hosts", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTopHosts(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPITopHosts_WithN(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/top-hosts?n=5", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTopHosts(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPITopHosts_BadN(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/top-hosts?n=badvalue", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTopHosts(w, r)
	assertStatus(t, w, http.StatusOK) // falls back to default n=20
}

// ─── apiSyslogConfig ──────────────────────────────────────────────────────────

func TestAPISyslogConfig_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/syslog", nil)
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
