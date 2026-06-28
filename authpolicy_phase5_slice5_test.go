package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Phase 5 Slice 5 (FINAL) — convergence/cleanup. UnauthMode is gone:
// defaultAuthOutcome is the sole source of truth. These tests pin the legacy
// unauth_mode read-only import-compat (conflict-wins), the AuthEnabled()/
// IsConfigured() split (admin-UI no-surprise), the SOCKS5 inversion removal, and
// the ConfigSnapshot field swap.

// ── Conflict-wins: default_auth_outcome is always authoritative ──────────────

// When BOTH fields are present with conflicting values, default_auth_outcome
// ALWAYS wins, deterministically (legacy unauth_mode is read-only and never
// authoritative once default_auth_outcome exists).
func TestS5_ConfigConflict_DefaultAuthOutcomeWins(t *testing.T) {
	cases := []struct {
		body string
		want AuthOutcome
	}{
		{`{"default_auth_outcome":"Default","unauth_mode":true,"users":[]}`, OutcomeDefault},
		{`{"default_auth_outcome":"Exempt","unauth_mode":false,"users":[]}`, OutcomeExempt},
		{`{"default_auth_outcome":"","unauth_mode":true,"users":[]}`, OutcomeDefault}, // present-but-empty ⇒ fail closed, never reopen
	}
	for _, tc := range cases {
		// Load repeatedly to prove determinism (no order/flake dependence).
		for i := 0; i < 5; i++ {
			c := loadEnvelope(t, tc.body)
			if c.defaultAuthOutcome != tc.want {
				t.Fatalf("conflict %q (iter %d): got %q, want %q (default_auth_outcome must always win)", tc.body, i, c.defaultAuthOutcome, tc.want)
			}
		}
	}
	// Legacy-only (default_auth_outcome absent) still migrates once.
	if c := loadEnvelope(t, `{"unauth_mode":true,"users":[]}`); c.defaultAuthOutcome != OutcomeExempt {
		t.Errorf("legacy-only unauth_mode=true must migrate to Exempt, got %q", c.defaultAuthOutcome)
	}
}

// ── Admin-UI no-surprise: Exempt-no-backend stays GATED (IsConfigured) ───────

// ui_middleware grants RoleAdmin-to-everyone only when setup is NOT complete.
// Open mode (Exempt) counts as configured (IsConfigured true), so the admin UI
// must stay gated — a naive AuthEnabled() decouple would have opened it.
func TestS5_AdminUI_ExemptKeepsGated(t *testing.T) {
	setupProxyTest(t) // no user/provider
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := uiAuthMiddleware(sentinel)

	// Exempt + no backend ⇒ IsConfigured ⇒ unauthenticated /api request is 401.
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/settings", http.NoBody))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Exempt-no-backend admin UI must stay gated (401), got %d — security regression", w.Code)
	}

	// Default + no backend ⇒ NOT configured ⇒ first-time setup grants RoleAdmin.
	cfg.SetDefaultAuthOutcome(OutcomeDefault)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/settings", http.NoBody))
	if w.Code != http.StatusOK {
		t.Fatalf("Default-no-backend (unconfigured) must open for first-time setup (200), got %d", w.Code)
	}
}

// ── SOCKS5 transition (inversion removed) ────────────────────────────────────

// socks5SelectedMethod offers a single auth method and returns the method the
// server selects (0x00 no-auth, 0x02 USERPASS, 0xFF none acceptable).
func socks5SelectedMethod(t *testing.T, addr string, method byte) byte {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	return resp[1]
}

func TestS5_SOCKS5_Transition(t *testing.T) {
	// Open install, NO credential backend ⇒ AuthEnabled() false ⇒ SOCKS5
	// negotiates no-auth (the inversion is gone — was: required USERPASS).
	setupProxyTest(t)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	ln := startSOCKS5Listener(t)
	addr := ln.Addr().String()
	if m := socks5SelectedMethod(t, addr, 0x00); m != 0x00 {
		t.Errorf("Exempt + no backend: server must accept no-auth (0x00), got 0x%02x", m)
	}
	_ = ln.Close()

	// With a credential backend ⇒ AuthEnabled() true ⇒ SOCKS5 requires USERPASS:
	// a no-auth offer is rejected (0xFF) and a USERPASS offer is selected (0x02).
	setupProxyTest(t)
	if err := cfg.SetAuth("u", "Passw0rd"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	ln2 := startSOCKS5Listener(t)
	addr2 := ln2.Addr().String()
	if m := socks5SelectedMethod(t, addr2, 0x00); m != 0xFF {
		t.Errorf("backend present: no-auth offer must be rejected (0xFF), got 0x%02x", m)
	}
	if m := socks5SelectedMethod(t, addr2, 0x02); m != 0x02 {
		t.Errorf("backend present: USERPASS offer must be selected (0x02), got 0x%02x", m)
	}
	_ = ln2.Close()
}

// ── Cluster: ConfigSnapshot carries defaultAuthOutcome ───────────────────────

func TestS5_ClusterSnapshot_CarriesDefaultAuthOutcome(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	if got := CurrentConfigSnapshot().DefaultAuthOutcome; got != "Exempt" {
		t.Errorf("snapshot DefaultAuthOutcome = %q, want Exempt", got)
	}
	cfg.SetDefaultAuthOutcome(OutcomeDefault)
	if got := CurrentConfigSnapshot().DefaultAuthOutcome; got != "Default" {
		t.Errorf("snapshot DefaultAuthOutcome = %q, want Default", got)
	}
}

// ── Diagnostics repointed to defaultAuthOutcome ──────────────────────────────

func TestS5_Diagnostics_DefaultAuthOpen(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	if c := checkDefaultAuthOpen(); c.Code != "default_auth_open" || c.Status != diagWarn {
		t.Errorf("Exempt ⇒ default_auth_open WARN, got %+v", c)
	}
	cfg.SetDefaultAuthOutcome(OutcomeDefault)
	if c := checkDefaultAuthOpen(); c.Status != diagOK {
		t.Errorf("Default ⇒ default_auth_open OK, got %+v", c)
	}
}
