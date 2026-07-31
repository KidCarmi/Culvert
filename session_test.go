package main

// session_test.go — main-side session tests. Engine tests (encode/decode/MAC,
// revocation list, TTL clamp, the C5.1 Jti suite) moved to internal/session
// with the ADR-0002 extraction. This file keeps what needs main: the
// Session→Identity conversion and the cookie-revocation HTTP helper.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/session"
)

// initSecret initialises the session signing key if it hasn't been set yet.
// Safe to call from multiple tests. (Shared helper — qa_gate_test.go and
// ui_test.go rely on it too.)
func initSecret(t *testing.T) {
	t.Helper()
	if !session.HasSigningKey() {
		initSessionSecret()
	}
}

// ─── sessionIdentity ─────────────────────────────────────────────────────────

func TestSession_Identity(t *testing.T) {
	s := &Session{
		Sub:      "u-001",
		Email:    "bob@example.com",
		Name:     "Bob",
		Groups:   []string{"ops"},
		Provider: "okta",
	}
	id := sessionIdentity(s)

	if id.Sub != s.Sub {
		t.Errorf("sessionIdentity().Sub = %q, want %q", id.Sub, s.Sub)
	}
	if id.Email != s.Email {
		t.Errorf("sessionIdentity().Email = %q, want %q", id.Email, s.Email)
	}
	if id.Name != s.Name {
		t.Errorf("sessionIdentity().Name = %q, want %q", id.Name, s.Name)
	}
	if id.Provider != s.Provider {
		t.Errorf("sessionIdentity().Provider = %q, want %q", id.Provider, s.Provider)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "ops" {
		t.Errorf("sessionIdentity().Groups = %v, want [ops]", id.Groups)
	}
}

// TestSession_Jti_NotInIdentity — Jti is a session-scope value, not an
// identity attribute. sessionIdentity must not surface it (no field on
// Identity exists for it, and no copy path should sneak it in via a
// future refactor).
func TestSession_Jti_NotInIdentity(t *testing.T) {
	s := &Session{Sub: "frank", Email: "f@example.com", Provider: "local", Jti: newSessionJti()}
	id := sessionIdentity(s)
	// Identity has no Jti field; this test guards against a future
	// addition that bridges them. We assert by JSON-marshaling the
	// identity and ensuring the Jti string never appears in it.
	idJSON, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("marshal Identity: %v", err)
	}
	if strings.Contains(string(idJSON), s.Jti) {
		t.Errorf("Identity JSON %q contains Jti %q — Jti must stay session-scoped", string(idJSON), s.Jti)
	}
}

// ─── revokeSessionCookie ─────────────────────────────────────────────────────

func TestRevokeSessionCookie_MalformedCookie(t *testing.T) {
	if !session.HasSigningKey() {
		initSessionSecret()
	}
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	// Attributes are irrelevant on an inbound request cookie (only Name=Value
	// serializes), set to satisfy gosec G124.
	req.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: "notvalid",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	// Should not panic on malformed cookie value.
	revokeSessionCookie(sessionCookieName, req)
}

// ─── initSessionSecret (env var) ─────────────────────────────────────────────

// TestInitSessionSecret_TrailingNewline covers CULVERT_SESSION_SECRET sourced
// from a file (Docker/K8s secret mounts, `EnvironmentFile=` in systemd units,
// or `export CULVERT_SESSION_SECRET=$(cat secret-file)`-style provisioning
// commonly leave a trailing newline). A byte-for-byte-valid 64-hex-char
// secret must not crash the process at startup just because of incidental
// whitespace — the documented multi-node "shared signing key" deployment
// path depends on this env var applying cleanly on every node.
func TestInitSessionSecret_TrailingNewline(t *testing.T) {
	origSecret := session.SigningKey()
	defer session.SetSigningKey(origSecret)

	const hexKey = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111" //nolint:gosec // test value
	t.Setenv("CULVERT_SESSION_SECRET", hexKey+"\n")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("initSessionSecret panicked on a valid secret with a trailing newline: %v", r)
		}
	}()
	initSessionSecret()

	got := session.SigningKey()
	if len(got) != 32 {
		t.Fatalf("session secret length = %d, want 32", len(got))
	}
	want, _ := hex.DecodeString(hexKey)
	if !bytes.Equal(got, want) {
		t.Fatalf("session secret = %x, want %x", got, want)
	}
}
