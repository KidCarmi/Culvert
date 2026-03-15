package main

import (
	"strings"
	"testing"
	"time"
)

// initSecret initialises sessionSecret if it hasn't been set yet.
// Safe to call from multiple tests.
func initSecret(t *testing.T) {
	t.Helper()
	if len(sessionSecret) == 0 {
		initSessionSecret()
	}
}

// ─── encodeSession / decodeSession roundtrip ──────────────────────────────────

func TestSessionRoundtrip(t *testing.T) {
	initSecret(t)

	s := &Session{
		Sub:      "user-123",
		Email:    "alice@example.com",
		Name:     "Alice",
		Groups:   []string{"admins", "users"},
		Provider: "local",
		Role:     "admin",
		Exp:      time.Now().Add(time.Hour).Unix(),
	}

	token, err := encodeSession(s)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}

	got, err := decodeSession(token)
	if err != nil {
		t.Fatalf("decodeSession: %v", err)
	}

	if got.Sub != s.Sub {
		t.Errorf("Sub = %q, want %q", got.Sub, s.Sub)
	}
	if got.Email != s.Email {
		t.Errorf("Email = %q, want %q", got.Email, s.Email)
	}
	if got.Name != s.Name {
		t.Errorf("Name = %q, want %q", got.Name, s.Name)
	}
	if got.Role != s.Role {
		t.Errorf("Role = %q, want %q", got.Role, s.Role)
	}
	if len(got.Groups) != len(s.Groups) {
		t.Errorf("Groups = %v, want %v", got.Groups, s.Groups)
	}
}

// ─── decodeSession error cases ────────────────────────────────────────────────

func TestDecodeSession_MalformedNoDot(t *testing.T) {
	initSecret(t)
	_, err := decodeSession("nodothere")
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected malformed error, got %v", err)
	}
}

func TestDecodeSession_InvalidSignature(t *testing.T) {
	initSecret(t)

	s := &Session{
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	token, _ := encodeSession(s)

	// Corrupt the signature part.
	dot := strings.LastIndex(token, ".")
	corrupted := token[:dot] + ".invalidsig"
	_, err := decodeSession(corrupted)
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected invalid signature error, got %v", err)
	}
}

func TestDecodeSession_Expired(t *testing.T) {
	initSecret(t)

	s := &Session{
		Sub: "user",
		Exp: time.Now().Add(-time.Hour).Unix(), // expired 1 hour ago
	}
	token, _ := encodeSession(s)

	_, err := decodeSession(token)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got %v", err)
	}
}

func TestDecodeSession_InvalidBase64(t *testing.T) {
	initSecret(t)

	// payload.sig where payload is not valid base64url
	// Sign the garbage payload so the MAC check passes, then we get a base64 error.
	badPayload := "!!!notbase64!!!"
	mac := sessionMAC(badPayload)
	token := badPayload + "." + mac

	_, err := decodeSession(token)
	if err == nil {
		t.Error("expected error for invalid base64 payload")
	}
}

// ─── Session revocation ───────────────────────────────────────────────────────

func TestRevocationList_RevokeAndIsRevoked(t *testing.T) {
	rl := &revocationList{tokens: map[string]time.Time{}}

	token := "sometoken"
	exp := time.Now().Add(time.Hour)

	if rl.IsRevoked(token) {
		t.Error("token should not be revoked before Revoke is called")
	}

	rl.Revoke(token, exp)

	if !rl.IsRevoked(token) {
		t.Error("token should be revoked after Revoke is called")
	}
}

func TestRevocationList_LazyEviction(t *testing.T) {
	rl := &revocationList{tokens: map[string]time.Time{}}

	token := "expired-token"
	// Set expiry in the past so it evicts on next IsRevoked check.
	rl.Revoke(token, time.Now().Add(-time.Minute))

	// IsRevoked should evict and return false.
	if rl.IsRevoked(token) {
		t.Error("expired revocation entry should be evicted and return false")
	}

	// Entry should be gone from the map.
	rl.mu.Lock()
	_, exists := rl.tokens[token]
	rl.mu.Unlock()
	if exists {
		t.Error("evicted entry should not remain in the map")
	}
}

func TestRevocationList_UnknownToken(t *testing.T) {
	rl := &revocationList{tokens: map[string]time.Time{}}
	if rl.IsRevoked("never-revoked-token") {
		t.Error("unknown token should not be revoked")
	}
}

// ─── decodeSession after revocation ──────────────────────────────────────────

func TestDecodeSession_Revoked(t *testing.T) {
	initSecret(t)

	s := &Session{
		Sub: "victim",
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	token, _ := encodeSession(s)

	// Revoke by extracting the b64 part.
	dot := strings.LastIndex(token, ".")
	b64part := token[:dot]
	sessionRevoked.Revoke(b64part, time.Unix(s.Exp, 0))

	_, err := decodeSession(token)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected revoked error, got %v", err)
	}

	// Clean up to avoid polluting other tests.
	sessionRevoked.mu.Lock()
	delete(sessionRevoked.tokens, b64part)
	sessionRevoked.mu.Unlock()
}

// ─── SetSessionTTL clamping ───────────────────────────────────────────────────

func TestSetSessionTTL_Clamping(t *testing.T) {
	// Save and restore original TTL.
	origTTL := getSessionTTL()
	defer SetSessionTTL(origTTL)

	cases := []struct {
		input time.Duration
		want  time.Duration
	}{
		{time.Second, 15 * time.Minute},          // below min → clamped to 15min
		{15 * time.Minute, 15 * time.Minute},     // exactly min → unchanged
		{8 * time.Hour, 8 * time.Hour},           // normal value
		{7 * 24 * time.Hour, 7 * 24 * time.Hour}, // exactly max → unchanged
		{8 * 24 * time.Hour, 7 * 24 * time.Hour}, // above max → clamped to 7d
	}
	for _, c := range cases {
		SetSessionTTL(c.input)
		got := getSessionTTL()
		if got != c.want {
			t.Errorf("SetSessionTTL(%v): got %v, want %v", c.input, got, c.want)
		}
	}
}

// ─── Session.Identity ────────────────────────────────────────────────────────

func TestSession_Identity(t *testing.T) {
	s := &Session{
		Sub:      "u-001",
		Email:    "bob@example.com",
		Name:     "Bob",
		Groups:   []string{"ops"},
		Provider: "okta",
	}
	id := s.Identity()

	if id.Sub != s.Sub {
		t.Errorf("Identity().Sub = %q, want %q", id.Sub, s.Sub)
	}
	if id.Email != s.Email {
		t.Errorf("Identity().Email = %q, want %q", id.Email, s.Email)
	}
	if id.Name != s.Name {
		t.Errorf("Identity().Name = %q, want %q", id.Name, s.Name)
	}
	if id.Provider != s.Provider {
		t.Errorf("Identity().Provider = %q, want %q", id.Provider, s.Provider)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "ops" {
		t.Errorf("Identity().Groups = %v, want [ops]", id.Groups)
	}
}

// ─── sessionMAC consistency ──────────────────────────────────────────────────

func TestSessionMAC_Deterministic(t *testing.T) {
	initSecret(t)

	data := "test-payload"
	mac1 := sessionMAC(data)
	mac2 := sessionMAC(data)

	if mac1 != mac2 {
		t.Error("sessionMAC should produce deterministic output for same input")
	}
	if mac1 == "" {
		t.Error("sessionMAC should produce non-empty output")
	}
}

func TestSessionMAC_DifferentInputs(t *testing.T) {
	initSecret(t)

	if sessionMAC("aaa") == sessionMAC("bbb") {
		t.Error("different inputs should produce different MACs")
	}
}
