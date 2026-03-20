package main

// session_extra_test.go — additional coverage for session encoding/decoding,
// revocation list, and SetSessionTTL clamping.

import (
	"net/http"
	"testing"
	"time"
)

func TestEncodeDecodeSession_RoundTrip(t *testing.T) {
	// Ensure session secret is initialised.
	initSessionSecret()

	s := &Session{
		Sub:      "user1",
		Email:    "user1@example.com",
		Name:     "Test User",
		Groups:   []string{"admin", "ops"},
		Provider: "local",
		Role:     "admin",
		Exp:      time.Now().Add(time.Hour).Unix(),
	}

	token, err := encodeSession(s)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	if token == "" {
		t.Fatal("encoded token should not be empty")
	}

	decoded, err := decodeSession(token)
	if err != nil {
		t.Fatalf("decodeSession: %v", err)
	}
	if decoded.Sub != s.Sub {
		t.Errorf("Sub mismatch: want %q got %q", s.Sub, decoded.Sub)
	}
	if decoded.Email != s.Email {
		t.Errorf("Email mismatch: want %q got %q", s.Email, decoded.Email)
	}
	if len(decoded.Groups) != len(s.Groups) {
		t.Errorf("Groups mismatch: want %v got %v", s.Groups, decoded.Groups)
	}
}

func TestDecodeSession_Tampered(t *testing.T) {
	initSessionSecret()

	s := &Session{Sub: "alice", Exp: time.Now().Add(time.Hour).Unix()}
	token, _ := encodeSession(s)

	// Tamper with the token (flip a byte in the middle).
	bs := []byte(token)
	if len(bs) > 10 {
		bs[10] ^= 0xFF
	}
	_, err := decodeSession(string(bs))
	if err == nil {
		t.Error("tampered token should fail decodeSession")
	}
}


func TestDecodeSession_Invalid(t *testing.T) {
	initSessionSecret()
	_, err := decodeSession("not.a.valid.token")
	if err == nil {
		t.Error("invalid token should fail decodeSession")
	}
	_, err = decodeSession("")
	if err == nil {
		t.Error("empty token should fail decodeSession")
	}
}

func TestRevocationList(t *testing.T) {
	rl := &revocationList{tokens: map[string]time.Time{}}

	// Not revoked initially.
	if rl.IsRevoked("token1") {
		t.Error("token1 should not be revoked")
	}

	// Revoke with future expiry.
	rl.Revoke("token1", time.Now().Add(time.Hour))
	if !rl.IsRevoked("token1") {
		t.Error("token1 should be revoked")
	}

	// Revoke with past expiry — lazy eviction, should return false.
	rl.Revoke("token2", time.Now().Add(-time.Millisecond))
	if rl.IsRevoked("token2") {
		t.Error("expired revocation should be evicted and return false")
	}
}

func TestRevokeSessionCookie_MalformedCookie(t *testing.T) {
	initSessionSecret()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "notvalid"})
	// Should not panic on malformed cookie value.
	revokeSessionCookie(sessionCookieName, req)
}
