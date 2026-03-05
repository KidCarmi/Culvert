package main

import (
	"encoding/hex"
	"testing"
	"time"
)

// ── NewLDAPAuth validation ────────────────────────────────────────────────────

func TestNewLDAPAuth_MissingURL(t *testing.T) {
	_, err := NewLDAPAuth(LDAPConfig{BaseDN: "dc=corp,dc=com"})
	if err == nil {
		t.Error("expected error when URL is empty")
	}
}

func TestNewLDAPAuth_MissingBaseDN(t *testing.T) {
	_, err := NewLDAPAuth(LDAPConfig{URL: "ldap://localhost:389"})
	if err == nil {
		t.Error("expected error when BaseDN is empty")
	}
}

func TestNewLDAPAuth_DefaultFilter(t *testing.T) {
	a, err := NewLDAPAuth(LDAPConfig{
		URL:    "ldap://localhost:389",
		BaseDN: "dc=corp,dc=com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.cfg.UserFilter != "(sAMAccountName=%s)" {
		t.Errorf("expected default filter, got %q", a.cfg.UserFilter)
	}
}

func TestNewLDAPAuth_DefaultTTL(t *testing.T) {
	a, err := NewLDAPAuth(LDAPConfig{
		URL:    "ldap://localhost:389",
		BaseDN: "dc=corp,dc=com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ttl != 5*time.Minute {
		t.Errorf("expected 5m TTL, got %v", a.ttl)
	}
}

func TestNewLDAPAuth_CustomTTL(t *testing.T) {
	a, err := NewLDAPAuth(LDAPConfig{
		URL:      "ldap://localhost:389",
		BaseDN:   "dc=corp,dc=com",
		CacheTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ttl != 10*time.Minute {
		t.Errorf("expected 10m TTL, got %v", a.ttl)
	}
}

func TestLDAPAuth_Name(t *testing.T) {
	a, _ := NewLDAPAuth(LDAPConfig{URL: "ldap://localhost:389", BaseDN: "dc=x,dc=com"})
	if a.Name() != "ldap" {
		t.Errorf("Name() = %q, want ldap", a.Name())
	}
}

// ── Cache logic ───────────────────────────────────────────────────────────────

func TestLDAPAuth_Cache_HitTrue(t *testing.T) {
	a, _ := NewLDAPAuth(LDAPConfig{URL: "ldap://localhost:389", BaseDN: "dc=x,dc=com"})
	k := cacheKey("alice", "secret")
	a.cacheSet(k, true)

	ok, hit := a.cacheGet(k)
	if !hit {
		t.Error("expected cache hit")
	}
	if !ok {
		t.Error("expected ok=true from cache")
	}
}

func TestLDAPAuth_Cache_HitFalse(t *testing.T) {
	a, _ := NewLDAPAuth(LDAPConfig{URL: "ldap://localhost:389", BaseDN: "dc=x,dc=com"})
	k := cacheKey("bob", "wrong")
	a.cacheSet(k, false)

	ok, hit := a.cacheGet(k)
	if !hit {
		t.Error("expected cache hit")
	}
	if ok {
		t.Error("expected ok=false from cache")
	}
}

func TestLDAPAuth_Cache_Miss(t *testing.T) {
	a, _ := NewLDAPAuth(LDAPConfig{URL: "ldap://localhost:389", BaseDN: "dc=x,dc=com"})
	_, hit := a.cacheGet("nonexistent")
	if hit {
		t.Error("expected cache miss for unknown key")
	}
}

func TestLDAPAuth_Cache_Expiry(t *testing.T) {
	a, _ := NewLDAPAuth(LDAPConfig{
		URL:      "ldap://localhost:389",
		BaseDN:   "dc=x,dc=com",
		CacheTTL: 1 * time.Millisecond,
	})
	k := cacheKey("alice", "secret")
	a.cacheSet(k, true)

	time.Sleep(5 * time.Millisecond)

	_, hit := a.cacheGet(k)
	if hit {
		t.Error("expected cache miss after TTL expiry")
	}
}

// ── Empty password ────────────────────────────────────────────────────────────

func TestLDAPAuth_Verify_EmptyPassword(t *testing.T) {
	a, _ := NewLDAPAuth(LDAPConfig{URL: "ldap://localhost:389", BaseDN: "dc=x,dc=com"})
	// Must return false without attempting a dial (empty password is always rejected).
	if a.Verify("alice", "") {
		t.Error("Verify with empty password should return false")
	}
}

// ── Dial failure ──────────────────────────────────────────────────────────────

func TestLDAPAuth_Verify_DialFailure(t *testing.T) {
	// Port 1 is guaranteed to refuse connections.
	a, _ := NewLDAPAuth(LDAPConfig{
		URL:    "ldap://127.0.0.1:1",
		BaseDN: "dc=x,dc=com",
	})
	// Should return false (dial error) and not panic.
	if a.Verify("alice", "secret") {
		t.Error("expected false on dial failure")
	}
}

// ── cacheKey uniqueness ───────────────────────────────────────────────────────

func TestLDAPAuth_CacheKeyUniqueness(t *testing.T) {
	k1 := cacheKey("alice", "p1")
	k2 := cacheKey("alice", "p2")
	k3 := cacheKey("bob", "p1")
	if k1 == k2 {
		t.Error("different passwords should produce different cache keys")
	}
	if k1 == k3 {
		t.Error("different users should produce different cache keys")
	}
}

func TestLDAPAuth_CacheKeyIsHex(t *testing.T) {
	k := cacheKey("user", "pass")
	_, err := hex.DecodeString(k)
	if err != nil {
		t.Errorf("cache key should be valid hex, got %q: %v", k, err)
	}
}
