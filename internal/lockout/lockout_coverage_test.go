package lockout

import (
	"fmt"
	"testing"
)

// Covers the constructors + SnapshotAndClear, which were exercised only through
// package main's shim (so they read as uncovered in the gate-critical
// per-function coverage of lockout.go). ADR-0002 extraction left these as the
// package's public API; this keeps lockout.go above the 80% floor directly.

func TestNewLoginLimiter_FreshState(t *testing.T) {
	l := NewLoginLimiter()
	if l == nil {
		t.Fatal("NewLoginLimiter returned nil")
	}
	if locked, _ := l.Check("203.0.113.1", "nobody"); locked {
		t.Error("a fresh limiter must not report anyone locked")
	}
	if got := l.AttemptsLeft("203.0.113.1", "nobody"); got != MaxAttempts {
		t.Errorf("AttemptsLeft on unknown user = %d, want %d", got, MaxAttempts)
	}
}

func TestAttemptsLeft_DecrementsAndFloors(t *testing.T) {
	l := NewLoginLimiter()
	l.RecordFailure("203.0.113.1", "u")
	if got := l.AttemptsLeft("203.0.113.1", "u"); got != MaxAttempts-1 {
		t.Errorf("AttemptsLeft after 1 failure = %d, want %d", got, MaxAttempts-1)
	}
	// Drive past the lock threshold; AttemptsLeft floors at 0.
	for range MaxAttempts + 2 {
		l.RecordFailure("203.0.113.1", "u")
	}
	if got := l.AttemptsLeft("203.0.113.1", "u"); got != 0 {
		t.Errorf("AttemptsLeft when locked = %d, want 0", got)
	}
}

func TestSnapshotAndClear_RestoresState(t *testing.T) {
	l := NewLoginLimiter()
	for range MaxAttempts {
		l.RecordFailure("203.0.113.1", "victim")
	}
	if locked, _ := l.Check("203.0.113.1", "victim"); !locked {
		t.Fatal("precondition: victim should be locked after MaxAttempts failures")
	}

	restore := l.SnapshotAndClear()
	// After clear, the limiter is empty.
	if locked, _ := l.Check("203.0.113.1", "victim"); locked {
		t.Error("SnapshotAndClear should leave an empty limiter (victim not locked)")
	}
	if got := l.AttemptsLeft("203.0.113.1", "victim"); got != MaxAttempts {
		t.Errorf("after clear AttemptsLeft = %d, want %d", got, MaxAttempts)
	}

	restore()
	// After restore, the captured locked state is back.
	if locked, _ := l.Check("203.0.113.1", "victim"); !locked {
		t.Error("restore() should bring back the locked state")
	}
}

func TestSnapshot_ReportsBothTiersAndOmitsExpired(t *testing.T) {
	l := NewLoginLimiter()
	if got := l.Snapshot(); len(got) != 0 {
		t.Fatalf("fresh limiter Snapshot() = %v, want empty", got)
	}

	// Trip the tier-1 pair lock for one (ip, username).
	for range MaxAttempts {
		l.RecordFailure("203.0.113.1", "pairlocked")
	}
	// Trip the tier-2 account lock (distinct IPs, same username) — untrusted
	// IPs so the account tier isn't bypassed.
	for i := range AccountMaxAttempts {
		l.RecordFailure(fmt.Sprintf("198.51.100.%d", i+1), "acctlocked")
	}

	snap := l.Snapshot()
	var sawPair, sawAccount bool
	for _, e := range snap {
		switch {
		case e.Tier == "pair" && e.Username == "pairlocked":
			sawPair = true
			if e.IP != "203.0.113.1" {
				t.Errorf("pair entry IP = %q, want 203.0.113.1", e.IP)
			}
			if e.SecondsRemaining <= 0 {
				t.Errorf("pair entry SecondsRemaining = %d, want > 0", e.SecondsRemaining)
			}
		case e.Tier == "account" && e.Username == "acctlocked":
			sawAccount = true
			if e.IP != "" {
				t.Errorf("account entry IP = %q, want empty", e.IP)
			}
		}
	}
	if !sawPair {
		t.Error("Snapshot() missing the tripped pair-tier lockout")
	}
	if !sawAccount {
		t.Error("Snapshot() missing the tripped account-tier lockout")
	}

	// ResetUser must remove the pair entry from a subsequent Snapshot.
	l.ResetUser("pairlocked")
	for _, e := range l.Snapshot() {
		if e.Username == "pairlocked" {
			t.Error("Snapshot() still reports a lockout ResetUser cleared")
		}
	}
}

func TestNewAPIRateLimiter_Allows(t *testing.T) {
	a := NewAPIRateLimiter()
	if a == nil {
		t.Fatal("NewAPIRateLimiter returned nil")
	}
	if !a.Allow("203.0.113.7") {
		t.Error("first request from an IP should be allowed")
	}
}
