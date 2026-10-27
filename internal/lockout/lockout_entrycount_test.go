package lockout

import "testing"

// TestLoginLimiter_EntryCount pins what culvert_login_limiter_entries reports:
// the tier-1 pair plus tier-2 account entries a caller's failures create (the
// keys an unauthenticated caller chooses), not the trusted-IP grants that only
// a successful authentication creates.
func TestLoginLimiter_EntryCount(t *testing.T) {
	l := newLimiter()
	if got := l.EntryCount(); got != 0 {
		t.Fatalf("fresh limiter EntryCount = %d, want 0", got)
	}

	l.RecordFailure(testIP, testUser)  // pair (testIP, alice) + account alice
	l.RecordFailure(otherIP, testUser) // pair (otherIP, alice); account reused
	l.RecordFailure(testIP, "bob")     // pair (testIP, bob) + account bob
	if got := l.EntryCount(); got != 5 {
		t.Fatalf("EntryCount = %d after failures on 3 pairs and 2 accounts, want 5", got)
	}

	// A success deletes its pair and records a trusted-IP grant, which is not
	// counted.
	l.RecordSuccess(testIP, "bob")
	if got := l.EntryCount(); got != 4 {
		t.Fatalf("EntryCount = %d after a success cleared one pair, want 4", got)
	}

	l.ResetUser(testUser)
	l.ResetUser("bob")
	if got := l.EntryCount(); got != 0 {
		t.Fatalf("EntryCount = %d after ResetUser on every account, want 0", got)
	}
}
