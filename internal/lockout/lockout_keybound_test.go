package lockout

import (
	"strings"
	"testing"
)

// ─── CHAOS-58 — the limiter's map keys are bounded in SIZE, not just in count ──
//
// Cleanup's own doc claims the maps are bounded "against an unbounded-memory
// DoS", and on the ENTRY-COUNT axis they are. They were not bounded on the
// SIZE axis: both keys derive from a username an UNAUTHENTICATED caller chooses
// on the admin login POST, and an entry cannot be swept before its Window has
// elapsed, so one caller retained (rate x Window x username size) bytes.
//
// These gates pin the size bound and — just as important — pin that the clamp
// is applied CONSISTENTLY, because a Check and a RecordFailure that disagreed
// about the key would split one attacker's failures across two counters and
// silently weaken the lock instead of strengthening it.

// oversizeName returns a username n bytes long.
func oversizeName(n int) string { return strings.Repeat("A", n) }

func TestBoundUsername_ClampsAtMaxAndLeavesShortNamesIdentical(t *testing.T) {
	for _, n := range []int{0, 1, 63, MaxUsernameKeyLen - 1, MaxUsernameKeyLen} {
		in := oversizeName(n)
		if got := boundUsername(in); got != in {
			t.Errorf("boundUsername(%d bytes) mutated a name within the bound (len %d)", n, len(got))
		}
	}
	for _, n := range []int{MaxUsernameKeyLen + 1, 4096, 1 << 20} {
		if got := boundUsername(oversizeName(n)); len(got) > MaxUsernameKeyLen {
			t.Errorf("boundUsername(%d bytes) = %d bytes, want <= %d", n, len(got), MaxUsernameKeyLen)
		}
	}
}

// TestBoundUsername_CutsOnARuneBoundary keeps a truncated key renderable on the
// Snapshot admin surface: the clamp must not leave a half-encoded rune behind.
func TestBoundUsername_CutsOnARuneBoundary(t *testing.T) {
	// "é" is 2 bytes, so a run of them straddles MaxUsernameKeyLen when the
	// prefix length is odd — the case a naive byte cut gets wrong.
	name := "x" + strings.Repeat("é", MaxUsernameKeyLen)
	got := boundUsername(name)
	if len(got) > MaxUsernameKeyLen {
		t.Fatalf("clamped to %d bytes, want <= %d", len(got), MaxUsernameKeyLen)
	}
	if !isValidUTF8Prefix(name, got) {
		t.Errorf("clamped value is not a whole-rune prefix of the input")
	}
}

// TestBoundUsername_CutsCleanlyForEveryRuneWidth walks every alignment of a
// 1-, 2-, 3- and 4-byte rune across the cut. The 4-byte case is the one a
// 3-step boundary search gets wrong (three continuation bytes can sit at the
// cut), and a padding offset is what puts each width into every alignment.
func TestBoundUsername_CutsCleanlyForEveryRuneWidth(t *testing.T) {
	runes := []string{"a", "é", "€", "𝄞"} // 1, 2, 3, 4 bytes
	for _, r := range runes {
		for pad := 0; pad < 4; pad++ {
			name := strings.Repeat("x", pad) + strings.Repeat(r, MaxUsernameKeyLen)
			got := boundUsername(name)
			if len(got) > MaxUsernameKeyLen {
				t.Errorf("rune %q pad %d: clamped to %d bytes, want <= %d", r, pad, len(got), MaxUsernameKeyLen)
			}
			if !isValidUTF8Prefix(name, got) {
				t.Errorf("rune %q pad %d: clamped value is not a whole-rune prefix", r, pad)
			}
		}
	}
}

// TestBoundUsername_InvalidUTF8StaysBoundedAndNonEmpty pins the fallback. An
// all-continuation-byte name has no rune boundary to find; an unbounded walk
// back would alias every such name onto the EMPTY username, which a caller can
// also submit legitimately.
func TestBoundUsername_InvalidUTF8StaysBoundedAndNonEmpty(t *testing.T) {
	name := strings.Repeat("\x80", MaxUsernameKeyLen*4)
	got := boundUsername(name)
	if len(got) > MaxUsernameKeyLen {
		t.Errorf("clamped to %d bytes, want <= %d", len(got), MaxUsernameKeyLen)
	}
	if got == "" {
		t.Error("invalid UTF-8 collapsed to the empty username")
	}
}

// isValidUTF8Prefix reports whether got is a prefix of name that ends on a rune
// boundary (i.e. re-encoding the decoded runes reproduces it exactly).
func isValidUTF8Prefix(name, got string) bool {
	if !strings.HasPrefix(name, got) {
		return false
	}
	return string([]rune(got)) == got
}

// TestOversizeUsername_NeverEntersAMapKey is the DEFECT gate: it fails against
// the pre-fix limiter, where the 1 MiB name became two map keys retained for a
// full Window.
func TestOversizeUsername_NeverEntersAMapKey(t *testing.T) {
	l := NewLoginLimiter()
	huge := oversizeName(1 << 20) // 1 MiB — what the 1 MiB body cap admits

	for i := 0; i < 3; i++ {
		l.RecordFailure("198.51.100.7", huge)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for key := range l.pairs {
		if len(key) > MaxUsernameKeyLen+len("198.51.100.7")+1 {
			t.Errorf("pair key retained %d bytes of attacker input", len(key))
		}
	}
	for key := range l.accounts {
		if len(key) > MaxUsernameKeyLen {
			t.Errorf("account key retained %d bytes of attacker input", len(key))
		}
	}
	if len(l.pairs) != 1 || len(l.accounts) != 1 {
		t.Errorf("entries = %d pair / %d account, want 1 / 1 (oversize names alias onto one bounded key)",
			len(l.pairs), len(l.accounts))
	}
}

// TestOversizeUsername_CheckAndRecordAgree is the CONTROL for the gate above: a
// clamp applied on only some entry points would pass the byte-size assertion
// while breaking the lock it is supposed to protect. The lock must still trip
// after MaxAttempts and must still be observable through Check.
func TestOversizeUsername_CheckAndRecordAgree(t *testing.T) {
	l := NewLoginLimiter()
	const ip = "198.51.100.8"
	huge := oversizeName(MaxUsernameKeyLen * 40)

	if locked, _ := l.Check(ip, huge); locked {
		t.Fatal("locked before any failure was recorded")
	}
	for i := 0; i < MaxAttempts-1; i++ {
		if tripped := l.RecordFailure(ip, huge); tripped {
			t.Fatalf("pair lock tripped early at attempt %d", i+1)
		}
	}
	if left := l.AttemptsLeft(ip, huge); left != 1 {
		t.Errorf("AttemptsLeft = %d, want 1 — AttemptsLeft is reading a different key", left)
	}
	if tripped := l.RecordFailure(ip, huge); !tripped {
		t.Fatal("pair lock did not trip on attempt MaxAttempts — Record and Check disagree on the key")
	}
	locked, secs := l.Check(ip, huge)
	if !locked || secs <= 0 {
		t.Fatalf("Check after the trip = (%v, %d), want locked with time remaining", locked, secs)
	}

	// ResetUser is the operator's unlock lever and must reach the same key.
	l.ResetUser(huge)
	if locked, _ := l.Check(ip, huge); locked {
		t.Error("still locked after ResetUser — the unlock path clamps differently")
	}
}

// TestOversizeUsername_SnapshotStaysBounded pins the admin-visible surface: an
// operator listing active lockouts must not be handed megabytes of attacker
// text (it is rendered into the Lockouts panel and serialised over the API).
func TestOversizeUsername_SnapshotStaysBounded(t *testing.T) {
	l := NewLoginLimiter()
	huge := oversizeName(1 << 20)
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure("198.51.100.9", huge)
	}
	snap := l.Snapshot()
	if len(snap) == 0 {
		t.Fatal("no active lockout recorded")
	}
	for _, e := range snap {
		if len(e.Username) > MaxUsernameKeyLen {
			t.Errorf("Snapshot exposed a %d-byte username, want <= %d", len(e.Username), MaxUsernameKeyLen)
		}
	}
}

// TestBoundedNames_BehaviourUnchanged is the no-regression control: every name
// short enough to be a real account must key exactly as it did before, so the
// clamp cannot be the reason a lockout stops working.
func TestBoundedNames_BehaviourUnchanged(t *testing.T) {
	l := NewLoginLimiter()
	const ip, user, other = "198.51.100.10", "admin", "admin2"

	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(ip, user)
	}
	if locked, _ := l.Check(ip, user); !locked {
		t.Error("ordinary username did not lock after MaxAttempts")
	}
	if locked, _ := l.Check(ip, other); locked {
		t.Error("a distinct ordinary username was locked — keys collided")
	}
	if locked, _ := l.Check("198.51.100.11", user); locked {
		t.Error("a distinct IP was pair-locked — tier-1 keying changed")
	}
}
