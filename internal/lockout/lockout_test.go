package lockout

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func newLimiter() *LoginLimiter { return NewLoginLimiter() }

const (
	testIP   = "203.0.113.10" // TEST-NET-3
	otherIP  = "203.0.113.20"
	victimIP = "203.0.113.99"
	testUser = "alice"
)

// ─── Check ────────────────────────────────────────────────────────────────────

func TestLoginLimiter_CheckUnknown(t *testing.T) {
	l := newLimiter()
	locked, secs := l.Check(testIP, "nobody")
	if locked || secs != 0 {
		t.Errorf("unknown pair should not be locked, got locked=%v secs=%d", locked, secs)
	}
}

func TestLoginLimiter_CheckLockedPair(t *testing.T) {
	l := newLimiter()
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(testIP, testUser)
	}
	locked, secs := l.Check(testIP, testUser)
	if !locked {
		t.Error("pair should be locked after max attempts")
	}
	if secs <= 0 {
		t.Errorf("seconds remaining should be positive, got %d", secs)
	}
}

func TestLoginLimiter_CheckExpiredLock(t *testing.T) {
	l := newLimiter()
	// Manually insert an expired pair lock.
	l.mu.Lock()
	l.pairs[pairKey(testIP, "bob")] = &lockoutEntry{
		attempts:    MaxAttempts,
		lockedUntil: time.Now().Add(-time.Second), // already expired
	}
	l.mu.Unlock()

	locked, secs := l.Check(testIP, "bob")
	if locked {
		t.Error("expired lockout should not be locked")
	}
	if secs != 0 {
		t.Errorf("expected 0 seconds for expired lock, got %d", secs)
	}
	// Entry should be cleaned up.
	l.mu.Lock()
	_, exists := l.pairs[pairKey(testIP, "bob")]
	l.mu.Unlock()
	if exists {
		t.Error("expired lockout entry should be deleted after Check")
	}
}

// ─── RISK-012 regression: pair keying localizes the lock ─────────────────────

// TestLoginLimiter_PairLock_DoesNotLockOtherIPs is THE RISK-012 regression
// guard: an attacker spamming failures for a username locks only their own
// (IP, username) pair — the same username from the victim's IP stays usable.
// Under the old username-only keying this test fails (victim locked out).
func TestLoginLimiter_PairLock_DoesNotLockOtherIPs(t *testing.T) {
	l := newLimiter()
	const admin = "admin"
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(testIP, admin) // attacker
	}
	if locked, _ := l.Check(testIP, admin); !locked {
		t.Fatal("attacker's pair should be locked")
	}
	if locked, secs := l.Check(victimIP, admin); locked {
		t.Fatalf("victim IP must NOT be locked by the attacker's failures (lockout-as-DoS): locked=%v secs=%d", locked, secs)
	}
}

// ─── Tier 2: account lock across IPs ─────────────────────────────────────────

// floodAccount spreads AccountMaxAttempts failures across enough IPs that no
// single pair trips (MaxAttempts-1 per IP) — a distributed brute-force shape.
func floodAccount(l *LoginLimiter, username string) {
	perIP := MaxAttempts - 1
	n := 0
	for i := 0; n < AccountMaxAttempts; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1) // TEST-NET-2
		for j := 0; j < perIP && n < AccountMaxAttempts; j++ {
			l.RecordFailure(ip, username)
			n++
		}
	}
}

func TestLoginLimiter_AccountLock_TripsAcrossIPs(t *testing.T) {
	l := newLimiter()
	floodAccount(l, testUser)
	// A fresh IP (never seen, not trusted) must be blocked by the account lock.
	if locked, secs := l.Check(otherIP, testUser); !locked || secs <= 0 {
		t.Fatalf("distributed flood must trip the account lock for untrusted IPs: locked=%v secs=%d", locked, secs)
	}
}

func TestLoginLimiter_AccountLock_TrustedIPBypasses(t *testing.T) {
	l := newLimiter()
	// The victim logged in successfully from victimIP before the attack.
	l.RecordSuccess(victimIP, testUser)
	floodAccount(l, testUser)

	if locked, _ := l.Check(otherIP, testUser); !locked {
		t.Fatal("untrusted IP should be blocked by the account lock")
	}
	if locked, secs := l.Check(victimIP, testUser); locked {
		t.Fatalf("trusted IP must bypass the account lock (anti-DoS): locked=%v secs=%d", locked, secs)
	}
}

func TestLoginLimiter_TrustedIP_StillSubjectToOwnPairLock(t *testing.T) {
	l := newLimiter()
	l.RecordSuccess(victimIP, testUser) // trusted
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(victimIP, testUser)
	}
	if locked, _ := l.Check(victimIP, testUser); !locked {
		t.Fatal("trust bypasses only the ACCOUNT lock — the trusted IP's own pair lock must still apply")
	}
}

func TestLoginLimiter_TrustExpires(t *testing.T) {
	l := newLimiter()
	l.RecordSuccess(victimIP, testUser)
	// Age the grant past TrustTTL.
	l.mu.Lock()
	l.trusted[testUser][victimIP] = time.Now().Add(-TrustTTL - time.Hour)
	l.mu.Unlock()
	floodAccount(l, testUser)
	if locked, _ := l.Check(victimIP, testUser); !locked {
		t.Fatal("an expired trust grant must no longer bypass the account lock")
	}
}

func TestLoginLimiter_TrustSetBounded(t *testing.T) {
	l := newLimiter()
	for i := 0; i < trustMaxIPs+3; i++ {
		l.RecordSuccess(fmt.Sprintf("203.0.113.%d", 100+i), testUser)
	}
	l.mu.Lock()
	n := len(l.trusted[testUser])
	l.mu.Unlock()
	if n > trustMaxIPs {
		t.Fatalf("trusted set size = %d, want <= %d (oldest evicted)", n, trustMaxIPs)
	}
}

// TestLoginLimiter_LiveAccountLockNotResetByLateFailure guards the
// recordFailureLocked refinement: a failure recorded after the accumulation
// Window has elapsed but while the lock is still ACTIVE must not reset the
// live lock (a trusted IP's stray failure would otherwise hand a flooding
// attacker a fresh budget).
func TestLoginLimiter_LiveAccountLockNotResetByLateFailure(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	l.mu.Lock()
	l.accounts[testUser] = &lockoutEntry{
		attempts:    AccountMaxAttempts,
		firstFail:   now.Add(-Window - time.Minute), // window elapsed…
		lockedUntil: now.Add(5 * time.Minute),       // …but lock still live
	}
	l.mu.Unlock()

	l.RecordFailure(victimIP, testUser) // e.g. trusted victim fat-fingers

	if locked, _ := l.Check(otherIP, testUser); !locked {
		t.Fatal("a late failure must not reset a still-active account lock")
	}
}

// ─── Pair-only path (setup endpoint) ─────────────────────────────────────────

// TestLoginLimiter_PairOnly_NoAccountAggregation is the FINDING-1 regression
// guard: the pair-only path (CheckPair/RecordPairFailure) must NOT touch the
// account tier, so failures spread across many IPs for the same pseudo-user
// (the "setup" bootstrap case) can never globally lock every IP. Under a
// two-tier RecordFailure they would (accounts["setup"] hits the cap).
func TestLoginLimiter_PairOnly_NoAccountAggregation(t *testing.T) {
	l := newLimiter()
	const user = "setup"
	// Far more than AccountMaxAttempts failures, each from a distinct IP,
	// none reaching the per-pair cap.
	for i := 0; i < AccountMaxAttempts*3; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		l.RecordPairFailure(ip, user)
	}
	// A fresh IP (the legitimate operator) must NOT be locked — the account
	// tier was never touched.
	if locked, _ := l.CheckPair("203.0.113.7", user); locked {
		t.Fatal("pair-only path must not aggregate into an account lock (global bootstrap DoS)")
	}
	// And the two-tier Check must ALSO be clean (no account entry created).
	if locked, _ := l.Check("203.0.113.7", user); locked {
		t.Fatal("pair-only failures must not create an account-tier lock")
	}
}

func TestLoginLimiter_PairOnly_LocksOwnIP(t *testing.T) {
	l := newLimiter()
	const user = "setup"
	for i := 0; i < MaxAttempts; i++ {
		l.RecordPairFailure(testIP, user)
	}
	if locked, secs := l.CheckPair(testIP, user); !locked || secs <= 0 {
		t.Fatalf("pair-only path must still lock the offending IP: locked=%v secs=%d", locked, secs)
	}
	if locked, _ := l.CheckPair(otherIP, user); locked {
		t.Fatal("a different IP must remain unlocked under the pair-only path")
	}
}

// ─── RecordFailure ────────────────────────────────────────────────────────────

func TestLoginLimiter_RecordFailure_NotYetLocked(t *testing.T) {
	l := newLimiter()
	for i := 0; i < MaxAttempts-1; i++ {
		locked := l.RecordFailure(testIP, "charlie")
		if locked {
			t.Errorf("attempt %d should not trigger lockout yet", i+1)
		}
	}
}

func TestLoginLimiter_RecordFailure_TriggersLockout(t *testing.T) {
	l := newLimiter()
	var justLocked bool
	for i := 0; i < MaxAttempts; i++ {
		justLocked = l.RecordFailure(testIP, "dave")
	}
	if !justLocked {
		t.Error("RecordFailure should return true when the pair just becomes locked")
	}
	locked, _ := l.Check(testIP, "dave")
	if !locked {
		t.Error("pair should be locked after max attempts")
	}
}

func TestLoginLimiter_RecordFailure_WindowReset(t *testing.T) {
	l := newLimiter()
	// Manually insert a stale entry (failure outside the window, unlocked).
	l.mu.Lock()
	l.pairs[pairKey(testIP, "eve")] = &lockoutEntry{
		attempts:  MaxAttempts - 1,
		firstFail: time.Now().Add(-(Window + time.Second)), // outside window
	}
	l.mu.Unlock()

	// Next failure should reset the window and start fresh.
	justLocked := l.RecordFailure(testIP, "eve")
	if justLocked {
		t.Error("should not lock immediately after window reset")
	}
	left := l.AttemptsLeft(testIP, "eve")
	if left != MaxAttempts-1 {
		t.Errorf("after window reset, attempts left = %d, want %d", left, MaxAttempts-1)
	}
}

// ─── RecordSuccess ────────────────────────────────────────────────────────────

func TestLoginLimiter_RecordSuccess_ClearsPairFailures(t *testing.T) {
	l := newLimiter()
	l.RecordFailure(testIP, "frank")
	l.RecordFailure(testIP, "frank")

	l.RecordSuccess(testIP, "frank")

	if l.AttemptsLeft(testIP, "frank") != MaxAttempts {
		t.Error("RecordSuccess should reset the pair failure counter to max")
	}
}

// ─── ResetUser ────────────────────────────────────────────────────────────────

func TestLoginLimiter_ResetUser_ClearsBothTiers(t *testing.T) {
	l := newLimiter()
	floodAccount(l, testUser)
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(testIP, testUser)
	}
	// Unrelated user must survive the reset.
	l.RecordFailure(testIP, "unrelated")

	l.ResetUser(testUser)

	if locked, _ := l.Check(testIP, testUser); locked {
		t.Error("ResetUser must clear the pair lock")
	}
	if locked, _ := l.Check(otherIP, testUser); locked {
		t.Error("ResetUser must clear the account lock")
	}
	if l.AttemptsLeft(testIP, "unrelated") != MaxAttempts-1 {
		t.Error("ResetUser must not touch other users' state")
	}
}

// ─── AttemptsLeft ─────────────────────────────────────────────────────────────

func TestLoginLimiter_AttemptsLeft_Default(t *testing.T) {
	l := newLimiter()
	if got := l.AttemptsLeft(testIP, "nobody"); got != MaxAttempts {
		t.Errorf("AttemptsLeft for unknown pair = %d, want %d", got, MaxAttempts)
	}
}

func TestLoginLimiter_AttemptsLeft_AfterFailures(t *testing.T) {
	l := newLimiter()
	l.RecordFailure(testIP, "grace")
	l.RecordFailure(testIP, "grace")

	if got := l.AttemptsLeft(testIP, "grace"); got != MaxAttempts-2 {
		t.Errorf("AttemptsLeft = %d, want %d", got, MaxAttempts-2)
	}
}

func TestLoginLimiter_AttemptsLeft_ZeroWhenLocked(t *testing.T) {
	l := newLimiter()
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(testIP, "heidi")
	}
	if got := l.AttemptsLeft(testIP, "heidi"); got != 0 {
		t.Errorf("AttemptsLeft when locked = %d, want 0", got)
	}
}

// ─── LockoutMsg ───────────────────────────────────────────────────────────────

func TestMsg(t *testing.T) {
	msg := Msg(300)
	if !strings.Contains(msg, "300") {
		t.Errorf("Msg should contain seconds, got %q", msg)
	}
	if !strings.Contains(msg, "locked") || !strings.Contains(msg, "300") {
		t.Errorf("Msg should mention lock, got %q", msg)
	}
}

// ─── API Rate Limiter ───────────────────────────────────────────────────────

func TestAPIRateLimiter_Allow(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	for i := 0; i < Burst; i++ {
		if !lim.Allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	// Next should be rejected.
	if lim.Allow("10.0.0.1") {
		t.Error("should be rate limited after burst")
	}
}

func TestAPIRateLimiter_DifferentIPs(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	for i := 0; i < Burst; i++ {
		lim.Allow("10.0.0.1")
	}
	// Different IP should still be allowed.
	if !lim.Allow("10.0.0.2") {
		t.Error("different IP should not be rate limited")
	}
}

func TestAPIRateLimiter_Cleanup(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	lim.Allow("10.0.0.1")
	if len(lim.entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	// Manually expire the entry.
	lim.entries["10.0.0.1"].windowStart = lim.entries["10.0.0.1"].windowStart.Add(-2 * RateWindow)
	lim.Cleanup()
	if len(lim.entries) != 0 {
		t.Error("expected cleanup to remove expired entry")
	}
}

// ─── LoginLimiter.Cleanup — bound the attacker-keyed maps ────────────────────

// TestLoginLimiter_Cleanup_RemovesStaleEntries is the regression guard for the
// unbounded-memory DoS: pair and account keys derive from the attacker-
// controlled username (and client IP) on the unauthenticated login POST, so
// without a sweep each failed attempt could leak a permanent entry. Cleanup
// must evict entries whose lock has expired AND unlocked entries whose failure
// window has elapsed, while keeping still-relevant ones — in BOTH tiers — and
// drop expired trust grants.
func TestLoginLimiter_Cleanup_RemovesStaleEntries(t *testing.T) {
	l := newLimiter()
	now := time.Now()

	l.mu.Lock()
	// Pair tier:
	// (a) lock expired → removable.
	l.pairs[pairKey(testIP, "expired-lock")] = &lockoutEntry{attempts: MaxAttempts, lockedUntil: now.Add(-time.Second)}
	// (b) unlocked, window elapsed → removable (a future RecordFailure resets it).
	l.pairs[pairKey(testIP, "stale-window")] = &lockoutEntry{attempts: 2, firstFail: now.Add(-Window - time.Minute)}
	// (c) unlocked, window still open → KEEP (an in-progress attacker must stay
	//     rate-limited).
	l.pairs[pairKey(testIP, "fresh-fail")] = &lockoutEntry{attempts: 2, firstFail: now.Add(-time.Second)}
	// (d) currently locked → KEEP (the lock must still apply).
	l.pairs[pairKey(testIP, "active-lock")] = &lockoutEntry{attempts: MaxAttempts, lockedUntil: now.Add(Duration)}
	// Account tier mirrors (a)/(d):
	l.accounts["acct-expired"] = &lockoutEntry{attempts: AccountMaxAttempts, lockedUntil: now.Add(-time.Second)}
	l.accounts["acct-active"] = &lockoutEntry{attempts: AccountMaxAttempts, lockedUntil: now.Add(Duration)}
	// Trust grants: one expired, one live.
	l.trusted["u1"] = map[string]time.Time{testIP: now.Add(-TrustTTL - time.Hour)}
	l.trusted["u2"] = map[string]time.Time{testIP: now}
	l.mu.Unlock()

	l.Cleanup()

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.pairs[pairKey(testIP, "expired-lock")]; ok {
		t.Error("expired pair lock should be evicted")
	}
	if _, ok := l.pairs[pairKey(testIP, "stale-window")]; ok {
		t.Error("elapsed-window pair entry should be evicted")
	}
	if _, ok := l.pairs[pairKey(testIP, "fresh-fail")]; !ok {
		t.Error("in-window pair entry must be kept (attacker still rate-limited)")
	}
	if _, ok := l.pairs[pairKey(testIP, "active-lock")]; !ok {
		t.Error("active pair lock must be kept (lock still applies)")
	}
	if _, ok := l.accounts["acct-expired"]; ok {
		t.Error("expired account lock should be evicted")
	}
	if _, ok := l.accounts["acct-active"]; !ok {
		t.Error("active account lock must be kept")
	}
	if _, ok := l.trusted["u1"]; ok {
		t.Error("expired trust grant should be evicted (and the empty user dropped)")
	}
	if _, ok := l.trusted["u2"][testIP]; !ok {
		t.Error("live trust grant must be kept")
	}
}

// TestLoginLimiter_Cleanup_DoesNotAlterDecision proves eviction is behavior-
// preserving: a fresh attempt after a stale entry is swept sees exactly the
// same state it would have via the hot-path lazy reset.
func TestLoginLimiter_Cleanup_DoesNotAlterDecision(t *testing.T) {
	l := newLimiter()

	l.mu.Lock()
	l.pairs[pairKey(testIP, "carol")] = &lockoutEntry{attempts: 3, firstFail: time.Now().Add(-Window - time.Minute)}
	l.mu.Unlock()

	l.Cleanup() // removes the stale entry

	// A subsequent failure must start a fresh window (attempts=1), identical to
	// the lazy reset RecordFailure would have applied to the stale entry.
	l.RecordFailure(testIP, "carol")
	if left := l.AttemptsLeft(testIP, "carol"); left != MaxAttempts-1 {
		t.Errorf("AttemptsLeft = %d after post-cleanup failure; want %d (fresh window)", left, MaxAttempts-1)
	}
}
