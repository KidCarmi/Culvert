// Package lockout provides the login account-lockout limiter and the admin-API
// rate limiter. It is a self-contained leaf (stdlib only, no Culvert coupling)
// extracted from the flat package main per ADR-0002.
package lockout

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Login rate-limiter / account lockout — two-tier (RISK-012)
//
// Tier 1 (pair lock): after MaxAttempts failures within Window from ONE
// client IP against ONE username, that (IP, username) pair is locked for
// Duration. This is the brute-force barrier a single attacker actually hits,
// and it localizes the lock: an attacker spamming failures for "admin" locks
// only their own pair, not the account — the legitimate admin's IP is
// unaffected (the old username-only keying let 5 unauthenticated POSTs lock
// the real admin out globally: lockout-as-DoS).
//
// Tier 2 (account lock): after AccountMaxAttempts failures within Window
// against ONE username ACROSS ALL IPs, the account locks for Duration — the
// backstop against distributed (IP-rotating) brute force, which tier 1 alone
// cannot see. To keep tier 2 from re-introducing the DoS, client IPs that
// previously completed a SUCCESSFUL login for that user (within TrustTTL,
// bounded at trustMaxIPs per user) BYPASS the account lock: the attacker's
// flood can trip tier 2, but the admin logging in from a known-good IP still
// gets through (and still answers to their own tier-1 pair lock).
//
// A successful login resets the pair counter and marks the IP trusted for
// that user. State is not persisted across restarts (intentional — an
// operator restart is the documented break-glass for a stuck lock).
// ---------------------------------------------------------------------------

const (
	// MaxAttempts is the number of failures from one IP against one username
	// that triggers a pair lock (tier 1).
	MaxAttempts = 5
	// AccountMaxAttempts is the number of failures against one username
	// across ALL IPs that triggers the account-wide lock (tier 2).
	AccountMaxAttempts = 20
	// Window is the span within which failures accumulate toward a lock.
	Window = 10 * time.Minute
	// Duration is how long a pair/account stays locked once tripped.
	Duration = 15 * time.Minute
	// TrustTTL is how long a successful login keeps its client IP exempt
	// from the tier-2 account lock for that username.
	TrustTTL = 30 * 24 * time.Hour
	// trustMaxIPs bounds the per-user trusted-IP set (oldest evicted).
	trustMaxIPs = 8
)

// MaxUsernameKeyLen bounds the username portion of every limiter map key.
//
// Both maps are keyed by data an UNAUTHENTICATED caller chooses: the login
// POST carries the username verbatim, and an entry survives at least Window
// (the janitor cannot remove it before then — see Cleanup). Cleanup therefore
// bounds the ENTRY COUNT over time but said nothing about the SIZE of a key,
// so a single caller sending oversized usernames retained
// (request rate x Window x username size) bytes of heap in a package whose own
// contract is to be bounded. The callers in package main clamp their input
// first; this bound is the structural half of the same guarantee, so no future
// caller can reintroduce the exposure by forgetting to.
//
// 256 bytes matches maxUsernameLen on the proxy-auth path (proxy_portal.go),
// which already answered this question for Proxy-Authorization. Note that a
// name past the bound CAN name a real account: `-user`/`auth.user` and
// `--reset-password` reach cfg.SetAuth/cfg.SetUIUser, and neither store bounds
// the name (only the API handlers cap at 64). The login endpoint therefore
// exempts a configured name from its own rejection, which means such a name
// reaches this limiter — so the clamp must stay INJECTIVE. See boundUsername.
const MaxUsernameKeyLen = 256

// usernameDigestLen is the hex-encoded SHA-256 prefix appended to a clamped
// name, plus the "…" marker. 16 hex characters is 64 bits: enough that two
// distinct usernames colliding is not something an attacker can construct.
const usernameDigestLen = len("…") + 16

// boundUsername clamps username to MaxUsernameKeyLen bytes. It MUST be applied
// at every public entry point that takes a username: Check and RecordFailure
// disagreeing about the key would silently split one attacker's failures across
// two counters and weaken the lock.
//
// The clamp is INJECTIVE, and that is a security property rather than tidiness.
// A plain truncation aliases every name sharing the first 256 bytes onto one
// entry, and because the login endpoint admits an over-long CONFIGURED name,
// one of those entries can belong to a real admin: an attacker who knew that
// admin's first 256 bytes could then submit an ordinary ≤256-byte name that
// clamps to the same key and drive the tier-2 account lock against them —
// lockout-as-DoS, the exact defect the two-tier design (RISK-012) exists to
// prevent. Appending a digest of the WHOLE name keeps the key bounded while
// keeping distinct names distinct.
//
// The retained prefix is cut on a UTF-8 rune boundary so the key stays
// renderable on the Snapshot admin surface.
func boundUsername(username string) string {
	if len(username) <= MaxUsernameKeyLen {
		return username
	}
	sum := sha256.Sum256([]byte(username))
	cut := MaxUsernameKeyLen - usernameDigestLen
	// A rune is at most 4 bytes, so one of the four bytes at or below the cut is
	// a rune start for any valid UTF-8 input. The search is bounded rather than
	// an unbounded walk back: an all-continuation-byte input would otherwise
	// walk to 0. Falling back to the raw byte cut keeps the value bounded (the
	// point of the clamp) and deterministic; the digest carries the identity
	// either way.
	for i := 0; i < 4 && cut > 0; i++ {
		if utf8.RuneStart(username[cut]) {
			break
		}
		cut--
	}
	if cut <= 0 || !utf8.RuneStart(username[cut]) {
		cut = MaxUsernameKeyLen - usernameDigestLen
	}
	return username[:cut] + "…" + hex.EncodeToString(sum[:])[:16]
}

// pairKey builds the tier-1 map key. \x00 cannot appear in an IP, so the
// separator is injection-safe (a crafted username cannot alias another
// client's pair).
func pairKey(ip, username string) string { return ip + "\x00" + username }

// splitPairKey reverses pairKey for display purposes (Snapshot).
func splitPairKey(key string) (ip, username string) {
	idx := strings.IndexByte(key, 0)
	if idx < 0 {
		return "", key
	}
	return key[:idx], key[idx+1:]
}

type lockoutEntry struct {
	attempts    int
	firstFail   time.Time
	lockedUntil time.Time
}

// recordFailureLocked applies one failure to e under the caller-held mutex,
// implementing the shared window-reset/lock-trip logic for both tiers.
// Returns true when this failure JUST tripped the lock.
func (e *lockoutEntry) recordFailureLocked(now time.Time, maxAttempts int) bool {
	// Reset the window once it has elapsed — but never while a lock is still
	// active: tier-2 entries keep receiving failures from trusted-IP clients
	// (who bypass the account lock at Check), and letting one such failure
	// reset a live lock would hand a flooding attacker a fresh budget.
	if !e.firstFail.IsZero() && now.Sub(e.firstFail) > Window && e.lockRemaining(now) == 0 {
		e.attempts = 0
		e.firstFail = time.Time{}
		e.lockedUntil = time.Time{}
	}
	if e.attempts == 0 {
		e.firstFail = now
	}
	e.attempts++
	if e.attempts == maxAttempts {
		e.lockedUntil = now.Add(Duration)
		return true
	}
	return false
}

// lockRemaining returns the seconds left on e's lock (0 when not locked or
// expired) under the caller-held mutex.
func (e *lockoutEntry) lockRemaining(now time.Time) int {
	if e == nil || e.lockedUntil.IsZero() {
		return 0
	}
	remaining := e.lockedUntil.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Seconds()) + 1
}

// LoginLimiter tracks failed login attempts per (client IP, username) pair
// (tier 1) and per username across IPs (tier 2), with a trusted-IP bypass on
// tier 2 for IPs that previously logged in successfully.
type LoginLimiter struct {
	mu       sync.Mutex
	pairs    map[string]*lockoutEntry        // key: ip\x00username
	accounts map[string]*lockoutEntry        // key: username
	trusted  map[string]map[string]time.Time // username -> ip -> last success
}

// NewLoginLimiter returns a ready-to-use LoginLimiter.
func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		pairs:    map[string]*lockoutEntry{},
		accounts: map[string]*lockoutEntry{},
		trusted:  map[string]map[string]time.Time{},
	}
}

// isTrustedLocked reports whether ip has a live TrustTTL grant for username.
// Caller holds l.mu.
func (l *LoginLimiter) isTrustedLocked(ip, username string, now time.Time) bool {
	ts, ok := l.trusted[username][ip]
	return ok && now.Sub(ts) <= TrustTTL
}

// Check returns (locked bool, secondsRemaining int) for a login attempt by
// username from client ip. A locked attempt must not be verified further.
// The pair lock always applies; the account lock is bypassed for IPs with a
// live trust grant. Expired entries are lazily deleted.
func (l *LoginLimiter) Check(ip, username string) (locked bool, secondsRemaining int) {
	username = boundUsername(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	if secs := l.pairLockSecondsLocked(ip, username, now); secs > 0 {
		return true, secs
	}
	if secs := l.accountLockSecondsLocked(ip, username, now); secs > 0 {
		return true, secs
	}
	return false, 0
}

// pairLockSecondsLocked returns the tier-1 lock's remaining seconds for the
// (ip, username) pair (0 = not locked), lazily deleting an expired entry. If
// the pair is locked it also raises the value to the account lock's remaining
// seconds (for untrusted IPs) so the retry hint reflects the longer wait.
// Caller holds l.mu.
func (l *LoginLimiter) pairLockSecondsLocked(ip, username string, now time.Time) int {
	e := l.pairs[pairKey(ip, username)]
	if e == nil || e.lockedUntil.IsZero() {
		return 0
	}
	secs := e.lockRemaining(now)
	if secs == 0 {
		delete(l.pairs, pairKey(ip, username)) // lock expired — clean up
		return 0
	}
	if !l.isTrustedLocked(ip, username, now) {
		if acctSecs := l.accounts[username].lockRemaining(now); acctSecs > secs {
			secs = acctSecs
		}
	}
	return secs
}

// accountLockSecondsLocked returns the tier-2 account lock's remaining seconds
// (0 = not locked or bypassed), lazily deleting an expired entry. A live trust
// grant for (ip, username) bypasses the lock. Caller holds l.mu.
func (l *LoginLimiter) accountLockSecondsLocked(ip, username string, now time.Time) int {
	e := l.accounts[username]
	if e == nil || e.lockedUntil.IsZero() {
		return 0
	}
	secs := e.lockRemaining(now)
	if secs == 0 {
		delete(l.accounts, username) // lock expired — clean up
		return 0
	}
	if l.isTrustedLocked(ip, username, now) {
		return 0 // known-good IP bypasses the account lock
	}
	return secs
}

// CheckPair reports the tier-1 (IP, username) pair lock ONLY, ignoring the
// account tier entirely. It is for callers that want pure per-IP rate
// limiting with no cross-IP aggregation — notably the pre-provisioning setup
// endpoint, where there is no account to protect yet and an account-wide
// counter would let a few IPs globally block bootstrap (lockout-as-DoS).
func (l *LoginLimiter) CheckPair(ip, username string) (locked bool, secondsRemaining int) {
	username = boundUsername(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	if secs := l.pairLockSecondsLocked(ip, username, time.Now()); secs > 0 {
		return true, secs
	}
	return false, 0
}

// RecordPairFailure registers one failed attempt against the tier-1 (IP,
// username) pair ONLY, leaving the account tier untouched. Pair-only
// companion to CheckPair. Returns true when this attempt JUST tripped the
// pair lock.
func (l *LoginLimiter) RecordPairFailure(ip, username string) bool {
	username = boundUsername(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	pk := pairKey(ip, username)
	pe := l.pairs[pk]
	if pe == nil {
		pe = &lockoutEntry{}
		l.pairs[pk] = pe
	}
	return pe.recordFailureLocked(time.Now(), MaxAttempts)
}

// RecordFailure registers one failed attempt from ip against username in
// both tiers. Returns true when this attempt JUST tripped either lock (so
// the caller can log the lockout event).
func (l *LoginLimiter) RecordFailure(ip, username string) bool {
	username = boundUsername(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	pk := pairKey(ip, username)
	pe := l.pairs[pk]
	if pe == nil {
		pe = &lockoutEntry{}
		l.pairs[pk] = pe
	}
	pairTripped := pe.recordFailureLocked(now, MaxAttempts)

	ae := l.accounts[username]
	if ae == nil {
		ae = &lockoutEntry{}
		l.accounts[username] = ae
	}
	acctTripped := ae.recordFailureLocked(now, AccountMaxAttempts)

	return pairTripped || acctTripped
}

// RecordSuccess clears the pair's failure history and marks ip as trusted
// for username (TrustTTL, bounded at trustMaxIPs with oldest-first eviction).
// The tier-2 account counter is deliberately NOT cleared: a victim's
// successful login must not erase the evidence of a concurrent distributed
// attack, and the victim doesn't need it cleared — their IP is now trusted.
func (l *LoginLimiter) RecordSuccess(ip, username string) {
	username = boundUsername(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.pairs, pairKey(ip, username))

	set := l.trusted[username]
	if set == nil {
		set = map[string]time.Time{}
		l.trusted[username] = set
	}
	now := time.Now()
	set[ip] = now
	if len(set) > trustMaxIPs {
		oldestIP, oldestTS := "", now
		for tip, ts := range set {
			if ts.Before(oldestTS) {
				oldestIP, oldestTS = tip, ts
			}
		}
		delete(set, oldestIP)
	}
}

// Cleanup removes entries that can no longer affect a decision, bounding the
// maps against an unbounded-memory DoS: the pair and account keys derive from
// the attacker-controlled username (and client IP) on the unauthenticated
// login POST, so without a sweep each failed attempt could leak a permanent
// entry. An entry is removable when its lock has expired (a future Check
// would delete it anyway) or when it is unlocked and its failure window has
// elapsed (a future RecordFailure would reset it to a fresh window). Trusted
// grants past TrustTTL are dropped too (they no longer bypass anything).
// Called periodically by the shared cleanup janitor. Removing a stale entry
// is behaviorally identical to the lazy reset the hot paths already perform,
// so it changes no decision.
func (l *LoginLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, entries := range []map[string]*lockoutEntry{l.pairs, l.accounts} {
		for key, e := range entries {
			if !e.lockedUntil.IsZero() {
				if e.lockedUntil.Before(now) {
					delete(entries, key) // lock expired
				}
				continue
			}
			if !e.firstFail.IsZero() && now.Sub(e.firstFail) > Window {
				delete(entries, key) // accumulating-failures window elapsed
			}
		}
	}
	for username, set := range l.trusted {
		for ip, ts := range set {
			if now.Sub(ts) > TrustTTL {
				delete(set, ip)
			}
		}
		if len(set) == 0 {
			delete(l.trusted, username)
		}
	}
}

// AttemptsLeft returns how many more failures the (ip, username) pair is
// allowed before the tier-1 lock trips.
func (l *LoginLimiter) AttemptsLeft(ip, username string) int {
	username = boundUsername(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.pairs[pairKey(ip, username)]
	if e == nil {
		return MaxAttempts
	}
	left := MaxAttempts - e.attempts
	if left < 0 {
		left = 0
	}
	return left
}

// ResetUser removes ALL failure/lock state for username — the tier-2 account
// entry and every (ip, username) pair — without touching the trusted-IP set
// (trust is an allowance earned by a successful login, not lock state). This
// is the explicit unlock primitive: test isolation helpers use it where the
// old single-tier code abused RecordSuccess as a full reset, and it is the
// natural hook for a future admin "unlock account" API.
func (l *LoginLimiter) ResetUser(username string) {
	username = boundUsername(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.accounts, username)
	suffix := "\x00" + username
	for key := range l.pairs {
		if len(key) >= len(suffix) && key[len(key)-len(suffix):] == suffix {
			delete(l.pairs, key)
		}
	}
}

// LockedEntry describes one currently-active lockout, for admin visibility.
// Tier is "account" (tier-2, blocks every IP for Username) or "pair"
// (tier-1, blocks only IP against Username). IP is empty for account-tier
// entries.
type LockedEntry struct {
	Tier             string `json:"tier"`
	Username         string `json:"username"`
	IP               string `json:"ip,omitempty"`
	SecondsRemaining int    `json:"seconds_remaining"`
}

// Snapshot returns every currently-active lockout across both tiers, sorted
// by username then IP for stable display. It is the read side of the
// explicit unlock primitive (ResetUser) — without it, an operator has no way
// to see who is locked out short of reading logs or waiting/restarting. It
// does not mutate limiter state; expired entries are simply omitted.
func (l *LoginLimiter) Snapshot() []LockedEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	out := []LockedEntry{}
	for username, e := range l.accounts {
		if secs := e.lockRemaining(now); secs > 0 {
			out = append(out, LockedEntry{Tier: "account", Username: username, SecondsRemaining: secs})
		}
	}
	for key, e := range l.pairs {
		if secs := e.lockRemaining(now); secs > 0 {
			ip, username := splitPairKey(key)
			out = append(out, LockedEntry{Tier: "pair", Username: username, IP: ip, SecondsRemaining: secs})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Username != out[j].Username {
			return out[i].Username < out[j].Username
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// SnapshotAndClear captures the current limiter state, replaces it with an
// empty state, and returns a closure that restores the captured state. It is
// the exported equivalent of the whitebox snapshot/restore idiom used for
// test isolation of the package-global limiter: the maps are deep-copied
// under the mutex and the restore runs under the mutex too, so neither tears
// against a concurrent reader/writer. Production code never calls this; it
// exists so package main's test isolation helper does not need access to the
// unexported maps across the package boundary (ADR-0002 extraction).
func (l *LoginLimiter) SnapshotAndClear() func() {
	l.mu.Lock()
	savedPairs := make(map[string]*lockoutEntry, len(l.pairs))
	for k, v := range l.pairs {
		cp := *v
		savedPairs[k] = &cp
	}
	savedAccounts := make(map[string]*lockoutEntry, len(l.accounts))
	for k, v := range l.accounts {
		cp := *v
		savedAccounts[k] = &cp
	}
	savedTrusted := make(map[string]map[string]time.Time, len(l.trusted))
	for u, set := range l.trusted {
		cpSet := make(map[string]time.Time, len(set))
		for ip, ts := range set {
			cpSet[ip] = ts
		}
		savedTrusted[u] = cpSet
	}
	l.pairs = map[string]*lockoutEntry{}
	l.accounts = map[string]*lockoutEntry{}
	l.trusted = map[string]map[string]time.Time{}
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.pairs = savedPairs
		l.accounts = savedAccounts
		l.trusted = savedTrusted
		l.mu.Unlock()
	}
}

// Msg returns a human-readable lockout error. Exposed in package main as
// LockoutMsg via the shim alias.
func Msg(seconds int) string {
	return fmt.Sprintf("Account temporarily locked. Try again in %d seconds.", seconds)
}

// ---------------------------------------------------------------------------
// Admin API rate limiter — protects mutation endpoints against abuse.
//
// A sliding window of Burst requests is allowed per IP per RateWindow.
// This runs *after* session auth, so it limits authenticated admin actions.
// ---------------------------------------------------------------------------

const (
	// Burst is the max API mutations allowed per window.
	Burst = 60
	// RateWindow is the sliding window width for the API rate limiter.
	RateWindow = 1 * time.Minute
)

type apiRateEntry struct {
	count       int
	windowStart time.Time
}

// APIRateLimiter limits mutating admin API calls per client IP.
type APIRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*apiRateEntry
}

// NewAPIRateLimiter returns a ready-to-use APIRateLimiter.
func NewAPIRateLimiter() *APIRateLimiter {
	return &APIRateLimiter{entries: map[string]*apiRateEntry{}}
}

// Allow returns true if the IP is within the rate limit for API mutations.
func (a *APIRateLimiter) Allow(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[ip]
	now := time.Now()
	if e == nil || now.Sub(e.windowStart) > RateWindow {
		a.entries[ip] = &apiRateEntry{count: 1, windowStart: now}
		return true
	}
	e.count++
	return e.count <= Burst
}

// Cleanup removes expired entries.
func (a *APIRateLimiter) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, e := range a.entries {
		if now.Sub(e.windowStart) > RateWindow {
			delete(a.entries, k)
		}
	}
}
