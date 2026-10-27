// Package session implements Culvert's HMAC-SHA256-signed session tokens and
// the revocation machinery behind them (ADR-0002 extraction; engine was
// session.go in package main).
//
// The package owns: the signing key (with synchronized access — the key is
// written at runtime by the cluster snapshot sync while the MAC path reads it
// concurrently) and the pooled HMAC-SHA256 engine bound to it (Decode runs on
// the proxy authentication hot path, so the verify step is allocation-free;
// see the MAC engine section below), token encode/decode (base64(json).HMAC),
// the revocation list (token- and user-level, with lazy expiry eviction,
// gossip export/merge, and optional disk persistence), the session TTL, and
// jti generation.
//
// package main keeps: the HTTP cookie helpers (they need isSecureRequest and
// the Identity hub type), the startup wiring (env/config key priority — env
// is read in the startup shim per the slice convention), and the
// Session→Identity conversion (Identity is a main hub type this package must
// not import).
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// CookieName is the session cookie name.
const CookieName = "ps_session"

// ---------------------------------------------------------------------------
// Signing key — configurable for multi-node deployments
// ---------------------------------------------------------------------------

var (
	signingKeyMu sync.RWMutex
	signingKey   []byte
)

// SetSigningKey installs the HMAC key. Callers own validation (length/hex);
// the cluster snapshot path and the startup shim both funnel through here.
// Synchronized: the DP config-sync path replaces the key at runtime while
// concurrent requests compute MACs (previously an unguarded global write —
// latent data race, fixed with this extraction).
func SetSigningKey(key []byte) {
	signingKeyMu.Lock()
	// Rebind the MAC engine in the SAME critical section, so two concurrent
	// installs order identically for the key and for the pool of HMAC states
	// that sign under it (see macEngines) — but only when the key actually
	// CHANGED. applySnapshotSessionSecret reinstalls the CP-synced secret on
	// every snapshot apply whether or not it moved, and an unconditional
	// rebind would throw away the warm pool on each of those no-ops.
	// Constant-time compare: both sides are server-owned secrets, so this is
	// hygiene rather than a defended oracle, and it costs 32 bytes of work.
	//
	// The comparison is only MEANINGFUL because signingKey is a copy this
	// package owns, which is why the copy below is on the rebind path rather
	// than at the top of the function. Were signingKey the caller's slice, a
	// caller that mutated the slice it had installed and then reinstalled it
	// would hand this compare the same mutated bytes on BOTH sides: equal, so
	// no rebind — and from then on SigningKey, and the CP snapshot export
	// reading through it, would report the new key while the engine still
	// signed with the old one. Cookies issued before that "rotation" would keep
	// verifying and an exported key would disagree with local verification.
	// Both halves were reproduced against the tree and are pinned by
	// TestSetSigningKey_CopiesKeyOnInstall (CodeRabbit, PR #1657). Only the
	// pooling makes this reachable at all: the per-call hmac.New form re-read
	// signingKey on every MAC and could not drift.
	//
	// Copying here and not above also keeps the no-op reinstall allocation-free,
	// which is the property TestBenchGate_UnchangedKeyKeepsPoolWarm measures.
	if subtle.ConstantTimeCompare(key, signingKey) != 1 {
		// make+copy, not append([]byte(nil), key...): appending no elements to
		// a nil slice yields nil, which would turn an installed EMPTY key into
		// an absent one and change what SigningKey reports.
		installed := make([]byte, len(key))
		copy(installed, key)
		signingKey = installed
		macEngines.Store(newMacEngine(installed))
	}
	signingKeyMu.Unlock()
}

// SigningKey returns a copy of the current HMAC key (nil when unset). Used by
// the CP snapshot export (hex-encoded into ConfigSnapshot.SessionHMAC) and by
// test snapshot/restore helpers.
func SigningKey() []byte {
	signingKeyMu.RLock()
	defer signingKeyMu.RUnlock()
	if signingKey == nil {
		return nil
	}
	out := make([]byte, len(signingKey))
	copy(out, signingKey)
	return out
}

// HasSigningKey reports whether a key is installed.
func HasSigningKey() bool {
	signingKeyMu.RLock()
	defer signingKeyMu.RUnlock()
	return len(signingKey) > 0
}

// InitRandomKey installs a fresh random 32-byte key. Fails loudly: session
// machinery that cannot generate randomness is unsafe to keep running.
func InitRandomKey() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("session: failed to generate secret: %v", err))
	}
	SetSigningKey(key)
}

// NewJti returns a fresh 128-bit random session identifier, hex encoded.
// Stamped into every newly-issued Session by the cookie issuers so two
// same-second logins for the same user produce distinct b64 payloads (and
// therefore distinct HMACs and cookie values). The only collision space is
// 2^128, far beyond birthday-bound concerns for any plausible deployment.
//
// crypto/rand failure is treated the same as InitRandomKey's: fail loudly.
func NewJti() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("session: failed to generate jti: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------
// Session revocation list — invalidates tokens on explicit logout.
// Entries are evicted lazily when their original expiry passes.
// ---------------------------------------------------------------------------

// RevocationList tracks revoked session tokens and user-level revocations.
type RevocationList struct {
	mu     sync.Mutex
	tokens map[string]time.Time // b64 payload → session expiry
	users  map[string]time.Time // username → revocation expiry (all sessions for this user)

	// sinceSweep counts insertions since the last expired-entry sweep.
	// CHAOS-73: eviction used to be lazy-on-read only, which never fires for
	// the one key that is guaranteed never to be presented again — the cookie
	// that just logged out — so an un-clustered node had no evictor at all.
	// See revocation_bounds.go.
	sinceSweep int

	// verified holds the tokens this process admitted through RevokeVerified
	// (or reloaded from the file with a valid provenance MAC). Only these are
	// written to the revocations file with a provenance MAC, and only entries
	// carrying a valid one are reloaded past the untrusted-origin bounds. See
	// provenanceMAC in revocation_bounds.go.
	verified map[string]struct{}

	// unread is set when THIS boot could not READ the revocations file, and it
	// makes SaveRevocations refuse rather than overwrite.
	//
	// A file that could not be read is deliberately NOT quarantined — its
	// content may be perfectly intact behind a transient permission or I/O
	// fault, and moving a healthy security-critical file aside is the worse
	// error. That reasoning is only sound if nothing LATER overwrites it, and
	// it did: the process boots with an EMPTY list, and the first logout,
	// account deletion or cluster sync that adds an entry calls
	// SaveRevocations, which renames a complete temp file over the target.
	// AtomicWrite needs only the parent DIRECTORY to be writable, so an
	// unreadable file in a writable directory — a mode change, an ACL, an EIO
	// on the file's own blocks — is replaced by the handful of revocations
	// this process happens to know about. Every revocation that was on disk
	// and never read is then gone for good, and the operator's own remedy
	// (fix the permission, restart) loads the truncated file instead.
	//
	// That is fail-OPEN on the one control that can withdraw an already-issued
	// session, and it was reachable by ordinary operation rather than by a
	// second fault. Reported by Codex on PR #1437 as a P1.
	//
	// Refusing costs no ENFORCEMENT: the revocation is still applied in
	// memory and honoured by this node. It costs DURABILITY, which is already
	// false and already reported — LoadDegraded makes revocationsAreDurable()
	// false and fails the session_revocation row — so the refusal adds no
	// silent state. And it preserves the one thing a restart can still
	// recover, which a write destroys permanently.
	//
	// Only the READ failure sets it. A CORRUPT file is quarantined (moved
	// aside), so the path is free and writing a fresh list there is correct —
	// but ONLY IF THE QUARANTINE ACTUALLY HAPPENED, which is what
	// fenceUnquarantined below covers.
	writeFence atomic.Int32
}

// Write-fence reasons. The fence is ONE mechanism with distinct reasons,
// because the two faults need different operator remedies and a single
// sentinel would tell one of them the wrong thing — the AU-36 lesson (a
// bounded classifier is worth nothing if one remedy is printed for every
// class) applied to the refusal itself.
const (
	fenceNone = iota
	// fenceUnread: this boot could not READ the file (AU-37).
	fenceUnread
	// fenceUnquarantined: the file was read, would not parse, and could NOT
	// be moved aside. The corrupt bytes are still at the target path and are
	// the only copy, so a save would destroy the evidence the quarantine
	// exists to preserve (AU-38).
	fenceUnquarantined
)

// NewRevocationList returns an empty list (used by tests to swap the
// package singleton, mirroring the bl pointer-swap idiom).
func NewRevocationList() *RevocationList {
	return &RevocationList{
		tokens:   map[string]time.Time{},
		users:    map[string]time.Time{},
		verified: map[string]struct{}{},
	}
}

// Revoked is the process-wide revocation list consulted by Decode.
var Revoked = NewRevocationList()

// Revoke marks a token (its b64 payload) as revoked until exp.
//
// It reports whether the list actually changed, so a caller that persists
// after revoking does not rewrite the whole file for a no-op. Callers that
// do not care may ignore the result.
//
// CHAOS-73: this is the UNVERIFIED primitive and it is now internal to the
// package's own trusted callers plus tests. The logout path must use
// RevokeVerified, which authenticates the cookie first — see
// revocation_bounds.go for why the MAC check is the whole security property.
func (r *RevocationList) Revoke(token string, exp time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, exists := r.tokens[token]; exists && !prev.Before(exp) {
		return false
	}
	r.tokens[token] = exp
	r.sweepIfDueLocked(time.Now())
	return true
}

// IsRevoked reports whether the token is currently revoked, lazily
// evicting entries whose original expiry has passed.
func (r *RevocationList) IsRevoked(token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.tokens[token]
	if !ok {
		return false
	}
	// SEC-REVEXP-1: the eviction test is Decode's acceptance test, so this
	// entry cannot be dropped while a cookie it revokes would still be
	// honoured. See revocation_expiry.go.
	if revocationExpired(time.Now(), exp) {
		delete(r.tokens, token) // lazy eviction
		delete(r.verified, token)
		return false
	}
	return true
}

// RevokeUser invalidates all sessions for a username. Active session cookies
// for this user are rejected until the revocation expiry (max session TTL).
// Called when a user account is deleted (Finding 5.2).
func (r *RevocationList) RevokeUser(username string) {
	r.mu.Lock()
	r.users[username] = time.Now().Add(TTL())
	r.mu.Unlock()
}

// IsUserRevoked returns true if all sessions for the given username are revoked.
func (r *RevocationList) IsUserRevoked(username string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.users[username]
	if !ok {
		return false
	}
	// SEC-REVEXP-1: same single oracle as the token list above.
	if revocationExpired(time.Now(), exp) {
		delete(r.users, username) // lazy eviction
		return false
	}
	return true
}

// userRevocationTokenPrefix namespaces the Token field of a USER-level
// revocation entry (CHAOS-68).
//
// A user entry needs a Token value for two independent reasons, and both are
// load-bearing:
//
//  1. `revocationAggregator.MergedExcluding` (controlplane.go) de-duplicates
//     the fleet-wide merge on `e.Token` alone. Leaving it empty would collapse
//     EVERY user revocation in the cluster into a single entry — the fleet
//     would learn about one deleted account and silently drop the rest.
//  2. A binary predating this change unmarshals the entry (unknown fields are
//     ignored) and files it under `tokens[Token]`. With the prefix that key is
//     INERT: a real token is the `base64.RawURLEncoding` of a Session payload,
//     whose alphabet is [A-Za-z0-9-_], so a key containing ':' can never equal
//     a cookie's payload segment. A downgraded node therefore carries the entry
//     harmlessly instead of matching a live cookie against it — and when it
//     gossips the entry back, MergeRevocations below recovers the username from
//     the prefix, so one hop through an old node does not erase the revocation.
//
// The non-collision is a security property, not a convenience, and is pinned by
// TestUserRevocationTokenCannotCollideWithACookiePayload.
const userRevocationTokenPrefix = "user:"

// RevocationEntry is a single revocation for gRPC gossip and for the persisted
// revocations file.
//
// Exactly one of the two revocation KINDS is represented by any entry:
//
//   - a TOKEN revocation (explicit logout) sets Token to the cookie's base64
//     payload segment and leaves User empty;
//   - a USER revocation (the account was deleted) sets User to the username and
//     Token to userRevocationTokenPrefix+User.
//
// User and Prov are `omitempty` and Token is always populated, so the document
// stays a JSON array that a binary predating CHAOS-68 parses without error.
// That downgrade compatibility is deliberate: promoting the file to an object
// would make an older binary fail the whole parse and lose the TOKEN
// revocations it does understand — trading a gap for a regression.
type RevocationEntry struct {
	Token  string `json:"token"`
	Expiry int64  `json:"expiry"` // Unix timestamp
	// User, when non-empty, makes this a user-level revocation (CHAOS-68).
	User string `json:"user,omitempty"`
	// Prov is the provenance MAC of a locally MAC-verified TOKEN revocation. It
	// is written to the PERSISTENCE FILE only (never by ExportRevocations, so
	// the gossip wire is unchanged) and lets LoadRevocations tell this
	// appliance's own verified entries from untrusted ones. See provenanceMAC.
	// User entries never carry one: they are reloaded through the untrusted
	// bounds, which no genuine account revocation can exceed.
	Prov string `json:"prov,omitempty"`
}

// ExportRevocations returns all non-expired revocation entries — BOTH kinds —
// for syncing and for persistence.
//
// CHAOS-68: this used to walk `r.tokens` only, which made the `users` map
// invisible to every durable and distributed surface the list has. A deleted
// account's live sessions were rejected in the memory of the one node that
// served the DELETE, until that process exited. Both maps are exported now, so
// a user revocation reaches disk and the fleet by the same paths a logout does.
func (r *RevocationList) ExportRevocations() []RevocationEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	// One shared sweep rather than a second inline copy of the eviction rule
	// (CHAOS-73: two dialects for one question inside one struct is the trap).
	// sweepLocked covers BOTH maps with SEC-REVEXP-1's oracle.
	r.sweepLocked(now)
	entries := make([]RevocationEntry, 0, len(r.tokens)+len(r.users))
	for tok, exp := range r.tokens {
		entries = append(entries, RevocationEntry{Token: tok, Expiry: exp.Unix()})
	}
	for user, exp := range r.users {
		// SEC-REVEXP-1: no inline eviction here. sweepLocked above already
		// dropped expired USER entries with the same oracle as the tokens — a
		// raw now.After(exp) in this loop once deleted a deleted ACCOUNT's
		// revocation from disk and from every peer during the wall-clock second
		// numbered Exp, while Decode still accepted that account's cookies
		// (AU-52's standing rule: fixing one loop does not fix its twin).
		entries = append(entries, RevocationEntry{
			Token:  userRevocationTokenPrefix + user,
			Expiry: exp.Unix(),
			User:   user,
		})
	}
	return entries
}

// ExportRevocationsByOrigin is ExportRevocations split by provenance, for the
// cluster gossip request that has to choose what to send first (AU-50).
//
// local holds the TOKEN entries this process admitted through RevokeVerified,
// or reloaded from its own file with a valid provenance MAC: the logouts that
// happened HERE, which no other node can tell the fleet about. other holds
// every other live entry — tokens learned from gossip or reloaded without
// provenance, and every ACCOUNT revocation. Account entries are not split
// because their origin is not tracked (they reload through the untrusted
// bounds), and the caller ranks them on their own anyway.
//
// The union is exactly what ExportRevocations returns, under the same sweep,
// so the split decides ORDER and never membership.
func (r *RevocationList) ExportRevocationsByOrigin() (local, other []RevocationEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(time.Now())
	local = make([]RevocationEntry, 0, len(r.verified))
	other = make([]RevocationEntry, 0, len(r.tokens)+len(r.users)-len(r.verified))
	for tok, exp := range r.tokens {
		e := RevocationEntry{Token: tok, Expiry: exp.Unix()}
		if _, ok := r.verified[tok]; ok {
			local = append(local, e)
			continue
		}
		other = append(other, e)
	}
	for user, exp := range r.users {
		other = append(other, RevocationEntry{
			Token:  userRevocationTokenPrefix + user,
			Expiry: exp.Unix(),
			User:   user,
		})
	}
	return local, other
}

// exportPersisted is ExportRevocations plus the provenance MAC on every
// locally verified TOKEN entry; it is what SaveRevocations writes. It carries
// BOTH kinds (CHAOS-68): a file that held only tokens would make an account
// deletion's revocation vanish at the next restart.
func (r *RevocationList) exportPersisted() []RevocationEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(time.Now())
	entries := make([]RevocationEntry, 0, len(r.tokens)+len(r.users))
	for tok, exp := range r.tokens {
		e := RevocationEntry{Token: tok, Expiry: exp.Unix()}
		if _, ok := r.verified[tok]; ok {
			e.Prov = provenanceMAC(tok, e.Expiry)
		}
		entries = append(entries, e)
	}
	for user, exp := range r.users {
		entries = append(entries, RevocationEntry{
			Token:  userRevocationTokenPrefix + user,
			Expiry: exp.Unix(),
			User:   user,
		})
	}
	return entries
}

// MergeRevocations imports remote revocation entries (from other cluster
// nodes). Only adds entries that are not yet expired and not already present.
// Returns how many entries were newly applied.
//
// CHAOS-73: this is an UNTRUSTED-ORIGIN path — a peer node chooses the key
// bytes, the key length and the entry count — so every entry goes through the
// untrusted admission bounds (key-size bound, far-future refusal, entry cap,
// counted refusal). The list is swept first so the cap is measured against
// LIVE entries rather than against expired ones nobody has read since they
// died.
//
// CHAOS-68: an entry is classified as a USER revocation when it carries an
// explicit User field, OR when its Token carries userRevocationTokenPrefix.
// The second form only arises when the entry has passed through a node
// predating CHAOS-68, which drops the unknown `user` JSON field but preserves
// the token verbatim; recovering the username from the prefix means one hop
// through an old node degrades nothing. A token that merely LOOKS like a user
// entry cannot be a real cookie payload (see userRevocationTokenPrefix), so
// this classification can never swallow a genuine token revocation. User
// entries get the same untrusted bounds as tokens (admitUntrustedUserLocked).
func (r *RevocationList) MergeRevocations(entries []RevocationEntry) int {
	return r.mergeUntrusted(entries, false)
}

// mergeUntrusted admits entries from an untrusted origin; persisted marks the
// on-disk revocations file (see admitUntrustedLocked).
func (r *RevocationList) mergeUntrusted(entries []RevocationEntry, persisted bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.sweepLocked(now)
	added := 0
	for _, e := range entries {
		exp := time.Unix(e.Expiry, 0)
		// SEC-REVEXP-1: admit on the same oracle that retains. A peer's entry
		// for a session Decode would still accept must not be refused as
		// "already expired".
		if revocationExpired(now, exp) {
			continue // already expired
		}
		if user := revocationEntryUser(e); user != "" {
			if !r.admitUntrustedUserLocked(e, user, exp, now) {
				continue
			}
			// Keep the LATER expiry: a re-delete of the same username extends
			// the window, and taking the earlier one would shorten a revocation
			// on a gossip round trip.
			if cur, exists := r.users[user]; !exists || exp.After(cur) {
				r.users[user] = exp
				added++
			}
			continue
		}
		// A persisted entry carrying a valid provenance MAC is one this
		// appliance verified itself (RevokeVerified) under the current signing
		// key, so it reloads past the untrusted bounds: refusing it on size or
		// capacity would resurrect a session an operator revoked (Codex P1/P2,
		// CodeRabbit, PR #1591). Gossip never takes this branch.
		if persisted && validProvenance(e) {
			if _, exists := r.tokens[e.Token]; !exists {
				added++
			}
			r.tokens[e.Token] = exp
			r.verified[e.Token] = struct{}{}
			continue
		}
		if !r.admitUntrustedLocked(e, now) {
			continue
		}
		r.tokens[e.Token] = time.Unix(e.Expiry, 0)
		added++
	}
	return added
}

// Count returns the number of active revoked session TOKENS.
//
// It sweeps first (sweepLocked), so it reports LIVE entries; see the note
// after UserCount for why.
func (r *RevocationList) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(time.Now())
	return len(r.tokens)
}

// UserCount returns the number of active user-level revocations.
//
// Separate from Count because the two answer different operator questions and
// used to be indistinguishable: `local_revoked` on the cluster API reported
// only tokens, so a node holding a hundred deleted-account revocations and one
// holding none serialised identically.
func (r *RevocationList) UserCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(time.Now())
	return len(r.users)
}

// Why Count and UserCount sweep (CHAOS-68), and why through sweepLocked.
//
// Counting live entries rather than map length is not cosmetic. Expiry in this
// list is otherwise amortised — IsRevoked drops an entry only when something
// asks about that exact token, and the insertion-driven sweep runs only every
// revocationSweepEvery inserts — so on a quiet standalone node an expired
// revocation can sit in the map for a long time. Both counts feed gauges whose
// HELP text says "currently in force" and the /api/cluster/revocations
// surface, so an expired entry reported there is a WRONG answer, not merely a
// stale one: it tells an operator that sessions are still being denied when
// they are not.
//
// The eviction test is SEC-REVEXP-1's shared oracle, NOT a raw now.After(exp),
// and that is a security property rather than tidiness. These functions
// DELETE, and they are reached from read-only surfaces — a /metrics scrape, the
// session_revocation diagnostics row, /api/cluster/revocations — so a looser
// test here destroys a revocation that Decode would still honour (Codex P2,
// PR #1437). Going through sweepLocked rather than a private prune loop also
// keeps the `verified` provenance set in step with `tokens` (CHAOS-73), which a
// prune that deleted only from `tokens` would leave holding orphaned keys.

// SwapForTest replaces the list's maps with empty ones and returns a restore
// function. Mirrors the snapshot/restore pattern documented in CLAUDE.md for
// tests that touch shared revocation state.
func (r *RevocationList) SwapForTest() (restore func()) {
	r.mu.Lock()
	prevTokens, prevUsers, prevSweep, prevVerified := r.tokens, r.users, r.sinceSweep, r.verified
	r.tokens = map[string]time.Time{}
	r.users = map[string]time.Time{}
	r.verified = map[string]struct{}{}
	r.sinceSweep = 0
	r.mu.Unlock()
	// The unread fence is a LATCH on this object, cleared in production only by
	// a load that succeeds — which normally means a restart. It therefore
	// outlives any test that trips it, and because the swap restores the SAME
	// object rather than installing a fresh one, one test driving
	// LoadRevocations against an unreadable path would make every LATER test's
	// SaveRevocations refuse. Order-dependent, so only -shuffle sees it; it was
	// found exactly that way.
	//
	// EVERY field added to this struct belongs here. That is the same rule this
	// sweep already recorded for resetDiagVerdictGlobals and broke again here:
	// a new process-global with a latching state must be registered with its
	// isolation primitive IN THE SAME CHANGE.
	prevFence := r.writeFence.Swap(fenceNone)
	return func() {
		r.mu.Lock()
		r.tokens = prevTokens
		r.users = prevUsers
		r.verified = prevVerified
		r.sinceSweep = prevSweep
		r.mu.Unlock()
		r.writeFence.Store(prevFence)
	}
}

// revocationsPath is the path used to persist revocations to disk.
// Set via SetRevocationsPath (--revocations-file flag); empty = no persistence.
var (
	revocationsPathMu sync.RWMutex
	revocationsPath   string
)

// SetRevocationsPath configures where SaveRevocations/LoadRevocations persist.
func SetRevocationsPath(p string) {
	revocationsPathMu.Lock()
	revocationsPath = p
	revocationsPathMu.Unlock()
}

// RevocationsPath returns the configured persistence path ("" = disabled).
func RevocationsPath() string {
	revocationsPathMu.RLock()
	defer revocationsPathMu.RUnlock()
	return revocationsPath
}

// ErrRevocationsCorrupt wraps a revocations file that was READ successfully and
// could not be PARSED.
//
// The distinction is the caller's whole decision (CHAOS-68): a file we could
// not read may be perfectly intact behind a transient permission or I/O fault,
// and quarantining it would move a healthy security-critical file aside; a file
// we read and could not parse is corrupt, and the next SaveRevocations would
// atomically OVERWRITE it — destroying the evidence and every revocation in it.
// Only the second warrants the quarantine path. Same rule as
// state_corruption.go's, expressed as a sentinel so the caller need not
// re-classify the error.
var ErrRevocationsCorrupt = errors.New("session: revocations file corrupt")

// ErrRevocationsUnread is returned by SaveRevocations while this boot could not
// READ the revocations file. Nothing is written.
//
// It is NOT a persistence failure and must not be counted as one: no write was
// attempted, the volume may be perfectly healthy, and the condition is already
// reported by the load-degraded branch of the session_revocation row. Routing
// it through the persist observers would replace that row's remedy (fix the
// permission or the mount and restart) with "check free space" — the wrong
// investigation, which is the defect class AU-36 closed one layer up.
var ErrRevocationsUnread = errors.New("session: revocations file was not read this boot; refusing to overwrite it")

// ErrRevocationsUnquarantined is returned by SaveRevocations when the
// revocations file was read, failed to parse, and could NOT be renamed aside.
//
// quarantineCorruptStateFile's own failure message says "the next save WILL
// OVERWRITE it" — that warning was the product's only mitigation, and it is a
// warning to a human who may never read it. The corrupt bytes at the target
// path are the only copy of whatever revocations the node was enforcing, so
// this refuses the save instead.
//
// It is DISTINCT from ErrRevocationsUnread because the remedies differ: an
// unread file needs a permission or mount repair, while this one needs the
// operator to copy the file elsewhere (its name is too long to rename, the
// directory is read-only, and so on) before the node can persist again.
var ErrRevocationsUnquarantined = errors.New("session: the corrupt revocations file could not be quarantined; refusing to overwrite the only copy")

// IsWriteFenced reports whether err is a refusal to write rather than a
// failed write. Callers MUST ask this rather than testing one sentinel: a
// refusal is not a persistence failure, and a call site that recognises only
// one reason will count the other as a failing volume and send the operator
// after free space (the AU-36 defect, one layer down).
func IsWriteFenced(err error) bool {
	return errors.Is(err, ErrRevocationsUnread) || errors.Is(err, ErrRevocationsUnquarantined)
}

// WriteFenced reports whether saves are currently refused (either reason; see
// SaveRevocations). While fenced, a missing backing file is EXPECTED — the
// operator may have moved the unreadable or corrupt original aside — and no
// save can recreate it, so callers must not treat its absence as a repairable
// durability doubt.
func (r *RevocationList) WriteFenced() bool {
	return r.writeFence.Load() != fenceNone
}

// FenceWritesUnquarantined refuses every later save because a corrupt file
// could not be moved aside. Called by the boot path when
// quarantineCorruptStateFile reports that its rename failed.
func (r *RevocationList) FenceWritesUnquarantined() {
	r.writeFence.Store(fenceUnquarantined)
}

// persistFailureObserver is notified whenever a revocation could not be made
// durable. Installed by package main beside the metrics/health plane.
//
// The seam exists because the failure is otherwise INVISIBLE in the direction
// that matters: SaveRevocations' error is logged by its callers and the admin
// action (a logout, an account deletion) still reports success, so the operator
// is told the session was withdrawn while the only durable record of that
// withdrawal does not exist. The observer must not itself revoke or persist.
var (
	persistObserverMu sync.RWMutex
	persistObserver   func(err error)
	persistOKObserver func()
)

// SetPersistFailureObserver installs the durability-failure callback (nil clears).
func SetPersistFailureObserver(fn func(err error)) {
	persistObserverMu.Lock()
	persistObserver = fn
	persistObserverMu.Unlock()
}

// SetPersistSuccessObserver installs the durability-RECOVERY callback (nil clears).
//
// It exists for the same reason `ca.RotationPersistSuccessObserver` does: a
// health surface keyed on a CUMULATIVE failure counter can never recover, so it
// keeps reporting a security-control failure after the operator has fixed the
// volume, until the process restarts. The counter is the right instrument for
// magnitude and the wrong one for state.
//
// A successful save is a genuine recovery here, not merely a fresh write:
// SaveRevocations persists the COMPLETE live list, so once one succeeds every
// revocation still in memory is durable again.
func SetPersistSuccessObserver(fn func()) {
	persistObserverMu.Lock()
	persistOKObserver = fn
	persistObserverMu.Unlock()
}

// callObserver runs fn with panics contained: a panicking observer must never
// take down the admin plane it is reporting on (the internal/audit rule).
func callObserver(fn func()) {
	if fn == nil {
		return
	}
	defer func() { _ = recover() }()
	fn()
}

func notePersistFailure(err error) error {
	persistObserverMu.RLock()
	fn := persistObserver
	persistObserverMu.RUnlock()
	if fn == nil {
		return err
	}
	// Wrapping in a closure would hide a nil fn from callObserver's guard (the
	// closure is non-nil regardless), leaving the nil call to be swallowed by
	// the recover — so the nil check is here, where fn is in scope.
	callObserver(func() { fn(err) })
	return err
}

func notePersistSuccess() {
	persistObserverMu.RLock()
	fn := persistOKObserver
	persistObserverMu.RUnlock()
	callObserver(fn)
}

// saveMu serializes the WHOLE save — snapshot, marshal and write — for every
// caller.
//
// r.mu is released when exportPersisted returns, so without this two writers
// (a logout request goroutine and the DP's 3 s revocation-sync loop) can each
// snapshot and then race to AtomicWrite: the rename that lands LAST wins, and
// it may carry the OLDER snapshot. The file then silently lacks a revocation
// that is still live in memory, and a restart inside that window resurrects
// the session (CodeRabbit, PR #1591).
//
// Serializing here rather than at one call site is deliberate: a lock around
// a single caller is no protection while another writer calls SaveRevocations
// directly. Holding it across the write is safe for the request path because
// it is NOT r.mu — IsRevoked, and therefore authentication, never waits on it.
var saveMu sync.Mutex

// SaveRevocations writes all non-expired revocations to disk as JSON.
//
// Every failure path is routed through notePersistFailure, so "the revocation
// is not durable" is a countable event rather than one log line at a call site
// that returns 200 regardless.
//
// The whole save is serialized by saveMu; see its comment for why.
func (r *RevocationList) SaveRevocations() error {
	path := RevocationsPath()
	if path == "" {
		// Not a failure: persistence is opt-in via --revocations-file. The
		// resulting posture (no revocation survives a restart, by
		// configuration) is reported by the health plane, not here.
		return nil
	}
	// Refuse BEFORE taking saveMu and before any I/O: there is nothing to
	// serialise, and a caller must not be delayed by other savers to be told
	// that nothing will be written (AU-37/AU-38).
	switch r.writeFence.Load() {
	case fenceUnread:
		return ErrRevocationsUnread
	case fenceUnquarantined:
		return ErrRevocationsUnquarantined
	}
	saveMu.Lock()
	defer saveMu.Unlock()
	// Snapshot INSIDE the lock, so the write that lands last is the one whose
	// snapshot was taken last. Before CHAOS-73's saveMu, export → marshal →
	// AtomicWrite were three independently-atomic steps that were jointly not:
	// two concurrent savers could interleave so the OLDER snapshot renamed
	// last, and the file lost a revocation both callers were told had been
	// applied (reported independently by Codex on PR #1437 as a P1 and by
	// CodeRabbit on PR #1591). SaveRevocations has several callers, three of
	// them background loops (the CP SyncRevocations handler, the DP sync loop,
	// the HA bundle apply) that run concurrently with an admin's delete.
	entries := r.exportPersisted()
	data, err := json.Marshal(entries)
	if err != nil {
		return notePersistFailure(fmt.Errorf("marshal revocations: %w", err))
	}
	// AtomicWrite (unique temp + fsync): a torn or power-loss-reverted
	// revocation file would resurrect revoked session cookies until their
	// natural expiry.
	if err := fileutil.AtomicWrite(path, data, 0o600); err != nil {
		return notePersistFailure(err)
	}
	// Only a real write counts as recovery. The `path == ""` early return above
	// deliberately does NOT reach here: nothing was written, so it must not
	// clear a durability degradation.
	notePersistSuccess()
	return nil
}

// probePersistPath PROVES the configured path is writable, by writing to it,
// and drives the persist observers so every durability surface reflects the
// answer at BOOT rather than at some later operator action.
//
// SaveRevocations writes the COMPLETE live list (ExportRevocations), so this is
// never a partial or synthetic write: on the absent-file branch it creates the
// file with the current list, and on the loaded branch it rewrites the superset
// that was just merged. AtomicWrite renames a fully-written temp file into
// place, so a failure leaves whatever was already on disk untouched — proving
// writability cannot cost the content being proved about.
//
// It is called from BOTH branches that reach a durable-looking posture, and
// from NEITHER branch that does not, which is the whole point:
//
//   - file ABSENT      → probe. Nothing to lose, and "not there yet" is not
//     the same claim as "the path works".
//   - file LOADED      → probe. The in-memory list is now a superset of the
//     file, so rewriting it is safe — and this is the case the first version
//     of this fix missed (Codex P2, PR #1437): an existing, perfectly
//     parseable file on a mount that has since gone read-only took the success
//     path, never attempted a write, and reported durable across diagnostics,
//     metrics and the cluster API until the first real logout failed.
//   - file UNREADABLE  → do NOT probe. The content may be intact behind a
//     transient fault, and a write attempt is the one action that could
//     destroy it. state_corruption.go's own rule: moving (or here, rewriting)
//     a healthy security-critical file is the worse error.
//   - file CORRUPT     → do NOT probe. The caller quarantines it, and writing
//     first would overwrite the evidence.
//
// The error is deliberately not returned. "Could not read" and "cannot write"
// are separate states (LoadDegraded vs the persist-degraded flag) and
// conflating them would report a corrupt-file remedy for a permissions fault.
func (r *RevocationList) probePersistPath() {
	if err := r.SaveRevocations(); err != nil {
		obs.Printf("Session: revocations path is not writable: %v", err)
	}
}

// LoadRevocations reads revocations from disk and merges them.
func (r *RevocationList) LoadRevocations() error {
	path := RevocationsPath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// An ABSENT file is a legitimate first run, but "the file is not
			// there yet" and "the path works" are different claims, and the
			// health plane reports the second one. Configured is already true
			// at this point, so returning here made revocationsAreDurable say
			// a revocation would survive a restart while the parent directory
			// was missing, read-only or unwritable — green on the cluster API,
			// on /api/diagnostics and on the metric, until some operator's
			// logout hours later became the first thing to discover the path
			// was bad. The unearned green is the defect, not the missing file
			// (Codex P2, PR #1437).
			r.probePersistPath()
			return nil
		}
		// Could not READ it. The file stays where it is, and from here on
		// SaveRevocations refuses rather than renaming over content this
		// process never saw. Cleared only by a load that actually succeeds,
		// which in practice means a restart after the fault is repaired.
		r.writeFence.Store(fenceUnread)
		return fmt.Errorf("read revocations: %w", err)
	}
	var entries []RevocationEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		// Read fine, parsed not at all: corrupt. Wrapped in the sentinel so the
		// caller quarantines instead of silently booting with an EMPTY list —
		// which is the fail-OPEN direction for this particular file, since
		// every revocation it held is resurrected for the rest of its TTL.
		// Deliberately returns BEFORE the probe: writing here would overwrite
		// the evidence the quarantine exists to preserve.
		return fmt.Errorf("%w: %v", ErrRevocationsCorrupt, err)
	}
	if entries == nil {
		// Parsed fine, and still not a revocation document: the top-level value
		// was the JSON literal `null`. encoding/json accepts it into a slice
		// WITHOUT error and leaves the slice nil, so it used to take the loaded
		// branch below — merging nothing, reporting durable, and then letting
		// probePersistPath rewrite the file as `[]`. That is the same silent
		// acceptance this sweep exists to close (defect 4), one shape over, and
		// the boot probe made it worse: before it, the anomaly survived on disk
		// until some later logout overwrote it and an operator could still see
		// it; now boot erases it every time.
		//
		// `entries == nil` is an EXACT discriminator here and not a heuristic:
		// after a successful unmarshal into a slice, only `null` leaves it nil.
		// An empty array yields a non-nil zero-length slice, and every other
		// top-level value (object, string, number, empty file) already failed
		// above with a type or syntax error.
		//
		// Quarantining is safe because this code cannot produce `null`:
		// ExportRevocations has allocated with make([]RevocationEntry, 0, …)
		// since it first landed (dc3921a), so an empty list is written as `[]`.
		// A `null` file therefore never came from a Culvert binary, and no
		// appliance's own file can be quarantined by this branch.
		//
		// Entry-level validation is deliberately NOT done here. Rejecting the
		// whole document over one malformed entry quarantines it, and a
		// quarantine boots with an EMPTY list — so it would drop every GOOD
		// revocation in that file to punish a bad one, which is the fail-OPEN
		// direction this file must never err in. The one entry shape that could
		// be argued for, an empty Token, is inert: it lands as tokens[""], which
		// matches no real cookie payload, and it cannot collide in
		// MergedExcluding's Token-keyed dedup with a user revocation, because
		// those always carry the `user:` prefix (the §38 constraint 2 hazard is
		// an empty token STANDING IN FOR a user entry, which ExportRevocations
		// cannot emit). It expires on its own.
		//
		// Reported by Codex on PR #1437 as a P1.
		return fmt.Errorf("%w: top-level value is null, not an array", ErrRevocationsCorrupt)
	}
	added := r.mergeUntrusted(entries, true)
	if added > 0 {
		obs.Printf("Session: loaded %d revocations from disk", added)
	}
	// A file that EXISTS and parses proves the path is readable and says
	// nothing about whether it is writable — a mount remounted read-only after
	// an I/O error, a volume restored read-only, a directory whose permissions
	// changed. That posture reported durable everywhere until the first logout
	// failed, which is the same unearned green as the absent-file branch, one
	// branch over. Prove it here too (Codex P2, second round, PR #1437).
	r.probePersistPath()
	return nil
}

// ---------------------------------------------------------------------------
// Session TTL
// ---------------------------------------------------------------------------

// ttl is the lifetime of admin UI sessions.
// Configurable at runtime via /api/session-timeout; default 8 hours.
var (
	ttl   = 8 * time.Hour
	ttlMu sync.RWMutex
)

// TTL returns the current session lifetime.
func TTL() time.Duration {
	ttlMu.RLock()
	defer ttlMu.RUnlock()
	return ttl
}

// MaxSessionLifetime is the longest session TTL SetTTL admits. No session
// this appliance issues can expire later than issue time plus this.
const MaxSessionLifetime = 7 * 24 * time.Hour

// SetTTL updates the session lifetime. Clamped to [15min, MaxSessionLifetime].
func SetTTL(d time.Duration) {
	const minTTL = 15 * time.Minute
	if d < minTTL {
		d = minTTL
	}
	if d > MaxSessionLifetime {
		d = MaxSessionLifetime
	}
	ttlMu.Lock()
	ttl = d
	ttlMu.Unlock()
}

// ---------------------------------------------------------------------------
// Session type
// ---------------------------------------------------------------------------

// Session is the payload stored inside the signed proxy session cookie.
// It carries just enough identity data to reconstruct an Identity object
// without talking to the IdP on every request. (The Session→Identity
// conversion lives in package main — Identity is a main hub type.)
type Session struct {
	Sub      string   `json:"sub"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Groups   []string `json:"grp,omitempty"`
	Provider string   `json:"pvd"`
	Role     string   `json:"role,omitempty"` // UI admin role: admin|operator|viewer
	Exp      int64    `json:"exp"`            // Unix timestamp
	// Jti is a 128-bit random session identifier (hex-encoded). Added in
	// Phase C5.1 to make the JSON payload unique per login even when two
	// logins for the same user happen in the same wall-clock second —
	// without Jti the (Sub, Role, Exp-in-seconds) tuple yielded a
	// byte-identical payload, identical b64, identical HMAC, and an
	// effectively-revoked cookie if any prior login of that tuple had
	// been revoked. omitempty keeps legacy cookies (issued before C5.1)
	// decoding cleanly: their Jti unmarshals to "" and the field is
	// simply absent on the wire.
	Jti string `json:"jti,omitempty"`
	// Iat is the Unix second the cookie was minted (AU-65). Package main
	// compares it with the asserting profile's SessionsNotBefore cutoff, so
	// re-enabling or re-creating an IdP under the same id does not revive
	// the sessions it minted before the cut. omitempty for the same reason
	// as Jti: a cookie minted before the field existed decodes to 0 and is
	// admitted only by a profile that carries no cutoff, and an older binary
	// ignores the key (json.Unmarshal drops unknown fields; the MAC covers
	// the encoded payload, not the struct).
	Iat int64 `json:"iat,omitempty"`
}

// ---------------------------------------------------------------------------
// Token encoding / decoding
// ---------------------------------------------------------------------------

// Encode serialises session data, signs it with HMAC-SHA256, and returns a
// cookie-safe string: base64(json).HMAC.
func Encode(s *Session) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + mac(b64), nil
}

// Decode parses and verifies a session cookie value.
// Returns an error when the signature is invalid, the session has expired,
// or the token/user has been revoked.
func Decode(raw string) (*Session, error) {
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		return nil, fmt.Errorf("session: malformed cookie")
	}
	b64, sig := raw[:dot], raw[dot+1:]

	// Constant-time MAC comparison. macEqual is the allocation-free form of
	// hmac.Equal([]byte(sig), []byte(mac(b64))) and decides identically.
	if !macEqual(b64, sig) {
		return nil, fmt.Errorf("session: invalid signature")
	}

	// Revocation check (explicit logout).
	if Revoked.IsRevoked(b64) {
		return nil, fmt.Errorf("session: revoked")
	}

	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("session: base64 decode: %w", err)
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, fmt.Errorf("session: json decode: %w", err)
	}
	if time.Now().Unix() > s.Exp {
		return nil, fmt.Errorf("session: expired")
	}
	// User-level revocation (account deleted while session was active).
	if s.Sub != "" && Revoked.IsUserRevoked(s.Sub) {
		return nil, fmt.Errorf("session: user revoked")
	}
	return &s, nil
}

// MAC computes the base64url HMAC-SHA256 of data under the current signing
// key. Exported for tests that hand-craft legacy-shaped tokens.
func MAC(data string) string { return mac(data) }

// ---------------------------------------------------------------------------
// MAC engine — reusable HMAC-SHA256 state for the per-request verify path
// ---------------------------------------------------------------------------
//
// Decode runs on the PROXY authentication hot path, not just the admin UI: the
// signed session cookie is the first credential arm resolveRequestAuth tries,
// so every authenticated proxied request verifies one MAC (proxy.go, arm 1 of
// the adaptive-auth chain).
//
// Building the HMAC state, not hashing the 250-odd bytes of payload, dominated
// that step. crypto/hmac.New costs five allocations — the HMAC struct, the ipad
// and opad blocks, and an inner and an outer sha256.Digest — and the old form
// paid them per request, plus a copy of the payload for Write, a digest for
// Sum(nil), two for EncodeToString, and two more for the []byte conversions
// hmac.Equal needed. Measured on this box (Go 1.26, linux/amd64, 4-core Xeon
// @ 2.80GHz) with a representative cookie: mac alone 9 allocs / 896 B of the
// 26 allocs / 1632 B that one Decode spent, and 2.38 µs of its 6.12 µs.
//
// HMAC state is explicitly reusable — Reset re-primes the inner hash with ipad
// — so it is built ONCE per signing key and recycled through a pool, and the
// digest is summed and encoded through inline buffers so the verify path can
// compare bytes without ever materialising the expected signature as a string.
// The hashing itself is untouched: same key, same two block compressions, same
// base64url alphabet, byte-identical output.

// macEncodedLen is base64.RawURLEncoding.EncodedLen(sha256.Size): the exact
// wire length of the signature half of every session cookie.
const macEncodedLen = 43

// macScratchLen bounds the payload a pooled state copies into its inline
// buffer instead of converting. A payload is base64(JSON) over a handful of
// short identity fields; 512 bytes covers every token this package issues with
// room for a large group list, and a longer one still verifies correctly, just
// with one allocation. The buffer is an inline ARRAY rather than a grown slice
// so a pooled state can never retain an oversized allocation — the failure
// mode the hostutil IDNA memo hit.
const macScratchLen = 512

// macState is one reusable HMAC-SHA256 computation, pooled per signing key.
type macState struct {
	h     hash.Hash
	msg   [macScratchLen]byte
	sum   [sha256.Size]byte
	coded [macEncodedLen]byte
	given [macEncodedLen]byte
}

// compute writes the base64url HMAC-SHA256 of data into s.coded and returns
// that slice. The result ALIASES s and is valid only until the state goes back
// to its pool, so callers copy (or compare) before releasing it.
func (s *macState) compute(data string) []byte {
	s.h.Reset()
	// hash.Hash.Write never reports an error; the blank assignment is the
	// convention for that, not a suppressed failure.
	if len(data) <= len(s.msg) {
		n := copy(s.msg[:], data)
		_, _ = s.h.Write(s.msg[:n])
	} else {
		_, _ = s.h.Write([]byte(data)) // oversized payload: one conversion
	}
	base64.RawURLEncoding.Encode(s.coded[:], s.h.Sum(s.sum[:0]))
	return s.coded[:]
}

// macEngine binds one signing key to a pool of states primed with that key.
type macEngine struct {
	key  []byte
	pool sync.Pool // *macState
}

func newMacEngine(key []byte) *macEngine {
	// The engine owns a COPY. Every state it mints later must be primed with
	// the same bytes as the ones already pooled, and the old per-call form
	// re-read the key on every MAC, so without the copy a mutation after
	// install would leave the pool holding two different keys at once.
	// SetSigningKey now hands over a slice this package already owns, so this
	// is belt-and-braces there — it keeps the invariant true for any future
	// caller of newMacEngine rather than resting on the funnel's discipline.
	e := &macEngine{key: append([]byte(nil), key...)}
	e.pool.New = func() any { return &macState{h: hmac.New(sha256.New, e.key)} }
	return e
}

// macEngines publishes the engine for the CURRENT signing key. Holding it
// outside signingKeyMu is deliberate and load-bearing twice over: the verify
// path reads the key binding with one atomic load instead of taking an RWMutex
// per request, and a request still holding a state from a SUPERSEDED engine
// returns it to THAT engine's pool — unreferenced the moment the straggler
// lets go — so a state primed with the old key can never be handed to a caller
// signing under the new one. The DP config-sync path replaces the key at
// runtime while requests are in flight, which is exactly that race.
//
// The key is bound at install time rather than re-read per call, so both the
// stored key and the engine are copies this package owns (see SetSigningKey and
// newMacEngine) and SigningKey keeps handing readers theirs. No slice a caller
// still holds backs the stored key or a live HMAC state, so the two can never
// drift apart.
var macEngines atomic.Pointer[macEngine]

func init() { macEngines.Store(newMacEngine(nil)) }

// mac returns the base64url HMAC-SHA256 of data under the current signing key.
// Used by Encode (once per login) and by the exported MAC test helper; the
// per-request verify path uses macEqual instead and allocates nothing.
func mac(data string) string {
	e := macEngines.Load()
	s := e.pool.Get().(*macState)
	out := string(s.compute(data))
	e.pool.Put(s)
	return out
}

// macEqual reports whether sig is the base64url HMAC-SHA256 of data under the
// current signing key, compared in constant time.
//
// Exactly equivalent to hmac.Equal([]byte(sig), []byte(mac(data))), including
// the length-mismatch rejection: crypto/subtle.ConstantTimeCompare, which
// hmac.Equal is, also decides unequal lengths before comparing any byte. The
// equivalence is pinned by a differential test and a fuzz target against a
// verbatim copy of the old form (session_mac_test.go).
func macEqual(data, sig string) bool {
	e := macEngines.Load()
	s := e.pool.Get().(*macState)
	want := s.compute(data)
	ok := len(sig) == len(want)
	if ok {
		n := copy(s.given[:], sig)
		ok = subtle.ConstantTimeCompare(s.given[:n], want) == 1
	}
	e.pool.Put(s)
	return ok
}
