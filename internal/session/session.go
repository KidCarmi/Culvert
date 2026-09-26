// Package session implements Culvert's HMAC-SHA256-signed session tokens and
// the revocation machinery behind them (ADR-0002 extraction; engine was
// session.go in package main).
//
// The package owns: the signing key (with synchronized access — the key is
// written at runtime by the cluster snapshot sync while the MAC path reads it
// concurrently), token encode/decode (base64(json).HMAC), the revocation list
// (token- and user-level, with lazy expiry eviction, gossip export/merge, and
// optional disk persistence), the session TTL, and jti generation.
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
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
	signingKey = key
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

	// saveMu serializes SaveRevocations end to end: snapshot THROUGH rename.
	//
	// It is a SECOND mutex rather than a wider hold of mu, and that is
	// deliberate. mu guards the maps every enforcement decision reads
	// (IsRevoked runs on the admin path) and every revocation writes, so
	// holding it across a marshal and an fsync would let a slow or full volume
	// delay the act of revoking — making a durability mechanism cost
	// availability of the security control it exists to protect. saveMu blocks
	// only other SAVERS.
	//
	// Lock order is saveMu → mu, and mu is never held while taking saveMu.
	saveMu sync.Mutex
}

// NewRevocationList returns an empty list (used by tests to swap the
// package singleton, mirroring the bl pointer-swap idiom).
func NewRevocationList() *RevocationList {
	return &RevocationList{
		tokens: map[string]time.Time{},
		users:  map[string]time.Time{},
	}
}

// Revoked is the process-wide revocation list consulted by Decode.
var Revoked = NewRevocationList()

// Revoke marks a token (its b64 payload) as revoked until exp.
func (r *RevocationList) Revoke(token string, exp time.Time) {
	r.mu.Lock()
	r.tokens[token] = exp
	r.mu.Unlock()
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
	if time.Now().After(exp) {
		delete(r.tokens, token) // lazy eviction
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
	if time.Now().After(exp) {
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
// User is `omitempty` and Token is always populated, so the document stays a
// JSON array that a binary predating CHAOS-68 parses without error. That
// downgrade compatibility is deliberate: promoting the file to an object would
// make an older binary fail the whole parse and lose the TOKEN revocations it
// does understand — trading a gap for a regression.
type RevocationEntry struct {
	Token  string `json:"token"`
	Expiry int64  `json:"expiry"` // Unix timestamp
	// User, when non-empty, makes this a user-level revocation.
	User string `json:"user,omitempty"`
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
	entries := make([]RevocationEntry, 0, len(r.tokens)+len(r.users))
	for tok, exp := range r.tokens {
		if now.After(exp) {
			delete(r.tokens, tok)
			continue
		}
		entries = append(entries, RevocationEntry{Token: tok, Expiry: exp.Unix()})
	}
	for user, exp := range r.users {
		if now.After(exp) {
			delete(r.users, user)
			continue
		}
		entries = append(entries, RevocationEntry{
			Token:  userRevocationTokenPrefix + user,
			Expiry: exp.Unix(),
			User:   user,
		})
	}
	return entries
}

// MergeRevocations imports remote revocation entries (from other cluster nodes,
// or from the persisted file at boot). Only adds entries that are not yet
// expired and not already present. Returns how many entries were newly applied.
//
// An entry is classified as a USER revocation when it carries an explicit User
// field, OR when its Token carries userRevocationTokenPrefix. The second form
// only arises when the entry has passed through a node predating CHAOS-68,
// which drops the unknown `user` JSON field but preserves the token verbatim;
// recovering the username from the prefix means one hop through an old node
// degrades nothing. A token that merely LOOKS like a user entry cannot be a
// real cookie payload (see userRevocationTokenPrefix), so this classification
// can never swallow a genuine token revocation.
func (r *RevocationList) MergeRevocations(entries []RevocationEntry) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	added := 0
	for _, e := range entries {
		exp := time.Unix(e.Expiry, 0)
		if now.After(exp) {
			continue // already expired
		}
		user := e.User
		if user == "" {
			user = strings.TrimPrefix(e.Token, userRevocationTokenPrefix)
			if user == e.Token {
				user = "" // no prefix — an ordinary token revocation
			}
		}
		if user != "" {
			// Keep the LATER expiry: a re-delete of the same username extends
			// the window, and taking the earlier one would shorten a revocation
			// on a gossip round trip.
			if cur, exists := r.users[user]; !exists || exp.After(cur) {
				r.users[user] = exp
				added++
			}
			continue
		}
		if _, exists := r.tokens[e.Token]; !exists {
			r.tokens[e.Token] = exp
			added++
		}
	}
	return added
}

// Count returns the number of active revoked session TOKENS.
func (r *RevocationList) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return pruneExpiredLocked(r.tokens)
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
	return pruneExpiredLocked(r.users)
}

// pruneExpiredLocked drops every entry whose expiry has passed and returns how
// many remain. The caller must hold r.mu.
//
// Counting live entries rather than map length is not cosmetic. Expiry in this
// list is otherwise LAZY — IsRevoked drops an entry only when something asks
// about that exact token, and ExportRevocations drops them only when something
// persists or gossips — so on a standalone node with persistence off and no
// cluster peer, nothing ever asks, and an expired revocation sits in the map for
// the life of the process. Both counts feed gauges whose HELP text says
// "currently in force" and the /api/cluster/revocations surface, so an expired
// entry reported there is a WRONG answer, not merely a stale one: it tells an
// operator that sessions are still being denied when they are not.
//
// Pruning rather than skipping also bounds the map on exactly that node, which
// is the one where nothing else would ever collect it.
//
// Reported by Codex on PR #1437 as a P2.
func pruneExpiredLocked(m map[string]time.Time) int {
	now := time.Now()
	for k, exp := range m {
		if now.After(exp) {
			delete(m, k)
		}
	}
	return len(m)
}

// SwapForTest replaces the list's maps with empty ones and returns a restore
// function. Mirrors the snapshot/restore pattern documented in CLAUDE.md for
// tests that touch shared revocation state.
func (r *RevocationList) SwapForTest() (restore func()) {
	r.mu.Lock()
	prevTokens, prevUsers := r.tokens, r.users
	r.tokens = map[string]time.Time{}
	r.users = map[string]time.Time{}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		r.tokens = prevTokens
		r.users = prevUsers
		r.mu.Unlock()
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

// SaveRevocations writes all non-expired revocations to disk as JSON.
//
// Every failure path is routed through notePersistFailure, so "the revocation
// is not durable" is a countable event rather than one log line at a call site
// that returns 200 regardless.
func (r *RevocationList) SaveRevocations() error {
	path := RevocationsPath()
	if path == "" {
		// Not a failure: persistence is opt-in via --revocations-file. The
		// resulting posture (no revocation survives a restart, by
		// configuration) is reported by the health plane, not here.
		return nil
	}
	// Snapshot THROUGH rename under one lock. ExportRevocations takes and
	// releases mu on its own, so without this the sequence
	// export → marshal → AtomicWrite is three independently-atomic steps that
	// are jointly not: two concurrent savers can interleave so the one holding
	// the OLDER snapshot renames last, and the file loses a revocation both
	// callers were told had been applied. Nothing detects it — both return nil,
	// both count as a successful write, and the durability row stays green —
	// until a restart resurrects the session. That is the defect class this
	// whole sweep exists to close, and this function had it: before this change
	// SaveRevocations had ONE caller, and it now has five, three of them in
	// background loops (the CP SyncRevocations handler, the DP sync loop, the HA
	// bundle apply) that run concurrently with an admin's delete.
	//
	// Reported by Codex on PR #1437 as a P1.
	r.saveMu.Lock()
	defer r.saveMu.Unlock()

	entries := r.ExportRevocations()
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
	added := r.MergeRevocations(entries)
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

// SetTTL updates the session lifetime. Clamped to [15min, 7d].
func SetTTL(d time.Duration) {
	const minTTL = 15 * time.Minute
	const maxTTL = 7 * 24 * time.Hour
	if d < minTTL {
		d = minTTL
	}
	if d > maxTTL {
		d = maxTTL
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

	// Constant-time MAC comparison.
	expected := mac(b64)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
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

func mac(data string) string {
	signingKeyMu.RLock()
	key := signingKey
	signingKeyMu.RUnlock()
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
