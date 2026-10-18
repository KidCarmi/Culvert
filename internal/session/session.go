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

// RevocationEntry is a single revoked session token for gRPC gossip.
type RevocationEntry struct {
	Token  string `json:"token"`
	Expiry int64  `json:"expiry"` // Unix timestamp
}

// ExportRevocations returns all non-expired revocation entries for syncing.
func (r *RevocationList) ExportRevocations() []RevocationEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	entries := make([]RevocationEntry, 0, len(r.tokens))
	for tok, exp := range r.tokens {
		if now.After(exp) {
			delete(r.tokens, tok)
			continue
		}
		entries = append(entries, RevocationEntry{Token: tok, Expiry: exp.Unix()})
	}
	return entries
}

// MergeRevocations imports remote revocation entries (from other cluster nodes).
// Only adds entries that are not yet expired and not already present.
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
		if _, exists := r.tokens[e.Token]; !exists {
			r.tokens[e.Token] = exp
			added++
		}
	}
	return added
}

// Count returns the number of active revoked sessions.
func (r *RevocationList) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tokens)
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

// SaveRevocations writes all non-expired revocations to disk as JSON.
func (r *RevocationList) SaveRevocations() error {
	path := RevocationsPath()
	if path == "" {
		return nil
	}
	entries := r.ExportRevocations()
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal revocations: %w", err)
	}
	// AtomicWrite (unique temp + fsync): a torn or power-loss-reverted
	// revocation file would resurrect revoked session cookies until their
	// natural expiry.
	return fileutil.AtomicWrite(path, data, 0o600)
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
			return nil
		}
		return fmt.Errorf("read revocations: %w", err)
	}
	var entries []RevocationEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("unmarshal revocations: %w", err)
	}
	added := r.MergeRevocations(entries)
	if added > 0 {
		obs.Printf("Session: loaded %d revocations from disk", added)
	}
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
