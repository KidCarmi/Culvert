package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// ─── Uptime ───────────────────────────────────────────────────────────────────

var startTime = time.Now()

// ─── Stats ────────────────────────────────────────────────────────────────────

var (
	statTotal       int64
	statBlocked     int64
	statAuthFail    int64
	statFileBlocked int64 // requests blocked by the file-extension profile
	statBytesSent   int64 // total bytes sent upstream (request bodies)
	statBytesRecv   int64 // total bytes received from upstream (response bodies)
	statAuthExempt  int64 // Stage-1 Exempt decisions (Phase 1 Slice 5: defined, NOT incremented from runtime yet)

	statAuthCredentialRequired int64 // Stage-1 CredentialRequired decisions (Phase 2 Slice 3: wired onto the runtime path)

	statAuthSSORequired int64 // Stage-1 SSORequired decisions (Phase 3 Slice 3: defined, NOT incremented from runtime yet)

	// Decryption-profile success-delta observability: which HTTP protocol the
	// inspected tunnel negotiated on the UPSTREAM (origin) leg. h2 counts native
	// HTTP/2 inspection (the profile working); http/1.1 counts the strip/downgrade
	// path. The ratio is how an operator confirms enabling Inspect-as-HTTP/2 changed
	// the negotiated protocol per destination.
	statInspectUpstreamH2 int64
	statInspectUpstreamH1 int64
)

// ─── Time-series: requests per minute, last 60 minutes ───────────────────────

// timeSeries deliberately keeps a plain mutex: an RLock+atomic fast path was
// benchmarked (2026-07) and measured FLAT under parallelism — every request
// increments the same current-minute bucket, so the shared cache line, not
// the lock, is the bound. See store_stats_bench_test.go.
type timeSeries struct {
	mu      sync.Mutex
	buckets [60]int64
	allowed [60]int64
	blocked [60]int64
	cur     int
	lastMin int64
}

var ts = &timeSeries{}

func tsAdvance() {
	now := time.Now().Unix() / 60
	if ts.lastMin == 0 {
		ts.lastMin = now
	}
	diff := now - ts.lastMin
	if diff > 0 {
		if diff > 60 {
			diff = 60
		}
		for i := int64(0); i < diff; i++ {
			ts.cur = (ts.cur + 1) % 60
			ts.buckets[ts.cur] = 0
			ts.allowed[ts.cur] = 0
			ts.blocked[ts.cur] = 0
		}
		ts.lastMin = now
	}
}

func tsRecord() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	tsAdvance()
	ts.buckets[ts.cur]++
}

func tsRecordResult(isAllowed bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	tsAdvance()
	ts.buckets[ts.cur]++
	if isAllowed {
		ts.allowed[ts.cur]++
	} else {
		ts.blocked[ts.cur]++
	}
}

func tsGet() (total, allowed, blocked []int64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	total = make([]int64, 60)
	allowed = make([]int64, 60)
	blocked = make([]int64, 60)
	for i := 0; i < 60; i++ {
		idx := (ts.cur - i + 60) % 60
		total[59-i] = ts.buckets[idx]
		allowed[59-i] = ts.allowed[idx]
		blocked[59-i] = ts.blocked[idx]
	}
	return
}

// ─── Request log ──────────────────────────────────────────────────────────────

// LogEntry moved to internal/logstore (logstore.Entry) with the history-store
// extraction (ADR-0002); the alias in logstore.go keeps every unqualified use
// — ring, JSONL writer, SSE feed, SIEM fields — source-compatible.

// AuthLogFields carries the low-cardinality Stage-1 authentication-policy
// observability fields attached to a request log entry. The zero value adds
// nothing to the wire output (every target field is omitempty). It deliberately
// carries NO identity — see the LogEntry auth_* contract above. Populate it only
// from an actual auth decision (authLogFieldsFor); existing recordRequest call
// sites pass the zero value implicitly and stay byte-identical.
type AuthLogFields struct {
	Outcome           AuthOutcome
	PolicyRuleID      string
	PolicyRuleName    string
	SubjectMatchTypes []string
	SchemaVersion     int
	// RuleID is the ULID of the matched FORWARD-PROXY policy rule (distinct
	// from the Stage-1 auth PolicyRuleID above) — the §1 rename-safe
	// decision-attribution seam. Rides this structured-fields carrier so the
	// hot-path recorders need no new positional param. Maps to LogEntry.RuleID.
	RuleID string
	// Dec is the ADR-0011 decryption-observability block, riding the same
	// structured carrier as RuleID so the tunnel-close recorders need no new
	// positional param. nil on every path that made no decryption decision
	// (the wire stays byte-identical); populated only on the CONNECT decision
	// path. Maps to LogEntry.Dec.
	Dec *DecryptionBlock
	// AuthSource is the categorical authentication source that produced this
	// request's identity context (F5): "local" | "exempt" | "unauth" | an IdP
	// profile source ("oidc:<id>" / "saml:<id>" / bare profile ID from
	// identityAuthSource). Populated ONLY from the server-side resolved auth
	// state (resolveRequestAuth's source / ProxyIdentity.AuthSource) — never
	// from any client-supplied header or request field (F6 removed the internal
	// X-User-Identity transport entirely; identity travels as typed values).
	// Empty on rows with no auth context (pre-auth blocks like
	// IP_BLOCKED/RATE_LIMITED, AUTH_FAIL where no backend authenticated the
	// credentials, and SOCKS5's boolean auth) — empty means "unattributed",
	// never "unauthenticated" (that is "unauth").
	// Maps to LogEntry.AuthSource (omitempty ⇒ wire byte-identical when empty).
	AuthSource string
}

// applyTo copies the auth observability fields onto a log entry. It never touches
// Identity (Exempt is logged by outcome + rule id/name only).
func (a AuthLogFields) applyTo(e *LogEntry) {
	e.AuthOutcome = string(a.Outcome)
	e.AuthPolicyRuleID = a.PolicyRuleID
	e.AuthPolicyRuleName = a.PolicyRuleName
	e.AuthSubjectMatchTypes = a.SubjectMatchTypes
	e.AuthSchemaVersion = a.SchemaVersion
	e.RuleID = a.RuleID
	e.Dec = a.Dec // nil ⇒ no dec block (byte-identical); set only on the decryption decision path
	e.AuthSource = a.AuthSource
}

// The request-log engine (ring + persistent JSONL layer + TTL read cache +
// levelForStatus) moved to internal/reqlog (ADR-0002, store.go decomposition
// Phase C). main keeps AuthLogFields above (welded to the frozen AuthOutcome
// contract), the recordRequest*/persistLogEntry fan-out below, and the API
// handlers — all through these aliases. Shutdown closes the file via
// reqlog.Close() (main.go); the ring/read caps live on the package
// (reqlog.MaxRing, reqlog.MaxPersistentReturn).
var (
	levelForStatus           = reqlog.LevelForStatus
	logAdd                   = reqlog.Add
	logGet                   = reqlog.Get
	initRequestLog           = reqlog.Init
	requestLogReadPersistent = reqlog.ReadPersistent
	requestLogPersistActive  = reqlog.PersistActive
)

// The queryable-history hook: the closure performs the same lock-free atomic
// load the pre-extraction inline code did, so a runtime enable/disable swap
// of the history store stays race-free on the hot path (logStore.Add is
// nil-receiver-safe).
func init() {
	reqlog.SetHistory(func(e LogEntry) { globalLogStore.Load().Add(e) })
}

// ─── Audit Log ────────────────────────────────────────────────────────────────
// The audit engine (ring + JSONL persistence + DP→CP push queue) moved to
// internal/audit (ADR-0002, store.go decomposition Phase B). main keeps the
// request wrappers (ui_helpers.go), the C2c middleware, the API handlers,
// and the CP push loop — all through these aliases. The SIEM hook is wired
// once below (the closure reads the runtime-configured syslog forwarder at
// call time); DP mode is set by the cluster wiring via audit.SetDPMode.

// AuditEntry is re-exposed unqualified (engine type is audit.Entry).
type AuditEntry = audit.Entry

// maxAuditLogs is re-exposed for tests (engine const is audit.MaxRing).
const maxAuditLogs = audit.MaxRing

func init() {
	audit.SetSIEM(func(e audit.Entry) {
		if globalSyslog != nil {
			globalSyslog.WriteAudit(e)
		}
	})
}

// Engine funcs re-exposed under their original names.
var (
	auditAdd                = audit.Add
	auditGet                = audit.Get
	auditGetMemory          = audit.GetMemory
	auditGetPersistent      = audit.GetPersistent
	drainPendingAuditEvents = audit.Drain
	requeueAuditEvents      = audit.Requeue
	auditPersistActive      = audit.PersistActive
	auditWriteErrors        = audit.WriteErrors
)

// InitAuditLog opens path for append-only JSONL audit persistence.
func InitAuditLog(path string) error { return audit.Init(path) }

// ─── Blocklist ────────────────────────────────────────────────────────────────
// The Blocklist engine moved to internal/blocklist (ADR-0002, store.go
// decomposition Phase A); blocklist_vars.go carries the aliases + the
// process-wide singleton. The hot-path matcher (IsBlocked), the sidecar
// persistence, feed attribution, and NormalizeLine all live in the package.

// ─── Auth cache ───────────────────────────────────────────────────────────────
//
// bcrypt is intentionally slow (~100 ms). For a proxy that authenticates on
// every request we cache the result for authCacheTTL to avoid a CPU bottleneck
// while still rotating frequently enough to catch revoked credentials.

const authCacheTTL = 5 * time.Minute

type authCacheEntry struct {
	ok     bool
	expiry time.Time
}

// authCacheStore caches verification outcomes under two SEPARATE budgets.
//
// The partition is a security control, not tidiness (CHAOS-57). Entries are
// keyed on HMAC(user:pass) with no client attribution, and the store is
// populated by UNAUTHENTICATED traffic: anyone who can reach the proxy port can
// mint a cache entry by presenting a credential. With one shared budget and the
// arbitrary eviction below, a flood of unique wrong credentials evicted a
// VALID cached credential roughly as often as another failure — so an
// unauthenticated stranger could push legitimate users back onto the ~74 ms
// hashing path at will, which is the amplifier this partition exists to remove.
//
// The fix does not need per-client attribution, because the asymmetry is
// structural: minting a POSITIVE entry requires credentials that actually
// verify, so an attacker can only ever write to `negatives`. Splitting the
// budgets therefore makes a failure flood evict only other failures — the same
// "a flooding source evicts ITSELF" property internal/authstate reaches for
// interactive-login state, obtained here without a fairness key.
//
// Both maps are lazily created by set(), so a zero-valued or partially
// constructed store (several tests build one with only `entries`) stays usable.
type authCacheStore struct {
	mu sync.Mutex
	// entries holds SUCCESSFUL verdicts. Only a caller presenting a credential
	// that verified can create one, so this map is unreachable to a flood.
	entries map[string]*authCacheEntry
	// negatives holds REJECTED verdicts, on their own budget. Attacker-writable
	// by construction; bounded so that is merely useless rather than harmful.
	negatives map[string]*authCacheEntry
}

func (a *authCacheStore) get(user, pass string) (ok, hit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := cacheKey(user, pass)
	now := time.Now()
	if e, found := a.entries[k]; found && now.Before(e.expiry) {
		return e.ok, true
	}
	if e, found := a.negatives[k]; found && now.Before(e.expiry) {
		return e.ok, true
	}
	return false, false
}

// maxAuthCacheSize caps the number of cached auth results to prevent unbounded
// memory growth from credential-stuffing attacks with unique user/pass pairs.
// Applied PER PARTITION — see the authCacheStore doc comment for why the two
// budgets must stay separate.
const maxAuthCacheSize = 5_000

// evictOneLocked frees a slot in m when it is at capacity: an expired entry if
// one is found, otherwise an arbitrary one. Arbitrary eviction is acceptable
// WITHIN a partition — the entries there are all the same kind, so the choice
// of victim cannot cross a trust boundary. It was not acceptable across kinds,
// which is what the partition fixes.
func evictOneLocked(m map[string]*authCacheEntry) {
	if len(m) < maxAuthCacheSize {
		return
	}
	now := time.Now()
	for k, e := range m {
		if now.After(e.expiry) {
			delete(m, k)
			return
		}
	}
	for k := range m {
		delete(m, k)
		return
	}
}

func (a *authCacheStore) set(user, pass string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	target := &a.entries
	if !ok {
		target = &a.negatives
	}
	if *target == nil {
		*target = map[string]*authCacheEntry{}
	}
	evictOneLocked(*target)
	(*target)[cacheKey(user, pass)] = &authCacheEntry{ok: ok, expiry: time.Now().Add(authCacheTTL)}
}

func (a *authCacheStore) clear() {
	a.mu.Lock()
	a.entries = map[string]*authCacheEntry{}
	a.negatives = map[string]*authCacheEntry{}
	a.mu.Unlock()
}

// cacheKeySecret is a per-process random key used to HMAC credential cache
// lookups. Using HMAC instead of a bare hash prevents offline brute-force
// if heap memory is ever dumped.
var cacheKeySecret = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return b
}()

// cacheKey derives an HMAC-SHA256 tag from (user+pass) so we never store
// plaintext credentials as map keys in heap-visible memory.
func cacheKey(user, pass string) string {
	mac := hmac.New(sha256.New, cacheKeySecret)
	mac.Write([]byte(user + ":" + pass))
	return hex.EncodeToString(mac.Sum(nil))
}

// ─── UI RBAC roles ────────────────────────────────────────────────────────────

// UIRole defines the permission level for admin UI users.
type UIRole string

const (
	RoleAdmin    UIRole = "admin"    // full system access
	RoleOperator UIRole = "operator" // manage content (policy, blocklist, etc.)
	RoleViewer   UIRole = "viewer"   // read-only dashboard access
)

// rolePriority maps roles to numeric levels for comparison.
var rolePriority = map[UIRole]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

// HasRole returns true when r's level is at least the level of min.
func (r UIRole) HasRole(min UIRole) bool {
	return rolePriority[r] >= rolePriority[min]
}

// uiAdminUser holds credentials and role for a single UI admin user.
type uiAdminUser struct {
	passHash        []byte
	role            UIRole
	totpSecret      string   // base32 TOTP secret; empty = TOTP not enrolled
	backupCodes     []string // bcrypt-hashed backup codes
	totpLastCounter int64    // last successfully-used TOTP time-step; prevents replay
}

// UIUserInfo is the public (no hash) view of a UI admin user.
type UIUserInfo struct {
	Username    string `json:"username"`
	Role        UIRole `json:"role"`
	TOTPEnabled bool   `json:"totpEnabled"`
}

// ─── Config (live-editable) ───────────────────────────────────────────────────

type Config struct {
	mu        sync.RWMutex
	ProxyPort int
	UIPort    int

	// Local (bcrypt) auth fields — used when no external AuthProvider is set.
	user     string
	passHash []byte // bcrypt hash; nil = no auth
	cache    authCacheStore
	// authRevision invalidates in-flight local-auth snapshots when credentials
	// or backend selection changes.
	authRevision uint64

	// External auth provider (LDAP or OIDC). When non-nil, takes precedence
	// over the local bcrypt credentials for Verify calls.
	provider AuthProvider

	// defaultAuthOutcome is the SINGLE authoritative global Stage-1 default,
	// applied only on no-match (see AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md).
	// OutcomeExempt == open unmatched traffic; OutcomeDefault == auth required
	// (fail-closed; empty normalizes to Default). Read via DefaultAuthOutcome(),
	// set via SetDefaultAuthOutcome() — the only API/UI/cluster/diagnostics path.
	defaultAuthOutcome AuthOutcome

	// uiUsers holds the multi-user admin roster with per-user roles.
	// When nil/empty, falls back to the legacy single-user (user/passHash).
	uiUsers map[string]*uiAdminUser

	// uiUsersFile is the path to persist UI users across restarts.
	// Empty = in-memory only (auth resets on every restart).
	uiUsersFile string

	// saveUIUsersMu serializes SaveUIUsersFile's snapshot+write sequence
	// end-to-end. mu alone is not enough: SaveUIUsersFile only holds mu
	// (RLock) while snapshotting the roster, then releases it before the
	// disk write. Two concurrent saves each take a valid, independent
	// snapshot, but their disk writes are otherwise unordered — whichever
	// write's rename() lands LAST wins, even if its snapshot was taken
	// FIRST, silently reverting a concurrently-added user on disk. Holding
	// saveUIUsersMu across the whole call forces saves to complete one at a
	// time, so each save's snapshot is taken only after any earlier save's
	// write has landed, guaranteeing disk order matches snapshot recency.
	saveUIUsersMu sync.Mutex
}

var cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}

// SetProvider replaces the active authentication backend.
// Pass nil to fall back to local bcrypt auth.
func (c *Config) SetProvider(p AuthProvider) {
	c.mu.Lock()
	c.provider = p
	c.authRevision++
	c.cache.clear()
	c.mu.Unlock()
	if p != nil {
		logger.Printf("Auth: provider %s", p.Name())
	}
}

// GetUser returns the configured local username (never returns the password).
func (c *Config) GetUser() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user
}

// SetAuth hashes pass with bcrypt and clears the auth cache.
// Call with empty user to disable local authentication.
// Has no effect on an external AuthProvider.
func (c *Config) SetAuth(user, pass string) error {
	if user == "" {
		c.mu.Lock()
		c.user = ""
		c.passHash = nil
		c.authRevision++
		c.cache.clear()
		c.mu.Unlock()
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.user = user
	c.passHash = hash
	c.authRevision++
	// Mirror into the RBAC user roster so the RBAC path works immediately.
	if c.uiUsers == nil {
		c.uiUsers = map[string]*uiAdminUser{}
	}
	c.uiUsers[user] = &uiAdminUser{passHash: hash, role: RoleAdmin}
	c.cache.clear()
	c.mu.Unlock()
	return nil
}

// RollbackFailedSetupAuth undoes a SetAuth(user, ...) call whose result could
// not be durably persisted (e.g. SaveUIUsersFile failed during first-time
// setup): it clears the legacy c.user/passHash and removes the roster entry
// SetAuth added, so IsConfigured() reverts to false and the setup wizard
// stays retryable. Unlike DeleteUIUser, this never refuses on "last admin" —
// there is no completed setup to protect, only an in-memory credential that
// must not survive a failed persist (leaving it in place while telling the
// operator setup failed would make a retry hit "setup already complete" with
// no session and no durable credential — a dead end).
func (c *Config) RollbackFailedSetupAuth(user string) {
	c.mu.Lock()
	c.user = ""
	c.passHash = nil
	c.authRevision++
	delete(c.uiUsers, user)
	c.cache.clear()
	c.mu.Unlock()
}

// dummyBcryptHash is a fixed bcrypt hash (cost = DefaultCost, matching stored
// credential hashes) used to equalise local-auth timing on a username miss
// (RISK-008). Without it, a wrong username returns instantly while a correct
// username pays the ~bcrypt cost, leaking which usernames exist via a timing
// oracle. Computed once at init; the input is always valid so the error is nil.
var dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("culvert-timing-equaliser"), bcrypt.DefaultCost)

type authBackendSnapshot struct {
	provider AuthProvider
	user     string
	passHash []byte
	revision uint64
}

func (c *Config) snapshotAuthBackend() authBackendSnapshot {
	c.mu.RLock()
	snapshot := authBackendSnapshot{provider: c.provider, user: c.user, passHash: c.passHash, revision: c.authRevision}
	c.mu.RUnlock()
	return snapshot
}

func (c *Config) verifyAuthWithSnapshot(snapshot authBackendSnapshot, user, pass string) bool {
	if snapshot.provider != nil {
		// An external provider is a NETWORK call, not a CPU one. It is bounded
		// by the CHAOS-47 probe gate and must NOT be routed through the
		// CPU-sized hashing gate — see rule 1 in auth_verify_cost.go.
		return snapshot.provider.Verify(user, pass)
	}
	if snapshot.user == "" {
		return true // auth disabled
	}

	// RISK-008: a wrong username must stay indistinguishable from a wrong
	// password, or the difference is a username-enumeration oracle. The
	// equaliser is therefore not a separate early-return branch any more but a
	// choice of WHICH hash the one shared sequence compares against: both
	// branches now run the same cache probe, the same admission gate and one
	// hash of the same cost, and differ only in that input.
	//
	// Keeping them on one path is the point. As two branches, the wrong-username
	// one consulted no cache and populated none, so a REPEATED IDENTICAL bogus
	// username paid a full ~74 ms hash every time while the wrong-password
	// branch paid it once — an asymmetry in the exact direction RISK-008 exists
	// to remove, and the amplifier CHAOS-57 measured. Any future change here
	// must move both together.
	hash := snapshot.passHash
	wrongUser := user != snapshot.user
	if wrongUser {
		hash = dummyBcryptHash
	}

	c.mu.RLock()
	if c.authRevision == snapshot.revision {
		if ok, hit := c.cache.get(user, pass); hit {
			c.mu.RUnlock()
			return ok
		}
	}
	c.mu.RUnlock()

	match, admitted := comparePasswordHashGated(hash, pass)
	if !admitted {
		// CHAOS-57 rule 2: the node was at its hashing capacity and no
		// comparison ran. Deny this request — never admit an unverified
		// credential — but do NOT remember the denial: a saturation refusal is
		// not an authoritative verdict, and caching it would deny a VALID
		// credential for the full TTL after the load passed (the stale-deny
		// defect CHAOS-47 closed for unreachable backends).
		return false
	}

	// The comparison above ran against dummyBcryptHash whenever the username
	// did not match, purely to equalise timing; its result is not an
	// authentication verdict and must never become one. Without this guard a
	// caller presenting the equaliser's own plaintext would authenticate under
	// ANY username.
	ok := match && !wrongUser

	c.mu.RLock()
	if c.authRevision == snapshot.revision {
		c.cache.set(user, pass, ok)
	}
	c.mu.RUnlock()
	return ok
}

// VerifyAuth checks credentials against one snapshot of the active auth backend:
//   - External provider (LDAP / OIDC) if configured, otherwise
//   - Local bcrypt hash with a short-lived cache.
func (c *Config) VerifyAuth(user, pass string) bool {
	return c.verifyAuthWithSnapshot(c.snapshotAuthBackend(), user, pass)
}

// resolveAuthIdentity preserves the legacy Config authentication selection but
// returns a provider-derived identity when the configured backend supports it.
// Non-identity providers and local bcrypt retain the historical caller username
// and "local" source semantics.
func (c *Config) resolveAuthIdentity(user, pass string) (*Identity, bool) {
	return c.resolveAuthIdentityWithSnapshot(c.snapshotAuthBackend(), user, pass)
}

func (c *Config) resolveAuthIdentityWithSnapshot(snapshot authBackendSnapshot, user, pass string) (*Identity, bool) {
	// VerifyAuth historically treats an empty backend as authentication disabled
	// and succeeds for setup/UI compatibility. Presented proxy credentials must
	// never turn that sentinel success into a caller-controlled identity.
	if snapshot.provider == nil && snapshot.user == "" {
		return nil, false
	}
	if resolver, ok := snapshot.provider.(interface {
		ResolveIdentity(username, credential string) (*Identity, bool)
	}); ok {
		return resolver.ResolveIdentity(user, pass)
	}
	if !c.verifyAuthWithSnapshot(snapshot, user, pass) {
		return nil, false
	}
	return &Identity{Sub: user, Provider: "local"}, true
}

// AuthEnabled returns true when any form of authentication is active, or when
// the global default is open/Exempt (setup is considered complete). The
// `defaultAuthOutcome == OutcomeExempt` term is the behavior-identical successor
// of the legacy `unauthMode` term (Slice 2); the SOCKS5 coupling is intentionally
// preserved here and decoupled later (Slice 5).
func (c *Config) AuthEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user != "" || c.provider != nil
}

// IsConfigured reports whether initial setup is complete: a credential backend
// exists OR the operator deliberately chose the open default (Exempt). The admin
// UI and setup flow gate on this — NOT AuthEnabled — so that open mode keeps the
// admin UI gated and makes setup one-time (Slice 5).
//
// The legacyLDAPRetired term (ADR-0027 / P1-2) keeps the gate CLOSED for a
// deployment whose only setup anchor was the legacy YAML LDAP provider: the
// cutover to the IdP registry deactivates that provider, and without this
// term the deactivation (or any later restart, with the durable sentinel but
// no wired provider) would flip setup back to "incomplete" — which the admin
// middleware treats as unauthenticated RoleAdmin for everyone. Retirement is
// a deliberate, durable operator state, so it counts as configured.
func (c *Config) IsConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.user != "" || c.provider != nil || c.defaultAuthOutcome == OutcomeExempt || legacyLDAPRetired()
}

// DefaultAuthOutcome returns the authoritative global Stage-1 default applied on
// no-match (Slice 3 runtime wiring). Fail-closed: only OutcomeExempt is returned
// as Exempt; any other/empty value normalizes to OutcomeDefault.
func (c *Config) DefaultAuthOutcome() AuthOutcome {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.defaultAuthOutcome == OutcomeExempt {
		return OutcomeExempt
	}
	return OutcomeDefault
}

// SetDefaultAuthOutcome sets the authoritative global Stage-1 default applied on
// no-match, fail-closed: any value other than OutcomeExempt normalizes to
// OutcomeDefault. Persists so the setting survives restarts. This is the only
// setter for the global default.
func (c *Config) SetDefaultAuthOutcome(outcome AuthOutcome) {
	if err := c.setDefaultAuthOutcomeChecked(outcome); err != nil {
		logWarnf("Auth: failed to persist defaultAuthOutcome: %v", err)
	}
}

// setDefaultAuthOutcomeChecked is SetDefaultAuthOutcome's persist-checked
// variant: on a SaveUIUsersFile failure it rolls the in-memory value back to
// whatever it was before the call and returns the error, instead of only
// logging it. Used by apiSetupComplete's open-mode ("unauth") branch, which
// — like the credentialed cfg.SetAuth branch beside it — must not report
// first-time setup as complete when the choice was never durably saved: an
// unpersisted Exempt default makes IsConfigured() report true for the rest
// of this process's lifetime, but reverts to false on the next restart,
// reopening the "one-time" setup wizard to any unauthenticated visitor.
func (c *Config) setDefaultAuthOutcomeChecked(outcome AuthOutcome) error {
	resolved := OutcomeDefault
	if outcome == OutcomeExempt {
		resolved = OutcomeExempt
	}
	c.mu.Lock()
	previous := c.defaultAuthOutcome
	c.defaultAuthOutcome = resolved
	c.mu.Unlock()
	if resolved == OutcomeExempt {
		logger.Printf("Auth: default authentication = Open unmatched traffic (defaultAuthOutcome=Exempt)")
	} else {
		logger.Printf("Auth: default authentication = Require authentication (defaultAuthOutcome=Default)")
	}
	// Persist so the setting survives restarts.
	if err := c.SaveUIUsersFile(); err != nil {
		// fileutil.ErrReplacedNotSynced means the rename already landed the
		// new content on disk — only the best-effort parent-directory sync
		// afterward failed. Its contract explicitly forbids a compensating
		// rollback on this error: restoring `previous` here would leave
		// memory contradicting the file that every reader (including a
		// restart) now sees, which is the same "reopens the wizard" hazard
		// this function exists to close, just approached from the opposite
		// direction. Still report the error — the write's durability across
		// an immediate crash isn't guaranteed — but keep the new value.
		if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
			c.mu.Lock()
			c.defaultAuthOutcome = previous
			c.mu.Unlock()
		}
		return err
	}
	return nil
}

// normalizeDefaultAuthOutcome maps a persisted string to a valid global default,
// fail-closed: only the exact canonical values "Exempt"/"Default" are accepted;
// anything else (unknown, empty, miscased, whitespace-padded, or a reserved
// future value such as "CredentialRequired") resolves to OutcomeDefault. The
// bool reports whether the input was a recognized canonical value.
func normalizeDefaultAuthOutcome(s string) (AuthOutcome, bool) {
	switch strings.TrimSpace(s) {
	case string(OutcomeExempt):
		return OutcomeExempt, true
	case string(OutcomeDefault):
		return OutcomeDefault, true
	default:
		return OutcomeDefault, false
	}
}

// resolveLoadedDefaultAuthOutcome computes the authoritative global default from
// a loaded envelope (Slice 2 migration; see AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md
// §3). When default_auth_outcome is present it wins (fail-closed-normalized) and
// the legacy unauth_mode mirror is ignored; otherwise it migrates one-way from
// the legacy bool (true⇒Exempt, false/absent/bare-array⇒Default). Deterministic
// and idempotent. Early returns keep LoadUIUsersFile flat.
func resolveLoadedDefaultAuthOutcome(env uiUsersFileEnvelope) AuthOutcome {
	// Key present (non-nil) ⇒ authoritative, even when empty: an empty or
	// otherwise non-canonical value fails closed to Default and the legacy
	// mirror is NOT consulted (a present-but-empty field must never reopen).
	if env.DefaultAuthOutcome != nil {
		raw := *env.DefaultAuthOutcome
		outcome, ok := normalizeDefaultAuthOutcome(raw)
		if !ok {
			logWarnf("Loader: ui_users.json: invalid default_auth_outcome %q — failing closed to %q",
				sanitizeLog(raw), string(OutcomeDefault))
		} else if env.UnauthMode != (outcome == OutcomeExempt) {
			// Both fields present and disagreeing: default_auth_outcome is
			// authoritative; surface the (bounded-window) drift for debugging.
			logWarnf("Loader: ui_users.json: default_auth_outcome=%q disagrees with legacy unauth_mode=%v — using default_auth_outcome (authoritative)",
				string(outcome), env.UnauthMode)
		}
		return outcome
	}
	// Key absent ⇒ one-way legacy migration from the mirror.
	if env.UnauthMode {
		return OutcomeExempt
	}
	return OutcomeDefault
}

// ─── UI multi-user admin management ──────────────────────────────────────────

// bcryptMaxPasswordBytes mirrors bcrypt's hard limit (golang.org/x/crypto/bcrypt):
// GenerateFromPassword errors on any password over 72 bytes. Rejecting it here
// turns that into a normal 400 validation error everywhere a password is set
// (first-time setup, user management, password change, config import) instead
// of a raw bcrypt error surfacing as a 500.
const bcryptMaxPasswordBytes = 72

// validatePasswordComplexity enforces minimum password strength:
// at least 8 characters, one uppercase letter, one lowercase letter, one digit,
// and no more than bcryptMaxPasswordBytes bytes (bcrypt's hard limit).
func validatePasswordComplexity(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > bcryptMaxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", bcryptMaxPasswordBytes)
	}
	var hasUpper, hasLower, hasDigit bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, and one digit")
	}
	return nil
}

// SetUIUser creates or updates an admin UI user with the given role.
// Call with empty password to update only the role (password unchanged).
func (c *Config) SetUIUser(username, password string, role UIRole) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uiUsers == nil {
		c.uiUsers = map[string]*uiAdminUser{}
	}
	existing := c.uiUsers[username]
	if password != "" {
		if err := validatePasswordComplexity(password); err != nil {
			return err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		c.uiUsers[username] = &uiAdminUser{passHash: hash, role: role}
	} else if existing != nil {
		existing.role = role
	} else {
		return fmt.Errorf("password is required to create a new user")
	}
	return nil
}

// DeleteUIUser removes a UI admin user.
// Returns an error if this would leave the roster with no admin.
func (c *Config) DeleteUIUser(username string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	u := c.uiUsers[username]
	if u != nil && u.role == RoleAdmin {
		adminCount := 0
		for _, usr := range c.uiUsers {
			if usr.role == RoleAdmin {
				adminCount++
			}
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot delete the last admin user")
		}
	}
	delete(c.uiUsers, username)
	return nil
}

// ListUIUsers returns a snapshot of all admin UI users (without password hashes).
func (c *Config) ListUIUsers() []UIUserInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]UIUserInfo, 0, len(c.uiUsers))
	for name, u := range c.uiUsers {
		out = append(out, UIUserInfo{Username: name, Role: u.role, TOTPEnabled: u.totpSecret != ""})
	}
	return out
}

// SetUIUsersFile sets the path used to persist UI users across restarts.
// Call before LoadUIUsersFile / SaveUIUsersFile.
func (c *Config) SetUIUsersFile(path string) {
	c.mu.Lock()
	c.uiUsersFile = path
	c.mu.Unlock()
}

// uiUserRecord is the on-disk representation of a UI admin user.
type uiUserRecord struct {
	Username        string   `json:"username"`
	PassHash        string   `json:"pass_hash"` // hex-encoded bcrypt hash
	Role            UIRole   `json:"role"`
	TOTPSecret      string   `json:"totp_secret,omitempty"`       // base32 TOTP secret
	BackupCodes     []string `json:"backup_codes,omitempty"`      // bcrypt-hashed one-time codes
	TOTPLastCounter int64    `json:"totp_last_counter,omitempty"` // last successfully-used TOTP step (replay protection)
}

// uiUsersFileEnvelope is the on-disk JSON structure that wraps the user
// roster along with global settings that must survive restarts.
type uiUsersFileEnvelope struct {
	// DefaultAuthOutcome is the single authoritative persisted global Stage-1
	// default. A POINTER so the loader can distinguish "key absent" (nil ⇒
	// migrate from the legacy mirror) from "key present but empty/invalid"
	// (non-nil "" ⇒ fail closed to Default, never reopen). Written explicitly on
	// every save (always non-nil) so "Default" round-trips and migration is
	// idempotent. See AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md.
	DefaultAuthOutcome *string `json:"default_auth_outcome"`
	// UnauthMode is a READ-ONLY import-compatibility input (Slice 5). It is
	// NEVER written and is consulted ONLY by resolveLoadedDefaultAuthOutcome when
	// default_auth_outcome is absent (a pre-Slice-2 config), mapping it once to
	// defaultAuthOutcome. When default_auth_outcome is present it ALWAYS wins,
	// even if the two conflict. Not part of the active architecture.
	UnauthMode bool           `json:"unauth_mode,omitempty"`
	Users      []uiUserRecord `json:"users"`
}

// LoadUIUsersFile reads persisted UI users from disk and populates the roster.
// Silently returns nil if the file does not exist yet (first run).
func (c *Config) LoadUIUsersFile() error {
	c.mu.RLock()
	path := c.uiUsersFile
	c.mu.RUnlock()
	if path == "" {
		return nil
	}
	// Re-surface an unreconciled quarantine from a prior boot (CHAOS-05):
	// the fresh file we write after a corrupt load parses cleanly next
	// time, so the /readyz row would otherwise vanish while the evidence
	// and the empty-roster state persist.
	noteResidualQuarantine("ui_users", path)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		logger.Printf("Loader: ui_users.json: file %q missing — caller may bootstrap defaults (D1.2-flag-F1)", sanitizeLog(path))
		return nil
	}
	if err != nil {
		return err
	}
	// Try new envelope format first, fall back to bare array for backward compat.
	var env uiUsersFileEnvelope
	var records []uiUserRecord
	if err := json.Unmarshal(data, &env); err == nil && env.Users != nil {
		records = env.Users
	} else if err := json.Unmarshal(data, &records); err != nil {
		// CHAOS-05: present-but-corrupt roster. Quarantine before
		// returning so the next SaveUIUsersFile (any admin mutation, or
		// the --reset-password one-shot) cannot overwrite the only copy
		// of the admin accounts + TOTP enrollments.
		quarantineCorruptStateFile("ui_users", path, err)
		return err
	}
	resolved := resolveLoadedDefaultAuthOutcome(env)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.authRevision++
	c.cache.clear()
	c.defaultAuthOutcome = resolved
	if c.uiUsers == nil {
		c.uiUsers = map[string]*uiAdminUser{}
	}
	for _, rec := range records {
		hash, err := hex.DecodeString(rec.PassHash)
		if err != nil {
			continue
		}
		c.uiUsers[rec.Username] = &uiAdminUser{
			passHash:        hash,
			role:            rec.Role,
			totpSecret:      rec.TOTPSecret,
			backupCodes:     rec.BackupCodes,
			totpLastCounter: rec.TOTPLastCounter,
		}
		// Keep legacy single-user in sync with the first admin found.
		if rec.Role == RoleAdmin && c.user == "" {
			c.user = rec.Username
			c.passHash = hash
		}
	}
	return nil
}

// SaveUIUsersFile writes the current UI user roster to disk atomically.
// No-op when no file path is configured.
//
// saveUIUsersMu serializes the whole snapshot+write sequence against other
// concurrent SaveUIUsersFile calls, so two saves triggered by concurrent
// admin-API requests can't race their disk writes and silently lose
// whichever one's rename() happens to land first (see the field comment).
func (c *Config) SaveUIUsersFile() error {
	c.saveUIUsersMu.Lock()
	defer c.saveUIUsersMu.Unlock()

	c.mu.RLock()
	path := c.uiUsersFile
	// Canonicalize for serialization: an unset in-memory value persists as the
	// fail-closed Default. default_auth_outcome is the ONLY field written (Slice
	// 5); the legacy unauth_mode mirror is no longer written (read-only import
	// compat only). See AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md §2.
	outcome := c.defaultAuthOutcome
	if outcome == "" {
		outcome = OutcomeDefault
	}
	authoritative := string(outcome)
	env := uiUsersFileEnvelope{
		DefaultAuthOutcome: &authoritative,
		Users:              make([]uiUserRecord, 0, len(c.uiUsers)),
	}
	for name, u := range c.uiUsers {
		env.Users = append(env.Users, uiUserRecord{
			Username:        name,
			PassHash:        hex.EncodeToString(u.passHash),
			Role:            u.role,
			TOTPSecret:      u.totpSecret,
			BackupCodes:     u.backupCodes,
			TOTPLastCounter: u.totpLastCounter,
		})
	}
	c.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	// AtomicWrite (unique temp + fsync) rather than a fixed ".tmp" +
	// rename: concurrent admin mutations save from separate handler
	// goroutines, and a shared temp name lets two writers interleave into
	// the same file before one renames the torn result over the roster.
	return fileutil.AtomicWrite(path, data, 0o600)
}

// VerifyUIUser checks credentials against the admin user roster and returns
// the user's role.  Falls back to the legacy single-user when the roster is
// empty, assigning RoleAdmin for backwards compatibility.
// UIUserExists returns true if the named user exists in the roster.
// Used to reject session cookies for deleted users.
func (c *Config) UIUserExists(username string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uiUsers[username] != nil
}

func (c *Config) VerifyUIUser(username, password string) (UIRole, bool) {
	c.mu.RLock()
	uiU := c.uiUsers[username]
	legacyUser := c.user
	legacyHash := c.passHash
	c.mu.RUnlock()

	// Multi-user roster takes precedence.
	if uiU != nil {
		if bcrypt.CompareHashAndPassword(uiU.passHash, []byte(password)) == nil {
			return uiU.role, true
		}
		return "", false
	}

	// Legacy single-user fallback (pre-RBAC deployments).
	if legacyUser != "" && username == legacyUser {
		if bcrypt.CompareHashAndPassword(legacyHash, []byte(password)) == nil {
			return RoleAdmin, true
		}
	}
	return "", false
}

// UserHasTOTP returns true if the user has TOTP enrolled.
func (c *Config) UserHasTOTP(username string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u, ok := c.uiUsers[username]; ok {
		return u.totpSecret != ""
	}
	return false
}

// GetTOTPSecret returns the base32 TOTP secret for a user (empty if not enrolled).
func (c *Config) GetTOTPSecret(username string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u, ok := c.uiUsers[username]; ok {
		return u.totpSecret
	}
	return ""
}

// SetTOTPSecret stores a TOTP secret and backup codes for a user.
func (c *Config) SetTOTPSecret(username, secret string, backupCodes []string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	u.totpSecret = secret
	u.backupCodes = backupCodes
	return true
}

// ClearTOTP removes TOTP enrollment for a user.
func (c *Config) ClearTOTP(username string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	u.totpSecret = ""
	u.backupCodes = nil
	return true
}

// GetTOTPLastCounter returns the last successfully-used TOTP time-step for a
// user (0 if none). Callers use this to detect replay of an OTP within the
// ±skew window (RFC 6238 §5.2).
func (c *Config) GetTOTPLastCounter(username string) int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u, ok := c.uiUsers[username]; ok {
		return u.totpLastCounter
	}
	return 0
}

// SetTOTPLastCounter records the TOTP time-step just consumed by a successful
// validation. Subsequent codes whose matched counter is <= this value are
// rejected as replays. Returns false if the user does not exist.
func (c *Config) SetTOTPLastCounter(username string, counter int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	if counter > u.totpLastCounter {
		u.totpLastCounter = counter
	}
	return true
}

// ConsumeBackupCode checks and consumes a backup code (one-time use).
// Returns true if code was valid and has been removed.
func (c *Config) ConsumeBackupCode(username, code string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.uiUsers[username]
	if !ok {
		return false
	}
	for i, hashed := range u.backupCodes {
		if bcrypt.CompareHashAndPassword([]byte(hashed), []byte(code)) == nil {
			u.backupCodes = append(u.backupCodes[:i], u.backupCodes[i+1:]...)
			return true
		}
	}
	return false
}

// ProviderEnabled returns true when an external auth provider (LDAP/OIDC) is set.
func (c *Config) ProviderEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.provider != nil
}

// oidcLoginURL stores the OIDC authorization/login URL for browser redirects.
var oidcLoginURL string

// proxyExternalBaseURL is the externally-visible base URL of the proxy UI
// (e.g. "https://proxy.corp.com:9090").  Set by SetProxyBaseURL() at startup.
// Used to build OIDC/SAML callback redirect_uris.
var proxyExternalBaseURL string

// trustForwardedHeaders controls whether X-Forwarded-Host / X-Forwarded-Proto
// are trusted for deriving the external base URL from requests.  Default false;
// set via --trust-forwarded-headers or proxy.trust_forwarded_headers in config.
// Must be explicitly enabled when running behind a reverse proxy.
var trustForwardedHeaders bool

// SetProxyBaseURL sets the external base URL used for OIDC/SAML callbacks.
func SetProxyBaseURL(u string) { proxyExternalBaseURL = strings.TrimRight(u, "/") }

// ProxyBaseURL returns the configured external base URL (empty if not set).
func (c *Config) ProxyBaseURL() string { return proxyExternalBaseURL }

// SetOIDCLoginURL stores the OIDC authorization URL so the proxy can redirect
// unauthenticated browser requests to the OIDC captive portal.
func SetOIDCLoginURL(u string) { oidcLoginURL = u }

// OIDCLoginURL returns the configured OIDC login redirect URL (empty if not set).
func (c *Config) OIDCLoginURL() string { return oidcLoginURL }

func uptime() string {
	d := time.Since(startTime).Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}

func recordRequest(ip, method, host, status, ruleMatched, actionTaken, identity, sslAction string) {
	recordRequestBytes(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, sslAction)
}

func recordRequestBytes(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv int64, sslAction string) {
	recordRequestBytesAuth(ip, method, host, status, ruleMatched, actionTaken, identity, bytesSent, bytesRecv, sslAction, AuthLogFields{})
}

// recordRequestAuth records a request log entry carrying the Stage-1 auth
// observability block. A zero AuthLogFields adds nothing to the wire output, so
// call sites converted from recordRequest stay byte-identical for requests with
// no auth decision (every non-exempt request). All current call sites are the
// pre-tunnel stage of handleRequest, where sslAction is not yet determined —
// hence no sslAction parameter; use recordRequestBytesAuth directly if a future
// inspect-stage call site needs one.
func recordRequestAuth(ip, method, host, status, ruleMatched, actionTaken, identity string, auth AuthLogFields) {
	recordRequestBytesAuth(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, "", auth)
}

// recordRequestAuthURI is recordRequestAuth plus a captured request URI
// (host+path, no query) for the per-rule "log full URL" option. It is the only
// recorder that populates LogEntry.URI; every other path leaves it empty so the
// field is omitted from the wire output (omitempty), keeping behavior unchanged
// for rules without LogFullURI set.
func recordRequestAuthURI(ip, method, host, status, ruleMatched, actionTaken, identity, sslAction, uri string, auth AuthLogFields) {
	recordRequestFull(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, sslAction, uri, auth)
}

// recordRequestBytesAuth is the core recorder; it attaches the Stage-1 auth
// observability block (AuthLogFields) to the log entry. recordRequest /
// recordRequestBytes delegate here with a zero AuthLogFields, so their wire
// output is unchanged. Reached from proxy.go (Slice 7) via recordRequestAuth at
// the post-auth-gate call sites in handleRequest.
func recordRequestBytesAuth(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv int64, sslAction string, auth AuthLogFields) {
	recordRequestFull(ip, method, host, status, ruleMatched, actionTaken, identity, bytesSent, bytesRecv, sslAction, "", auth)
}

// recordStats records the metric/time-series/alert/top-host side effects of a
// request WITHOUT writing a request-log entry. It is the shared core of
// recordRequestFull and the path used when a policy rule has traffic logging
// disabled ("Log traffic" off): the request still counts toward stats and
// dashboards, it just produces no feed/history/syslog entry.
func recordStats(ip, host, status, ruleMatched, actionTaken string) {
	atomic.AddInt64(&statTotal, 1)
	isAllowed := status == "OK" || status == "POLICY_ALLOW" || status == "POLICY_REDIRECT"
	tsRecordResult(isAllowed)
	// PR3 Option B: both sinks below are subject to the SAME destination contract, so
	// the pseudonym is derived ONCE here and shared. The alert payload is a STREAMED
	// sink (Slack/PagerDuty/SIEM webhook) — the "no plaintext destination on any
	// streamed sink" guarantee includes alerts — and the top-hosts ranking is a
	// viewer-facing sink (/api/top-hosts, the dashboard widget, PAC sampling). Deriving
	// it twice cost a second keyed HMAC per request for a value already in hand.
	// Off ⇒ plaintext, byte-identical.
	redactedHost := redactDestinationHost(host)
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine (the HasSubscriber contract; same rationale as the
	// storage_write_failed producer in storage_health.go). This is the PER-REQUEST
	// block path, so it is the hottest alert producer in the product and the one
	// where the skip matters most: without the gate every blocked request pays a
	// goroutine spawn, a payload allocation and a global dedup-mutex round trip to
	// deliver an alert to nobody. That cost lands precisely when a gateway is under
	// a scanning/beaconing flood — when block volume is highest and latency matters
	// most — and it is paid on the default posture (no webhooks configured) and in
	// every test binary. The gate is a pure fast path: when a subscriber does exist
	// the dispatch below is byte-identical.
	switch status {
	case "THREAT_BLOCKED", "SCAN_BLOCKED", "DPI_BLOCKED":
		if globalAlertStore.HasSubscriber("threat_detected") {
			go fireAlert("threat_detected", AlertPayload{
				Actor: ip, Host: redactedHost, Detail: ruleMatched + " " + actionTaken, Source: ruleMatched,
			})
		}
	case "POLICY_BLOCK", "POLICY_DROP":
		if globalAlertStore.HasSubscriber("policy_block") {
			go fireAlert("policy_block", AlertPayload{
				Actor: ip, Host: redactedHost, Detail: ruleMatched, Source: "policy",
			})
		}
	}
	if status == "OK" || status == "POLICY_ALLOW" {
		// Token cardinality is fixed (12 hex), so the bounded-map behavior is unchanged.
		topHosts.Record(redactedHost)
	}
}

// recordRequestFull is the implementation behind every recorder. uri is the
// captured request URL (host+path, no query) or "" when not logged.
func recordRequestFull(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv int64, sslAction, uri string, auth AuthLogFields) {
	recordStats(ip, host, status, ruleMatched, actionTaken)
	persistLogEntry(ip, method, host, status, ruleMatched, actionTaken, identity, bytesSent, bytesRecv, 0, sslAction, uri, auth)
}

// recordRequestLogOnly writes a request-log entry WITHOUT the stats/alert/
// top-host side effects. It is used for SSL-inspected inner requests (per-URL
// "log full URL" entries): the enclosing CONNECT was already counted by the
// allow path, so counting each inner request again would inflate statTotal
// (a CONNECT carrying N requests would count as 1+N).
func recordRequestLogOnly(ip, method, host, status, ruleMatched, actionTaken, identity, sslAction, uri string, auth AuthLogFields) {
	persistLogEntry(ip, method, host, status, ruleMatched, actionTaken, identity, 0, 0, 0, sslAction, uri, auth)
}

// recordTunnelBytes folds a raw tunnel's relayed bytes into the global byte
// counters. This is ALWAYS done for an allowed tunnel, independent of the
// per-rule "log traffic" flag: that flag is a feed-volume control, not a
// stats-accounting control. Raw tunnels are the dominant traffic class and
// were previously invisible in the bytes dashboard (only SSL-inspected bodies
// were counted). Split out from persistence so a quiet-rule tunnel still
// updates the byte totals even when it writes no feed entry.
func recordTunnelBytes(bytesSent, bytesRecv int64) {
	atomic.AddInt64(&statBytesSent, bytesSent)
	atomic.AddInt64(&statBytesRecv, bytesRecv)
}

// persistTunnelClose writes the per-connection TUNNEL_CLOSED feed entry (byte
// counts + lifetime). Log-only — the tunnel was already stats-counted by the
// allow path when it was established, so running the stats fan-out again would
// double-count statTotal/topHosts. Byte counters are handled separately by
// recordTunnelBytes so they are not tied to the log gate.
// ruleID is the matched rule's stable ULID (rename-safe decision attribution,
// §1) — empty when no policy rule is attributed (e.g. raw SOCKS5).
func persistTunnelClose(ip, method, host, identity, ruleMatched, ruleID string, bytesSent, bytesRecv int64, start time.Time, sslAction string) {
	persistTunnelCloseReason(ip, method, host, identity, ruleMatched, ruleID, bytesSent, bytesRecv, start, sslAction, "")
}

// persistTunnelCloseReason is persistTunnelClose with a structured actionTaken
// reason (surfaced in the feed entry's ActionTaken field) — e.g. an adaptive
// decryption client-cert live-rescue (ADR-0009), so the bypass is queryable in
// the request/tunnel feed and not just inferable from SSLAction.
func persistTunnelCloseReason(ip, method, host, identity, ruleMatched, ruleID string, bytesSent, bytesRecv int64, start time.Time, sslAction, actionTaken string) {
	persistTunnelCloseDec(ip, method, host, identity, ruleMatched, ruleID, bytesSent, bytesRecv, start, sslAction, actionTaken, nil, "")
}

// persistTunnelCloseDec is persistTunnelCloseReason plus an optional ADR-0011
// decryption-observability block on the feed entry. nil ⇒ no dec block (byte-identical).
// authSource is the F5 categorical attribution from the resolved auth context
// (ProxyIdentity.AuthSource); empty on paths with no auth context (SOCKS5).
func persistTunnelCloseDec(ip, method, host, identity, ruleMatched, ruleID string, bytesSent, bytesRecv int64, start time.Time, sslAction, actionTaken string, dec *DecryptionBlock, authSource string) {
	persistLogEntry(ip, method, host, "TUNNEL_CLOSED", ruleMatched, actionTaken, identity,
		bytesSent, bytesRecv, time.Since(start).Milliseconds(), sslAction, "", AuthLogFields{RuleID: ruleID, Dec: dec, AuthSource: authSource})
}

// recordTunnelClose accounts a raw tunnel's bytes AND writes its feed entry
// unconditionally. Used by the always-logged paths (SOCKS5) and tests.
func recordTunnelClose(ip, method, host, identity, ruleMatched, ruleID string, bytesSent, bytesRecv int64, start time.Time, sslAction string) {
	recordTunnelBytes(bytesSent, bytesRecv)
	persistTunnelClose(ip, method, host, identity, ruleMatched, ruleID, bytesSent, bytesRecv, start, sslAction)
}

// recordTunnelCloseGated is the raw-relay call-site helper. It ALWAYS folds the
// bytes into the global counters, then applies the per-rule "log traffic" gate
// to the FEED ENTRY only (mirroring the OK entry recorded at allow time —
// LogTraffic=false suppresses the entry but not the byte accounting). A nil
// match (no rule matched, default-allow) always logs.
func recordTunnelCloseGated(match *PolicyMatch, id ProxyIdentity, method, host string, bytesSent, bytesRecv int64, start time.Time, sslAction string) {
	recordTunnelCloseGatedReason(match, id, method, host, bytesSent, bytesRecv, start, sslAction, "")
}

// recordTunnelCloseGatedReason is recordTunnelCloseGated with a structured
// actionTaken reason for the feed entry (ADR-0009 client-cert rescue). Byte
// accounting is unconditional; the reason rides only the (gated) feed entry.
func recordTunnelCloseGatedReason(match *PolicyMatch, id ProxyIdentity, method, host string, bytesSent, bytesRecv int64, start time.Time, sslAction, actionTaken string) {
	recordTunnelCloseGatedDec(match, id, method, host, bytesSent, bytesRecv, start, sslAction, actionTaken, nil, false)
}

// recordTunnelCloseGatedDec is recordTunnelCloseGatedReason plus an optional ADR-0011
// decryption OUTCOME, projected onto the feed entry's nested dec block. A nil outcome
// leaves the entry byte-identical (no dec key); redact applies the §4 host/SNI privacy
// posture. Byte accounting stays unconditional; the block rides only the (gated) feed
// entry via AuthLogFields.Dec. The decryption decision path passes a non-nil outcome (a
// later ADR-0011 slice); every current caller passes nil, so this is behavior-neutral
// plumbing. Projection (toBlock) happens off the latency-critical decision, at close.
func recordTunnelCloseGatedDec(match *PolicyMatch, id ProxyIdentity, method, host string, bytesSent, bytesRecv int64, start time.Time, sslAction, actionTaken string, dec *DecryptionOutcome, redact bool) {
	recordTunnelBytes(bytesSent, bytesRecv) // always — independent of the log gate
	// ADR-0011 coverage metric: count the session once, unconditionally (a quiet rule
	// still had a decryption decision). nil dec ⇒ a non-decryption close (WS/SOCKS) ⇒
	// no-op. This is the choke point for bypass / learned-bypass / rescue / non-TLS
	// fallback; the inspect-success path counts separately (it never reaches here).
	recordDecryptSession(dec)
	if match != nil && !ruleLogsTraffic(match.Rule) {
		return
	}
	ruleName, ruleID := "", ""
	if match != nil && match.Rule != nil {
		ruleName = match.Rule.Name
		ruleID = match.Rule.ID
	}
	var block *DecryptionBlock
	if dec != nil {
		block = dec.toBlock(redact)
	}
	persistTunnelCloseDec(id.ClientIP, method, host, id.Identity, ruleName, ruleID, bytesSent, bytesRecv, start, sslAction, actionTaken, block, id.AuthSource)
}

// persistLogEntry builds the LogEntry and writes it to the ring, JSONL file,
// history store, and syslog — the logging half shared by recordRequestFull,
// recordRequestLogOnly, and recordTunnelClose.
func persistLogEntry(ip, method, host, status, ruleMatched, actionTaken, identity string, bytesSent, bytesRecv, durationMs int64, sslAction, uri string, auth AuthLogFields) {
	// PR3 Option B: pseudonymize the destination at this single chokepoint when the
	// privacy posture is on, so every downstream sink (ring, JSONL, history store,
	// syslog/SIEM, drill-down) inherits the identical token and no plaintext host/URI.
	// Off ⇒ redactDestination* return the inputs unchanged (byte-identical to today).
	// The dec.* block is redacted upstream in toBlock via the same keyed helper, so all
	// three destination fields share one contract. redactedHost is computed once and
	// threaded into the URI redactor so the host is HMAC'd a single time per record.
	redactedHost := redactDestinationHost(host)
	// One clock read for the whole record. Two reads not only cost twice as
	// much, they could straddle a second boundary and emit a TS and a Time that
	// disagree. The human-readable field is memoised per wall-clock second
	// (store_logclock.go) — byte-identical output, and it removes the only
	// remaining allocation on this per-request path.
	now := time.Now()
	entry := LogEntry{
		TS:          now.UnixMilli(),
		Time:        logClockStamp(now),
		IP:          ip,
		Identity:    identity,
		Method:      method,
		Host:        redactedHost,
		URI:         redactDestinationURI(uri, host, redactedHost),
		Status:      status,
		Level:       levelForStatus(status),
		RuleMatched: ruleMatched,
		ActionTaken: actionTaken,
		BytesSent:   bytesSent,
		BytesRecv:   bytesRecv,
		DurationMs:  durationMs,
		SSLAction:   sslAction,
	}
	auth.applyTo(&entry)
	logAdd(entry)
	// Forward request log entry to syslog/SIEM if configured (Finding 17.2).
	if globalSyslog != nil {
		globalSyslog.WriteRequest(entry)
	}
}

// ─── Top hosts ────────────────────────────────────────────────────────────────

// HostStat is a hostname with its request count, used for top-hosts ranking.
type HostStat struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// hostCounter follows the read-heavy contract the per-rule hit counters use
// (ruleMetrics.RecordHit): counting an ALREADY-TRACKED host — the case ~all
// production traffic hits, since the distinct-host working set repeats
// heavily — takes mu.RLock and bumps the counter atomically (concurrent RLock
// holders share slots, hence *int64 values). The exclusive lock is reserved
// for the rare mutations: inserting a new host, the decay pass, and Top.
type hostCounter struct {
	mu           sync.RWMutex
	hosts        map[string]*int64
	pendingDecay int // new-host drops since the last decay pass (amortization)
}

var topHosts = &hostCounter{hosts: map[string]*int64{}}

// topHostsMaxEntries bounds the number of distinct hostnames the top-hosts
// counter tracks. The hostname is attacker-controllable (any client can
// request arbitrarily many distinct hosts), so without a bound the map is an
// unbounded memory-exhaustion DoS. A var (not const) so tests can lower it.
var topHostsMaxEntries = 10000

func (hc *hostCounter) Record(host string) {
	// Fast path: already tracked — always count, never gated. The atomic add
	// happens INSIDE the RLock so the decay pass (which mutates counters with
	// plain ops under the exclusive lock) can never run concurrently with it.
	hc.mu.RLock()
	if p, ok := hc.hosts[host]; ok {
		atomic.AddInt64(p, 1)
		hc.mu.RUnlock()
		return
	}
	hc.mu.RUnlock()

	hc.mu.Lock()
	defer hc.mu.Unlock()
	if p, ok := hc.hosts[host]; ok {
		atomic.AddInt64(p, 1) // raced with another inserter — count, don't reset
		return
	}
	if len(hc.hosts) >= topHostsMaxEntries {
		// At capacity with a NEW host. Decaying (halve all counts, drop those
		// that reach zero) evicts cold entries — including high-cardinality
		// count-1 junk from a flood — so continuously-reinforced heavy hitters
		// survive (each decay only halves them, and their ongoing traffic tops
		// them back up) while a host that has gone silent correctly ages out.
		// Decay is O(n), so amortize it to at most once per topHostsMaxEntries
		// new-host drops; between passes newcomers are dropped in O(1). Net:
		// strict memory bound + amortized O(1) per call.
		hc.pendingDecay++
		if hc.pendingDecay < topHostsMaxEntries {
			return
		}
		hc.pendingDecay = 0
		hc.decayLocked()
		if len(hc.hosts) >= topHostsMaxEntries {
			return // still saturated with hot hosts — drop the newcomer
		}
	}
	one := int64(1)
	hc.hosts[host] = &one
}

// decayLocked halves every count and deletes entries that reach zero. Caller
// holds hc.mu (the EXCLUSIVE lock — plain counter access is safe because the
// RLock-holding atomic writers are excluded). This is the eviction primitive:
// cold entries (low counts) fall out while heavy hitters persist, keeping the
// top-N ranking meaningful.
func (hc *hostCounter) decayLocked() {
	for h, p := range hc.hosts {
		c := *p / 2
		if c == 0 {
			delete(hc.hosts, h)
		} else {
			*p = c
		}
	}
}

// Top returns the n most-requested hosts, sorted descending by count. The
// snapshot runs under the exclusive lock so the plain pointer reads cannot
// race the RLock-holding atomic increments.
func (hc *hostCounter) Top(n int) []HostStat {
	hc.mu.Lock()
	all := make([]HostStat, 0, len(hc.hosts))
	for h, p := range hc.hosts {
		all = append(all, HostStat{Host: h, Count: *p})
	}
	hc.mu.Unlock()

	// Simple selection: sort descending.
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}
