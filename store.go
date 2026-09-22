package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
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

// ── The current minute's counters are SHARDED ────────────────────────────────
//
// tsRecordResult runs on EVERY proxied request — HTTP, CONNECT, WebSocket,
// SOCKS5 — from recordStats. It used to take one process-wide sync.Mutex and,
// while HOLDING it, read the clock (tsAdvance's time.Now) before bumping three
// counters. So every request in the process serialised on one lock across a
// vDSO clock read, which is not a constant cost but a throughput CEILING: the
// same shape as the internal/threatfeed, internal/connlimit, IP-filter and
// latency-histogram findings already closed in this tree.
//
// The header this replaces recorded that an RLock+atomic fast path had been
// benchmarked and measured FLAT, concluding "the shared cache line, not the
// lock, is the bound". That conclusion was right about RWMutex and wrong about
// the bound: swapping Mutex for RWMutex cannot help a path that MUTATES, and
// the shared cache line is only inherent if the counter stays shared. Measured
// on a 4-core box (Go 1.26, one record per iteration, n=4, ns/op):
//
//	                                    │ GOMAXPROCS=1 │ GOMAXPROCS=4 │
//	mutex + clock INSIDE the lock (old) │     85.5     │    178.6     │
//	mutex, clock hoisted out            │     83.1     │    144.9     │
//	lock-free, counters still SHARED    │     78.9     │     62.2     │
//	lock-free, counters SHARDED (this)  │     85.9     │     38.1     │
//	time.Now().Unix()/60 alone (floor)  │     64.8     │     16.6     │
//
// Read the last row first: the clock is the irreducible floor, and at four
// cores the old path spent 162 of its 179 ns NOT doing the work. Sharding
// removes ~92% of that. Four cores went from 5.6M records/s (WORSE than one
// core's 11.7M — adding cores subtracted throughput) to 26.2M, a 4.7x lift of
// the old ceiling, and the gap widens on the 16- and 32-core hardware this
// ships to.
//
// In this tree rather than the model, at GOMAXPROCS 1 / 4 (n=5):
// BenchmarkTSRecordResultParallel 87.4 / 172.6 -> 78.6 / 36.1, and the whole
// per-request stats fan-out, BenchmarkRecordStatsAllowedParallel, 142.9 /
// 275.8 -> 130.0 / 131.2. There is no low-concurrency price to trade: one core
// came out AHEAD too, because dropping the lock/unlock pair and collapsing the
// verdict pair into a single atomic add (see tsLiveShard) together cost less
// than picking a shard.
//
// Only the CURRENT minute is hot, so only it is sharded: the 60-bucket ring is
// untouched and still mutex-guarded. Requests accumulate into `live`, and a
// rollover folds those accumulators into the bucket they belong to. Readers
// (tsGet — the SSE dashboard tick, /api/stats, the history-store estimate) sum
// the shards in. That moves work read-ward, exactly as the sharded latency
// histogram does: a read happens once per dashboard poll, a write once per
// request.
//
// THE RING ITSELF MUST NOT BE SHARDED, and that is a separate, still-standing
// rejection rather than an oversight. Sharding the ring was prototyped (60
// buckets x 3 counters per shard, 16 shards, mutex and atomic variants) and did
// not pay on 4-core hardware: the only shard key available here is a
// rand.Uint64, and against an object that size its cost ate the gain. What
// makes the CURRENT-MINUTE shard win instead is that it is 2 words rather than
// 180, its shards are cache-line PADDED (16 unpadded shards still false-share),
// and the verdict pair is PACKED into one atomic add rather than two or three —
// so the same ~7 ns key stops mattering above one core. Do not re-derive this
// as shared atomics either: removing the mutex without splitting the line
// removes the BATCHING a lock holder gets (measured 62.2 ns/op at four cores
// against this shape's 38.1). See the CLAUDE.md note for the paired
// marginal-cost evidence.
//
// THE INVARIANT IS CONSERVATION, NOT INSTANT ATTRIBUTION. A request that reads
// liveMin, is descheduled, and increments after a concurrent rollover lands in
// the NEXT minute's accumulator rather than the one it read. Nothing is ever
// lost — the fold SWAPS each shard to zero, so a late increment is simply
// carried to the following fold — and the boundary shift is at most one bucket
// on a 60-minute dashboard sparkline. Pinned by
// TestTimeSeries_ConcurrentRecordsAreConserved.
const (
	// tsShardCount is a power of two so the shard index is a mask, not a
	// division. 64 mirrors the per-IP rate limiter (rlShardCount) and
	// internal/connlimit, which reached the same figure for the same reason.
	tsShardCount = 64
	// tsCacheLine is the padding target. Three int64s is 24 bytes, so without
	// padding two shards share a line and incrementing one invalidates the
	// other — false sharing that hands back most of what splitting just bought.
	tsCacheLine = 64
)

// tsLiveShard is one padded slice of the current minute's counters.
//
// A request's counters live in ONE word, and that is a correctness requirement,
// not a packing trick. With a separate total/allowed/blocked triple the writer
// took two independent atomic adds and the fold three independent swaps, so a
// fold landing between a writer's two adds banked its total in the OLD bucket
// and its verdict in the NEW one. Whole-window conservation still held — which
// is exactly why the window-sum tests passed — but the per-bucket invariant
// allowed[i]+blocked[i] == buckets[i] was permanently broken for every request
// in flight across a minute rollover, and /api/timeseries hands those three
// arrays straight to the dashboard. (Codex review, PR #1286.)
//
// So the allow/block pair is packed into one word — allowed in the high 32
// bits, blocked in the low 32 — and a verdict is a SINGLE atomic add. Requests
// recorded without a verdict (tsRecord) get their own word. Each writer touches
// exactly one of the two, so no request can be drained apart, and the fold's
// two swaps are independent by construction rather than by luck.
//
// The 32-bit halves bound one shard's traffic between two folds, i.e. one
// wall-clock minute: 4.29e9 requests on a single shard, which at 64 shards is
// ~4.6 billion requests/second process-wide. That is not reachable on any
// hardware this runs on, and the fold interval does not grow when traffic
// stops (an idle shard accumulates nothing).
type tsLiveShard struct {
	verdicts int64 // allowed<<32 | blocked
	plain    int64 // recorded without a verdict (tsRecord)
	_        [tsCacheLine - 16]byte
}

const (
	tsAllowedUnit int64 = 1 << 32   // one allowed request, added to verdicts
	tsBlockedUnit int64 = 1         // one blocked request, added to verdicts
	tsBlockedMask int64 = 1<<32 - 1 // low half of a packed verdicts word
)

// split decomposes a packed verdicts word. Both halves are non-negative, so
// the shift and mask stay plain int64 arithmetic — no conversions.
func tsSplitVerdicts(v int64) (allowed, blocked int64) {
	return v >> 32, v & tsBlockedMask
}

type timeSeries struct {
	// mu guards the 60-minute ring below. It is taken on a rollover (at most
	// once per minute) and by readers — never by the per-request counting path.
	mu      sync.Mutex
	buckets [60]int64
	allowed [60]int64
	blocked [60]int64
	cur     int
	lastMin int64

	// liveMin is the minute `live` belongs to; it is the only field the
	// per-request path reads, and a plain atomic load is the whole check.
	liveMin atomic.Int64
	live    [tsShardCount]tsLiveShard
}

var ts = &timeSeries{}

// tsShardIndex picks the accumulator this request increments.
//
// Unlike every other sharded structure in this tree there is NO key to shard
// on — a request contributes to a global count, not to a per-IP or per-host
// slot — so the index comes from the runtime's per-P generator, which is
// lock-free and needs no shared state of its own. The counters are only ever
// SUMMED, so which shard a given request lands in is not observable.
//
// math/rand/v2 (aliased: this file's `rand` is crypto/rand) rather than a
// shared atomic round-robin counter, which would reintroduce exactly the
// contended cache line this change exists to remove.
func tsShardIndex() uint64 {
	return mrand.Uint64() & (tsShardCount - 1) // #nosec G404 -- shard spread, not crypto
}

// tsRecord counts a request without an allow/block verdict.
func tsRecord() { ts.record(false, false) }

// tsRecordResult counts a request and its allow/block verdict.
func tsRecordResult(isAllowed bool) { ts.record(true, isAllowed) }

// record is the per-request hot path: one clock read, one atomic load, and
// exactly ONE atomic add against a shard nobody else is likely to be touching.
// The single add is what keeps a request's counters in one bucket — see the
// tsLiveShard comment.
func (t *timeSeries) record(withVerdict, isAllowed bool) {
	now := time.Now().Unix() / 60
	if t.liveMin.Load() != now {
		t.rollover(now)
	}
	s := &t.live[tsShardIndex()]
	switch {
	case !withVerdict:
		atomic.AddInt64(&s.plain, 1)
	case isAllowed:
		atomic.AddInt64(&s.verdicts, tsAllowedUnit)
	default:
		atomic.AddInt64(&s.verdicts, tsBlockedUnit)
	}
}

// rollover folds the live accumulators into the minute they belong to and
// advances the ring. It runs at most once per minute on a busy proxy; the
// re-check under the lock makes the losers of a concurrent rollover no-ops.
func (t *timeSeries) rollover(now int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.liveMin.Load() == now {
		return
	}
	t.foldLiveLocked()
	t.advanceLocked(now)
	t.liveMin.Store(now)
}

// foldLiveLocked drains every shard into the CURRENT bucket. The swap-to-zero
// is what makes conservation hold: an increment that arrives after the swap is
// simply carried into the next fold instead of being overwritten. The two
// swaps are safe to take independently because no single request writes both
// words — see the tsLiveShard comment.
func (t *timeSeries) foldLiveLocked() {
	for i := range t.live {
		s := &t.live[i]
		allowed, blocked := tsSplitVerdicts(atomic.SwapInt64(&s.verdicts, 0))
		plain := atomic.SwapInt64(&s.plain, 0)
		t.allowed[t.cur] += allowed
		t.blocked[t.cur] += blocked
		t.buckets[t.cur] += allowed + blocked + plain
	}
}

// advanceLocked moves the ring forward to `now`, zeroing each newly-current
// bucket. Behaviour is carried over verbatim from the old tsAdvance, including
// the first-record (lastMin == 0) and clock-went-backwards (diff <= 0) cases.
func (t *timeSeries) advanceLocked(now int64) {
	if t.lastMin == 0 {
		t.lastMin = now
		return
	}
	diff := now - t.lastMin
	if diff <= 0 {
		return
	}
	if diff > 60 {
		diff = 60
	}
	for i := int64(0); i < diff; i++ {
		t.cur = (t.cur + 1) % 60
		t.buckets[t.cur] = 0
		t.allowed[t.cur] = 0
		t.blocked[t.cur] = 0
	}
	t.lastMin = now
}

// tsGet returns the last 60 minutes, oldest first. Like the version it
// replaces it does NOT advance the ring, so an idle proxy keeps reporting the
// window as it stood at the last request. The live shards belong to the
// current bucket and are summed in WITHOUT draining — a read never mutates the
// series, so two consecutive reads with no traffic between them agree.
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
	for i := range ts.live {
		s := &ts.live[i]
		a, b := tsSplitVerdicts(atomic.LoadInt64(&s.verdicts))
		allowed[59] += a
		blocked[59] += b
		total[59] += a + b + atomic.LoadInt64(&s.plain)
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
	auditPendingDrops       = audit.PendingDrops
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

	// client is the fairness key of whoever caused this entry to be written,
	// and added is when. Neither participates in lookup — the map key is still
	// the HMAC of (user, pass) alone — they exist only to decide WHO gets
	// evicted when the cache is full. See evictOneLocked.
	client string
	added  time.Time
}

// authCacheBucket tracks one client's entries in insertion order, so eviction
// can take that client's OLDEST without scanning the whole cache. head is the
// index of the first key not yet consumed; live is how many of this client's
// keys are still present in the map.
type authCacheBucket struct {
	keys []string
	head int
	live int
}

type authCacheStore struct {
	mu      sync.Mutex
	entries map[string]*authCacheEntry
	buckets map[string]*authCacheBucket

	// evictions counts entries dropped to stay under the cap. It is the
	// operator's only signal that cached credentials are being displaced —
	// every eviction costs somebody a full ~80 ms bcrypt on their next request.
	evictions uint64
}

func (a *authCacheStore) get(user, pass string) (ok, hit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := cacheKey(user, pass)
	if e, found := a.entries[k]; found && time.Now().Before(e.expiry) {
		return e.ok, true
	}
	return false, false
}

// maxAuthCacheSize caps the number of cached auth results to prevent unbounded
// memory growth from credential-stuffing attacks with unique user/pass pairs.
const maxAuthCacheSize = 5_000

// set records a verification outcome, evicting fairly if the cache is full.
//
// CHAOS-57. This cache is populated by UNAUTHENTICATED requests: any client
// that presents the configured username with any password writes an entry,
// because negative results are cached too (deliberately — not caching them
// would make every wrong password a fresh bcrypt). So its EVICTION POLICY is a
// security control, not housekeeping, exactly as internal/authstate's is.
//
// The pre-fix policy was "scan for an expired entry; if none, drop an
// arbitrary one" — a Go map range that stops at the first key, i.e. a
// uniformly random LIVE entry. Two defects followed:
//
//   - A flood of distinct passwords under a known username displaced OTHER
//     clients' cached positives at random. Measured: a legitimate user's
//     cached credential survived a flood of one times the cache capacity and
//     was reliably gone by two times it. The victim then paid a full ~80 ms
//     bcrypt on EVERY subsequent request, which turns the attacker's CPU
//     amplification onto legitimate traffic — the flood makes the gateway slow
//     for exactly the users it is supposed to serve.
//
//   - The expired-entry scan is O(cache) whenever nothing has expired, which
//     is precisely the state a flood keeps it in, and it runs holding the
//     process-wide auth mutex. Measured at 64 µs per insertion at capacity.
//
// The replacement is internal/authstate's policy, which was written for the
// same shape of problem: entries are attributed to a client key, and eviction
// always takes the OLDEST entry of the client holding the MOST (ties broken by
// oldest entry, then by client key, so the victim never depends on Go's map
// iteration order). A flooding source therefore evicts ITSELF until it is no
// longer the largest holder, and a client holding a single entry cannot be
// displaced until every other client is down to one entry too.
func (a *authCacheStore) set(client, user, pass string, ok bool) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.entries == nil {
		a.entries = map[string]*authCacheEntry{}
	}
	if a.buckets == nil {
		a.buckets = map[string]*authCacheBucket{}
	}

	k := cacheKey(user, pass)
	// Overwriting a live entry (same credential re-verified after its TTL) must
	// not double-count it in its bucket.
	if _, exists := a.entries[k]; exists {
		a.removeLocked(k)
	}
	if len(a.entries) >= maxAuthCacheSize {
		a.evictOneLocked(now)
	}

	a.entries[k] = &authCacheEntry{ok: ok, expiry: now.Add(authCacheTTL), client: client, added: now}
	b := a.buckets[client]
	if b == nil {
		b = &authCacheBucket{}
		a.buckets[client] = b
	}
	b.keys = append(b.keys, k)
	b.live++
	a.compactLocked(client, b)
}

// evictOneLocked drops exactly one entry: an already-expired one if any is
// found, otherwise the oldest live entry of the client holding the most.
//
// Only bucket FRONTS are examined, which is both cheap (O(active clients), not
// O(cache)) and sufficient: entries within a bucket are in insertion order and
// every entry carries the same TTL, so a bucket's front is its oldest and
// therefore the first to expire. An expired entry is preferred wherever it is
// found because dropping it costs nobody anything — it would have been a cache
// miss anyway — so the fairness ordering only has to arbitrate between LIVE
// entries, which is the case it exists for.
func (a *authCacheStore) evictOneLocked(now time.Time) {
	var (
		victimKey    string
		victimClient string
		victimLive   int
		victimAdded  time.Time
		found        bool
	)
	for client, b := range a.buckets {
		k, e, okFront := a.frontLocked(client, b)
		if !okFront {
			continue
		}
		// An expired entry is free to drop and is always the better victim.
		if now.After(e.expiry) {
			a.removeLocked(k)
			a.evictions++
			return
		}
		if !found || betterAuthCacheVictim(b.live, e.added, client, victimLive, victimAdded, victimClient) {
			victimKey, victimClient, victimLive, victimAdded, found = k, client, b.live, e.added, true
		}
	}
	if !found {
		return
	}
	a.removeLocked(victimKey)
	a.evictions++
}

// betterAuthCacheVictim reports whether candidate (live, added, client) is a
// better eviction victim than the incumbent. Ordering: most live entries
// first, then the oldest entry, then the lexicographically smaller client key
// — total and deterministic, so the victim never depends on map order.
func betterAuthCacheVictim(live int, added time.Time, client string, bestLive int, bestAdded time.Time, bestClient string) bool {
	switch {
	case live != bestLive:
		return live > bestLive
	case !added.Equal(bestAdded):
		return added.Before(bestAdded)
	default:
		return client < bestClient
	}
}

// frontLocked returns the client's oldest still-present entry, advancing head
// past keys that have already been removed.
func (a *authCacheStore) frontLocked(client string, b *authCacheBucket) (string, *authCacheEntry, bool) {
	for b.head < len(b.keys) {
		k := b.keys[b.head]
		if e, present := a.entries[k]; present && e.client == client {
			return k, e, true
		}
		b.head++
	}
	return "", nil, false
}

// removeLocked deletes one entry and decrements its bucket, dropping the
// bucket entirely at zero so the map's cardinality tracks ACTIVE clients
// rather than every client ever seen.
func (a *authCacheStore) removeLocked(k string) {
	e, present := a.entries[k]
	if !present {
		return
	}
	delete(a.entries, k)
	b := a.buckets[e.client]
	if b == nil {
		return
	}
	b.live--
	if b.live <= 0 {
		delete(a.buckets, e.client)
	}
}

// compactLocked drops consumed positions once a bucket's backing slice has
// grown past a small multiple of what the client actually holds.
//
// The condition is on len(b.keys), NOT on the un-consumed window
// len(b.keys)-b.head: under a sustained flood the window stays pinned at the
// cap while head and len advance together forever, so a window-based test
// never fires and the backing array grows with total request count — a memory
// leak reachable by the same flood the eviction policy exists to survive.
// (The identical trap is documented in internal/authstate.)
func (a *authCacheStore) compactLocked(client string, b *authCacheBucket) {
	if len(b.keys) <= 8 || len(b.keys) < 4*b.live {
		return
	}
	kept := b.keys[:0]
	for _, k := range b.keys[b.head:] {
		if e, present := a.entries[k]; present && e.client == client {
			kept = append(kept, k)
		}
	}
	b.keys = kept
	b.head = 0
	if len(b.keys) == 0 {
		delete(a.buckets, client)
	}
}

// Evictions reports how many cached verification results have been displaced
// to stay under the cap.
func (a *authCacheStore) Evictions() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.evictions
}

func (a *authCacheStore) clear() {
	a.mu.Lock()
	a.entries = map[string]*authCacheEntry{}
	a.buckets = map[string]*authCacheBucket{}
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

// cacheKey derives an HMAC-SHA256 tag from (user, pass) so we never store
// plaintext credentials as map keys in heap-visible memory.
//
// The inputs are LENGTH-FRAMED, and that is a correctness requirement, not a
// stylistic one. The previous derivation hashed `user + ":" + pass`, which is
// NOT injective as soon as either field can contain the separator:
//
//	("admin",   "a:b")  ->  "admin:a:b"
//	("admin:a", "b")    ->  "admin:a:b"     <- same key, different credential
//
// That was latent while the cache was consulted only AFTER the presented
// username had been confirmed equal to the configured one — every reachable
// key then shared the same `user + ":"` prefix, so distinct passwords gave
// distinct keys. CHAOS-57 moves the lookup ahead of that comparison (so a
// client riding a warm cache never consumes a verification slot), which makes
// the ambiguity reachable with a caller-chosen username and turns it into an
// AUTHENTICATION BYPASS: with a colon anywhere in the configured password, a
// caller could present a re-split of it and hit the cached positive.
//
// Framing each field with its length makes the encoding injective, so no two
// distinct (user, pass) pairs can ever share a key. Pinned by
// TestChaos57_CacheKeyIsInjective and by the end-to-end bypass gate
// TestChaos57_ReSplitCredentialCannotAuthenticate.
//
// The key derivation is process-local (cacheKeySecret is random per start) and
// the cache is memory-only, so changing the encoding invalidates nothing that
// outlives a restart.
func cacheKey(user, pass string) string {
	mac := hmac.New(sha256.New, cacheKeySecret)
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(user)))
	mac.Write(lenBuf[:])
	mac.Write([]byte(user))
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(pass)))
	mac.Write(lenBuf[:])
	mac.Write([]byte(pass))
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
	return c.verifyAuthFrom(snapshot, "", user, pass)
}

// verifyAuthFrom is verifyAuthWithSnapshot with the caller's client-fairness
// key threaded in, so the credential-verification cost governor
// (internal/authcost, CHAOS-57) can attribute the bcrypt work it admits.
//
// The ORDER of the four steps below is a security contract, not a style
// choice. Read it as: answer for free if you can, then buy permission to spend
// 80 ms of CPU, and only then look at the credential.
//
//  1. CACHE FIRST, and unconditionally — before the username is compared.
//     Moving the lookup ahead of the comparison changes no verdict (entries are
//     only ever stored for the configured username, so a wrong username was
//     always a miss and still is) and costs the same one HMAC + one map probe
//     either way, but it means a client riding a warm cache never consumes a
//     verification slot. Without that, a legitimate high-rate deployment would
//     be throttled by a governor that exists to bound work it is not doing.
//
//  2. ADMISSION SECOND, and INDEPENDENTLY OF THE USERNAME. This is the part
//     that must not be "simplified". RISK-008 equalises the wrong-username and
//     wrong-password paths — the dummy comparison below exists for no other
//     reason — so that neither is distinguishable by timing. A gate consulted
//     only on the branch that reaches the real hash, or given a budget that
//     differed between the branches, would make "over budget" fast for one and
//     slow for the other and hand back the username-enumeration oracle the
//     equalisation removed. The decision is therefore taken here, where the
//     code has not yet looked at `user`. Pinned by
//     TestChaos57_AdmissionDecisionIsUsernameIndependent.
//
//  3. REFUSAL IS A DENY. Fail closed: the cost of a spurious refusal is a 407
//     the client retries, and the cost of admitting without a bound is a
//     remotely triggerable CPU exhaustion of the whole data plane (~13 KB/s of
//     unauthenticated traffic saturated all four cores of the reference box).
//     It is never silent — see auth_cost_health.go.
//
//  4. THE SLOT IS HELD ACROSS BOTH comparison branches, and released by defer
//     so a panic inside bcrypt cannot leak it.
func (c *Config) verifyAuthFrom(snapshot authBackendSnapshot, client, user, pass string) bool {
	if snapshot.provider != nil {
		// External providers (LDAP bind, OIDC introspection) do not run bcrypt;
		// their cost and their failure modes are governed by CHAOS-47's
		// authProbeGate instead. Charging them a verification slot here would
		// bound the wrong resource.
		return snapshot.provider.Verify(user, pass)
	}
	if snapshot.user == "" {
		return true // auth disabled
	}

	c.mu.RLock()
	revisionCurrent := c.authRevision == snapshot.revision
	var ok, hit bool
	if revisionCurrent {
		ok, hit = c.cache.get(user, pass)
	}
	c.mu.RUnlock()
	if hit {
		return ok
	}

	if !authCostAdmit(client) {
		return false
	}
	defer authCostRelease(client)

	if user != snapshot.user {
		// RISK-008: equalise timing with the correct-username path so a wrong
		// username is indistinguishable from a wrong password — defeats
		// username enumeration via a timing oracle.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(pass))
		return false
	}
	ok = bcrypt.CompareHashAndPassword(snapshot.passHash, []byte(pass)) == nil
	c.mu.RLock()
	if c.authRevision == snapshot.revision {
		c.cache.set(client, user, pass, ok)
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

// AuthCacheEvictions reports how many cached verification results have been
// displaced to stay under the cache cap. A climbing counter is the operator's
// signal that either the cap is undersized for real login volume or somebody
// is flooding the credential path — each eviction costs the displaced client a
// full bcrypt on its next request (CHAOS-57).
func (c *Config) AuthCacheEvictions() uint64 { return c.cache.Evictions() }

// VerifyAuthFrom is VerifyAuth with the caller's client-fairness key, so the
// CHAOS-57 verification governor can attribute the bcrypt work. Data-plane
// callers that know their peer MUST use this: the plain VerifyAuth passes the
// empty key, which is valid but puts every such caller in one shared fairness
// bucket where they can only throttle each other.
func (c *Config) VerifyAuthFrom(client, user, pass string) bool {
	return c.verifyAuthFrom(c.snapshotAuthBackend(), client, user, pass)
}

// resolveAuthIdentity preserves the legacy Config authentication selection but
// returns a provider-derived identity when the configured backend supports it.
// Non-identity providers and local bcrypt retain the historical caller username
// and "local" source semantics.
func (c *Config) resolveAuthIdentity(user, pass string) (*Identity, bool) {
	return c.resolveAuthIdentityWithSnapshot(c.snapshotAuthBackend(), user, pass)
}

// resolveAuthIdentityFrom is resolveAuthIdentity carrying the caller's
// client-fairness key through to the CHAOS-57 verification governor.
func (c *Config) resolveAuthIdentityFrom(client, user, pass string) (*Identity, bool) {
	return c.resolveAuthIdentityFromSnapshot(c.snapshotAuthBackend(), client, user, pass)
}

func (c *Config) resolveAuthIdentityWithSnapshot(snapshot authBackendSnapshot, user, pass string) (*Identity, bool) {
	return c.resolveAuthIdentityFromSnapshot(snapshot, "", user, pass)
}

func (c *Config) resolveAuthIdentityFromSnapshot(snapshot authBackendSnapshot, client, user, pass string) (*Identity, bool) {
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
	if !c.verifyAuthFrom(snapshot, client, user, pass) {
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
	return c.saveUIUsersLocked()
}

// saveUIUsersLocked is SaveUIUsersFile's body with saveUIUsersMu already held.
// Split out for mutateRosterDurably, which must hold that mutex across the
// whole snapshot → mutate → persist → rollback sequence: a concurrent save
// landing between this call and a rollback would persist state the rollback is
// about to undo.
func (c *Config) saveUIUsersLocked() error {
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

// rosterSnapshot is a deep copy of every piece of state SaveUIUsersFile
// serialises. It exists so a mutation whose durable write fails can be undone
// exactly, without each caller having to write an inverse operation — undoing
// a DeleteUIUser, for instance, means restoring the account's password hash,
// role, TOTP secret, backup codes AND replay counter, which no caller has in
// hand by the time the write fails.
type rosterSnapshot struct {
	users   map[string]*uiAdminUser
	outcome AuthOutcome
}

// snapshotRoster deep-copies the roster. Takes c.mu itself, so the caller must
// NOT hold it; saveUIUsersMu is expected to be held by mutateRosterDurably.
func (c *Config) snapshotRoster() rosterSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snap := rosterSnapshot{outcome: c.defaultAuthOutcome}
	if c.uiUsers != nil {
		snap.users = make(map[string]*uiAdminUser, len(c.uiUsers))
		for k, v := range c.uiUsers {
			cp := *v
			cp.passHash = append([]byte(nil), v.passHash...)
			cp.backupCodes = append([]string(nil), v.backupCodes...)
			snap.users[k] = &cp
		}
	}
	return snap
}

// restoreRoster puts a snapshot back and invalidates every cached auth
// decision derived from the state being rolled back. Takes c.mu itself, so the
// caller must NOT hold it.
func (c *Config) restoreRoster(snap rosterSnapshot) {
	c.mu.Lock()
	c.uiUsers = snap.users
	c.defaultAuthOutcome = snap.outcome
	// A rolled-back password change may have cached a positive verdict for the
	// NEW password; leaving it would let a credential the roster no longer
	// contains keep authenticating for the cache TTL. authRevision additionally
	// invalidates local-auth snapshots already in flight.
	c.authRevision++
	c.cache.clear()
	c.mu.Unlock()
}

// ErrRosterNotPersisted reports that a roster mutation was rolled back because
// it could not be written durably. Callers turn it into a non-2xx: the change
// did not happen, and the operator must retry once the volume is writable.
var ErrRosterNotPersisted = errors.New("admin roster change was not persisted")

// mutateRosterDurably applies mutate to the admin roster and commits it to
// disk, rolling the in-memory change back when the write does not land.
//
// CHAOS-66. ui_users.json is the ONLY durable home of the admin roster,
// password hashes, roles, TOTP secrets, consumed backup codes and the TOTP
// replay counter. Every mutation changes memory first and persists second, so
// the two can disagree; the disagreement is resolved at the next restart, when
// the file wins. A handler that mutates memory, logs the persist error and
// answers 2xx therefore reports a security decision as done while the durable
// state still says otherwise — deleting a compromised administrator, revoking a
// role or rotating a leaked password all revert on the next restart, with the
// audit trail recording the action as successful.
//
// apiSetupComplete already treats that as a wrong answer rather than a degraded
// success (see setDefaultAuthOutcomeChecked and the RollbackFailedSetupAuth
// branch beside it, both pinned by tests). This is the same rule applied to the
// ongoing-administration mutations of the same file.
//
// fileutil.ErrReplacedNotSynced is deliberately NOT rolled back: its contract
// says the rename already landed the new content, so restoring the snapshot
// would leave memory contradicting the file every future reader — including a
// restart — now sees. The error is still returned so the caller can report that
// durability across an immediate crash is not guaranteed.
//
// Lock order: saveUIUsersMu → c.mu, matching SaveUIUsersFile. mutate is invoked
// with neither held, so it may take c.mu itself as the ordinary setters do.
func (c *Config) mutateRosterDurably(mutate func() error) error {
	c.saveUIUsersMu.Lock()
	defer c.saveUIUsersMu.Unlock()

	snap := c.snapshotRoster()
	if err := mutate(); err != nil {
		// CONTRACT: mutate must leave the roster untouched when it returns an
		// error. Both current mutations satisfy it — SetUIUser validates and
		// hashes before assigning anything, DeleteUIUser runs its "last admin"
		// check before the delete — and a future one must too.
		//
		// The snapshot is deliberately NOT restored here, because restoring
		// means clearing the credential-verification cache: that cache is read
		// by the PROXY data path, and dropping it makes every active user
		// re-pay a ~80 ms bcrypt on their next request (CHAOS-57). Restoring on
		// every refused password-complexity check would hand an authenticated
		// admin a repeatable way to do exactly that. A refused mutation wrote
		// nothing, so there is nothing to undo.
		return err
	}
	if err := c.saveUIUsersLocked(); err != nil {
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			return err
		}
		c.restoreRoster(snap)
		return fmt.Errorf("%w: %w", ErrRosterNotPersisted, err)
	}
	return nil
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

// LoginNameConfigured reports whether username names an account VerifyUIUser
// could authenticate — the roster, or the legacy single user.
//
// It exists for CHAOS-63's oversize-username guard (login_input_bounds.go),
// which must never refuse a name that belongs to a real admin. Its resolution
// MUST stay identical to VerifyUIUser's below: a name this returns false for is
// a name the login endpoint may reject outright, so any divergence locks an
// operator out of the admin UI.
//
// Deliberately NOT UIUserExists: that one checks only c.uiUsers, and a legacy
// single-user deployment can carry a name that lives solely in c.user.
// Deliberately not password-aware, and it retains nothing — the caller passes
// untrusted input, so this is a hash-and-compare, never a store.
func (c *Config) LoginNameConfigured(username string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uiUsers[username] != nil || (c.user != "" && username == c.user)
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

// hostCounter counts requests per destination host. Record runs on EVERY
// allowed request (recordStats), so the tracked-host path — the case ~all
// production traffic hits, since the distinct-host working set repeats
// heavily — must not serialise on a process-wide word.
//
// It used to take mu.RLock around the map read, on the reasoning that a reader
// lock is cheap. It is not: sync.RWMutex.RLock/RUnlock are two atomic
// read-modify-writes on ONE shared word, so every request in the process wrote
// the same cache line purely to read a map that in steady state never changes.
// That is not a constant cost but a THROUGHPUT CEILING, the same shape already
// found and fixed in internal/threatfeed, internal/connlimit and the IP filter.
//
// The map is therefore a sync.Map, which is precisely the shape this access
// pattern wants: a key's counter is written once at insert and read forever
// after, so a steady-state Load is an atomic pointer load plus a map read with
// NO read-modify-write on any shared word.
//
// Measured on a 4-core Xeon, 512-host working set, isolated runs of n=7,
// medians, BenchmarkTopHostsRecord_HitParallel:
//
//	GOMAXPROCS │    1    │    2    │    4    │ 1→4 throughput
//	RWMutex    │ 35.8 ns │ 92.6 ns │ 96.8 ns │ 0.37x  (cores SUBTRACTED throughput)
//	sync.Map   │ 42.0 ns │ 26.1 ns │ 16.1 ns │ 2.6x
//
// So six times the throughput at four cores, and — the part that matters for an
// appliance that ships onto 16- and 32-core hardware — a curve that IMPROVES
// with core count instead of degrading. State the cost honestly too: at
// GOMAXPROCS=1 this shape is ~17% slower (42.0 vs 35.8), because sync.Map.Load
// costs one more indirection than a map read under an uncontended RLock. The
// serial single-host benchmark (BenchmarkTopHostsRecord_Hit, n=8) shows no such
// gap — 33.5 → 31.7 ns — so the cost appears only when rotating a working set
// wide enough to miss cache, and a single-core gateway is not the shape this
// product runs in.
//
// A 64-shard RWMutex (the internal/connlimit pattern) was built and measured
// alongside it and NOT carried: it reached only ~37 ns/op at four cores and
// cost ~31% at GOMAXPROCS=1, because it still pays a lock acquisition per call.
// sync.Map pays none.
//
// mu now guards only the RARE mutations — inserting a new host, the decay
// pass, and the Top snapshot — and is never taken by the tracked-host path.
// n is the live-entry count that topHostsMaxEntries bounds; sync.Map has no
// len(), and it is the memory bound that matters, so it is tracked explicitly.
type hostCounter struct {
	hosts sync.Map     // host string → *int64
	n     atomic.Int64 // live entries in hosts — the quantity the cap bounds

	mu           sync.Mutex
	pendingDecay int // new-host drops since the last decay pass (amortization)
}

var topHosts = &hostCounter{}

// topHostsMaxEntries bounds the number of distinct hostnames the top-hosts
// counter tracks. The hostname is attacker-controllable (any client can
// request arbitrarily many distinct hosts), so without a bound the map is an
// unbounded memory-exhaustion DoS. A var (not const) so tests can lower it.
var topHostsMaxEntries = 10000

// size reports the number of live tracked hosts — the quantity
// topHostsMaxEntries bounds.
func (hc *hostCounter) size() int { return int(hc.n.Load()) }

// count returns the current count for host, and whether it is tracked at all.
func (hc *hostCounter) count(host string) (int64, bool) {
	v, ok := hc.hosts.Load(host)
	if !ok {
		return 0, false
	}
	return atomic.LoadInt64(v.(*int64)), true
}

func (hc *hostCounter) Record(host string) {
	// Fast path: already tracked — always count, never gated, and NO lock. The
	// counter a key maps to is written once at insert and never replaced, so a
	// stale-free Load plus an atomic add is the whole operation.
	if v, ok := hc.hosts.Load(host); ok {
		atomic.AddInt64(v.(*int64), 1)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()
	if v, ok := hc.hosts.Load(host); ok {
		atomic.AddInt64(v.(*int64), 1) // raced with another inserter — count, don't reset
		return
	}
	if hc.size() >= topHostsMaxEntries {
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
		if hc.size() >= topHostsMaxEntries {
			return // still saturated with hot hosts — drop the newcomer
		}
	}
	one := int64(1)
	hc.hosts.Store(host, &one)
	hc.n.Add(1)
}

// decayLocked halves every count and deletes entries that reach zero. Caller
// holds hc.mu, which excludes inserts, other decay passes and Top — but NOT
// the lock-free tracked-host increments, so every counter mutation here is
// atomic. This is the eviction primitive: cold entries (low counts) fall out
// while heavy hitters persist, keeping the top-N ranking meaningful.
//
// The one residual of the lock-free reader: a Record that has already loaded a
// counter's pointer can land its increment after this pass deletes that entry,
// and the increment is then lost. It is bounded to entries being evicted —
// whose count is 0 or 1 by construction, since only those halve to zero — and
// a decay pass runs at most once per topHostsMaxEntries new-host drops, and
// only while saturated. That is strictly inside the approximation this counter
// already documents past the cap (counts become lower bounds; ranking stays
// correct), and it can only ever UNDER-count a host that was already cold.
func (hc *hostCounter) decayLocked() {
	hc.hosts.Range(func(k, v any) bool {
		p := v.(*int64)
		for {
			cur := atomic.LoadInt64(p)
			half := cur / 2
			if !atomic.CompareAndSwapInt64(p, cur, half) {
				continue // a concurrent increment landed; re-read and halve that
			}
			if half == 0 {
				hc.hosts.Delete(k)
				hc.n.Add(-1)
			}
			return true
		}
	})
}

// Top returns the n most-requested hosts, sorted descending by count. The
// snapshot runs under hc.mu so it cannot interleave with a decay pass; the
// counters themselves are read atomically because the increment path is
// lock-free.
func (hc *hostCounter) Top(n int) []HostStat {
	hc.mu.Lock()
	all := make([]HostStat, 0, hc.size())
	hc.hosts.Range(func(k, v any) bool {
		all = append(all, HostStat{Host: k.(string), Count: atomic.LoadInt64(v.(*int64))})
		return true
	})
	hc.mu.Unlock()

	// Simple selection: sort descending.
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}
