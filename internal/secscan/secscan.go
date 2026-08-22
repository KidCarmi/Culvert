// Package secscan is the security-scan orchestrator: it ties ClamAV, YARA,
// the threat feed, the hash cache, and the admin hash allowlist into the
// single pipeline the proxy hot path calls. Extracted from package main per
// ADR-0006 Slice 2; the collaborators arrive as constructor-injected
// interfaces (Deps), so the engines stay decoupled and the decision tree is
// unit-testable with fakes. package main keeps the free-function glue
// (safeScanBody, scanBlock*, bodyNeedsBuffering, the status map) and the
// production adapters (security_scan.go shim).
//
// Pipeline for every proxied request/response:
//
//  1. URL / domain threat-feed check  (CheckURL / CheckDomain)
//     Instant, in-memory lookup against URLhaus + OpenPhish data.
//     Applied in handleRequest before the request is forwarded upstream.
//
//  2. Response body scan  (ScanBody)
//     a. SHA-256 hash looked up in cache → return cached verdict immediately.
//     b. ClamAV INSTREAM scan (binary + text content).
//     c. YARA rule matching (all loaded *.yar / *.yara rules).
//     d. Result stored in hash cache.
//     Applied in handleHTTP and handleTunnelInspect after reading the body.
//
// All components are optional:
//   - ClamAV is skipped when no address is configured or daemon is unreachable.
//   - YARA is skipped when no matcher is injected or it reports not loaded.
//   - Threat feeds are skipped when no checker is injected or it is disabled.
package secscan

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/clamav"
	"github.com/KidCarmi/Culvert/internal/hashcache"
	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// MaxDecompressBytes limits decompressed data to 64 MB to guard against gzip bombs.
const MaxDecompressBytes = 64 << 20

// zstdDecoderPool reuses zstd decoders to avoid allocating ~1-8 MB of internal
// buffers per response. Decoders are reset with Reset() before reuse.
var zstdDecoderPool = sync.Pool{
	New: func() any {
		d, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1)) //nolint:errcheck // nil reader is valid for pool initialization
		return d
	},
}

// ScanBodyTimeout caps the total time for all body scanners (ClamAV + YARA).
// If the combined scan doesn't finish in time, the content is blocked (fail-closed).
const ScanBodyTimeout = 10 * time.Second

// ── Counters ─────────────────────────────────────────────────────────────────
// Package-owned atomics; package main reads them via Counters() (Prometheus,
// OTLP, SSE events, status APIs) and increments the two main-side events via
// AddScanSkipped / AddRemoteScanFail.

var (
	statClamBlocked       int64 // requests blocked by ClamAV
	statYARABlocked       int64 // requests blocked by YARA rules
	statThreatFeedBlocked int64 // requests blocked by threat intel feeds
	statScanTimeout       int64 // body scans that hit ScanBodyTimeout (fail-closed)
	statScanSkipped       int64 // responses forwarded unscanned (size > maxBytes)
	statRemoteScanFail    int64 // remote scan sidecar failures (fail-open)
	statClamScanError     int64 // ClamAV scan errors mid-request (fail-open, alerted)
	statClamSaturated     int64 // scans that could not get a ClamAV slot within the budget
	statScanLateDiscarded int64 // clean verdicts computed after the deadline and discarded
)

// scanInflight counts body scans currently running, INCLUDING scans whose
// caller has already returned the fail-closed timeout verdict and is no longer
// waiting. Abandoned work is the part that used to be invisible, and it is the
// part that matters: each abandoned scan holds its share of the ClamAV
// concurrency limit and a copy of the response body until it unwinds.
var scanInflight atomic.Int64

// ScanInflight reports body scans currently running (abandoned ones included).
// It is a saturation gauge: a value that stays near or above the ClamAV
// concurrency limit means scans are queueing, which is the leading indicator of
// the timeout-and-abandon regime.
func ScanInflight() int64 { return scanInflight.Load() }

// CounterSnapshot is a point-in-time copy of the scan counters.
type CounterSnapshot struct {
	ClamBlocked       int64
	YARABlocked       int64
	ThreatFeedBlocked int64
	ScanTimeout       int64
	ScanSkipped       int64
	RemoteScanFail    int64
	ClamScanError     int64
	ClamSaturated     int64
	ScanLateDiscarded int64
	ScanInflight      int64
}

// Counters returns a snapshot of all scan counters.
func Counters() CounterSnapshot {
	return CounterSnapshot{
		ClamBlocked:       atomic.LoadInt64(&statClamBlocked),
		YARABlocked:       atomic.LoadInt64(&statYARABlocked),
		ThreatFeedBlocked: atomic.LoadInt64(&statThreatFeedBlocked),
		ScanTimeout:       atomic.LoadInt64(&statScanTimeout),
		ScanSkipped:       atomic.LoadInt64(&statScanSkipped),
		RemoteScanFail:    atomic.LoadInt64(&statRemoteScanFail),
		ClamScanError:     atomic.LoadInt64(&statClamScanError),
		ClamSaturated:     atomic.LoadInt64(&statClamSaturated),
		ScanLateDiscarded: atomic.LoadInt64(&statScanLateDiscarded),
		ScanInflight:      scanInflight.Load(),
	}
}

// AddScanSkipped records a response forwarded unscanned because it exceeded
// the scan buffer limit (incremented by package main's logScanLimitExceeded).
func AddScanSkipped() { atomic.AddInt64(&statScanSkipped, 1) }

// AddRemoteScanFail records a remote scan sidecar failure (incremented by the
// remote scanner client in package main).
func AddRemoteScanFail() { atomic.AddInt64(&statRemoteScanFail, 1) }

// ── Collaborator contracts (ADR-0006) ────────────────────────────────────────
// The orchestrator owns the narrow interfaces it needs; the engines stay
// interface-free. Production wiring (package main) adapts the singletons;
// tests inject in-memory fakes via New. All deps are optional: a nil
// collaborator behaves as "absent/disabled".

// ClamScanner is the ClamAV surface ScanBody/ClamAVStatus need.
type ClamScanner interface {
	Ping() error
	Scan(data []byte) (name string, found bool, err error)
}

// YARAMatcher is the YARA surface the scan pipeline needs. Loaded and Enabled
// are deliberately distinct to preserve pre-ADR-0006 behavior verbatim:
// BodyScanEnabled keys on rules-present only (Loaded), while the body scan
// additionally honors the runtime enable toggle (Enabled).
type YARAMatcher interface {
	Loaded() bool
	Enabled() bool
	Match(data []byte) []string
}

// ThreatChecker is the threat-feed surface CheckURL/CheckDomain need.
type ThreatChecker interface {
	Enabled() bool
	CheckURL(rawURL string) (bool, string)
	CheckDomain(domain string) (bool, string)
}

// HashExcluder is the admin hash-allowlist surface ScanBody needs.
type HashExcluder interface{ IsHashExcluded(hash string) bool }

// ── Scanner ──────────────────────────────────────────────────────────────────

// Result describes the outcome of a scan that triggered a block.
type Result struct {
	Blocked bool
	Reason  string // virus name, YARA rule name, or feed source
	Source  string // "clamav", "yara", or "threatfeed"
	Hash    string // SHA-256 hex of scanned content (body scans only)
}

// Scanner ties together ClamAV, YARA, the threat feed, and the hash cache
// into a single, easy-to-use interface for the proxy pipeline.
type Scanner struct {
	mu       sync.RWMutex
	clam     ClamScanner
	yara     YARAMatcher   // nil → no YARA
	feed     ThreatChecker // nil → no threat feed
	excl     HashExcluder  // nil → no hash allowlist
	cache    *hashcache.HashCache
	maxBytes int64 // max bytes to buffer per response for body scanning

	// enabled is the outermost per-request gate (proxy.go preDispatchBlocked
	// consults it before every threat-feed check, on EVERY proxied request), so
	// it is deliberately atomic rather than guarded by mu. Same reasoning as
	// threatfeed.Feed.enabled: reading a config boolean through the RWMutex that
	// also guards the scanner's collaborators made the request path contend on a
	// single reader-count cache line for no benefit. Init writes it once; nothing
	// reads it in a composite invariant with the locked fields except
	// BodyScanEnabled, which still takes the lock for the clam/yara pointers.
	enabled atomic.Bool

	// Tier 2.3: ClamAV ping cache. Protects the admin dashboard from
	// opening a fresh TCP connection to ClamAV on every status poll.
	clamStatusVal    string
	clamStatusExpiry time.Time

	// ClamAV VERSION cache. Signature databases update at most a few times a
	// day, so this is cached far longer than the ping status.
	clamVerVal    clamav.Version
	clamVerOK     bool
	clamVerExpiry time.Time
}

// clamStatusTTL is how long a successful ClamAV ping result is considered fresh.
const clamStatusTTL = 30 * time.Second

// clamVersionTTL is how long a ClamAV VERSION reply is cached. Definitions
// change a few times a day at most, so a 10-minute cache is plenty and keeps
// the admin dashboard from opening a fresh connection on every poll.
const clamVersionTTL = 10 * time.Minute

// clamVersioner is the optional VERSION capability. *clamav.Client implements
// it; test fakes need not, so it is type-asserted rather than folded into the
// required ClamScanner interface.
type clamVersioner interface {
	Version() (clamav.Version, error)
}

// Deps carries the injectable collaborators for New. Nil collaborators behave
// as absent (that engine/check is skipped), so partial injection is fine.
type Deps struct {
	Clam     ClamScanner
	Yara     YARAMatcher
	Feed     ThreatChecker
	Excl     HashExcluder
	Cache    *hashcache.HashCache
	MaxBytes int64
}

// New builds a scanner from injected collaborators (ADR-0006). The scanner
// starts DISABLED — call Init to enable it — mirroring the pre-extraction
// package-main singleton (a struct literal with cache+maxBytes defaults that
// only Init flipped on). Collaborators are fixed at construction and never
// mutated afterwards (Init only touches clam/cache/maxBytes/enabled).
func New(deps Deps) *Scanner {
	ss := &Scanner{
		clam:     deps.Clam,
		yara:     deps.Yara,
		feed:     deps.Feed,
		excl:     deps.Excl,
		cache:    deps.Cache,
		maxBytes: deps.MaxBytes,
	}
	if ss.cache == nil {
		ss.cache = hashcache.New(10_000, 0)
	}
	if ss.maxBytes <= 0 {
		ss.maxBytes = 5 << 20
	}
	return ss
}

// Init configures the scanner.
//
//	clamAddr — ClamAV address string (see clamav.New); "" disables ClamAV.
//	maxBytes — maximum bytes to buffer per response (0 = use default 5 MiB).
//	cache    — hash cache to adopt; nil keeps the current one (ADR-0006: the
//	           cache is handed over here instead of being poked from outside).
func (ss *Scanner) Init(clamAddr string, maxBytes int64, cache *hashcache.HashCache) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if maxBytes > 0 {
		ss.maxBytes = maxBytes
	}
	if cache != nil {
		ss.cache = cache
	}
	if clamAddr != "" {
		ss.clam = clamav.New(clamAddr)
		if err := ss.clam.Ping(); err != nil {
			obs.Printf("SecurityScan: ClamAV unreachable at %q (%v) — retrying per request", clamAddr, err)
		} else {
			obs.Printf("SecurityScan: ClamAV connected at %q", clamAddr)
		}
	}
	ss.enabled.Store(true)
	// Tier 2.3: Invalidate any cached clam status so the first admin poll
	// after reconfiguration runs a real ping.
	ss.clamStatusVal = ""
	ss.clamStatusExpiry = time.Time{}
	// Same for the VERSION cache — a reconfigured daemon may report a
	// different engine/signature set.
	ss.clamVerOK = false
	ss.clamVerExpiry = time.Time{}
}

// Enabled reports whether the scanner has been initialised.
//
// Lock-free by contract — see the enabled field. This is the gate the proxy
// consults before any threat check, so it must stay free of mu.
// TestScannerEnabled_IsLockFree pins the property.
func (ss *Scanner) Enabled() bool {
	return ss.enabled.Load()
}

// BodyScanEnabled reports whether body scanning (ClamAV and/or YARA) is active.
// Unlike Enabled it still takes mu: the clam/yara collaborators are ordinary
// mu-guarded fields and this is a response-stage check, not the request gate.
func (ss *Scanner) BodyScanEnabled() bool {
	if !ss.enabled.Load() {
		return false
	}
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.clam != nil || (ss.yara != nil && ss.yara.Loaded())
}

// MaxBytes returns the buffer limit for body scanning.
func (ss *Scanner) MaxBytes() int64 {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.maxBytes
}

// ClamAVStatus returns a human-readable daemon connectivity string.
// Tier 2.3: Result is cached for clamStatusTTL to avoid hammering the ClamAV
// daemon on every admin dashboard poll. Cache is invalidated on Init().
func (ss *Scanner) ClamAVStatus() string {
	ss.mu.RLock()
	clam := ss.clam
	if clam == nil {
		ss.mu.RUnlock()
		return "disabled"
	}
	// Cache hit: return stored status without pinging.
	if ss.clamStatusVal != "" && time.Now().Before(ss.clamStatusExpiry) {
		v := ss.clamStatusVal
		ss.mu.RUnlock()
		return v
	}
	ss.mu.RUnlock()

	// Cache miss or expired — ping outside any lock, then cache result.
	var val string
	if err := clam.Ping(); err != nil {
		val = fmt.Sprintf("unreachable: %v", err)
	} else {
		val = "connected"
	}
	ss.mu.Lock()
	ss.clamStatusVal = val
	ss.clamStatusExpiry = time.Now().Add(clamStatusTTL)
	ss.mu.Unlock()
	return val
}

// ClamAVVersion returns the ClamAV engine + signature database version, so
// operators can see whether virus definitions are current. Returns ok=false
// when ClamAV is disabled, the client does not support VERSION, or the daemon
// is unreachable. Cached for clamVersionTTL (definitions change rarely) and
// invalidated on Init, mirroring ClamAVStatus.
func (ss *Scanner) ClamAVVersion() (clamav.Version, bool) {
	ss.mu.RLock()
	clam := ss.clam
	if clam == nil {
		ss.mu.RUnlock()
		return clamav.Version{}, false
	}
	if ss.clamVerOK && time.Now().Before(ss.clamVerExpiry) {
		v := ss.clamVerVal
		ss.mu.RUnlock()
		return v, true
	}
	ss.mu.RUnlock()

	versioner, ok := clam.(clamVersioner)
	if !ok {
		return clamav.Version{}, false
	}
	// Query outside any lock, then cache. On error, cache a short-lived "not
	// available" so a down daemon isn't hammered on every poll.
	v, err := versioner.Version()
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if err != nil {
		obs.Printf("SecurityScan: ClamAV VERSION query failed: %v", err)
		ss.clamVerOK = false
		ss.clamVerExpiry = time.Now().Add(clamStatusTTL) // retry sooner than a good result
		return clamav.Version{}, false
	}
	ss.clamVerVal = v
	ss.clamVerOK = true
	ss.clamVerExpiry = time.Now().Add(clamVersionTTL)
	return v, true
}

// ── URL / domain checks ───────────────────────────────────────────────────────

// CheckURL checks a full URL against the threat feed.
// Returns nil when no threat is found.
func (ss *Scanner) CheckURL(rawURL string) *Result {
	feed := ss.feed
	if feed == nil || !feed.Enabled() {
		return nil
	}
	if ok, source := feed.CheckURL(rawURL); ok {
		atomic.AddInt64(&statThreatFeedBlocked, 1)
		return &Result{
			Blocked: true,
			Reason:  "threat intelligence (" + source + ")",
			Source:  "threatfeed",
		}
	}
	return nil
}

// CheckDomain checks a bare hostname against the threat feed.
// Returns nil when no threat is found.
func (ss *Scanner) CheckDomain(domain string) *Result {
	feed := ss.feed
	if feed == nil || !feed.Enabled() {
		return nil
	}
	if ok, source := feed.CheckDomain(domain); ok {
		atomic.AddInt64(&statThreatFeedBlocked, 1)
		return &Result{
			Blocked: true,
			Reason:  "threat intelligence (" + source + ")",
			Source:  "threatfeed",
		}
	}
	return nil
}

// ── Body decompression (1.1 fix) ──────────────────────────────────────────────

// DecompressForScan transparently decompresses a response body based on its
// Content-Encoding header so that ClamAV/YARA signatures can match the actual
// content. Supports gzip, deflate, and identity (no-op). Brotli ("br") is
// attempted as gzip (some servers mislabel); on failure the raw bytes are
// returned so the scan still runs (defense in depth).
//
// Returned data is limited to MaxDecompressBytes to guard against gzip bombs.
// If decompression fails, the original data is returned unchanged — the scan
// still runs on compressed bytes (fail-open for availability, but the
// signature gap is closed for the common case).
func DecompressForScan(data []byte, contentEncoding string) []byte {
	ce := strings.ToLower(strings.TrimSpace(contentEncoding))
	if ce == "" || ce == "identity" {
		return data
	}

	var reader io.ReadCloser
	var err error

	switch ce {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(data))
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(data))
	case "br":
		reader = io.NopCloser(brotli.NewReader(bytes.NewReader(data)))
	case "zstd":
		zr := zstdDecoderPool.Get().(*zstd.Decoder)
		if err := zr.Reset(bytes.NewReader(data)); err != nil {
			zstdDecoderPool.Put(zr)
			return data
		}
		decompressed, zReadErr := io.ReadAll(io.LimitReader(zr, MaxDecompressBytes))
		zstdDecoderPool.Put(zr)
		if zReadErr != nil || len(decompressed) == 0 {
			return data
		}
		return decompressed
	default:
		// Unknown encoding — scan raw bytes.
		return data
	}
	if err != nil {
		// gzip.NewReader failed (malformed header) — scan raw bytes.
		return data
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(io.LimitReader(reader, MaxDecompressBytes))
	if err != nil {
		// Decompression error (truncated, corrupt) — scan raw bytes.
		return data
	}
	if len(decompressed) == 0 {
		return data // empty after decompression — scan original
	}
	return decompressed
}

// ── Body scanning ─────────────────────────────────────────────────────────────

// ScanBody scans a response body with ClamAV and YARA.
// Results are cached by SHA-256 to avoid redundant work.
// The entire scan is bounded by ScanBodyTimeout (fail-closed: blocks on timeout).
// Returns nil when the content is clean (or no scanner is enabled).
func (ss *Scanner) ScanBody(data []byte) *Result {
	if !ss.BodyScanEnabled() || len(data) == 0 {
		return nil
	}
	hash := hashcache.SHA256Hex(data)

	// Tier 3.3: admin-managed hash allowlist. If the content hash is
	// explicitly trusted, skip all scanning.
	if excl := ss.excl; excl != nil && excl.IsHashExcluded(hash) {
		return nil
	}

	// Cache hit?
	if cached, ok := ss.cache.Get(hash); ok {
		if !cached.Clean {
			return &Result{
				Blocked: true,
				Reason:  cached.Reason,
				Source:  cached.Source,
				Hash:    hash,
			}
		}
		return nil // cached clean
	}

	// Run all scanners under a single timeout.
	// Fail-closed: if the deadline fires, we block the content (Zero Trust).
	//
	// The deadline is a context, not a bare timer, so that the work actually
	// STOPS when we stop waiting for it. Previously the inner goroutine ran on
	// uninterrupted — holding one of the four ClamAV slots for up to the
	// client's own 30 s timeout, three times this budget — so under a slow
	// daemon the slots filled with scans nobody was waiting for and live
	// requests fell onto ClamAV's fail-OPEN queue-full path. Cancelling here is
	// what stops that from becoming self-sustaining.
	ctx, cancel := context.WithTimeout(context.Background(), scanBodyTimeout())
	defer cancel()

	var abandoned atomic.Bool
	ch := make(chan *Result, 1)
	scanInflight.Add(1)
	go func() {
		defer scanInflight.Add(-1)
		ch <- ss.scanBodyInner(ctx, data, hash, &abandoned)
	}()

	select {
	case result := <-ch:
		return ss.completeScan(result, hash)
	case <-ctx.Done():
		abandoned.Store(true)
		return ss.noteScanTimeout(hash)
	}
}

// completeScan finalises a result the worker delivered before the select gave
// up on it.
//
// A timeout-SOURCED result means the worker found the budget gone and enforced
// it from its own side. With a budget-aware ClamAV client that is not a rare
// race: the connection deadline and ctx.Done() become ready at the same
// instant, so either arm of the select can win, and the choice between two
// ready cases is random. Both arms must therefore land on the same accounting
// — otherwise statScanTimeout undercounts nondeterministically, and, worse, no
// cooldown is written, so the next request for the same hot object immediately
// launches another doomed scan. That is precisely the stampede the cooldown
// exists to prevent, unreliable in exactly the regime it was built for.
func (ss *Scanner) completeScan(result *Result, hash string) *Result {
	if result != nil && result.Source == "timeout" {
		return ss.noteScanTimeout(hash)
	}
	return result
}

// noteScanTimeout performs the fail-closed timeout accounting — counter, log,
// cooldown memo — and returns the refusal. Exactly one of ScanBody's two arms
// calls it per scan, so the counter counts scans, not events.
func (ss *Scanner) noteScanTimeout(hash string) *Result {
	atomic.AddInt64(&statScanTimeout, 1)
	obs.Warnf("SecurityScan: ScanBody timeout after %s for hash %s — blocking (fail-closed)", scanBodyTimeout(), hash)
	ss.cacheTimeoutCooldown(hash)
	return &Result{Blocked: true, Reason: "scan timeout", Source: "timeout", Hash: hash}
}

// cacheTimeoutCooldown memoises the fail-closed refusal briefly.
//
// Two rules, and both were learned the hard way. First, the lifetime: this is
// an INFRASTRUCTURE verdict, not a verdict about the content, and it used to be
// stored with the full content-cache TTL (1 h by default) — so a few seconds of
// scanner slowness blocked that exact object, node-wide, for every user, for an
// hour after the fault cleared, recoverable only by an admin cache flush.
// scanBodyInner's clamDark branch already refuses to cache a verdict computed
// while ClamAV was dark, for exactly this reason; the reasoning simply had not
// been applied to its neighbour. A short cooldown keeps the useful half — a
// stampede of doomed scans for one hot object is what fills the queue in the
// first place — without outliving the fault.
//
// Second, the direction: it must never DOWNGRADE a confirmed threat verdict.
// A late block from this scan's own abandoned goroutine, or from a concurrent
// scan of the same hash, can land between the deadline firing and this write.
// Overwriting it would replace a named, full-TTL threat entry with a generic
// one that lapses in 30 s, after which the object depends on the next scan
// succeeding — and the engine-error path is fail-OPEN. That is the same
// tighten-only rule publishVerdict enforces; it had simply not been carried
// across to the neighbouring branch, which is the very mistake this whole
// change exists to correct.
func (ss *Scanner) cacheTimeoutCooldown(hash string) {
	timeoutVerdict := hashcache.ScanCacheResult{Clean: false, Reason: "scan timeout", Source: "timeout"}
	ss.cache.SetTTLUnless(hash, timeoutVerdict, scanTimeoutCooldown, func(existing hashcache.ScanCacheResult) bool {
		// Keep any CONFIRMED block: it names the threat and carries the full
		// content TTL, both of which this generic entry would destroy.
		return !existing.Clean && existing.Source != "timeout"
	})
}

// scanTimeoutCooldown is how long a fail-closed scan-timeout refusal is
// remembered. Deliberately far shorter than the content-cache TTL: it bounds
// how long an infrastructure fault can keep blocking content after it clears,
// while still absorbing a burst of requests for the same object during it.
// Production never assigns it; it is a var only so the chaos gates can prove
// the refusal actually expires rather than waiting 30 s to watch it happen.
var scanTimeoutCooldown = 30 * time.Second

// scanBodyTimeoutOverride is a test seam for the scan budget. Production never
// sets it; ScanBodyTimeout stays the exported contract.
var scanBodyTimeoutOverride atomic.Int64

func scanBodyTimeout() time.Duration {
	if v := scanBodyTimeoutOverride.Load(); v > 0 {
		return time.Duration(v)
	}
	return ScanBodyTimeout
}

// clamScanError records a ClamAV mid-request scan failure: counter + webhook
// alert (deduped by the alerts store), mirroring the remote sidecar's
// remoteScanFail model (CHAOS-10). Fired on its own goroutine like
// remoteScanFail: Dispatch's semaphore-full path enqueues the retry with a
// synchronous disk write, and this runs inside ScanBody's fail-closed
// timeout — a saturated webhook queue must not turn the fail-open error
// path into a scan-timeout block.
func clamScanError(err error) {
	atomic.AddInt64(&statClamScanError, 1)
	go alerts.Fire("scan_clam_error", alerts.Payload{
		Source: "clamav",
		Detail: err.Error(),
	})
}

// clamContextScanner is the optional budget-aware scan capability.
// *clamav.Client implements it; test fakes need not, so it is type-asserted
// rather than folded into the required ClamScanner interface (same pattern as
// clamVersioner). A scanner without it keeps the legacy private-deadline
// behavior.
type clamContextScanner interface {
	ScanContext(ctx context.Context, data []byte) (name string, found bool, err error)
}

// runClam performs the ClamAV leg under the scan budget when the injected
// scanner supports it.
func runClam(ctx context.Context, clam ClamScanner, data []byte) (name string, found bool, err error) {
	if cs, ok := clam.(clamContextScanner); ok {
		return cs.ScanContext(ctx, data)
	}
	return clam.Scan(data)
}

// publishVerdict records a verdict in the hash cache under the tighten-only
// rule for abandoned scans.
//
// A scan whose caller already returned the fail-closed timeout verdict is
// ABANDONED, and an abandoned scan must never publish a CLEAN result: doing so
// silently converts a fail-closed refusal into a cached admission for the rest
// of the TTL, so whether a given object is blocked or served comes down to a
// race between the deadline and the scanner. A late BLOCK is still published —
// it can only tighten the cached verdict, and it upgrades the placeholder
// "scan timeout" entry to the real threat name.
func (ss *Scanner) publishVerdict(hash string, r hashcache.ScanCacheResult, abandoned *atomic.Bool) {
	if r.Clean && abandoned != nil && abandoned.Load() {
		noteLateCleanDiscarded(hash)
		return
	}
	ss.cache.Set(hash, r)
}

// noteLateCleanDiscarded records a clean verdict computed outside the scan
// budget and thrown away. It is a CORRECTNESS signal, not a liveness one: a
// non-zero value means content was refused by the deadline rather than judged
// by the engines, so a persistently non-zero counter says the scan budget (or
// the scanner behind it) no longer fits the traffic.
func noteLateCleanDiscarded(hash string) {
	atomic.AddInt64(&statScanLateDiscarded, 1)
	if degradedLogAllowed(&lastLateDiscardLog) {
		obs.Warnf("SecurityScan: discarding clean verdict for hash %s computed after the %s deadline (fail-closed decision stands); total %d",
			hash, scanBodyTimeout(), atomic.LoadInt64(&statScanLateDiscarded))
	}
}

// Every condition this file reports is one that recurs PER REQUEST for as long
// as the fault lasts, so the log line is rate-limited while the counter stays
// exact — the same count-everything / gate-the-noise discipline as
// storage_health.go and ca_health.go. Logging every occurrence would degrade
// the node hardest exactly when it is already saturated, which is the shape
// this whole change exists to remove.
const degradedLogInterval = time.Minute

var (
	lastLateDiscardLog atomic.Int64
	lastSaturatedLog   atomic.Int64
	lastAbandonedLog   atomic.Int64
)

// degradedLogAllowed reports whether enough time has passed since the last log
// line gated by last, and claims the slot if so.
func degradedLogAllowed(last *atomic.Int64) bool {
	now := time.Now().UnixNano()
	prev := last.Load()
	if prev != 0 && now-prev < int64(degradedLogInterval) {
		return false
	}
	return last.CompareAndSwap(prev, now)
}

// scanBodyInner runs ClamAV + YARA sequentially. Called from ScanBody under
// ctx, which carries the scan budget; abandoned reports whether the caller has
// already given up and returned the fail-closed verdict.
func (ss *Scanner) scanBodyInner(ctx context.Context, data []byte, hash string, abandoned *atomic.Bool) *Result {
	ss.mu.RLock()
	clam := ss.clam
	ss.mu.RUnlock()

	// ClamAV scan. An engine error (daemon crash mid-stream) falls through to
	// YARA — fail-open for THIS request, but counted + alerted, and the verdict
	// is never cached: a "clean" computed while ClamAV was dark would otherwise
	// keep admitting the same content by hash long after the daemon recovers.
	clamDark := false
	if clam != nil {
		name, found, err := runClam(ctx, clam, data)
		switch {
		case err != nil:
			clamDark = true
			ss.recordClamFailure(ctx, err)
		case found:
			atomic.AddInt64(&statClamBlocked, 1)
			ss.publishVerdict(hash, hashcache.ScanCacheResult{Clean: false, Reason: name, Source: "clamav"}, abandoned)
			return &Result{Blocked: true, Reason: name, Source: "clamav", Hash: hash}
		}
	}

	// YARA scan.
	if y := ss.yara; y != nil && y.Enabled() {
		if matches := y.Match(data); len(matches) > 0 {
			reason := strings.Join(matches, ", ")
			atomic.AddInt64(&statYARABlocked, 1)
			ss.publishVerdict(hash, hashcache.ScanCacheResult{Clean: false, Reason: reason, Source: "yara"}, abandoned)
			return &Result{Blocked: true, Reason: reason, Source: "yara", Hash: hash}
		}
	}

	// The budget is enforced from BOTH sides. ScanBody's select can observe a
	// completed scan and an expired deadline as simultaneously ready and pick
	// either — so without this check an overrun could be laundered into a
	// clean verdict by winning a coin flip. A scan that finishes outside its
	// budget returns the same fail-closed refusal its caller would have.
	if ctx.Err() != nil {
		noteLateCleanDiscarded(hash)
		return &Result{Blocked: true, Reason: "scan timeout", Source: "timeout", Hash: hash}
	}

	// Content is clean — cache the negative result, unless ClamAV errored:
	// a partial scan is not a clean verdict (the next occurrence rescans).
	if !clamDark {
		ss.publishVerdict(hash, hashcache.ScanCacheResult{Clean: true, Source: "clean"}, abandoned)
	}
	return nil
}

// recordClamFailure classifies a failed ClamAV leg. The three causes need
// different operator responses and must not share one counter or one alert:
//
//	budget exhausted — WE gave up (deadline/cancel). Not a daemon fault at all;
//	                   alerting on it turns one slow-scanner incident into an
//	                   alert storm blaming a healthy daemon.
//	queue full       — the daemon is healthy, this node is at capacity. The fix
//	                   is capacity, and it is now charged to the caller's
//	                   budget, so it lands on the fail-closed timeout path
//	                   rather than the fail-open engine-error path.
//	engine error     — a genuine daemon fault: counted + alerted as before.
func (ss *Scanner) recordClamFailure(ctx context.Context, err error) {
	switch {
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		if errors.Is(err, clamav.ErrQueueFull) {
			ss.noteClamSaturated(err, "scan budget exhausted while queued")
			return
		}
		if degradedLogAllowed(&lastAbandonedLog) {
			obs.Printf("SecurityScan: ClamAV scan abandoned at the scan deadline: %s", strings.ReplaceAll(err.Error(), "\n", " "))
		}
	case errors.Is(err, clamav.ErrQueueFull):
		ss.noteClamSaturated(err, "no slot available")
	default:
		clamScanError(err)
		obs.Printf("ERROR SecurityScan: ClamAV error: %s", strings.ReplaceAll(err.Error(), "\n", " "))
	}
}

// noteClamSaturated counts a capacity refusal and logs it at most once per
// degradedLogInterval. The counter carries the magnitude; the line carries the
// explanation.
func (ss *Scanner) noteClamSaturated(err error, why string) {
	atomic.AddInt64(&statClamSaturated, 1)
	if degradedLogAllowed(&lastSaturatedLog) {
		obs.Warnf("SecurityScan: ClamAV at capacity (%s) — %s; total %d",
			strings.ReplaceAll(err.Error(), "\n", " "), why, atomic.LoadInt64(&statClamSaturated))
	}
}

// ── Cache accessors (ADR-0006) ──────────────────────────────────────────────
// Consumers (admin API, metrics, OTLP) go through these instead of reaching
// into the cache field, so the orchestrator owns its cache. All are
// nil-tolerant (scanner or cache not yet initialised).

// CacheStats returns hash-cache hit/miss counters and current size.
func (ss *Scanner) CacheStats() (hits, misses int64, size int) {
	if ss == nil || ss.cache == nil {
		return 0, 0, 0
	}
	return ss.cache.Stats()
}

// CacheReady reports whether the scan hash cache is initialised.
func (ss *Scanner) CacheReady() bool { return ss != nil && ss.cache != nil }

// CacheClear empties the scan hash cache.
func (ss *Scanner) CacheClear() {
	if ss != nil && ss.cache != nil {
		ss.cache.Clear()
	}
}

// CacheEvict removes a single hash from the scan cache, reporting whether it
// was present.
func (ss *Scanner) CacheEvict(hash string) bool {
	if ss == nil || ss.cache == nil {
		return false
	}
	return ss.cache.Evict(hash)
}

// CacheSet stores a scan verdict directly (test support and remote-scan
// result adoption).
func (ss *Scanner) CacheSet(hash string, r hashcache.ScanCacheResult) {
	if ss != nil && ss.cache != nil {
		ss.cache.Set(hash, r)
	}
}

// CacheGet looks up a scan verdict (test support).
func (ss *Scanner) CacheGet(hash string) (hashcache.ScanCacheResult, bool) {
	if ss == nil || ss.cache == nil {
		return hashcache.ScanCacheResult{}, false
	}
	return ss.cache.Get(hash)
}
