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
//   - ClamAV is skipped when no address is configured. A configured-but-failing
//     daemon is governed by the on-scan-error posture (default fail-closed).
//   - YARA is skipped when no matcher is injected or it reports not loaded.
//   - Threat feeds are skipped when no checker is injected or it is disabled.
package secscan

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
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

// ── Scan-error posture (CHAOS-10) ────────────────────────────────────────────
// What happens when a configured scanner CANNOT scan (ClamAV daemon error
// mid-stream, remote scan sidecar unreachable) and no other engine produced a
// verdict. The scan TIMEOUT is a separate, unconditionally fail-closed path;
// this posture governs scanner-infrastructure errors only. Default fail_closed
// matches the timeout posture and the YARA on_timeout/on_saturation defaults:
// an attacker who can crash the scanner must not thereby pass unscanned.

// Posture values (same vocabulary as internal/yara).
const (
	FailClosed        = "fail_closed"
	FailOpenWithAlert = "fail_open_with_alert"
)

// scanOnErrorVar holds the current posture ("" is treated as FailClosed).
var scanOnErrorVar atomic.Value // string

// GetOnScanError returns the on-scan-error posture (FailClosed | FailOpenWithAlert).
func GetOnScanError() string {
	if v, ok := scanOnErrorVar.Load().(string); ok && v != "" {
		return v
	}
	return FailClosed
}

// SetOnScanError sets the on-scan-error posture (FailClosed | FailOpenWithAlert).
func SetOnScanError(v string) { scanOnErrorVar.Store(v) }

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
	statRemoteScanFail    int64 // remote scan sidecar failures (posture-governed)
	statScanError         int64 // scanner-infrastructure errors (ClamAV error + remote fail), CHAOS-10
)

// CounterSnapshot is a point-in-time copy of the scan counters.
type CounterSnapshot struct {
	ClamBlocked       int64
	YARABlocked       int64
	ThreatFeedBlocked int64
	ScanTimeout       int64
	ScanSkipped       int64
	RemoteScanFail    int64
	ScanError         int64
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
		ScanError:         atomic.LoadInt64(&statScanError),
	}
}

// AddScanSkipped records a response forwarded unscanned because it exceeded
// the scan buffer limit (incremented by package main's logScanLimitExceeded).
func AddScanSkipped() { atomic.AddInt64(&statScanSkipped, 1) }

// AddRemoteScanFail records a remote scan sidecar failure (incremented by the
// remote scanner client in package main).
func AddRemoteScanFail() { atomic.AddInt64(&statRemoteScanFail, 1) }

// AddScanError records a scanner-infrastructure error (a configured scanner
// could not scan). Incremented by the in-process pipeline (ClamAV error) and
// the remote scan client; exported for the plain-HTTP scan path in package
// main. Feeds culvert_scan_errors_total (CHAOS-10/17).
func AddScanError() { atomic.AddInt64(&statScanError, 1) }

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
	enabled  bool

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
	ss.enabled = true
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
func (ss *Scanner) Enabled() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.enabled
}

// BodyScanEnabled reports whether body scanning (ClamAV and/or YARA) is active.
func (ss *Scanner) BodyScanEnabled() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.enabled && (ss.clam != nil || (ss.yara != nil && ss.yara.Loaded()))
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
	ch := make(chan *Result, 1)
	go func() {
		ch <- ss.scanBodyInner(data, hash)
	}()

	select {
	case result := <-ch:
		return result
	case <-time.After(ScanBodyTimeout):
		atomic.AddInt64(&statScanTimeout, 1)
		obs.Warnf("SecurityScan: ScanBody timeout after %s for hash %s — blocking (fail-closed)", ScanBodyTimeout, hash)
		ss.cache.Set(hash, hashcache.ScanCacheResult{Clean: false, Reason: "scan timeout", Source: "timeout"})
		return &Result{Blocked: true, Reason: "scan timeout", Source: "timeout", Hash: hash}
	}
}

// scanBodyInner runs ClamAV + YARA sequentially. Called from ScanBody under a timeout.
//
// CHAOS-10: a ClamAV daemon error mid-stream no longer degrades silently. The
// remaining engines still run first — a real YARA verdict beats a generic
// error block and remains valid (and cacheable) regardless of which engine
// missed its turn. But when NO real engine produced a verdict under a failed
// scanner, the outcome is posture-governed (GetOnScanError, default
// fail-closed — consistent with the scan-timeout path) and NEVER cached:
// caching "clean" here poisoned the hash cache for the TTL, so content that
// slipped past a crashed daemon stayed unscanned even after recovery.
func (ss *Scanner) scanBodyInner(data []byte, hash string) *Result {
	ss.mu.RLock()
	clam := ss.clam
	ss.mu.RUnlock()

	scanErrored := false
	scanErrDetail := ""

	// ClamAV scan.
	if clam != nil {
		name, found, err := clam.Scan(data)
		if err != nil {
			atomic.AddInt64(&statScanError, 1)
			scanErrored = true
			scanErrDetail = "clamav error: " + strings.ReplaceAll(err.Error(), "\n", " ")
			obs.Printf("ERROR SecurityScan: ClamAV error: %s", strings.ReplaceAll(err.Error(), "\n", " "))
			go alerts.Fire("scan_error", alerts.Payload{
				Source: "clamav",
				Detail: scanErrDetail + " — posture: " + GetOnScanError(),
			})
		} else if found {
			atomic.AddInt64(&statClamBlocked, 1)
			ss.cache.Set(hash, hashcache.ScanCacheResult{Clean: false, Reason: name, Source: "clamav"})
			return &Result{Blocked: true, Reason: name, Source: "clamav", Hash: hash}
		}
	}

	// YARA scan.
	if y := ss.yara; y != nil && y.Enabled() {
		if matches := y.Match(data); len(matches) > 0 {
			reason := strings.Join(matches, ", ")
			atomic.AddInt64(&statYARABlocked, 1)
			ss.cache.Set(hash, hashcache.ScanCacheResult{Clean: false, Reason: reason, Source: "yara"})
			return &Result{Blocked: true, Reason: reason, Source: "yara", Hash: hash}
		}
	}

	if scanErrored {
		// A configured scanner failed and nothing else blocked. The verdict is
		// posture-decided and deliberately NOT cached in either direction: a
		// transient daemon failure must neither poison the cache with a false
		// "clean" nor pin a hash as blocked after the daemon recovers.
		if GetOnScanError() != FailOpenWithAlert {
			return &Result{Blocked: true, Reason: scanErrDetail, Source: "scan_error", Hash: hash}
		}
		return nil
	}

	// Content is clean — cache the negative result.
	ss.cache.Set(hash, hashcache.ScanCacheResult{Clean: true, Source: "clean"})
	return nil
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
