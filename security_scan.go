package main

// SecurityScanner — orchestrates ClamAV, YARA, and threat-feed checks.
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
//   - YARA is skipped when no rules directory is set or the directory is empty.
//   - Threat feeds are skipped when Init has not been called.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/scanexcl"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// maxDecompressBytes limits decompressed data to 64 MB to guard against gzip bombs.
const maxDecompressBytes = 64 << 20

// zstdDecoderPool reuses zstd decoders to avoid allocating ~1-8 MB of internal
// buffers per response. Decoders are reset with Reset() before reuse.
var zstdDecoderPool = sync.Pool{
	New: func() any {
		d, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1)) //nolint:errcheck // nil reader is valid for pool initialization
		return d
	},
}

// scanBodyTimeout caps the total time for all body scanners (ClamAV + YARA).
// If the combined scan doesn't finish in time, the content is blocked (fail-closed).
const scanBodyTimeout = 10 * time.Second

// ── Prometheus counters ───────────────────────────────────────────────────────

var (
	statClamBlocked       int64 // requests blocked by ClamAV
	statYARABlocked       int64 // requests blocked by YARA rules
	statThreatFeedBlocked int64 // requests blocked by threat intel feeds
	statScanTimeout       int64 // body scans that hit scanBodyTimeout (fail-closed)
	statScanSkipped       int64 // responses forwarded unscanned (size > maxBytes)
	statRemoteScanFail    int64 // remote scan sidecar failures (fail-open)
)

// ── SecurityScanner ───────────────────────────────────────────────────────────

// SecurityScanResult describes the outcome of a scan that triggered a block.
type SecurityScanResult struct {
	Blocked bool
	Reason  string // virus name, YARA rule name, or feed source
	Source  string // "clamav", "yara", or "threatfeed"
	Hash    string // SHA-256 hex of scanned content (body scans only)
}

// ── Collaborator contracts (ADR-0006 Slice 1) ────────────────────────────────
// The orchestrator owns the narrow interfaces it needs; the engines stay
// interface-free. Production wiring adapts the existing singletons; tests
// inject in-memory fakes via NewSecurityScanner.

// clamScanner is the ClamAV surface ScanBody/ClamAVStatus need.
type clamScanner interface {
	Ping() error
	Scan(data []byte) (name string, found bool, err error)
}

// yaraMatcher is the YARA surface the scan pipeline needs. Loaded and Enabled
// are deliberately distinct to preserve pre-ADR-0006 behavior verbatim:
// BodyScanEnabled keys on rules-present only (Loaded), while scanBodyInner
// additionally honors the runtime enable toggle (Enabled).
type yaraMatcher interface {
	Loaded() bool
	Enabled() bool
	Match(data []byte) []string
}

// threatChecker is the threat-feed surface CheckURL/CheckDomain need.
type threatChecker interface {
	Enabled() bool
	CheckURL(rawURL string) (bool, string)
	CheckDomain(domain string) (bool, string)
}

// hashExcluder is the admin hash-allowlist surface ScanBody needs.
type hashExcluder interface{ IsHashExcluded(hash string) bool }

// yaraRuleSetMatcher adapts a YARARuleSet plus the runtime enable toggle to
// the yaraMatcher contract.
type yaraRuleSetMatcher struct{ rs *YARARuleSet }

func (m yaraRuleSetMatcher) Loaded() bool               { return m.rs.Enabled() }
func (m yaraRuleSetMatcher) Enabled() bool              { return yaraGetEnabled() && m.rs.Enabled() }
func (m yaraRuleSetMatcher) Match(data []byte) []string { return m.rs.Match(data) }

// SecurityScanner ties together ClamAV, YARA, the threat feed, and the hash
// cache into a single, easy-to-use interface for the proxy pipeline.
type SecurityScanner struct {
	mu       sync.RWMutex
	clam     clamScanner
	yara     yaraMatcher   // nil → globalYARA (+ runtime toggle)
	feed     threatChecker // nil → globalThreatFeed
	excl     hashExcluder  // nil → globalScanExclusions
	cache    *HashCache
	maxBytes int64 // max bytes to buffer per response for body scanning
	enabled  bool

	// Tier 2.3: ClamAV ping cache. Protects the admin dashboard from
	// opening a fresh TCP connection to ClamAV on every status poll.
	clamStatusVal    string
	clamStatusExpiry time.Time
}

// secScannerDeps carries the injectable collaborators for NewSecurityScanner.
// Nil fields fall back to the process-wide singletons, so partial injection
// (e.g. only a fake ClamAV) is fine.
type secScannerDeps struct {
	clam     clamScanner
	yara     yaraMatcher
	feed     threatChecker
	excl     hashExcluder
	cache    *HashCache
	maxBytes int64
}

// NewSecurityScanner builds a ready-to-use scanner from injected
// collaborators (ADR-0006). Unlike the globalSecScanner+Init path it is
// enabled on construction; it exists for tests today and future callers.
func NewSecurityScanner(deps secScannerDeps) *SecurityScanner {
	ss := &SecurityScanner{
		clam:     deps.clam,
		yara:     deps.yara,
		feed:     deps.feed,
		excl:     deps.excl,
		cache:    deps.cache,
		maxBytes: deps.maxBytes,
		enabled:  true,
	}
	if ss.cache == nil {
		ss.cache = newHashCache(10_000, 0)
	}
	if ss.maxBytes <= 0 {
		ss.maxBytes = 5 << 20
	}
	return ss
}

// yaraDep / feedDep / exclDep return the injected collaborator or the
// production singleton when unset. The nil-defaulting keeps existing
// &SecurityScanner{...} literals (tests, globalSecScanner) behaving exactly
// as before injection existed.
func (ss *SecurityScanner) yaraDep() yaraMatcher {
	if ss.yara != nil {
		return ss.yara
	}
	return yaraRuleSetMatcher{globalYARA}
}

func (ss *SecurityScanner) feedDep() threatChecker {
	if ss.feed != nil {
		return ss.feed
	}
	return globalThreatFeed
}

func (ss *SecurityScanner) exclDep() hashExcluder {
	if ss.excl != nil {
		return ss.excl
	}
	return globalScanExclusions
}

// clamStatusTTL is how long a successful ClamAV ping result is considered fresh.
const clamStatusTTL = 30 * time.Second

// globalSecScanner is the process-wide scanner, initialised in main.go.
var globalSecScanner = &SecurityScanner{
	cache:    newHashCache(10_000, 0), // TTL overridden in Init
	maxBytes: 5 << 20,                 // 5 MiB default
}

// ── ScanExclusionStore (moved to internal/scanexcl, ADR-0002) ──────────────────

// ScanExclusionStore is the package-main alias for the relocated admin-managed
// allowlist store, so the consumers (main.go Load, proxy.go IsHostExcluded,
// ui_security.go Lists/Replace/Save) and ScanBody's IsHashExcluded check stay
// unqualified.
type ScanExclusionStore = scanexcl.Store

// globalScanExclusions is the process-wide exclusion store.
var globalScanExclusions = scanexcl.New()

// Init configures the scanner.
//
//	clamAddr — ClamAV address string (see NewClamAV); "" disables ClamAV.
//	maxBytes — maximum bytes to buffer per response (0 = use default 5 MiB).
//	cache    — hash cache to adopt; nil keeps the current one (ADR-0006: the
//	           cache is handed over here instead of being poked from outside).
func (ss *SecurityScanner) Init(clamAddr string, maxBytes int64, cache *HashCache) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if maxBytes > 0 {
		ss.maxBytes = maxBytes
	}
	if cache != nil {
		ss.cache = cache
	}
	if clamAddr != "" {
		ss.clam = NewClamAV(clamAddr)
		if err := ss.clam.Ping(); err != nil {
			logger.Printf("SecurityScan: ClamAV unreachable at %q (%v) — retrying per request", clamAddr, err)
		} else {
			logInfof("SecurityScan: ClamAV connected at %q", clamAddr)
		}
	}
	ss.enabled = true
	// Tier 2.3: Invalidate any cached clam status so the first admin poll
	// after reconfiguration runs a real ping.
	ss.clamStatusVal = ""
	ss.clamStatusExpiry = time.Time{}
}

// Enabled reports whether the scanner has been initialised.
func (ss *SecurityScanner) Enabled() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.enabled
}

// BodyScanEnabled reports whether body scanning (ClamAV and/or YARA) is active.
func (ss *SecurityScanner) BodyScanEnabled() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.enabled && (ss.clam != nil || ss.yaraDep().Loaded())
}

// MaxBytes returns the buffer limit for body scanning.
func (ss *SecurityScanner) MaxBytes() int64 {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.maxBytes
}

// ClamAVStatus returns a human-readable daemon connectivity string.
// Tier 2.3: Result is cached for clamStatusTTL to avoid hammering the ClamAV
// daemon on every admin dashboard poll. Cache is invalidated on Init().
func (ss *SecurityScanner) ClamAVStatus() string {
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

// ── URL / domain checks ───────────────────────────────────────────────────────

// CheckURL checks a full URL against the threat feed.
// Returns nil when no threat is found.
func (ss *SecurityScanner) CheckURL(rawURL string) *SecurityScanResult {
	feed := ss.feedDep()
	if !feed.Enabled() {
		return nil
	}
	if ok, source := feed.CheckURL(rawURL); ok {
		atomic.AddInt64(&statThreatFeedBlocked, 1)
		return &SecurityScanResult{
			Blocked: true,
			Reason:  "threat intelligence (" + source + ")",
			Source:  "threatfeed",
		}
	}
	return nil
}

// CheckDomain checks a bare hostname against the threat feed.
// Returns nil when no threat is found.
func (ss *SecurityScanner) CheckDomain(domain string) *SecurityScanResult {
	feed := ss.feedDep()
	if !feed.Enabled() {
		return nil
	}
	if ok, source := feed.CheckDomain(domain); ok {
		atomic.AddInt64(&statThreatFeedBlocked, 1)
		return &SecurityScanResult{
			Blocked: true,
			Reason:  "threat intelligence (" + source + ")",
			Source:  "threatfeed",
		}
	}
	return nil
}

// ── Body decompression (1.1 fix) ──────────────────────────────────────────────

// decompressForScan transparently decompresses a response body based on its
// Content-Encoding header so that ClamAV/YARA signatures can match the actual
// content. Supports gzip, deflate, and identity (no-op). Brotli ("br") is
// attempted as gzip (some servers mislabel); on failure the raw bytes are
// returned so the scan still runs (defense in depth).
//
// Returned data is limited to maxDecompressBytes to guard against gzip bombs.
// If decompression fails, the original data is returned unchanged — the scan
// still runs on compressed bytes (fail-open for availability, but the
// signature gap is closed for the common case).
func decompressForScan(data []byte, contentEncoding string) []byte {
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
		decompressed, zReadErr := io.ReadAll(io.LimitReader(zr, maxDecompressBytes))
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

	decompressed, err := io.ReadAll(io.LimitReader(reader, maxDecompressBytes))
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
// The entire scan is bounded by scanBodyTimeout (fail-closed: blocks on timeout).
// Returns nil when the content is clean (or no scanner is enabled).
func (ss *SecurityScanner) ScanBody(data []byte) *SecurityScanResult {
	if !ss.BodyScanEnabled() || len(data) == 0 {
		return nil
	}
	hash := SHA256Hex(data)

	// Tier 3.3: admin-managed hash allowlist. If the content hash is
	// explicitly trusted, skip all scanning.
	if ss.exclDep().IsHashExcluded(hash) {
		return nil
	}

	// Cache hit?
	if cached, ok := ss.cache.Get(hash); ok {
		if !cached.Clean {
			return &SecurityScanResult{
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
	ch := make(chan *SecurityScanResult, 1)
	go func() {
		ch <- ss.scanBodyInner(data, hash)
	}()

	select {
	case result := <-ch:
		return result
	case <-time.After(scanBodyTimeout):
		atomic.AddInt64(&statScanTimeout, 1)
		logWarnf("SecurityScan: ScanBody timeout after %s for hash %s — blocking (fail-closed)", scanBodyTimeout, hash)
		ss.cache.Set(hash, ScanCacheResult{Clean: false, Reason: "scan timeout", Source: "timeout"})
		return &SecurityScanResult{Blocked: true, Reason: "scan timeout", Source: "timeout", Hash: hash}
	}
}

// scanBodyInner runs ClamAV + YARA sequentially. Called from ScanBody under a timeout.
func (ss *SecurityScanner) scanBodyInner(data []byte, hash string) *SecurityScanResult {
	ss.mu.RLock()
	clam := ss.clam
	ss.mu.RUnlock()

	// ClamAV scan.
	if clam != nil {
		name, found, err := clam.Scan(data)
		if err != nil {
			logErrorf("SecurityScan: ClamAV error: %s", strings.ReplaceAll(err.Error(), "\n", " "))
		} else if found {
			atomic.AddInt64(&statClamBlocked, 1)
			ss.cache.Set(hash, ScanCacheResult{Clean: false, Reason: name, Source: "clamav"})
			return &SecurityScanResult{Blocked: true, Reason: name, Source: "clamav", Hash: hash}
		}
	}

	// YARA scan.
	if y := ss.yaraDep(); y.Enabled() {
		if matches := y.Match(data); len(matches) > 0 {
			reason := strings.Join(matches, ", ")
			atomic.AddInt64(&statYARABlocked, 1)
			ss.cache.Set(hash, ScanCacheResult{Clean: false, Reason: reason, Source: "yara"})
			return &SecurityScanResult{Blocked: true, Reason: reason, Source: "yara", Hash: hash}
		}
	}

	// Content is clean — cache the negative result.
	ss.cache.Set(hash, ScanCacheResult{Clean: true, Source: "clean"})
	return nil
}

// ── Cache accessors (ADR-0006) ──────────────────────────────────────────────
// Production consumers (ui_security.go, metrics.go, otlp.go) go through these
// instead of reaching into the cache field, so the orchestrator owns its
// cache. All three are nil-tolerant (scanner or cache not yet initialised).

// CacheStats returns hash-cache hit/miss counters and current size.
func (ss *SecurityScanner) CacheStats() (hits, misses int64, size int) {
	if ss == nil || ss.cache == nil {
		return 0, 0, 0
	}
	return ss.cache.Stats()
}

// CacheReady reports whether the scan hash cache is initialised.
func (ss *SecurityScanner) CacheReady() bool { return ss != nil && ss.cache != nil }

// CacheClear empties the scan hash cache.
func (ss *SecurityScanner) CacheClear() {
	if ss != nil && ss.cache != nil {
		ss.cache.Clear()
	}
}

// CacheEvict removes a single hash from the scan cache, reporting whether it
// was present.
func (ss *SecurityScanner) CacheEvict(hash string) bool {
	if ss == nil || ss.cache == nil {
		return false
	}
	return ss.cache.Evict(hash)
}

// ── Panic-safe scan wrappers ────────────────────────────────────────────────
// These wrappers prevent panics in scan engines (ClamAV, YARA, DPI regex)
// from crashing the request handler goroutine.

// safeScanBody wraps globalSecScanner.ScanBody with panic recovery.
// When a remote scan service is configured, it delegates to the sidecar instead.
func safeScanBody(data []byte) (result *SecurityScanResult) {
	defer func() {
		if r := recover(); r != nil {
			logErrorf("SecurityScan: panic in ScanBody recovered: %v", r)
			result = nil
		}
	}()
	if globalRemoteScanner.Enabled() {
		return globalRemoteScanner.ScanBody(data, "")
	}
	return globalSecScanner.ScanBody(data)
}

// safeScanBodyWithCT is like safeScanBody but passes a content type hint
// to the remote scanner so it can also apply DPI checks.
func safeScanBodyWithCT(data []byte, contentType string) (result *SecurityScanResult) {
	defer func() {
		if r := recover(); r != nil {
			logErrorf("SecurityScan: panic in ScanBody recovered: %v", r)
			result = nil
		}
	}()
	if globalRemoteScanner.Enabled() {
		return globalRemoteScanner.ScanBody(data, contentType)
	}
	return globalSecScanner.ScanBody(data)
}

// safeDPIScan wraps dpiScanner.Scan with panic recovery.
// When a remote scan service is configured, DPI is handled by safeScanBodyWithCT.
func safeDPIScan(data []byte) (pattern string, matched bool) {
	defer func() {
		if r := recover(); r != nil {
			logErrorf("SecurityScan: panic in DPI scan recovered: %v", r)
			pattern = ""
			matched = false
		}
	}()
	return dpiScanner.Scan(data)
}

// ── HTTP response helpers ─────────────────────────────────────────────────────

// scanBlock sends a 403 Forbidden response to a plain http.ResponseWriter.
func scanBlock(w http.ResponseWriter, host, reason, source string) {
	logger.Printf("SecurityScan: blocked host=%s source=%s reason=%q", host, source, reason)
	body := fmt.Sprintf("Blocked by %s scan: %s", strings.ToUpper(source), reason)
	http.Error(w, body, http.StatusForbidden)
}

// scanBlockConn sends a 403 Forbidden HTTP/1.1 response to a raw connection
// (used inside SSL-inspect tunnels where http.ResponseWriter is not available).
func scanBlockConn(dst interface{ Write([]byte) (int, error) }, host, reason, source string) {
	logger.Printf("SecurityScan: blocked host=%s source=%s reason=%q", host, source, reason)
	body := fmt.Sprintf("Blocked by %s scan: %s\r\n", strings.ToUpper(source), reason)
	fmt.Fprintf(dst, //nolint:errcheck
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		len(body), body,
	)
}

// ── Buffer sizing helpers ─────────────────────────────────────────────────────

// maxScanBufferBytes returns the maximum bytes to buffer for scanning, taking
// the larger of the DPI scanner limit and the security scanner limit.
func maxScanBufferBytes() int64 {
	dpi := dpiScanner.MaxBytes()
	sec := globalSecScanner.MaxBytes()
	if sec > dpi {
		return sec
	}
	return dpi
}

// logScanLimitExceeded logs a warning and fires a "scan_skipped" alert when a
// response body exceeds the scan buffer limit and is therefore forwarded
// without ClamAV/YARA/DPI inspection (Finding 4.2).
// Tier 1.2: also increments the statScanSkipped counter so the status API
// exposes size-skipped events without grepping logs.
func logScanLimitExceeded(host, clientIP string, maxBytes int64) {
	atomic.AddInt64(&statScanSkipped, 1)
	if logger != nil {
		logger.Printf("SCAN: response from %s exceeds scan limit (%d bytes), forwarded unscanned", sanitizeLog(host), maxBytes)
	}
	go alerts.Fire("scan_skipped", alerts.Payload{
		Actor:  clientIP,
		Host:   host,
		Detail: fmt.Sprintf("response exceeds scan limit (%d bytes)", maxBytes),
		Source: "size_limit",
	})
}

// bodyNeedsBuffering reports whether a response body must be fully buffered
// before forwarding, based on the active scanners and the content type.
func bodyNeedsBuffering(contentType string) bool {
	// Remote scan service handles all scan types.
	if globalRemoteScanner.Enabled() {
		return true
	}
	if dpiScanner.Enabled() && isTextContentType(contentType) {
		return true
	}
	if globalSecScanner.BodyScanEnabled() {
		return true // ClamAV handles binary content as well as text
	}
	return false
}

// ── Admin / monitoring helpers ────────────────────────────────────────────────

// secScanStatusMap returns a map suitable for JSON serialisation by the
// /api/security-scan/status endpoint.
func secScanStatusMap() map[string]interface{} {
	// When remote scanner is active, fetch status from the sidecar.
	if globalRemoteScanner.Enabled() {
		m := map[string]interface{}{
			"enabled":       true,
			"scan_svc_mode": "remote",
			"scan_svc_url":  globalRemoteScanner.URL(),
		}
		if status, err := globalRemoteScanner.Status(); err == nil {
			for k, v := range status {
				m[k] = v
			}
			m["scan_svc_degraded"] = false
		} else {
			m["scan_svc_status"] = fmt.Sprintf("unreachable: %v", err)
			m["scan_svc_degraded"] = true
		}
		// Always include local threat feed stats (feeds run locally even with remote scanning).
		feedTotal, feedLastSync, feedInterval := globalThreatFeed.Stats()
		m["threat_feed_entries"] = feedTotal
		m["threat_feed_last_sync"] = feedLastSync
		m["threat_feed_interval"] = feedInterval.String()
		m["stat_feed_blocked"] = atomic.LoadInt64(&statThreatFeedBlocked)
		// Tier 2.2: surface remote sidecar failure counter even when scan_svc_mode=remote.
		m["stat_remote_scan_fail"] = atomic.LoadInt64(&statRemoteScanFail)
		return m
	}

	feedTotal, feedLastSync, feedInterval := globalThreatFeed.Stats()
	hits, misses, cacheSize := globalSecScanner.CacheStats()
	return map[string]interface{}{
		"enabled":               globalSecScanner.Enabled(),
		"scan_svc_mode":         "local",
		"clamav_status":         globalSecScanner.ClamAVStatus(),
		"yara_rules":            globalYARA.Count(),
		"yara_warnings":         len(globalYARA.Warnings()), // Tier 2.1
		"yara_inflight":         yaraInflightLoad(),         // Tier 1.3
		"yara_inflight_max":     yaraGetMaxInflight(),       // Tier 1.3
		"yara_enabled":          yaraGetEnabled(),
		"yara_timeout_secs":     yaraGetTimeoutSecs(),
		"yara_on_timeout":       yaraGetOnTimeout(),
		"yara_on_saturation":    yaraGetOnSaturation(),
		"yara_alert_degraded":   yaraGetAlertDegraded(),
		"threat_feed_entries":   feedTotal,
		"threat_feed_last_sync": feedLastSync,
		"threat_feed_interval":  feedInterval.String(),
		"cache_size":            cacheSize,
		"cache_hits":            hits,
		"cache_misses":          misses,
		"stat_clam_blocked":     atomic.LoadInt64(&statClamBlocked),
		"stat_yara_blocked":     atomic.LoadInt64(&statYARABlocked),
		"stat_feed_blocked":     atomic.LoadInt64(&statThreatFeedBlocked),
		"stat_scan_timeout":     atomic.LoadInt64(&statScanTimeout),    // Tier 1.2
		"stat_scan_skipped":     atomic.LoadInt64(&statScanSkipped),    // Tier 1.2
		"stat_remote_scan_fail": atomic.LoadInt64(&statRemoteScanFail), // Tier 2.2
	}
}
