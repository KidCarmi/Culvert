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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// SecurityScanner ties together ClamAV, YARA, the threat feed, and the hash
// cache into a single, easy-to-use interface for the proxy pipeline.
type SecurityScanner struct {
	mu       sync.RWMutex
	clam     *ClamAV
	cache    *HashCache
	maxBytes int64 // max bytes to buffer per response for body scanning
	enabled  bool

	// Tier 2.3: ClamAV ping cache. Protects the admin dashboard from
	// opening a fresh TCP connection to ClamAV on every status poll.
	clamStatusVal    string
	clamStatusExpiry time.Time
}

// clamStatusTTL is how long a successful ClamAV ping result is considered fresh.
const clamStatusTTL = 30 * time.Second

// globalSecScanner is the process-wide scanner, initialised in main.go.
var globalSecScanner = &SecurityScanner{
	cache:    newHashCache(10_000, 0), // TTL overridden in Init
	maxBytes: 5 << 20,                 // 5 MiB default
}

// ── ScanExclusionStore (Tier 3.3) ─────────────────────────────────────────────

// ScanExclusionStore holds admin-managed exclusions: known-good SHA-256
// content hashes and hostnames that bypass all body scanning. It is designed
// for an extreme read:write ratio (IsHashExcluded / IsHostExcluded are called
// on every request; writes happen only when an admin updates the lists), so
// it uses sync.RWMutex per CLAUDE.md's read-heavy store convention.
type ScanExclusionStore struct {
	mu     sync.RWMutex
	hashes map[string]bool
	hosts  map[string]bool
	path   string // JSON file for persistence (optional)
}

// scanExclusionsFile is the on-disk JSON envelope for ScanExclusionStore.
type scanExclusionsFile struct {
	Hashes []string `json:"hashes"`
	Hosts  []string `json:"hosts"`
}

// globalScanExclusions is the process-wide exclusion store.
var globalScanExclusions = &ScanExclusionStore{
	hashes: map[string]bool{},
	hosts:  map[string]bool{},
}

// Load reads the JSON file at path into the store. Missing file is not an error.
func (s *ScanExclusionStore) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	data, err := os.ReadFile(path) // #nosec G304 -- admin-configured path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scan exclusions read: %w", err)
	}
	var f scanExclusionsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("scan exclusions parse: %w", err)
	}
	s.mu.Lock()
	s.hashes = make(map[string]bool, len(f.Hashes))
	for _, h := range f.Hashes {
		s.hashes[strings.ToLower(h)] = true
	}
	s.hosts = make(map[string]bool, len(f.Hosts))
	for _, h := range f.Hosts {
		s.hosts[stripHostPort(strings.ToLower(h))] = true
	}
	s.mu.Unlock()
	return nil
}

// Save persists the exclusion lists to the configured file path using an
// atomic tmp+rename write. No-op if no path configured.
func (s *ScanExclusionStore) Save() error {
	s.mu.RLock()
	path := s.path
	f := scanExclusionsFile{
		Hashes: make([]string, 0, len(s.hashes)),
		Hosts:  make([]string, 0, len(s.hosts)),
	}
	for h := range s.hashes {
		f.Hashes = append(f.Hashes, h)
	}
	for h := range s.hosts {
		f.Hosts = append(f.Hosts, h)
	}
	s.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { // #nosec G306
		return err
	}
	return os.Rename(tmp, path)
}

// Replace atomically swaps the exclusion lists, normalising to lower case.
func (s *ScanExclusionStore) Replace(hashes, hosts []string) {
	hmap := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			hmap[h] = true
		}
	}
	hostMap := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = stripHostPort(strings.TrimSpace(strings.ToLower(h)))
		if h != "" {
			hostMap[h] = true
		}
	}
	s.mu.Lock()
	s.hashes = hmap
	s.hosts = hostMap
	s.mu.Unlock()
}

// IsHashExcluded reports whether the SHA-256 hex is on the hash allowlist.
// Hot path: called on every ScanBody invocation. RLock-only.
func (s *ScanExclusionStore) IsHashExcluded(hash string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hashes[strings.ToLower(hash)]
}

// IsHostExcluded reports whether the hostname is on the host allowlist.
// Hot path: called once per proxied HTTP request before buffering. RLock-only.
func (s *ScanExclusionStore) IsHostExcluded(host string) bool {
	if s == nil || host == "" {
		return false
	}
	// Strip port suffix and IPv6 brackets if present.
	host = stripHostPort(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hosts[strings.ToLower(host)]
}

// Lists returns copies of the current hash and host lists, sorted for stable
// admin output.
func (s *ScanExclusionStore) Lists() (hashes []string, hosts []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hashes = make([]string, 0, len(s.hashes))
	for h := range s.hashes {
		hashes = append(hashes, h)
	}
	hosts = make([]string, 0, len(s.hosts))
	for h := range s.hosts {
		hosts = append(hosts, h)
	}
	sortStrings(hashes)
	sortStrings(hosts)
	return hashes, hosts
}

// sortStrings is a tiny helper to avoid pulling sort into this file's imports
// when only ScanExclusionStore needs it.
func sortStrings(s []string) {
	// Insertion sort — exclusion lists are short (dozens of entries) so the
	// constant-factor cost of reflection-based sort.Strings is not worth it.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Init configures the scanner.
//
//	clamAddr — ClamAV address string (see NewClamAV); "" disables ClamAV.
//	maxBytes — maximum bytes to buffer per response (0 = use default 5 MiB).
func (ss *SecurityScanner) Init(clamAddr string, maxBytes int64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if maxBytes > 0 {
		ss.maxBytes = maxBytes
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
	return ss.enabled && (ss.clam != nil || globalYARA.Enabled())
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
	if !globalThreatFeed.Enabled() {
		return nil
	}
	if ok, source := globalThreatFeed.CheckURL(rawURL); ok {
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
	if !globalThreatFeed.Enabled() {
		return nil
	}
	if ok, source := globalThreatFeed.CheckDomain(domain); ok {
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
	if globalScanExclusions.IsHashExcluded(hash) {
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
	if yaraGetEnabled() && globalYARA.Enabled() {
		if matches := globalYARA.Match(data); len(matches) > 0 {
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
	dpi := dpiScanner.maxBytes
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
	go fireAlert("scan_skipped", AlertPayload{
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
	hits, misses, cacheSize := globalSecScanner.cache.Stats()
	return map[string]interface{}{
		"enabled":               globalSecScanner.Enabled(),
		"scan_svc_mode":         "local",
		"clamav_status":         globalSecScanner.ClamAVStatus(),
		"yara_rules":            globalYARA.Count(),
		"yara_warnings":         len(globalYARA.Warnings()), // Tier 2.1
		"yara_inflight":         yaraInflight.Load(),        // Tier 1.3
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
