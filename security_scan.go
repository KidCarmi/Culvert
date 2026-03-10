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
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// ── Prometheus counters ───────────────────────────────────────────────────────

var (
	statClamBlocked       int64 // requests blocked by ClamAV
	statYARABlocked       int64 // requests blocked by YARA rules
	statThreatFeedBlocked int64 // requests blocked by threat intel feeds
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
}

// globalSecScanner is the process-wide scanner, initialised in main.go.
var globalSecScanner = &SecurityScanner{
	cache:    newHashCache(10_000, 0), // TTL overridden in Init
	maxBytes: 5 << 20,                // 5 MiB default
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
			logger.Printf("SecurityScan: ClamAV connected at %q", clamAddr)
		}
	}
	ss.enabled = true
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
func (ss *SecurityScanner) ClamAVStatus() string {
	ss.mu.RLock()
	clam := ss.clam
	ss.mu.RUnlock()
	if clam == nil {
		return "disabled"
	}
	if err := clam.Ping(); err != nil {
		return fmt.Sprintf("unreachable: %v", err)
	}
	return "connected"
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

// ── Body scanning ─────────────────────────────────────────────────────────────

// ScanBody scans a response body with ClamAV and YARA.
// Results are cached by SHA-256 to avoid redundant work.
// Returns nil when the content is clean (or no scanner is enabled).
func (ss *SecurityScanner) ScanBody(data []byte) *SecurityScanResult {
	if !ss.BodyScanEnabled() || len(data) == 0 {
		return nil
	}
	hash := SHA256Hex(data)

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

	ss.mu.RLock()
	clam := ss.clam
	ss.mu.RUnlock()

	// ClamAV scan.
	if clam != nil {
		name, found, err := clam.Scan(data)
		if err != nil {
			logger.Printf("SecurityScan: ClamAV error: %v", err)
		} else if found {
			atomic.AddInt64(&statClamBlocked, 1)
			ss.cache.Set(hash, ScanCacheResult{Clean: false, Reason: name, Source: "clamav"})
			return &SecurityScanResult{Blocked: true, Reason: name, Source: "clamav", Hash: hash}
		}
	}

	// YARA scan.
	if globalYARA.Enabled() {
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

// ── HTTP response helpers ─────────────────────────────────────────────────────

// scanBlock sends a 403 Forbidden response to a plain http.ResponseWriter.
func scanBlock(w http.ResponseWriter, host, reason, source string) {
	logger.Printf("SCAN_BLOCKED host=%s source=%s reason=%q", host, source, reason)
	body := fmt.Sprintf("Blocked by %s scan: %s", strings.ToUpper(source), reason)
	http.Error(w, body, http.StatusForbidden)
}

// scanBlockConn sends a 403 Forbidden HTTP/1.1 response to a raw connection
// (used inside SSL-inspect tunnels where http.ResponseWriter is not available).
func scanBlockConn(dst interface{ Write([]byte) (int, error) }, host, reason, source string) {
	logger.Printf("SCAN_BLOCKED host=%s source=%s reason=%q", host, source, reason)
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

// bodyNeedsBuffering reports whether a response body must be fully buffered
// before forwarding, based on the active scanners and the content type.
func bodyNeedsBuffering(contentType string) bool {
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
	feedTotal, feedLastSync, feedInterval := globalThreatFeed.Stats()
	hits, misses, cacheSize := globalSecScanner.cache.Stats()
	return map[string]interface{}{
		"enabled":               globalSecScanner.Enabled(),
		"clamav_status":         globalSecScanner.ClamAVStatus(),
		"yara_rules":            globalYARA.Count(),
		"threat_feed_entries":   feedTotal,
		"threat_feed_last_sync": feedLastSync,
		"threat_feed_interval":  feedInterval.String(),
		"cache_size":            cacheSize,
		"cache_hits":            hits,
		"cache_misses":          misses,
		"stat_clam_blocked":     atomic.LoadInt64(&statClamBlocked),
		"stat_yara_blocked":     atomic.LoadInt64(&statYARABlocked),
		"stat_feed_blocked":     atomic.LoadInt64(&statThreatFeedBlocked),
	}
}
