package main

// security_scan.go — package-main glue for the scan orchestrator, moved to
// internal/secscan (ADR-0006 Slice 2). The alias shim keeps the proxy hot
// path, the startup slice, and the test suite using the original unqualified
// names; the production adapters (YARA runtime toggle, threat feed, exclusion
// store), the panic-safe wrappers, the HTTP block helpers, and the status map
// stay here (logger/alerts/sanitizeLog and the remote-scanner fork are
// main-owned).

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/scanexcl"
	"github.com/KidCarmi/Culvert/internal/secscan"
)

// SecurityScanResult / SecurityScanner re-exposed unqualified (engine types
// are secscan.Result / .Scanner).
type (
	SecurityScanResult = secscan.Result
	SecurityScanner    = secscan.Scanner
)

// decompressForScan and the scan constants re-exposed for the proxy pipeline
// (proxy.go, cdr_proxy.go) and the test suite.
var decompressForScan = secscan.DecompressForScan

// readScanBuffer fills the scan buffer for one response body. It replaces
// io.ReadAll(io.LimitReader(body, limit)) at the two buffering call sites
// (the SSL-inspect inner loop and the plain-HTTP path), using the origin's
// declared Content-Length to size the destination in one allocation instead of
// growing it a doubling at a time. The hint is advisory only — the read still
// runs to EOF or to limit — so what reaches the scanners is unchanged; see
// internal/secscan/scanbuffer.go for the measurements and the equivalence
// contract.
var readScanBuffer = secscan.ReadScanBuffer

const (
	maxDecompressBytes = secscan.MaxDecompressBytes
	scanBodyTimeout    = secscan.ScanBodyTimeout
)

// ── Production adapters (ADR-0006) ──────────────────────────────────────────

// yaraRuleSetMatcher adapts the process-wide YARARuleSet plus the runtime
// enable toggle to the secscan.YARAMatcher contract. Loaded and Enabled are
// deliberately distinct: BodyScanEnabled keys on rules-present only (Loaded),
// while the body scan additionally honors the toggle (Enabled).
type yaraRuleSetMatcher struct{ rs *YARARuleSet }

func (m yaraRuleSetMatcher) Loaded() bool               { return m.rs.Enabled() }
func (m yaraRuleSetMatcher) Enabled() bool              { return yaraGetEnabled() && m.rs.Enabled() }
func (m yaraRuleSetMatcher) Match(data []byte) []string { return m.rs.Match(data) }

// ── ScanExclusionStore (moved to internal/scanexcl, ADR-0002) ──────────────────

// ScanExclusionStore is the package-main alias for the relocated admin-managed
// allowlist store, so the consumers (main.go Load, proxy.go IsHostExcluded,
// ui_security.go Lists/Replace/Save) stay unqualified.
type ScanExclusionStore = scanexcl.Store

// globalScanExclusions is the process-wide exclusion store.
var globalScanExclusions = scanexcl.New()

// globalSecScanner is the process-wide scanner, enabled by the scanning
// startup slice (Init). Constructed disabled with the production
// collaborators injected — exactly the pre-extraction literal semantics
// (cache + maxBytes defaults, enabled only after Init).
var globalSecScanner = secscan.New(secscan.Deps{
	Yara: yaraRuleSetMatcher{globalYARA},
	Feed: globalThreatFeed,
	Excl: globalScanExclusions,
})

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
func scanBlockConn(br blockResponder, host, reason, source string) {
	logger.Printf("SecurityScan: blocked host=%s source=%s reason=%q", host, source, reason)
	body := fmt.Sprintf("Blocked by %s scan: %s\r\n", strings.ToUpper(source), reason)
	br.blockBeforeResponse("text/plain; charset=utf-8", body)
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

// readScanPrefix buffers the bytes a scanner may inspect and arranges for the
// truncation signal to fire if the body genuinely continues past that window.
//
// scan is exactly what io.ReadAll(io.LimitReader(body, limit)) would have
// produced (pre-sized from contentLength via secscan.ReadScanBuffer, hint
// only), so scan semantics are byte-identical to the call it replaces. rest is
// the remainder the caller must forward after scan when reassembling the body.
//
// The signal is DEFERRED, not probed: an earlier revision read limit+1 bytes
// to learn "is there more?" up front, but that probe blocks on a streaming
// body of exactly limit bytes that pauses without sending EOF — on the
// SSL-inspect path there is no upstream body deadline, so a stalling origin
// could withhold an already-clean response indefinitely (review P2). Instead,
// when the window filled, rest wraps the remainder so that onOverflow fires
// exactly once, at the moment a byte beyond the window is actually delivered.
// That is when "forwarded unscanned" becomes true, this never reads ahead of
// what the caller forwards (no new blocking anywhere), a body of exactly
// limit bytes never false-signals (its rest returns EOF), and block paths —
// which never forward the tail — never signal, preserving the deliberate
// no-signal-on-block behavior.
//
// A non-positive limit means there is no scan window at all: nothing is read,
// rest is the untouched body, and onOverflow never fires (matching
// LimitReader(body, 0)). A read error is never laundered into a truncation:
// it is propagated, preserving the CHAOS-17 fail-closed contract exactly.
func readScanPrefix(body io.Reader, limit, contentLength int64, onOverflow func()) (scan []byte, rest io.Reader, err error) {
	if limit <= 0 {
		return []byte{}, body, nil
	}
	raw, err := readScanBuffer(body, limit, contentLength)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(raw)) < limit {
		// EOF inside the window: the scanners saw everything.
		return raw, eofReader{}, nil
	}
	return raw, &overflowSignalReader{r: body, onFirstByte: onOverflow}, nil
}

// eofReader is an always-empty remainder for bodies that ended inside the
// scan window.
type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

// overflowSignalReader passes reads through to the unread remainder of a
// response body and fires onFirstByte exactly once, when the first byte past
// the scan window is actually delivered toward the client.
type overflowSignalReader struct {
	r           io.Reader
	onFirstByte func()
	fired       bool
}

func (o *overflowSignalReader) Read(p []byte) (int, error) {
	n, err := o.r.Read(p)
	if n > 0 && !o.fired {
		o.fired = true
		if o.onFirstByte != nil {
			o.onFirstByte()
		}
	}
	return n, err
}

// logScanLimitExceeded logs a warning and fires a "scan_skipped" alert when a
// response body exceeds the scan buffer limit and is therefore forwarded
// without ClamAV/YARA/DPI inspection (Finding 4.2).
// Tier 1.2: also increments the scan-skipped counter so the status API
// exposes size-skipped events without grepping logs.
//
// Every path that forwards bytes the scanners never saw MUST call this — not
// only the declared-Content-Length pre-check. A response body is truncated to
// the scan window on the SSL-inspect path (scanInspectBody) and on the
// plain-HTTP path whenever the length is not declared up front (chunked
// transfer encoding), and both forward the unscanned remainder to the client.
// Signalling only the declared-length case leaves the operator blind in exactly
// the shape an origin chooses for itself.
func logScanLimitExceeded(host, clientIP string, maxBytes int64) {
	secscan.AddScanSkipped()
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
	counters := secscan.Counters()

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
			// The sidecar's /status IS its own secScanStatusMap, so it carries
			// its own "enabled" and "scan_svc_mode": "local". Merged in blind,
			// those overwrote the three keys this process owns, and a proxy in
			// remote mode reported scan_svc_mode "local" to its own admin UI.
			// The identity of THIS node is not the far end's to state.
			m["enabled"] = true
			m["scan_svc_mode"] = "remote"
			m["scan_svc_url"] = globalRemoteScanner.URL()
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
		feedOK, feedLastSuccess, feedErr := globalThreatFeed.SyncStatus()
		m["threat_feed_sync_ok"] = feedOK
		m["threat_feed_last_success"] = feedLastSuccess
		if feedErr != "" {
			m["threat_feed_sync_error"] = feedErr
		}
		m["stat_feed_blocked"] = counters.ThreatFeedBlocked
		m["threat_feed_allowlist_masked"] = globalThreatFeed.AllowlistMaskedTotal()
		// Tier 2.2: surface remote sidecar failure counter even when scan_svc_mode=remote.
		m["stat_remote_scan_fail"] = counters.RemoteScanFail
		// CHAOS-53: the fail-CLOSED half of the remote posture. scan_timeout now
		// counts budget refusals from the sidecar path too, so this deployment
		// finally reports both directions of a scanning fault instead of only
		// the one that admits content.
		m["stat_scan_timeout"] = counters.ScanTimeout
		m["stat_remote_scan_saturated"] = counters.RemoteScanSaturated
		m["remote_scan_inflight"] = counters.RemoteScanInflight
		return m
	}

	feedTotal, feedLastSync, feedInterval := globalThreatFeed.Stats()
	feedOK, feedLastSuccess, feedErr := globalThreatFeed.SyncStatus()
	hits, misses, cacheSize := globalSecScanner.CacheStats()
	m := map[string]interface{}{
		"enabled":                  globalSecScanner.Enabled(),
		"scan_svc_mode":            "local",
		"clamav_status":            globalSecScanner.ClamAVStatus(),
		"yara_rules":               globalYARA.Count(),
		"yara_warnings":            len(globalYARA.Warnings()), // Tier 2.1
		"yara_inflight":            yaraInflightLoad(),         // Tier 1.3
		"yara_inflight_max":        yaraGetMaxInflight(),       // Tier 1.3
		"yara_match_panics":        yaraMatchPanicsLoad(),      // CHAOS-25: a match panicked (crashed) and was contained; distinct from a timeout
		"yara_enabled":             yaraGetEnabled(),
		"yara_timeout_secs":        yaraGetTimeoutSecs(),
		"yara_on_timeout":          yaraGetOnTimeout(),
		"yara_on_saturation":       yaraGetOnSaturation(),
		"yara_alert_degraded":      yaraGetAlertDegraded(),
		"threat_feed_entries":      feedTotal,
		"threat_feed_last_sync":    feedLastSync,
		"threat_feed_interval":     feedInterval.String(),
		"threat_feed_sync_ok":      feedOK,
		"threat_feed_last_success": feedLastSuccess,
		"cache_size":               cacheSize,
		"cache_hits":               hits,
		"cache_misses":             misses,
		"stat_clam_blocked":        counters.ClamBlocked,
		"stat_yara_blocked":        counters.YARABlocked,
		"stat_feed_blocked":        counters.ThreatFeedBlocked,
		"stat_scan_timeout":        counters.ScanTimeout,    // Tier 1.2
		"stat_scan_skipped":        counters.ScanSkipped,    // Tier 1.2
		"stat_remote_scan_fail":    counters.RemoteScanFail, // Tier 2.2
		"stat_clam_scan_error":     counters.ClamScanError,  // CHAOS-10
		// Saturation plane: capacity exhaustion is reported separately from a
		// daemon fault (different operator response), and late-discarded
		// verdicts say how often content was decided by the deadline rather
		// than by the engines.
		"stat_clam_saturated":    counters.ClamSaturated,
		"stat_scan_late_discard": counters.ScanLateDiscarded,
		"scan_inflight":          counters.ScanInflight,

		"threat_feed_allowlist_masked": globalThreatFeed.AllowlistMaskedTotal(),
	}
	// ClamAV engine + signature-database version (Finding 4.3), so operators
	// can see whether virus definitions are current. Absent when ClamAV is
	// disabled or the daemon does not answer VERSION.
	if v, ok := globalSecScanner.ClamAVVersion(); ok {
		m["clamav_version"] = v
	}
	if feedErr != "" {
		m["threat_feed_sync_error"] = feedErr
	}
	return m
}
