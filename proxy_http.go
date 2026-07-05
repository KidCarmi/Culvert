package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// maxRequestBody is the largest body we'll forward for non-tunnel requests.
// CONNECT tunnels and WebSocket upgrades bypass this limit (they stream raw TCP).
const maxRequestBody = 64 << 20 // 64 MB

// sslInspectBodyStallTimeout bounds the gap between successive bytes on a
// decrypted SSL-inspected request body. A peer that pauses longer than this
// while req.Write is streaming the body upstream trips the deadline and
// releases the pinned upstream TLS conn. Long legitimate uploads complete
// as long as bytes keep flowing within the window.
const sslInspectBodyStallTimeout = 60 * time.Second

// stallDetectReadCloser wraps an io.ReadCloser (an http.Request.Body during
// inner-request forwarding) and re-arms conn.SetReadDeadline on every Read.
// The underlying net.Conn's SetReadDeadline is expected to abort blocked
// Reads with i/o timeout when the deadline elapses. This turns an
// inactivity pause > timeout into a Read error, which unwinds the caller.
// Used by the SSL-inspect loop to close the slowloris body-transfer window
// (H2 fix).
type stallDetectReadCloser struct {
	io.ReadCloser
	conn    net.Conn
	timeout time.Duration
}

// Read re-arms the deadline before delegating. Any Read that completes
// successfully resets the clock for the next Read; any Read that blocks
// past the deadline returns a timeout error.
func (s *stallDetectReadCloser) Read(p []byte) (int, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(s.timeout))
	return s.ReadCloser.Read(p)
}

// countingReader wraps an io.ReadCloser and counts bytes read through it.
type countingReader struct {
	r     io.ReadCloser
	count int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.count += int64(n)
	return n, err
}

func (cr *countingReader) Close() error { return cr.r.Close() }

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}

	// Wrap request body to count bytes sent upstream.
	var reqCounter countingReader
	if r.Body != nil {
		reqCounter.r = r.Body
		r.Body = &reqCounter
	}

	removeHopHeaders(r.Header)

	// Scrub internal/private headers before forwarding upstream (shift-left:
	// prevent topology leakage and fake identity injection).
	scrubForwardedHeaders(r)

	// Apply request-side rewrite rules before forwarding.
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	rewriter.ApplyRequest(host, r.Header)

	client := &http.Client{
		Transport: getUpstreamTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
	r.RequestURI = ""
	resp, err := client.Do(r)
	if err != nil {
		logger.Printf("upstream request error: %v", err)
		if isDNSError(err) {
			go fireAlert("dns_failure", AlertPayload{Host: r.Host, Detail: err.Error(), Source: "proxy"})
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	pluginOnResponse(resp)
	rewriter.ApplyResponse(host, resp) // response-side rewrite rules
	removeHopHeaders(resp.Header)

	// Response-header file blocking (Content-Disposition filename + Content-Type
	// MIME). Catches downloads whose URL hides the real type.
	if blockedByResponseHeaders(w, r, resp) {
		return
	}

	// Security body scan (magic/polyglot + ClamAV/YARA) for non-tunnel responses.
	if scanHTTPResponseBody(w, r, resp) {
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	respBytes, err := io.Copy(w, resp.Body)
	if err != nil {
		logger.Printf("HTTP response copy error for %q: %v", sanitizeLog(r.Host), err)
	}

	// Track bytes transferred for data exfiltration detection.
	atomic.AddInt64(&statBytesSent, reqCounter.count)
	atomic.AddInt64(&statBytesRecv, respBytes)
}

// serveHTTPFileBlock records a response-header file block and serves the block
// page. source is the short tag used in the log line ("resp cd"/"resp ct").
func serveHTTPFileBlock(w http.ResponseWriter, r *http.Request, ext, source string) {
	cip, _, _ := net.SplitHostPort(r.RemoteAddr)
	atomic.AddInt64(&statFileBlocked, 1)
	atomic.AddInt64(&statBlocked, 1)
	recordRequest(cip, r.Method, r.Host, "FILE_BLOCKED", ext, "", r.Header.Get("X-User-Identity"), "inspect")
	logger.Printf("FILE_BLOCKED (%s) %s -> %q%q (ext=%q)", source, cip, sanitizeLog(r.Host), sanitizeLog(r.URL.Path), sanitizeLog(ext))
	serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
}

// blockedByResponseHeaders checks the response Content-Disposition (blocked
// download extensions) and Content-Type (dangerous MIME types — catches renamed
// executables). Returns true if the response was blocked (block page served;
// caller must return).
func blockedByResponseHeaders(w http.ResponseWriter, r *http.Request, resp *http.Response) bool {
	if ext := fileBlocker.CheckContentDisposition(resp.Header.Get("Content-Disposition")); ext != "" {
		serveHTTPFileBlock(w, r, ext, "resp cd")
		return true
	}
	if ext := fileBlocker.CheckContentType(resp.Header.Get("Content-Type")); ext != "" {
		serveHTTPFileBlock(w, r, ext, "resp ct")
		return true
	}
	return false
}

// scanHTTPResponseBody runs the security body-scan pipeline (archive magic,
// polyglot, ClamAV/YARA) over a plain-HTTP response. It returns true if the
// response was blocked (block page served; caller must return). On a clean scan
// it reassembles resp.Body (buffered prefix + any bytes beyond the scan limit)
// so the caller streams it unchanged; when scanning does not apply — or the
// body cannot be read — it leaves resp.Body as-is and returns false.
func scanHTTPResponseBody(w http.ResponseWriter, r *http.Request, resp *http.Response) bool {
	// Skip buffering if Content-Length signals the response exceeds the scan
	// limit — avoids wasting memory and I/O on oversized bodies.
	scanActive := globalRemoteScanner.Enabled() || globalSecScanner.BodyScanEnabled()
	// Tier 3.3: admin-managed host allowlist short-circuits the whole pipeline
	// so known-good hosts (e.g. internal content mirrors) aren't buffered.
	if scanActive && globalScanExclusions.IsHostExcluded(r.Host) {
		scanActive = false
	}
	if scanActive && resp.ContentLength > globalSecScanner.MaxBytes() {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		logScanLimitExceeded(r.Host, cip, globalSecScanner.MaxBytes())
	}
	if !scanActive || (resp.ContentLength >= 0 && resp.ContentLength > globalSecScanner.MaxBytes()) {
		return false
	}

	buffered, readErr := io.ReadAll(io.LimitReader(resp.Body, globalSecScanner.MaxBytes()))
	if readErr != nil {
		return false
	}
	// 1.1 fix: decompress gzip/deflate bodies before scanning so ClamAV/YARA
	// signatures match the actual content.
	scanData := decompressForScan(buffered, resp.Header.Get("Content-Encoding"))

	// F4: Archive magic byte detection — block archives even if the
	// URL/Content-Disposition doesn't reveal the true format.
	if archType := IsBlockedArchive(scanData); archType != "" {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordRequest(cip, r.Method, r.Host, "FILE_BLOCKED", "magic:"+archType, "", r.Header.Get("X-User-Identity"), "inspect")
		logger.Printf("FILE_BLOCKED (magic) %s -> %q (type=%s)", cip, sanitizeLog(r.Host), archType)
		serveBlockPage(w, r.Host+r.URL.Path, "File Block", "magic:"+archType)
		return true
	}
	// F5: Polyglot detection — block files whose Content-Type doesn't match
	// their actual magic bytes (disguised executables).
	if reason := CheckMagicVsContentType(scanData, resp.Header.Get("Content-Type")); reason != "" {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordRequest(cip, r.Method, r.Host, "POLYGLOT_BLOCKED", reason, "", r.Header.Get("X-User-Identity"), "inspect")
		logger.Printf("POLYGLOT_BLOCKED %s -> %q (%s)", cip, sanitizeLog(r.Host), sanitizeLog(reason))
		serveBlockPage(w, r.Host+r.URL.Path, "Polyglot Detection", reason)
		return true
	}

	if scanResult := safeScanBodyWithCT(scanData, resp.Header.Get("Content-Type")); scanResult != nil {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statBlocked, 1)
		// Fire scan_timeout alert for infrastructure monitoring (Finding 8.3).
		if scanResult.Source == "timeout" {
			go fireAlert("scan_timeout", AlertPayload{
				Actor:  cip,
				Host:   r.Host,
				Detail: scanResult.Reason,
				Source: "scan_timeout",
			})
		}
		recordRequest(cip, r.Method, r.Host, "SCAN_BLOCKED", scanResult.Source, scanResult.Reason, r.Header.Get("X-User-Identity"), "inspect")
		logger.Printf("SCAN_BLOCKED %s -> %q (%q: %q)", cip, sanitizeLog(r.Host), sanitizeLog(scanResult.Source), sanitizeLog(scanResult.Reason))
		scanBlock(w, r.Host, scanResult.Reason, scanResult.Source)
		return true
	}
	// Reassemble: buffered prefix + any remaining bytes beyond the limit.
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buffered), resp.Body))
	return false
}
