package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// maxRequestBody is the largest body we'll forward for non-tunnel requests.
// CONNECT tunnels and WebSocket upgrades bypass this limit (they stream raw TCP).
const maxRequestBody = 64 << 20 // 64 MB

// ── Why the forward path calls the transport directly ────────────────────────
//
// handleHTTP used to build an http.Client per request whose entire job was to
// say "don't follow redirects" (CheckRedirect: ErrUseLastResponse) and to carry
// a timeout. It paid for the redirect machinery regardless: Client.do sets that
// up unconditionally BEFORE the first round trip, long before CheckRedirect is
// consulted. Per proxied request that meant a full Header.Clone of the client's
// header map (makeHeadersCopier), the body-rewind wrapper (setupRewindBody), a
// cancelTimerBody wrapper around the response body, and the Client itself —
// none of which a forward proxy can ever use, because a 3xx belongs to the
// client and is passed straight back to it.
//
// Measured against a real *http.Transport and a local origin
// (proxy_http_forward_bench_test.go): 90 -> 81 allocs/op, 11.5 KB -> 10.7 KB
// per request; -12% ns/op on the 4-core parallel mix. Gated by
// TestBenchGate_HTTPForwardAllocs; the behaviours http.Client was providing are
// pinned individually in proxy_http_forward_test.go.

// upstreamRequestTimeout bounds a whole plain-HTTP exchange with the origin —
// dial, headers, and the response-body read. It was previously spelled as the
// http.Client.Timeout of that per-request client. The value and the scope it
// covers are unchanged: for a *http.Transport, net/http implements
// Client.Timeout as exactly this, a context deadline on the request
// (setRequestCancel's knownTransport branch).
const upstreamRequestTimeout = 30 * time.Second

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

// readErrTracker wraps a response body and remembers the first non-EOF read
// error, so the caller can distinguish a parent-side body failure from a
// client-side write failure after io.Copy (which folds both into one error).
type readErrTracker struct {
	r   io.Reader
	err error
}

func (t *readErrTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

// prepareHTTPForward applies the request-side forward transforms before the
// round trip: body limit + sent-bytes counter, hop-by-hop and internal-header
// scrub, request-side rewrite rules, and the URL-userinfo → Basic
// Authorization promotion http.Client.send used to perform (the transport
// drops userinfo from the request line, so without the promotion an
// absolute-form URI with credentials would reach the origin with none).
// Returns the rewrite host and the byte counter (nil when the request has no
// body). Extracted from handleHTTP verbatim (funlen; behavior identical).
func prepareHTTPForward(w http.ResponseWriter, r *http.Request) (string, *countingReader) {
	var reqCounter *countingReader
	if r.Body != nil {
		// Wrap request body: limit + count bytes sent upstream.
		reqCounter = &countingReader{r: http.MaxBytesReader(w, r.Body, maxRequestBody)}
		r.Body = reqCounter
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

	r.RequestURI = ""

	// http.Client.send promotes URL userinfo to a Basic Authorization header
	// before the round trip; the transport does not (see above), so keep the
	// promotion here.
	if u := r.URL.User; u != nil && r.Header.Get("Authorization") == "" {
		password, _ := u.Password()
		r.SetBasicAuth(u.Username(), password)
	}
	return host, reqCounter
}

// handleHTTP forwards a plain-HTTP request. id is the TYPED server-resolved
// identity context (F6) — identity/provenance never rides a header.
func handleHTTP(w http.ResponseWriter, r *http.Request, id ProxyIdentity) {
	host, reqCounter := prepareHTTPForward(w, r)

	// Forward through the transport, not through an http.Client: a forward proxy
	// must never follow a redirect (a 3xx belongs to the client), so the only
	// things the per-request client here provided were "don't redirect" and a
	// timeout — while Client.do set up the redirect machinery unconditionally
	// anyway, before CheckRedirect is ever consulted. Rationale and measurements
	// are in the block above upstreamRequestTimeout.
	tr := getUpstreamTransport()

	ctx := r.Context()

	// CHAOS-11: attribute this request's outcome to the parent proxy the
	// transport selects, so real request failures trip the pool's circuit
	// breaker (previously only the periodic health probe ever ejected a
	// broken upstream). No-op (nil attribution) when the pool is disabled.
	// Success is recorded only AFTER the response body is consumed — a
	// parent that returns headers and then drops/truncates the body must
	// be charged, not credited (Codex P1 on the original wiring).
	var upstreamAtt *upstream.Attribution
	if upstreamPool.Enabled() {
		var att *upstream.Attribution
		ctx, att = upstream.WithAttribution(ctx)
		upstreamAtt = att
	}

	// Registered BEFORE resp.Body.Close() below, so it runs AFTER it: the
	// deadline covers the body read, and cancelling early would truncate it.
	ctx, cancel := context.WithTimeout(ctx, upstreamRequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	resp, err := tr.RoundTrip(r)
	if err != nil {
		upstreamAtt.Record(err) // nil-safe
		// RoundTrip returns the bare error where Client.Do returned a *url.Error
		// carrying the target; name the host explicitly so the line keeps its
		// context. Host only, never the full URL — query strings routinely carry
		// tokens and PII (same rule as policyLogURI).
		logger.Printf("upstream request error for %q: %v", sanitizeLog(r.Host), err)
		if isDNSError(err) {
			fireDNSFailureAlert(r.Host, err)
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
	if blockedByResponseHeaders(w, r, resp, id) {
		// Policy outcome, not a parent failure: the parent delivered valid
		// headers and the body is unread by design.
		upstreamAtt.Record(nil)
		return
	}

	// Security body scan (magic/polyglot + ClamAV/YARA) for non-tunnel responses.
	if handled, scanReadErr := scanHTTPResponseBody(w, r, resp, id); handled {
		// scanReadErr is non-nil only when the parent-side body read failed
		// while buffering (the CHAOS-17 fail-closed 502) — charge that;
		// block-page outcomes are parent successes.
		upstreamAtt.Record(scanReadErr)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	// Track parent-side read errors separately from client-side write errors:
	// io.Copy returns either, but only a failed upstream read is evidence
	// against the parent proxy (a client that disconnects mid-download must
	// not charge the parent's breaker).
	tracked := &readErrTracker{r: resp.Body}
	respBytes, err := io.Copy(w, tracked)
	if err != nil {
		logger.Printf("HTTP response copy error for %q: %v", sanitizeLog(r.Host), err)
	}
	// CHAOS-11 (Codex P1): success is recorded only now — a parent that
	// returns headers then drops/truncates the body is charged, so it can be
	// ejected instead of resetting its breaker on every request.
	upstreamAtt.Record(tracked.err)

	// Track bytes transferred for data exfiltration detection.
	if reqCounter != nil {
		atomic.AddInt64(&statBytesSent, reqCounter.count)
	}
	atomic.AddInt64(&statBytesRecv, respBytes)
}

// serveHTTPFileBlock records a response-header file block and serves the block
// page. source is the short tag used in the log line ("resp cd"/"resp ct").
func serveHTTPFileBlock(w http.ResponseWriter, r *http.Request, ext, source string, id ProxyIdentity) {
	cip, _, _ := net.SplitHostPort(r.RemoteAddr)
	atomic.AddInt64(&statFileBlocked, 1)
	atomic.AddInt64(&statBlocked, 1)
	recordRequestAuthURI(cip, r.Method, r.Host, "FILE_BLOCKED", ext, "", id.Identity, "inspect", "", AuthLogFields{AuthSource: id.AuthSource})
	logger.Printf("FILE_BLOCKED (%s) %s -> %q%q (ext=%q)", source, cip, sanitizeLog(r.Host), sanitizeLog(r.URL.Path), sanitizeLog(ext))
	serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
}

// blockedByResponseHeaders checks the response Content-Disposition (blocked
// download extensions) and Content-Type (dangerous MIME types — catches renamed
// executables). Returns true if the response was blocked (block page served;
// caller must return).
func blockedByResponseHeaders(w http.ResponseWriter, r *http.Request, resp *http.Response, id ProxyIdentity) bool {
	if ext := fileBlocker.CheckContentDisposition(resp.Header.Get("Content-Disposition")); ext != "" {
		serveHTTPFileBlock(w, r, ext, "resp cd", id)
		return true
	}
	if ext := fileBlocker.CheckContentType(resp.Header.Get("Content-Type")); ext != "" {
		serveHTTPFileBlock(w, r, ext, "resp ct", id)
		return true
	}
	return false
}

// scanHTTPResponseBody runs the security body-scan pipeline (archive magic,
// polyglot, ClamAV/YARA) over a plain-HTTP response. It returns handled=true
// if the response was handled here (block page or error served; caller must
// return). On a clean scan it reassembles resp.Body (buffered prefix + any
// bytes beyond the scan limit) so the caller streams it unchanged; when
// scanning does not apply it leaves resp.Body as-is and returns false. A body
// READ error while buffering fails closed with a 502 (CHAOS-17): nothing has
// been written to the client yet, the origin read already failed mid-body,
// and forwarding would stream unscanned, truncated content — mirroring the
// inspect path's scanReadError contract (proxy_tunnel.go). That read error is
// also returned (upstreamReadErr) so the caller can charge the upstream
// breaker attribution (CHAOS-11); it is nil for every other outcome.
func scanHTTPResponseBody(w http.ResponseWriter, r *http.Request, resp *http.Response, id ProxyIdentity) (handled bool, upstreamReadErr error) {
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
		return false, nil
	}

	// Buffer the scan window; if the body runs past it, the deferred overflow
	// signal fires when the first uninspected byte is actually forwarded. An
	// origin that omits Content-Length (chunked) skips the pre-check above
	// entirely, so this is the ONLY place the plain-HTTP path can observe that
	// it is forwarding bytes no scanner inspected. The ContentLength >
	// MaxBytes case already returned above, so the declaration here is either
	// absent (-1, chunked) or within the limit; it sizes the buffer only.
	scanLimit := globalSecScanner.MaxBytes()
	scanHost, scanClientIP := r.Host, r.RemoteAddr
	buffered, rest, readErr := readScanPrefix(resp.Body, scanLimit, resp.ContentLength, func() {
		cip, _, _ := net.SplitHostPort(scanClientIP)
		logScanLimitExceeded(scanHost, cip, scanLimit)
	})
	if readErr != nil {
		// Fail closed (CHAOS-17): before this fix the error path returned
		// false, silently forwarding the response unscanned AND truncated
		// (the consumed prefix was never reassembled).
		logger.Printf("HTTP scan: body read error for %q: %v — failing closed", sanitizeLog(r.Host), readErr)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return true, readErr
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
		recordRequestAuthURI(cip, r.Method, r.Host, "FILE_BLOCKED", "magic:"+archType, "", id.Identity, "inspect", "", AuthLogFields{AuthSource: id.AuthSource})
		logger.Printf("FILE_BLOCKED (magic) %s -> %q (type=%s)", cip, sanitizeLog(r.Host), archType)
		serveBlockPage(w, r.Host+r.URL.Path, "File Block", "magic:"+archType)
		return true, nil
	}
	// F5: Polyglot detection — block files whose Content-Type doesn't match
	// their actual magic bytes (disguised executables).
	if reason := CheckMagicVsContentType(scanData, resp.Header.Get("Content-Type")); reason != "" {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordRequestAuthURI(cip, r.Method, r.Host, "POLYGLOT_BLOCKED", reason, "", id.Identity, "inspect", "", AuthLogFields{AuthSource: id.AuthSource})
		logger.Printf("POLYGLOT_BLOCKED %s -> %q (%s)", cip, sanitizeLog(r.Host), sanitizeLog(reason))
		serveBlockPage(w, r.Host+r.URL.Path, "Polyglot Detection", reason)
		return true, nil
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
		recordRequestAuthURI(cip, r.Method, r.Host, "SCAN_BLOCKED", scanResult.Source, scanResult.Reason, id.Identity, "inspect", "", AuthLogFields{AuthSource: id.AuthSource})
		logger.Printf("SCAN_BLOCKED %s -> %q (%q: %q)", cip, sanitizeLog(r.Host), sanitizeLog(scanResult.Source), sanitizeLog(scanResult.Reason))
		scanBlock(w, r.Host, scanResult.Reason, scanResult.Source)
		return true, nil
	}
	// Nothing matched in the window we could see. If the body ran past that
	// window, rest's deferred signal records the delivery of the first
	// uninspected byte (counter + log + deduped scan_skipped alert) exactly as
	// the declared-Content-Length pre-check does, so an origin cannot suppress
	// the signal just by using chunked transfer encoding — and a body of
	// exactly the window size never false-signals, without the limit+1 probe
	// read that could stall on a pausing origin.
	//
	// Reassemble: buffered prefix + the unread remainder.
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buffered), rest))
	return false, nil
}
