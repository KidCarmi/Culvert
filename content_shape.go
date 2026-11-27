package main

// content_shape.go — the two content-shape blocks, and the bounded path that
// reaches them when no scanner will buffer the body (CHAOS-129).
//
// ── What the content-shape stage is ──────────────────────────────────────────
//
// Archive magic bytes (F4) and Content-Type/magic polyglots (F5) are the only
// two response blocks in this product that decide from the FIRST BYTES of a
// body alone. They consult no daemon, no rule set and no feed: F4 asks the
// admin's own file profile whether the detected archive type is blocked, and F5
// compares the detected type against the header the origin itself sent. Their
// position says so — inspectMagicStage (proxy_tunnel.go) is documented as
// running "before CDR and before any scanner".
//
// ── What CHAOS-129 found ─────────────────────────────────────────────────────
//
// That documented independence was true of their ORDER and false of their
// PRECONDITION. Both legs reached them only from INSIDE the scanner's
// buffering branch, so the stage inherited a precondition it has no need of:
//
//   - plain HTTP (scanHTTPResponseBody): the enclosing gate was
//     `globalRemoteScanner.Enabled() || globalSecScanner.BodyScanEnabled()`,
//     and the function returned before the stage when it was false.
//   - SSL-inspect (scanInspectBody): the enclosing gate was
//     `bodyNeedsBuffering(ct)`, which is false for every content type unless a
//     remote scanner, ClamAV, a loaded YARA rule set or DPI-on-text is active.
//
// So in the default posture — no ClamAV address, no YARA rules, no sidecar —
// NEITHER leg evaluated either block. Measured on the production function: the
// same ZIP body served as `Content-Type: text/plain` is 403 POLYGLOT_BLOCKED
// with a clean ClamAV client configured and 200, forwarded, without one.
//
// It also flipped at RUNTIME. BodyScanEnabled is `clam != nil || yara.Loaded()`
// (internal/secscan/secscan.go), and deleting the last YARA rule through the
// admin API (globalYARA.DeleteRule, ui_security.go) takes Loaded() false. On a
// YARA-only node that turned both content-shape blocks off fleet-wide with no
// log line, no counter and no alert — an operator removing one malware rule had
// no reason to expect file-type and polyglot blocking to leave with it. A
// ClamAV daemon OUTAGE correctly does not do this: clam stays non-nil, so the
// stage survives the failure of the thing it never depended on.
//
// A third arm was silent in the same way: a response whose DECLARED length is
// past the scan window also returned early, so an origin could place a body
// outside both blocks by declaring it large — with a scanner fully configured.
//
// ── Why the bound is the prefix window and not the scan window ───────────────
//
// The fix must not buy parity with the memory the gate was protecting. It does
// not: filemagic.PrefixWindow() is 6 bytes — the longest offset-0 signature in
// the table — and secscan.ReadScanBuffer caps its Content-Length pre-size by
// the limit it is given, so the shape-only path retains the prefix, not a scan
// window. ISO9660 is the one signature outside that window (its "CD001" sits at
// sector 16, filemagic.MaxWindow() = 32 774 bytes); reaching it on every
// response would retain ~32 KiB per in-flight body to add one type. It is left
// to the scanner-configured path, which still buffers the full window, and
// recorded as a residue rather than quietly claimed. filemagic.Detect declines
// any signature longer than the data it is handed, so a short window cannot
// MISreport — only decline to match.
//
// Encoded bodies are left to the full-window path for a correctness reason, not
// a cost one: six bytes cannot be expanded, and testing the COMPRESSED bytes
// would block a gzip-encoded PDF as "GZIP disguised as application/pdf". The
// full-window path decompresses first (decompressForScan), so deferring to it
// keeps the two paths' verdicts identical and adds no false positive.

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/filemagic"
)

// shapeStagePrefixBytes is the bound the shape-only path reads, derived from
// the signature table rather than written down (filemagic.PrefixWindow).
func shapeStagePrefixBytes() int64 { return int64(filemagic.PrefixWindow()) }

// streamingContentTypes are the content types whose contract is "the body
// arrives when the server has something to say". They are skipped by the
// shape-only path for an availability reason, and it is the one place this
// round trades coverage for it.
//
// The stage reads up to shapeStagePrefixBytes() before the response reaches the
// client, and on these types that read can block indefinitely: an idle SSE or
// gRPC server-stream sends headers and then nothing until an event occurs, so
// a six-byte read holds the headers back with it. Before this round the
// no-scanner path read NOTHING, so stalling one is a regression in working
// traffic, which is a worse outcome than the coverage gap — the more so because
// an operator on a node with no scanner has had no reason to populate the
// scan-exclusion host allowlist that is the existing remedy.
//
// This never makes anything worse than the status quo: with a scanner
// configured these same types go through the FULL window path, which is
// content-type-independent and already buffers them. The gap is confined to the
// posture that had no content-shape coverage at all, and it is a real evasion —
// an origin that declares `text/event-stream` and serves a PE is not shape-
// checked on an unscanned node. Recorded as a residue; closing it needs a
// deadline-bounded read, which io.Reader cannot express.
var streamingContentTypes = []string{
	"text/event-stream",
	"application/grpc",
	"multipart/x-mixed-replace",
}

// contentShapeDeferredToFullWindow reports whether a response must be left to
// the scanner's full-window path instead of the bounded shape-only one.
//
// Two cases. A declared Content-Encoding: six bytes cannot be expanded, and
// judging the compressed bytes would block a gzip-encoded PDF as "GZIP
// disguised as application/pdf" (see the file comment). And a streaming content
// type: see streamingContentTypes.
func contentShapeDeferredToFullWindow(resp *http.Response) bool {
	if resp.Header.Get("Content-Encoding") != "" {
		return true
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	for _, s := range streamingContentTypes {
		if strings.Contains(ct, s) {
			return true
		}
	}
	return false
}

// shapeReassembledBody is "the prefix this stage read, then the untouched
// remainder", with the ORIGIN's Close preserved.
//
// The preservation is the point. Replacing resp.Body with io.NopCloser — which
// is what the scanner's own full-window reassembly does — strands the handle
// the caller closes, so the upstream body and its connection leak on every
// clean pass. On the inspect leg that is not theoretical: it is what
// TestRunInspectExchange_BodyClose caught when this stage was first wired in,
// because the exchange seam closes exactly the handle it is left with.
type shapeReassembledBody struct {
	io.Reader
	orig io.Closer
}

// Close closes the body this stage read from, not the reader wrapping it.
func (b shapeReassembledBody) Close() error { return b.orig.Close() }

// reassembleShapeBody rebuilds resp.Body from the prefix and the remainder
// without losing the origin's Close.
func reassembleShapeBody(orig io.ReadCloser, prefix []byte, rest io.Reader) io.ReadCloser {
	return shapeReassembledBody{
		Reader: io.MultiReader(bytes.NewReader(prefix), rest),
		orig:   orig,
	}
}

// httpMagicStage runs the two content-shape blocks for the plain-HTTP leg and
// reports whether one of them blocked the response. It is the sibling of
// inspectMagicStage (proxy_tunnel.go) and the single place the plain-HTTP
// bookkeeping for these two blocks lives, so the full-window path and the
// bounded shape-only path below cannot drift in what they count, log or serve.
//
// scanData is the bytes to decide from: the decompressed scan window on the
// full-window path, the identity-encoded prefix on the shape-only path.
func httpMagicStage(w http.ResponseWriter, r *http.Request, scanData []byte, contentType string, id ProxyIdentity) bool {
	// F4: block archives even if the URL/Content-Disposition doesn't reveal the
	// true format.
	if archType := IsBlockedArchive(scanData); archType != "" {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordRequestAuthURI(cip, r.Method, r.Host, "FILE_BLOCKED", "magic:"+archType, "", id.Identity, "inspect", "", AuthLogFields{AuthSource: id.AuthSource})
		logger.Printf("FILE_BLOCKED (magic) %s -> %q (type=%s)", cip, sanitizeLog(r.Host), archType)
		serveBlockPage(w, r.Host+r.URL.Path, "File Block", "magic:"+archType)
		return true
	}
	// F5: block files whose Content-Type doesn't match their actual magic bytes
	// (disguised executables).
	if reason := CheckMagicVsContentType(scanData, contentType); reason != "" {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordRequestAuthURI(cip, r.Method, r.Host, "POLYGLOT_BLOCKED", reason, "", id.Identity, "inspect", "", AuthLogFields{AuthSource: id.AuthSource})
		logger.Printf("POLYGLOT_BLOCKED %s -> %q (%s)", cip, sanitizeLog(r.Host), sanitizeLog(reason))
		serveBlockPage(w, r.Host+r.URL.Path, "Polyglot Detection", reason)
		return true
	}
	return false
}

// scanHTTPContentShape is the plain-HTTP leg's bounded content-shape pass: the
// path CHAOS-129 added for the responses no scanner will buffer. It returns the
// same (handled, upstreamReadErr) pair as scanHTTPResponseBody.
//
// The read error arm is the CHAOS-17 contract, narrowed to this window: nothing
// has been written to the client, the origin failed inside the first few bytes
// of its own body, and forwarding would stream a truncated body the shape stage
// never saw. The error is returned so the caller still charges the upstream
// breaker attribution (CHAOS-11).
func scanHTTPContentShape(w http.ResponseWriter, r *http.Request, resp *http.Response, id ProxyIdentity) (handled bool, upstreamReadErr error) {
	if contentShapeDeferredToFullWindow(resp) {
		return false, nil
	}
	prefix, rest, err := readScanPrefix(resp.Body, shapeStagePrefixBytes(), resp.ContentLength, nil)
	if err != nil {
		logger.Printf("HTTP content shape: body read error for %q: %v — failing closed", sanitizeLog(r.Host), err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return true, err
	}
	if httpMagicStage(w, r, prefix, resp.Header.Get("Content-Type"), id) {
		return true, nil
	}
	// Reassemble: the prefix this stage read, then the untouched remainder. No
	// overflow signal is armed (the nil callback above): "forwarded past the
	// scan window" is the scanners' signal, and a six-byte window would fire it
	// on essentially every response, which would make logScanLimitExceeded's
	// counter and scan_skipped alert meaningless.
	resp.Body = reassembleShapeBody(resp.Body, prefix, rest)
	return false, nil
}

// inspectContentShape is the SSL-inspect leg's bounded content-shape pass — the
// same stage as scanHTTPContentShape, reported through scanBodyOutcome.
//
// scanReadError rather than a block on a read failure: the caller must tear the
// tunnel down (H1) or reset the stream (H2) and must never let this surface as
// a clean empty 200, which is the distinction scanInspectBody's own contract
// turns on.
func inspectContentShape(req *http.Request, br blockResponder, resp *http.Response, match *PolicyMatch, hostOnly string, id ProxyIdentity, dec *DecryptionBlock) scanBodyOutcome {
	if contentShapeDeferredToFullWindow(resp) {
		return scanClean
	}
	origBody := resp.Body
	prefix, rest, err := readScanPrefix(origBody, shapeStagePrefixBytes(), resp.ContentLength, nil)
	if err != nil {
		origBody.Close()
		logger.Printf("SSL_INSPECT content shape: body read error for %q: %v", sanitizeLog(hostOnly), err)
		return scanReadError
	}
	ct := resp.Header.Get("Content-Type")
	if archType := IsBlockedArchive(prefix); archType != "" {
		inspectMagicBlock(br, origBody, match, "FILE_BLOCKED", "magic:"+archType, "magic bytes", hostOnly, id, req.URL.Path, dec)
		return scanBlocked
	}
	if reason := CheckMagicVsContentType(prefix, ct); reason != "" {
		inspectMagicBlock(br, origBody, match, "POLYGLOT_BLOCKED", reason, "polyglot", hostOnly, id, req.URL.Path, dec)
		return scanBlocked
	}
	resp.Body = reassembleShapeBody(origBody, prefix, rest)
	return scanClean
}
