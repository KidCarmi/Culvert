package main

// Scan microservice — optional sidecar HTTP server for process-isolated scanning.
//
// When Culvert is started with -scan-svc-listen :8484 (or scan_svc.listen in
// config), it launches a lightweight HTTP server that exposes the ClamAV, YARA,
// and DPI scanning engines over a simple JSON API. The main proxy process (or
// any other process on the same host/network) can then call this service instead
// of running scanners in-process.
//
// This is useful for deployments that need:
//   - Process isolation: a crash in YARA regex or ClamAV doesn't affect proxy
//   - Resource limits: run the scanner in a separate cgroup/container
//   - Shared scanning: multiple proxy instances sharing one scanner
//
// Endpoints:
//   POST /scan          — full body scan (ClamAV + YARA + DPI)
//   GET  /health        — liveness check
//   GET  /status        — scanner status (same as /api/security-scan/status)

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// ScanService is the HTTP sidecar server for remote scanning.
type ScanService struct {
	listener net.Listener
	server   *http.Server
	addr     string
}

// ScanRequest is the JSON envelope for a scan request.
// Body is sent as the raw HTTP request body (not JSON-encoded).
type ScanRequest struct {
	ContentType string `json:"content_type,omitempty"` // for DPI text filtering
}

var statScanSvcRequests int64

// statScanSvcOversize counts /scan requests refused because the body ran past
// this process's own scan window. It is surfaced on /health because the sidecar
// is the only process that knows its window: the caller buffered within ITS
// limit and has no way to discover that this one is narrower.
var statScanSvcOversize int64

// lastScanSvcOversizeLog throttles the refusal log line. The producer's rate is
// set by TRAFFIC — an origin chooses its own response size, so a client can put
// every request on this path — and the same doctrine the engine uses for its
// degraded lines applies: the counter carries the magnitude, the line carries
// the news.
var lastScanSvcOversizeLog atomic.Int64

// scanSvcOversizeLogInterval matches internal/secscan's degradedLogInterval.
const scanSvcOversizeLogInterval = time.Minute

// NewScanService creates a scan sidecar server bound to addr.
func NewScanService(addr string) *ScanService {
	return &ScanService{addr: addr}
}

// Listen creates the TCP listener. Call this before Start() so the address is
// available via Addr() without a data race.
func (ss *ScanService) Listen() error {
	ln, err := net.Listen("tcp", ss.addr)
	if err != nil {
		return err
	}
	ss.listener = ln
	return nil
}

// Start begins serving on the listener created by Listen(). Blocks until the
// server is shut down. If Listen() was not called, Start calls it internally.
func (ss *ScanService) Start() error {
	if ss.listener == nil {
		if err := ss.Listen(); err != nil {
			return err
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/scan", ss.handleScan)
	mux.HandleFunc("/health", ss.handleHealth)
	mux.HandleFunc("/status", ss.handleStatus)

	ss.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	logger.Printf("ScanSvc: listening on %s", ss.listener.Addr())

	if err := ss.server.Serve(ss.listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the scan service with the given context deadline.
func (ss *ScanService) Shutdown(ctx context.Context) error {
	if ss.server == nil {
		return nil
	}
	return ss.server.Shutdown(ctx)
}

// Addr returns the listener address (useful when binding to :0 for tests).
func (ss *ScanService) Addr() string {
	if ss.listener != nil {
		return ss.listener.Addr().String()
	}
	return ss.addr
}

// handleScan processes POST /scan requests.
// The request body is the raw content to scan. An optional X-Content-Type
// header tells the scanner the original content type (for DPI text filtering).
func (ss *ScanService) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	atomic.AddInt64(&statScanSvcRequests, 1)
	start := time.Now()

	maxBytes := scanSvcWindow()
	data, truncated, err := readScanWindow(r.Body, maxBytes)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	resp := ScanResponse{Clean: true}

	// ClamAV + YARA scan.
	if result := safeScanBody(data); result != nil {
		resp.Clean = false
		resp.Blocked = true
		resp.Reason = result.Reason
		resp.Source = result.Source
		resp.Hash = result.Hash
	}

	// DPI scan (only for text content).
	contentType := r.Header.Get("X-Content-Type")
	if contentType == "" {
		contentType = r.Header.Get("Content-Type")
	}
	if resp.Clean && dpiScanner.Enabled() && isTextContentType(contentType) {
		if pattern, matched := safeDPIScan(data); matched {
			resp.Clean = false
			resp.Blocked = true
			resp.DPIPattern = pattern
			resp.Source = "dpi"
			resp.Reason = "DPI pattern match: " + pattern
		}
	}

	// A truncated read is refused LAST, and only when the prefix came back
	// clean — see refuseTruncatedScan for why that ordering is the whole
	// correctness argument.
	if truncated && resp.Clean {
		refuseTruncatedScan(w, r, maxBytes)
		return
	}

	resp.ElapsedMS = time.Since(start).Milliseconds()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck // headers are already sent; an encode failure here is a client-side write the caller cannot be told about
}

// scanSvcWindow is this process's scan window, with the engine default as the
// floor. It is deliberately the SAME maxScanBufferBytes() the in-process path
// uses, computed in THIS process — which is the root of CHAOS-101: each process
// derives it from its own security.max_scan_mb and nothing reconciles the
// caller's window with the sidecar's.
func scanSvcWindow() int64 {
	if window := maxScanBufferBytes(); window > 0 {
		return window
	}
	return 5 << 20
}

// readScanWindow buffers at most limit+1 bytes and reports whether the body
// continued past limit.
//
// limit+1 is the overflow PROBE: one byte past the window is all it takes to
// learn that there is more. The probe byte is RETURNED, not sliced off, so the
// engines scan exactly the bytes the handler scanned before CHAOS-101 —
// LimitReader(body, limit+1). Dropping it would make a signature that ENDS on
// that byte unmatchable: the handler would then answer 413, which the client
// classifies as a size limit and forwards fail-open, admitting content the
// pre-fix handler blocked (Codex P2, PR #1711; gated by
// TestScanSvc_SignatureEndingOnTheProbeByteStillBlocks). A read error is
// propagated, never laundered into a truncation.
func readScanWindow(body io.Reader, limit int64) (data []byte, truncated bool, err error) {
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, false, err
	}
	return raw, int64(len(raw)) > limit, nil
}

// refuseTruncatedScan answers 413 for a body this process could not read to the
// end, instead of reporting the prefix's verdict as the whole object's.
//
// CHAOS-101. Answering `clean: true` for a partial read switched scanning off
// for every byte past the window with no counter, no log line and no alert
// anywhere in the fleet: the caller buffers maxScanBufferBytes() in ITS process
// from ITS security.max_scan_mb, nothing makes the two windows agree, and a
// fleet of 20 MiB proxies in front of a sidecar left at the 5 MiB default hands
// this handler bodies it cannot finish. The caller's own overflow signal
// correctly does not fire, because the body fit the CALLER's window.
//
// ORDERING IS THE WHOLE CORRECTNESS ARGUMENT, and the caller must keep it.
// Refusing on size BEFORE scanning — the obvious shape — turns a body whose
// malware sits INSIDE the window into a 413, which the client classifies as a
// size limit and therefore forwards fail-open: the one case where this handler
// holds a real block verdict is the case the refusal would throw away, so the
// "safe" check would admit known-malicious content that the unfixed code
// blocked. A caught verdict is strictly better news than "I could not read it
// all", so the verdict wins and truncation is not reported at all on a block —
// the same asymmetry the local path documents (readScanPrefix: block paths
// never forward the tail, so they never signal).
//
// 413 is the honest status for what remains: the entity genuinely is too large
// for this scanner. The client classifies it as the size-limit outcome it is
// and charges the LOCAL path's scan-skipped vocabulary, rather than laundering
// it into a generic sidecar fault (internal/secscan remote.go
// remoteScanOversize). A body of exactly limit bytes was read whole and still
// gets its real clean verdict.
func refuseTruncatedScan(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	atomic.AddInt64(&statScanSvcOversize, 1)
	if scanSvcOversizeLogAllowed() {
		logger.Printf("ScanSvc: refused /scan from %q — body exceeds this scanner's %d-byte window (declared content-length %d); total %d",
			sanitizeLog(r.RemoteAddr), maxBytes, r.ContentLength, atomic.LoadInt64(&statScanSvcOversize))
	}
	http.Error(w, "scan body exceeds this scanner's window", http.StatusRequestEntityTooLarge)
}

// scanSvcOversizeLogAllowed reports whether enough time has passed to log
// another refusal. Same CAS shape as internal/secscan's degradedLogAllowed.
func scanSvcOversizeLogAllowed() bool {
	now := time.Now().UnixNano()
	prev := lastScanSvcOversizeLog.Load()
	if prev != 0 && now-prev < int64(scanSvcOversizeLogInterval) {
		return false
	}
	return lastScanSvcOversizeLog.CompareAndSwap(prev, now)
}

// handleHealth returns 200 OK for liveness probes.
func (ss *ScanService) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // headers are already sent; an encode failure here is a client-side write the caller cannot be told about
		"status":            "ok",
		"requests":          atomic.LoadInt64(&statScanSvcRequests),
		"oversize_refused":  atomic.LoadInt64(&statScanSvcOversize),
		"scan_window_bytes": scanSvcWindow(),
	})
}

// handleStatus returns the same status map as /api/security-scan/status.
func (ss *ScanService) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secScanStatusMap()) //nolint:errcheck
}
