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

// ScanResponse is the JSON response from the scan service.
type ScanResponse struct {
	Clean      bool   `json:"clean"`
	Blocked    bool   `json:"blocked"`
	Reason     string `json:"reason,omitempty"`
	Source     string `json:"source,omitempty"`      // "clamav", "yara", "dpi"
	Hash       string `json:"hash,omitempty"`        // SHA-256 of scanned content
	DPIPattern string `json:"dpi_pattern,omitempty"` // matched DPI pattern
	ElapsedMS  int64  `json:"elapsed_ms"`
}

var statScanSvcRequests int64

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

	logger.Printf("ScanSvc  → listening on %s", ss.listener.Addr())

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

	// Read body up to the configured max.
	maxBytes := maxScanBufferBytes()
	if maxBytes <= 0 {
		maxBytes = 5 << 20
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
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

	resp.ElapsedMS = time.Since(start).Milliseconds()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// handleHealth returns 200 OK for liveness probes.
func (ss *ScanService) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":   "ok",
		"requests": atomic.LoadInt64(&statScanSvcRequests),
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
