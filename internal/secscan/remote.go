package secscan

// Remote scan client — sends scan requests to a scan microservice sidecar
// instead of running ClamAV/YARA/DPI in-process. Moved from package main
// (scan_remote.go) per ADR-0006; the sidecar SERVER (scan_svc.go) stays in
// main, sharing the ScanResponse wire type via alias.
//
// When -scan-svc-url is set (or scan_svc.url in config), the proxy delegates
// all body scanning to the remote service. The local Scanner and DPI engine
// are not initialised.
//
// This provides process isolation: a regex catastrophic backtracking or ClamAV
// crash in the sidecar does not take down the proxy process.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ScanResponse is the JSON wire type between the scan sidecar and this
// client. The sidecar server (package main, scan_svc.go) produces it; keep
// the field set in sync with the server handler.
type ScanResponse struct {
	Clean      bool   `json:"clean"`
	Blocked    bool   `json:"blocked"`
	Reason     string `json:"reason,omitempty"`
	Source     string `json:"source,omitempty"`      // "clamav", "yara", "dpi"
	Hash       string `json:"hash,omitempty"`        // SHA-256 of scanned content
	DPIPattern string `json:"dpi_pattern,omitempty"` // matched DPI pattern
	ElapsedMS  int64  `json:"elapsed_ms"`
}

// RemoteScanner sends scan requests to a scan microservice.
type RemoteScanner struct {
	mu      sync.RWMutex
	baseURL string // e.g. "http://localhost:8484"
	client  *http.Client

	// enabled is atomic for the same reason as Scanner.enabled: Enabled() is
	// consulted once per plain-HTTP response (proxy_http.go scanHTTPResponseBody)
	// and the overwhelmingly common answer is "no remote scanner configured",
	// which should not cost a round trip on this struct's RWMutex. The methods
	// that need baseURL/client still take mu; they just read the flag atomically.
	//
	// This struct is small enough (56 B) that enabled lands on the same 64-byte
	// line as mu, so an RLock elsewhere does invalidate it. Measured and accepted
	// rather than padded: mu is taken ONLY when a sidecar is configured, and only
	// by ScanBody/Health/Status, each of which then makes an HTTP round trip that
	// dwarfs a cache miss. In the default posture mu is never taken at all.
	// Scanner and threatfeed.Feed are large enough that their flags already sit
	// on a separate line.
	enabled atomic.Bool
}

// Init configures the remote scanner client.
func (rs *RemoteScanner) Init(baseURL string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.baseURL = baseURL
	rs.client = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	rs.enabled.Store(true)
	obs.Printf("ScanSvc: remote scanner at %s", baseURL)
}

// Enabled reports whether remote scanning is configured.
//
// Lock-free by contract — see the enabled field.
// TestRemoteScannerEnabled_IsLockFree pins the property.
func (rs *RemoteScanner) Enabled() bool {
	return rs.enabled.Load()
}

// URL returns the configured base URL.
func (rs *RemoteScanner) URL() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.baseURL
}

// remoteScanFail increments the fail counter and fires a webhook alert (via
// the alerts seam) so admins see when the sidecar starts dropping scans.
// Tier 2.2: every fail-open return path routes through this helper.
func remoteScanFail(reason string) {
	AddRemoteScanFail()
	go alerts.Fire("scan_svc_down", alerts.Payload{
		Source: "remote_scan",
		Detail: reason,
	})
}

// ScanBody sends data to the remote scan service and returns the result.
// Returns nil when the content is clean or the service is unreachable (fail-open
// on network errors to avoid blocking all traffic when the sidecar is down).
func (rs *RemoteScanner) ScanBody(data []byte, contentType string) *Result {
	rs.mu.RLock()
	if !rs.enabled.Load() {
		rs.mu.RUnlock()
		return nil
	}
	baseURL := rs.baseURL
	client := rs.client
	rs.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/scan", bytes.NewReader(data))
	if err != nil {
		obs.Printf("ScanSvc: request error: %v", err)
		remoteScanFail("request build error: " + err.Error())
		return nil // fail-open
	}
	if contentType != "" {
		req.Header.Set("X-Content-Type", contentType)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		obs.Printf("ScanSvc: remote scan error: %v", err)
		remoteScanFail("transport error: " + err.Error())
		return nil // fail-open
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		obs.Printf("ScanSvc: remote scan HTTP %d", resp.StatusCode)
		remoteScanFail(fmt.Sprintf("sidecar returned HTTP %d", resp.StatusCode))
		return nil // fail-open
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		obs.Printf("ScanSvc: read response error: %v", err)
		remoteScanFail("response read error: " + err.Error())
		return nil
	}

	var sr ScanResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		obs.Printf("ScanSvc: parse response error: %v", err)
		remoteScanFail("response parse error: " + err.Error())
		return nil
	}

	if sr.Blocked {
		return &Result{
			Blocked: true,
			Reason:  sr.Reason,
			Source:  sr.Source,
			Hash:    sr.Hash,
		}
	}
	return nil
}

// Health checks the remote scan service liveness.
func (rs *RemoteScanner) Health() error {
	rs.mu.RLock()
	if !rs.enabled.Load() {
		rs.mu.RUnlock()
		return fmt.Errorf("remote scanner not configured")
	}
	baseURL := rs.baseURL
	client := rs.client
	rs.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/health", http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Status fetches the remote scanner status (mirrors /api/security-scan/status).
func (rs *RemoteScanner) Status() (map[string]interface{}, error) {
	rs.mu.RLock()
	if !rs.enabled.Load() {
		rs.mu.RUnlock()
		return nil, fmt.Errorf("remote scanner not configured")
	}
	baseURL := rs.baseURL
	client := rs.client
	rs.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/status", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return status, nil
}
