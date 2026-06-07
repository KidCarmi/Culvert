package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// directClient returns an HTTP client that bypasses any proxy settings.
func directClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
		Timeout: 10 * time.Second,
	}
}

// ── ScanService (sidecar server) tests ─────────────────────────────────────

func TestScanService_Health(t *testing.T) {
	svc := NewScanService(":0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer svc.Shutdown(context.Background()) //nolint:errcheck

	go svc.Start() //nolint:errcheck
	addr := svc.Addr()
	if addr == "" {
		t.Fatal("scan service did not start")
	}

	client := directClient()
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("health status = %d, want 200; body = %q", resp.StatusCode, string(respBody))
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	if body["status"] != "ok" {
		t.Errorf("health status = %v, want ok", body["status"])
	}
}

func TestScanService_ScanClean(t *testing.T) {
	svc := NewScanService(":0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer svc.Shutdown(context.Background()) //nolint:errcheck

	go svc.Start() //nolint:errcheck
	addr := svc.Addr()

	client := directClient()
	data := []byte("Hello, this is clean content.")
	resp, err := client.Post("http://"+addr+"/scan", "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("scan request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("scan status = %d, want 200", resp.StatusCode)
	}

	var sr ScanResponse
	json.NewDecoder(resp.Body).Decode(&sr) //nolint:errcheck
	if !sr.Clean {
		t.Error("expected clean=true for benign content")
	}
	if sr.Blocked {
		t.Error("expected blocked=false for benign content")
	}
}

func TestScanService_ScanDPIBlock(t *testing.T) {
	// Set up a DPI pattern that matches.
	oldRaw := dpiScanner.List()
	defer func() { dpiScanner.Set(oldRaw) }() //nolint:errcheck
	dpiScanner.Set([]string{"EVIL_PATTERN"})  //nolint:errcheck

	svc := NewScanService(":0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer svc.Shutdown(context.Background()) //nolint:errcheck

	go svc.Start() //nolint:errcheck
	addr := svc.Addr()

	client := directClient()
	data := []byte("This contains EVIL_PATTERN inside text.")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+addr+"/scan", bytes.NewReader(data))
	req.Header.Set("X-Content-Type", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("scan request failed: %v", err)
	}
	defer resp.Body.Close()

	var sr ScanResponse
	json.NewDecoder(resp.Body).Decode(&sr) //nolint:errcheck
	if sr.Clean {
		t.Error("expected clean=false for DPI-matching content")
	}
	if !sr.Blocked {
		t.Error("expected blocked=true for DPI-matching content")
	}
	if sr.Source != "dpi" {
		t.Errorf("source = %q, want dpi", sr.Source)
	}
	if sr.DPIPattern != "EVIL_PATTERN" {
		t.Errorf("dpi_pattern = %q, want EVIL_PATTERN", sr.DPIPattern)
	}
}

func TestScanService_MethodNotAllowed(t *testing.T) {
	svc := NewScanService(":0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer svc.Shutdown(context.Background()) //nolint:errcheck

	go svc.Start() //nolint:errcheck
	addr := svc.Addr()

	client := directClient()
	resp, err := client.Get("http://" + addr + "/scan")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /scan status = %d, want 405", resp.StatusCode)
	}
}

func TestScanService_Status(t *testing.T) {
	svc := NewScanService(":0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer svc.Shutdown(context.Background()) //nolint:errcheck

	go svc.Start() //nolint:errcheck
	addr := svc.Addr()

	client := directClient()
	resp, err := client.Get("http://" + addr + "/status")
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status code = %d, want 200", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	if _, ok := body["enabled"]; !ok {
		t.Error("status response missing 'enabled' field")
	}
}

// ── RemoteScanner (client) tests ───────────────────────────────────────────

func TestRemoteScanner_ScanBody_Clean(t *testing.T) {
	// Start a mock scan service.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)                                   //nolint:errcheck
		json.NewEncoder(w).Encode(ScanResponse{Clean: true}) //nolint:errcheck
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rs := &RemoteScanner{}
	rs.Init(ts.URL)

	result := rs.ScanBody([]byte("clean data"), "text/plain")
	if result != nil {
		t.Errorf("expected nil result for clean content, got %+v", result)
	}
}

func TestRemoteScanner_ScanBody_Blocked(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)                      //nolint:errcheck
		json.NewEncoder(w).Encode(ScanResponse{ //nolint:errcheck
			Clean:   false,
			Blocked: true,
			Reason:  "Eicar-Test-Signature",
			Source:  "clamav",
			Hash:    "abc123",
		})
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rs := &RemoteScanner{}
	rs.Init(ts.URL)

	result := rs.ScanBody([]byte("malicious data"), "")
	if result == nil {
		t.Fatal("expected non-nil result for blocked content")
	}
	if !result.Blocked {
		t.Error("expected Blocked=true")
	}
	if result.Source != "clamav" {
		t.Errorf("source = %q, want clamav", result.Source)
	}
	if result.Reason != "Eicar-Test-Signature" {
		t.Errorf("reason = %q, want Eicar-Test-Signature", result.Reason)
	}
}

func TestRemoteScanner_ScanBody_FailOpen(t *testing.T) {
	// Remote service is unreachable → fail-open (return nil).
	rs := &RemoteScanner{}
	rs.Init("http://127.0.0.1:1") // unlikely to be listening

	result := rs.ScanBody([]byte("data"), "")
	if result != nil {
		t.Errorf("expected nil (fail-open) when remote unreachable, got %+v", result)
	}
}

func TestRemoteScanner_NotEnabled(t *testing.T) {
	rs := &RemoteScanner{}
	if rs.Enabled() {
		t.Error("expected Enabled()=false for unconfigured scanner")
	}
	result := rs.ScanBody([]byte("data"), "")
	if result != nil {
		t.Errorf("expected nil from disabled scanner")
	}
}

func TestRemoteScanner_Health(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rs := &RemoteScanner{}
	rs.Init(ts.URL)

	if err := rs.Health(); err != nil {
		t.Errorf("health check failed: %v", err)
	}
}

func TestRemoteScanner_Health_Unreachable(t *testing.T) {
	rs := &RemoteScanner{}
	rs.Init("http://127.0.0.1:1")

	if err := rs.Health(); err == nil {
		t.Error("expected error for unreachable scanner")
	}
}

func TestRemoteScanner_Status(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"enabled":    true,
			"yara_rules": 5,
		})
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rs := &RemoteScanner{}
	rs.Init(ts.URL)

	status, err := rs.Status()
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if status["enabled"] != true {
		t.Errorf("status.enabled = %v, want true", status["enabled"])
	}
}

func TestRemoteScanner_ContentTypeHeader(t *testing.T) {
	var gotCT string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("X-Content-Type")
		io.ReadAll(r.Body)                                   //nolint:errcheck
		json.NewEncoder(w).Encode(ScanResponse{Clean: true}) //nolint:errcheck
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rs := &RemoteScanner{}
	rs.Init(ts.URL)
	rs.ScanBody([]byte("data"), "text/html; charset=utf-8")

	if gotCT != "text/html; charset=utf-8" {
		t.Errorf("X-Content-Type = %q, want text/html; charset=utf-8", gotCT)
	}
}

// ── API endpoint test ──────────────────────────────────────────────────────

func TestAPIScanSvcConfig(t *testing.T) {
	// Save and restore global state.
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	defer func() { globalRemoteScanner = orig }()

	req := httptest.NewRequest(http.MethodGet, "/api/security-scan/svc", nil)
	w := httptest.NewRecorder()
	apiScanSvcConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp) //nolint:errcheck
	if resp["remote_enabled"] != false {
		t.Errorf("remote_enabled = %v, want false", resp["remote_enabled"])
	}
}

// ── secScanStatusMap with remote scanner ───────────────────────────────────

func TestSecScanStatusMap_RemoteMode(t *testing.T) {
	// Stand up a mock scan service that responds to /status.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"enabled":       true,
			"clamav_status": "connected",
			"yara_rules":    10,
		})
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(ts.URL)
	defer func() { globalRemoteScanner = orig }()

	m := secScanStatusMap()
	if m["scan_svc_mode"] != "remote" {
		t.Errorf("scan_svc_mode = %v, want remote", m["scan_svc_mode"])
	}
	if m["scan_svc_url"] != ts.URL {
		t.Errorf("scan_svc_url = %v, want %s", m["scan_svc_url"], ts.URL)
	}
	if m["clamav_status"] != "connected" {
		t.Errorf("clamav_status = %v, want connected", m["clamav_status"])
	}
}

func TestSecScanStatusMap_LocalMode(t *testing.T) {
	// Ensure remote scanner is disabled.
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	defer func() { globalRemoteScanner = orig }()

	m := secScanStatusMap()
	if m["scan_svc_mode"] != "local" {
		t.Errorf("scan_svc_mode = %v, want local", m["scan_svc_mode"])
	}
}

// ── Integration: safeScanBody with remote scanner ──────────────────────────

func TestSafeScanBody_RemoteDelegation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "MALWARE") {
			json.NewEncoder(w).Encode(ScanResponse{ //nolint:errcheck
				Clean: false, Blocked: true, Reason: "test-virus", Source: "clamav",
			})
		} else {
			json.NewEncoder(w).Encode(ScanResponse{Clean: true}) //nolint:errcheck
		}
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(ts.URL)
	defer func() { globalRemoteScanner = orig }()

	// Clean content should return nil.
	if result := safeScanBody([]byte("clean")); result != nil {
		t.Errorf("expected nil for clean content, got %+v", result)
	}

	// Malicious content should return a result.
	result := safeScanBody([]byte("contains MALWARE"))
	if result == nil {
		t.Fatal("expected non-nil result for malicious content")
	}
	if !result.Blocked {
		t.Error("expected Blocked=true")
	}
	if result.Source != "clamav" {
		t.Errorf("source = %q, want clamav", result.Source)
	}
}

func TestBodyNeedsBuffering_RemoteScanner(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	defer func() { globalRemoteScanner = orig }()

	// Without remote scanner, binary content may not need buffering.
	if bodyNeedsBuffering("application/octet-stream") {
		t.Error("expected false for binary content without remote scanner")
	}

	// With remote scanner, all content needs buffering.
	globalRemoteScanner.Init("http://localhost:9999")
	if !bodyNeedsBuffering("application/octet-stream") {
		t.Error("expected true for any content with remote scanner")
	}
	if !bodyNeedsBuffering("text/html") {
		t.Error("expected true for text content with remote scanner")
	}
}
