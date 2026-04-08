package main

// Remote scan client — sends scan requests to a scan microservice sidecar
// instead of running ClamAV/YARA/DPI in-process.
//
// When -scan-svc-url is set (or scan_svc.url in config), the proxy delegates
// all body scanning to the remote service. The local SecurityScanner and DPI
// engine are not initialised.
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
	"time"
)

// RemoteScanner sends scan requests to a scan microservice.
type RemoteScanner struct {
	mu      sync.RWMutex
	baseURL string // e.g. "http://localhost:8484"
	client  *http.Client
	enabled bool
}

// globalRemoteScanner is the process-wide remote scanner, nil when not configured.
var globalRemoteScanner = &RemoteScanner{}

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
	rs.enabled = true
	logger.Printf("ScanSvc: remote scanner at %s", baseURL)
}

// Enabled reports whether remote scanning is configured.
func (rs *RemoteScanner) Enabled() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.enabled
}

// URL returns the configured base URL.
func (rs *RemoteScanner) URL() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.baseURL
}

// ScanBody sends data to the remote scan service and returns the result.
// Returns nil when the content is clean or the service is unreachable (fail-open
// on network errors to avoid blocking all traffic when the sidecar is down).
func (rs *RemoteScanner) ScanBody(data []byte, contentType string) *SecurityScanResult {
	rs.mu.RLock()
	if !rs.enabled {
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
		logger.Printf("ScanSvc: request error: %v", err)
		return nil // fail-open
	}
	if contentType != "" {
		req.Header.Set("X-Content-Type", contentType)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("ScanSvc: remote scan error: %v", err)
		return nil // fail-open
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("ScanSvc: remote scan HTTP %d", resp.StatusCode)
		return nil // fail-open
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		logger.Printf("ScanSvc: read response error: %v", err)
		return nil
	}

	var sr ScanResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		logger.Printf("ScanSvc: parse response error: %v", err)
		return nil
	}

	if sr.Blocked {
		return &SecurityScanResult{
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
	if !rs.enabled {
		rs.mu.RUnlock()
		return fmt.Errorf("remote scanner not configured")
	}
	baseURL := rs.baseURL
	client := rs.client
	rs.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/health", nil)
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
	if !rs.enabled {
		rs.mu.RUnlock()
		return nil, fmt.Errorf("remote scanner not configured")
	}
	baseURL := rs.baseURL
	client := rs.client
	rs.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/status", nil)
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
