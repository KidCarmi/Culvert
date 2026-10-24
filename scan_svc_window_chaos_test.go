package main

// CHAOS-88 — the scan sidecar's own buffer window.
//
// The in-process SWG path buffers maxScanBufferBytes() and, when the body runs
// past that window, fires the operator's only notification that bytes went
// unscanned (proxy_tunnel.go scanInspectBody -> readScanPrefix's deferred
// onOverflow -> logScanLimitExceeded: counter + log + "scan_skipped" alert).
//
// The sidecar (scan_svc.go handleScan) serves the SAME engines over HTTP for
// the process-isolated deployment the CHAOS-52 runbook recommends, and it
// computes its window from ITS OWN process configuration (security.max_scan_mb
// -> secscan.Deps.MaxBytes). Nothing makes the two windows agree: a fleet whose
// proxies buffer 20 MiB in front of a sidecar left at the 5 MiB default hands
// the sidecar a body it cannot read to the end.
//
// These tests pin the contract that falls out of that: a reply the sidecar
// produced from a TRUNCATED read is not an affirmative clean verdict. The
// client already enforces exactly this doctrine for every other shape of
// non-answer (internal/secscan remote.go scanOnce: "A verdict must be
// AFFIRMATIVE"); the sidecar must not be the one hole in it.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/scanner"
	"github.com/KidCarmi/Culvert/internal/secscan"
)

// withScanWindow narrows BOTH engines that maxScanBufferBytes() maxes over to
// window bytes, and restores the globals afterwards. Conventions: setupProxyTest
// resets at test START only, so a test that moves a shared global registers its
// own restoration.
func withScanWindow(t *testing.T, window int64, dpiPatterns []string) {
	t.Helper()
	origDPI, origSec := dpiScanner, globalSecScanner
	t.Cleanup(func() {
		dpiScanner = origDPI
		globalSecScanner = origSec
	})

	ds := scanner.New(window)
	if len(dpiPatterns) > 0 {
		if err := ds.Set(dpiPatterns); err != nil {
			t.Fatalf("set DPI patterns: %v", err)
		}
	}
	dpiScanner = ds
	// Deliberately NOT Init'ed: ClamAV/YARA stay disabled so safeScanBody
	// returns nil and the only thing under test is the window, not an engine.
	globalSecScanner = secscan.New(secscan.Deps{
		Cache:    newHashCache(16, time.Minute),
		MaxBytes: window,
	})

	if got := maxScanBufferBytes(); got != window {
		t.Fatalf("maxScanBufferBytes() = %d, want %d (window not installed)", got, window)
	}
}

// startScanSvc brings up the sidecar on an ephemeral port.
func startScanSvc(t *testing.T) string {
	t.Helper()
	svc := NewScanService("127.0.0.1:0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(ctx)
	})
	go svc.Start() //nolint:errcheck // Serve returns on Shutdown
	addr := svc.Addr()
	if addr == "" {
		t.Fatal("sidecar did not bind")
	}
	return addr
}

func postScan(t *testing.T, addr, contentType string, body []byte) (int, ScanResponse) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, "http://"+addr+"/scan", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := directClient().Do(req)
	if err != nil {
		t.Fatalf("scan request: %v", err)
	}
	defer resp.Body.Close()
	var sr ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		// A refusal need not carry a ScanResponse body; the caller asserts on
		// the status code in that case.
		return resp.StatusCode, ScanResponse{}
	}
	return resp.StatusCode, sr
}

// TestScanSvc_TruncatedBodyIsNeverReportedClean is the load-bearing one. The
// marker sits PAST the sidecar's window, so the sidecar genuinely cannot see
// it — the defect is not the miss, it is answering "clean" for an object it
// only partially read, with no counter, no log line and no alert anywhere in
// the fleet.
func TestScanSvc_TruncatedBodyIsNeverReportedClean(t *testing.T) {
	const window = 4096
	withScanWindow(t, window, []string{"CULVERT-CHAOS88-MARKER"})
	addr := startScanSvc(t)

	body := append(bytes.Repeat([]byte("a"), window+64), []byte("CULVERT-CHAOS88-MARKER")...)
	status, sr := postScan(t, addr, "text/plain", body)

	if status == http.StatusOK && sr.Clean {
		t.Errorf("sidecar answered 200 clean=true for a body truncated at its %d-byte window "+
			"(%d bytes posted): scanning is off for everything past the window, silently",
			window, len(body))
	}
}

// TestScanSvc_BodyExactlyAtWindowStillScansClean is the negative control: the
// fix must not turn the boundary case into a refusal. A body of exactly window
// bytes was fully read, so it gets a real clean verdict.
func TestScanSvc_BodyExactlyAtWindowStillScansClean(t *testing.T) {
	const window = 4096
	withScanWindow(t, window, []string{"CULVERT-CHAOS88-MARKER"})
	addr := startScanSvc(t)

	status, sr := postScan(t, addr, "text/plain", bytes.Repeat([]byte("a"), window))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a body that fits the window exactly", status)
	}
	if !sr.Clean || sr.Blocked {
		t.Errorf("clean=%v blocked=%v, want clean=true blocked=false for a fully-read benign body",
			sr.Clean, sr.Blocked)
	}
}

// TestScanSvc_MatchInsideWindowStillBlocks is the second negative control: the
// window check must not short-circuit ahead of a real verdict. The marker is
// INSIDE the window of an over-long body, so the sidecar saw the match and must
// report the block rather than a truncation refusal — a block is the stronger,
// actionable answer and the local path never signals truncation on a block
// either (readScanPrefix's doc: block paths never forward the tail).
func TestScanSvc_MatchInsideWindowStillBlocks(t *testing.T) {
	const window = 4096
	withScanWindow(t, window, []string{"CULVERT-CHAOS88-MARKER"})
	addr := startScanSvc(t)

	body := append([]byte("CULVERT-CHAOS88-MARKER"), bytes.Repeat([]byte("a"), window*2)...)
	status, sr := postScan(t, addr, "text/plain", body)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 carrying the block verdict", status)
	}
	if !sr.Blocked || sr.Clean {
		t.Errorf("blocked=%v clean=%v, want blocked=true clean=false: the match was inside the window",
			sr.Blocked, sr.Clean)
	}
}

// TestScanSvc_OversizeRefusalIsCountedAndOnHealth: the sidecar is the only
// process that knows its own window, so the refusal has to be legible HERE too
// — the caller buffered within ITS limit and cannot discover that this one is
// narrower from anything but a counter the sidecar publishes.
func TestScanSvc_OversizeRefusalIsCountedAndOnHealth(t *testing.T) {
	const window = 4096
	withScanWindow(t, window, nil)
	origCount := atomic.LoadInt64(&statScanSvcOversize)
	t.Cleanup(func() { atomic.StoreInt64(&statScanSvcOversize, origCount) })
	addr := startScanSvc(t)

	status, _ := postScan(t, addr, "application/octet-stream",
		bytes.Repeat([]byte("a"), window*2))
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", status)
	}

	health := getHealth(t, addr)
	if got := int64(health["oversize_refused"].(float64)); got-origCount != 1 {
		t.Errorf("health oversize_refused moved by %d, want 1", got-origCount)
	}
	if got := int64(health["scan_window_bytes"].(float64)); got != window {
		t.Errorf("health scan_window_bytes = %d, want %d — the operator compares this against the caller's limit", got, window)
	}
}

func getHealth(t *testing.T, addr string) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, "http://"+addr+"/health", http.NoBody)
	if err != nil {
		t.Fatalf("build health request: %v", err)
	}
	resp, err := directClient().Do(req)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	return out
}
