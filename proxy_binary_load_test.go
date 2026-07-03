//go:build proxybinload

package main

// Real-binary HTTP load smoke (CI quality program — PR-2), Go-native.
//
// Where proxy_load_test.go drives the proxy HANDLER stack in-process, this
// drives the SHIPPED BINARY as a separate OS process — exercising flag/config
// wiring, the production http.Server (timeouts, listener setup), and graceful
// SIGTERM shutdown. It replaces the original k6 plan with pure Go: a Go upstream
// (httptest), a Go load driver, and http.ProxyURL (which is unconditional, so
// unlike k6's HTTP_PROXY it does not bypass loopback targets — no /etc/hosts or
// NO_PROXY gymnastics needed).
//
// Build-tagged `proxybinload`, excluded from the required gates. Run by the
// nightly workflow, which prepares a writable /data (the binary's dataDir is
// currently hardcoded to /data — see docs/ci/proxy-quality-architecture.md).
//
// Run locally (needs a writable /data):
//   sudo mkdir -p /data && sudo chown "$USER" /data
//   go test -tags proxybinload -run TestBinaryLoad_HTTP -v -timeout 5m .
//
// Knobs (shared defaults with the in-process harness where sensible):
//   CULVERT_BIN              prebuilt binary path (else the test builds one)
//   CULVERT_LOAD_CLIENTS     concurrent clients      (default 50)
//   CULVERT_LOAD_REQS        requests per client     (default 20)
//   CULVERT_LOAD_HTTP_P95_MS p95 bound, ms           (default 1500)

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	binLoadProxyPort = 28080
	binLoadUIPort    = 28090
)

// ensureWritableDataDir skips the test (rather than failing) when /data is not
// writable, since the binary's dataDir is hardcoded. The nightly workflow makes
// it writable; a developer box without it gets a clear hint.
func ensureWritableDataDir(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll("/data", 0o755); err != nil {
		t.Skipf("/data not creatable (%v); run: sudo mkdir -p /data && sudo chown $USER /data", err)
	}
	probe := filepath.Join("/data", ".culvert-load-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
		t.Skipf("/data not writable (%v); run: sudo chown $USER /data", err)
	}
	os.Remove(probe)
}

// buildOrFindBinary returns a culvert binary path, building one into a temp dir
// if CULVERT_BIN is not provided.
func buildOrFindBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("CULVERT_BIN"); bin != "" {
		if _, err := os.Stat(bin); err == nil {
			return bin
		}
		t.Fatalf("CULVERT_BIN=%q does not exist", bin)
	}
	bin := filepath.Join(t.TempDir(), "culvert")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build culvert: %v\n%s", err, out)
	}
	return bin
}

func TestBinaryLoad_HTTP(t *testing.T) {
	ensureWritableDataDir(t)
	bin := buildOrFindBinary(t)

	clients := loadBinEnvInt("CULVERT_LOAD_CLIENTS", 50)
	reqsPer := loadBinEnvInt("CULVERT_LOAD_REQS", 20)
	p95Bound := time.Duration(loadBinEnvInt("CULVERT_LOAD_HTTP_P95_MS", 1500)) * time.Millisecond
	total := clients * reqsPer

	// Go upstream — the proxy forwards here. http.ProxyURL routes EVERY request
	// (incl. this loopback target) through the proxy, so no bypass concerns.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer upstream.Close()

	// Allow-all policy file.
	policyPath := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(policyPath, []byte(`[{"priority":1,"name":"allow-all","destFQDN":"*","action":"Allow"}]`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Launch the real binary.
	logPath := filepath.Join(t.TempDir(), "culvert.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	defer logFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc := exec.CommandContext(ctx, bin,
		"-port", fmt.Sprintf("%d", binLoadProxyPort),
		"-ui-port", fmt.Sprintf("%d", binLoadUIPort),
		"-ui-no-tls",
		"-policy", policyPath,
	)
	proc.Stdout = logFile
	proc.Stderr = logFile
	proc.Dir = "." // repo root (test CWD) so seed files resolve
	if err := proc.Start(); err != nil {
		t.Fatalf("start culvert: %v", err)
	}
	dumpLogOnFail := func() {
		if t.Failed() {
			if b, err := os.ReadFile(logPath); err == nil {
				t.Logf("culvert log:\n%s", tail(b, 2000))
			}
		}
	}
	defer dumpLogOnFail()

	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", binLoadProxyPort)}

	// Wait until the binary actually FORWARDS (data-plane readiness, not just
	// liveness): poll a real request through the proxy.
	probeClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}
	ready := false
	for i := 0; i < 40; i++ {
		resp, err := probeClient.Get(upstream.URL + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("binary never forwarded a 200 through proxy port %d within 10s", binLoadProxyPort)
	}

	// Load.
	lat := make([]time.Duration, total)
	var errs int64
	var wg sync.WaitGroup
	wg.Add(clients)
	start := time.Now()
	for c := 0; c < clients; c++ {
		go func(cid int) {
			defer wg.Done()
			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), MaxIdleConnsPerHost: 4},
				Timeout:   10 * time.Second,
			}
			for r := 0; r < reqsPer; r++ {
				idx := cid*reqsPer + r
				t0 := time.Now()
				resp, err := client.Get(upstream.URL + "/")
				if err != nil {
					atomic.AddInt64(&errs, 1)
					continue
				}
				if resp.StatusCode != http.StatusOK {
					atomic.AddInt64(&errs, 1)
				}
				resp.Body.Close()
				lat[idx] = time.Since(t0)
			}
		}(c)
	}
	wg.Wait()
	elapsed := time.Since(start)

	if errs != 0 {
		t.Errorf("binary HTTP load: %d/%d requests errored at %d concurrent clients", errs, total, clients)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p95 := lat[int(0.95*float64(len(lat)-1))]
	t.Logf("binary HTTP load: %d reqs in %s = %.0f req/s, p95=%s (clients=%d)",
		total, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), p95, clients)
	if p95 > p95Bound {
		t.Errorf("binary HTTP p95=%s exceeds bound %s", p95, p95Bound)
	}

	// Graceful shutdown: SIGTERM and assert the process exits within the drain
	// window (README claims a 15s drain). A binary that hangs on shutdown is a
	// production incident.
	if err := proc.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- proc.Wait() }()
	select {
	case <-done:
		// exited (any exit code is acceptable on SIGTERM)
	case <-time.After(20 * time.Second):
		t.Errorf("binary did not exit within 20s of SIGTERM — graceful shutdown stuck")
		cancel()
	}
}

func loadBinEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
