//go:build proxybinload

package main

// Restart-under-traffic resilience test (CI quality program — PR-3), Go-native.
//
// Reuses the PR-2 binary harness (buildOrFindBinary, ensureWritableDataDir).
// Drives continuous load against the SHIPPED binary, SIGTERMs it mid-traffic,
// asserts it drains/exits within the documented window, then starts a fresh
// instance on the same port and asserts it serves — i.e. the proxy survives a
// restart while traffic flows.
//
//   go test -tags proxybinload -run 'TestBinaryRestart_' -v -timeout 5m .

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	restartProxyPort = 28081
	restartUIPort    = 28091
)

// launchCulvert starts the binary and returns the process + a stop func. Output
// is captured to logPath.
func launchCulvert(t *testing.T, bin, policyPath, logPath string) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	proc := exec.CommandContext(ctx, bin,
		"-port", fmt.Sprintf("%d", restartProxyPort),
		"-ui-port", fmt.Sprintf("%d", restartUIPort),
		"-ui-no-tls",
		"-policy", policyPath,
	)
	proc.Stdout = logFile
	proc.Stderr = logFile
	proc.Dir = "."
	if err := proc.Start(); err != nil {
		logFile.Close()
		cancel()
		t.Fatalf("start culvert: %v", err)
	}
	return proc, cancel
}

// waitForward polls a real request through the proxy until it forwards a 200.
func waitForward(proxyURL *url.URL, targetURL string, attempts int) bool {
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}
	for i := 0; i < attempts; i++ {
		resp, err := client.Get(targetURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func TestBinaryRestart_UnderTraffic(t *testing.T) {
	ensureWritableDataDir(t)
	bin := buildOrFindBinary(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	defer upstream.Close()

	policyPath := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(policyPath, []byte(`[{"priority":1,"name":"allow-all","destFQDN":"*","action":"Allow"}]`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "culvert-restart.log")
	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", restartProxyPort)}

	dumpLogOnFail := func() {
		if t.Failed() {
			if b, err := os.ReadFile(logPath); err == nil {
				t.Logf("culvert log:\n%s", tail(b, 3000))
			}
		}
	}
	defer dumpLogOnFail()

	// ── Instance #1 ──────────────────────────────────────────────────────────
	proc1, cancel1 := launchCulvert(t, bin, policyPath, logPath)
	defer cancel1()
	if !waitForward(proxyURL, upstream.URL+"/", 40) {
		t.Fatalf("instance #1 never forwarded within 10s")
	}

	// Continuous background load until we stop it.
	stopLoad := make(chan struct{})
	var loadWG sync.WaitGroup
	var success, failure int64
	workers := 8
	loadWG.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer loadWG.Done()
			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
				Timeout:   2 * time.Second,
			}
			for {
				select {
				case <-stopLoad:
					return
				default:
				}
				resp, err := client.Get(upstream.URL + "/")
				if err != nil {
					atomic.AddInt64(&failure, 1)
					continue
				}
				if resp.StatusCode == http.StatusOK {
					atomic.AddInt64(&success, 1)
				} else {
					atomic.AddInt64(&failure, 1)
				}
				resp.Body.Close()
			}
		}()
	}

	// Let traffic flow, then restart under load.
	time.Sleep(750 * time.Millisecond)
	preRestart := atomic.LoadInt64(&success)
	if preRestart == 0 {
		t.Errorf("no successful requests before restart")
	}

	// SIGTERM #1 and assert graceful exit within the drain window.
	if err := proc1.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM #1: %v", err)
	}
	exited := make(chan struct{})
	go func() { proc1.Wait(); close(exited) }()
	select {
	case <-exited:
	case <-time.After(20 * time.Second):
		t.Errorf("instance #1 did not exit within 20s of SIGTERM (graceful drain stuck)")
		cancel1()
	}

	// ── Instance #2 on the same port (Go listeners set SO_REUSEADDR) ──────────
	proc2, cancel2 := launchCulvert(t, bin, policyPath, logPath)
	defer cancel2()
	if !waitForward(proxyURL, upstream.URL+"/", 60) {
		close(stopLoad)
		loadWG.Wait()
		t.Fatalf("instance #2 never forwarded after restart")
	}
	postRestartStart := atomic.LoadInt64(&success)

	// Confirm the fresh instance serves new traffic.
	time.Sleep(500 * time.Millisecond)
	close(stopLoad)
	loadWG.Wait()

	served := atomic.LoadInt64(&success) - postRestartStart
	if served == 0 {
		t.Errorf("instance #2 served no requests after restart")
	}
	t.Logf("restart-under-traffic: pre=%d, post-restart served=%d, total failures (incl. expected during restart)=%d",
		preRestart, served, atomic.LoadInt64(&failure))

	// Graceful shutdown of #2.
	if err := proc2.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM #2: %v", err)
	}
	done2 := make(chan struct{})
	go func() { proc2.Wait(); close(done2) }()
	select {
	case <-done2:
	case <-time.After(20 * time.Second):
		t.Errorf("instance #2 did not exit within 20s of SIGTERM")
		cancel2()
	}
}
