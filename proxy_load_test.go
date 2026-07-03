//go:build proxyload

package main

// Proxy traffic-plane LOAD harness (CI quality program — PR-2).
//
// Build-tagged `proxyload` so it is EXCLUDED from the normal `go test ./...`
// that qa-gate.yml runs — it adds zero cost to the required gates. The nightly
// workflow runs it with `-tags proxyload` and uploads pprof profiles.
//
// It reuses the hermetic PR-1 fixtures (startTestProxy, startEchoServer,
// startCountingBackend, allowLoopbackTunnel, readConnectStatus): no public
// internet, no Docker. It pushes concurrent real traffic through the real proxy
// listener and answers production questions:
//
//   - Can the proxy sustain N concurrent HTTP clients with a 0% error rate?
//   - Can it sustain N concurrent CONNECT tunnels, each relaying bytes exactly?
//   - What are the p50/p95/p99 latencies under that load?
//   - Do request metrics move, and do active-connection / goroutine counts
//     return to baseline afterwards (no leak)?
//
// All knobs are env-tunable with conservative CI-smoke defaults so the same
// test scales from a PR runner to a lab box:
//
//   CULVERT_LOAD_CLIENTS    HTTP concurrent clients          (default 50)
//   CULVERT_LOAD_REQS       HTTP requests per client         (default 20)
//   CULVERT_LOAD_TUNNELS    concurrent CONNECT tunnels        (default 50)
//   CULVERT_LOAD_HTTP_P95_MS HTTP p95 latency bound, ms        (default 1000)
//   CULVERT_LOAD_CONNECT_P95_MS CONNECT setup p95 bound, ms    (default 1000)
//   CULVERT_LOAD_PPROF      dir to write cpu/heap/goroutine profiles (default off)
//
// Run locally:
//   go test -tags proxyload -run 'TestProxyLoad_' -v -timeout 5m .

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func loadEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// percentile returns the p-th percentile (0..100) of an already-sorted slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p / 100 * float64(len(sorted)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func reportLatencies(t *testing.T, label string, lat []time.Duration) (p50, p95, p99 time.Duration) {
	t.Helper()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50, p95, p99 = percentile(lat, 50), percentile(lat, 95), percentile(lat, 99)
	max := time.Duration(0)
	if len(lat) > 0 {
		max = lat[len(lat)-1]
	}
	t.Logf("%s: samples=%d p50=%s p95=%s p99=%s max=%s", label, len(lat), p50, p95, p99, max)
	return p50, p95, p99
}

// startCPUProfile begins a CPU profile if CULVERT_LOAD_PPROF names a dir, and
// returns a stop func that also writes heap + goroutine profiles.
func startCPUProfile(t *testing.T, name string) func() {
	t.Helper()
	dir := os.Getenv("CULVERT_LOAD_PPROF")
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("pprof: mkdir %s: %v", dir, err)
		return func() {}
	}
	cpuPath := filepath.Join(dir, name+"-cpu.prof")
	f, err := os.Create(cpuPath)
	if err != nil {
		t.Logf("pprof: create %s: %v", cpuPath, err)
		return func() {}
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		t.Logf("pprof: start: %v", err)
		return func() {}
	}
	return func() {
		pprof.StopCPUProfile()
		f.Close()
		for _, p := range []string{"heap", "goroutine"} {
			path := filepath.Join(dir, name+"-"+p+".prof")
			pf, err := os.Create(path)
			if err != nil {
				continue
			}
			pprof.Lookup(p).WriteTo(pf, 0) //nolint:errcheck
			pf.Close()
		}
		t.Logf("pprof: wrote %s-{cpu,heap,goroutine}.prof to %s", name, dir)
	}
}

// TestProxyLoad_HTTPConcurrent drives many concurrent HTTP clients through the
// real proxy and asserts a 0% error rate, exact upstream delivery, moving
// metrics, and a bounded p95.
func TestProxyLoad_HTTPConcurrent(t *testing.T) {
	clients := loadEnvInt("CULVERT_LOAD_CLIENTS", 50)
	reqsPer := loadEnvInt("CULVERT_LOAD_REQS", 20)
	p95Bound := time.Duration(loadEnvInt("CULVERT_LOAD_HTTP_P95_MS", 1000)) * time.Millisecond
	total := clients * reqsPer

	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t) // default-allow

	// Optionally drive the load under a large policy set so the measured p95
	// includes per-request policy evaluation cost (answers "p95 under policy
	// load"). The rules are non-matching, so default-allow still admits every
	// request — but Evaluate scans all of them on the hot path.
	if polRules := loadEnvInt("CULVERT_LOAD_POLICY_RULES", 0); polRules > 0 {
		policyStore.rules = nil
		for i := 0; i < polRules; i++ {
			policyStore.Add(PolicyRule{
				Priority: i + 1,
				Name:     fmt.Sprintf("load-rule-%d", i),
				DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
				Action:   ActionAllow,
			})
		}
		t.Logf("HTTP load running under %d-rule policy set", polRules)
	}

	statBefore := atomic.LoadInt64(&statTotal)
	blockedBefore := atomic.LoadInt64(&statBlocked)

	lat := make([]time.Duration, total)
	var errs int64
	var wg sync.WaitGroup
	wg.Add(clients)

	stop := startCPUProfile(t, "http-load")
	start := time.Now()
	for c := 0; c < clients; c++ {
		go func(cid int) {
			defer wg.Done()
			// One client (keep-alive transport) per goroutine — also exercises
			// connection reuse through the proxy.
			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), MaxIdleConnsPerHost: 4},
				Timeout:   10 * time.Second,
			}
			for r := 0; r < reqsPer; r++ {
				idx := cid*reqsPer + r
				t0 := time.Now()
				resp, err := client.Get(backend.URL + "/")
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
	stop()

	if errs != 0 {
		t.Errorf("HTTP load: %d/%d requests errored — proxy must sustain %d concurrent clients at 0%% error", errs, total, clients)
	}
	if got := cb.hitCount(); got != int64(total) {
		t.Errorf("HTTP load: upstream received %d requests, want %d", got, total)
	}
	if delta := atomic.LoadInt64(&statTotal) - statBefore; delta < int64(total) {
		t.Errorf("HTTP load: statTotal moved by %d, want >= %d (request metrics must count load)", delta, total)
	}
	if delta := atomic.LoadInt64(&statBlocked) - blockedBefore; delta != 0 {
		t.Errorf("HTTP load: statBlocked moved by %d under an all-allow policy, want 0", delta)
	}

	p50, p95, _ := reportLatencies(t, "HTTP", lat)
	t.Logf("HTTP throughput: %d reqs in %s = %.0f req/s (clients=%d, reqs/client=%d)",
		total, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), clients, reqsPer)
	if p95 > p95Bound {
		t.Errorf("HTTP p95=%s exceeds bound %s (p50=%s) — raise CULVERT_LOAD_HTTP_P95_MS only if the runner is known-slow", p95, p95Bound, p50)
	}
}

// TestProxyLoad_CONNECTTunnels opens many concurrent CONNECT tunnels through
// the real proxy, relays a unique payload through each, and asserts byte-exact
// echo, a 0% failure rate, a bounded setup p95, and no connection / goroutine
// leak after teardown.
func TestProxyLoad_CONNECTTunnels(t *testing.T) {
	tunnels := loadEnvInt("CULVERT_LOAD_TUNNELS", 50)
	p95Bound := time.Duration(loadEnvInt("CULVERT_LOAD_CONNECT_P95_MS", 1000)) * time.Millisecond

	allowLoopbackTunnel(t)
	echo := startEchoServer(t)
	proxyURL := startTestProxy(t)

	baseGoroutines := runtime.NumGoroutine()
	setupLat := make([]time.Duration, tunnels)
	var errs int64
	var wg sync.WaitGroup
	wg.Add(tunnels)

	stop := startCPUProfile(t, "connect-load")
	start := time.Now()
	for i := 0; i < tunnels; i++ {
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", proxyURL.Host, 10*time.Second)
			if err != nil {
				atomic.AddInt64(&errs, 1)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))

			t0 := time.Now()
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.addr, echo.addr); err != nil {
				atomic.AddInt64(&errs, 1)
				return
			}
			br := bufio.NewReader(conn)
			status, err := readConnectStatus(br)
			if err != nil || status != http.StatusOK {
				atomic.AddInt64(&errs, 1)
				return
			}
			setupLat[id] = time.Since(t0)

			payload := []byte(fmt.Sprintf("tunnel-%d-payload-probe", id))
			if _, err := conn.Write(payload); err != nil {
				atomic.AddInt64(&errs, 1)
				return
			}
			got := make([]byte, len(payload))
			if _, err := readFull(br, got); err != nil || !bytes.Equal(got, payload) {
				atomic.AddInt64(&errs, 1)
				return
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	stop()

	if errs != 0 {
		t.Errorf("CONNECT load: %d/%d tunnels failed — proxy must sustain %d concurrent tunnels", errs, tunnels, tunnels)
	}
	if got := echo.acceptCount(); got != int64(tunnels) {
		t.Errorf("CONNECT load: echo upstream accepted %d tunnels, want %d", got, tunnels)
	}

	_, p95, _ := reportLatencies(t, "CONNECT-setup", setupLat)
	t.Logf("CONNECT throughput: %d tunnels in %s = %.0f tunnels/s", tunnels, elapsed.Round(time.Millisecond), float64(tunnels)/elapsed.Seconds())
	if p95 > p95Bound {
		t.Errorf("CONNECT setup p95=%s exceeds bound %s", p95, p95Bound)
	}

	// Active-conn gauge and goroutines must return to baseline (drain / no leak).
	deadline := time.Now().Add(3 * time.Second)
	for getActiveConns() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := getActiveConns(); n != 0 {
		t.Errorf("CONNECT load: %d active connections still counted after teardown — drain/leak", n)
	}
	assertGoroutinesSettle(t, baseGoroutines)
}

// readFull is io.ReadFull without importing io into the tag file's surface
// (kept local for clarity; bufio.Reader satisfies io.Reader).
func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
