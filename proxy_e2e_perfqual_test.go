package main

// F3 Performance Qualification — END-TO-END proxy benchmarks (HTTP forward +
// CONNECT tunnel establishment) through the REAL handleRequest dispatch, with a
// realistic mixed rulebase. Untracked qualification artifact: Benchmark
// functions only (no Test*), so `go test ./...` is unaffected. Builds
// identically on parent a4f9ee1 and HEAD.
//
//   go test -run '^$' -bench 'BenchmarkPerfQual_Proxy' -benchmem -count=N .
//
// Reported custom metrics: p50-ns / p95-ns per operation (full request for the
// HTTP benchmark; CONNECT establishment for the tunnel benchmark).

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// cpuNow returns the process's cumulative user+system CPU time. Wall-clock
// latency on a shared VM is scheduler-noisy; CPU/request is the stable metric
// the qualification budget is defined over. All benchmark actors (client,
// proxy handler, backend) run in this one process, identically on both builds,
// so the delta isolates the build difference.
func cpuNow() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	toDur := func(tv syscall.Timeval) time.Duration {
		return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
	}
	return toDur(ru.Utime) + toDur(ru.Stime)
}

// benchProxySetup wires the minimal globals handleRequest needs, with a
// realistic mixed rulebase: `size` rules alternating FQDN-scoped and
// CIDR-scoped misses, with a catch-all Allow evaluated LAST — the worst
// realistic case for allowed traffic (full scan per request). Returns a
// teardown func.
func benchProxySetup(size int) func() {
	restoreLog := benchSilenceLogger() // per-request POLICY_ALLOW stderr writes would dominate
	prevCfg, prevReg := cfg, idpRegistry
	prevBl := bl
	bl = blocklist.New()
	ipf = &IPFilter{single: map[string]bool{}}
	rl = newRateLimiter()
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	idpRegistry = &IdPRegistry{}
	pluginReplace(nil)
	prevAction := defaultPolicyAction()
	setDefaultPolicyAction("deny")

	rules := make([]PolicyRule, 0, size+1)
	for i := 0; i < size; i++ {
		r := PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("bench-rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
		if i%3 == 1 { // every third rule is source-scoped (client inside the CIDR)
			r.SourceIP = "127.0.0.0/8"
		}
		rules = append(rules, r)
	}
	rules = append(rules, PolicyRule{Priority: size + 1, Name: "catch-all", DestFQDN: "*", Action: ActionAllow})
	policyStore.ReplaceAll(rules)

	return func() {
		restoreLog()
		policyStore.ReplaceAll(nil)
		setDefaultPolicyAction(prevAction)
		cfg, idpRegistry = prevCfg, prevReg
		bl = prevBl
	}
}

func reportPercentiles(b *testing.B, lat []time.Duration) {
	if len(lat) == 0 {
		return
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) float64 {
		idx := int(q * float64(len(lat)-1))
		return float64(lat[idx].Nanoseconds())
	}
	b.ReportMetric(p(0.50), "p50-ns")
	b.ReportMetric(p(0.95), "p95-ns")
}

// BenchmarkPerfQual_ProxyHTTPForward drives plain-HTTP forward requests through
// handleRequest (auth resolution → host gate → pre-dispatch blocks → policy
// evaluation → handleHTTP → upstream round trip) over a keep-alive connection.
func BenchmarkPerfQual_ProxyHTTPForward(b *testing.B) {
	for _, size := range []int{10, 100, 500} {
		b.Run(fmt.Sprintf("rules=%d", size), func(b *testing.B) {
			teardown := benchProxySetup(size)
			defer teardown()

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body) //nolint:errcheck
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "ok") //nolint:errcheck
			}))
			defer backend.Close()

			proxySrv := httptest.NewServer(http.HandlerFunc(handleRequest))
			defer proxySrv.Close()
			proxyURL, _ := url.Parse(proxySrv.URL)

			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), MaxIdleConnsPerHost: 4},
				Timeout:   10 * time.Second,
			}

			lat := make([]time.Duration, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			cpu0 := cpuNow()
			for i := 0; i < b.N; i++ {
				t0 := time.Now()
				resp, err := client.Get(backend.URL + "/")
				if err != nil {
					b.Fatalf("proxied GET: %v", err)
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					b.Fatalf("status %d", resp.StatusCode)
				}
				lat = append(lat, time.Since(t0))
			}
			cpuUsed := cpuNow() - cpu0
			b.StopTimer()
			b.ReportMetric(float64(cpuUsed.Nanoseconds())/float64(b.N), "cpu-ns/op")
			reportPercentiles(b, lat)
		})
	}
}

// BenchmarkPerfQual_ProxyCONNECT measures CONNECT tunnel ESTABLISHMENT (dial →
// CONNECT → 200 → close) through the real bypass-tunnel path, per operation.
func BenchmarkPerfQual_ProxyCONNECT(b *testing.B) {
	for _, size := range []int{100} {
		b.Run(fmt.Sprintf("rules=%d", size), func(b *testing.B) {
			teardown := benchProxySetup(size)
			defer teardown()
			restoreSSRF := ssrf.AllowLoopbackForTest()
			defer restoreSSRF()

			// Raw TCP echo target for the tunnel.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						io.Copy(c, c) //nolint:errcheck
					}(c)
				}
			}()

			proxySrv := httptest.NewServer(http.HandlerFunc(handleRequest))
			defer proxySrv.Close()
			proxyURL, _ := url.Parse(proxySrv.URL)
			target := ln.Addr().String()

			lat := make([]time.Duration, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			cpu0 := cpuNow()
			for i := 0; i < b.N; i++ {
				t0 := time.Now()
				conn, err := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second)
				if err != nil {
					b.Fatalf("dial proxy: %v", err)
				}
				fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target) //nolint:errcheck
				br := bufio.NewReader(conn)
				line, err := br.ReadString('\n')
				if err != nil || !containsHTTP200(line) {
					b.Fatalf("CONNECT response %q err %v", line, err)
				}
				// drain headers to the blank line
				for {
					h, err := br.ReadString('\n')
					if err != nil {
						b.Fatalf("read headers: %v", err)
					}
					if h == "\r\n" || h == "\n" {
						break
					}
				}
				conn.Close()
				lat = append(lat, time.Since(t0))
			}
			cpuUsed := cpuNow() - cpu0
			b.StopTimer()
			b.ReportMetric(float64(cpuUsed.Nanoseconds())/float64(b.N), "cpu-ns/op")
			reportPercentiles(b, lat)
		})
	}
}

func containsHTTP200(line string) bool {
	return len(line) >= 12 && line[9] == '2' && line[10] == '0' && line[11] == '0'
}
