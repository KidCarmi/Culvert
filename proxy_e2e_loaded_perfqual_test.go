package main

// F3 Performance Qualification — DEPLOYED-POSTURE end-to-end proxy benchmark.
//
// WHY THIS EXISTS. The 2026-11-18 Performance Guardian pass closed with this
// nomination, in writing:
//
//	"A realistic-posture e2e profile. Every end-to-end benchmark in the tree
//	 configures an EMPTY blocklist, no threat feed, no plugins and no auth
//	 backend, so the profiles above under-represent a real deployment. A
//	 harness with a loaded feed and authentication enabled would profile a
//	 different function set — that is the most likely place an unswept cost
//	 remains."
//
// benchProxySetup (proxy_e2e_perfqual_test.go) is that empty posture: `bl =
// blocklist.New()` with zero entries, and a process-wide threat feed that has
// never been enabled. Both content gates then answer from a short-circuit —
// blocklist.IsBlocked returns on `len(m) == 0`, and secscan.Enabled() is false
// so CheckDomain and CheckRequestURL are never reached at all. A deployed
// gateway runs neither of those short-circuits.
//
// THE POSTURE IS THE ONLY VARIABLE. The two sub-benchmarks below share one
// rulebase, one client, one backend, one destination URL and one pinned
// upstream dial; `posture=loaded` differs from `posture=empty` by exactly the
// two gates' contents. That is what makes the allocation delta attributable,
// and it is the mistake this harness made in draft: measuring the loaded
// posture against the EXISTING benchmark compared two different destination
// URLs as well, so the net/http cost of a longer request landed in the
// column that was supposed to isolate Culvert's gates.
//
//	go test -run '^$' -bench 'BenchmarkPerfQual_ProxyHTTPForwardPosture' -benchmem -count=5 .

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// benchLoadedFeedEntries is the order of magnitude a deployed feed carries
// (urlhaus alone publishes ~100k rows). The lookups under test are map probes,
// so the count governs table size and cache behaviour, not algorithmic cost.
const benchLoadedFeedEntries = 100000

// benchLoadPosture loads the two content gates handleRequest consults on the
// request goroutine, before the policy engine: the legacy blocklist and the
// threat-intelligence feed. Returns a teardown that restores both.
func benchLoadPosture(tb testing.TB, entries int) func() {
	tb.Helper()
	feedDomains := make(map[string]int64, entries)
	feedURLs := make(map[string]int64, entries)
	blHosts := make([]string, 0, entries+entries/10)
	now := time.Now().Unix()
	for i := 0; i < entries; i++ {
		h := fmt.Sprintf("malware-%d.example.invalid", i)
		feedDomains[h] = now
		feedURLs["http://"+h+"/payload"] = now
		blHosts = append(blHosts, fmt.Sprintf("blocked-%d.example.invalid", i))
	}
	// Every tenth blocklist entry is a wildcard, so isListed's label walk is
	// LIVE rather than erased by its `len(b.wildcards) == 0` short-circuit —
	// the shape a real feed produces, and the one that makes the walk a cost
	// this benchmark can see.
	for i := 0; i < entries/10; i++ {
		blHosts = append(blHosts, fmt.Sprintf("*.wild-%d.example.invalid", i))
	}
	bl.ReplaceFeedEntries(blHosts)

	prevURLs, prevDomains := globalThreatFeed.ExportURLs(), globalThreatFeed.ExportDomains()
	globalThreatFeed.ImportFeedData(feedURLs, feedDomains)
	prevFeedEnabled := globalThreatFeed.SetEnabledForTest(true)
	globalSecScanner.Init("", 0, nil)

	return func() {
		globalThreatFeed.ImportFeedData(prevURLs, prevDomains)
		globalThreatFeed.SetEnabledForTest(prevFeedEnabled)
		bl.ReplaceFeedEntries(nil)
	}
}

// benchPinUpstreamDial points every upstream dial at addr, whatever authority
// the client asked for, and returns a teardown restoring the previous
// transport.
//
// WHY THE HARNESS NEEDS THIS. It is not a convenience — it is what makes the
// posture real. An httptest backend is reached as "127.0.0.1:PORT", and a
// loopback destination SHORT-CIRCUITS the gate this benchmark exists to
// exercise: the threat feed's URL check returns ("", "") for a private IP
// (verbatim from NormaliseURL, deliberately), so it never builds a lookup key
// and answers on two empty strings. Measured against 127.0.0.1 an enabled
// feed therefore looks nearly free — an artefact of the harness, not a
// property of the code. Measured here: a loopback destination hides 4 of the
// 6 allocations the loaded posture actually adds. Pinning the dial lets the
// request carry a PUBLIC hostname, what a deployed gateway sees, while the
// bytes still land on the in-process backend.
//
// Mutation goes through swapUpstreamTransport with old.Clone(), never a write
// to the published transport — see upstream_transport.go's contract.
func benchPinUpstreamDial(addr string) func() {
	prev := getUpstreamTransport()
	d := &net.Dialer{Timeout: 5 * time.Second}
	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		next := old.Clone()
		next.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
		return next
	})
	return func() {
		swapUpstreamTransport(func(*http.Transport) *http.Transport { return prev })
	}
}

// benchLoadedDestURL is the destination shape a deployed gateway forwards: a
// PUBLIC hostname with a real path and a query string. The query is present
// deliberately — the threat feed strips it, so it is bytes the check carries
// and then discards.
const benchLoadedDestURL = "http://files.example.com/downloads/report/q3-2026.pdf?token=abc123&v=2"

// BenchmarkPerfQual_ProxyHTTPForwardPosture drives one identical plain-HTTP
// forward request through the real handleRequest dispatch under both content
// postures. Read the two rows against each other: the delta is what a deployed
// blocklist and threat feed cost per allowed request, and it is the number
// every other end-to-end benchmark in the tree reports as zero.
func BenchmarkPerfQual_ProxyHTTPForwardPosture(b *testing.B) {
	for _, loaded := range []bool{false, true} {
		name := "posture=empty"
		if loaded {
			name = "posture=loaded"
		}
		b.Run(name, func(b *testing.B) {
			teardown := benchProxySetup(100)
			defer teardown()
			if loaded {
				untie := benchLoadPosture(b, benchLoadedFeedEntries)
				defer untie()
			}

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body) //nolint:errcheck // bench backend body drain; best-effort
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "ok") //nolint:errcheck // bench backend write; best-effort
			}))
			defer backend.Close()

			proxySrv := httptest.NewServer(http.HandlerFunc(handleRequest))
			defer proxySrv.Close()
			proxyURL, _ := url.Parse(proxySrv.URL)
			backendURL, _ := url.Parse(backend.URL)
			unpin := benchPinUpstreamDial(backendURL.Host)
			defer unpin()

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
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, benchLoadedDestURL, http.NoBody)
				resp, err := client.Do(req)
				if err != nil {
					b.Fatalf("proxied GET: %v", err)
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck // bench body drain; best-effort
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
