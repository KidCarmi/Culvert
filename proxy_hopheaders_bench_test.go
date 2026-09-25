package main

import (
	"net/http"
	"testing"
)

// Benchmarks for the per-request hop-by-hop header strip (removeHopHeaders).
//
// removeHopHeaders runs FOUR times per proxied exchange on the two highest
// volume paths in the product: the plain-HTTP forward path strips the request
// leg (prepareHTTPForward) and the response leg (handleHTTP), and the
// SSL-inspect path strips both legs of every decrypted inner exchange
// (runInspectExchange). An allocation here is an allocation on essentially
// every proxied request.
//
// Each shape is measured against legacyRemoveHopHeaders — the verbatim
// pre-change implementation, frozen in proxy_hopheaders_test.go — so the
// before/after comparison is reproducible from the tree rather than quoted
// from a commit message, and so the two arms are timed on the same machine in
// the same run. Run:
//
//	go test -run '^$' -bench 'HopHeaders' -benchmem .

func benchHopHeaders(b *testing.B, strip func(http.Header)) {
	for _, sh := range hopHeaderShapes {
		b.Run(sh.name, func(b *testing.B) {
			// Clone per iteration: the strip MUTATES the map, so a shared
			// header would measure a no-op after the first iteration.
			h := make(http.Header, len(sh.hdr)+4)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				clear(h)
				for k, vs := range sh.hdr {
					h[k] = vs
				}
				strip(h)
			}
		})
	}
}

func BenchmarkRemoveHopHeaders(b *testing.B)        { benchHopHeaders(b, removeHopHeaders) }
func BenchmarkRemoveHopHeaders_Legacy(b *testing.B) { benchHopHeaders(b, legacyRemoveHopHeaders) }

// BenchmarkRemoveHopHeadersExchange measures what one proxied exchange actually
// pays: the request leg plus the response leg, which is the unit an operator
// cares about (and half of what an inspected HTTPS request pays, since that
// path strips both legs of every inner exchange too).
func BenchmarkRemoveHopHeadersExchange(b *testing.B) {
	for _, arm := range []struct {
		name  string
		strip func(http.Header)
	}{
		{"Current", removeHopHeaders},
		{"Legacy", legacyRemoveHopHeaders},
	} {
		b.Run(arm.name, func(b *testing.B) {
			req := map[string][]string{
				"Host": {"example.com"}, "User-Agent": {"Mozilla/5.0"},
				"Accept": {"text/html"}, "Accept-Encoding": {"gzip"},
				"Connection": {"keep-alive"},
			}
			resp := map[string][]string{
				"Date": {"Thu, 18 Sep 2026 10:00:00 GMT"}, "Content-Type": {"text/html"},
				"Content-Length": {"1234"}, "Server": {"nginx"}, "Connection": {"keep-alive"},
			}
			rh := make(http.Header, len(req)+4)
			sh := make(http.Header, len(resp)+4)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				clear(rh)
				for k, vs := range req {
					rh[k] = vs
				}
				clear(sh)
				for k, vs := range resp {
					sh[k] = vs
				}
				arm.strip(rh)
				arm.strip(sh)
			}
		})
	}
}
