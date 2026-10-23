package main

import (
	"net/http"
	"net/textproto"
	"strings"
	"testing"
)

// legacyRemoveHopHeaders is a VERBATIM copy of removeHopHeaders as it stood
// before the canonical-spelling change (proxy_tunnel.go). It is the oracle for
// the differential test below and the "before" arm of the benchmarks in
// proxy_hopheaders_bench_test.go, so the comparison stays reproducible from the
// tree instead of quoted from a commit message.
//
// Do not "tidy" this function — its value is that it is the old code.
func legacyRemoveHopHeaders(h http.Header) {
	for _, v := range h["Connection"] {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, hdr := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(hdr)
	}
}

// hopHeaderShapes are the request/response header sets that reach
// removeHopHeaders in production. Each is exercised twice per proxied plain-HTTP
// request (request leg + response leg) and twice per decrypted inner exchange of
// an SSL-inspected tunnel.
var hopHeaderShapes = []struct {
	name string
	hdr  map[string][]string
}{
	// The dominant shape: an HTTP/1.1 client that relies on the keep-alive
	// default and sends no Connection header at all.
	{"NoConnectionHeader", map[string][]string{
		"Host": {"example.com"}, "User-Agent": {"curl/8.5.0"},
		"Accept": {"*/*"}, "Accept-Encoding": {"gzip"},
	}},
	{"ConnectionKeepAlive", map[string][]string{
		"Host": {"example.com"}, "User-Agent": {"Mozilla/5.0"},
		"Accept": {"text/html"}, "Connection": {"keep-alive"},
	}},
	{"ConnectionClose", map[string][]string{
		"Host": {"example.com"}, "Connection": {"close"},
		"Content-Type": {"application/json"},
	}},
	// A response leg as an origin typically writes it.
	{"OriginResponse", map[string][]string{
		"Date": {"Thu, 18 Sep 2026 10:00:00 GMT"}, "Content-Type": {"text/html"},
		"Content-Length": {"1234"}, "Server": {"nginx"}, "Connection": {"keep-alive"},
	}},
	// WebSocket upgrade: Connection names a further hop-by-hop header.
	{"ConnectionUpgrade", map[string][]string{
		"Host": {"example.com"}, "Connection": {"Upgrade"},
		"Upgrade": {"websocket"}, "Sec-Websocket-Version": {"13"},
	}},
	// Connection listing several tokens, the RFC 7230 §6.1 case the first loop
	// exists for.
	{"ConnectionMultiToken", map[string][]string{
		"Host": {"example.com"}, "Connection": {"keep-alive, Trailer, X-Custom-Hop"},
		"X-Custom-Hop": {"drop-me"}, "Trailer": {"Expires"},
	}},
	// Every hop-by-hop name actually present — the worst case for the Del loop.
	{"AllHopHeadersPresent", map[string][]string{
		"Host": {"example.com"}, "Connection": {"keep-alive"},
		"Keep-Alive": {"timeout=5"}, "Proxy-Authenticate": {"Basic"},
		"Proxy-Authorization": {"Basic eA=="}, "Te": {"trailers"},
		"Trailer": {"Expires"}, "Transfer-Encoding": {"chunked"},
		"Upgrade": {"h2c"},
	}},
}

func cloneShape(src map[string][]string) http.Header {
	h := make(http.Header, len(src))
	for k, vs := range src {
		h[k] = append([]string(nil), vs...)
	}
	return h
}

// TestRemoveHopHeaders_MatchesLegacy is the differential contract: the
// canonical-spelling rewrite is a COST change, not a behaviour change, so for
// every reachable header shape the surviving header map must be byte-identical
// to what the frozen pre-change implementation produced.
func TestRemoveHopHeaders_MatchesLegacy(t *testing.T) {
	shapes := append([]struct {
		name string
		hdr  map[string][]string
	}{}, hopHeaderShapes...)

	// Divergence shapes the production set does not reach: the empty header,
	// the empty and degenerate Connection values (which strings.Split renders
	// as a one-element slice), non-canonical client spellings, multi-line
	// Connection headers, and the "TE" spelling in both cases.
	extra := []struct {
		name string
		hdr  map[string][]string
	}{
		{"Empty", map[string][]string{}},
		{"EmptyConnectionValue", map[string][]string{"Connection": {""}, "Te": {"trailers"}}},
		{"CommaOnlyConnection", map[string][]string{"Connection": {","}, "Te": {"trailers"}}},
		{"TrailingCommaConnection", map[string][]string{"Connection": {"keep-alive,"}, "Keep-Alive": {"timeout=5"}}},
		{"EmptyFieldInsideConnection", map[string][]string{"Connection": {"a,,b"}, "A": {"1"}, "B": {"2"}}},
		{"MultiLineConnection", map[string][]string{"Connection": {"keep-alive", "X-Hop"}, "X-Hop": {"1"}}},
		{"LowercaseTEPresent", map[string][]string{"te": {"trailers"}, "Host": {"example.com"}}},
		{"UppercaseTEPresent", map[string][]string{"TE": {"trailers"}, "Host": {"example.com"}}},
		{"CanonicalTePresent", map[string][]string{"Te": {"trailers"}, "Host": {"example.com"}}},
		{"ConnectionNamesTE", map[string][]string{"Connection": {"TE"}, "Te": {"trailers"}}},
		{"WhitespaceOnlyField", map[string][]string{"Connection": {"  ,  "}, "Host": {"example.com"}}},
		{"ConnectionNamesItself", map[string][]string{"Connection": {"Connection"}, "Host": {"example.com"}}},
	}
	shapes = append(shapes, extra...)

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			got, want := cloneShape(sh.hdr), cloneShape(sh.hdr)
			removeHopHeaders(got)
			legacyRemoveHopHeaders(want)

			if len(got) != len(want) {
				t.Fatalf("key count: got %d %v, legacy %d %v", len(got), got, len(want), want)
			}
			for k, wv := range want {
				gv, ok := got[k]
				if !ok {
					t.Fatalf("key %q present in legacy result, missing from new result", k)
				}
				if strings.Join(gv, "\x00") != strings.Join(wv, "\x00") {
					t.Fatalf("key %q: got %q, legacy %q", k, gv, wv)
				}
			}
		})
	}
}

// TestHopByHopHeaderNames_AreCanonical is the STRUCTURAL half of the change and
// the reason it is a win at all: http.Header.Del routes its argument through
// textproto.CanonicalMIMEHeaderKey, whose fast path returns an already-canonical
// key verbatim and whose slow path allocates. "TE" is NOT the canonical spelling
// (Go renders it "Te"), so spelling it that way cost an allocation and a rewrite
// on every one of the four per-request call sites.
//
// This pins the table against net/textproto itself, so neither a future Go
// change nor a well-meaning respelling can silently reintroduce the cost.
func TestHopByHopHeaderNames_AreCanonical(t *testing.T) {
	if len(hopByHopHeaderNames) == 0 {
		t.Fatal("hopByHopHeaderNames is empty — the Del loop would strip nothing")
	}
	for _, name := range hopByHopHeaderNames {
		if canonical := textproto.CanonicalMIMEHeaderKey(name); canonical != name {
			t.Errorf("hopByHopHeaderNames entry %q is not canonical: net/textproto renders it %q, "+
				"so every Del takes the allocating slow path", name, canonical)
		}
	}
}

// TestHopByHopHeaderNames_CoverRFC7230 pins the SET, so the canonicalisation
// gate above can never be satisfied by deleting a name from the table.
func TestHopByHopHeaderNames_CoverRFC7230(t *testing.T) {
	want := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	}
	have := make(map[string]bool, len(hopByHopHeaderNames))
	for _, n := range hopByHopHeaderNames {
		have[n] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("hop-by-hop header %q is no longer stripped", n)
		}
	}
	if len(hopByHopHeaderNames) != len(want) {
		t.Errorf("hopByHopHeaderNames has %d entries, want %d: %v", len(hopByHopHeaderNames), len(want), hopByHopHeaderNames)
	}
}

// TestRemoveHopHeaders_StripsEveryHopByHopSpelling is the behavioural control:
// the point of the strip is that the header is GONE, whatever case the peer
// sent it in. A gate that only checked canonicality would pass if the function
// stopped stripping anything.
func TestRemoveHopHeaders_StripsEveryHopByHopSpelling(t *testing.T) {
	for _, spelling := range []string{"TE", "te", "Te", "tE"} {
		h := http.Header{}
		h[textproto.CanonicalMIMEHeaderKey(spelling)] = []string{"trailers"}
		h.Set("Host", "example.com")
		removeHopHeaders(h)
		if v := h.Get("TE"); v != "" {
			t.Errorf("spelling %q: TE survived the strip as %q", spelling, v)
		}
		if h.Get("Host") != "example.com" {
			t.Errorf("spelling %q: end-to-end header Host was stripped", spelling)
		}
	}
}
