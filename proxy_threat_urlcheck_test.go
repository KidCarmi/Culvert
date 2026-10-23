package main

// End-to-end coverage for the full-URL threat check on the request path.
//
// preDispatchBlocked runs this check on every forwarded plain-HTTP request
// (CONNECT and WebSocket are excluded by the guard above it). It used to call it
// as CheckURL(r.URL.String()) — serialising a *url.URL net/http had just parsed
// so the feed could parse it straight back — and now calls
// CheckRequestURL(r.URL), which reaches the same
// verdict without the round trip (see threatfeed.Feed.CheckRequestURL and
// internal/threatfeed/checkrequesturl_test.go for the differential proving the
// two agree).
//
// That call-site swap is the only production line the change touches, and
// nothing exercised this branch end to end: the package had unit coverage for
// Scanner.CheckURL (idp_geoip_secscan_test.go) but nothing that drove the real
// preDispatchBlocked, so a wiring mistake — the wrong field, a dropped guard,
// the check silently never firing — would have shipped green. These tests are
// deliberately about the WIRING, not about normalisation: they assert that a
// URL-table entry still blocks through the real dispatch gate, that the query
// string is still stripped before the lookup, and that clean traffic still
// passes.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// withURLThreatFeed installs a scanner whose feed carries exactly the given
// URL-table entries, and restores the previous one.
func withURLThreatFeed(t *testing.T, urls map[string]string) {
	t.Helper()
	prevScanner, prevFeed := globalSecScanner, globalThreatFeed
	tf := newEnabledFeed()
	tf.SeedForTest(urls, nil)
	globalThreatFeed = tf
	globalSecScanner = newEnabledScanner(secscan.Deps{Feed: tf})
	// The plugin chain runs inside preDispatchBlocked ahead of the threat
	// checks; isolate it so a middleware installed by another test cannot
	// decide these verdicts.
	prevPlugins := pluginReplace(nil)
	t.Cleanup(func() {
		globalSecScanner, globalThreatFeed = prevScanner, prevFeed
		pluginReplace(prevPlugins)
	})
}

func TestPreDispatch_URLThreatCheckBlocksThroughRequestPath(t *testing.T) {
	withURLThreatFeed(t, map[string]string{"http://evil.example.com/malware": "urlhaus"})

	cases := []struct {
		name     string
		target   string
		wantStat string
	}{
		{"exact match blocks", "http://evil.example.com/malware", "THREAT_BLOCKED"},
		// NormaliseURL strips the query before the lookup, so a query string
		// must not let a listed URL through. This is the property the removed
		// round trip used to establish by re-parsing.
		{"query stripped before lookup", "http://evil.example.com/malware?x=1&y=2", "THREAT_BLOCKED"},
		{"host case folded", "http://EVIL.EXAMPLE.COM/malware", "THREAT_BLOCKED"},
		{"different path passes", "http://evil.example.com/benign", ""},
		{"different host passes", "http://clean.example.com/malware", ""},
		// A '#' in a request-target is NOT a fragment: url.ParseRequestURI does
		// not split one off, so it is part of the path and this is a different
		// URL. Worth pinning because it is the case the removed round trip
		// handled by escaping to %23 and unescaping back — reading u.Path
		// directly has to land on the same key, and does.
		{"hash in request-target is part of the path", "http://evil.example.com/malware#frag", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, http.NoBody)
			w := httptest.NewRecorder()
			status, blocked := preDispatchBlocked(w, r, "203.0.113.7", r.URL.Hostname(), "req-1", "", AuthLogFields{})
			switch {
			case tc.wantStat == "" && blocked:
				t.Fatalf("preDispatchBlocked(%q) blocked with status %q, want pass-through", tc.target, status)
			case tc.wantStat != "" && (!blocked || status != tc.wantStat):
				t.Fatalf("preDispatchBlocked(%q) = (%q, %v), want (%q, true)", tc.target, status, blocked, tc.wantStat)
			}

			// The expectations above are hand-written, so they can encode a
			// wrong guess (an earlier draft of this table did, for the '#'
			// case). Assert against the PRE-CHANGE call shape as well: whatever
			// the right answer is, the two must agree.
			legacyHit, _ := globalThreatFeed.CheckURL(r.URL.String())
			if legacyHit != blocked {
				t.Fatalf("preDispatchBlocked(%q) blocked=%v but CheckURL(u.String()) hit=%v — "+
					"the call-site swap changed a verdict", tc.target, blocked, legacyHit)
			}
		})
	}
}

// TestPreDispatch_URLThreatCheckSkippedForCONNECT pins the pre-existing guard
// that the full-URL check is plain-HTTP only — a CONNECT target is opaque, and
// the domain check above it is what covers tunnels.
func TestPreDispatch_URLThreatCheckSkippedForCONNECT(t *testing.T) {
	withURLThreatFeed(t, map[string]string{"http://evil.example.com/malware": "urlhaus"})

	r := httptest.NewRequest(http.MethodConnect, "http://evil.example.com/malware", http.NoBody)
	r.Method = http.MethodConnect
	w := httptest.NewRecorder()
	if status, blocked := preDispatchBlocked(w, r, "203.0.113.7", "evil.example.com", "req-2", "", AuthLogFields{}); blocked {
		t.Fatalf("CONNECT reached the full-URL check: status %q", status)
	}
}
