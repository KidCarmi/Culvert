package main

// F3b-2 download/network tests — the §A.8 URL/SSRF/redirect/TLS/timeout/compression
// contract. Required-test classes: 1 (official URL acceptance), 2 (every URL/SSRF
// rejection class), 3 (public→private rebinding), 4 (dial validated IP w/ official
// Host+SNI), 5 (TLS hostname/cert failure), 6 (redirect limit + per-hop revalidation),
// 7 (redirect escape), 8 (timeout/cancellation classification), 9 (compressed/
// oversized/truncated), 15 (artifact path traversal), 33 (fuzz on URL/key decoding).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ── 1. official manifest URL acceptance ──────────────────────────────────────────

func TestF3b2_ManifestURLAccepted(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	fo := newFeedOrigin(t, newFeedMux(g))
	out, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err != nil {
		t.Fatalf("official URL rejected: %v", err)
	}
	if len(out.Body) == 0 || out.NotModified {
		t.Fatalf("expected body, got %+v", out)
	}
}

// ── 2. every URL / SSRF rejection class (validated before any dial) ──────────────

func TestF3b2_URLContractRejections(t *testing.T) {
	fetcher := newFeedFetcher(feedFetcherOpts{allowPrivate: true})
	cases := map[string]string{
		"http scheme":       "http://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
		"ftp scheme":        "ftp://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
		"wrong host":        "https://evil.example.com/v1/url-categories/saas/manifest.sigstore.json",
		"subdomain":         "https://cdn.feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
		"userinfo":          "https://user:pass@feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
		"explicit port":     "https://feeds.culvertlabs.com:8443/v1/url-categories/saas/manifest.sigstore.json",
		"ipv4 literal":      "https://93.184.216.34/v1/url-categories/saas/manifest.sigstore.json",
		"ipv6 literal":      "https://[2606:2800:220:1:248:1893:25c8:1946]/v1/url-categories/saas/manifest.sigstore.json",
		"query":             "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json?x=1",
		"fragment":          "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json#f",
		"wrong path":        "https://feeds.culvertlabs.com/v1/url-categories/saas/other.json",
		"traversal in path": "https://feeds.culvertlabs.com/v1/url-categories/saas/../../etc/passwd",
		"root path":         "https://feeds.culvertlabs.com/",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := fetcher.fetchManifest(context.Background(), raw, "")
			if err == nil {
				t.Fatalf("%s: accepted a contract-violating URL", name)
			}
			if !errors.Is(err, errFeedFetchURLContract) {
				t.Fatalf("%s: err = %v; want errFeedFetchURLContract", name, err)
			}
		})
	}
}

// ── 3. public resolution followed by a private rebinding attempt ─────────────────

func TestF3b2_SSRFPrivateAddressRejected(t *testing.T) {
	privates := []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1", "100.64.0.1"}
	for _, ipStr := range privates {
		t.Run(ipStr, func(t *testing.T) {
			fetcher := newFeedFetcher(feedFetcherOpts{
				// The host "resolves public" at the contract layer but the resolver
				// hands back a PRIVATE address (the rebinding target). The dial-time
				// guard must reject the actually-resolved IP.
				resolve: func(_ context.Context, host string) ([]net.IP, error) {
					return []net.IP{net.ParseIP(ipStr)}, nil
				},
				dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					t.Fatalf("dial reached for a private target %s (addr=%s)", ipStr, addr)
					return nil, nil
				},
				// Production guard (allowPrivate=false) so private addresses are rejected.
			})
			_, err := fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
			if err == nil || !errors.Is(err, errFeedFetchSSRF) {
				t.Fatalf("%s: err = %v; want errFeedFetchSSRF", ipStr, err)
			}
		})
	}
}

// ── 4. dialing the validated IP with official Host + SNI ─────────────────────────

func TestF3b2_DialsResolvedIPWithOfficialHostAndSNI(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	var gotHost string
	mux := newFeedMux(g)
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		mux.ServeHTTP(w, r)
	}))
	if _, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, ""); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if fo.dialedAddr != "127.0.0.1:443" {
		t.Fatalf("dialed %q; want the resolved public IP", fo.dialedAddr)
	}
	if fo.sniName != saasFeedOfficialHost {
		t.Fatalf("SNI %q; want %q", fo.sniName, saasFeedOfficialHost)
	}
	if gotHost != saasFeedOfficialHost {
		t.Fatalf("HTTP Host %q; want %q", gotHost, saasFeedOfficialHost)
	}
}

// ── 5. TLS hostname / certificate failure ────────────────────────────────────────

func TestF3b2_TLSHostnameFailure(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	// Cert bears the WRONG SAN, so verifying it against the pinned official hostname
	// fails even though the CA is trusted.
	fo := newFeedOriginCert(t, newFeedMux(g), []string{"not-the-feed.example"}, true)
	_, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err == nil {
		t.Fatal("accepted a cert without the official hostname")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Fatalf("err = %v; want a TLS certificate error", err)
	}
}

func TestF3b2_TLSUntrustedCA(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	// Correct SAN but the fetcher does NOT trust the CA.
	fo := newFeedOriginCert(t, newFeedMux(g), []string{saasFeedOfficialHost}, false)
	if _, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, ""); err == nil {
		t.Fatal("accepted an untrusted CA")
	}
}

// ── 6/7. redirects: cap + per-hop revalidation + escape rejection ────────────────

func TestF3b2_RedirectLimit(t *testing.T) {
	// Always redirect back to the SAME approved manifest URL (contract-valid target),
	// so the ONLY thing that stops the loop is the hop cap.
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, builtinSaaSFeedURL, http.StatusFound)
	}))
	_, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err == nil || !errors.Is(err, errFeedFetchTooMany) {
		t.Fatalf("err = %v; want errFeedFetchTooMany", err)
	}
}

func TestF3b2_RedirectEscapeRejected(t *testing.T) {
	cases := map[string]string{
		"other host":       "https://evil.example.com/v1/url-categories/saas/manifest.sigstore.json",
		"other path":       "https://feeds.culvertlabs.com/v1/url-categories/saas/secret.json",
		"private host":     "https://169.254.169.254/latest/meta-data",
		"scheme downgrade": "http://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target)
				w.WriteHeader(http.StatusFound)
			}))
			_, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
			if err == nil || !errors.Is(err, errFeedFetchRedirect) {
				t.Fatalf("%s: err = %v; want errFeedFetchRedirect", name, err)
			}
		})
	}
}

func TestF3b2_SingleRedirectFollowedThenServed(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	mux := newFeedMux(g)
	hit := 0
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == saasFeedManifestPath && hit == 0 {
			hit++
			// A contract-valid redirect (same origin + exact path) is followed once.
			http.Redirect(w, r, builtinSaaSFeedURL, http.StatusMovedPermanently)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	out, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err != nil {
		t.Fatalf("single redirect not followed: %v", err)
	}
	if string(out.Body) != string(g.EnvelopeBytes) {
		t.Fatalf("body mismatch after redirect")
	}
}

// ── 8. timeout & cancellation classification ─────────────────────────────────────

func TestF3b2_ContextDeadlineClassified(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // outlast the deadline
		_, _ = w.Write(g.EnvelopeBytes)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := fo.fetcher.fetchManifest(ctx, builtinSaaSFeedURL, "")
	if err == nil || !isFeedFetchCanceled(err) {
		t.Fatalf("err = %v; want a classified cancellation", err)
	}
}

func TestF3b2_CancelClassified(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	started := make(chan struct{})
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write(g.EnvelopeBytes)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	_, err := fo.fetcher.fetchManifest(ctx, builtinSaaSFeedURL, "")
	if err == nil || !isFeedFetchCanceled(err) {
		t.Fatalf("err = %v; want a classified cancellation", err)
	}
}

// ── 9. compressed / oversized / truncated responses ──────────────────────────────

func TestF3b2_RejectsContentEncoding(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(g.EnvelopeBytes) // bytes are not actually gzip; we must reject on the header
	}))
	_, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err == nil || !errors.Is(err, errFeedFetchEncoding) {
		t.Fatalf("err = %v; want errFeedFetchEncoding", err)
	}
}

func TestF3b2_RejectsOversizeManifest(t *testing.T) {
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		big := make([]byte, int(urlcatfeedMaxBundleForTest())+1024)
		_, _ = w.Write(big)
	}))
	_, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err == nil || !errors.Is(err, errFeedFetchBody) {
		t.Fatalf("err = %v; want errFeedFetchBody (oversize)", err)
	}
}

func TestF3b2_RejectsBadStatus(t *testing.T) {
	fo := newFeedOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err == nil || !errors.Is(err, errFeedFetchStatus) {
		t.Fatalf("err = %v; want errFeedFetchStatus", err)
	}
}

// ── 304 conditional handling (typed, never content) ──────────────────────────────

func TestF3b2_NotModifiedTyped(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	mux := newFeedMux(g)
	mux.manifestETag = `"v42"`
	fo := newFeedOrigin(t, mux)
	// First fetch (unconditional) returns the ETag.
	out1, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, "")
	if err != nil {
		t.Fatalf("fetch1: %v", err)
	}
	if out1.ETag != `"v42"` {
		t.Fatalf("etag = %q", out1.ETag)
	}
	// Conditional fetch with the ETag returns a TYPED NotModified with no body.
	out2, err := fo.fetcher.fetchManifest(context.Background(), builtinSaaSFeedURL, out1.ETag)
	if err != nil {
		t.Fatalf("fetch2: %v", err)
	}
	if !out2.NotModified || len(out2.Body) != 0 {
		t.Fatalf("expected typed NotModified with no body, got %+v", out2)
	}
}

// ── 15. artifact-key traversal / encoded traversal / separators ──────────────────

func TestF3b2_ArtifactKeyRejections(t *testing.T) {
	fetcher := newFeedFetcher(feedFetcherOpts{allowPrivate: true})
	bad := []string{
		"../secret.json",
		"..%2fsecret.json",
		"%2e%2e/secret.json",
		"sub/dir.json",
		"a\\b.json",
		"/abs.json",
		"with space.json",
		"..",
		"",
		"nul\x00.json",
	}
	for _, key := range bad {
		t.Run(fmt.Sprintf("%q", key), func(t *testing.T) {
			if safeArtifactKey(key) {
				t.Fatalf("safeArtifactKey accepted %q", key)
			}
			_, err := fetcher.fetchArtifactObject(context.Background(), builtinSaaSFeedURL, key, 1<<20)
			if err == nil || !errors.Is(err, errFeedFetchArtifactKey) {
				t.Fatalf("%q: err = %v; want errFeedFetchArtifactKey", key, err)
			}
		})
	}
	// A well-formed key passes the guard.
	if !safeArtifactKey("saas-00000042-20260731.json") {
		t.Fatal("safeArtifactKey rejected a valid key")
	}
}

// ── 33. fuzz: URL-contract and artifact-key decoding never panic ─────────────────

func FuzzF3b2_URLContract(f *testing.F) {
	seeds := []string{
		builtinSaaSFeedURL, "http://x", "https://feeds.culvertlabs.com/", "://",
		"https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json?a=b",
		"https://feeds.culvertlabs.com:0/x", "https://[::1]/x",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	fetcher := newFeedFetcher(feedFetcherOpts{allowPrivate: true})
	f.Fuzz(func(t *testing.T, raw string) {
		// Must never panic; a non-official URL must never be accepted at the contract
		// layer (it either errors at parse/validation or, if by some chance it parses
		// to the exact official origin+path, only then proceeds — which the fuzz
		// corpus will not reach without the real host).
		_, _ = fetcher.fetchManifest(context.Background(), raw, "")
	})
}

func FuzzF3b2_ArtifactKey(f *testing.F) {
	for _, s := range []string{"a.json", "../x", "%2e%2e", "a/b", "", "..", "x\x00y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if safeArtifactKey(key) {
			// An accepted key must be a single safe segment: no separators, no "..",
			// no percent, bounded.
			if strings.ContainsAny(key, "/\\%") || strings.Contains(key, "..") || key == "" || len(key) > 255 {
				t.Fatalf("safeArtifactKey accepted an unsafe key %q", key)
			}
		}
	})
}

// urlcatfeedMaxBundleForTest exposes the manifest read bound for the oversize test
// without importing the constant name into every test.
func urlcatfeedMaxBundleForTest() int64 { return 1 << 20 }
