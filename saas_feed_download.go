package main

// saas_feed_download.go — F3b-2: the SSRF/URL-hardened, one-shot HTTP fetcher for
// the signed SaaS URL-category feed.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §A.8 (manifest-URL & SSRF
// contract) and the F3b-2 slice. This file owns ONLY the network transport +
// destination controls; it verifies NO signatures, parses NO trusted payload, and
// writes NO durable state. Every guarantee here is transport-level: the exact
// official origin + path, dial-the-resolved-IP (DNS-rebind resistant), hostname-
// pinned TLS, per-hop redirect revalidation, bounded reads/timeouts, and no
// ambient-credential / proxy / auto-decompression escape.
//
// The destination controls are applied TOGETHER, not as a trade-off (§A.8): the
// host is resolved and the connection is dialed to the *validated public IP* (so
// the address checked is the address dialed — no TOCTOU / DNS-rebind window), while
// the TLS handshake sets SNI = feeds.culvertlabs.com and verifies the presented
// certificate against that DNS name (never the IP). The IP is only the dial target;
// the authenticated peer identity is always the official hostname.
//
// Injectable seams (clock / resolver / dialer / TLS) exist for deterministic tests
// WITHOUT a production bypass: the production constructor wires the real resolver +
// dialer + private-address guard + pinned SNI, and the seams only replace those with
// equivalents (a loopback resolver, a test TLS root) inside _test.go.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// ─── constants ──────────────────────────────────────────────────────────────────

const (
	// saasFeedArtifactPrefix is the exact approved key prefix the artifact and its
	// Sigstore bundle live under (the manifest path's parent). Derived from and
	// pinned byte-consistent with saasFeedManifestPath (saas_feed_config.go); an
	// artifact key is joined onto this and re-validated per request.
	saasFeedArtifactPrefix = "/v1/url-categories/saas/"

	// saasFeedUserAgent self-identifies feed fetches to a CDN/WAF fronting the origin
	// (a bare Go UA is indistinguishable from bot traffic and may be 403'd).
	saasFeedUserAgent = "Culvert-SaaSFeed/1.0 (+https://github.com/KidCarmi/Culvert)"

	// saasFeedMaxRedirects bounds the redirect chain (§A.8).
	saasFeedMaxRedirects = 5

	// Bounded timeouts (compiled; §A.8 "bounded connect, TLS handshake, response-
	// header, idle, and total-operation timeouts").
	saasFeedDialTimeout       = 10 * time.Second
	saasFeedTLSTimeout        = 10 * time.Second
	saasFeedRespHeaderTimeout = 15 * time.Second
	saasFeedIdleTimeout       = 30 * time.Second
	saasFeedTotalTimeout      = 60 * time.Second
)

// ─── structured errors (classification for later F3b failure counters) ───────────

var (
	errFeedFetchURLContract = errors.New("saas feed fetch: url violates the official-origin contract")
	errFeedFetchSSRF        = errors.New("saas feed fetch: destination resolves to a prohibited address")
	errFeedFetchResolve     = errors.New("saas feed fetch: host resolution failed")
	errFeedFetchRedirect    = errors.New("saas feed fetch: redirect violates the origin/path contract")
	errFeedFetchTooMany     = errors.New("saas feed fetch: too many redirects")
	errFeedFetchStatus      = errors.New("saas feed fetch: unexpected HTTP status")
	errFeedFetchEncoding    = errors.New("saas feed fetch: unsupported content-encoding")
	errFeedFetchBody        = errors.New("saas feed fetch: response body read failed or exceeded bound")
	errFeedFetchArtifactKey = errors.New("saas feed fetch: unsafe artifact key")
	errFeedFetchCanceled    = errors.New("saas feed fetch: canceled") // shutdown vs failure classification
)

// isFeedFetchCanceled reports whether err is a context cancellation/deadline — a
// SHUTDOWN class the later failure counters must NOT charge as a fetch failure.
func isFeedFetchCanceled(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, errFeedFetchCanceled)
}

// ─── fetcher ─────────────────────────────────────────────────────────────────────

// feedFetchOutcome carries a manifest fetch's result. NotModified is a TYPED result
// (a 304 to a conditional request) — it is NEVER treated as verified new content and
// never implies freshness (§B.11).
type feedFetchOutcome struct {
	Body        []byte
	ETag        string
	NotModified bool
}

// feedFetcher issues the bounded, SSRF-guarded, hostname-pinned requests. It is
// constructed once per acquisition and is safe for sequential use.
type feedFetcher struct {
	client       *http.Client
	guard        func(ip net.IP) bool // returns true if the IP is PROHIBITED (private/internal)
	resolve      func(ctx context.Context, host string) ([]net.IP, error)
	maxRedirects int
	maxManifest  int64
	maxArtifact  int64
	maxBundle    int64
}

// feedFetcherOpts injects the clock/resolver/dialer/TLS for deterministic tests. The
// zero value yields the production fetcher (real resolver + dialer + private-address
// guard + pinned SNI). Every override is a same-shape replacement, never a control
// bypass.
type feedFetcherOpts struct {
	// resolve maps a hostname to its addresses. Production: net.DefaultResolver.
	// Tests: a fixed loopback map so httptest servers are reachable without touching
	// real DNS. nil ⇒ production resolver.
	resolve func(ctx context.Context, host string) ([]net.IP, error)
	// dial establishes the raw TCP connection to an already-validated public IP.
	// nil ⇒ a bounded net.Dialer.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// tlsConfig overrides the pinned TLS config. nil ⇒ ServerName pinned to the
	// official host with default (full chain + hostname) verification. Tests supply a
	// RootCAs trusting the httptest cert and a matching ServerName.
	tlsConfig *tls.Config
	// allowPrivate disables the private-address rejection (tests dialing loopback).
	// Production leaves it false so loopback/RFC1918/link-local/etc. are rejected.
	allowPrivate bool
}

// newFeedFetcher builds the hardened one-shot fetcher.
func newFeedFetcher(opts feedFetcherOpts) *feedFetcher {
	f := &feedFetcher{
		maxRedirects: saasFeedMaxRedirects,
		maxManifest:  urlcatfeed.MaxBundleBytes,  // the manifest envelope is bundle-sized (1 MiB)
		maxArtifact:  urlcatfeed.MaxArtifactSize, // 8 MiB
		maxBundle:    urlcatfeed.MaxBundleBytes,  // 1 MiB
	}

	f.resolve = opts.resolve
	if f.resolve == nil {
		f.resolve = defaultFeedResolve
	}
	// The SSRF guard rejects private/internal IPs. Tests dialing loopback set
	// allowPrivate; production never does, so the resolved public IP is enforced.
	if opts.allowPrivate {
		f.guard = func(net.IP) bool { return false }
	} else {
		f.guard = isPrivateIP
	}

	dial := opts.dial
	if dial == nil {
		d := &net.Dialer{Timeout: saasFeedDialTimeout, KeepAlive: saasFeedIdleTimeout}
		dial = d.DialContext
	}

	tlsCfg := opts.tlsConfig
	if tlsCfg == nil {
		// Pin SNI + cert hostname to the official origin. Default verification (no
		// InsecureSkipVerify): the peer identity is always feeds.culvertlabs.com,
		// even though the dial target is the validated resolved IP.
		tlsCfg = &tls.Config{ServerName: saasFeedOfficialHost, MinVersion: tls.VersionTLS12} // #nosec G402 -- ServerName pinned, full verification, MinVersion 1.2
	}

	transport := &http.Transport{
		// No proxy: an ambient HTTP(S)_PROXY env var must NOT be able to redirect the
		// fetch through an arbitrary proxy that would bypass the dial-time SSRF guard
		// and the hostname pin (§A.8 "no environment behavior that bypasses the
		// approved destination controls").
		Proxy:                 nil,
		DialContext:           f.dialResolvedPublic(dial),
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true, // no automatic decompression; content-encoding is rejected below
		MaxIdleConns:          2,
		IdleConnTimeout:       saasFeedIdleTimeout,
		TLSHandshakeTimeout:   saasFeedTLSTimeout,
		ResponseHeaderTimeout: saasFeedRespHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	f.client = &http.Client{
		Timeout:   saasFeedTotalTimeout,
		Transport: transport,
		// Do NOT auto-follow redirects: we validate + re-issue each hop ourselves so
		// EVERY hop is revalidated against the full origin/path contract (§A.8).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return f
}

func defaultFeedResolve(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for i := range addrs {
		ips = append(ips, addrs[i].IP)
	}
	return ips, nil
}

// dialResolvedPublic returns a DialContext that resolves the host ONCE, dials a
// validated PUBLIC resolved IP directly (so the checked address is the dialed
// address — no re-resolution by the transport), and rejects private/internal
// destinations. This closes the DNS-rebinding TOCTOU window.
func (f *feedFetcher) dialResolvedPublic(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: split %q: %v", errFeedFetchSSRF, addr, err)
		}
		// A literal IP is never expected here (the URL contract rejects IP-literal
		// hosts), but if one arrives, guard it directly rather than resolving.
		if ip := net.ParseIP(host); ip != nil {
			if f.guard(ip) {
				return nil, fmt.Errorf("%w: literal %s", errFeedFetchSSRF, ip)
			}
			return dial(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		ips, err := f.resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errFeedFetchResolve, host, err)
		}
		var lastErr error
		for _, ip := range ips {
			if f.guard(ip) {
				lastErr = fmt.Errorf("%w: %s → %s", errFeedFetchSSRF, host, ip)
				continue
			}
			conn, derr := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("%w: %s: no public address", errFeedFetchResolve, host)
		}
		return nil, lastErr
	}
}

// ─── URL contract ────────────────────────────────────────────────────────────────

// validateFeedURLContract enforces the full §A.8 accepted-URL contract for one
// resource, requiring the URL to land on EXACTLY the official https origin and the
// given approved absolute path — no userinfo, no explicit port, no IP-literal host,
// no query, no fragment. It is applied to the initial request AND re-applied to every
// redirect hop (so a redirect can never escape the exact approved origin *and* path).
func validateFeedURLContract(u *url.URL, expectPath string) error {
	if u == nil {
		return fmt.Errorf("%w: nil url", errFeedFetchURLContract)
	}
	if u.Opaque != "" || u.Scheme != saasFeedOfficialScheme {
		return fmt.Errorf("%w: scheme %q", errFeedFetchURLContract, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo", errFeedFetchURLContract)
	}
	host := u.Hostname()
	if host != saasFeedOfficialHost {
		return fmt.Errorf("%w: host %q", errFeedFetchURLContract, host)
	}
	if net.ParseIP(host) != nil {
		return fmt.Errorf("%w: ip-literal host", errFeedFetchURLContract)
	}
	if u.Port() != "" {
		return fmt.Errorf("%w: port %q", errFeedFetchURLContract, u.Port())
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("%w: query", errFeedFetchURLContract)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("%w: fragment", errFeedFetchURLContract)
	}
	if u.EscapedPath() != expectPath {
		return fmt.Errorf("%w: path %q != %q", errFeedFetchURLContract, u.EscapedPath(), expectPath)
	}
	return nil
}

// safeArtifactKey is the download-path's INDEPENDENT guard on the manifest-supplied
// artifact key (defense-in-depth over urlcatfeed's safeRelKey): a single path
// segment of [A-Za-z0-9._-], no "..", no separators, no percent-escapes. The key
// came from a signature-verified manifest, but the fetch site re-validates it before
// composing a URL, so a producer/verifier gap can never yield a traversal fetch.
func safeArtifactKey(k string) bool {
	if k == "" || len(k) > 255 || strings.Contains(k, "..") {
		return false
	}
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// ─── requests ────────────────────────────────────────────────────────────────────

// fetchManifest does a (conditionally) bounded GET of the manifest envelope at
// manifestURL. When priorETag is non-empty it sends If-None-Match and classifies a
// 304 as NotModified (never verified content). It returns the raw envelope bytes on
// 200. Only the approved success/304 statuses are accepted; any other status, an
// unsupported content-encoding, or an oversize/short body is an error.
func (f *feedFetcher) fetchManifest(ctx context.Context, manifestURL, priorETag string) (feedFetchOutcome, error) {
	u, err := url.Parse(strings.TrimSpace(manifestURL))
	if err != nil {
		return feedFetchOutcome{}, fmt.Errorf("%w: parse: %v", errFeedFetchURLContract, err)
	}
	if err := validateFeedURLContract(u, saasFeedManifestPath); err != nil {
		return feedFetchOutcome{}, err
	}
	resp, err := f.do(ctx, u, saasFeedManifestPath, priorETag)
	if err != nil {
		return feedFetchOutcome{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// A conditional 304: typed result, NOT content. A prohibited-body on 304 is
		// ignored (we never read/trust it) and freshness is not inferred here.
		return feedFetchOutcome{NotModified: true, ETag: sanitizeETag(resp.Header.Get("ETag"))}, nil
	case http.StatusOK:
		if err := rejectContentEncoding(resp); err != nil {
			return feedFetchOutcome{}, err
		}
		body, err := readAllBounded(resp.Body, f.maxManifest)
		if err != nil {
			return feedFetchOutcome{}, fmt.Errorf("%w: manifest: %v", errFeedFetchBody, err)
		}
		return feedFetchOutcome{Body: body, ETag: sanitizeETag(resp.Header.Get("ETag"))}, nil
	default:
		return feedFetchOutcome{}, fmt.Errorf("%w: manifest %d", errFeedFetchStatus, resp.StatusCode)
	}
}

// fetchArtifactObject GETs one artifact-class object (the artifact or its .sigstore
// bundle) by its manifest-supplied key, bounded by limit. The key is re-validated
// and composed onto the exact approved prefix; the request requires a complete 200
// response (no conditional/304 on artifacts — they are immutable, content-addressed).
func (f *feedFetcher) fetchArtifactObject(ctx context.Context, manifestURL, key string, limit int64) ([]byte, error) {
	if !safeArtifactKey(key) {
		return nil, fmt.Errorf("%w: %q", errFeedFetchArtifactKey, key)
	}
	base, err := url.Parse(strings.TrimSpace(manifestURL))
	if err != nil {
		return nil, fmt.Errorf("%w: parse base: %v", errFeedFetchURLContract, err)
	}
	// Derive the artifact URL from the (already contract-validated) manifest origin +
	// the fixed approved prefix + the safe key. NEVER from operator input.
	art := *base
	art.Path = saasFeedArtifactPrefix + key
	art.RawPath = ""
	art.RawQuery = ""
	art.Fragment = ""
	art.RawFragment = ""
	expectPath := saasFeedArtifactPrefix + key
	if err := validateFeedURLContract(&art, expectPath); err != nil {
		return nil, err
	}
	resp, err := f.do(ctx, &art, expectPath, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s %d", errFeedFetchStatus, key, resp.StatusCode)
	}
	if err := rejectContentEncoding(resp); err != nil {
		return nil, err
	}
	body, err := readAllBounded(resp.Body, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errFeedFetchBody, key, err)
	}
	return body, nil
}

// do issues the request and manually follows redirects, revalidating EVERY hop
// against the origin/path contract (expectPath) and the dial-time SSRF guard. It
// caps the hop count. Cancellation is classified so shutdown is not a fetch failure.
func (f *feedFetcher) do(ctx context.Context, u *url.URL, expectPath, priorETag string) (*http.Response, error) {
	cur := u
	for hop := 0; ; hop++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cur.String(), http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", saasFeedUserAgent)
		req.Header.Set("Accept-Encoding", "identity") // belt: no compressed transfer negotiated
		if priorETag != "" {
			req.Header.Set("If-None-Match", priorETag)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			if isFeedFetchCanceled(err) {
				return nil, err
			}
			return nil, fmt.Errorf("saas feed fetch: GET %s: %w", expectPath, err)
		}
		if !isRedirect(resp.StatusCode) {
			return resp, nil
		}
		// Redirect: consume + close, validate the target, cap hops, re-issue.
		loc := resp.Header.Get("Location")
		_ = resp.Body.Close()
		if hop >= f.maxRedirects {
			return nil, fmt.Errorf("%w: >%d", errFeedFetchTooMany, f.maxRedirects)
		}
		next, err := cur.Parse(loc) // resolves relative Location against the current URL
		if err != nil {
			return nil, fmt.Errorf("%w: bad location %q: %v", errFeedFetchRedirect, loc, err)
		}
		if err := validateFeedURLContract(next, expectPath); err != nil {
			return nil, fmt.Errorf("%w: %v", errFeedFetchRedirect, err)
		}
		cur = next
	}
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// rejectContentEncoding rejects any non-identity Content-Encoding. Automatic
// decompression is disabled (DisableCompression), so a compressed body would not be
// transparently expanded; refusing it outright prevents an unbounded decompressed
// stream from ever being considered.
func rejectContentEncoding(resp *http.Response) error {
	enc := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding")))
	if enc != "" && enc != "identity" {
		return fmt.Errorf("%w: %q", errFeedFetchEncoding, enc)
	}
	return nil
}

// sanitizeETag bounds an opaque validator: it must be short and free of control
// characters (an attacker-influenced header must not smuggle control bytes into a
// later conditional request). A malformed value is dropped (empty) rather than sent.
func sanitizeETag(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 256 {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return ""
		}
	}
	return v
}
