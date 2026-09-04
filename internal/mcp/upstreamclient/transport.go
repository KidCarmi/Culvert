package upstreamclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// serverPool bounds concurrency for one upstream server: a queue admission slot
// then an in-flight slot. Exhaustion of either is a classified availability
// failure (never an unbounded wait).
type serverPool struct {
	queue chan struct{}
	sem   chan struct{}
}

func newServerPool(lim Limits) *serverPool {
	return &serverPool{
		queue: make(chan struct{}, lim.MaxQueuePerServer()),
		sem:   make(chan struct{}, lim.MaxInFlight()),
	}
}

// acquire takes a queue slot then an in-flight slot. It returns a release func or
// a classified pool-exhausted / cancelled error.
func (p *serverPool) acquire(ctx context.Context) (func(), error) {
	select {
	case p.queue <- struct{}{}:
	default:
		return nil, mcperr.New(mcperr.ReasonUpstreamPoolExhausted, "upstreamclient", "per-server queue full")
	}
	select {
	case p.sem <- struct{}{}:
		<-p.queue
		return func() { <-p.sem }, nil
	case <-ctx.Done():
		<-p.queue
		return nil, mcperr.New(mcperr.ReasonUpstreamCancelled, "upstreamclient", "cancelled awaiting in-flight slot")
	}
}

// roundTrip performs one bounded, pinned HTTPS POST of body to target.Endpoint. It
// returns (rawBody, preResponse, error): preResponse is true when the failure
// happened before any response headers were received (dial/TLS/timeout) so an
// idempotent read may retry.
func (c *Client) roundTrip(ctx context.Context, target Target, body []byte, authHeader string, attemptID string) (respBody []byte, preResponse bool, err error) {
	canon, class, err := destination.Canonicalize(target.Endpoint, c.cfg.Policy, c.cfg.InspectionLimits)
	if err != nil {
		return nil, false, mcperr.Wrap(mcperr.ReasonUpstreamEndpointInvalid, "upstreamclient", "endpoint canonicalize", err)
	}
	// Reject only structurally-forbidden endpoint classes here; the authoritative
	// SSRF classification (private/loopback/metadata handling) happens in Resolve +
	// VerifyPeer.
	//
	// destination.Policy — including AllowPrivate — is CLIENT-WIDE, not per-server:
	// Config carries one Policy and Target carries no override. So AllowPrivate is
	// not, and must not be read as, "private destinations are permitted for the
	// approved internal servers that need them": enabling it disables the
	// private/loopback/metadata rejection for EVERY registered server this client
	// calls, so a public server whose DNS answer is hostile or compromised could then
	// reach link-local metadata. PolicyConfig.AllowPrivate is documented as TEST- or
	// ENVIRONMENT-scoped for that reason and has no production caller. Supporting a
	// genuinely internal MCP server needs a per-target policy that does not exist
	// yet — adding one is a design change, not a flag flip.
	if class == destination.ClassMalformed || class == destination.ClassBlockedScheme {
		return nil, false, mcperr.New(mcperr.ReasonUpstreamEndpointInvalid, "upstreamclient", "endpoint scheme/form not permitted")
	}
	now := c.cfg.Clock()
	pin, _, err := destination.Resolve(ctx, canon, c.cfg.Policy, c.cfg.Resolver, c.cfg.InspectionLimits, now, c.cfg.Limits.PinTTL())
	if err != nil {
		return nil, true, mcperr.Wrap(mcperr.ReasonUpstreamConnectFailed, "upstreamclient", "resolve", err)
	}

	client, transport := c.httpClientFor(target, canon, pin)
	// SEC-MCP-10. The transport is built per call, and a Go http.Transport OWNS its
	// idle connections: it sets no IdleConnTimeout, and nothing reclaims a Transport
	// that has gone out of scope while a connection's read/write loops still
	// reference it. Without this release every upstream call permanently leaked one
	// socket and two goroutines — an unbounded file-descriptor leak on a gateway
	// that makes one upstream call per agent tool invocation.
	defer transport.CloseIdleConnections()
	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Limits.RequestTimeout())
	defer cancel()
	// POST to the FULL validated canonical endpoint (origin + path), so a
	// Streamable-HTTP server mounted under a path such as /mcp is reached rather than
	// the bare origin root.
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, canon.RequestURL(), bytesReader(body))
	if err != nil {
		return nil, false, mcperr.Wrap(mcperr.ReasonUpstreamCallFailed, "upstreamclient", "build request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// The ONLY Authorization value ever sent is the broker-materialized APPROVED
	// SERVER credential (set by the executor inside the materialization callback).
	// The client's own token is never forwarded.
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	// Attempt identity for independent witness correlation (§5/§11). Non-secret and
	// Culvert-minted; empty for lifecycle/discovery traffic, which carries no attempt.
	if attemptID != "" {
		req.Header.Set(AttemptHeader, attemptID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, true, classifyTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := readBounded(resp.Body, c.cfg.Limits.MaxResponseBytes())
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, mcperr.New(mcperr.ReasonUpstreamCallFailed, "upstreamclient", "upstream non-200 status")
	}
	return raw, false, nil
}

// httpClientFor builds a per-call http.Client whose transport dials ONLY the
// pinned IPs, re-verifies the connected peer, verifies the pinned TLS identity,
// and refuses any redirect that leaves the approved server. The transport is
// returned alongside the client so the caller can release its idle connections
// when the call completes (SEC-MCP-10).
func (c *Client) httpClientFor(target Target, canon destination.Canonical, pin destination.PinnedDestination) (*http.Client, *http.Transport) {
	tr := &http.Transport{
		DialContext:           c.pinnedDial(pin),
		TLSClientConfig:       c.tlsConfig(target, canon),
		TLSHandshakeTimeout:   c.cfg.Limits.TLSTimeout(),
		MaxConnsPerHost:       c.cfg.Limits.MaxConnsPerServer(),
		MaxIdleConnsPerHost:   c.cfg.Limits.MaxConnsPerServer(),
		ResponseHeaderTimeout: c.cfg.Limits.RequestTimeout(),
		DisableCompression:    false,
		ForceAttemptHTTP2:     false,
	}
	maxRedirects := c.cfg.Limits.MaxRedirects()
	// The approved server's identity is host AND port: Canonical.Host is the bare
	// hostname (the port is a separate field), so comparing only the hostname would
	// admit a redirect to a different port on the same name. The dial is pinned to
	// the original port regardless, so such a redirect would silently reach a
	// different endpoint than the one it named — a mismatch between what the request
	// says and where it goes (OVN-04).
	// SCHEME is part of the approved identity too, and omitting it was a credential
	// exposure, not a tidiness gap: an upstream could answer
	// `http://<approved-host>:<approved-port>/...`, which matches on host and port,
	// and Go forwards the Authorization header on a same-host redirect. The transport
	// then uses the plain DialContext for an http URL — pinnedDial connects to the
	// pinned address with NO TLS — so the broker-materialized upstream credential
	// would leave this process in cleartext on the wire, chosen by the far end's own
	// response data. A redirect may change the path; it may not change the protocol
	// the credential travels over.
	approvedScheme := strings.ToLower(canon.Scheme)
	approvedHost, approvedPort := strings.ToLower(canon.Host), canon.Port
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return mcperr.New(mcperr.ReasonUpstreamTransportRejected, "upstreamclient", "redirect not permitted")
			}
			// SEC-MCP-13. A redirect must never leave the APPROVED SERVER. The hop
			// count alone does not express that: with MaxRedirects raised above zero,
			// an upstream's own response data chose where a credentialed request went
			// next. The pinned dialer bounds the damage, but "bounded two layers down"
			// is not "refused" — and a redirect to a foreign host would still have the
			// gateway speak that host's name on a connection it did not approve.
			if req == nil || req.URL == nil {
				return mcperr.New(mcperr.ReasonUpstreamTLSIdentity, "upstreamclient", "redirect leaves the approved server identity")
			}
			if !strings.EqualFold(req.URL.Scheme, approvedScheme) ||
				strings.ToLower(req.URL.Hostname()) != approvedHost ||
				redirectPort(req.URL) != approvedPort {
				return mcperr.New(mcperr.ReasonUpstreamTLSIdentity, "upstreamclient", "redirect leaves the approved server identity")
			}
			return nil
		},
	}, tr
}

// pinnedDial returns a DialContext that dials ONLY an address in the pinned set,
// re-running the SSRF peer check via destination.VerifyPeer at connect time. It
// never re-resolves the host.
func (c *Client) pinnedDial(pin destination.PinnedDestination) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		if pin.Stale(c.cfg.Clock()) {
			return nil, mcperr.New(mcperr.ReasonUpstreamConnectFailed, "upstreamclient", "resolution pin expired")
		}
		d := &net.Dialer{Timeout: c.cfg.Limits.ConnectTimeout()}
		var lastErr error
		for _, ip := range pinnedIPs(pin) {
			if err := destination.VerifyPeer(pin, ip, c.cfg.Policy, c.cfg.Clock()); err != nil {
				lastErr = mcperr.Wrap(mcperr.ReasonUpstreamConnectFailed, "upstreamclient", "peer verify", err)
				continue
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), pin.Port))
			if err != nil {
				lastErr = classifyTransportError(err)
				continue
			}
			return conn, nil
		}
		if lastErr == nil {
			lastErr = mcperr.New(mcperr.ReasonUpstreamConnectFailed, "upstreamclient", "no pinned address dialable")
		}
		return nil, lastErr
	}
}

func pinnedIPs(pin destination.PinnedDestination) []netip.Addr { return pin.AllowedIPs }

// tlsConfig builds the TLS config. When a pinned identity is configured we verify
// the leaf against it (a private-CA/self-signed internal server is trusted by its
// pinned identity, not a public chain); otherwise standard chain + hostname
// verification applies.
func (c *Client) tlsConfig(target Target, canon destination.Canonical) *tls.Config {
	if target.PinnedIdentity == "" {
		return &tls.Config{ServerName: canon.Host, RootCAs: c.cfg.RootCAs, MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		// #nosec G402 -- pinned-identity verification is enforced in VerifyConnection;
		// standard chain verification is intentionally replaced by the exact pin.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(state tls.ConnectionState) error {
			return c.cfg.Identity.VerifyIdentity(state, target.PinnedIdentity)
		},
	}
}

// spkiVerifier is the default IdentityVerifier: it compares the base64 SHA-256 of
// the leaf certificate's SubjectPublicKeyInfo against the pinned identity.
type spkiVerifier struct{}

// VerifyIdentity implements IdentityVerifier.
func (spkiVerifier) VerifyIdentity(state tls.ConnectionState, pinnedIdentity string) error {
	if pinnedIdentity == "" {
		return nil
	}
	if len(state.PeerCertificates) == 0 {
		return mcperr.New(mcperr.ReasonUpstreamTLSIdentity, "upstreamclient", "no peer certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	got := base64.StdEncoding.EncodeToString(sum[:])
	if got != pinnedIdentity {
		return mcperr.New(mcperr.ReasonUpstreamTLSIdentity, "upstreamclient", "peer identity does not match the pinned identity")
	}
	return nil
}

// readBounded reads at most limit+1 bytes; exceeding limit is a classified failure.
func readBounded(r io.Reader, limit int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonUpstreamCallFailed, "upstreamclient", "read response", err)
	}
	if len(buf) > limit {
		return nil, mcperr.New(mcperr.ReasonUpstreamResponseTooLarge, "upstreamclient", "upstream response exceeds bound")
	}
	return buf, nil
}

// classifyTransportError maps a transport error to a sanitized classified reason.
// It never embeds the raw network error text.
func classifyTransportError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return mcperr.New(mcperr.ReasonUpstreamCancelled, "upstreamclient", "cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return mcperr.New(mcperr.ReasonUpstreamTimeout, "upstreamclient", "deadline exceeded")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return mcperr.New(mcperr.ReasonUpstreamTimeout, "upstreamclient", "network timeout")
	}
	// A classified mcperr from the pin/verify path passes through.
	if mcperr.ReasonOf(err) != mcperr.ReasonNone {
		return err
	}
	return mcperr.New(mcperr.ReasonUpstreamConnectFailed, "upstreamclient", "connection failed")
}

// bytesReader wraps a byte slice as a fresh io.Reader for each attempt.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// redirectPort returns a redirect target's effective port, defaulting to the
// scheme port when none is given, so the comparison against the approved server's
// canonical port is like-for-like (Canonical.Port is always explicit).
func redirectPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}
