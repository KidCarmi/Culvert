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
func (c *Client) roundTrip(ctx context.Context, target Target, body []byte, authHeader string) ([]byte, bool, error) {
	canon, class, err := destination.Canonicalize(target.Endpoint, c.cfg.Policy, c.cfg.InspectionLimits)
	if err != nil {
		return nil, false, mcperr.Wrap(mcperr.ReasonUpstreamEndpointInvalid, "upstreamclient", "endpoint canonicalize", err)
	}
	// Reject only structurally-forbidden endpoint classes here; the authoritative
	// SSRF classification (private/loopback/metadata handling, honoring the policy's
	// AllowPrivate for approved internal servers) happens in Resolve + VerifyPeer.
	if class == destination.ClassMalformed || class == destination.ClassBlockedScheme {
		return nil, false, mcperr.New(mcperr.ReasonUpstreamEndpointInvalid, "upstreamclient", "endpoint scheme/form not permitted")
	}
	now := c.cfg.Clock()
	pin, _, err := destination.Resolve(ctx, canon, c.cfg.Policy, c.cfg.Resolver, c.cfg.InspectionLimits, now, c.cfg.Limits.PinTTL())
	if err != nil {
		return nil, true, mcperr.Wrap(mcperr.ReasonUpstreamConnectFailed, "upstreamclient", "resolve", err)
	}

	client := c.httpClientFor(target, canon, pin)
	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Limits.RequestTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, canon.Origin()+"/", bytesReader(body))
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
// and rejects redirects beyond the bound.
func (c *Client) httpClientFor(target Target, canon destination.Canonical, pin destination.PinnedDestination) *http.Client {
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
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return mcperr.New(mcperr.ReasonUpstreamTransportRejected, "upstreamclient", "redirect not permitted")
			}
			return nil
		},
	}
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

// readBounded reads at most max+1 bytes; exceeding max is a classified failure.
func readBounded(r io.Reader, max int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonUpstreamCallFailed, "upstreamclient", "read response", err)
	}
	if len(buf) > max {
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
