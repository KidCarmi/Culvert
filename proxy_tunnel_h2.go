package main

// HTTP/2 SSL-inspection transport (PR3). All protocol-specific HTTP/2 decisions
// live here, in the transport layer; the inspection pipeline (runInspectExchange)
// is reused verbatim per stream, so there is ONE enforcement path for H1 and H2.
//
// Scope of this file (PR3b — minimal working + functional): native-ALPN dispatch,
// per-stream request/response proxying via runInspectExchange, pre-commit block
// emission, and trailer forwarding. Deferred to later focused PRs (marked inline):
//   - PR3c security: per-stream stall/inactivity cancel, adversarial frame limits
//     (Rapid Reset / CONTINUATION flood / HPACK bounds), :authority pinning / 421.
//   - PR3d concurrency: GOAWAY-on-shutdown / drainActiveTunnels registration,
//     upstream GOAWAY → per-stream failure mapping, graceful teardown.
//   - perf: forged-leaf session resumption for native tunnels (ticket-key sharing).

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/http2"
)

// h2MaxConcurrentStreams bounds concurrent streams per inspected H2 connection.
// Browser-parity (100) keeps the per-connection scan-buffer memory ceiling
// bounded (maxScanBufferBytes × this) while covering real client fan-out.
const h2MaxConcurrentStreams uint32 = 100

// handleInspectNativeALPN runs the native-ALPN inspection flow for a rule with
// StripALPN==false. It has already received the freshly-dialled (not yet
// handshaked) upstream TCP conn. Sequence (plan C1): send 200 → peek the client's
// ALPN offer → build the upstream ALPN offer as the intersection(client-offer,
// policy) → upstream handshake → constrain the forged-leaf offer to the protocol
// the upstream negotiated → client handshake → dispatch (h2↔h2 to handleInspectH2,
// otherwise the shared HTTP/1.1 loop). The intersection guarantees the two legs
// can only both be h2 or both be h1 — the mixed quadrants are impossible by
// construction, so an HTTP/1.1-only client is never stranded.
func handleInspectNativeALPN(w http.ResponseWriter, r *http.Request, rawUpstream net.Conn, targetHost, hostOnly string, tlsSkipVerify bool, match *PolicyMatch, id ProxyIdentity) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		rawUpstream.Close() //nolint:errcheck // best-effort cleanup
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	rawClient, clientBuf, err := hijacker.Hijack()
	if err != nil {
		rawUpstream.Close() //nolint:errcheck // best-effort cleanup
		logger.Printf("SSL_INSPECT(native) hijack error: %v", err)
		return
	}
	peekBuf := clientBuf.Reader

	// Non-TLS over CONNECT (SSH/RDP/etc.): we cannot MITM; the upstream TLS
	// handshake has not happened yet, so raw-relay the plaintext client to the
	// plaintext upstream TCP conn — mirrors the strip path's non-TLS fallback.
	firstByte, ferr := peekBuf.Peek(1)
	if ferr != nil {
		rawClient.Close()   //nolint:errcheck // best-effort cleanup
		rawUpstream.Close() //nolint:errcheck // best-effort cleanup
		return
	}
	if firstByte[0] != 0x16 {
		logger.Printf("SSL_INSPECT(native) non-TLS first byte 0x%02x for %q — raw relay", firstByte[0], sanitizeLog(hostOnly))
		relayPlaintextInspectFallback(rawClient, peekBuf, rawUpstream, hostOnly, match, id)
		return
	}

	clientOffer := peekClientALPN(peekBuf)

	// Upstream ALPN offer, bounded by the client offer so up ∈ client's set.
	upstreamProtos := []string{"http/1.1"}
	if clientOffersH2(clientOffer) {
		upstreamProtos = []string{"h2", "http/1.1"}
	}
	upstreamTLS, up, err := handshakeUpstreamALPN(r.Context(), rawUpstream, hostOnly, tlsSkipVerify, upstreamProtos)
	if err != nil {
		rawClient.Close() //nolint:errcheck // best-effort cleanup (200 already sent; cannot 502)
		logger.Printf("SSL_INSPECT(native) upstream TLS handshake %q: %v", sanitizeLog(targetHost), err)
		return
	}

	// Constrain the forged-leaf downstream offer to exactly what the upstream
	// negotiated (a protocol the client is guaranteed to also support).
	downstreamProtos := []string{"http/1.1"}
	if up == "h2" {
		downstreamProtos = []string{"h2"}
	}
	clientTLS := tls.Server(readerConn{Conn: rawClient, r: peekBuf}, newMITMClientConfigForALPN(downstreamProtos))
	if err := clientTLS.HandshakeContext(r.Context()); err != nil {
		clientTLS.Close()   //nolint:errcheck // best-effort cleanup
		upstreamTLS.Close() //nolint:errcheck // best-effort cleanup
		logger.Printf("SSL_INSPECT(native) client TLS handshake %q: %v", sanitizeLog(hostOnly), err)
		return
	}

	down := clientTLS.ConnectionState().NegotiatedProtocol
	logger.Printf("SSLInspect(native): tunnel %q up=%q down=%q", sanitizeLog(targetHost), sanitizeLog(up), sanitizeLog(down))
	recordActiveConn(1)
	defer recordActiveConn(-1)

	if up == "h2" && down == "h2" {
		handleInspectH2(r, clientTLS, upstreamTLS, hostOnly, match, id)
		return
	}
	// Both legs HTTP/1.1 (origin declined h2, or client offered only h1) — reuse
	// the shared H1 inspection loop. One enforcement path for both protocols.
	runH1InspectLoop(r, clientTLS, upstreamTLS, hostOnly, match, id)
}

// relayPlaintextInspectFallback raw-relays a non-TLS CONNECT client to the
// plaintext upstream TCP conn (idle-bounded) and records a TUNNEL_CLOSED entry —
// the native-path equivalent of the strip path's non-TLS fallback.
func relayPlaintextInspectFallback(rawClient net.Conn, peekBuf io.Reader, rawUpstream net.Conn, hostOnly string, match *PolicyMatch, id ProxyIdentity) {
	start := time.Now()
	var toUp, toCl int64
	shared := newTunnelActivityStamp()
	done := make(chan struct{}, 2)
	relay := func(dst net.Conn, src io.Reader, srcConn net.Conn, count *int64) {
		*count = idleCopyCounted(dst, src, srcConn, shared)
		done <- struct{}{}
	}
	go relay(rawUpstream, peekBuf, rawClient, &toUp)
	go relay(rawClient, rawUpstream, rawUpstream, &toCl)
	<-done
	rawClient.Close()   //nolint:errcheck // force peer unblock
	rawUpstream.Close() //nolint:errcheck // force peer unblock
	<-done
	recordTunnelCloseGated(match, id, "CONNECT", hostOnly, toUp, toCl, start, "inspect")
}

// handshakeUpstreamALPN performs the upstream inspect-leg TLS handshake offering
// the given ALPN protocols and returns the connection and the negotiated protocol.
// It closes the connection on handshake failure. tlsSkipVerify (admin-configured
// per rule) disables upstream cert verification for internal/self-signed hosts.
func handshakeUpstreamALPN(ctx context.Context, rawUpstream net.Conn, hostOnly string, tlsSkipVerify bool, protos []string) (*tls.Conn, string, error) {
	cfg := upstreamInspectTLSConfig(hostOnly, tlsSkipVerify)
	cfg.NextProtos = protos
	up := tls.Client(rawUpstream, cfg)
	if err := up.HandshakeContext(ctx); err != nil {
		up.Close() //nolint:errcheck // best-effort cleanup (closes underlying TCP conn)
		return nil, "", err
	}
	return up, up.ConnectionState().NegotiatedProtocol, nil
}

// peekClientALPN reads the client's offered ALPN protocols from the buffered
// ClientHello WITHOUT consuming it (tls.Server re-reads the same bytes via
// readerConn). Fail-closed: any short/oversized/malformed ClientHello returns
// ["http/1.1"], so the tunnel degrades to the fully-inspected HTTP/1.1 path
// rather than mis-negotiating. The parser itself is bounds-checked and fuzzed
// (parseClientHelloALPN).
func peekClientALPN(br *bufio.Reader) []string {
	fallback := []string{"http/1.1"}
	hdr, err := br.Peek(5)
	if err != nil || hdr[0] != 0x16 {
		return fallback
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	full, err := br.Peek(5 + recLen)
	if err != nil {
		// ClientHello larger than the buffered window (rare): the real handshake
		// still succeeds (reads from the conn), but we cannot read ALPN here —
		// downgrade the decision to http/1.1.
		return fallback
	}
	if protos, ok := parseClientHelloALPN(full); ok {
		return protos
	}
	return fallback
}

// newMITMClientConfigForALPN builds a per-connection forged-leaf TLS config that
// offers exactly the given ALPN protocol(s). It mirrors mitmClientTLSConfig
// (GetCertificate via certMgr, TLS 1.2 floor) but is per-connection so the ALPN
// offer can vary per tunnel without mutating the shared global (RF2). Native
// tunnels therefore do not share the global's session-ticket keys — session
// resumption for native tunnels is a deferred perf optimization, not a
// correctness gap.
func newMITMClientConfigForALPN(protos []string) *tls.Config {
	return &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return certMgr.GetCert(chi) },
		MinVersion:     tls.VersionTLS12,
		NextProtos:     protos,
	}
}

// handleInspectH2 proxies an inspected HTTP/2 tunnel: it serves the client leg
// with an http2.Server and, per stream, runs the shared inspection pipeline
// (runInspectExchange) with H2 transport hooks that round-trip over a single
// upstream http2.ClientConn and deliver via the stream's ResponseWriter.
// ServeConn blocks until the client connection is done; both conns are closed on
// return.
func handleInspectH2(outer *http.Request, clientTLS, upstreamTLS *tls.Conn, hostOnly string, match *PolicyMatch, id ProxyIdentity) {
	defer clientTLS.Close()   //nolint:errcheck // best-effort cleanup at tunnel end
	defer upstreamTLS.Close() //nolint:errcheck // best-effort cleanup at tunnel end

	// One upstream H2 client connection carries every stream of this tunnel;
	// http2.ClientConn.RoundTrip is safe for concurrent use (h2 multiplexing).
	tr := &http2.Transport{}
	upstreamCC, err := tr.NewClientConn(upstreamTLS)
	if err != nil {
		logger.Printf("SSL_INSPECT(h2) upstream client-conn %q: %v", sanitizeLog(hostOnly), err)
		return
	}

	clientIP, _, _ := net.SplitHostPort(outer.RemoteAddr)

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h2InspectStream(outer, w, req, upstreamCC, hostOnly, clientIP, match, id)
	})

	srv := &http2.Server{MaxConcurrentStreams: h2MaxConcurrentStreams}
	// ServeConn runs each stream's handler in its own goroutine and blocks until
	// the client connection is no longer readable.
	srv.ServeConn(clientTLS, &http2.ServeConnOpts{
		Context: outer.Context(),
		Handler: handler,
	})
}

// h2InspectStream handles one HTTP/2 stream: it reshapes the server-side request
// for an upstream round-trip and runs the shared inspection pipeline. The pipeline
// is protocol-agnostic; only the roundTrip (upstream http2 RoundTrip) and deliver
// (h2 ResponseWriter) hooks and the block responder are H2-specific.
func h2InspectStream(outer *http.Request, w http.ResponseWriter, req *http.Request, upstreamCC *http2.ClientConn, hostOnly, clientIP string, match *PolicyMatch, id ProxyIdentity) {
	// Reshape the h2 server request for an h2 client RoundTrip: RoundTrip requires
	// an absolute URL (scheme+host) and an empty RequestURI. The request travels
	// over upstreamCC, which is pinned to the CONNECT target, so the :authority
	// cannot redirect it off that connection (no SSRF). Strict :authority pinning
	// / 421 handling is a security-PR refinement.
	req.URL.Scheme = "https"
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	req.RequestURI = ""

	ex := &inspectExchange{
		outer:     outer,
		req:       req,
		match:     match,
		id:        id,
		host:      hostOnly,
		clientIP:  clientIP,
		responder: &h2BlockResponder{w: w},
		roundTrip: func(rq *http.Request) (*http.Response, error) { return upstreamCC.RoundTrip(rq) },
		deliver:   func(resp *http.Response) error { return h2DeliverResponse(w, resp) },
	}

	switch runInspectExchange(ex).kind {
	case exRoundTripError:
		// Upstream failed before any byte was delivered — emit a clean 502.
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	case exUpgrade:
		// HTTP/2 has no 101 Switching Protocols; an upstream that returns one is
		// malformed for h2. Fail the stream rather than raw-relaying a shared conn.
		logger.Printf("SSL_INSPECT(h2) unexpected 101 upgrade for %q — failing stream", sanitizeLog(hostOnly))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	default:
		// exDelivered / exBlocked / exDeliverError: the responder or deliver hook
		// has already written the stream response (or the client is gone).
	}
}

// h2BlockResponder emits a policy block on an HTTP/2 stream via its ResponseWriter.
// It writes a 403 with a text body and NO connection-specific headers
// (Connection: close is illegal in HTTP/2, RFC 9113 §8.2.2). Pre-commit only: it
// must run before any response header/body has been written to the stream, which
// the pipeline guarantees (blocks fire before deliver).
type h2BlockResponder struct {
	w http.ResponseWriter
}

func (h *h2BlockResponder) blockBeforeResponse(contentType, body string) {
	h.w.Header().Set("Content-Type", contentType)
	h.w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	h.w.WriteHeader(http.StatusForbidden)
	io.WriteString(h.w, body) //nolint:errcheck // best-effort; client may have gone
}

// h2DeliverResponse forwards a clean upstream response onto the client stream:
// status + headers, body, then any trailers (e.g. gRPC grpc-status). Hop-by-hop
// and connection-specific headers were already stripped by the pipeline
// (removeHopHeaders) before deliver, so nothing HTTP/2-illegal is emitted.
// Trailers are read after the body is drained (they are populated on EOF) and
// emitted via the http.TrailerPrefix mechanism, which does not require
// pre-announcing them — the correct pattern for forwarding gRPC trailers whose
// values are unknown until the message completes.
func h2DeliverResponse(w http.ResponseWriter, resp *http.Response) error {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return err
	}
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(http.TrailerPrefix+k, v)
		}
	}
	return nil
}
