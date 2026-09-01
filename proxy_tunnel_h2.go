package main

// HTTP/2 SSL-inspection transport (PR3). All protocol-specific HTTP/2 decisions
// live here, in the transport layer; the inspection pipeline (runInspectExchange)
// is reused verbatim per stream, so there is ONE enforcement path for H1 and H2.
//
// Scope: native-ALPN dispatch, per-stream request/response proxying via
// runInspectExchange, pre-commit block emission, trailer forwarding (PR3b), the
// per-stream inactivity watchdog + frame/header caps (PR3c). Rapid Reset
// (CVE-2023-44487) and the HTTP/2 CONTINUATION flood (CVE-2023-45288 — the Go /
// x-net identifier; not the Apache-httpd CVE-2024-27316) are mitigated by default
// in the vendored x/net v0.57.0 (the effective Rapid-Reset cap equals
// MaxConcurrentStreams). Still deferred (marked inline):
//   - :authority pinning / 421: NOT a security hole — upstreamCC is pinned to the
//     CONNECT target so a client :authority cannot redirect the request off that
//     connection (no SSRF). It is defense-in-depth against cross-origin coalescing
//     confusion; deferred because a naive 421 risks breaking legitimate edge cases
//     (IP-target CONNECT, single-SAN forged leaves already prevent coalescing) and
//     warrants its own careful pass.
//   - upstream (origin-initiated) GOAWAY → per-stream failure mapping is already
//     handled: an origin GOAWAY errors the in-flight upstreamCC.RoundTrip, mapped to
//     exRoundTripError/exDeliverError by handleH2StreamOutcome. No extra work.
//   - perf: the response body copy is pooled (relayBufPool) + adaptive-flush
//     (h2CopyBody); forged-leaf session resumption for native tunnels (ticket-key
//     sharing) is the remaining deferred perf item.
//
// PR3d graceful GOAWAY-on-shutdown is implemented in proxy_tunnel_h2_drain.go: the
// shared ConfigureServer'd server (used below) + the order-95 drain hook +
// drainActiveTunnels re-fire/backstop send every active inspected-H2 client a GOAWAY
// on process shutdown and force-close laggards at the drain deadline.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/http2"
)

// h2MaxConcurrentStreams bounds concurrent streams per inspected H2 connection.
// This is the primary per-connection resource cap: the scan pipeline buffers up
// to maxScanBufferBytes per in-flight response, so the per-connection scan-buffer
// memory ceiling is maxScanBufferBytes × this. Kept intentionally low (not the
// 100 browsers advertise) because native H2 multiplies H1's single-in-flight
// memory by this factor; 32 keeps a malicious connection's buffered footprint an
// order of magnitude below the naive 100 while covering real client fan-out. It
// also tightens the vendored x/net Rapid-Reset backstop (CVE-2023-44487), whose
// effective cap equals MaxConcurrentStreams. Per-stream stall/inactivity bounds
// are PR3c.
const h2MaxConcurrentStreams uint32 = 32

// h2ConnWriteByteTimeout bounds a stuck client write on the H2 leg so a stalled
// reader cannot pin a handler goroutine + its scan buffer indefinitely.
const h2ConnWriteByteTimeout = 30 * time.Second

// h2MaxReadFrameSize pins the largest HTTP/2 frame the server will read. 1 MiB
// equals the x/net default, so this does not tighten below the library — it pins
// the value explicitly so a future default change can't silently widen it.
// h2MaxHeaderBytes caps the decoded header-list size per request (1 MiB), the
// effective defense against oversized / compression-amplified header blocks
// (SETTINGS_MAX_HEADER_LIST_SIZE).
const (
	h2MaxReadFrameSize = 1 << 20
	h2MaxHeaderBytes   = 1 << 20
)

// hopByHopTrailerNames are the RFC 7230 §6.1 hop-by-hop header names (canonicalized
// http.Header keys) that must not be forwarded by an intermediary. removeHopHeaders
// strips these from request/response header blocks; the H2 deliver path filters
// them out of forwarded trailers too (removeHopHeaders operates on Header, not
// Trailer). Keep in sync with removeHopHeaders' list.
var hopByHopTrailerNames = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

// h2StreamStallTimeout bounds per-stream body inactivity. It is the HTTP/2
// analogue of the H1 stallDetectReadCloser: H2 cannot use a per-conn read deadline
// (one conn multiplexes many streams), so each stream gets an inactivity timer
// that cancels only that stream's context on stall. A var (not const) so tests can
// shorten it; production keeps the H1 body-stall posture.
var h2StreamStallTimeout = sslInspectBodyStallTimeout

// h2StallReader wraps a per-stream body reader and re-arms a shared inactivity
// timer whenever the read makes progress. Request-upload and response-download
// share one timer, so if a byte moves in either direction the stream stays alive;
// if neither moves within h2StreamStallTimeout the timer cancels the stream
// context, aborting RoundTrip / delivery — a slow-loris stream cannot pin a
// handler goroutine + its buffer indefinitely.
type h2StallReader struct {
	rc    io.ReadCloser
	reset func()
}

func (s *h2StallReader) Read(p []byte) (int, error) {
	n, err := s.rc.Read(p)
	if n > 0 {
		s.reset()
	}
	return n, err
}

func (s *h2StallReader) Close() error { return s.rc.Close() }

// handleInspectNativeALPN runs the native-ALPN inspection flow for a rule with
// StripALPN==false. It has already received the freshly-dialled (not yet
// handshaked) upstream TCP conn. Sequence (plan C1): send 200 → peek the client's
// ALPN offer → build the upstream ALPN offer as the intersection(client-offer,
// policy) → upstream handshake → constrain the forged-leaf offer to the protocol
// the upstream negotiated → client handshake → dispatch (h2↔h2 to handleInspectH2,
// otherwise the shared HTTP/1.1 loop). The intersection guarantees the two legs
// can only both be h2 or both be h1 — the mixed quadrants are impossible by
// construction, so an HTTP/1.1-only client is never stranded. (Residual edge: a
// client offering ONLY "h2" against an h1-only origin is forced to http/1.1
// downstream and its handshake fails with no_application_protocol — but this is
// identical to the strip path, which pins http/1.1 for all clients, and browsers
// always include http/1.1 in their offer.)
func handleInspectNativeALPN(w http.ResponseWriter, r *http.Request, rawUpstream net.Conn, targetHost, hostOnly string, dec sslResolution, match *PolicyMatch, id ProxyIdentity) {
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
	upstreamTLS, up, effectiveSkip, err := handshakeUpstreamALPN(r.Context(), rawUpstream, hostOnly, dec.SkipVerify, upstreamProtos, match)
	if err != nil {
		rawClient.Close() //nolint:errcheck // best-effort cleanup (200 already sent; cannot 502)
		// Learn-only on the native path: the 200 is already sent, so the current
		// session cannot be rescued (unlike the strip path). A qualifying failure
		// still learns the host so the NEXT session self-heals via the cache.
		learned, _ := maybeFailOpenOrigin(hostOnly, match, id, err)
		recordDecryptFailureEntry(withLearn(originInspectFailureOutcome(err, hostOnly, dec, match), learned, dec.ScopeID), id, hostOnly, match, decRedactHosts()) // ADR-0011 failure taxonomy + feed row (learner fields when this session fed the cache)
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
		clientTLS.Close()                                                                                                                                         //nolint:errcheck // best-effort cleanup
		upstreamTLS.Close()                                                                                                                                       //nolint:errcheck // best-effort cleanup
		learned := maybeFailOpenClient(hostOnly, match, id, err)                                                                                                  // learn a pinning rejection (learn-only)
		recordDecryptFailureEntry(withLearn(clientInspectFailureOutcome(err, hostOnly, dec, match), learned, dec.ScopeID), id, hostOnly, match, decRedactHosts()) // ADR-0011 failure taxonomy + feed row (learner fields when this session fed the cache)
		logger.Printf("SSL_INSPECT(native) client TLS handshake %q: %v", sanitizeLog(hostOnly), err)
		return
	}

	down := clientTLS.ConnectionState().NegotiatedProtocol
	recordInspectUpstreamALPN(up)
	logger.Printf("SSLInspect(native): tunnel %q up=%q down=%q", sanitizeLog(targetHost), sanitizeLog(up), sanitizeLog(down))
	// CHAOS-57: counted before, but held by no registry — a native tunnel that
	// negotiated http/1.1 (dispatchNativeInspect → runH1InspectLoop) had no deadline
	// backstop at all. A tunnel that negotiates h2 ALSO registers its client leg in
	// h2InspectConns; that is deliberate and not double-counting — this registry owns
	// the single activeConns increment, while culvert_h2_inspect_active measures the
	// GOAWAY-capable subset. Both backstops fire at the same deadline and a second
	// Close is a no-op.
	defer registerDrainableTunnel(tunnelClassConnectInspect, clientTLS, upstreamTLS)()

	dispatchNativeInspect(r, clientTLS, upstreamTLS, up, down, hostOnly, dec, match, id, effectiveSkip)
}

// dispatchNativeInspect finalises an established native-ALPN inspected tunnel: it builds
// the ADR-0011 inspected outcome ONCE from the completed origin TLS state, counts the
// session (both the H2 and H1-fallback dispatches are inspect-success terminals that never
// reach the strip path's counter or the close seam — without this native-ALPN rules
// under-report in culvert_decrypt_sessions_total), then routes to the H2 or H1 enforcement
// loop, threading the projected dec block onto both paths' per-request log entries. The
// block carries the native (h2 or h1) leg's negotiated TLS state — the piece the earlier
// nil-block follow-up left out. redact=false mirrors the strip path.
func dispatchNativeInspect(r *http.Request, clientTLS, upstreamTLS *tls.Conn, up, down, hostOnly string, dec sslResolution, match *PolicyMatch, id ProxyIdentity, effectiveSkip bool) {
	inspected := inspectedOutcome(dec, hostOnly, upstreamTLS.ConnectionState(), match, effectiveSkip)
	recordDecryptSession(inspected)
	decBlock := inspected.toBlock(decRedactHosts())
	if up == "h2" && down == "h2" {
		handleInspectH2(r, clientTLS, upstreamTLS, hostOnly, match, id, decBlock)
		return
	}
	// Both legs HTTP/1.1 (origin declined h2, or client offered only h1) — reuse the
	// shared H1 inspection loop. One enforcement path for both protocols.
	runH1InspectLoop(r, clientTLS, upstreamTLS, hostOnly, match, id, decBlock)
}

// relayPlaintextInspectFallback raw-relays a non-TLS CONNECT client to the
// plaintext upstream TCP conn (idle-bounded) and records a TUNNEL_CLOSED entry —
// the native-path equivalent of the strip path's non-TLS fallback.
func relayPlaintextInspectFallback(rawClient net.Conn, peekBuf io.Reader, rawUpstream net.Conn, hostOnly string, match *PolicyMatch, id ProxyIdentity) {
	// CHAOS-57: the native path's non-TLS fallback was invisible to the shutdown
	// drain for the same reason as its strip-path twin — the recordActiveConn call
	// sits after the client handshake this branch returns before.
	defer registerDrainableTunnel(tunnelClassInspectFallback, rawClient, rawUpstream)()
	start := time.Now()
	var toUp, toCl int64
	shared := newTunnelActivityStamp()
	done := make(chan struct{}, 2)
	// PX-4 residual (CHAOS-57): this was the ONE relay goroutine in the tree with no
	// panic guard — every other raw relay (relayCounted, the strip-path fallback,
	// rawRelay, socks5Relay) has carried one since CHAOS-24. A panic inside
	// idleCopyCounted here propagated to the runtime and killed an in-line security
	// appliance, dropping every other in-flight tunnel with it. Containing it is
	// strictly fail-closed: a relay goroutine holds no authority the recovery could
	// extend (the CHAOS-24 objection), and closing BOTH legs unblocks the peer relay,
	// which may be parked in a deadline-less Write that only a close can end.
	relay := func(dst net.Conn, src io.Reader, srcConn net.Conn, count *int64) {
		defer func() {
			if v := recover(); v != nil {
				recordCrash("tunnel-relay", "", v)
				_ = dst.Close()
				if srcConn != nil {
					_ = srcConn.Close()
				}
			}
			done <- struct{}{} // sole sender
		}()
		*count = idleCopyCounted(dst, src, srcConn, shared)
	}
	go relay(rawUpstream, peekBuf, rawClient, &toUp)
	go relay(rawClient, rawUpstream, rawUpstream, &toCl)
	<-done
	rawClient.Close()   //nolint:errcheck // force peer unblock
	rawUpstream.Close() //nolint:errcheck // force peer unblock
	<-done
	// ADR-0011: the client spoke a non-TLS protocol, so no MITM happened — record the
	// not_decrypted/non_tls_fallback outcome. Unlike the native path's inspected block
	// (a documented follow-up needing the h2 leg's TLS state), this outcome is pure
	// sentinels + host, so it is populated now for parity with the strip path.
	recordTunnelCloseGatedDec(match, id, "CONNECT", hostOnly, toUp, toCl, start, "inspect", "", nonTLSFallbackOutcome(hostOnly), decRedactHosts())
}

// handshakeUpstreamALPN performs the upstream inspect-leg TLS handshake offering
// the given ALPN protocols and returns the connection and the negotiated protocol.
// It closes the connection on handshake failure. tlsSkipVerify (admin-configured
// per rule) disables upstream cert verification for internal/self-signed hosts.
// The returned effectiveSkip is the InsecureSkipVerify the handshake's own
// tls.Config carried — the ground truth for the ADR-0011 cert_verify record
// (captured, never re-resolved against the live profile store; CWE-367).
func handshakeUpstreamALPN(ctx context.Context, rawUpstream net.Conn, hostOnly string, tlsSkipVerify bool, protos []string, match *PolicyMatch) (*tls.Conn, string, bool, error) {
	cfg := upstreamInspectTLSConfigForMatch(hostOnly, tlsSkipVerify, match)
	cfg.NextProtos = protos
	up := tls.Client(rawUpstream, cfg)
	if err := up.HandshakeContext(ctx); err != nil {
		up.Close()                       //nolint:errcheck // best-effort cleanup (closes underlying TCP conn)
		recordProfileMintlsReject(match) // attribute the drop if a profile set a min-TLS floor
		return nil, "", false, err
	}
	return up, up.ConnectionState().NegotiatedProtocol, cfg.InsecureSkipVerify, nil
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
func handleInspectH2(outer *http.Request, clientTLS, upstreamTLS *tls.Conn, hostOnly string, match *PolicyMatch, id ProxyIdentity, decBlock *DecryptionBlock) {
	defer clientTLS.Close()   //nolint:errcheck // best-effort cleanup at tunnel end
	defer upstreamTLS.Close() //nolint:errcheck // best-effort cleanup at tunnel end

	// Admission fence (PR3d): once the shutdown drain has begun, do not serve a NEW
	// inspected flow on a departing node — close so the client re-routes/retries
	// against the surviving node rather than being force-closed mid-flow in ≤15s. By
	// the time we reach here the 200 was sent and both TLS handshakes completed
	// (that work is in handleInspectNativeALPN); the fence prevents SERVING H2
	// streams, and the refused client sees a bare TLS close (no h2 GOAWAY frame — the
	// h2 server never starts), which is the intended "don't admit the flow" signal,
	// distinct from the graceful GOAWAY the ALREADY-serving tunnels get. A tunnel
	// racing this check (shutdown fires after it) is still caught by the drain's
	// per-tick GOAWAY re-fire and the deadline backstop.
	if h2InspectShuttingDown.Load() {
		logger.Printf("SSL_INSPECT(h2) refusing new tunnel %q during shutdown drain", sanitizeLog(hostOnly))
		return
	}

	// Register the client leg for the drain backstop BEFORE any upstream work, so a
	// stalled tr.NewClientConn cannot leave this tunnel invisible to BOTH the GOAWAY
	// re-fire (it isn't in the h2 server state until ServeConn) AND the deadline
	// force-close. The active gauge tracks from here; the deferred unregister
	// balances every exit path below.
	registerH2InspectConn(clientTLS)
	defer unregisterH2InspectConn(clientTLS)

	// One upstream H2 client connection carries every stream of this tunnel;
	// http2.ClientConn.RoundTrip is safe for concurrent use (h2 multiplexing).
	tr := &http2.Transport{}
	upstreamCC, err := tr.NewClientConn(upstreamTLS)
	if err != nil {
		logger.Printf("SSL_INSPECT(h2) upstream client-conn %q: %v", sanitizeLog(hostOnly), err)
		return
	}
	// Explicitly close the upstream client conn on teardown so the origin gets a
	// GOAWAY rather than a bare mid-stream FIN, and the ClientConn's reader
	// goroutine is reaped deterministically (closing upstreamTLS alone also reaps
	// it, but this documents the teardown).
	defer upstreamCC.Close() //nolint:errcheck // best-effort GOAWAY + reader-goroutine reap

	clientIP, _, _ := net.SplitHostPort(outer.RemoteAddr)

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h2InspectStream(outer, w, req, upstreamCC, hostOnly, clientIP, match, id, decBlock)
	})

	// Serve on the SHARED, ConfigureServer'd server (PR3d) so this tunnel's
	// serverConn registers into the graceful-shutdown state and receives a client
	// GOAWAY on process shutdown. The server carries the same caps as before —
	// MaxConcurrentStreams (primary per-connection bound + effective Rapid-Reset
	// cap), IdleTimeout, WriteByteTimeout, MaxReadFrameSize, and BaseConfig's
	// MaxHeaderBytes — moved onto the shared instance, not changed. Eager-init makes
	// h2InspectSrv non-nil in production; the fallback covers direct-call tests.
	sh := h2InspectSrv
	if sh == nil {
		// A nil here in production would mean init ordering regressed — the tunnel
		// would use a per-conn server the global GOAWAY trigger can't reach (only the
		// backstop registry closes it). Warn once so that regression is loud, not a
		// silently dropped graceful shutdown.
		warnH2InspectFallbackOnce()
		sh = newH2InspectServer()
	}

	// ServeConn runs each stream's handler in its own goroutine and blocks until
	// the client connection is no longer readable (or a shutdown GOAWAY + stream
	// completion, or the backstop force-close).
	sh.srv.ServeConn(clientTLS, &http2.ServeConnOpts{
		Context:    outer.Context(),
		Handler:    handler,
		BaseConfig: sh.base,
	})
}

// h2InspectStream handles one HTTP/2 stream: it reshapes the server-side request
// for an upstream round-trip and runs the shared inspection pipeline. The pipeline
// is protocol-agnostic; only the roundTrip (upstream http2 RoundTrip) and deliver
// (h2 ResponseWriter) hooks and the block responder are H2-specific.
func h2InspectStream(outer *http.Request, w http.ResponseWriter, req *http.Request, upstreamCC *http2.ClientConn, hostOnly, clientIP string, match *PolicyMatch, id ProxyIdentity, decBlock *DecryptionBlock) {
	// Per-request debug log, parity with the H1 loop's SSL_INNER line so admins can
	// trace file-block/scan decisions on H2 tunnels too. Logged before the reshape
	// (req.URL.Path is unchanged by it).
	filterStr := "off"
	profileStr := ""
	if match != nil && match.Rule != nil && match.Rule.FileFiltering {
		filterStr = "on"
		profileStr = sanitizeLog(string(match.Rule.FileProfile))
	}
	logger.Printf("SSL_INNER %s %s %s%s (profile=%q filter=%s)", sanitizeLog(clientIP), sanitizeLog(req.Method), sanitizeLog(hostOnly), sanitizeLog(req.URL.Path), profileStr, filterStr)

	// Reshape the h2 server request for an h2 client RoundTrip: RoundTrip requires
	// an absolute URL (scheme+host) and an empty RequestURI. The request travels
	// over upstreamCC, which is pinned to the CONNECT target, so the :authority
	// cannot redirect it off that connection (no SSRF). Strict :authority pinning
	// / 421 handling is a security-PR refinement.
	reqPath := req.URL.Path

	// Per-stream inactivity watchdog: cancel this stream's context if no body byte
	// moves in either direction within h2StreamStallTimeout. This is the H2
	// analogue of the H1 stallDetectReadCloser; a per-conn read deadline can't be
	// used because one conn multiplexes many streams. On cancel, RoundTrip aborts
	// (→ exRoundTripError before headers, or a body-read error → exDeliverError →
	// stream reset). The base ServeConn context still bounds the whole tunnel.
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	stallTO := resolveH2StallTimeout(match) // profile StallTimeoutSecs, else engine default
	stall := time.AfterFunc(stallTO, cancel)
	defer stall.Stop()
	resetStall := func() { stall.Reset(stallTO) }
	req = req.WithContext(ctx)

	req.URL.Scheme = "https"
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	req.RequestURI = ""
	if req.Body != nil {
		req.Body = &h2StallReader{rc: req.Body, reset: resetStall} // client-upload progress re-arms
	}

	ex := &inspectExchange{
		outer:     outer,
		req:       req,
		match:     match,
		id:        id,
		host:      hostOnly,
		clientIP:  clientIP,
		dec:       decBlock, // ADR-0011: rides block-log rows too
		responder: &h2BlockResponder{w: w},
		roundTrip: func(rq *http.Request) (*http.Response, error) {
			resp, err := upstreamCC.RoundTrip(rq)
			if err != nil {
				return nil, err
			}
			// Wrap here (not in deliver) so download progress re-arms the watchdog
			// during BOTH the scanInspectBody buffering phase and delivery — a slow
			// but steadily-progressing large download must not be falsely cancelled
			// mid-scan.
			resp.Body = &h2StallReader{rc: resp.Body, reset: resetStall}
			return resp, nil
		},
		deliver: func(resp *http.Response) error { return h2DeliverResponse(w, resp) },
	}

	out := runInspectExchange(ex)
	// If the per-stream watchdog (or the client) cancelled the context mid-exchange,
	// reset the stream — including the mid-scan case, which otherwise surfaces as
	// exBlocked with nothing written (a clean, empty 200). A genuinely delivered
	// response (exDelivered) completed its copy, so it is never reset here.
	if ctx.Err() != nil && out.kind != exDelivered {
		panic(http.ErrAbortHandler)
	}
	handleH2StreamOutcome(w, out, req, hostOnly, reqPath, clientIP, match, id, decBlock)
}

// handleH2StreamOutcome maps an inspection outcome to the H2 stream's terminal
// action. Extracted from h2InspectStream to keep it under the complexity cap.
func handleH2StreamOutcome(w http.ResponseWriter, out exchangeOutcome, req *http.Request, hostOnly, reqPath, clientIP string, match *PolicyMatch, id ProxyIdentity, decBlock *DecryptionBlock) {
	switch out.kind {
	case exRoundTripError:
		// Upstream failed before any byte was delivered — emit a clean 502.
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	case exUpgrade:
		// HTTP/2 has no 101 Switching Protocols; an upstream that returns one is
		// malformed for h2. Close the surfaced body and fail the stream rather than
		// raw-relaying a shared conn.
		if out.resp != nil {
			out.resp.Body.Close() //nolint:errcheck // best-effort; avoid an fd leak on this near-impossible path
		}
		logger.Printf("SSL_INSPECT(h2) unexpected 101 upgrade for %q — failing stream", sanitizeLog(hostOnly))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	case exDeliverError:
		// Delivery failed AFTER the response headers were committed (upstream body
		// truncation, a stalled stream cancelled by the watchdog, or the client went
		// away). Reset the stream with RST_STREAM so the client observes an error
		// rather than a clean-but-truncated 200 — http2.Server recovers
		// ErrAbortHandler into a stream reset.
		panic(http.ErrAbortHandler)
	case exDelivered:
		// Per-rule "log full URL" parity with the H1 path (log-only; the enclosing
		// CONNECT was already counted at allow time).
		if match != nil && match.Rule != nil && match.Rule.LogFullURI && ruleLogsTraffic(match.Rule) {
			recordRequestLogOnly(clientIP, req.Method, hostOnly, "OK", match.Rule.Name, string(ActionAllow), id.Identity, "inspect", policyLogURI(hostOnly, reqPath), AuthLogFields{RuleID: match.Rule.ID, Dec: decBlock, AuthSource: id.AuthSource})
		}
	case exBlocked:
		// The h2 block responder already wrote the 403 to the stream.
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
	if err := h2CopyBody(w, resp.Body); err != nil {
		return err
	}
	for k, vs := range resp.Trailer {
		if hopByHopTrailerNames[k] {
			continue // don't forward hop-by-hop names as trailers
		}
		for _, v := range vs {
			w.Header().Add(http.TrailerPrefix+k, v)
		}
	}
	return nil
}

// h2CopyBody streams an upstream response body onto the client H2 stream.
//
// The GUARANTEED win is allocation: it uses a pooled 128 KiB relay buffer (the same
// relayBufPool every other tunnel relay uses) instead of io.Copy's fresh 32 KiB
// per-response allocation, so the byte-moving hot path allocates nothing per
// response.
//
// Flushing is ADAPTIVE and NEVER delays a byte the origin has finished sending: it
// forces a Flush after any SHORT read (nr < 128 KiB) — every real streaming message
// (SSE events, gRPC frames, long-poll bodies are all far below 128 KiB) lands as a
// short read and flushes exactly as the old unconditional per-write flush did, so
// streaming latency is unchanged. The flush is skipped ONLY when a read fills the
// whole 128 KiB buffer, which means more data was already waiting; back-to-back
// full reads then coalesce into the h2 write scheduler instead of paying a Flush
// each. This coalescing is OPPORTUNISTIC, not guaranteed — a real http2.Transport
// body reads out of a flow-control-bounded pipe and often returns < 128 KiB even
// under sustained bulk, in which case the cadence is effectively the old per-read
// flush (no worse). So the change is a strict improvement (pooled buffer always;
// fewer flushes when full reads happen) but the bulk-coalescing magnitude depends
// on the upstream's read sizes.
//
// A full-buffer final chunk is still delivered: a 128 KiB write goes straight
// through the h2 handler's ~4 KiB bufio to the frame scheduler, and on normal
// completion the h2 server flushes the sub-4 KiB remainder on END_STREAM when the
// handler returns — no tail is stranded on the success path. The only deferral is a
// streamed chunk that EXACTLY fills the buffer then pauses on a still-open stream;
// its < 4 KiB bufio remainder waits for the next read, bounded by the per-stream
// watchdog. That does not arise for real streaming protocols.
//
// The src is the watchdog-wrapped body (h2StallReader), so every Read here re-arms
// the per-stream inactivity timer exactly as before — flushing less often does not
// affect the stall bound.
func h2CopyBody(w http.ResponseWriter, src io.Reader) error {
	flusher, _ := w.(http.Flusher)
	bp := getRelayBuf()
	defer relayBufPool.Put(bp)
	buf := *bp
	for {
		// Mirrors io.Copy's read/write loop (including the benign (0,nil) case: a
		// well-behaved body — the h2StallReader-wrapped http2 body here — never spins,
		// same assumption io.Copy makes). len(buf) is relayBufSize (getRelayBuf never
		// returns a larger slice), so "nr < len(buf)" is the 128 KiB short-read test.
		nr, rerr := src.Read(buf)
		if nr > 0 {
			// Preserve io.Copy's byte-integrity guarantee: a short write with a nil
			// error (an io.Writer contract violation the production h2 responseWriter
			// never commits, but which the replaced io.Copy still guarded) must fail
			// the exchange → exDeliverError → RST_STREAM, never a clean truncated 200.
			nw, werr := w.Write(buf[:nr])
			if werr != nil {
				return werr
			}
			if nw < nr {
				return io.ErrShortWrite
			}
			if flusher != nil && nr < len(buf) {
				flusher.Flush()
			}
		}
		if rerr != nil {
			// errors.Is (not ==) so a body that ever wraps EOF (%w) still ends the
			// stream cleanly rather than surfacing as exDeliverError → a spurious
			// RST_STREAM on a fully-delivered response.
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}
