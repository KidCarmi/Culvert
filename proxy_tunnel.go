package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileblock"
)

// relayBufSize is the size of each pooled relay buffer.
const relayBufSize = 128 * 1024

// relayBufPool provides reusable 128 KB buffers for tunnel relays, replacing
// io.Copy's default 32 KB allocation and reducing GC pressure under load.
var relayBufPool = sync.Pool{
	New: func() any { b := make([]byte, relayBufSize); return &b },
}

// getRelayBuf retrieves a relay buffer from the pool with a type-safe assertion.
func getRelayBuf() *[]byte {
	bp, ok := relayBufPool.Get().(*[]byte)
	if !ok || bp == nil || len(*bp) < relayBufSize {
		b := make([]byte, relayBufSize)
		bp = &b
	}
	return bp
}

// isWebSocketUpgrade returns true when the request is an HTTP→WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleWebSocket proxies a plain-HTTP WebSocket upgrade by dialling the
// target host directly, forwarding the original HTTP request (including
// Upgrade headers), then bridging the raw TCP streams. match/id carry the
// policy decision and authenticated identity for the close accounting entry.
// dialWebSocketUpstream applies the two-layer SSRF guard (DNS-layer
// isPrivateHost + connect-layer ssrfControl via ssrfSafeDialContext) and dials
// the WebSocket target, normalising a bare host to :80. On failure it writes
// the terminal error response and returns ok=false. Extracted from
// handleWebSocket to keep it under the funlen cap.
func dialWebSocketUpstream(w http.ResponseWriter, r *http.Request) (net.Conn, bool) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	if err := isPrivateHost(host); err != nil {
		logger.Printf("WS SSRF block %q: %v", sanitizeLog(host), err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}
	// ssrfSafeDialContext applies ssrfControl on every resolved address,
	// matching every other outbound dial in the codebase. isPrivateHost above is
	// the DNS-layer guard; this is the connect-layer guard — defense in depth.
	destConn, err := ssrfSafeDialContext(r.Context(), "tcp", host)
	if err != nil {
		logger.Printf("WS dial error %q: %v", sanitizeLog(host), err)
		if isDNSError(err) {
			go fireAlert("dns_failure", AlertPayload{Host: host, Detail: err.Error(), Source: "proxy"})
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return nil, false
	}
	return destConn, true
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, match *PolicyMatch, id ProxyIdentity) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	destConn, ok := dialWebSocketUpstream(w, r)
	if !ok {
		return
	}
	defer destConn.Close()

	// Sanitise before forwarding, exactly like handleHTTP/inspect: strips the
	// internal X-User-Identity (it previously leaked to WS targets) and
	// private X-Forwarded-For/X-Real-IP hops. Upgrade/Connection are untouched.
	scrubForwardedHeaders(r)

	// Forward the original request to the target (preserve Upgrade headers).
	r.RequestURI = r.URL.RequestURI()
	if err := r.Write(destConn); err != nil {
		logger.Printf("WS write error %q: %v", sanitizeLog(host), err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read the 101 Switching Protocols response from the target.
	br := bufio.NewReader(destConn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		logger.Printf("WS upstream response error %q: %v", sanitizeLog(host), err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Only a 101 Switching Protocols actually upgrades the connection. If the
	// upstream declined the upgrade (any other status), relay the response
	// through the normal ResponseWriter and return WITHOUT hijacking. Entering
	// raw-tunnel mode on a connection that never switched protocols would let a
	// client pipeline arbitrary bytes to the target over a keep-alive HTTP
	// connection, bypassing the HTTP-level policy and scanning that plain
	// requests are subject to. The SSL-inspected path already gates on this.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		logger.Printf("WS: upstream declined upgrade for %q (status %d)", sanitizeLog(host), resp.StatusCode)
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck // best-effort copy of block-page body to client
		return
	}

	// Hijack the client connection and replay the 101 response.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		logger.Printf("WS hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	// Write the 101 response back to the client.
	if err := resp.Write(clientBuf); err != nil {
		return
	}
	if err := clientBuf.Flush(); err != nil {
		return
	}

	logger.Printf("WS: tunnel established %q", sanitizeLog(host))
	start := time.Now()

	// Bridge both directions. client → target reads via clientBuf.Reader, NOT
	// the raw clientConn: the HTTP server may have buffered client bytes (frames
	// pipelined right after the Upgrade request) into the hijacked reader;
	// relaying the raw conn would strand them and the target would block. Same
	// class of bug as the CONNECT bypass path.
	toClient, toDest := bidiRelayCounted(clientConn, br, destConn, clientBuf.Reader)

	// Per-connection accounting entry (bytes + lifetime).
	recordTunnelCloseGated(match, id, "WS", r.Host, toDest, toClient, start, "")
}

// tunnelIdleTimeout bounds how long a raw tunnel relay may sit with zero bytes
// flowing in EITHER direction before it is torn down (CHAOS-03). Half-open
// peers that keep ACKing TCP keepalives but never send data previously pinned
// 2 goroutines + 2 FDs + a pooled buffer indefinitely; a flood of such
// connections exhausts the process. One hour is deliberately conservative:
// legitimate idle-but-alive tunnels (SSH, IMAP IDLE, WebSocket ping/pong) all
// generate application bytes well inside that window, so only truly dead or
// abusive tunnels are reaped. Var (not const) so tests can shorten it;
// production never mutates it (configurability is a recorded deferral).
var tunnelIdleTimeout = 1 * time.Hour

// newTunnelActivityStamp returns the shared last-activity stamp (unix nanos)
// for one tunnel's two relay directions, seeded to now so a tunnel that never
// moves a byte is reaped one idle window after establishment.
func newTunnelActivityStamp() *atomic.Int64 {
	s := new(atomic.Int64)
	s.Store(time.Now().UnixNano())
	return s
}

// idleCopyCounted copies src→dst through a pooled relay buffer, arming a read
// deadline on srcConn (the conn src ultimately reads — src itself may be a
// bufio wrapper over it) so the copy wakes at least twice per idle window. A
// deadline pop while the tunnel saw bytes in either direction (shared stamp
// fresh) re-arms and resumes — safe because only read deadlines are used and
// read-deadline timeouts are resumable on both *net.TCPConn and *tls.Conn
// (only write timeouts corrupt TLS state). A pop with the stamp stale for a
// full window means BOTH directions were silent: the tunnel is torn down by
// closing BOTH conns — a hard close, not CloseWrite, because the peer relay
// may be blocked in a deadline-less Write (receiver ACKs but never reads)
// that only a close can unblock.
//
// Two deliberate mechanics:
//   - Deadlines are armed AROUND io.CopyBuffer, not via a reader wrapper, so
//     the ReaderFrom/WriterTo kernel-splice fast path on TCP↔TCP relays is
//     preserved on the CONNECT-bypass hot path.
//   - The arm interval is HALF the idle window. The stamp is only refreshed
//     when a copy call returns (a busy copy runs without returning), so an
//     active direction refreshes the stamp every half-window at latest; the
//     silent direction's staleness check therefore carries a half-window
//     scheduling margin and can never reap a tunnel whose other direction is
//     alive, even when both deadlines pop near-simultaneously.
//
// Returns the bytes copied into dst.
func idleCopyCounted(dst net.Conn, src io.Reader, srcConn net.Conn, shared *atomic.Int64) int64 {
	timeout := tunnelIdleTimeout
	armInterval := timeout / 2
	bp := getRelayBuf()
	defer relayBufPool.Put(bp)
	var total int64
	for {
		srcConn.SetReadDeadline(time.Now().Add(armInterval)) //nolint:errcheck // a set failure on a closing conn surfaces as the next read error
		n, err := io.CopyBuffer(dst, src, *bp)
		total += n
		if n > 0 {
			shared.Store(time.Now().UnixNano())
		}
		var ne net.Error
		if err != nil && errors.As(err, &ne) && ne.Timeout() {
			if time.Since(time.Unix(0, shared.Load())) >= timeout {
				logger.Printf("tunnel idle timeout: no bytes in either direction for %v, closing relay", timeout)
				dst.Close()     //nolint:errcheck // teardown; peer relay unblocks on the close
				srcConn.Close() //nolint:errcheck // teardown; peer relay unblocks on the close
				return total
			}
			continue // the tunnel was active inside the window — re-arm and keep waiting
		}
		// nil (src EOF) or a terminal error — relay copy errors are expected
		// on peer close; the byte count is still valid.
		return total
	}
}

// relayCounted copies src→dst through a pooled relay buffer, adds the bytes
// copied to *count, closes dst's write half so the peer sees EOF (B2 — without
// interfering with the other direction's in-flight writes), and signals done.
// srcConn is the conn src reads (idle-deadline anchor — see idleCopyCounted).
// Shared by the WebSocket and CONNECT-bypass raw relays.
func relayCounted(dst net.Conn, src io.Reader, srcConn net.Conn, shared *atomic.Int64, count *int64, done chan<- struct{}) {
	*count += idleCopyCounted(dst, src, srcConn, shared)
	if tc, ok := dst.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite() //nolint:errcheck // best-effort EOF signal; peer may already be gone
	}
	done <- struct{}{}
}

// bidiRelayCounted runs two relayCounted goroutines (aDst←aSrc and bDst←bSrc)
// and waits for both to drain, returning the bytes copied into aDst and bDst
// respectively. Each direction's count is written by exactly one goroutine
// before its done-send and read only after both receives (channel
// happens-before), so no atomics are needed.
//
// Idle-deadline anchoring relies on the bridge invariant that holds for both
// callers by construction: aSrc reads the conn that is bDst, and bSrc reads
// the conn that is aDst (each direction reads one peer and writes the other).
func bidiRelayCounted(aDst net.Conn, aSrc io.Reader, bDst net.Conn, bSrc io.Reader) (aBytes, bBytes int64) {
	shared := newTunnelActivityStamp()
	done := make(chan struct{}, 2)
	go relayCounted(aDst, aSrc, bDst, shared, &aBytes, done)
	go relayCounted(bDst, bSrc, aDst, shared, &bBytes, done)
	<-done
	<-done
	return aBytes, bBytes
}

// readerConn wraps a net.Conn with a bufio.Reader so that bytes already peeked
// (e.g. for protocol detection) are not lost when the conn is handed to tls.Server.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// detectProtocolName returns a human-readable name for the protocol identified
// by its first byte on the wire. Used for logging when a non-TLS protocol is
// detected inside a CONNECT tunnel under SSL inspection.
func detectProtocolName(b byte) string {
	switch {
	case b == 0x16:
		return "TLS"
	case b == 'S': // "SSH-..." banner
		return "SSH"
	case b == 0x03: // RDP TPKT header (version 3)
		return "RDP"
	case b >= 0x14 && b <= 0x17: // other TLS content types (change_cipher_spec, alert, application_data)
		return "TLS"
	case b == 'G' || b == 'P' || b == 'H' || b == 'D' || b == 'O' || b == 'C' || b == 'T':
		return "HTTP" // GET, POST, HEAD, DELETE, OPTIONS, CONNECT, TRACE
	default:
		return "unknown"
	}
}

// handleTunnel dispatches to SSL-bypass or SSL-inspect based on policy.
// match is the policy evaluation result (may be nil when no rule matched and
// default action is "allow"); it is forwarded to the inspect path so per-rule
// file-blocking profiles can be enforced on inner HTTP requests.
//
// id is the authenticated context extracted by the top-level handler; it is
// forwarded to inspect so downstream stages (CDR, future audit enrichment)
// can branch on identity without re-parsing headers.
func handleTunnel(w http.ResponseWriter, r *http.Request, sslAction SSLAction, tlsSkipVerify bool, match *PolicyMatch, id ProxyIdentity) {
	if sslAction == SSLInspect && certMgr.Ready() {
		handleTunnelInspect(w, r, tlsSkipVerify, match, id)
	} else {
		handleTunnelBypass(w, r, match, id)
	}
}

// The shared upstream http.Transport is owned by upstream_transport.go
// (P5.3 / S6). Production code reads it via getUpstreamTransport() and
// mutates it via swapUpstreamTransport(update). Direct field mutation
// on a loaded transport is forbidden — see upstream_transport.go and
// CLAUDE.md for the convention.

// applyUpstreamProxy configures the shared transport to route through parent
// proxies when the upstream pool is active. P5.3: routes through
// swapUpstreamTransport so the swap is atomic vs concurrent readers.
func applyUpstreamProxy() {
	if !upstreamPool.Enabled() {
		return
	}
	proxyFn := upstreamPool.ProxyFunc()
	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		newT := cloneTransport(old)
		newT.Proxy = proxyFn
		return newT
	})
}

// handleTunnelBypass is the original transparent TCP tunnel (Bypass mode).
// match/id carry the policy decision and authenticated identity for the
// close accounting entry.
func handleTunnelBypass(w http.ResponseWriter, r *http.Request, match *PolicyMatch, id ProxyIdentity) {
	if err := isPrivateHost(r.Host); err != nil {
		logger.Printf("CONNECT SSRF block %q: %v", sanitizeLog(r.Host), err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// Use ssrfControl so the final connect() call is rejected if DNS rebinding
	// flipped the target to a private IP between isPrivateHost and here.
	destConn, err := (&net.Dialer{Timeout: 10 * time.Second, Control: ssrfControl}).DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		logger.Printf("tunnel dial error %q: %v", sanitizeLog(r.Host), err)
		if isDNSError(err) {
			go fireAlert("dns_failure", AlertPayload{Host: r.Host, Detail: err.Error(), Source: "proxy"})
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	// Hijack BEFORE sending the 200 and relay the response by hand. Calling
	// w.WriteHeader(200) and THEN hijacking discards the *bufio.ReadWriter the
	// server returns — and the server's request reader may have already buffered
	// client bytes into it (body bytes a client pipelines right after CONNECT).
	// A raw-conn relay never sees those stranded bytes, so the upstream stalls
	// waiting for them: the rare first-byte tunnel hang observed under concurrent
	// setup. Hijack first, send the 200, then FLUSH any buffered client bytes to
	// the upstream before starting the byte relay.
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		logger.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		logger.Printf("CONNECT 200 write error %q: %v", sanitizeLog(r.Host), err)
		return
	}

	recordActiveConn(1)
	defer recordActiveConn(-1)

	start := time.Now()
	var toDest, toClient int64

	// Drain bytes the HTTP server already buffered from the client during request
	// parsing; without this they are lost and the upstream blocks forever.
	if clientBuf != nil {
		if n := clientBuf.Reader.Buffered(); n > 0 {
			flushed, err := io.CopyN(destConn, clientBuf.Reader, int64(n))
			toDest += flushed
			if err != nil {
				logger.Printf("CONNECT prebuffer flush error %q: %v", sanitizeLog(r.Host), err)
				return
			}
		}
	}

	// Bridge both directions. toDest already carries any prebuffer bytes
	// flushed above; bidiRelayCounted's relayCounted adds (+=) to it.
	dOut, cOut := bidiRelayCounted(destConn, clientConn, clientConn, destConn)
	toDest += dOut
	toClient += cOut

	// Per-connection accounting entry (bytes + lifetime).
	recordTunnelCloseGated(match, id, "CONNECT", r.Host, toDest, toClient, start, "bypass")
}

// upstreamVerifyRoots returns the process-wide root pool used to verify
// upstream certificates on SSL-inspected tunnels. x509.SystemCertPool clones
// the cached system pool on EVERY call (~150 roots ⇒ ~160 allocs / ~26 KB /
// ~20 µs measured on the CI runner class), and the pre-optimization code paid
// that per inspected CONNECT tunnel. The pool is loaded once and shared
// read-only across all upstream tls.Configs — safe because certificate
// verification never mutates a CertPool and nothing calls AddCert on this one
// (callers that need to extend a pool must Clone it first). Fail-closed: when
// the system pool is unavailable the cached EMPTY pool rejects all unknown
// CAs — that condition is environmental (missing ca-certificates bundle) and
// does not heal without operator action, so caching it is correct; the
// warning now logs once per process instead of once per tunnel.
var upstreamVerifyRoots = sync.OnceValue(func() *x509.CertPool {
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		logWarnf("TLS: SystemCertPool unavailable, using empty pool (will reject all unknown CAs): %v", err)
		return x509.NewCertPool()
	}
	return systemRoots
})

// upstreamSessionCache lets the upstream leg of inspected tunnels RESUME TLS
// instead of paying a full handshake (ECDHE + cert-chain verify + signature) on
// every reconnect to the same host — the dominant per-connection CPU cost for a
// browsing mix (perf F1). It is shared across all per-tunnel configs; the stdlib
// keys the client cache on ServerName (the port-stripped origin host set on
// every verifying config), so a ticket minted for one origin can only be
// offered back to that same origin — a foreign server can't decrypt it and the
// handshake safely falls back to a full verified one. A session is only cached
// AFTER a successful verified handshake, so a resumption inherits that
// handshake's verification (no security change); the one accepted tradeoff is
// the universal TLS-resumption semantics — a session cached while the origin
// cert was valid can resume without re-checking that cert until the ticket
// expires. The cache is attached ONLY to the verifying config below — the
// per-rule skip-verify path stays fully isolated (no cache, always a fresh
// handshake), so an unverified session can never be stored or resumed.
var upstreamSessionCache = tls.NewLRUClientSessionCache(4096)

// mitmClientTLSConfig is the shared client-facing (forged-leaf) TLS config for
// inspected tunnels (perf F2). Hoisting it to ONE instance keeps the
// session-ticket keys stable across connections — enabling TLS 1.3 client
// resumption (a per-connection config rotated keys, giving ~0% resumption and a
// re-presented forged leaf on every reconnect) and removing a tls.Config
// allocation per inspected connection. GetCertificate indirects through the
// certMgr global on every call so CA rotation and test reassignment are
// respected (previously `certMgr.GetCert` was bound per-connection). The config
// is read-only after init; tls.Server never mutates the passed config and the
// stdlib locks ticket-key rotation internally, so concurrent handshakes are
// safe.
//
//   - MinVersion floor: never present legacy TLS to clients. Matches Go's
//     current default but is pinned so a toolchain/refactor change can't
//     silently weaken the client-facing posture (asserted by
//     TestMITM_ForgedLeafTLSPosture).
//   - NextProtos http/1.1 only: the inner request loop uses http.ReadRequest
//     (HTTP/1.x). Without this, browsers negotiate HTTP/2 via ALPN and the
//     parser can't read H2 frames, silently falling back to raw relay with zero
//     file-blocking/DPI/scanning.
var mitmClientTLSConfig = &tls.Config{
	GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return certMgr.GetCert(chi) },
	MinVersion:     tls.VersionTLS12,
	NextProtos:     []string{"http/1.1"},
}

// rotateMITMTicketKeys installs a fresh random session-ticket key on the shared
// client-facing config, invalidating every outstanding TLS session ticket. It
// is wired to ca.CAChangedObserver so a Root-CA change (auto-rotation, manual
// force-rotate, or custom-CA upload) ends the resumption epoch: the next
// reconnect can no longer take the TLS 1.3 PSK path (which never re-runs
// GetCertificate) and must full-handshake, re-presenting a leaf signed by the
// NEW CA. Within one CA epoch the key is stable, which is what lets clients
// resume (perf F2); the pinned-key exposure is bounded — a client only offers
// tickets up to the stdlib's ~7-day max age, and TLS 1.3's per-session ECDHE
// keeps session data forward-secret even if a ticket key leaks.
// SetSessionTicketKeys is safe to call concurrently with live handshakes on the
// shared config (the stdlib guards ticket-key state internally).
func rotateMITMTicketKeys() {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		// Extremely unlikely; leave the existing keys in place rather than
		// zeroing them. A failed rotation only means the old epoch's tickets
		// stay valid until age-expiry — no worse than before this hook.
		logWarnf("MITM ticket-key rotation: rand read failed: %v", err)
		return
	}
	mitmClientTLSConfig.SetSessionTicketKeys([][32]byte{key})
}

// upstreamInspectTLSConfig builds the tls.Config for the upstream leg of an
// SSL-inspected tunnel. The default path verifies against the shared
// upstreamVerifyRoots pool; tlsSkipVerify (admin-configured per-rule) disables
// upstream certificate validation for internal/self-signed hosts and stays
// logged per tunnel so every unverified connection remains auditable.
func upstreamInspectTLSConfig(hostOnly string, tlsSkipVerify bool) *tls.Config {
	if tlsSkipVerify {
		logWarnf("SSLInspect: skipping upstream cert verify for %q (tlsSkipVerify rule)", sanitizeLog(hostOnly))
		return &tls.Config{
			ServerName:         hostOnly,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // #nosec G402 — admin-configured per-rule override
		}
	}
	return &tls.Config{
		ServerName:         hostOnly,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            upstreamVerifyRoots(),
		ClientSessionCache: upstreamSessionCache,
	}
}

// handleTunnelInspect performs SSL inspection (MITM) for CONNECT tunnels.
// It terminates TLS on both sides using on-the-fly certificates signed by the
// internal Root CA, allowing the proxy to inspect decrypted HTTP/1.x traffic.
// tlsSkipVerify disables upstream certificate validation for specific policy
// rules (e.g. internal sites with self-signed certs); use with caution.
//
// pre-existing complexity predating the CDR integration (was gocognit 128 before CDR;
// dropped to 112 after Phase 2b extracted runCDRStage out of here).  Further splitting
// would change the keep-alive loop semantics and is out of scope for CDR work —
// tracked as a day-2 refactor item in roadmap/roadmap-day2.md.
//
//nolint:gocognit,gocyclo,cyclop,funlen // handleTunnelInspect is the SSL-inspection orchestrator —
func handleTunnelInspect(w http.ResponseWriter, r *http.Request, tlsSkipVerify bool, match *PolicyMatch, id ProxyIdentity) {
	targetHost := r.Host
	if _, _, err := net.SplitHostPort(targetHost); err != nil {
		targetHost += ":443"
	}
	hostOnly, _, _ := net.SplitHostPort(targetHost)

	// 1. Connect to the upstream server over plain TCP.
	if err := isPrivateHost(targetHost); err != nil {
		logger.Printf("inspect SSRF block %q: %v", sanitizeLog(targetHost), err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	// Use ssrfControl so the final connect() call is rejected if DNS rebinding
	// flipped the target to a private IP between isPrivateHost and here.
	rawUpstream, err := (&net.Dialer{Timeout: 10 * time.Second, Control: ssrfControl}).DialContext(r.Context(), "tcp", targetHost)
	if err != nil {
		logger.Printf("inspect dial error %q: %v", sanitizeLog(targetHost), err)
		if isDNSError(err) {
			go fireAlert("dns_failure", AlertPayload{Host: targetHost, Detail: err.Error(), Source: "proxy"})
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// 2. Perform TLS handshake with the upstream.
	// upstreamInspectTLSConfig verifies against the shared system root pool by
	// default (fail-secure); tlsSkipVerify (admin-configured per-rule) skips
	// cert validation for internal/self-signed hosts and is logged as a warning
	// so it is auditable.
	upstreamTLSCfg := upstreamInspectTLSConfig(hostOnly, tlsSkipVerify)
	upstreamTLS := tls.Client(rawUpstream, upstreamTLSCfg)
	if err := upstreamTLS.HandshakeContext(r.Context()); err != nil {
		upstreamTLS.Close() //nolint:errcheck // best-effort cleanup; closes both TLS and underlying TCP conn
		logger.Printf("upstream TLS handshake error %q: %v", sanitizeLog(targetHost), err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// 3. Hijack the client connection and send the 200 Connection Established.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstreamTLS.Close() //nolint:errcheck // best-effort cleanup on hijack-unsupported
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	rawClient, clientBuf, err := hijacker.Hijack()
	if err != nil {
		upstreamTLS.Close() //nolint:errcheck // best-effort cleanup on hijack failure
		logger.Printf("SSL_INSPECT hijack error: %v", err)
		return
	}

	// 3b. Peek the first byte from the client to detect the protocol.
	// TLS ClientHello starts with 0x16 (handshake record). If the client
	// is sending SSH, RDP, or another non-TLS protocol through CONNECT,
	// fall back to raw relay instead of crashing on TLS handshake.
	//
	// Read through clientBuf.Reader (the hijacked buffer) rather than a fresh
	// reader over the raw conn: the HTTP server may have already buffered client
	// bytes (a pipelined ClientHello) into it, and reading the raw conn would
	// strand them — breaking protocol detection / the client handshake. Same
	// class of bug as the CONNECT bypass path.
	peekBuf := clientBuf.Reader
	firstByte, err := peekBuf.Peek(1)
	if err != nil {
		rawClient.Close()   //nolint:errcheck // best-effort cleanup on peek failure
		upstreamTLS.Close() //nolint:errcheck // best-effort cleanup on peek failure
		logger.Printf("SSL_INSPECT peek error for %q: %v", sanitizeLog(hostOnly), err)
		return
	}
	if firstByte[0] != 0x16 { // not a TLS handshake record
		proto := detectProtocolName(firstByte[0])
		logger.Printf("SSL_INSPECT non-TLS protocol detected for %q (first byte=0x%02x, proto=%s) — falling back to raw relay",
			sanitizeLog(hostOnly), firstByte[0], proto)
		// Raw relay: splice the peeked reader (client) ↔ upstream (already
		// TLS-connected). This is a non-TLS tunnel that bypasses HTTP-level
		// inspection, so — like the CONNECT-bypass / WebSocket / SOCKS5 relays —
		// account its bytes and lifetime in the request log (Finding 11.1).
		// Teardown is unchanged: wait for one side to EOF, then Close both to
		// unblock the other. Each direction's count is written by exactly one
		// goroutine before its done-send and read only after both done-receives
		// (channel happens-before), so no atomics are needed. Both directions
		// share an idle stamp (idleCopyCounted) so a half-open peer cannot pin
		// the tunnel forever; the client direction reads through peekBuf, so
		// its deadline anchors on the underlying rawClient conn.
		start := time.Now()
		var toUpstream, toClient int64
		shared := newTunnelActivityStamp()
		done := make(chan struct{}, 2)
		relay := func(dst net.Conn, src io.Reader, srcConn net.Conn, count *int64) {
			*count = idleCopyCounted(dst, src, srcConn, shared)
			done <- struct{}{}
		}
		go relay(upstreamTLS, peekBuf, rawClient, &toUpstream)   // client → upstream
		go relay(rawClient, upstreamTLS, upstreamTLS, &toClient) // upstream → client
		<-done
		rawClient.Close()   //nolint:errcheck // force the peer relay to unblock
		upstreamTLS.Close() //nolint:errcheck // force the peer relay to unblock
		<-done
		recordTunnelCloseGated(match, id, "CONNECT", hostOnly, toUpstream, toClient, start, "inspect")
		return
	}

	// 4. Perform TLS handshake with the client using a dynamically-signed cert.
	// Wrap rawClient with the peek buffer so the already-peeked byte isn't lost.
	// Uses the shared mitmClientTLSConfig (perf F2) so session-ticket keys are
	// stable across connections and clients can resume.
	clientTLS := tls.Server(readerConn{Conn: rawClient, r: peekBuf}, mitmClientTLSConfig)
	if err := clientTLS.HandshakeContext(r.Context()); err != nil {
		clientTLS.Close()   //nolint:errcheck // best-effort cleanup on handshake failure
		upstreamTLS.Close() //nolint:errcheck // best-effort cleanup on handshake failure
		logger.Printf("SSL_INSPECT client TLS handshake error for %q: %v", sanitizeLog(hostOnly), err)
		return
	}

	logger.Printf("SSLInspect: tunnel %q", sanitizeLog(targetHost))
	recordActiveConn(1)
	defer recordActiveConn(-1)

	// 5. Proxy HTTP/1.x with optional DPI scanning on response bodies.
	//
	// Parsing the decrypted HTTP stream request-by-request lets us:
	//   a) Apply DPI signatures to text response bodies before forwarding.
	//   b) Block on match (true prevention, not just detection).
	//
	// WebSocket upgrades (101 Switching Protocols) fall back to raw relay
	// because the protocol is no longer HTTP after the handshake.
	//
	// Limitation: HTTP/2 inside the tunnel is not parsed; the fallback raw
	// relay is used.  H2 DPI support requires a full HPACK parser.
	clientBR := bufio.NewReaderSize(clientTLS, 32*1024)
	upstreamBR := bufio.NewReaderSize(upstreamTLS, 32*1024)

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	for {
		// Slowloris protection: enforce a read deadline so a slow client cannot
		// hold the connection open indefinitely by trickling bytes.
		clientTLS.SetReadDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck // best-effort slowloris deadline
		// Read next HTTP/1.x request from the (decrypted) client stream.
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			break
		}
		// H2: wrap req.Body with a stall-detecting reader. The previous
		// implementation cleared the read deadline entirely before
		// req.Write(upstreamTLS), leaving the upstream TLS connection
		// pinned to a slow body transfer indefinitely. Stall detection
		// re-arms the client-side read deadline on every Body.Read, so a
		// pause longer than sslInspectBodyStallTimeout trips the next
		// Read — long legitimate uploads still complete as long as bytes
		// keep flowing.
		req.Body = &stallDetectReadCloser{
			ReadCloser: req.Body,
			conn:       clientTLS,
			timeout:    sslInspectBodyStallTimeout,
		}

		// Debug: log every inner request so admins can trace file-blocking decisions.
		// All values are sanitized or hardcoded to satisfy CodeQL CWE-117.
		filterStr := "off"
		profileStr := ""
		if match != nil && match.Rule != nil && match.Rule.FileFiltering {
			filterStr = "on"
			profileStr = sanitizeLog(string(match.Rule.FileProfile))
		}
		logger.Printf("SSL_INNER %s %s %s%s (profile=%q filter=%s)", sanitizeLog(clientIP), sanitizeLog(req.Method), sanitizeLog(hostOnly), sanitizeLog(req.URL.Path), profileStr, filterStr)
		// Scrub client-spoofable forwarded/identity headers on the DECRYPTED
		// inner request, exactly as the plain-HTTP path does in handleHTTP.
		// Without this, an SSL-inspected HTTPS request could inject
		// X-User-Identity (impersonating an authenticated user to upstreams that
		// trust the proxy's identity header) or leak private X-Forwarded-For /
		// X-Real-IP addresses — a defense the plain-HTTP path already has but the
		// inspect path was missing.
		scrubForwardedHeaders(req)
		// Strip hop-by-hop headers before forwarding upstream.
		removeHopHeaders(req.Header)

		// Forward the request to the upstream TLS connection.
		if err := req.Write(upstreamTLS); err != nil {
			req.Body.Close()
			break
		}
		req.Body.Close()

		// Read the upstream HTTP/1.x response.
		resp, err := http.ReadResponse(upstreamBR, req)
		if err != nil {
			break
		}

		// ── File blocking (tunnel inner request) ────────────────────────────
		// Mirrors the file-blocking logic in handleHTTP and the pre-policy
		// global check in handleRequest. Runs before any data is written to the
		// client, so a clean 403 is safe to inject.
		if inspectFileBlocked(h1BlockResponder{w: clientTLS}, req, resp, match, hostOnly, clientIP) {
			break
		}

		// WebSocket upgrade: the protocol switches after the 101 handshake.
		// Write the 101 response to the client and fall back to raw relay.
		if resp.StatusCode == http.StatusSwitchingProtocols {
			resp.Write(clientTLS) //nolint:errcheck // best-effort write of buffered response to client
			resp.Body.Close()
			// Idle-bounded (idleCopyCounted) like every other raw relay: a
			// half-open WebSocket peer inside an inspected tunnel cannot pin
			// the two TLS conns forever. Read deadlines re-arm per window and
			// are resumable on tls.Conn (only write timeouts corrupt TLS).
			shared := newTunnelActivityStamp()
			done := make(chan struct{}, 2)
			rawRelay := func(dst, src net.Conn) {
				idleCopyCounted(dst, src, src, shared)
				done <- struct{}{}
			}
			go rawRelay(upstreamTLS, clientTLS)
			go rawRelay(clientTLS, upstreamTLS)
			<-done
			// Unblock the peer goroutine by closing both TLS connections.
			// tls.Conn has no CloseWrite, so full Close is used instead.
			clientTLS.Close()   //nolint:errcheck // best-effort; unblocks the peer relay goroutine
			upstreamTLS.Close() //nolint:errcheck // best-effort; unblocks the peer relay goroutine
			<-done
			return
		}

		// Unified scan buffer: magic/polyglot + CDR + DPI signatures + ClamAV +
		// YARA. Buffers up to maxScanBufferBytes() before forwarding so any match
		// blocks the response entirely (true prevention, not merely logging).
		if scanInspectBody(r, req, resp, h1BlockResponder{w: clientTLS}, match, id, hostOnly, clientIP) {
			break
		}

		closeAfter := req.Close || resp.Close
		removeHopHeaders(resp.Header)
		if err := resp.Write(clientTLS); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		// Per-rule "log full URL": one log entry per delivered inner request,
		// carrying the decrypted host+path (no query). Opt-in via the matched
		// rule's LogFullURI flag — off by default, so inspected traffic for
		// other rules still produces only the single CONNECT-open entry.
		if match != nil && match.Rule != nil && match.Rule.LogFullURI && ruleLogsTraffic(match.Rule) {
			// Log-only: the enclosing CONNECT was already counted by the allow
			// path, so this per-URL entry must not re-increment request stats.
			recordRequestLogOnly(clientIP, req.Method, hostOnly, "OK", match.Rule.Name, string(ActionAllow), id.Identity, "inspect", policyLogURI(hostOnly, req.URL.Path), AuthLogFields{})
		}
		if closeAfter {
			break
		}
	}
	clientTLS.Close()   //nolint:errcheck // best-effort cleanup at relay end
	upstreamTLS.Close() //nolint:errcheck // best-effort cleanup at relay end
}

// inspectFileBlocked runs the inner-request file-block checks against a decrypted
// tunnel request/response: (1) global file-extension blocklist on the URL, (2)
// per-rule file profile on the URL, (3) Content-Disposition filename, (4)
// Content-Type MIME. On a match it records the block, closes resp.Body, writes
// the block page to the client, and returns true — the caller must stop serving
// the tunnel. Returns false (resp.Body left open) when nothing is blocked.
func inspectFileBlocked(br blockResponder, req *http.Request, resp *http.Response, match *PolicyMatch, hostOnly, clientIP string) bool {
	// 1. Global file extension blocklist — inner request URL.
	if ext := fileBlocker.CheckPath(req.URL.Path); ext != "" {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(clientIP, "FILE_BLOCKED", ext, "", hostOnly, req.URL.Path, match)
		resp.Body.Close()
		emitFileBlock(br, hostOnly, req.URL.Path, ext, "global ext")
		return true
	}
	// 2. Per-rule file profile — inner request URL against the profile on the
	//    matched policy rule.
	if match != nil && match.Rule != nil && match.Rule.FileProfileBlocked(req.URL.Path) {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(clientIP, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, hostOnly, req.URL.Path, match)
		resp.Body.Close()
		emitFileBlock(br, hostOnly, req.URL.Path, string(match.Rule.FileProfile), "policy profile")
		return true
	}
	// 3. Content-Disposition header — generic URL but declared filename.
	if inspectCDBlocked(br, req, resp, match, hostOnly, clientIP) {
		return true
	}
	// 4. Content-Type MIME — renamed executables where the server still reports
	//    the true MIME type.
	if ext := fileBlocker.CheckContentType(resp.Header.Get("Content-Type")); ext != "" {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(clientIP, "FILE_BLOCKED", ext, "", hostOnly, req.URL.Path, match)
		resp.Body.Close()
		emitFileBlock(br, hostOnly, req.URL.Path, ext, "content-type")
		return true
	}
	return false
}

// emitFileBlock logs the FILE_BLOCKED tunnel line and emits the 403 through the
// protocol-neutral responder (the same bytes fileblock.BlockConn wrote, minus the
// H1 force-close — the H1 loop owns teardown, and an H2 per-stream block must not
// close the shared conn). This is the single file-block choke point for both
// protocols (invariant C5).
func emitFileBlock(br blockResponder, hostOnly, urlPath, ext, source string) {
	fileblock.LogBlock(hostOnly, urlPath, ext, source)
	br.blockBeforeResponse("text/plain; charset=utf-8", fileblock.BlockMessage(ext, source))
}

// inspectCDBlocked is check 3 of inspectFileBlocked, factored out to keep the
// nesting flat: it blocks on a Content-Disposition filename whose extension is
// on the global blocklist, or whose filename matches the matched rule's file
// profile (catches SourceForge-style /files/latest/download URLs). Returns true
// if it blocked (resp.Body closed, block page written).
func inspectCDBlocked(br blockResponder, req *http.Request, resp *http.Response, match *PolicyMatch, hostOnly, clientIP string) bool {
	cd := resp.Header.Get("Content-Disposition")
	if cd == "" {
		return false
	}
	if ext := fileBlocker.CheckContentDisposition(cd); ext != "" {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(clientIP, "FILE_BLOCKED", ext, "", hostOnly, req.URL.Path, match)
		resp.Body.Close()
		emitFileBlock(br, hostOnly, req.URL.Path, ext, "content-disposition")
		return true
	}
	if match == nil || match.Rule == nil || !match.Rule.FileFiltering || match.Rule.FileProfile == "" {
		return false
	}
	fn := fileblock.ExtractCDFilename(cd)
	if fn == "" || !match.Rule.FileProfileBlocked(fn) {
		return false
	}
	atomic.AddInt64(&statFileBlocked, 1)
	atomic.AddInt64(&statBlocked, 1)
	recordInspectBlock(clientIP, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, hostOnly, req.URL.Path, match)
	resp.Body.Close()
	emitFileBlock(br, hostOnly, fn, string(match.Rule.FileProfile), "policy profile (content-disposition)")
	return true
}

// inspectMagicBlock is the shared block bookkeeping for the two magic-byte
// detections in scanInspectBody (blocked archive / polyglot): closes the
// original body, bumps the file-block counters, records the block, and writes
// the block page. status is the request-log status ("FILE_BLOCKED"/
// "POLYGLOT_BLOCKED"), detail the matched type/reason, source the BlockConn
// label ("magic bytes"/"polyglot").
func inspectMagicBlock(br blockResponder, origBody io.ReadCloser, match *PolicyMatch, status, detail, source, hostOnly, clientIP, path string) {
	origBody.Close()
	atomic.AddInt64(&statFileBlocked, 1)
	atomic.AddInt64(&statBlocked, 1)
	recordInspectBlock(clientIP, status, detail, "", hostOnly, path, match)
	emitFileBlock(br, hostOnly, path, detail, source)
}

// scanInspectBody buffers and scans a decrypted tunnel response body: magic-byte
// archive/polyglot detection, then CDR (content disarm), then either the remote
// scan service or local DPI + ClamAV/YARA. It returns true if the caller must
// stop serving the tunnel — either because the content was blocked (block page
// already written, origBody closed) or the body could not be read. On a clean
// scan it reassembles resp.Body (buffered prefix + unread remainder) and returns
// false. When buffering does not apply (host excluded or a content type that
// needs no buffering) it returns false without touching the body.
func scanInspectBody(r, req *http.Request, resp *http.Response, br blockResponder, match *PolicyMatch, id ProxyIdentity, hostOnly, clientIP string) bool {
	ct := resp.Header.Get("Content-Type")
	// Tier 3.3/3.4: admin-managed host allowlists short-circuit buffering.
	if globalScanExclusions.IsHostExcluded(hostOnly) || !bodyNeedsBuffering(ct) {
		return false
	}

	origBody := resp.Body
	body, readErr := io.ReadAll(io.LimitReader(origBody, maxScanBufferBytes()))
	if readErr != nil {
		origBody.Close()
		logger.Printf("SSL_INSPECT: body read error for %q: %v", sanitizeLog(hostOnly), readErr)
		return true
	}
	// 1.1 fix: decompress gzip/deflate bodies before scanning so ClamAV/YARA
	// signatures match the actual content.
	ce := resp.Header.Get("Content-Encoding")
	scanBody := decompressForScan(body, ce)

	// File blocking: magic byte detection — block archives even if the
	// URL/Content-Disposition doesn't reveal the format.
	if archType := IsBlockedArchive(scanBody); archType != "" {
		inspectMagicBlock(br, origBody, match, "FILE_BLOCKED", "magic:"+archType, "magic bytes", hostOnly, clientIP, req.URL.Path)
		return true
	}
	// File blocking: polyglot detection — block files whose Content-Type
	// doesn't match their actual magic bytes.
	if reason := CheckMagicVsContentType(scanBody, ct); reason != "" {
		inspectMagicBlock(br, origBody, match, "POLYGLOT_BLOCKED", reason, "polyglot", hostOnly, clientIP, req.URL.Path)
		return true
	}

	// ── CDR (Sluice content disarm & reconstruction) ──
	// Runs BEFORE ClamAV/YARA so downstream scanners see the sanitized bytes
	// if CDR stripped active content. No-op (single atomic load) when disabled.
	cdrDecision := runCDRStage(r, req, body, scanBody, ct, ce, br, hostOnly, clientIP, id)
	if cdrDecision.blocked {
		origBody.Close()
		return true
	}
	body = cdrDecision.body
	scanBody = cdrDecision.scanBody

	// Read the remote-scanner toggle ONCE so the DPI gate and the body-scan
	// branch below can't observe different values if an admin flips it
	// mid-request (preserves the original's single-read semantics).
	remoteScan := globalRemoteScanner.Enabled()

	// Local-only: DPI regex scan (text content only) before the body scan.
	// Tier 3.4: respect per-host DPI bypass list. The remote scan service
	// folds DPI into its single call, so this only runs on the local path.
	if !remoteScan && !dpiScanner.IsBypassHost(hostOnly) && dpiScanner.Enabled() && isTextContentType(ct) {
		if pattern, matched := safeDPIScan(scanBody); matched {
			origBody.Close()
			recordInspectBlock(clientIP, "DPI_BLOCKED", "", pattern, hostOnly, req.URL.Path, match)
			dpiBlock(br, hostOnly, pattern)
			return true
		}
	}

	// Body scan: remote (ClamAV + YARA + DPI in one call) when the remote scan
	// service is active, otherwise local ClamAV + YARA. Both surface the same
	// *SecurityScanResult and are handled identically.
	var scanResult *SecurityScanResult
	if remoteScan {
		scanResult = safeScanBodyWithCT(scanBody, ct)
	} else {
		scanResult = safeScanBody(scanBody)
	}
	if scanResult != nil {
		if scanResult.Source == "timeout" {
			go fireAlert("scan_timeout", AlertPayload{Actor: clientIP, Host: hostOnly, Detail: scanResult.Reason, Source: "scan_timeout"})
		}
		origBody.Close()
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(clientIP, "SCAN_BLOCKED", scanResult.Source, scanResult.Reason, hostOnly, req.URL.Path, match)
		scanBlockConn(br, hostOnly, scanResult.Reason, scanResult.Source)
		return true
	}

	// No match: reassemble the body (buffered prefix + remaining bytes).
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), origBody))
	return false
}

func removeHopHeaders(h http.Header) {
	// RFC 7230 §6.1: the Connection header itself lists additional hop-by-hop
	// headers that intermediaries MUST remove before forwarding.
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

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
