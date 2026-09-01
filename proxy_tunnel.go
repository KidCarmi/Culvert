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

	"github.com/KidCarmi/Culvert/internal/decryptobs"
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
			fireDNSFailureAlert(host, err)
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
	// CHAOS-57: a WebSocket is a hijacked conn, so net/http's Shutdown stops
	// tracking it — before this, SIGTERM severed live WS sessions with zero grace
	// while a CONNECT tunnel beside them got 15 s, and the per-connection byte
	// accounting below never ran.
	defer registerDrainableTunnel(tunnelClassWebSocket, clientConn, destConn)()
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
	defer func() {
		if v := recover(); v != nil {
			// Detached relay goroutine: no request-plane recover reaches here.
			// Close BOTH conns so the peer relay (blocked in a deadline-less copy)
			// unblocks immediately instead of leaking until the ~1h idle timeout.
			recordCrash("tunnel-relay", "", v)
			_ = dst.Close()
			if srcConn != nil {
				_ = srcConn.Close()
			}
		}
		done <- struct{}{} // SOLE sender — the parent's <-done always completes (buffered chan)
	}()
	*count += idleCopyCounted(dst, src, srcConn, shared)
	if tc, ok := dst.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite() //nolint:errcheck // best-effort EOF signal; peer may already be gone
	}
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
func handleTunnel(w http.ResponseWriter, r *http.Request, dec sslResolution, match *PolicyMatch, id ProxyIdentity) {
	if dec.Action == SSLInspect && certMgr.Ready() {
		// CHAOS-28 / CA-1: a Root CA that is installed but outside its own
		// validity window can still SIGN — nothing in x509.CreateCertificate
		// checks the parent's NotBefore/NotAfter — so the pre-guard behavior was
		// to hand every client a well-formed leaf chained to an expired issuer
		// and let it fail path validation. Fail CLOSED here instead, before the
		// 200, so the client gets a proxy error it can act on rather than an
		// opaque per-site certificate warning, and the appliance emits one
		// countable event instead of N invisible ones.
		//
		// This deliberately does NOT fall through to the bypass branch below,
		// and deliberately does NOT honour a decryption profile's fail-open
		// setting. Both would convert an appliance-wide fault into fleet-wide
		// UNINSPECTED egress: DLP, AV, YARA, CDR and DPI all off, silently, for
		// every host at once. The profile fail-open contract is scoped to
		// PER-ORIGIN incompatibility and is gated behind a confirm-count for
		// exactly that reason; an expired CA is host-independent, so treating it
		// as a decryption exclusion would poison the whole cache from one fault.
		if err := certMgr.Usable(); err != nil {
			failClosedUnusableCA(w, r, dec, match, id, err)
			return
		}
		noteCAUsable()
		handleTunnelInspect(w, r, dec, match, id)
		return
	}
	if dec.Action == SSLInspect {
		// Policy selected inspection but no Root CA is loaded at all, so this
		// session proceeds as an unscanned tunnel: DLP, AV, YARA, CDR and DPI are
		// all off for it. That is the OPPOSITE posture to the expired-CA branch
		// above, and until CHAOS-50 it moved no counter and produced no runtime
		// signal — only a startup log line that has long scrolled away by the time
		// anyone asks how much traffic left uninspected. Counting it does not
		// change the posture (see the review's Residual Risk: the fail-open →
		// fail-closed flip is a customer-visible availability decision and is
		// recorded as an owner decision, not taken here); it makes the window
		// measurable while it is open.
		noteCAInspectUnavailableBypass()
	}
	// Bypass path — attach the ADR-0011 decryption outcome for the close record.
	handleTunnelBypass(w, r, match, id, "", bypassOutcome(dec, r.Host))
}

// failClosedUnusableCA rejects a CONNECT that policy selected for inspection
// while the Root CA cannot produce a leaf any client would accept (CHAOS-28).
//
// It runs BEFORE the 200, so it uses the same 502-before-200 semantics as the
// unreachable-origin branch in handleTunnelInspect: the client sees a proxy
// error rather than a hijacked connection that then fails its TLS handshake for
// reasons it cannot attribute to the proxy. The response body carries no detail
// — the cause names the appliance's own certificate state and belongs in the
// log, the alert and the admin surfaces, not in a response any client on the
// network can read.
func failClosedUnusableCA(w http.ResponseWriter, r *http.Request, dec sslResolution, match *PolicyMatch, id ProxyIdentity, err error) {
	hostOnly, _, splitErr := net.SplitHostPort(r.Host)
	if splitErr != nil {
		hostOnly = r.Host
	}
	// Counted, rate-limited log + alert. The per-connection rate is bounded by
	// the sink's gate, not by this call site: an expired CA fails every request.
	noteCAConnectBlocked(err.Error())
	recordDecryptFailureEntry(caUnusableOutcome(hostOnly, dec, match), id, hostOnly, match, decRedactHosts())
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

// bypassOutcome builds the ADR-0011 DecryptionOutcome for a CONNECT that was BYPASSED
// (not inspected). A bypass does no MITM handshake, so the TLS/cert fields stay at their
// sentinels — that is the honest value, not missing data. Classification: a learned
// exclusion is bypass_learned/autoexclude_cache; an inspect rule that could not run
// because the CA was not ready is inspect_unavailable (a misconfiguration, still
// bypassed — surfaced distinctly via the source); anything else is a manual/policy bypass.
func bypassOutcome(dec sslResolution, host string) *DecryptionOutcome {
	source := dec.Source
	outcome := decryptobs.OutcomeBypassManual
	switch {
	case dec.Action == SSLInspect: // inspect intended but the CA was not ready
		source = decryptobs.DecisionInspectUnavailable
	case dec.Source == decryptobs.DecisionAutoexcludeCache:
		outcome = decryptobs.OutcomeBypassLearned
	}
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	hit := dec.Source == decryptobs.DecisionAutoexcludeCache
	exclScope := ""
	if hit {
		exclScope = dec.ScopeID // the scope of the exclusion that bypassed — only on a hit
	}
	return &DecryptionOutcome{
		Outcome:        outcome,
		DecisionSource: source,
		Host:           h,
		ExclReason:     dec.ExclReason, // set only on a hit
		ExclScope:      exclScope,      // set only on a hit
		ProfileID:      dec.ScopeID,    // the session's fail-open profile scope, if any (hit or consulted-miss)
		CacheConsulted: dec.Consulted,  // the fail-open read path ran (hit OR miss)
		CacheHit:       hit,
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
// handleTunnelBypass relays a CONNECT as a raw bypass tunnel (no inspection). It
// re-runs its own SSRF guard (isPrivateHost + the ssrfControl connect-time gate)
// so a rescue caller cannot use it to reach an internal host. bypassReason, when
// non-empty, is written to the TUNNEL_CLOSED feed entry's ActionTaken field
// (e.g. an ADR-0009 client-cert rescue); "" for an ordinary policy bypass. dec is the
// ADR-0011 decryption outcome for the close record (nil ⇒ no dec block).
func handleTunnelBypass(w http.ResponseWriter, r *http.Request, match *PolicyMatch, id ProxyIdentity, bypassReason string, dec *DecryptionOutcome) {
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
			fireDNSFailureAlert(r.Host, err)
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

	// CHAOS-57: register with the shutdown drain. This OWNS the activeConns
	// accounting for the tunnel (do not also call recordActiveConn) and hands the
	// drain both legs so its deadline backstop can end the tunnel deterministically
	// instead of leaving it to the container SIGKILL.
	defer registerDrainableTunnel(tunnelClassConnectBypass, clientConn, destConn)()

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

	// Per-connection accounting entry (bytes + lifetime). bypassReason (when set)
	// tags the feed entry so a rescue is queryable, not just an unattributed bypass.
	recordTunnelCloseGatedDec(match, id, "CONNECT", r.Host, toDest, toClient, start, "bypass", bypassReason, dec, decRedactHosts())
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
// dec carries the resolved SSL decision: dec.SkipVerify disables upstream
// certificate validation for specific policy rules (e.g. internal sites with
// self-signed certs); dec.Source/ScopeID/Consulted feed the ADR-0011 decryption
// observability block attached to the per-request inspect log entries.
//
// pre-existing complexity predating the CDR integration (was gocognit 128 before CDR;
// dropped to 112 after Phase 2b extracted runCDRStage out of here).  Further splitting
// would change the keep-alive loop semantics and is out of scope for CDR work —
// tracked as a day-2 refactor item in roadmap/roadmap-day2.md.
//
//nolint:gocognit,gocyclo,cyclop,funlen // handleTunnelInspect is the SSL-inspection orchestrator —
func handleTunnelInspect(w http.ResponseWriter, r *http.Request, dec sslResolution, match *PolicyMatch, id ProxyIdentity) {
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
			fireDNSFailureAlert(targetHost, err)
		}
		// ADR-0011: an inspect rule whose ORIGIN is unreachable is a FAILED
		// decryption attempt (fail_stage=tcp_connect) — count it toward coverage +
		// the failure taxonomy and write the drill-down row, instead of vanishing.
		// This site is BEFORE the native/strip split, so it covers both paths. NO
		// maybeFailOpen* — a dial failure is a transport error, not a learn signal.
		//
		// Record ONLY a genuine unreachable-origin failure. A client abort mid-dial
		// (the request context ended → r.Context().Err() != nil) and an ssrfControl
		// security rejection (DNS-rebinding/private-IP block, errSSRFBlocked) are NOT
		// decryption attempts against the upstream, so they must not pollute the
		// Decryption Health coverage/failure metrics (Codex #846). The dialer's own
		// 10s Timeout does not cancel r.Context(), so a real dial timeout still records.
		if shouldRecordConnectFailure(r.Context().Err(), err) {
			recordDecryptFailureEntry(upstreamConnectFailureOutcome(err, hostOnly, dec, match), id, hostOnly, match, decRedactHosts())
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Native-ALPN dispatch (opt-in per rule; StripALPN==false). The default and
	// every pre-feature rule resolve to strip=true and fall through to the
	// byte-for-byte-unchanged HTTP/1.1 path below. The native path needs the
	// client's ALPN offer — which only arrives after the 200 — so it reorders
	// (200 → peek client ALPN → upstream handshake → constrained client handshake
	// → dispatch), which is why it is a separate function rather than a flag in
	// this flow: reordering here would change the strip path's 502-before-200
	// semantics. It takes ownership of the freshly-dialled rawUpstream.
	if !resolveStripALPN(match) {
		handleInspectNativeALPN(w, r, rawUpstream, targetHost, hostOnly, dec, match, id)
		return
	}

	// 2. Perform TLS handshake with the upstream.
	// upstreamInspectTLSConfig verifies against the shared system root pool by
	// default (fail-secure); tlsSkipVerify (admin-configured per-rule) skips
	// cert validation for internal/self-signed hosts and is logged as a warning
	// so it is auditable.
	upstreamTLSCfg := upstreamInspectTLSConfigForMatch(hostOnly, dec.SkipVerify, match)
	// ADR-0009: structurally detect an origin CertificateRequest (a Go client's
	// HandshakeContext never surfaces "certificate required" — TLS 1.3 returns nil,
	// TLS 1.2 a generic handshake_failure — so the error string is not reliable). The
	// callback is a SIGNAL PRODUCER ONLY: it records that the origin asked for a
	// client cert and presents NONE; it makes no policy decision and never bypasses.
	// It is attached ONLY for fail-open rules, so fail-close and feature-off
	// inspection is byte-identical (the callback never runs).
	var originRequestedClientCert atomic.Bool
	failOpen := resolveFailOpen(match)
	if failOpen {
		upstreamTLSCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			originRequestedClientCert.Store(true)
			return &tls.Certificate{}, nil // never provide or synthesize a client certificate
		}
	}
	upstreamTLS := tls.Client(rawUpstream, upstreamTLSCfg)
	herr := upstreamTLS.HandshakeContext(r.Context())

	// ADR-0009 client-cert live-rescue (strip path only). The DECISION lives here,
	// gated by clientCertRescueDecision. It fires ONLY when the origin asked for a
	// client cert AND the handshake actually FAILED (herr != nil) under a fail-open
	// rule and it was not a cert-verify failure. A SUCCESSFUL handshake is left to
	// inspection — that is the required-vs-optional-mTLS distinction: an origin that
	// merely REQUESTS a client cert (tls.RequestClientCert / VerifyClientCertIfGiven)
	// completes the handshake and is perfectly inspectable, so it must not be
	// bypassed. The 200 has not been sent yet, so a failed-handshake rescue can
	// re-dial as a bypass. recordAutoExclude LEARNS (confirm-count → next-session
	// self-heal); recordAutoExcludeRescue fires audit+alert+metric independent of
	// promotion; handleTunnelBypass re-dials through its own isPrivateHost +
	// ssrfControl guard and tags the feed entry.
	if clientCertRescueDecision(failOpen, originRequestedClientCert.Load(), herr) {
		upstreamTLS.Close() //nolint:errcheck // best-effort cleanup before the bypass re-dial
		recordAutoExclude(match, hostOnly, autoExReasonClientCert, id)
		recordAutoExcludeRescue(match, hostOnly, autoExReasonClientCert, id)
		logger.Printf("SSL_AUTOEXCLUDE_RESCUE %q: origin requires a client certificate (handshake failed) — failing open to bypass", sanitizeLog(targetHost))
		rescueDec := &DecryptionOutcome{
			Outcome:        decryptobs.OutcomeRescued,
			DecisionSource: decryptobs.DecisionAutoexcludeRescue,
			Host:           hostOnly,
			// The rescue is gated on a fail-open profile, so dec.ScopeID is the
			// non-empty profile identity recordAutoExclude/recordAutoExcludeRescue
			// keyed the cache/audit/alert entry on. Project it like every sibling
			// builder (bypass/failure/withLearn) so the rescued row is attributable
			// to its profile scope — otherwise a per-scope blast-radius/SIEM query
			// misses every rescued session (review finding: scope-attribution gap).
			ProfileID:      dec.ScopeID,
			ExclReason:     autoExReasonClientCert,
			ExclScope:      dec.ScopeID,
			FailStage:      decryptobs.FailStageUpstreamHandshake,
			FailCategory:   decryptobs.FailCategoryClientCertRequired,
			Rescued:        true,
			CacheConsulted: true,
			CacheLearned:   true, // recordAutoExclude above recorded this session's evidence
		}
		handleTunnelBypass(w, r, match, id, feedReasonClientCertRescue, rescueDec)
		return
	}

	if herr != nil {
		upstreamTLS.Close()              //nolint:errcheck // best-effort cleanup; closes both TLS and underlying TCP conn
		recordProfileMintlsReject(match) // attribute the drop if a profile set a min-TLS floor
		// Non-client-cert learn paths: unsupported-params LEARNS (learn-only — the
		// next session self-heals) and returns false; cert-verify and generic/origin-
		// emitted alerts never learn. No rescue here (client-cert is handled above,
		// structurally, before this branch).
		learned, _ := maybeFailOpenOrigin(hostOnly, match, id, herr)
		recordDecryptFailureEntry(withLearn(originInspectFailureOutcome(herr, hostOnly, dec, match), learned, dec.ScopeID), id, hostOnly, match, decRedactHosts()) // ADR-0011 failure taxonomy + feed row (learner fields when this session fed the cache)
		logger.Printf("upstream TLS handshake error %q: %v%s", sanitizeLog(targetHost), herr, mintlsHint(match))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	// Strip path offers no upstream ALPN → the origin leg is HTTP/1.1 (the
	// downgrade); count it so the H2-vs-H1 success-delta metric is complete.
	recordInspectUpstreamALPN("http/1.1")

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
	// FD-leak guard: a panic between the hijack and relay spawn would otherwise
	// leak the hijacked conn. Idempotent — the relay closes it on the happy path
	// (this function blocks on relay completion), so this is a harmless 2nd close.
	defer rawClient.Close() //nolint:errcheck // idempotent best-effort cleanup, see comment above

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
			sanitizeLog(hostOnly), firstByte[0], sanitizeLog(proto))
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
		// CHAOS-57: this relay was invisible to the shutdown drain — the strip
		// path's recordActiveConn sits after the client TLS handshake, which this
		// branch returns before, so an SSH-over-CONNECT session on an inspect rule
		// was severed with zero grace and lost its TUNNEL_CLOSED accounting.
		releaseDrain := registerDrainableTunnel(tunnelClassInspectFallback, rawClient, upstreamTLS)
		defer releaseDrain()
		start := time.Now()
		var toUpstream, toClient int64
		shared := newTunnelActivityStamp()
		done := make(chan struct{}, 2)
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
		go relay(upstreamTLS, peekBuf, rawClient, &toUpstream)   // client → upstream
		go relay(rawClient, upstreamTLS, upstreamTLS, &toClient) // upstream → client
		<-done
		rawClient.Close()   //nolint:errcheck // force the peer relay to unblock
		upstreamTLS.Close() //nolint:errcheck // force the peer relay to unblock
		<-done
		recordTunnelCloseGatedDec(match, id, "CONNECT", hostOnly, toUpstream, toClient, start, "inspect", "", nonTLSFallbackOutcome(hostOnly), decRedactHosts())
		return
	}

	// 4. Perform TLS handshake with the client using a dynamically-signed cert.
	// Wrap rawClient with the peek buffer so the already-peeked byte isn't lost.
	// Uses the shared mitmClientTLSConfig (perf F2) so session-ticket keys are
	// stable across connections and clients can resume.
	clientTLS := tls.Server(readerConn{Conn: rawClient, r: peekBuf}, mitmClientTLSConfig)
	if err := clientTLS.HandshakeContext(r.Context()); err != nil {
		clientTLS.Close()                                                                                                                                         //nolint:errcheck // best-effort cleanup on handshake failure
		upstreamTLS.Close()                                                                                                                                       //nolint:errcheck // best-effort cleanup on handshake failure
		learned := maybeFailOpenClient(hostOnly, match, id, err)                                                                                                  // learn a pinning rejection (learn-only; next session self-heals)
		recordDecryptFailureEntry(withLearn(clientInspectFailureOutcome(err, hostOnly, dec, match), learned, dec.ScopeID), id, hostOnly, match, decRedactHosts()) // ADR-0011 failure taxonomy + feed row (learner fields when this session fed the cache)
		logger.Printf("SSL_INSPECT client TLS handshake error for %q: %v", sanitizeLog(hostOnly), err)
		return
	}

	logger.Printf("SSLInspect: tunnel %q", sanitizeLog(targetHost))
	// CHAOS-57: this tunnel was already counted, but held by no registry — so the
	// drain waited on it and had no way to end the wait. Registering both legs gives
	// it the deadline backstop the inspected-H2 path has had since PR3d.
	defer registerDrainableTunnel(tunnelClassConnectInspect, clientTLS, upstreamTLS)()

	// ADR-0011: build the inspected decryption-observability outcome ONCE from the
	// completed origin TLS state, count the session (this is the inspect-success
	// terminal — it logs per-inner-request and never reaches the close seam that counts
	// the other paths), then project the block for reuse across every inner-request log
	// entry. The entries are opt-in per rule (LogFullURI), so the projection is cheap and
	// off the latency-critical handshake path. redact=false mirrors the bypass close path
	// — the §4 host/SNI redaction config surface is a later slice.
	// cert_verify is CAPTURED from the config the handshake ACTUALLY used
	// (upstreamTLSCfg.InsecureSkipVerify), not re-resolved against the live
	// profile store — the store may have mutated during the handshake window (CWE-367).
	inspected := inspectedOutcome(dec, hostOnly, upstreamTLS.ConnectionState(), match, upstreamTLSCfg.InsecureSkipVerify)
	recordDecryptSession(inspected)
	decBlock := inspected.toBlock(decRedactHosts())

	// 5. Proxy the decrypted HTTP/1.x stream request-by-request (DPI/scan/CDR/
	// file-block via the shared inspection pipeline). Extracted so the native-ALPN
	// path reuses the exact same loop when a tunnel negotiates HTTP/1.1.
	runH1InspectLoop(r, clientTLS, upstreamTLS, hostOnly, match, id, decBlock)
}

// runH1InspectLoop drives the HTTP/1.1 keep-alive inspection loop over a decrypted
// tunnel: it parses each client request, runs the protocol-neutral inspection
// pipeline (runInspectExchange) with H1 transport hooks, and tears the tunnel down
// on block/error/close-after. WebSocket 101 upgrades fall back to idle-bounded raw
// relay (H1-only; HTTP/2 does not advertise Extended CONNECT). This is the exact
// body that was inline in handleTunnelInspect; the native-ALPN dispatcher reuses it
// for tunnels that negotiate HTTP/1.1 on either leg, so there is ONE enforcement
// path for both protocols. Closes both conns on return.
//
// decBlock is the pre-built ADR-0011 inspected decryption block (built once per tunnel
// from the completed TLS state); it rides the opt-in per-request LogFullURI entries. It
// may be nil (the native-ALPN caller passes nil until that sub-path builds its own block
// — a documented follow-up), in which case the entries carry no dec block.
func runH1InspectLoop(r *http.Request, clientTLS, upstreamTLS *tls.Conn, hostOnly string, match *PolicyMatch, id ProxyIdentity, decBlock *DecryptionBlock) {
	clientBR := bufio.NewReaderSize(clientTLS, 32*1024)
	upstreamBR := bufio.NewReaderSize(upstreamTLS, 32*1024)

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

relayLoop:
	for {
		// Slowloris protection: enforce a read deadline so a slow client cannot
		// hold the connection open indefinitely by trickling bytes.
		clientTLS.SetReadDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck // best-effort slowloris deadline
		// Read next HTTP/1.x request from the (decrypted) client stream.
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			break
		}
		// Wrap req.Body with a stall-detecting reader that re-arms the
		// client-side read deadline on every Body.Read, so a pause longer than
		// sslInspectBodyStallTimeout trips the next Read — long legitimate
		// uploads still complete as long as bytes keep flowing. This is an
		// H1-transport concern (per-conn deadline); the H2 path replaces it with
		// per-stream context cancellation.
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

		ex := &inspectExchange{
			outer:     r,
			req:       req,
			match:     match,
			id:        id,
			host:      hostOnly,
			clientIP:  clientIP,
			dec:       decBlock, // ADR-0011: rides block-log rows too
			responder: h1BlockResponder{w: clientTLS},
			// H1 upstream leg: serialize the request and parse the response over
			// the persistent TLS conn pair. req.Body is closed after the write
			// attempt (success or failure), matching the original semantics.
			roundTrip: func(rq *http.Request) (*http.Response, error) {
				werr := rq.Write(upstreamTLS)
				rq.Body.Close() //nolint:errcheck // best-effort; body drained by Write
				if werr != nil {
					return nil, werr
				}
				return http.ReadResponse(upstreamBR, rq)
			},
			// H1 client leg: serialize the clean response back over the forged-leaf
			// TLS conn (resp.Write forwards any trailers natively).
			deliver: func(rp *http.Response) error { return rp.Write(clientTLS) },
		}

		out := runInspectExchange(ex)
		switch out.kind {
		case exRoundTripError, exDeliverError, exBlocked:
			// Bodies are already closed by the round-trip hook / deliver path /
			// the inspect functions. Tear the tunnel down.
			break relayLoop
		case exUpgrade:
			// WebSocket upgrade: the protocol switches after the 101 handshake.
			// Write the raw 101 to the client and fall back to idle-bounded raw
			// relay (H1-only; H2 does not advertise Extended CONNECT).
			resp := out.resp
			resp.Write(clientTLS) //nolint:errcheck // best-effort write of buffered response to client
			resp.Body.Close()     //nolint:errcheck // best-effort
			shared := newTunnelActivityStamp()
			done := make(chan struct{}, 2)
			rawRelay := func(dst, src net.Conn) {
				defer func() {
					if v := recover(); v != nil {
						recordCrash("tunnel-relay", "", v)
						_ = dst.Close()
						_ = src.Close()
					}
					done <- struct{}{} // sole sender
				}()
				idleCopyCounted(dst, src, src, shared)
			}
			go rawRelay(upstreamTLS, clientTLS)
			go rawRelay(clientTLS, upstreamTLS)
			<-done
			clientTLS.Close()   //nolint:errcheck // best-effort; unblocks the peer relay goroutine
			upstreamTLS.Close() //nolint:errcheck // best-effort; unblocks the peer relay goroutine
			<-done
			return
		case exDelivered:
			logInspectedInnerRequest(clientIP, req, hostOnly, match, id, decBlock)
			if out.closeAfter {
				break relayLoop
			}
		}
	}
	clientTLS.Close()   //nolint:errcheck // best-effort cleanup at relay end
	upstreamTLS.Close() //nolint:errcheck // best-effort cleanup at relay end
}

// logInspectedInnerRequest emits the per-rule "log full URL" entry for one delivered
// inner request of an inspected tunnel — carrying the decrypted host+path (no query) and
// the ADR-0011 inspected decryption block. Opt-in via the matched rule's LogFullURI flag
// (off by default) and gated on the rule's log-traffic flag. Log-only: the enclosing
// CONNECT was already counted by the allow path, so this per-URL entry must not
// re-increment request stats. Extracted from runH1InspectLoop to keep its keep-alive loop
// under the cyclop threshold.
func logInspectedInnerRequest(clientIP string, req *http.Request, hostOnly string, match *PolicyMatch, id ProxyIdentity, decBlock *DecryptionBlock) {
	if match == nil || match.Rule == nil || !match.Rule.LogFullURI || !ruleLogsTraffic(match.Rule) {
		return
	}
	recordRequestLogOnly(clientIP, req.Method, hostOnly, "OK", match.Rule.Name, string(ActionAllow), id.Identity, "inspect", policyLogURI(hostOnly, req.URL.Path), AuthLogFields{RuleID: match.Rule.ID, Dec: decBlock, AuthSource: id.AuthSource})
}

// exchangeOutcomeKind is the result of one protocol-neutral inspection exchange.
type exchangeOutcomeKind int

const (
	exDelivered      exchangeOutcomeKind = iota // clean response delivered
	exBlocked                                   // policy block emitted (bodies closed by the inspect fns)
	exUpgrade                                   // upstream returned 101; caller must raw-relay resp
	exRoundTripError                            // upstream round-trip failed (req.Body closed)
	exDeliverError                              // client delivery failed (resp.Body closed)
)

// scanBodyOutcome is the result of scanInspectBody. It distinguishes a policy
// block (block page already written) from a scan-buffer read failure (nothing
// written — the caller must fail the exchange, never deliver a clean success),
// so the H1 and H2 transports both fail closed on a truncated/aborted body.
type scanBodyOutcome int

const (
	scanClean     scanBodyOutcome = iota // nothing matched; body reassembled, deliver it
	scanBlocked                          // content blocked; block page written, stop serving
	scanReadError                        // body read failed; nothing written, fail the exchange
)

// exchangeOutcome is returned by runInspectExchange. resp is set only for
// exUpgrade (the 101 response the transport driver must raw-relay). closeAfter is
// meaningful only for exDelivered (HTTP/1.x Connection: close semantics).
type exchangeOutcome struct {
	kind       exchangeOutcomeKind
	resp       *http.Response
	closeAfter bool
}

// inspectExchange is the protocol-neutral inspection contract (invariant C5): the
// SAME pipeline serves the HTTP/1.1 keep-alive loop and the HTTP/2 per-stream
// handler. The transport legs are function-typed hooks (roundTrip upstream,
// deliver to client) so no inspection code names a *tls.Conn or branches on
// protocol. outer is the enclosing CONNECT request (CDR context); req is the
// parsed inner request (with its body already wrapped for stall detection by the
// transport driver).
type inspectExchange struct {
	outer     *http.Request
	req       *http.Request
	match     *PolicyMatch
	id        ProxyIdentity
	host      string
	clientIP  string
	responder blockResponder
	roundTrip func(*http.Request) (*http.Response, error)
	deliver   func(*http.Response) error
	// dec is the ADR-0011 inspected decryption block for this tunnel (built once per
	// session). It rides the BLOCK-log rows too — a blocked inspected session is the
	// highest-value dec.* drill-down target — not just the delivered LogFullURI entry.
	dec *DecryptionBlock
}

// runInspectExchange applies the protocol-neutral inspection pipeline to one
// request/response exchange: scrub client-spoofable headers → strip hop-by-hop →
// upstream round-trip → file-block → (surface 101) → body scan (magic/polyglot/
// CDR/DPI/ClamAV/YARA) → strip hop-by-hop → deliver. It performs NO
// protocol-specific I/O; both transport legs go through the hooks. Block
// enforcement, SSRF-guarded upstream access, scanning, and CDR are identical to
// the H1 path because this is the exact code the H1 loop used to run inline.
func runInspectExchange(ex *inspectExchange) exchangeOutcome {
	// Scrub client-spoofable forwarded/identity headers on the DECRYPTED inner
	// request (prevents X-User-Identity spoofing / private XFF leakage), then
	// strip hop-by-hop headers before forwarding upstream.
	scrubForwardedHeaders(ex.req)
	removeHopHeaders(ex.req.Header)

	resp, err := ex.roundTrip(ex.req)
	if err != nil {
		return exchangeOutcome{kind: exRoundTripError}
	}

	// File blocking (inner request) runs before any response byte reaches the
	// client, so a clean 403 is safe to emit.
	if inspectFileBlocked(ex.responder, ex.req, resp, ex.match, ex.host, ex.id, ex.dec) {
		return exchangeOutcome{kind: exBlocked}
	}

	// WebSocket upgrade: surface it; the transport driver decides how to relay
	// (H1 raw-relays the conn pair; H2 never reaches here — no 101 in HTTP/2).
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return exchangeOutcome{kind: exUpgrade, resp: resp}
	}

	// Unified scan buffer: magic/polyglot + CDR + DPI + ClamAV + YARA. Buffers up
	// to maxScanBufferBytes() before forwarding so any match blocks the response
	// entirely (true prevention).
	switch scanInspectBody(ex.outer, ex.req, resp, ex.responder, ex.match, ex.id, ex.host, ex.dec) {
	case scanBlocked:
		return exchangeOutcome{kind: exBlocked}
	case scanReadError:
		// The scan buffer could not read the full body and NOTHING was written to
		// the client (scanInspectBody already closed the body). Fail the exchange
		// like a delivery error: H1 tears the tunnel down, H2 resets the stream.
		// Must never fall through as a clean success — on H2 that otherwise
		// surfaced as a silent empty 200 (an origin reset mid-buffer became a
		// cacheable success).
		return exchangeOutcome{kind: exDeliverError}
	}

	closeAfter := ex.req.Close || resp.Close
	removeHopHeaders(resp.Header)
	if err := ex.deliver(resp); err != nil {
		resp.Body.Close() //nolint:errcheck // best-effort cleanup on delivery failure
		return exchangeOutcome{kind: exDeliverError}
	}
	resp.Body.Close() //nolint:errcheck // best-effort cleanup after delivery
	return exchangeOutcome{kind: exDelivered, closeAfter: closeAfter}
}

// inspectFileBlocked runs the inner-request file-block checks against a decrypted
// tunnel request/response: (1) global file-extension blocklist on the URL, (2)
// per-rule file profile on the URL, (3) Content-Disposition filename, (4)
// Content-Type MIME. On a match it records the block, closes resp.Body, writes
// the block page to the client, and returns true — the caller must stop serving
// the tunnel. Returns false (resp.Body left open) when nothing is blocked.
func inspectFileBlocked(br blockResponder, req *http.Request, resp *http.Response, match *PolicyMatch, hostOnly string, id ProxyIdentity, dec *DecryptionBlock) bool {
	// 1. Global file extension blocklist — inner request URL.
	if ext := fileBlocker.CheckPath(req.URL.Path); ext != "" {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(id, "FILE_BLOCKED", ext, "", hostOnly, req.URL.Path, match, dec)
		resp.Body.Close()
		emitFileBlock(br, hostOnly, req.URL.Path, ext, "global ext")
		return true
	}
	// 2. Per-rule file profile — inner request URL against the profile on the
	//    matched policy rule.
	if match != nil && match.Rule != nil && match.Rule.FileProfileBlocked(req.URL.Path) {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(id, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, hostOnly, req.URL.Path, match, dec)
		resp.Body.Close()
		emitFileBlock(br, hostOnly, req.URL.Path, string(match.Rule.FileProfile), "policy profile")
		return true
	}
	// 3. Content-Disposition header — generic URL but declared filename.
	if inspectCDBlocked(br, req, resp, match, hostOnly, id, dec) {
		return true
	}
	// 4. Content-Type MIME — renamed executables where the server still reports
	//    the true MIME type.
	if ext := fileBlocker.CheckContentType(resp.Header.Get("Content-Type")); ext != "" {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(id, "FILE_BLOCKED", ext, "", hostOnly, req.URL.Path, match, dec)
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
func inspectCDBlocked(br blockResponder, req *http.Request, resp *http.Response, match *PolicyMatch, hostOnly string, id ProxyIdentity, dec *DecryptionBlock) bool {
	cd := resp.Header.Get("Content-Disposition")
	if cd == "" {
		return false
	}
	if ext := fileBlocker.CheckContentDisposition(cd); ext != "" {
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(id, "FILE_BLOCKED", ext, "", hostOnly, req.URL.Path, match, dec)
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
	recordInspectBlock(id, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, hostOnly, req.URL.Path, match, dec)
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
func inspectMagicBlock(br blockResponder, origBody io.ReadCloser, match *PolicyMatch, status, detail, source, hostOnly string, id ProxyIdentity, path string, dec *DecryptionBlock) {
	origBody.Close()
	atomic.AddInt64(&statFileBlocked, 1)
	atomic.AddInt64(&statBlocked, 1)
	recordInspectBlock(id, status, detail, "", hostOnly, path, match, dec)
	emitFileBlock(br, hostOnly, path, detail, source)
}

// scanInspectBody buffers and scans a decrypted tunnel response body: magic-byte
// archive/polyglot detection, then CDR (content disarm), then either the remote
// scan service or local DPI + ClamAV/YARA. The returned scanBodyOutcome tells the
// caller how to terminate the exchange:
//   - scanClean: nothing matched; resp.Body has been reassembled (buffered prefix
//   - unread remainder) and the caller delivers it. Also returned when buffering
//     does not apply (host excluded or a content type that needs no buffering),
//     leaving the body untouched.
//   - scanBlocked: content was blocked — the block page has already been written
//     via the responder and origBody closed; the caller must stop serving.
//   - scanReadError: the response body could not be fully read (origin RST/GOAWAY/
//     truncation mid-buffer). NOTHING was written to the client, so the caller MUST
//     fail the exchange (H1 tears the tunnel down; H2 resets the stream) — never
//     let this surface as a clean, empty success. Conflating it with scanBlocked
//     produced a silent empty 200 on the H2 path (an on-path origin reset became a
//     cacheable success); keeping it distinct is the fail-closed contract.
func scanInspectBody(r, req *http.Request, resp *http.Response, br blockResponder, match *PolicyMatch, id ProxyIdentity, hostOnly string, dec *DecryptionBlock) scanBodyOutcome {
	ct := resp.Header.Get("Content-Type")
	// Tier 3.3/3.4: admin-managed host allowlists short-circuit buffering.
	if globalScanExclusions.IsHostExcluded(hostOnly) || !bodyNeedsBuffering(ct) {
		return scanClean
	}

	origBody := resp.Body
	// Buffer the scan window (pre-sized from the origin's declaration, hint
	// only; -1 when chunked). This path has no Content-Length pre-check, so
	// before this change an over-limit download was partially scanned and the
	// remainder forwarded with no counter, no log line and no alert — the
	// primary SWG path was the blind one. If the decrypted body runs past the
	// window, rest's deferred signal fires when the first uninspected byte is
	// actually relayed toward the client.
	scanLimit := maxScanBufferBytes()
	body, rest, readErr := readScanPrefix(origBody, scanLimit, resp.ContentLength, func() {
		logScanLimitExceeded(hostOnly, id.ClientIP, scanLimit)
	})
	if readErr != nil {
		origBody.Close()
		logger.Printf("SSL_INSPECT: body read error for %q: %v", sanitizeLog(hostOnly), readErr)
		return scanReadError
	}
	// 1.1 fix: decompress gzip/deflate bodies before scanning so ClamAV/YARA
	// signatures match the actual content.
	ce := resp.Header.Get("Content-Encoding")
	scanBody := decompressForScan(body, ce)

	// File blocking: magic byte detection — block archives even if the
	// URL/Content-Disposition doesn't reveal the format.
	if archType := IsBlockedArchive(scanBody); archType != "" {
		inspectMagicBlock(br, origBody, match, "FILE_BLOCKED", "magic:"+archType, "magic bytes", hostOnly, id, req.URL.Path, dec)
		return scanBlocked
	}
	// File blocking: polyglot detection — block files whose Content-Type
	// doesn't match their actual magic bytes.
	if reason := CheckMagicVsContentType(scanBody, ct); reason != "" {
		inspectMagicBlock(br, origBody, match, "POLYGLOT_BLOCKED", reason, "polyglot", hostOnly, id, req.URL.Path, dec)
		return scanBlocked
	}

	// ── CDR (Sluice content disarm & reconstruction) ──
	// Runs BEFORE ClamAV/YARA so downstream scanners see the sanitized bytes
	// if CDR stripped active content. No-op (single atomic load) when disabled.
	cdrDecision := runCDRStage(r, req, body, scanBody, ct, ce, br, hostOnly, id.ClientIP, id)
	if cdrDecision.blocked {
		origBody.Close()
		return scanBlocked
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
			recordInspectBlock(id, "DPI_BLOCKED", "", pattern, hostOnly, req.URL.Path, match, dec)
			dpiBlock(br, hostOnly, pattern)
			return scanBlocked
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
			go fireAlert("scan_timeout", AlertPayload{Actor: id.ClientIP, Host: hostOnly, Detail: scanResult.Reason, Source: "scan_timeout"})
		}
		origBody.Close()
		atomic.AddInt64(&statBlocked, 1)
		recordInspectBlock(id, "SCAN_BLOCKED", scanResult.Source, scanResult.Reason, hostOnly, req.URL.Path, match, dec)
		scanBlockConn(br, hostOnly, scanResult.Reason, scanResult.Source)
		return scanBlocked
	}

	// No match in the window we could see. If the body runs past that window,
	// rest's deferred signal records the delivery of the first uninspected
	// byte (counter + log + deduped scan_skipped alert) — the same signal the
	// plain-HTTP path emits. Deliberately structural on the block paths above:
	// those never read rest, never deliver the tail, and therefore never
	// signal — "forwarded unscanned" stays true by construction.
	//
	// Reassemble: buffered prefix + the unread remainder.
	resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), rest))
	return scanClean
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
