package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// socks5Server owns the SOCKS5 accept loop. It wraps a pre-bound listener
// and spawns one handleSOCKS5 goroutine per accepted connection. Stop closes
// the listener, which causes Accept to return net.ErrClosed; the serve loop
// treats that as the expected stop signal and returns. P1.5 / S4.SOCKS5.
//
// Out of scope here: in-flight SOCKS5 tunnels are NOT drained on Stop.
// The per-conn 30s deadline set in handleSOCKS5 covers only the
// handshake/negotiation phase — it is cleared before the relay starts, so
// an established tunnel runs until either peer closes (no idle deadline;
// tracked as CHAOS-03). Graceful tunnel drain is tracked separately for
// Phase 2.
type socks5Server struct {
	ln   net.Listener
	done chan struct{}

	// stopping is closed by Stop BEFORE the listener is closed, so the accept
	// loop's backoff sleep is interruptible (CHAOS-54). Without it, a Stop that
	// lands while the loop is sleeping off an accept error would wait out the
	// remaining backoff — up to socks5AcceptBackoffMax — inside a 2 s shutdown
	// budget. stopOnce keeps Stop idempotent: closing a closed channel panics.
	stopping chan struct{}
	stopOnce sync.Once
}

// newSOCKS5Server wraps a pre-bound listener. Tests use this directly with
// a 127.0.0.1:0 listener; production callers go through startSOCKS5 which
// also binds the listener.
func newSOCKS5Server(ln net.Listener) *socks5Server {
	return &socks5Server{
		ln:       ln,
		done:     make(chan struct{}),
		stopping: make(chan struct{}),
	}
}

// startSOCKS5 binds a TCP listener for SOCKS5 connections, constructs the
// owner, and spawns the accept loop. Bind failure is fatal — preserving the
// previous startSOCKS5 behaviour. Returns the server so initSOCKS5 can stash
// the handle on startupState for runProxyUntilShutdown to Stop.
// Supports CONNECT (TCP proxy) only; UDP ASSOCIATE is rejected by handleSOCKS5.
// Respects the global blocklist, IP filter, rate limiter, and plugin chain.
func startSOCKS5(port int) *socks5Server {
	// Use ListenConfig.Listen(ctx, ...) per project policy (CLAUDE.md
	// "HTTP contexts" + golangci noctx); ctx is Background here because
	// startup binding is synchronous and not user-cancellable.
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logFatalf("SOCKS5 listen error: %v", err)
	}
	srv := newSOCKS5Server(ln)
	// Record the feature as configured BEFORE the accept loop starts, so a
	// listener that fails on its very first Accept is reported against a
	// configured service rather than as "SOCKS5 not configured" (CHAOS-54).
	noteSOCKS5Configured(port)
	srv.Start()
	logger.Printf("SOCKS5: socks5://localhost:%d", port)
	return srv
}

// Start spawns the accept-loop goroutine. No-ops on a nil receiver or a
// server constructed from a nil listener; that branch exists so future
// callers cannot panic the serve loop. Must not be called more than once
// on the same non-nil-listener server.
func (s *socks5Server) Start() {
	if s == nil || s.ln == nil {
		return
	}
	go s.serve()
}

// Addr returns the listener's bound address (useful for logs and tests).
// Returns nil if the receiver or its listener is nil.
func (s *socks5Server) Addr() net.Addr {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Stop closes the listener and waits for the accept loop to exit, bounded
// by ctx. Nil-safe and idempotent: a nil receiver or a nil-listener server
// returns nil; a second call after a successful Stop returns nil because
// closing an already-closed listener is filtered. Stop expects Start to
// have been called for a non-nil listener (production goes through
// startSOCKS5, which does both). P1.5 / S4.SOCKS5.
func (s *socks5Server) Stop(ctx context.Context) error {
	if s == nil || s.ln == nil {
		return nil
	}
	// Signal first, close second: the accept loop may be sleeping off an accept
	// backoff, and only the signal wakes it early (CHAOS-54). Closing the
	// listener alone would be observed no sooner than the next Accept call.
	s.stopOnce.Do(func() { close(s.stopping) })
	closeErr := s.ln.Close()
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

// socks5AcceptFatal reports whether an accept error means the LISTENING SOCKET
// itself is gone, so that retrying can never succeed (CHAOS-54).
//
// The distinction is the whole safety argument for retrying forever. EMFILE,
// ENFILE, ENOBUFS and ENOMEM are resource conditions that clear on their own —
// backing off and retrying is exactly right, and giving up on them would turn a
// transient descriptor spike into a permanent SOCKS5 outage requiring a
// restart. EBADF/ENOTSOCK/EINVAL/EFAULT/ENOTCONN mean the descriptor is no
// longer a listening socket; every subsequent Accept returns the same error
// immediately, so a retry loop is a pure spin that will never accept anything.
//
// UNRECOGNISED errors are NOT fatal. That is the fail-safe direction here:
// backed off to one syscall per second, retrying an unknown error costs
// nothing and keeps a recoverable service alive, whereas misclassifying a
// transient fault as fatal is a customer-visible outage. The degradation is
// never silent — a listener stuck retrying is reported degraded after
// socks5AcceptDegradedAfter with an alert, a warn row and a gauge.
//
// The errno set is matched with errors.As rather than by string: net wraps
// accept errors in *net.OpError{Err: *os.SyscallError{Err: syscall.Errno}} and
// the text is platform-specific.
func socks5AcceptFatal(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EBADF, syscall.ENOTSOCK, syscall.EINVAL, syscall.EFAULT, syscall.ENOTCONN:
		return true
	}
	return false
}

// socks5AcceptReason classifies an accept error into a BOUNDED reason string
// for the health record.
//
// It must stay bounded. The reason reaches the alert Detail, which
// alerts.Store.Dispatch dedups on `event + ":" + Detail`; a raw err.Error()
// embeds the listener address and would yield a distinct key per failure that
// the dedup window cannot suppress by construction — the WK-12/RS-5 defect. It
// also reaches the viewer-role /api/diagnostics row, which must not carry
// internal addresses. The full error text goes to the rate-limited log line.
func socks5AcceptReason(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "accept_error"
	}
	switch errno {
	case syscall.EMFILE:
		return "process_fd_limit"
	case syscall.ENFILE:
		return "system_fd_limit"
	case syscall.ENOBUFS, syscall.ENOMEM:
		return "kernel_memory"
	case syscall.ECONNABORTED:
		return "connection_aborted"
	case syscall.EBADF, syscall.ENOTSOCK, syscall.EINVAL, syscall.EFAULT, syscall.ENOTCONN:
		return "listener_socket_invalid"
	}
	return "accept_error"
}

// nextSOCKS5AcceptBackoff advances the accept backoff: 5 ms on the first
// failure, doubling, capped at 1 s. Same schedule net/http.Server.Serve uses.
func nextSOCKS5AcceptBackoff(cur time.Duration) time.Duration {
	if cur == 0 {
		return socks5AcceptBackoffInitial
	}
	cur *= 2
	if cur > socks5AcceptBackoffMax {
		return socks5AcceptBackoffMax
	}
	return cur
}

// serve is the accept loop.
//
// Returns cleanly when the listener is closed (errors.Is(err, net.ErrClosed)),
// which is Stop's signal.
//
// CHAOS-54 — every other branch used to be `log and retry immediately`, which
// under EMFILE spun at ~870,000 attempts/second, pinned a core, and flooded the
// process log fast enough to rotate away the evidence of the incident (see
// socks5_health.go for the full chain). The loop now:
//
//   - backs off exponentially on a retryable error, 5 ms → 1 s, resetting on an
//     observed successful accept;
//   - sleeps INTERRUPTIBLY so Stop stays prompt;
//   - stops, closes the listener and reports the service DOWN when the socket
//     itself is unrecoverable, rather than spinning on an error that can never
//     clear. Closing is deliberate: a bound-but-never-accepting port is a black
//     hole in which clients hang, while connection-refused fails fast and is
//     what a health check can see.
//
// The whole loop runs under a panic guard for the same reason handleSOCKS5
// does. A panic here would otherwise take the entire proxy process down, and
// the CHAOS-24 objection to recovering at the top of a worker goroutine
// (turning a loud crash into a silent stall) does not apply: this guard reports
// the listener DOWN — fail row, alert, gauge at zero — which is the loudest
// state this file can produce.
func (s *socks5Server) serve() {
	defer close(s.done)
	defer func() {
		if v := recover(); v != nil {
			recordCrash("socks5-accept", "", v)
			_ = s.ln.Close()
			noteSOCKS5ListenerDown("accept loop panicked")
		}
	}()

	var backoff time.Duration
	for {
		conn, err := s.ln.Accept()
		if err == nil {
			// One atomic load on a healthy listener (socks5EverFailed); the
			// mutex is only taken when there is an episode to close out.
			suppressed := noteSOCKS5AcceptSuccess()
			if backoff > 0 {
				logger.Printf("SOCKS5 accept recovered after backing off to %s (%d further error lines suppressed)",
					backoff, suppressed)
				backoff = 0
			}
			go handleSOCKS5(conn)
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			// net.ErrClosed means the listener is gone, but it does NOT by
			// itself mean this was a shutdown: Stop is only one of the ways a
			// listener can end up closed. Ask whether Stop actually ran.
			//
			// The check is race-free in the direction that matters because
			// Stop closes `stopping` BEFORE `ln.Close()`, so an in-progress
			// shutdown is always visible here by the time Accept returns.
			//
			// Treating every ErrClosed as an expected stop would leave the one
			// hole this whole change exists to close: the loop exits, nothing
			// is recorded, and `/healthz` keeps saying `socks5: ready` with
			// `culvert_socks5_listener_up 1` on a node whose SOCKS5 service is
			// gone — PX-18 in a narrower costume. Raised by Codex review on
			// PR #1208.
			select {
			case <-s.stopping:
				return
			default:
			}
			noteSOCKS5ListenerDown("listener_closed_unexpectedly")
			logger.Printf("SOCKS5 accept: listener was closed without a shutdown request — SOCKS5 is unavailable until restart")
			return
		}
		reason := socks5AcceptReason(err)
		if socks5AcceptFatal(err) {
			_ = s.ln.Close()
			noteSOCKS5ListenerDown(reason)
			logger.Printf("SOCKS5 accept FATAL (%s): %v — listener closed, SOCKS5 is unavailable until restart",
				reason, err)
			return
		}
		backoff = nextSOCKS5AcceptBackoff(backoff)
		if noteSOCKS5AcceptFailure(reason, backoff, time.Now()) {
			logger.Printf("SOCKS5 accept error (%s): %v; retrying in %s", reason, err, backoff)
		}
		select {
		case <-s.stopping:
			return
		case <-time.After(backoff):
		}
	}
}

// errSOCKS5ATYPUnsupported is returned by parseSOCKS5Request for an unknown
// address type. It is the ONLY parse error the caller answers with a reply
// (0x08, "address type not supported"), reproducing the prior inline behavior;
// every other parse failure (bad version, short read) returns a distinct error
// and the caller closes silently.
var errSOCKS5ATYPUnsupported = errors.New("socks5: unsupported address type")

// parseSOCKS5Request reads a SOCKS5 request — VER(1) CMD(1) RSV(1) ATYP(1),
// the ATYP-typed destination address, and the 2-byte big-endian port — from r.
// It is a pure wire parser: it performs NO writes, dials, logging, or policy
// checks; the caller owns every reply and side effect. Host formatting matches
// the wire: IPv4/IPv6 via net.IP.String() (IPv6 bracketed), domain as the raw
// string. A zero-length domain is accepted (host == "", err == nil), exactly as
// the prior inline parser did — it is rejected later by the SSRF guard, not here.
// The returned cmd is NOT validated (the caller enforces CONNECT-only) so the
// full address+port frame is consumed first, preserving the original read order.
func parseSOCKS5Request(r io.Reader) (cmd byte, host string, port uint16, err error) {
	req := make([]byte, 4)
	if _, err = io.ReadFull(r, req); err != nil {
		return 0, "", 0, err
	}
	if req[0] != 0x05 {
		return 0, "", 0, fmt.Errorf("socks5: bad request version 0x%02x", req[0])
	}
	cmd = req[1]

	switch req[3] { // ATYP
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(b).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(r, lenBuf); err != nil {
			return 0, "", 0, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(r, domain); err != nil {
			return 0, "", 0, err
		}
		host = string(domain)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return 0, "", 0, err
		}
		host = "[" + net.IP(b).String() + "]"
	default:
		return 0, "", 0, errSOCKS5ATYPUnsupported
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(r, portBuf); err != nil {
		return 0, "", 0, err
	}
	return cmd, host, binary.BigEndian.Uint16(portBuf), nil
}

// socks5Negotiate performs the SOCKS5 greeting (VER NMETHODS METHODS) and, when
// auth is enabled, the RFC 1929 username/password sub-negotiation, writing the
// method-selection and auth-status replies. It returns true iff the client
// authenticated (or auth is disabled) and may proceed to the request phase.
// Every failure path (bad greeting, no acceptable method, short read, auth
// failure) is fully handled here — reply + stats + audit — and returns false so
// the caller simply closes the connection. Extracted from handleSOCKS5 to keep
// that function's cognitive complexity under the linter threshold; behavior is a
// strict relocation of the prior inline greeting/auth block.
func socks5Negotiate(conn net.Conn, clientIP string) bool {
	// Greeting: VER(1) NMETHODS(1) METHODS(N)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x05 {
		return false
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}

	if !cfg.AuthEnabled() {
		conn.Write([]byte{0x05, 0x00}) //nolint:errcheck // best-effort no-auth method selection; a write error surfaces on the next read
		return true
	}

	// Auth required: the client must offer USER/PASS (0x02).
	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		conn.Write([]byte{0x05, 0xFF}) //nolint:errcheck // best-effort "no acceptable method" reply before close
		return false
	}
	conn.Write([]byte{0x05, 0x02}) //nolint:errcheck // best-effort USER/PASS method selection; error surfaces on the next read

	// RFC 1929 sub-negotiation: VER(1) ULEN(1) UNAME PLEN(1) PASSWD
	subHdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, subHdr); err != nil {
		return false
	}
	uname := make([]byte, subHdr[1])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return false
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return false
	}
	passwd := make([]byte, plenBuf[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return false
	}
	authOK := cfg.VerifyAuth(string(uname), string(passwd))
	// B5: Zero credentials from memory immediately after auth check.
	clear(uname)
	clear(passwd)
	if !authOK {
		conn.Write([]byte{0x01, 0x01}) //nolint:errcheck // best-effort auth-failure reply before close
		atomic.AddInt64(&statAuthFail, 1)
		recordRequest(clientIP, "SOCKS5", "", "AUTH_FAIL", "", "", "", "")
		logger.Printf("SOCKS5 AUTH_FAIL %s", clientIP)
		return false
	}
	conn.Write([]byte{0x01, 0x00}) //nolint:errcheck // best-effort auth-success reply; error surfaces on the next read
	return true
}

func handleSOCKS5(conn net.Conn) {
	defer recoverGoroutine("socks5") // the whole SOCKS5 chain runs in its own goroutine
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck // deadline is best-effort; a set failure still yields a bounded relay via peer close

	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// ── Connection limit per IP ──────────────────────────────────────────────
	// Symmetric with handleRequest (proxy.go): SOCKS5 tunnels hold goroutines
	// and FDs for their full lifetime, so they must consume the same per-IP
	// budget as HTTP/CONNECT — otherwise one IP can exhaust the process with
	// idle tunnels the limiter was configured to prevent (CHAOS-02).
	if !connLimiter.Acquire(clientIP) {
		recordRequest(clientIP, "SOCKS5", "", "CONN_LIMITED", "", "", "", "")
		logger.Printf("SOCKS5 CONN_LIMITED %s", clientIP)
		return
	}
	defer connLimiter.Release(clientIP)

	// ── IP filter ────────────────────────────────────────────────────────────
	if !ipf.Allowed(clientIP) {
		recordRequest(clientIP, "SOCKS5", "", "IP_BLOCKED", "", "", "", "")
		return
	}

	// ── Rate limit ───────────────────────────────────────────────────────────
	if !rl.AllowAuto(clientIP) {
		recordRequest(clientIP, "SOCKS5", "", "RATE_LIMITED", "", "", "", "")
		return
	}

	// ── Greeting + auth negotiation ─────────────────────────────────────────
	if !socks5Negotiate(conn, clientIP) {
		return
	}

	// ── Request: VER(1) CMD(1) RSV(1) ATYP(1) + address + port ──────────────
	cmd, host, port, err := parseSOCKS5Request(conn)
	if err != nil {
		// Only the unsupported-ATYP case emits a reply before closing, exactly
		// as the prior inline parser did; every other parse failure (bad VER,
		// short read) closes silently.
		if errors.Is(err, errSOCKS5ATYPUnsupported) {
			socks5Reply(conn, 0x08) // address type not supported
		}
		return
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if cmd != 0x01 { // only CONNECT supported
		socks5Reply(conn, 0x07)
		return
	}

	// ── Host canonicalization gate (RISK-013, fail-closed) ──────────────────
	// Mirror of the handleRequest gate: a destination that cannot be
	// IDNA-normalized would reach the blocklist/plugin matchers un-normalized.
	if _, ok := normalizeHostStrict(host); !ok {
		atomic.AddInt64(&statBlocked, 1)
		socks5Reply(conn, 0x02)
		recordRequest(clientIP, "SOCKS5", host, "INVALID_HOST", "idna", "", "", "")
		logger.Printf("SOCKS5 INVALID_HOST %s -> %q {action=block source=idna}", clientIP, sanitizeLog(host))
		return
	}

	// ── Blocklist check ───────────────────────────────────────────────────────
	if bl.IsBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		socks5Reply(conn, 0x02)
		recordRequest(clientIP, "SOCKS5", host, "BLOCKED", "", "", "", "")
		logger.Printf("SOCKS5 BLOCKED %s -> %s", clientIP, host)
		return
	}

	// ── Plugin check ──────────────────────────────────────────────────────────
	if pluginDecision(clientIP, "SOCKS5", host) == DecisionBlock {
		atomic.AddInt64(&statBlocked, 1)
		socks5Reply(conn, 0x02)
		recordRequest(clientIP, "SOCKS5", host, "BLOCKED", "", "", "", "")
		return
	}

	// ── SSRF guard: block private/internal destinations ───────────────────────
	if err := isPrivateHost(target); err != nil {
		socks5Reply(conn, 0x02) // Connection not allowed by ruleset
		logger.Printf("SOCKS5 SSRF block %s -> %s: %v", clientIP, target, err)
		recordRequest(clientIP, "SOCKS5", host, "BLOCKED", "", "", "", "")
		return
	}

	// ── Dial target ───────────────────────────────────────────────────────────
	// Use Dialer.Control so the final connect() is rejected when DNS rebinding
	// flipped the target to a private IP between isPrivateHost and here.
	destConn, err := (&net.Dialer{Timeout: 10 * time.Second, Control: ssrfControl}).DialContext(context.Background(), "tcp", target)
	if err != nil {
		socks5Reply(conn, 0x05)
		logger.Printf("SOCKS5 dial error %s: %v", target, err)
		return
	}
	defer destConn.Close()

	// CHAOS-57: refuse to MINT a new long-lived tunnel on a node that is already
	// past the point where the drain can account for it. Checked here — after the
	// dial, immediately before the success reply — so the check-to-register window
	// is microseconds instead of spanning the 30s negotiation deadline and the 10s
	// dial above. Without it, a session accepted just before Stop could establish
	// after the drain, the force-close backstop AND the flush hooks had all run, and
	// be reset at process exit with no TUNNEL_CLOSED entry: PX-8 surviving inside
	// its own fix. Reply 0x01 (general SOCKS server failure) is protocol-correct and
	// is what lets the client retry elsewhere instead of being handed a success and
	// a tunnel that dies seconds later.
	if tunnelEstablishmentFenced() {
		noteTunnelFenceRefusal()
		socks5Reply(conn, 0x01)
		recordRequest(clientIP, "SOCKS5", host, "SHUTTING_DOWN", "", "", "", "")
		logger.Printf("SOCKS5 SHUTTING_DOWN %s -> %s (refused: node is draining)", clientIP, sanitizeLog(host))
		return
	}

	socks5Reply(conn, 0x00)       // success
	conn.SetDeadline(time.Time{}) //nolint:errcheck // remove deadline for streaming

	atomic.AddInt64(&statTotal, 1)
	recordRequest(clientIP, "SOCKS5", host, "OK", "", "", "", "")
	logger.Printf("SOCKS5 OK %s -> %s", clientIP, target)

	socks5Relay(conn, destConn, clientIP, host)
}

// socks5Relay bidirectionally copies between the client and destination conns,
// waiting for BOTH directions to finish. Closing the write half of each side
// (CloseWrite) unblocks the peer's io.Copy so the second direction returns —
// the same relay contract as the CONNECT/WebSocket tunnels (CLAUDE.md relay
// pattern). On teardown it records the per-connection tunnel-close accounting
// entry (byte counts + lifetime); log-only — the OK request-log entry already
// ran the stats fan-out for this connection.
func socks5Relay(client, dest net.Conn, clientIP, host string) {
	// CHAOS-57: SOCKS5 sessions were the drain's largest blind spot. `Stop` waits
	// only for the ACCEPT LOOP — every session runs in a detached
	// `go handleSOCKS5(conn)` — so nothing in the shutdown sequence waited for or
	// closed them, and a long-lived SSH-over-SOCKS5 session was reset by process
	// exit without its TUNNEL_CLOSED accounting ever being written.
	defer registerDrainableTunnel(tunnelClassSOCKS5, client, dest)()
	start := time.Now()
	// Byte counts: each direction is written by exactly one goroutine before
	// its done-send and read only after both receives (channel happens-before).
	var toDest, toClient int64
	// Idle-bounded via the shared tunnel helper (CHAOS-03): both directions
	// share one activity stamp, so a half-open peer that never sends again is
	// reaped after tunnelIdleTimeout instead of pinning goroutines + FDs
	// forever. Each direction reads its own peer conn, so the idle deadline
	// anchors on src itself. This also moves SOCKS5 onto the pooled relay
	// buffers the other tunnel paths use.
	shared := newTunnelActivityStamp()
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn, count *int64) {
		defer func() {
			if v := recover(); v != nil {
				recordCrash("socks5-relay", "", v)
				_ = dst.Close()
				_ = src.Close()
			}
			done <- struct{}{} // sole sender
		}()
		*count = idleCopyCounted(dst, src, src, shared)
	}
	go relay(dest, client, &toDest)
	go relay(client, dest, &toClient)
	<-done
	// Unblock the peer goroutine by closing write halves so io.Copy returns.
	if tc, ok := dest.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite() //nolint:errcheck
	}
	if tc, ok := client.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite() //nolint:errcheck
	}
	<-done

	recordTunnelClose(clientIP, "SOCKS5", host, "", "", "", toDest, toClient, start, "")
}

// socks5Reply sends a minimal SOCKS5 reply (IPv4 bind address 0.0.0.0:0).
func socks5Reply(conn net.Conn, rep byte) {
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //nolint:errcheck
}
