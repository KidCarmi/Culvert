package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// socks5Server owns the SOCKS5 accept loop. It wraps a pre-bound listener
// and spawns one handleSOCKS5 goroutine per accepted connection. Stop closes
// the listener, which causes Accept to return net.ErrClosed; the serve loop
// treats that as the expected stop signal and returns. P1.5 / S4.SOCKS5.
//
// Out of scope here: in-flight SOCKS5 tunnels are NOT drained on Stop —
// they continue running on their own per-conn 30s deadlines (set in
// handleSOCKS5). Graceful tunnel drain is tracked separately for Phase 2.
type socks5Server struct {
	ln   net.Listener
	done chan struct{}
}

// newSOCKS5Server wraps a pre-bound listener. Tests use this directly with
// a 127.0.0.1:0 listener; production callers go through startSOCKS5 which
// also binds the listener.
func newSOCKS5Server(ln net.Listener) *socks5Server {
	return &socks5Server{
		ln:   ln,
		done: make(chan struct{}),
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
		logger.Fatalf("SOCKS5 listen error: %v", err)
	}
	srv := newSOCKS5Server(ln)
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

// serve is the accept loop. Returns cleanly when the listener is closed
// (errors.Is(err, net.ErrClosed)); other accept errors are logged and the
// loop continues, matching the previous startSOCKS5 behaviour for transient
// failures.
func (s *socks5Server) serve() {
	defer close(s.done)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// Stop closed the listener; expected stop signal.
				return
			}
			logger.Printf("SOCKS5 accept error: %v", err)
			continue
		}
		go handleSOCKS5(conn)
	}
}

func handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck

	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

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

	// ── Greeting: VER(1) NMETHODS(1) METHODS(N) ─────────────────────────────
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// ── Auth negotiation ─────────────────────────────────────────────────────
	if cfg.AuthEnabled() {
		hasUserPass := false
		for _, m := range methods {
			if m == 0x02 {
				hasUserPass = true
				break
			}
		}
		if !hasUserPass {
			conn.Write([]byte{0x05, 0xFF}) //nolint:errcheck
			return
		}
		conn.Write([]byte{0x05, 0x02}) //nolint:errcheck

		// RFC 1929 sub-negotiation
		subHdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, subHdr); err != nil {
			return
		}
		uname := make([]byte, subHdr[1])
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil {
			return
		}
		passwd := make([]byte, plenBuf[0])
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}
		authOK := cfg.VerifyAuth(string(uname), string(passwd))
		// B5: Zero credentials from memory immediately after auth check.
		clear(uname)
		clear(passwd)
		if !authOK {
			conn.Write([]byte{0x01, 0x01}) //nolint:errcheck
			atomic.AddInt64(&statAuthFail, 1)
			recordRequest(clientIP, "SOCKS5", "", "AUTH_FAIL", "", "", "", "")
			logger.Printf("SOCKS5 AUTH_FAIL %s", clientIP)
			return
		}
		conn.Write([]byte{0x01, 0x00}) //nolint:errcheck
	} else {
		conn.Write([]byte{0x05, 0x00}) //nolint:errcheck
	}

	// ── Request: VER(1) CMD(1) RSV(1) ATYP(1) ───────────────────────────────
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 0x05 {
		return
	}
	cmd, atyp := req[1], req[3]

	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = "[" + net.IP(b).String() + "]"
	default:
		socks5Reply(conn, 0x08) // address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if cmd != 0x01 { // only CONNECT supported
		socks5Reply(conn, 0x07)
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

	socks5Reply(conn, 0x00)       // success
	conn.SetDeadline(time.Time{}) //nolint:errcheck // remove deadline for streaming

	atomic.AddInt64(&statTotal, 1)
	recordRequest(clientIP, "SOCKS5", host, "OK", "", "", "", "")
	logger.Printf("SOCKS5 OK %s -> %s", clientIP, target)

	start := time.Now()
	// Byte counts: each direction is written by exactly one goroutine before
	// its done-send and read only after both receives (channel happens-before).
	var toDest, toClient int64
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn, count *int64) {
		n, _ := io.Copy(dst, src) //nolint:errcheck // relay copy error is expected on peer close; byte count still valid
		*count = n
		done <- struct{}{}
	}
	go relay(destConn, conn, &toDest)
	go relay(conn, destConn, &toClient)
	<-done
	// Unblock the peer goroutine by closing write halves so io.Copy returns.
	if tc, ok := destConn.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite() //nolint:errcheck
	}
	if tc, ok := conn.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite() //nolint:errcheck
	}
	<-done

	// Per-connection accounting entry (bytes + lifetime). Log-only: the OK
	// entry above already ran the stats fan-out for this connection.
	recordTunnelClose(clientIP, "SOCKS5", host, "", "", toDest, toClient, start, "")
}

// socks5Reply sends a minimal SOCKS5 reply (IPv4 bind address 0.0.0.0:0).
func socks5Reply(conn net.Conn, rep byte) {
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //nolint:errcheck
}
