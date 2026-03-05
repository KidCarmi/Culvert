package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// startSOCKS5 listens for SOCKS5 connections on the given port.
// Supports CONNECT (TCP proxy) only; UDP ASSOCIATE is rejected.
// Respects the global blocklist, IP filter, rate limiter, and plugin chain.
func startSOCKS5(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Fatalf("SOCKS5 listen error: %v", err)
	}
	logger.Printf("SOCKS5  → socks5://localhost:%d", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
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
		recordRequest(clientIP, "SOCKS5", "", "IP_BLOCKED")
		return
	}

	// ── Rate limit ───────────────────────────────────────────────────────────
	if !rl.Allow(clientIP) {
		recordRequest(clientIP, "SOCKS5", "", "RATE_LIMITED")
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
	authUser, authPass := cfg.GetAuth()
	if cfg.AuthEnabled() && authUser != "" {
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
		if string(uname) != authUser || string(passwd) != authPass {
			conn.Write([]byte{0x01, 0x01}) //nolint:errcheck
			atomic.AddInt64(&statAuthFail, 1)
			recordRequest(clientIP, "SOCKS5", "", "AUTH_FAIL")
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
	target := fmt.Sprintf("%s:%d", host, port)

	if cmd != 0x01 { // only CONNECT supported
		socks5Reply(conn, 0x07)
		return
	}

	// ── Blocklist check ───────────────────────────────────────────────────────
	if bl.IsBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		socks5Reply(conn, 0x02)
		recordRequest(clientIP, "SOCKS5", host, "BLOCKED")
		logger.Printf("SOCKS5 BLOCKED %s -> %s", clientIP, host)
		return
	}

	// ── Plugin check ──────────────────────────────────────────────────────────
	if pluginDecision(clientIP, "SOCKS5", host) == DecisionBlock {
		atomic.AddInt64(&statBlocked, 1)
		socks5Reply(conn, 0x02)
		recordRequest(clientIP, "SOCKS5", host, "BLOCKED")
		return
	}

	// ── Dial target ───────────────────────────────────────────────────────────
	destConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		socks5Reply(conn, 0x05)
		logger.Printf("SOCKS5 dial error %s: %v", target, err)
		return
	}
	defer destConn.Close()

	socks5Reply(conn, 0x00) // success
	conn.SetDeadline(time.Time{}) //nolint:errcheck // remove deadline for streaming

	atomic.AddInt64(&statTotal, 1)
	recordRequest(clientIP, "SOCKS5", host, "OK")
	logger.Printf("SOCKS5 OK %s -> %s", clientIP, target)

	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) { io.Copy(dst, src); done <- struct{}{} } //nolint:errcheck
	go relay(destConn, conn)
	go relay(conn, destConn)
	<-done
}

// socks5Reply sends a minimal SOCKS5 reply (IPv4 bind address 0.0.0.0:0).
func socks5Reply(conn net.Conn, rep byte) {
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //nolint:errcheck
}
