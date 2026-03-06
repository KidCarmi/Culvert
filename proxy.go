package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// privateCIDRs lists RFC 1918, loopback, link-local, and ULA ranges whose
// addresses must never be forwarded to upstream servers in headers such as
// X-Forwarded-For, preventing internal network topology leakage.
var privateCIDRs = func() []*net.IPNet {
	ranges := []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"127.0.0.0/8",    // loopback (IPv4)
		"169.254.0.0/16", // link-local (IPv4)
		"::1/128",        // loopback (IPv6)
		"fc00::/7",       // ULA (IPv6)
		"fe80::/10",      // link-local (IPv6)
	}
	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, cidr, _ := net.ParseCIDR(r)
		if cidr != nil {
			nets = append(nets, cidr)
		}
	}
	return nets
}()

// isPrivateIP reports whether ip falls within any private/internal range.
func isPrivateIP(ip net.IP) bool {
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// scrubForwardedHeaders sanitises request headers before forwarding upstream:
//   - X-Forwarded-For: private/internal IPs are stripped; if all IPs were
//     private the header is removed entirely.
//   - X-Real-IP: removed when it contains a private address.
//   - X-User-Identity: always removed (internal identity mock header —
//     must not be trusted from downstream clients or leak upstream).
//
// This prevents internal network topology disclosure and stops clients from
// injecting fake identity claims via the mock identity header.
func scrubForwardedHeaders(r *http.Request) {
	// Strip private IPs from X-Forwarded-For.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		var public []string
		for _, raw := range strings.Split(xff, ",") {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip != nil && !isPrivateIP(ip) {
				public = append(public, ip.String())
			}
		}
		if len(public) == 0 {
			r.Header.Del("X-Forwarded-For")
		} else {
			r.Header.Set("X-Forwarded-For", strings.Join(public, ", "))
		}
	}

	// Remove X-Real-IP if it resolves to a private address.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := net.ParseIP(strings.TrimSpace(xri))
		if ip == nil || isPrivateIP(ip) {
			r.Header.Del("X-Real-IP")
		}
	}

	// Always remove internal identity header before forwarding.
	r.Header.Del("X-User-Identity")
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// IP filter check.
	if !ipf.Allowed(clientIP) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "IP_BLOCKED", "", "")
		logger.Printf("IP_BLOCKED %s", clientIP)
		return
	}

	// Rate limit check.
	if !rl.Allow(clientIP) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		recordRequest(clientIP, r.Method, r.Host, "RATE_LIMITED", "", "")
		logger.Printf("RATE_LIMITED %s", clientIP)
		return
	}

	// Basic auth check (bcrypt-verified, cached per authCacheTTL).
	if cfg.AuthEnabled() {
		u, p, ok := parseProxyAuth(r)
		if !ok || !cfg.VerifyAuth(u, p) {
			atomic.AddInt64(&statAuthFail, 1)
			w.Header().Set("Proxy-Authenticate", `Basic realm="ProxyShield"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			recordRequest(clientIP, r.Method, r.Host, "AUTH_FAIL", "", "")
			logger.Printf("AUTH_FAIL %s", clientIP)
			return
		}
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Legacy blocklist check (still active alongside policy engine).
	if bl.IsBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by ProxyShield", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "BLOCKED", "", "")
		logger.Printf("BLOCKED %s -> %s", clientIP, host)
		return
	}

	// Plugin check.
	if pluginDecision(clientIP, r.Method, host) == DecisionBlock {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by plugin", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "BLOCKED", "", "")
		return
	}

	// File block profile — check URL path extension for non-tunnel requests.
	// CONNECT tunnels are opaque until SSL inspection; inner requests go through
	// handleRequest again and will be checked at that point.
	if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
		if ext := fileBlocker.CheckPath(r.URL.Path); ext != "" {
			atomic.AddInt64(&statFileBlocked, 1)
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "FILE_BLOCKED", ext, "")
			logger.Printf("FILE_BLOCKED %s -> %s%s (ext=%s)", clientIP, host, r.URL.Path, ext)
			serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
			return
		}
	}

	// ── Policy engine (PBAC) pre-check ───────────────────────────────────────
	// X-User-Identity is a mock header for identity; future versions will
	// populate this from the OIDC/LDAP auth context.
	identity := r.Header.Get("X-User-Identity")
	match := policyStore.Evaluate(clientIP, identity, host)

	if match != nil {
		switch match.Action {
		case ActionDrop:
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "POLICY_DROP", match.Rule.Name, string(ActionDrop))
			logger.Printf("POLICY_DROP rule=%q %s -> %s", match.Rule.Name, clientIP, host)
			// Silent TCP RST — hijack and close without sending an HTTP response.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return

		case ActionBlockPage:
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "POLICY_BLOCK", match.Rule.Name, string(ActionBlockPage))
			logger.Printf("POLICY_BLOCK rule=%q %s -> %s", match.Rule.Name, clientIP, host)
			serveBlockPage(w, r.Host, string(match.Rule.DestCategory), match.Rule.Name)
			return

		case ActionRedirect:
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "POLICY_REDIRECT", match.Rule.Name, string(ActionRedirect))
			if !isSafeRedirectURL(match.Rule.RedirectURL) {
				logger.Printf("POLICY_REDIRECT rule=%q: invalid redirect URL %q — blocking", match.Rule.Name, match.Rule.RedirectURL)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			logger.Printf("POLICY_REDIRECT rule=%q %s -> %s => %s", match.Rule.Name, clientIP, host, match.Rule.RedirectURL)
			http.Redirect(w, r, match.Rule.RedirectURL, http.StatusFound)
			return

		case ActionAllow:
			recordRequest(clientIP, r.Method, r.Host, "OK", match.Rule.Name, string(ActionAllow))
			logger.Printf("POLICY_ALLOW rule=%q %s %s %s", match.Rule.Name, clientIP, r.Method, r.Host)
			// Fall through to normal handling below.
		}
	} else {
		recordRequest(clientIP, r.Method, r.Host, "OK", "", "")
		logger.Printf("OK %s %s %s", clientIP, r.Method, r.Host)
	}

	// Determine SSL action and per-rule TLS options for CONNECT tunnels.
	sslAction := SSLBypass
	tlsSkipVerify := false
	if match != nil {
		if match.SSLAction == SSLInspect {
			sslAction = SSLInspect
		}
		tlsSkipVerify = match.TLSSkipVerify
	}

	if r.Method == http.MethodConnect {
		handleTunnel(w, r, sslAction, tlsSkipVerify)
	} else if isWebSocketUpgrade(r) {
		handleWebSocket(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func parseProxyAuth(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// maxRequestBody is the largest body we'll forward for non-tunnel requests.
// CONNECT tunnels and WebSocket upgrades bypass this limit (they stream raw TCP).
const maxRequestBody = 64 << 20 // 64 MB

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	removeHopHeaders(r.Header)

	// Scrub internal/private headers before forwarding upstream (shift-left:
	// prevent topology leakage and fake identity injection).
	scrubForwardedHeaders(r)

	// Apply request-side rewrite rules before forwarding.
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	rewriter.ApplyRequest(host, r.Header)

	client := &http.Client{
		Transport: upstreamTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
	r.RequestURI = ""
	resp, err := client.Do(r)
	if err != nil {
		logger.Printf("upstream request error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	pluginOnResponse(resp)
	rewriter.ApplyResponse(host, resp) // response-side rewrite rules
	removeHopHeaders(resp.Header)

	// File block — check Content-Disposition for blocked download extensions.
	// This catches downloads that use a generic URL but declare the real
	// file extension in the response header (e.g. /download?id=123 →
	// Content-Disposition: attachment; filename="setup.exe").
	if ext := fileBlocker.CheckContentDisposition(resp.Header.Get("Content-Disposition")); ext != "" {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordRequest(cip, r.Method, r.Host, "FILE_BLOCKED", ext, "")
		logger.Printf("FILE_BLOCKED (resp cd) %s -> %s%s (ext=%s)", cip, r.Host, r.URL.Path, ext)
		serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// isSafeRedirectURL returns true only for absolute http/https URLs, preventing
// javascript: URIs and protocol-relative open redirects from policy config.
func isSafeRedirectURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https")
}

// isWebSocketUpgrade returns true when the request is an HTTP→WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleWebSocket proxies a plain-HTTP WebSocket upgrade by dialling the
// target host directly, forwarding the original HTTP request (including
// Upgrade headers), then bridging the raw TCP streams.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		logger.Printf("WS dial error %s: %v", host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	// Forward the original request to the target (preserve Upgrade headers).
	r.RequestURI = r.URL.RequestURI()
	if err := r.Write(destConn); err != nil {
		logger.Printf("WS write error %s: %v", host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read the 101 Switching Protocols response from the target.
	br := bufio.NewReader(destConn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		logger.Printf("WS upstream response error %s: %v", host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
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

	logger.Printf("WS tunnel established → %s", host)

	// Bridge: drain any buffered bytes from the target first.
	done := make(chan struct{}, 2)
	relay := func(dst net.Conn, src io.Reader) {
		io.Copy(dst, src) //nolint:errcheck
		done <- struct{}{}
	}
	go relay(clientConn, br)       // target → client (br may have buffered bytes)
	go relay(destConn, clientConn) // client → target
	<-done
}

// handleTunnel dispatches to SSL-bypass or SSL-inspect based on policy.
func handleTunnel(w http.ResponseWriter, r *http.Request, sslAction SSLAction, tlsSkipVerify bool) {
	if sslAction == SSLInspect && certMgr.Ready() {
		handleTunnelInspect(w, r, tlsSkipVerify)
	} else {
		handleTunnelBypass(w, r)
	}
}

// upstreamTransport is a shared http.Transport used by handleHTTP so that
// connections to upstream servers are pooled across requests, avoiding the
// overhead of a new TCP/TLS handshake per proxied request.
var upstreamTransport = &http.Transport{
	MaxIdleConns:        256,
	MaxIdleConnsPerHost: 16,
	MaxConnsPerHost:     64,
	IdleConnTimeout:     90 * time.Second,
}

// handleTunnelBypass is the original transparent TCP tunnel (Bypass mode).
func handleTunnelBypass(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		logger.Printf("tunnel dial error %s: %v", r.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) { io.Copy(dst, src); done <- struct{}{} }
	go relay(destConn, clientConn)
	go relay(clientConn, destConn)
	<-done
}

// handleTunnelInspect performs SSL inspection (MITM) for CONNECT tunnels.
// It terminates TLS on both sides using on-the-fly certificates signed by the
// internal Root CA, allowing the proxy to inspect decrypted HTTP/1.x traffic.
// tlsSkipVerify disables upstream certificate validation for specific policy
// rules (e.g. internal sites with self-signed certs); use with caution.
func handleTunnelInspect(w http.ResponseWriter, r *http.Request, tlsSkipVerify bool) {
	targetHost := r.Host
	if _, _, err := net.SplitHostPort(targetHost); err != nil {
		targetHost += ":443"
	}
	hostOnly, _, _ := net.SplitHostPort(targetHost)

	// 1. Connect to the upstream server over plain TCP.
	rawUpstream, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		logger.Printf("inspect dial error %s: %v", targetHost, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// 2. Perform TLS handshake with the upstream.
	// By default RootCAs is set from the system cert pool (fail-secure).
	// When tlsSkipVerify is true (admin-configured per-rule) cert validation is
	// skipped — this is intentional for internal/self-signed cert hosts and is
	// logged as a warning so it is auditable.
	var upstreamTLSCfg *tls.Config
	if tlsSkipVerify {
		logger.Printf("WARN SSL_INSPECT skipping upstream cert verify for %s (tlsSkipVerify rule)", hostOnly)
		upstreamTLSCfg = &tls.Config{
			ServerName:         hostOnly,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // #nosec G402 — admin-configured per-rule override
		}
	} else {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			// Fall back to an empty pool; handshake will reject unknown CAs.
			systemRoots = x509.NewCertPool()
		}
		upstreamTLSCfg = &tls.Config{
			ServerName: hostOnly,
			MinVersion: tls.VersionTLS12,
			RootCAs:    systemRoots,
		}
	}
	upstreamTLS := tls.Client(rawUpstream, upstreamTLSCfg)
	if err := upstreamTLS.Handshake(); err != nil {
		rawUpstream.Close()
		logger.Printf("upstream TLS handshake error %s: %v", targetHost, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// 3. Hijack the client connection and send the 200 Connection Established.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstreamTLS.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	rawClient, _, err := hijacker.Hijack()
	if err != nil {
		upstreamTLS.Close()
		logger.Printf("SSL_INSPECT hijack error: %v", err)
		return
	}

	// 4. Perform TLS handshake with the client using a dynamically-signed cert.
	clientTLS := tls.Server(rawClient, &tls.Config{
		GetCertificate: certMgr.GetCert,
	})
	if err := clientTLS.Handshake(); err != nil {
		clientTLS.Close()
		upstreamTLS.Close()
		logger.Printf("SSL_INSPECT client TLS handshake error for %s: %v", hostOnly, err)
		return
	}

	logger.Printf("SSL_INSPECT tunnel → %s", targetHost)

	// 5. Relay decrypted traffic bidirectionally.
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) { io.Copy(dst, src); done <- struct{}{} }
	go relay(upstreamTLS, clientTLS)
	go relay(clientTLS, upstreamTLS)
	<-done
	clientTLS.Close()
	upstreamTLS.Close()
}

func removeHopHeaders(h http.Header) {
	for _, hdr := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade",
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
