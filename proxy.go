package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

// defaultPolicyAction controls what happens when no PBAC rule matches a request.
// "allow" = passthrough mode (initial setup), "deny" = zero-trust (production).
// Set by setDefaultPolicyAction() during startup based on config or rule count.
// Stored as 1 (allow) or 0 (deny) via atomic int32 to avoid data races.
var defaultPolicyActionAllow int32 // 0 = deny (default)

func setDefaultPolicyAction(action string) {
	if action == "allow" {
		atomic.StoreInt32(&defaultPolicyActionAllow, 1)
	} else {
		atomic.StoreInt32(&defaultPolicyActionAllow, 0)
	}
}

// defaultPolicyAction returns the current default action string ("allow"/"deny").
func defaultPolicyAction() string {
	if atomic.LoadInt32(&defaultPolicyActionAllow) == 1 {
		return "allow"
	}
	return "deny"
}

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

// isPrivateHost resolves host (host or host:port) and returns an error if any
// resolved IP falls within a private/internal range. This prevents SSRF via
// proxy CONNECT to loopback, RFC 1918, link-local, or metadata endpoints.
// Results are cached in ssrfDNSCache (30s TTL) to avoid redundant DNS lookups.
func isPrivateHost(hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport // no port
	}
	// Check cache first.
	if priv, ok := ssrfDNSCache.Lookup(host); ok {
		if priv {
			return fmt.Errorf("destination %s resolves to private address (cached)", host)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		// Fail closed: unresolvable hosts are rejected to prevent DNS-rebinding
		// attacks where the check resolves to a public IP but Dial resolves to
		// a private one after TTL expiry. DNS errors are NOT cached.
		return fmt.Errorf("destination %s: DNS resolution failed: %w", host, err)
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && isPrivateIP(ip) {
			ssrfDNSCache.Store(host, true)
			return fmt.Errorf("destination %s resolves to private address %s", host, ipStr)
		}
	}
	ssrfDNSCache.Store(host, false)
	return nil
}

// scrubForwardedHeaders sanitises request headers before forwarding upstream:
//   - X-Forwarded-For: private/internal IPs are stripped; if all IPs were
//     private the header is removed entirely.
//   - X-Real-IP: removed when it contains a private address.
//   - X-User-Identity: always removed — set internally by auth context;
//     must not be trusted from downstream clients or leak upstream.
//
// This prevents internal network topology disclosure and stops clients from
// injecting identity claims.
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

func handleRequest(w http.ResponseWriter, r *http.Request) { //nolint:gocognit,cyclop,funlen // request dispatcher; complexity is inherent to the auth+policy+routing pipeline
	start := time.Now()
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// ── Request tracing: generate X-Request-ID if not present ────────────
	reqID := strings.ReplaceAll(strings.ReplaceAll(r.Header.Get("X-Request-ID"), "\n", ""), "\r", "") // sanitize for CWE-117
	if reqID == "" {
		reqID = generateRequestID()
		r.Header.Set("X-Request-ID", reqID)
	}
	w.Header().Set("X-Request-ID", reqID)

	// ── W3C Trace Context: propagate or generate traceparent ────────────
	if r.Header.Get("Traceparent") == "" {
		r.Header.Set("Traceparent", generateTraceparent())
	}

	// ── Connection limit per IP ─────────────────────────────────────────
	if !connLimiter.Acquire(clientIP) {
		http.Error(w, "Too Many Connections", http.StatusServiceUnavailable)
		return
	}
	defer connLimiter.Release(clientIP)

	// IP filter check.
	if !ipf.Allowed(clientIP) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "IP_BLOCKED", "", "", "", "")
		logger.Printf("IP_BLOCKED %s {req_id=%s action=block}", clientIP, reqID)
		return
	}

	// Rate limit check.
	if !rl.AllowAuto(clientIP) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		recordRequest(clientIP, r.Method, r.Host, "RATE_LIMITED", "", "", "", "")
		logger.Printf("RATE_LIMITED %s {req_id=%s action=block}", clientIP, reqID)
		return
	}

	// ── Adaptive Authentication ───────────────────────────────────────────────
	// Resolution order:
	//  1. Signed session cookie (browser SSO — OIDC code flow or SAML).
	//  2. Proxy-Authorization Basic header (non-browser / API clients).
	//     a. Resolved via IdP registry (OIDC introspection) if providers exist.
	//     b. Legacy single LDAP/OIDC provider (cfg.ProviderEnabled).
	//     c. Local bcrypt auth.
	//  3. No credentials — redirect browser to captive portal or send 407.
	var authenticatedIdentity string
	var authenticatedGroups []string
	authenticatedSource := "unauth" // default: no credentials presented

	authRequired := !cfg.UnauthMode() && (cfg.AuthEnabled() || cfg.ProviderEnabled() || len(idpRegistry.EnabledProviders()) > 0)

	if authRequired {
		// ── 1. Session cookie (browser SSO) ──────────────────────────────────
		if sess, err := readSessionCookie(r); err == nil && sess != nil {
			id := sess.Identity()
			authenticatedIdentity = id.Sub
			if authenticatedIdentity == "" {
				authenticatedIdentity = id.Email
			}
			authenticatedGroups = id.Groups
			if id.Provider != "" {
				authenticatedSource = id.Provider
			} else {
				authenticatedSource = "local"
			}
		} else {
			// ── 2. Basic Auth header ──────────────────────────────────────────
			u, p, ok := parseProxyAuth(r)
			if ok {
				// Try IdP registry providers first (OIDC introspection).
				authed := false
				for _, prov := range idpRegistry.EnabledProviders() {
					if id, resolved := prov.ResolveIdentity(u, p); resolved && id != nil {
						authenticatedIdentity = id.Sub
						if authenticatedIdentity == "" {
							authenticatedIdentity = u
						}
						authenticatedGroups = id.Groups
						authenticatedSource = prov.Name()
						authed = true
						break
					}
				}
				// Fall back to legacy single provider or local bcrypt.
				if !authed {
					if !cfg.VerifyAuth(u, p) {
						atomic.AddInt64(&statAuthFail, 1)
						w.Header().Set("Proxy-Authenticate", `Basic realm="Culvert"`)
						http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
						recordRequest(clientIP, r.Method, r.Host, "AUTH_FAIL", "", "", "", "")
						logger.Printf("AUTH_FAIL %s {req_id=%s action=block}", clientIP, reqID)
						return
					}
					authenticatedIdentity = u
					authenticatedSource = "local"
				}
			} else {
				// ── 3. No credentials ────────────────────────────────────────
				isBrowser := strings.Contains(r.Header.Get("User-Agent"), "Mozilla")
				if isBrowser && r.Method != http.MethodConnect {
					// Route browser to appropriate IdP based on email domain hint.
					loginURL := resolveCaptivePortalURL(r)
					if loginURL != "" {
						http.Redirect(w, r, loginURL, http.StatusFound)
						return
					}
				}
				atomic.AddInt64(&statAuthFail, 1)
				w.Header().Set("Proxy-Authenticate", `Basic realm="Culvert"`)
				if u := cfg.OIDCLoginURL(); u != "" {
					w.Header().Set("Link", `<`+u+`>; rel="authorization_endpoint"`)
				}
				http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
				recordRequest(clientIP, r.Method, r.Host, "AUTH_FAIL", "", "", "", "")
				logger.Printf("AUTH_FAIL (no-credentials) %s {req_id=%s action=block}", clientIP, reqID)
				return
			}
		}
	}

	// Set internal identity headers — scrubForwardedHeaders removes them
	// before forwarding upstream.
	if authenticatedIdentity != "" {
		r.Header.Set("X-User-Identity", authenticatedIdentity)
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Legacy blocklist check (still active alongside policy engine).
	if bl.IsBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by Culvert", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "BLOCKED", "blocklist", "", authenticatedIdentity, "")
		logger.Printf("BLOCKED %s -> %q {req_id=%s identity=%s action=block source=blocklist}", clientIP, sanitizeLog(host), reqID, sanitizeLog(authenticatedIdentity))
		return
	}

	// Threat intelligence feed check — covers both plain HTTP destinations
	// and CONNECT tunnel targets.
	if globalSecScanner.Enabled() {
		// Domain-level check (applies to CONNECT and plain HTTP).
		if result := globalSecScanner.CheckDomain(host); result != nil {
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "THREAT_BLOCKED", result.Source, result.Reason, authenticatedIdentity, "")
			logger.Printf("THREAT_BLOCKED domain %s -> %q (%q)", clientIP, sanitizeLog(host), sanitizeLog(result.Reason))
			serveBlockPage(w, r.Host, "Threat Intelligence", result.Reason)
			return
		}
		// Full-URL check for non-CONNECT (plain HTTP) requests.
		if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
			if result := globalSecScanner.CheckURL(r.URL.String()); result != nil {
				atomic.AddInt64(&statBlocked, 1)
				recordRequest(clientIP, r.Method, r.Host, "THREAT_BLOCKED", result.Source, result.Reason, authenticatedIdentity, "")
				logger.Printf("THREAT_BLOCKED url %s -> %q (%q)", clientIP, sanitizeLog(r.Host), sanitizeLog(result.Reason))
				serveBlockPage(w, r.Host, "Threat Intelligence", result.Reason)
				return
			}
		}
	}

	// Plugin check.
	if pluginDecision(clientIP, r.Method, host) == DecisionBlock {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by plugin", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "BLOCKED", "plugin", "", authenticatedIdentity, "")
		return
	}

	// File block profile — check URL path extension for non-tunnel requests.
	// CONNECT tunnels are opaque until SSL inspection; inner requests go through
	// handleRequest again and will be checked at that point.
	if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
		if ext := fileBlocker.CheckPath(r.URL.Path); ext != "" {
			atomic.AddInt64(&statFileBlocked, 1)
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "FILE_BLOCKED", ext, "", authenticatedIdentity, "")
			logger.Printf("FILE_BLOCKED %s -> %q%q (ext=%q)", clientIP, sanitizeLog(host), sanitizeLog(r.URL.Path), sanitizeLog(ext))
			serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
			return
		}
	}

	// ── Policy engine (PBAC) pre-check ───────────────────────────────────────
	// X-User-Identity is the authenticated identity set by the auth layer
	// (OIDC/LDAP); scrubForwardedHeaders already stripped any client-supplied
	// value, so this value is safe to use for policy matching.
	identity := r.Header.Get("X-User-Identity")
	match := policyStore.Evaluate(clientIP, identity, authenticatedSource, host, authenticatedGroups)

	if match != nil { //nolint:nestif // policy action dispatch is inherently branchy
		ruleMet.RecordHit(match.Rule.Name)
		switch match.Action {
		case ActionDrop:
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "POLICY_DROP", match.Rule.Name, string(ActionDrop), authenticatedIdentity, "")
			logger.Printf("POLICY_DROP rule=%q pri=%s %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			// Silent TCP RST — hijack and close without sending an HTTP response.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return

		case ActionBlockPage:
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "POLICY_BLOCK", match.Rule.Name, string(ActionBlockPage), authenticatedIdentity, "")
			logger.Printf("POLICY_BLOCK rule=%q pri=%s %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			serveBlockPage(w, r.Host, string(match.Rule.DestCategory), match.Rule.Name)
			return

		case ActionRedirect:
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "POLICY_REDIRECT", match.Rule.Name, string(ActionRedirect), authenticatedIdentity, "")
			if !isSafeRedirectURL(match.Rule.RedirectURL) {
				logger.Printf("POLICY_REDIRECT rule=%q: invalid redirect URL %q — blocking", sanitizeLog(match.Rule.Name), sanitizeLog(match.Rule.RedirectURL))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			logger.Printf("POLICY_REDIRECT rule=%q pri=%s %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.Rule.RedirectURL), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			http.Redirect(w, r, match.Rule.RedirectURL, http.StatusFound)
			return

		case ActionAllow:
			// Per-rule file profile: even when the policy allows the request,
			// the attached file-extension profile can still block specific
			// download types (e.g. "Allow github.com but block Executables").
			// CONNECT tunnels are handled inside handleTunnelInspect where
			// the inner URL is visible; here we only check plain HTTP.
			if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
				if match.Rule != nil && match.Rule.FileProfileBlocked(r.URL.Path) {
					atomic.AddInt64(&statFileBlocked, 1)
					atomic.AddInt64(&statBlocked, 1)
					recordRequest(clientIP, r.Method, r.Host, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, authenticatedIdentity, "")
					logger.Printf("FILE_BLOCKED (policy profile) %s -> %q%q (profile=%q rule=%q)", clientIP, sanitizeLog(host), sanitizeLog(r.URL.Path), sanitizeLog(string(match.Rule.FileProfile)), sanitizeLog(match.Rule.Name))
					serveBlockPage(w, r.Host+r.URL.Path, "File Block (Policy)", string(match.Rule.FileProfile))
					return
				}
			}
			recordRequest(clientIP, r.Method, r.Host, "OK", match.Rule.Name, string(ActionAllow), authenticatedIdentity, "")
			logger.Printf("POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, r.Method, sanitizeLog(r.Host), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			// Fall through to normal handling below.
		}
	} else {
		// No rule matched — apply the configured default action.
		if defaultPolicyAction() == "allow" {
			// Passthrough mode: allow all unmatched traffic (initial setup).
			recordRequest(clientIP, r.Method, r.Host, "OK", "default-allow", "Allow", authenticatedIdentity, "")
		} else {
			// Zero Trust: deny by default. Serve the custom HTML block page so
			// end-users see a clear, branded explanation.
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, r.Method, r.Host, "POLICY_DEFAULT_DENY", "", "", authenticatedIdentity, "")
			logger.Printf("POLICY_DEFAULT_DENY %s %s %q {req_id=%s identity=%s action=deny}", clientIP, r.Method, sanitizeLog(r.Host), reqID, sanitizeLog(authenticatedIdentity))
			serveBlockPage(w, r.Host, "Default Deny", "No matching policy rule")
			return
		}
	}

	// ── Geo-IP tracking (async) ───────────────────────────────────────────────
	// Record destination country for the live dashboard without blocking.
	go func(h string) {
		code, name := geo.LookupFull(h)
		if code != "" {
			countryTraffic.Record(code, name)
		}
	}(host)

	// Determine SSL action and per-rule TLS options for CONNECT tunnels.
	sslAction := SSLBypass
	tlsSkipVerify := false
	if match != nil {
		if match.SSLAction == SSLInspect {
			sslAction = SSLInspect
		}
		tlsSkipVerify = match.TLSSkipVerify
	}
	// Smart Bypass: explicit bypass-list patterns (glob or regex) always
	// override policy-based SSL inspection, regardless of rule SSLAction.
	if sslAction == SSLInspect && sslBypass.Matches(host) {
		sslAction = SSLBypass
		logger.Printf("SSL_BYPASS_PATTERN %s -> %q", clientIP, sanitizeLog(host))
	}

	// Identity context forwarded to SSL-inspect (consumed by CDR today;
	// future audit enrichment can read this without re-parsing headers).
	proxyID := ProxyIdentity{
		ClientIP:   clientIP,
		Identity:   authenticatedIdentity,
		AuthSource: authenticatedSource,
		Groups:     authenticatedGroups,
	}

	switch {
	case r.Method == http.MethodConnect:
		handleTunnel(w, r, sslAction, tlsSkipVerify, match, proxyID)
	case isWebSocketUpgrade(r):
		handleWebSocket(w, r)
	default:
		handleHTTP(w, r)
	}

	// Record request latency for Prometheus histogram.
	latencyHist.Observe(time.Since(start).Seconds())

	// OTLP span export: record one span per proxied request for Jaeger/Tempo.
	// Only fires when the OTLP endpoint is configured; the Enabled() check
	// avoids constructing the SpanRecord struct on the common no-OTLP path.
	if globalOTLPTraces.Enabled() {
		traceID, spanID := parseTraceparent(r.Header.Get("Traceparent"))
		sslStr := ""
		if sslAction == SSLInspect {
			sslStr = "inspect"
		} else if r.Method == http.MethodConnect {
			sslStr = "bypass"
		}
		ruleName := ""
		if match != nil && match.Rule != nil {
			ruleName = match.Rule.Name
		}
		globalOTLPTraces.RecordSpan(SpanRecord{
			TraceID:   traceID,
			SpanID:    spanID,
			Name:      "proxy_request",
			Method:    r.Method,
			Host:      host,
			Status:    "OK",
			Rule:      ruleName,
			ClientIP:  clientIP,
			SSLAction: sslStr,
			StartNano: start.UnixNano(),
			EndNano:   time.Now().UnixNano(),
		})
	}
}

const maxUsernameLen = 256

// resolveCaptivePortalURL picks the best IdP login URL for an unauthenticated
// browser request.  Resolution priority:
//  1. Email domain hint from "X-Proxy-Email-Hint" header or "email" query param.
//  2. First enabled IdP in registry (if exactly one — skips selection screen).
//  3. Proxy selection page (/auth/select) when multiple providers are registered.
//  4. Legacy OIDCLoginURL from single-provider config.
func resolveCaptivePortalURL(r *http.Request) string {
	// Determine the original URL the browser was trying to reach (relay URL).
	relayURL := r.URL.String()
	if r.Host != "" {
		relayURL = "http://" + r.Host + r.URL.RequestURI()
	}

	// Email domain hint.
	emailHint := r.Header.Get("X-Proxy-Email-Hint")
	if emailHint == "" {
		emailHint = r.URL.Query().Get("email")
	}
	if emailHint != "" {
		if at := strings.LastIndex(emailHint, "@"); at >= 0 {
			domain := emailHint[at+1:]
			if prov := idpRegistry.RouteByDomain(domain); prov != nil {
				return prov.CaptiveLoginURL(relayURL, r)
			}
		}
	}

	// Single provider — redirect directly without selection screen.
	providers := idpRegistry.EnabledProviders()
	if len(providers) == 1 {
		return providers[0].CaptiveLoginURL(relayURL, r)
	}
	// Multiple providers — send to selection page.
	if len(providers) > 1 {
		return fmt.Sprintf("/auth/select?relay=%s", url.QueryEscape(relayURL))
	}

	// Legacy single OIDC provider.
	return cfg.OIDCLoginURL()
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
	if len(parts[0]) > maxUsernameLen {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// maxRequestBody is the largest body we'll forward for non-tunnel requests.
// CONNECT tunnels and WebSocket upgrades bypass this limit (they stream raw TCP).
const maxRequestBody = 64 << 20 // 64 MB

// countingReader wraps an io.ReadCloser and counts bytes read through it.
type countingReader struct {
	r     io.ReadCloser
	count int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.count += int64(n)
	return n, err
}
func (cr *countingReader) Close() error { return cr.r.Close() }

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}

	// Wrap request body to count bytes sent upstream.
	var reqCounter countingReader
	if r.Body != nil {
		reqCounter.r = r.Body
		r.Body = &reqCounter
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
		if isDNSError(err) {
			go fireAlert("dns_failure", AlertPayload{Host: r.Host, Detail: err.Error(), Source: "proxy"})
		}
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
		recordRequest(cip, r.Method, r.Host, "FILE_BLOCKED", ext, "", r.Header.Get("X-User-Identity"), "inspect")
		logger.Printf("FILE_BLOCKED (resp cd) %s -> %q%q (ext=%q)", cip, sanitizeLog(r.Host), sanitizeLog(r.URL.Path), sanitizeLog(ext))
		serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
		return
	}

	// File block — check Content-Type MIME for dangerous types.
	// Catches renamed executables (e.g. malware.exe → malware.txt) where the
	// server still reports the true MIME type in the Content-Type header.
	if ext := fileBlocker.CheckContentType(resp.Header.Get("Content-Type")); ext != "" {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		atomic.AddInt64(&statFileBlocked, 1)
		atomic.AddInt64(&statBlocked, 1)
		recordRequest(cip, r.Method, r.Host, "FILE_BLOCKED", ext, "", r.Header.Get("X-User-Identity"), "inspect")
		logger.Printf("FILE_BLOCKED (resp ct) %s -> %q%q (ext=%q)", cip, sanitizeLog(r.Host), sanitizeLog(r.URL.Path), sanitizeLog(ext))
		serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
		return
	}

	// Security body scan (ClamAV + YARA) for non-tunnel HTTP responses.
	// Skip buffering if Content-Length signals the response exceeds the
	// scan limit — avoids wasting memory and I/O on oversized bodies.
	scanActive := globalRemoteScanner.Enabled() || globalSecScanner.BodyScanEnabled()
	// Tier 3.3: admin-managed host allowlist short-circuits the whole pipeline
	// so known-good hosts (e.g. internal content mirrors) aren't buffered.
	if scanActive && globalScanExclusions.IsHostExcluded(r.Host) {
		scanActive = false
	}
	if scanActive && resp.ContentLength > globalSecScanner.MaxBytes() {
		cip, _, _ := net.SplitHostPort(r.RemoteAddr)
		logScanLimitExceeded(r.Host, cip, globalSecScanner.MaxBytes())
	}
	if scanActive && (resp.ContentLength < 0 || resp.ContentLength <= globalSecScanner.MaxBytes()) {
		buffered, readErr := io.ReadAll(io.LimitReader(resp.Body, globalSecScanner.MaxBytes()))
		if readErr == nil {
			// 1.1 fix: decompress gzip/deflate bodies before scanning so
			// ClamAV/YARA signatures match the actual content.
			scanData := decompressForScan(buffered, resp.Header.Get("Content-Encoding"))

			// F4: Archive magic byte detection — block archives even if
			// the URL/Content-Disposition doesn't reveal the true format.
			if archType := IsBlockedArchive(scanData); archType != "" {
				cip3, _, _ := net.SplitHostPort(r.RemoteAddr)
				atomic.AddInt64(&statFileBlocked, 1)
				atomic.AddInt64(&statBlocked, 1)
				recordRequest(cip3, r.Method, r.Host, "FILE_BLOCKED", "magic:"+archType, "", r.Header.Get("X-User-Identity"), "inspect")
				logger.Printf("FILE_BLOCKED (magic) %s -> %q (type=%s)", cip3, sanitizeLog(r.Host), archType)
				serveBlockPage(w, r.Host+r.URL.Path, "File Block", "magic:"+archType)
				return
			}

			// F5: Polyglot detection — block files whose Content-Type
			// doesn't match their actual magic bytes (disguised executables).
			if reason := CheckMagicVsContentType(scanData, resp.Header.Get("Content-Type")); reason != "" {
				cip3, _, _ := net.SplitHostPort(r.RemoteAddr)
				atomic.AddInt64(&statFileBlocked, 1)
				atomic.AddInt64(&statBlocked, 1)
				recordRequest(cip3, r.Method, r.Host, "POLYGLOT_BLOCKED", reason, "", r.Header.Get("X-User-Identity"), "inspect")
				logger.Printf("POLYGLOT_BLOCKED %s -> %q (%s)", cip3, sanitizeLog(r.Host), sanitizeLog(reason))
				serveBlockPage(w, r.Host+r.URL.Path, "Polyglot Detection", reason)
				return
			}

			scanResult := safeScanBodyWithCT(scanData, resp.Header.Get("Content-Type"))
			if scanResult != nil {
				cip2, _, _ := net.SplitHostPort(r.RemoteAddr)
				atomic.AddInt64(&statBlocked, 1)
				// Fire scan_timeout alert for infrastructure monitoring (Finding 8.3).
				if scanResult.Source == "timeout" {
					go fireAlert("scan_timeout", AlertPayload{
						Actor:  cip2,
						Host:   r.Host,
						Detail: scanResult.Reason,
						Source: "scan_timeout",
					})
				}
				recordRequest(cip2, r.Method, r.Host, "SCAN_BLOCKED", scanResult.Source, scanResult.Reason, r.Header.Get("X-User-Identity"), "inspect")
				logger.Printf("SCAN_BLOCKED %s -> %q (%q: %q)", cip2, sanitizeLog(r.Host), sanitizeLog(scanResult.Source), sanitizeLog(scanResult.Reason))
				scanBlock(w, r.Host, scanResult.Reason, scanResult.Source)
				return
			}
			// Reassemble: buffered prefix + any remaining bytes beyond the limit.
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buffered), resp.Body))
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	respBytes, err := io.Copy(w, resp.Body)
	if err != nil {
		logger.Printf("HTTP response copy error for %q: %v", sanitizeLog(r.Host), err)
	}

	// Track bytes transferred for data exfiltration detection.
	atomic.AddInt64(&statBytesSent, reqCounter.count)
	atomic.AddInt64(&statBytesRecv, respBytes)
}

// sanitizeLog strips newlines, carriage returns, and tabs from s to prevent
// log forging (CWE-117). Uses strings.ReplaceAll so that CodeQL recognises
// the sanitisation (go/log-injection).
func sanitizeLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "_")
	s = strings.ReplaceAll(s, "\r", "_")
	s = strings.ReplaceAll(s, "\t", "_")
	return s
}

// isSafeRedirectURL returns true only for absolute http/https URLs whose host
// resolves to a public IP. This prevents javascript: URIs, protocol-relative
// open redirects, and SSRF via redirect to internal/private destinations.
func isSafeRedirectURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	// isPrivateHost returns nil only when all resolved IPs are public.
	// DNS failure now also returns an error (fail-closed), so unresolvable
	// hosts are rejected as unsafe redirect destinations.
	return isPrivateHost(u.Host) == nil
}

// isDNSError returns true when err wraps a *net.DNSError.
func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
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

	if err := isPrivateHost(host); err != nil {
		logger.Printf("WS SSRF block %q: %v", sanitizeLog(host), err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	destConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", host)
	if err != nil {
		logger.Printf("WS dial error %q: %v", sanitizeLog(host), err)
		if isDNSError(err) {
			go fireAlert("dns_failure", AlertPayload{Host: host, Detail: err.Error(), Source: "proxy"})
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

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

	// Bridge: drain any buffered bytes from the target first.
	// B2: Each relay closes its own dst write half after copy completes.
	done := make(chan struct{}, 2)
	relayWS := func(dst net.Conn, src io.Reader) {
		bp := getRelayBuf()
		io.CopyBuffer(dst, src, *bp) //nolint:errcheck
		relayBufPool.Put(bp)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite() //nolint:errcheck
		}
		done <- struct{}{}
	}
	go relayWS(clientConn, br)       // target → client (br may have buffered bytes)
	go relayWS(destConn, clientConn) // client → target
	<-done
	<-done
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
		handleTunnelBypass(w, r)
	}
}

// upstreamTransport is a shared http.Transport used by handleHTTP so that
// connections to upstream servers are pooled across requests, avoiding the
// overhead of a new TCP/TLS handshake per proxied request.
var upstreamTransport = &http.Transport{
	MaxIdleConns:          512,
	MaxIdleConnsPerHost:   64,
	MaxConnsPerHost:       0, // unlimited — let the OS handle it
	IdleConnTimeout:       120 * time.Second,
	TLSHandshakeTimeout:  10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	DisableCompression:    false,
	WriteBufferSize:       64 * 1024, // 64 KB
	ReadBufferSize:        64 * 1024, // 64 KB
}

// applyUpstreamProxy configures the shared transport to route through parent
// proxies when the upstream pool is active.
func applyUpstreamProxy() {
	if upstreamPool.Enabled() {
		upstreamTransport.Proxy = upstreamPool.ProxyFunc()
	}
}

// handleTunnelBypass is the original transparent TCP tunnel (Bypass mode).
func handleTunnelBypass(w http.ResponseWriter, r *http.Request) {
	if err := isPrivateHost(r.Host); err != nil {
		logger.Printf("CONNECT SSRF block %q: %v", sanitizeLog(r.Host), err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	destConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", r.Host)
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
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	recordActiveConn(1)
	defer recordActiveConn(-1)

	done := make(chan struct{}, 2)
	// B2: Each relay closes its own dst write half after copy completes,
	// signaling EOF to the remote peer without interfering with the other
	// relay's writes. This prevents the race where CloseWrite on one
	// connection kills an in-flight write from the other direction.
	relay := func(dst, src net.Conn) {
		bp := getRelayBuf()
		io.CopyBuffer(dst, src, *bp) //nolint:errcheck
		relayBufPool.Put(bp)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite() //nolint:errcheck
		}
		done <- struct{}{}
	}
	go relay(destConn, clientConn)
	go relay(clientConn, destConn)
	<-done
	<-done
}

// handleTunnelInspect performs SSL inspection (MITM) for CONNECT tunnels.
// It terminates TLS on both sides using on-the-fly certificates signed by the
// internal Root CA, allowing the proxy to inspect decrypted HTTP/1.x traffic.
// tlsSkipVerify disables upstream certificate validation for specific policy
// rules (e.g. internal sites with self-signed certs); use with caution.
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
	rawUpstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", targetHost)
	if err != nil {
		logger.Printf("inspect dial error %q: %v", sanitizeLog(targetHost), err)
		if isDNSError(err) {
			go fireAlert("dns_failure", AlertPayload{Host: targetHost, Detail: err.Error(), Source: "proxy"})
		}
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
		logWarnf("SSLInspect: skipping upstream cert verify for %q (tlsSkipVerify rule)", sanitizeLog(hostOnly))
		upstreamTLSCfg = &tls.Config{
			ServerName:         hostOnly,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // #nosec G402 — admin-configured per-rule override
		}
	} else {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			// Fail-closed: empty pool rejects all unknown CAs.
			logWarnf("TLS: SystemCertPool unavailable, using empty pool (will reject all unknown CAs): %v", err)
			systemRoots = x509.NewCertPool()
		}
		upstreamTLSCfg = &tls.Config{
			ServerName: hostOnly,
			MinVersion: tls.VersionTLS12,
			RootCAs:    systemRoots,
		}
	}
	upstreamTLS := tls.Client(rawUpstream, upstreamTLSCfg)
	if err := upstreamTLS.HandshakeContext(r.Context()); err != nil {
		upstreamTLS.Close() // closes both TLS and underlying TCP conn
		logger.Printf("upstream TLS handshake error %q: %v", sanitizeLog(targetHost), err)
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

	// 3b. Peek the first byte from the client to detect the protocol.
	// TLS ClientHello starts with 0x16 (handshake record). If the client
	// is sending SSH, RDP, or another non-TLS protocol through CONNECT,
	// fall back to raw relay instead of crashing on TLS handshake.
	peekBuf := bufio.NewReaderSize(rawClient, 1)
	firstByte, err := peekBuf.Peek(1)
	if err != nil {
		rawClient.Close()              //nolint:errcheck // best-effort cleanup on peek failure
		upstreamTLS.Close()            //nolint:errcheck // best-effort cleanup on peek failure
		logger.Printf("SSL_INSPECT peek error for %q: %v", sanitizeLog(hostOnly), err)
		return
	}
	if firstByte[0] != 0x16 { // not a TLS handshake record
		proto := detectProtocolName(firstByte[0])
		logger.Printf("SSL_INSPECT non-TLS protocol detected for %q (first byte=0x%02x, proto=%s) — falling back to raw relay",
			sanitizeLog(hostOnly), firstByte[0], proto)
		// Raw relay: splice the peeked reader (client) ↔ upstream (already TLS-connected)
		done := make(chan struct{}, 2)
		relay := func(dst io.Writer, src io.Reader) {
			bp := getRelayBuf()
			io.CopyBuffer(dst, src, *bp) //nolint:errcheck
			relayBufPool.Put(bp)
			done <- struct{}{}
		}
		go relay(upstreamTLS, peekBuf) // client → upstream
		go relay(rawClient, upstreamTLS) // upstream → client
		<-done
		rawClient.Close()
		upstreamTLS.Close()
		<-done
		return
	}

	// 4. Perform TLS handshake with the client using a dynamically-signed cert.
	// Wrap rawClient with the peek buffer so the already-peeked byte isn't lost.
	clientTLS := tls.Server(readerConn{Conn: rawClient, r: peekBuf}, &tls.Config{
		GetCertificate: certMgr.GetCert,
		// Force HTTP/1.1 — the inner request loop uses http.ReadRequest which
		// is HTTP/1.x only. Without this, browsers negotiate HTTP/2 via ALPN
		// and the parser can't read H2 frames, causing a silent fallback to
		// raw relay with zero file-blocking/DPI/scanning checks.
		NextProtos: []string{"http/1.1"},
	})
	if err := clientTLS.HandshakeContext(r.Context()); err != nil {
		clientTLS.Close()  //nolint:errcheck // best-effort cleanup on handshake failure
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
		clientTLS.SetReadDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck
		// Read next HTTP/1.x request from the (decrypted) client stream.
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			break
		}
		clientTLS.SetReadDeadline(time.Time{}) //nolint:errcheck // clear deadline for forwarding

		// Debug: log every inner request so admins can trace file-blocking decisions.
		// All values are sanitized or hardcoded to satisfy CodeQL CWE-117.
		filterStr := "off"
		profileStr := ""
		if match != nil && match.Rule != nil && match.Rule.FileFiltering {
			filterStr = "on"
			profileStr = sanitizeLog(string(match.Rule.FileProfile))
		}
		logger.Printf("SSL_INNER %s %s %s%s (profile=%q filter=%s)", sanitizeLog(clientIP), sanitizeLog(req.Method), sanitizeLog(hostOnly), sanitizeLog(req.URL.Path), profileStr, filterStr)
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
		// These checks mirror the file-blocking logic in handleHTTP and the
		// pre-policy global check in handleRequest. They run before any data
		// is written to the client, so a clean 403 is safe to inject.

		// 1. Global file extension blocklist — check the inner request URL.
		if ext := fileBlocker.CheckPath(req.URL.Path); ext != "" {
			atomic.AddInt64(&statFileBlocked, 1)
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, "CONNECT", hostOnly, "FILE_BLOCKED", ext, "", "", "inspect")
			resp.Body.Close()
			fileBlockConn(clientTLS, hostOnly, req.URL.Path, ext, "global ext")
			break
		}
		// 2. Per-rule file profile — check the inner request URL against the
		//    file-extension profile attached to the matched policy rule.
		if match != nil && match.Rule != nil && match.Rule.FileProfileBlocked(req.URL.Path) {
			atomic.AddInt64(&statFileBlocked, 1)
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, "CONNECT", hostOnly, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, "", "inspect")
			resp.Body.Close()
			fileBlockConn(clientTLS, hostOnly, req.URL.Path, string(match.Rule.FileProfile), "policy profile")
			break
		}
		// 3. Content-Disposition header — catches downloads that use a generic
		//    URL but declare the real filename in the response header.
		if cd := resp.Header.Get("Content-Disposition"); cd != "" {
			if ext := fileBlocker.CheckContentDisposition(cd); ext != "" {
				atomic.AddInt64(&statFileBlocked, 1)
				atomic.AddInt64(&statBlocked, 1)
				recordRequest(clientIP, "CONNECT", hostOnly, "FILE_BLOCKED", ext, "", "", "inspect")
				resp.Body.Close()
				fileBlockConn(clientTLS, hostOnly, req.URL.Path, ext, "content-disposition")
				break
			}
			// Per-rule profile: check the CD filename against the matched rule's
			// file profile (catches SourceForge-style /files/latest/download URLs).
			if match != nil && match.Rule != nil && match.Rule.FileFiltering && match.Rule.FileProfile != "" {
				if fn := extractCDFilename(cd); fn != "" {
					if match.Rule.FileProfileBlocked(fn) {
						atomic.AddInt64(&statFileBlocked, 1)
						atomic.AddInt64(&statBlocked, 1)
						recordRequest(clientIP, "CONNECT", hostOnly, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, "", "inspect")
						resp.Body.Close()
						fileBlockConn(clientTLS, hostOnly, fn, string(match.Rule.FileProfile), "policy profile (content-disposition)")
						break
					}
				}
			}
		}
		// 4. Content-Type MIME — catches renamed executables where the server
		//    still reports the true MIME type.
		if ext := fileBlocker.CheckContentType(resp.Header.Get("Content-Type")); ext != "" {
			atomic.AddInt64(&statFileBlocked, 1)
			atomic.AddInt64(&statBlocked, 1)
			recordRequest(clientIP, "CONNECT", hostOnly, "FILE_BLOCKED", ext, "", "", "inspect")
			resp.Body.Close()
			fileBlockConn(clientTLS, hostOnly, req.URL.Path, ext, "content-type")
			break
		}

		// WebSocket upgrade: the protocol switches after the 101 handshake.
		// Write the 101 response to the client and fall back to raw relay.
		if resp.StatusCode == http.StatusSwitchingProtocols {
			resp.Write(clientTLS) //nolint:errcheck
			resp.Body.Close()
			done := make(chan struct{}, 2)
			rawRelay := func(dst, src net.Conn) {
				bp := getRelayBuf()
				io.CopyBuffer(dst, src, *bp) //nolint:errcheck
				relayBufPool.Put(bp)
				done <- struct{}{}
			}
			go rawRelay(upstreamTLS, clientTLS)
			go rawRelay(clientTLS, upstreamTLS)
			<-done
			// Unblock the peer goroutine by closing both TLS connections.
			// tls.Conn has no CloseWrite, so full Close is used instead.
			clientTLS.Close()
			upstreamTLS.Close()
			<-done
			return
		}

		// Unified scan buffer: DPI signatures + ClamAV + YARA.
		// We buffer up to maxScanBufferBytes() before forwarding so any match
		// blocks the response entirely (true prevention, not merely logging).
		ct := resp.Header.Get("Content-Type")
		// Tier 3.3/3.4: admin-managed host allowlists short-circuit buffering.
		hostExcluded := globalScanExclusions.IsHostExcluded(hostOnly)
		dpiBypassed := dpiScanner.IsBypassHost(hostOnly)
		if !hostExcluded && bodyNeedsBuffering(ct) {
			origBody := resp.Body
			body, readErr := io.ReadAll(io.LimitReader(origBody, maxScanBufferBytes()))
			if readErr != nil {
				origBody.Close()
				logger.Printf("SSL_INSPECT: body read error for %q: %v", sanitizeLog(hostOnly), readErr)
				break
			}
			if readErr == nil {
				// 1.1 fix: decompress gzip/deflate bodies before scanning so
				// ClamAV/YARA signatures match the actual content.
				ce := resp.Header.Get("Content-Encoding")
				scanBody := decompressForScan(body, ce)

				// File blocking: magic byte detection — block archives even
				// if the URL/Content-Disposition doesn't reveal the format.
				if archType := IsBlockedArchive(scanBody); archType != "" {
					origBody.Close()
					atomic.AddInt64(&statFileBlocked, 1)
					atomic.AddInt64(&statBlocked, 1)
					recordRequest(clientIP, "CONNECT", hostOnly, "FILE_BLOCKED", "magic:"+archType, "", "", "inspect")
					fileBlockConn(clientTLS, hostOnly, req.URL.Path, "magic:"+archType, "magic bytes")
					break
				}
				// File blocking: polyglot detection — block files whose
				// Content-Type doesn't match their actual magic bytes.
				if reason := CheckMagicVsContentType(scanBody, ct); reason != "" {
					origBody.Close()
					atomic.AddInt64(&statFileBlocked, 1)
					atomic.AddInt64(&statBlocked, 1)
					recordRequest(clientIP, "CONNECT", hostOnly, "POLYGLOT_BLOCKED", reason, "", "", "inspect")
					fileBlockConn(clientTLS, hostOnly, req.URL.Path, reason, "polyglot")
					break
				}

				// ── CDR (Sluice content disarm & reconstruction) ──
				// Runs BEFORE ClamAV/YARA so downstream scanners see the
				// sanitized bytes if CDR stripped active content.  No-op
				// (single atomic load) when CDR is disabled.
				cdrDecision := runCDRStage(r, req, body, scanBody, ct, ce, clientTLS, hostOnly, clientIP, id)
				if cdrDecision.blocked {
					origBody.Close()
					break
				}
				body = cdrDecision.body
				scanBody = cdrDecision.scanBody

				// When remote scan service is active, delegate all scanning
				// (ClamAV + YARA + DPI) in a single remote call.
				if globalRemoteScanner.Enabled() {
					if scanResult := safeScanBodyWithCT(scanBody, ct); scanResult != nil {
						if scanResult.Source == "timeout" {
							go fireAlert("scan_timeout", AlertPayload{Actor: clientIP, Host: hostOnly, Detail: scanResult.Reason, Source: "scan_timeout"})
						}
						origBody.Close()
						atomic.AddInt64(&statBlocked, 1)
						recordRequest(clientIP, "CONNECT", hostOnly, "SCAN_BLOCKED", scanResult.Source, scanResult.Reason, "", "inspect")
						scanBlockConn(clientTLS, hostOnly, scanResult.Reason, scanResult.Source)
						break
					}
				} else {
					// DPI regex scan (text content only).
					// Tier 3.4: respect per-host DPI bypass list.
					if !dpiBypassed && dpiScanner.Enabled() && isTextContentType(ct) {
						if pattern, matched := safeDPIScan(scanBody); matched {
							origBody.Close()
							recordRequest(clientIP, "CONNECT", hostOnly, "DPI_BLOCKED", "", pattern, "", "inspect")
							dpiBlock(clientTLS, hostOnly, pattern)
							break
						}
					}
					// ClamAV + YARA body scan (all content types).
					if scanResult := safeScanBody(scanBody); scanResult != nil {
						if scanResult.Source == "timeout" {
							go fireAlert("scan_timeout", AlertPayload{Actor: clientIP, Host: hostOnly, Detail: scanResult.Reason, Source: "scan_timeout"})
						}
						origBody.Close()
						atomic.AddInt64(&statBlocked, 1)
						recordRequest(clientIP, "CONNECT", hostOnly, "SCAN_BLOCKED", scanResult.Source, scanResult.Reason, "", "inspect")
						scanBlockConn(clientTLS, hostOnly, scanResult.Reason, scanResult.Source)
						break
					}
				}
				// No match: reassemble the body (buffered prefix + remaining bytes).
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), origBody))
			}
		}

		closeAfter := req.Close || resp.Close
		removeHopHeaders(resp.Header)
		if err := resp.Write(clientTLS); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		if closeAfter {
			break
		}
	}
	clientTLS.Close()
	upstreamTLS.Close()
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
