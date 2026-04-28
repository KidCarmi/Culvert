package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// tlsErrorFilter is an io.Writer that suppresses noisy TLS handshake errors
// from Go's http.Server.ErrorLog. These are expected when clients connect to
// a self-signed admin UI and reject the certificate.
type tlsErrorFilter struct{}

func (f *tlsErrorFilter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil // silently discard
	}
	// Forward non-TLS errors to the application logger.
	logger.Printf("HTTP: %s", strings.TrimSpace(string(p)))
	return len(p), nil
}

// cspNonce generates a cryptographically random 16-byte base64 nonce for CSP.
func cspNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure means the system entropy source is broken.
		// Fail closed: return an empty nonce so the CSP blocks all scripts
		// rather than allowing a predictable nonce to bypass the policy.
		logger.Printf("ERROR: crypto/rand failed for CSP nonce: %v", err)
		return ""
	}
	return hex.EncodeToString(b)
}

// cspNonceKey is the context key for passing the per-request CSP nonce from
// the index.html handler to securityMiddleware.
type cspNonceKey struct{}

// uiAllowedNets is the optional allowlist for admin panel access.
// Empty = allow from any IP. Populated via -ui-allow-ip flag or /api/ui-allow-ips.
var (
	uiAllowedNetsMu sync.RWMutex
	uiAllowedNets   []*net.IPNet
)

// AddUIAllowedCIDR adds a CIDR to the UI access allowlist.
func AddUIAllowedCIDR(cidr string) error {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		// Try as bare IP.
		ip := net.ParseIP(strings.TrimSpace(cidr))
		if ip == nil {
			return fmt.Errorf("invalid IP/CIDR: %s", cidr)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	uiAllowedNetsMu.Lock()
	uiAllowedNets = append(uiAllowedNets, n)
	uiAllowedNetsMu.Unlock()
	return nil
}

// SetUIAllowedCIDRs replaces the full allowlist.
func SetUIAllowedCIDRs(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			ip := net.ParseIP(c)
			if ip == nil {
				return fmt.Errorf("invalid IP/CIDR: %s", c)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		nets = append(nets, n)
	}
	uiAllowedNetsMu.Lock()
	uiAllowedNets = nets
	uiAllowedNetsMu.Unlock()
	return nil
}

// ListUIAllowedCIDRs returns the current allowlist as strings.
func ListUIAllowedCIDRs() []string {
	uiAllowedNetsMu.RLock()
	defer uiAllowedNetsMu.RUnlock()
	out := make([]string, len(uiAllowedNets))
	for i, n := range uiAllowedNets {
		out[i] = n.String()
	}
	return out
}

// uiIPGuardMiddleware blocks requests from IPs not in uiAllowedNets.
// When the allowlist is empty all IPs are permitted (default behaviour).
func uiIPGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uiAllowedNetsMu.RLock()
		allowed := uiAllowedNets
		uiAllowedNetsMu.RUnlock()
		if len(allowed) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		for _, cidr := range allowed {
			if ip != nil && cidr.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Forbidden: admin panel access restricted by IP", http.StatusForbidden)
	})
}

// securityMiddleware sets restrictive CORS and security headers.
// CSRF protection is based on same-origin check (Origin == Host), not
// localhost-only, so the UI works from any IP the admin uses.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ── Security headers ─────────────────────────────────────────────────
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// CSP: generate a per-request nonce and pass it to handlers via context.
		// The index.html handler reads this to inject into <script> tags.
		nonce := cspNonce()
		r = r.WithContext(context.WithValue(r.Context(), cspNonceKey{}, nonce))
		w.Header().Set("Content-Security-Policy",
			fmt.Sprintf("default-src 'self'; frame-ancestors 'none'; script-src 'self' 'nonce-%s' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://flagcdn.com; connect-src 'self'", nonce))

		// ── CORS: allow same-origin requests (reflect the origin back) ───────
		origin := r.Header.Get("Origin")
		if origin != "" && isSameOrigin(r, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// ── CSRF: reject state-changing requests from a foreign origin ────────
		// Browsers send Origin on cross-site requests; if it's present and
		// doesn't match our Host header it's a cross-site forgery attempt.
		// Requests without Origin (curl, API clients) are allowed through.
		isMutating := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete
		if origin != "" && !isSameOrigin(r, origin) && isMutating {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// ── Body size limit on mutating requests ─────────────────────────────
		if isMutating {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
		}

		// ── API rate limit on mutating requests ──────────────────────────────
		if isMutating && strings.HasPrefix(r.URL.Path, "/api/") {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			if !apiLimiter.Allow(ip) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isSameOrigin returns true when the Origin header matches the request's Host.
// This is the correct CSRF protection for single-origin admin UIs: any IP is
// fine as long as the request comes from the same scheme+host+port as the UI.
// When Culvert sits behind a reverse proxy, X-Forwarded-Host carries the
// original Host header — we accept that as an alternative match target.
func isSameOrigin(r *http.Request, origin string) bool {
	if origin == "" {
		return true // no Origin = direct tool access — not a browser cross-site request
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := u.Host
	if strings.EqualFold(originHost, r.Host) {
		return true
	}
	// Behind a reverse proxy the original Host is forwarded as X-Forwarded-Host.
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" && strings.EqualFold(originHost, fwd) {
		return true
	}
	return false
}

// uiAuthMiddleware gates /api/ endpoints with session-cookie auth and injects
// the authenticated user's UIRole into the request context for RBAC checks.
// Static assets (/) and bootstrap + auth endpoints are always public.
// HTTP Basic Auth is accepted as a fallback for CLI / API clients.
func uiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always public: setup bootstrap, specific auth endpoints (login/logout/status),
		// IdP callbacks, and /proxy.pac (Windows clients need it without credentials).
		// NOTE: /api/auth/users is intentionally NOT in this list — it requires admin role.
		if strings.HasPrefix(r.URL.Path, "/api/setup") ||
			r.URL.Path == "/api/auth/login" ||
			r.URL.Path == "/api/auth/logout" ||
			r.URL.Path == "/api/auth/status" ||
			strings.HasPrefix(r.URL.Path, "/api/auth/totp") ||
			strings.HasPrefix(r.URL.Path, "/auth/") ||
			r.URL.Path == "/proxy.pac" {
			next.ServeHTTP(w, r)
			return
		}
		// Auth not yet configured — first-time or intentionally disabled.
		if !cfg.AuthEnabled() {
			ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Gate only /api/ endpoints; static assets are always public.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// Check session cookie (browser login via login overlay).
		sess, err := readUISessionCookie(r)
		if err == nil && sess != nil {
			// Reject sessions for deleted users (Finding 5.2).
			if sess.Provider == "local" && !cfg.UIUserExists(sess.Sub) {
				clearUISessionCookie(w, r)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			role := UIRole(sess.Role)
			if !role.HasRole(RoleViewer) {
				role = RoleAdmin // backwards compat: sessions without role = admin
			}
			ctx := context.WithValue(r.Context(), uiRoleKey{}, role)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Fallback: HTTP Basic Auth for programmatic / CLI access.
		user, pass, ok := r.BasicAuth()
		if ok {
			if role, valid := cfg.VerifyUIUser(user, pass); valid {
				ctx := context.WithValue(r.Context(), uiRoleKey{}, role)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		// No valid auth — 401 without WWW-Authenticate: Basic so the browser
		// does NOT show its native credential dialog.
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
