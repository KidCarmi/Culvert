package main

import (
	"html"
	"io/fs"
	"net/http"
	"strings"
)

// cachedIndexHTML holds the embedded index.html template with __CSP_NONCE__
// placeholders. Read once at startup so we don't re-read the embed on every
// page load. The placeholder is replaced per-request with the nonce that
// securityMiddleware put in the request context.
var cachedIndexHTML []byte

// loadUIShell pre-reads the SPA index.html from the embedded static FS.
// Called once from startUI; cachedIndexHTML stays empty if the read fails,
// in which case serveUIShell falls back to whatever http.FileServer returns
// (i.e. the original behavior before nonce injection was added).
func loadUIShell(sub fs.FS) {
	if data, err := fs.ReadFile(sub, "index.html"); err == nil {
		cachedIndexHTML = data
	}
}

// serveUIShell returns the SPA shell handler used at "/". It serves the
// index.html with per-request CSP nonce injection; all other static assets
// (logo.png, etc.) are delegated to the supplied staticServer.
func serveUIShell(staticServer http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			// The embedded FS has zero mod-times, so http.FileServer emits no
			// validators — without a policy every load re-downloads the 205 KB
			// chart bundle. The asset only changes with a binary upgrade, so a
			// bounded max-age is safe (worst case: a day-old chart lib that
			// still renders; the nonce'd shell below is never cached).
			if r.URL.Path == "/chart.umd.js" {
				w.Header().Set("Cache-Control", "public, max-age=86400")
			}
			staticServer.ServeHTTP(w, r)
			return
		}
		// Read nonce from context (set by securityMiddleware).
		nonce, _ := r.Context().Value(cspNonceKey{}).(string)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The shell embeds a per-request CSP nonce — a cached copy would carry
		// a stale nonce and every script would be blocked. Never cache it.
		w.Header().Set("Cache-Control", "no-store")
		body := strings.ReplaceAll(string(cachedIndexHTML), "__CSP_NONCE__", html.EscapeString(nonce))
		w.Write([]byte(body)) //nolint:errcheck
	}
}

// registerStaticRoutes wires the SPA shell route. staticServer handles all
// non-shell static assets (logo, css, etc.) via fall-through inside
// serveUIShell.
func registerStaticRoutes(mux *http.ServeMux, staticServer http.Handler) {
	mux.HandleFunc("/", serveUIShell(staticServer))
}
