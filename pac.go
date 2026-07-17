package main

// pac.go — package-main glue for the PAC engine, moved to internal/pac
// (ADR-0002). The alias shim keeps the handlers, the startup slice, the
// cluster PAC sync (controlplane.go), and the test suite using the original
// unqualified names; the HTTP handlers and route registration stay here
// (requireRole/auditEvent/saveConfigVersion are main-owned).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// PACConfig / PACStore re-exposed unqualified (engine types are pac.Config /
// pac.Store).
type (
	PACConfig = pac.Config
	PACStore  = pac.Store
)

// pacStore is the process-wide PAC store, loaded by the startup slice.
var pacStore = &PACStore{}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

// apiPACConfig handles GET/POST /api/pac-config.
func apiPACConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c := pacStore.Get()
		// Include the effective proxy port so the UI can show the right hint.
		if c.ProxyPort == 0 {
			if def := pacStore.DefaultPort(); def > 0 {
				c.ProxyPort = def
			} else {
				c.ProxyPort = 8080
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c) //nolint:errcheck
	case http.MethodPost:
		// PAC config drives every Windows / browser proxy client; mutation is
		// admin-only. Without this gate any authenticated UI user (including
		// RoleViewer) could repoint the entire fleet to a chosen upstream.
		// See docs/C15_UNKNOWN_AUDIT.md §3.1 for the audit finding.
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var c PACConfig
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Strict validation lives HERE, at the API boundary — never in
		// Store.Set, whose replay callers (rollback, cluster apply) discard
		// errors. Invalid input is rejected with actionable per-entry issues.
		norm, issues := pac.ValidateConfig(c)
		if len(issues) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort error body
				"error":  "validation failed",
				"issues": issues,
			})
			return
		}
		// Persist the canonical form (lowercased/punycoded hosts, deduped,
		// host-bits-cleared CIDRs) so on-disk config and generated PAC agree.
		canonical := PACConfig{ProxyHost: norm.ProxyHost, ProxyPort: norm.ProxyPort}
		for _, e := range norm.Exclusions {
			canonical.Exclusions = append(canonical.Exclusions, e.Canonical())
		}
		if err := pacStore.Set(canonical); err != nil {
			http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		actor := sessionAdmin(r)
		auditEvent(r, "pac.update", "pac-config", fmt.Sprintf("host=%s port=%d exclusions=%d",
			sanitizeLog(canonical.ProxyHost), canonical.ProxyPort, len(canonical.Exclusions)))
		saveConfigVersion(actor, "pac.update")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct { //nolint:errcheck // best-effort response write
			PACConfig
			Warnings []pac.ValidationIssue `json:"warnings,omitempty"`
		}{PACConfig: canonical, Warnings: norm.Warnings})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// servePACFile handles GET /proxy.pac — serves the dynamically generated PAC file.
func servePACFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// r.Host is attacker-influenced; strip everything outside RFC-3986
	// host:port characters before it flows into the generated PAC body
	// (gosec G705 taint). GeneratePAC additionally %q-quotes the value and
	// the response is served as application/x-ns-proxy-autoconfig, not HTML.
	reqHost := strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == ':', c == '[', c == ']':
			return c
		}
		return -1
	}, r.Host)
	art := pacStore.Compile(reqHost)
	etag := `"` + art.Digest + `"`

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Culvert-PAC-Version", art.CompilerVersion+"-"+art.Digest[:16])
	if art.HostFallback {
		// The body embeds the request-derived proxy host, so it varies per
		// Host header — a shared cache serving it cross-host would poison
		// clients. Keep the legacy no-store posture in fallback mode.
		w.Header().Set("Cache-Control", "no-cache, no-store")
	} else {
		// Configured proxy host: the body is request-independent, so clients
		// may cache but must revalidate (cheap 304 via the strong ETag).
		w.Header().Set("Cache-Control", "max-age=0, must-revalidate")
		if mt := pacStore.ModTime(); !mt.IsZero() {
			w.Header().Set("Last-Modified", mt.UTC().Format(http.TimeFormat))
		}
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	fmt.Fprint(w, art.JS) //nolint:errcheck,gosec // best-effort response write
	// #nosec G705 -- host is character-whitelisted above; PAC output is %q-quoted JS served as application/x-ns-proxy-autoconfig
}

// etagMatches implements If-None-Match comparison for a single strong ETag:
// "*" matches anything; otherwise each comma-separated candidate matches on
// byte equality, ignoring a weak-validator prefix (weak comparison is
// sufficient for cache revalidation per RFC 9110 §13.1.2).
func etagMatches(ifNoneMatch, etag string) bool {
	if strings.TrimSpace(ifNoneMatch) == "*" {
		return true
	}
	for _, cand := range strings.Split(ifNoneMatch, ",") {
		cand = strings.TrimSpace(cand)
		cand = strings.TrimPrefix(cand, "W/")
		if cand == etag {
			return true
		}
	}
	return false
}

// registerPACRoutes wires the PAC file endpoint and its admin config API.
// /proxy.pac is intentionally unauthenticated (Windows PAC clients cannot
// send credentials) and is on the public-route allowlist in
// uiAuthMiddleware. /api/pac-config is gated like every other /api/*.
func registerPACRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/proxy.pac", servePACFile) // served on the UI port
	mux.HandleFunc("/api/pac-config", apiPACConfig)
}
