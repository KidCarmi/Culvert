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
	"time"

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

// pacProfiles is the process-wide profiles/pools store (initiative PR 2),
// loaded by the startup slice from <dataDir>/pac_profiles.json. The
// "default" profile is NOT stored here — it is the virtual legacy-backed
// view over pacStore (see internal/pac/profiles.go).
var pacProfiles = &pac.ProfileStore{}

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

// servePACFile handles GET /proxy.pac — serves the dynamically generated PAC
// file for the default (legacy-backed) profile. /pac/default.pac is the
// stable alias for the same artifact.
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
	writePACResponse(w, r, art, pacStore.ModTime())
	// #nosec G705 -- host is character-whitelisted above; PAC output is %q-quoted JS served as application/x-ns-proxy-autoconfig
}

// servePACProfileFile handles GET /pac/{id}.pac — the stable per-profile PAC
// endpoints. "/pac/default.pac" aliases the legacy-backed default profile
// (byte-identical with /proxy.pac); other IDs resolve enabled custom
// profiles. Unauthenticated by design, like /proxy.pac.
func servePACProfileFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/pac/")
	id := strings.TrimSuffix(name, ".pac")
	if !strings.HasSuffix(name, ".pac") || id == "" {
		http.NotFound(w, r)
		return
	}
	if id == pac.DefaultProfileID {
		servePACFile(w, r)
		return
	}
	if !pac.ValidIdentifier(id) {
		http.NotFound(w, r)
		return
	}
	profile, ok := pacProfiles.ProfileByID(id)
	if !ok || !profile.Enabled {
		http.NotFound(w, r)
		return
	}
	art := pac.CompileProfile(profile, pacProfiles.PoolMap())
	writePACResponse(w, r, art, pacProfiles.ModTime())
}

// writePACResponse writes a compiled PAC artifact with the shared
// caching/versioning contract: strong ETag over the actual bytes,
// If-None-Match → 304, and the two cache modes (host-fallback bodies vary
// per request Host and must not be shared-cached).
func writePACResponse(w http.ResponseWriter, r *http.Request, art pac.Artifact, modTime time.Time) {
	etag := `"` + art.Digest + `"`
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Culvert-PAC-Version", art.CompilerVersion+"-"+art.Digest[:16])
	if art.HostFallback {
		w.Header().Set("Cache-Control", "no-cache, no-store")
	} else {
		w.Header().Set("Cache-Control", "max-age=0, must-revalidate")
		if !modTime.IsZero() {
			w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
		}
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	fmt.Fprint(w, art.JS) //nolint:errcheck,gosec // best-effort response write
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

// registerPACRoutes wires the PAC file endpoints and their admin config API.
// /proxy.pac and the /pac/{id}.pac profile endpoints are intentionally
// unauthenticated (Windows PAC clients cannot send credentials) and are on
// the public-route allowlist in uiAuthMiddleware. The /api/pac/* routes are
// gated like every other /api/*.
func registerPACRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/proxy.pac", servePACFile) // legacy alias for /pac/default.pac
	mux.HandleFunc("/pac/", servePACProfileFile)
	mux.HandleFunc("/api/pac-config", apiPACConfig)
	mux.HandleFunc("/api/pac/profiles", apiPACProfiles)
	mux.HandleFunc("/api/pac/profiles/", apiPACProfileItem)
	mux.HandleFunc("/api/pac/pools", apiPACPools)
	mux.HandleFunc("/api/pac/pools/", apiPACPoolItem)
}
