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
	"sync"
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

// pacConfigAPIMu serializes the legacy-config fence decision with its Set
// (2F-A): the revision check and the commit must be one decision, or two
// admins echoing the same token could both pass and the second silently
// overwrite the first.
var pacConfigAPIMu sync.Mutex

// pacProfiles is the process-wide profiles/pools store (initiative PR 2),
// loaded by the startup slice from <dataDir>/pac_profiles.json. The
// "default" profile is NOT stored here — it is the virtual legacy-backed
// view over pacStore (see internal/pac/profiles.go).
var pacProfiles = &pac.ProfileStore{}

// pacArtifactCache memoizes compiled PAC artifacts keyed on store mod-time,
// so the unauthenticated /proxy.pac and /pac/{id}.pac endpoints do not
// recompile a ~1 MB artifact on every request (Palo perf/security review).
var pacArtifactCache = &pac.ArtifactCache{}

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
		// 2F-A fence: the caller must echo the revision it loaded. Decided
		// under pacConfigAPIMu so the check and the Set are one serialized
		// decision against the authoritative store.
		token := pacFenceInt(r, "revision", c.Revision)
		pacConfigAPIMu.Lock()
		defer pacConfigAPIMu.Unlock()
		if !pacCheckRevision(w, "revision", token, pacStore.Get().Revision) {
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
		canonical.Revision = pacStore.Get().Revision // the token the store just minted
		actor := sessionAdmin(r)
		auditEvent(r, "pac.update", "pac-config", fmt.Sprintf("host=%s port=%d exclusions=%d",
			sanitizeLog(canonical.ProxyHost), canonical.ProxyPort, len(canonical.Exclusions)))
		saveConfigVersion(actor, "pac.update")
		// Republish the cluster snapshot so DPs converge on the next poll —
		// without this, an exclusions change (including a wipe) waits for an
		// UNRELATED mutation to bump the snapshot version (Palo fleet review,
		// ops finding 1).
		_ = publishCurrentConfigSnapshot()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct { //nolint:errcheck // best-effort response write
			PACConfig
			Warnings []pac.ValidationIssue `json:"warnings,omitempty"`
		}{PACConfig: canonical, Warnings: norm.Warnings})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// routeProxyListenerBuiltin dispatches the proxy listener's non-proxied
// built-in endpoints (health/ready/metrics/PAC). It returns true when it
// handled the request; false means the caller must forward to handleRequest.
// These endpoints share the plain-HTTP contract of the proxy port (clients
// fetch without TLS); the r.URL.Host guard keeps PROXIED absolute-URI
// requests (which carry a Host in the URL) out of the local handlers so a
// client proxying `GET http://origin/health` (or /ready, /metrics, /pac/x.pac)
// is forwarded to origin, not hijacked into serving Culvert's own status —
// a forward proxy must not shadow an upstream site's own paths of the same
// name (e.g. an app's own /metrics or /health endpoint).
func routeProxyListenerBuiltin(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/health" && r.URL.Host == "":
		handleHealth(w, r)
	case r.URL.Path == "/ready" && r.URL.Host == "":
		handleReady(w, r)
	case r.URL.Path == "/metrics" && r.URL.Host == "":
		handleMetrics(w, r)
	case r.URL.Path == "/proxy.pac" && r.URL.Host == "":
		servePACFile(w, r)
	case strings.HasPrefix(r.URL.Path, "/pac/") && r.URL.Host == "":
		servePACProfileFile(w, r)
	default:
		return false
	}
	return true
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
	art := pacArtifactCache.Legacy(pacStore, reqHost)
	writePACResponse(w, r, art, pacStore.ModTime(), pac.DefaultProfileID)
	// #nosec G705 -- host is character-allowlisted above; PAC output is %q-quoted JS served as application/x-ns-proxy-autoconfig
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
	art := pacArtifactCache.Profile(pacProfiles, profile)
	writePACResponse(w, r, art, pacProfiles.ModTime(), id)
}

// writePACResponse writes a compiled PAC artifact with the shared
// caching/versioning contract: strong ETag over the actual bytes,
// If-None-Match → 304, and the two cache modes (host-fallback bodies vary
// per request Host and must not be shared-cached).
func writePACResponse(w http.ResponseWriter, r *http.Request, art pac.Artifact, modTime time.Time, profileID string) {
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
	if pacNotModified(r, etag, art, modTime) {
		pacObserveServe(profileID, art, true)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		pacObserveServe(profileID, art, false)
		return // headers already set; HEAD carries no body
	}
	pacObserveServe(profileID, art, false)
	fmt.Fprint(w, art.JS) //nolint:errcheck,gosec // best-effort response write
}

// pacNotModified reports whether the request revalidates to 304. ETag
// (strong) is the primary validator; If-Modified-Since is the date fallback
// for WinHTTP/WinINET clients, honored only in configured (cacheable) mode
// where Last-Modified is sent.
func pacNotModified(r *http.Request, etag string, art pac.Artifact, modTime time.Time) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		return etagMatches(inm, etag)
	}
	if art.HostFallback || modTime.IsZero() {
		return false
	}
	ims := r.Header.Get("If-Modified-Since")
	if ims == "" {
		return false
	}
	t, err := http.ParseTime(ims)
	return err == nil && !modTime.Truncate(time.Second).After(t)
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
	mux.HandleFunc("/api/pac/simulate", apiPACSimulate)
	mux.HandleFunc("/api/pac/analyze", apiPACAnalyze)
	mux.HandleFunc("/api/pac/posture/inventory", apiPACPostureInventory)
	mux.HandleFunc("/api/pac/posture/diff", apiPACPostureDiff)
	mux.HandleFunc("/api/pac/posture/exceptions", apiPACExceptions)
	mux.HandleFunc("/api/pac/posture/exceptions/", apiPACExceptionItem)
}
