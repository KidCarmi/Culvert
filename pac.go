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
		if err := pacStore.Set(c); err != nil {
			http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		actor := sessionAdmin(r)
		auditEvent(r, "pac.update", "pac-config", fmt.Sprintf("host=%s port=%d exclusions=%d",
			sanitizeLog(c.ProxyHost), c.ProxyPort, len(c.Exclusions)))
		saveConfigVersion(actor, "pac.update")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c) //nolint:errcheck
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

	pacBody := pacStore.GeneratePAC(r.Host)
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	fmt.Fprint(w, pacBody) //nolint:errcheck // best-effort response write
}

// registerPACRoutes wires the PAC file endpoint and its admin config API.
// /proxy.pac is intentionally unauthenticated (Windows PAC clients cannot
// send credentials) and is on the public-route allowlist in
// uiAuthMiddleware. /api/pac-config is gated like every other /api/*.
func registerPACRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/proxy.pac", servePACFile) // served on the UI port
	mux.HandleFunc("/api/pac-config", apiPACConfig)
}
