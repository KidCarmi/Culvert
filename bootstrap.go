package main

// bootstrap.go — package-main glue for one-click DP-node bootstrap, moved to
// internal/bootstrap (ADR-0002). The package owns the shell-script and
// docker-compose templates, the image-reference resolution, and the pure
// request-derivation helpers (token extraction, CP base URL, enrollment
// address — with trustForwardedHeaders passed in as a parameter). main keeps
// the HTTP handlers: they validate the single-use enrollment token against
// globalClusterStore and assemble the enrollment URL from cluster state
// (clusterRole, globalClusterCA), which are core-hub singletons.

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/KidCarmi/Culvert/internal/bootstrap"
)

// apiBootstrapRouter routes bootstrap requests to either the shell script
// or the docker-compose.yml handler based on the path suffix.
func apiBootstrapRouter(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/compose") {
		apiBootstrapCompose(w, r)
	} else {
		apiBootstrapScript(w, r)
	}
}

// apiBootstrapScript serves the install script for a given enrollment token.
// GET /api/cluster/bootstrap/{token} — returns shell script (no auth required,
// but the token itself is the auth — it's single-use and time-limited).
func apiBootstrapScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := bootstrap.ExtractToken(r.URL.Path, "/api/cluster/bootstrap/")
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token path", http.StatusBadRequest)
		return
	}

	// Verify token exists (don't consume it — compose download needs it too).
	if !globalClusterStore.TokenExists(token) {
		http.Error(w, "invalid or expired token", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=culvert-bootstrap.sh")
	if err := bootstrap.RenderScript(w, r.Host, bootstrap.BaseURL(r, trustForwardedHeaders), token); err != nil {
		logger.Printf("Bootstrap: script template error: %v", err)
	}
}

// apiBootstrapCompose serves the docker-compose.yml for a given enrollment token.
// GET /api/cluster/bootstrap/{token}/compose — returns YAML (no auth required,
// token is the auth).
func apiBootstrapCompose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract token — path is /api/cluster/bootstrap/{token}/compose
	path := r.URL.Path
	const prefix = "/api/cluster/bootstrap/"
	const suffix = "/compose"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	token := path[len(prefix) : len(path)-len(suffix)]
	if token == "" || strings.Contains(token, "/") {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	// Verify token exists (don't consume — enrollment RPC consumes it).
	if !globalClusterStore.TokenExists(token) {
		http.Error(w, "invalid or expired token", http.StatusNotFound)
		return
	}

	// Build enrollment URL — derive CP host from the HTTP request so the
	// generated docker-compose.yml works from remote machines (not just localhost).
	cpAddr := bootstrap.EnrollmentAddr(r, clusterRole.grpcAddr, trustForwardedHeaders)
	caFP := globalClusterCA.CACertFingerprint()
	enrollURL := fmt.Sprintf("culvert://enroll/%s/%s?ca-fp=sha256:%s", cpAddr, token, caFP)

	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=docker-compose.yml")
	err := bootstrap.RenderCompose(w,
		bootstrap.Image(registrySettingsFile, version),
		enrollURL)
	if err != nil {
		logger.Printf("Bootstrap: compose template error: %v", err)
	}
}
