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
	"sync"
	"sync/atomic"
	"time"

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

	// SEC-BOOTSTRAP-HOST-1 — the rendered script is documented to be piped
	// into `sudo bash`, and both of the values below are request-derived. They
	// are validated BEFORE any header is written, so a refusal is a clean 400
	// and never a half-written artifact. Fail closed: a Control Plane that
	// cannot name itself as a plain host[:port] does not get to emit a
	// root-executed script naming something else.
	cpHost, hostOK := bootstrap.SafeAuthority(r.Host)
	cpBase, baseOK := bootstrap.BaseURL(r, trustForwardedHeaders)
	if !hostOK || !baseOK {
		noteBootstrapHostRefused("script")
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=culvert-bootstrap.sh")
	if err := bootstrap.RenderScript(w, cpHost, cpBase, token); err != nil {
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
	// The bare path "/api/cluster/bootstrap/compose" (no token segment) has
	// prefix and suffix overlapping on the separating slash: it satisfies
	// both HasPrefix and HasSuffix, but len(path) < len(prefix)+len(suffix),
	// which would make the slice below start past its end and panic. Reject
	// it here instead — this path is reachable without session auth (its
	// own token is meant to be the auth), so a malformed/attacker request
	// must not be able to crash the handler goroutine.
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) || len(path) < len(prefix)+len(suffix) {
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
	//
	// SEC-BOOTSTRAP-HOST-1: the address is request-derived and the document is
	// run by the DP node, so it is validated before a header is written.
	cpAddr, addrOK := bootstrap.EnrollmentAddr(r, clusterRole.grpcAddr, trustForwardedHeaders)
	if !addrOK {
		noteBootstrapHostRefused("compose")
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	caFP := globalClusterCA.CACertFingerprint()
	enrollURL := fmt.Sprintf("culvert://enroll/%s/%s?ca-fp=sha256:%s", cpAddr, token, caFP)
	if !bootstrap.SafeEnrollURL(enrollURL) {
		// Reachable when the cluster CA is not initialised (no fingerprint).
		// A compose document carrying an unpinned enrollment URL would have a
		// DP node trust whatever answers, so it is refused rather than served.
		http.Error(w, "cluster CA not initialized", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=docker-compose.yml")
	err := bootstrap.RenderCompose(w,
		bootstrap.Image(registrySettingsFile, version),
		enrollURL)
	if err != nil {
		logger.Printf("Bootstrap: compose template error: %v", err)
	}
}

// bootstrapHostRefusedLogGate rate-limits the refusal line. Both bootstrap
// endpoints sit on the public allowlist (their own token is the auth), and the
// token check runs BEFORE this is reached, so only a token holder can drive it
// — but a mitigation for an injection defect must not itself be a
// write-amplification defect (CHAOS-63), so the line is bounded and the counter
// carries the magnitude.
var bootstrapHostRefusedLogGate struct {
	mu sync.Mutex
	at time.Time
}

const bootstrapHostRefusedLogInterval = time.Minute

// bootstrapHostRefused counts artifact renders refused because the request's
// derived authority was not a plain host[:port]. Non-zero means either a
// reverse proxy is forwarding an authority this appliance cannot name itself
// by, or somebody is probing the bootstrap surface with a crafted Host /
// X-Forwarded-Host — the two look identical from here, which is why the value
// is never echoed back to the caller.
var bootstrapHostRefused atomic.Int64

// bootstrapHostRefusedCount reports the refusal counter for the metrics surface.
func bootstrapHostRefusedCount() int64 { return bootstrapHostRefused.Load() }

func noteBootstrapHostRefused(artifact string) {
	n := bootstrapHostRefused.Add(1)

	now := time.Now()
	bootstrapHostRefusedLogGate.mu.Lock()
	due := bootstrapHostRefusedLogGate.at.IsZero() ||
		now.Sub(bootstrapHostRefusedLogGate.at) >= bootstrapHostRefusedLogInterval
	if due {
		bootstrapHostRefusedLogGate.at = now
	}
	bootstrapHostRefusedLogGate.mu.Unlock()

	if due && logger != nil {
		logger.Printf("Bootstrap: refused to render the %s artifact — the request's derived authority "+
			"is not a plain host[:port]; %d refusal(s) so far. Check the reverse proxy's Host / "+
			"X-Forwarded-Host handling.", sanitizeLog(artifact), n)
	}
}
