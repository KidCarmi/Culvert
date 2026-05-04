// Package server hosts the agent's JSON-over-HTTP/1.1 API on a Unix
// domain socket. D1.6a exposes only the read-only foundation surface;
// every state-changing path returns 404 by design and remains 404 until
// the slice that adds it.
//
// Transport (D1.6 plan § 4.3): UDS only, mode 0660, owner
// culvert-maint:culvert-maint. No TCP listener, no 0.0.0.0 option.
//
// Auth (§ 4.4): SO_PEERCRED gate via internal/auth. Peers not on the
// allowlist are rejected with HTTP 403.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/health"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// Version is the agent version string. Overridable at link time:
// `go build -ldflags "-X culvert-maint/internal/server.Version=v0.1.0"`
var Version = "dev"

// StatusProvider returns a snapshot of the operator-facing status payload
// (compose project state, agent posture flags, etc.). The Status package
// implements this; Server consumes it through the interface so the
// server has no docker-compose knowledge.
type StatusProvider interface {
	Snapshot(ctx context.Context) (Status, error)
}

// Status is the JSON shape of GET /v1/status.
type Status struct {
	AgentVersion       string                 `json:"agent_version"`
	PrivilegeMode      string                 `json:"privilege_mode"`
	PrivilegeWarning   string                 `json:"privilege_warning,omitempty"`
	ComposeProjectDir  string                 `json:"compose_project_dir"`
	ComposeFile        string                 `json:"compose_file"`
	ComposeStackUp     bool                   `json:"compose_stack_up"`
	ComposeServices    []ServiceStatus        `json:"compose_services"`
	ComposeError       string                 `json:"compose_error,omitempty"`
	LockHeldBy         *ops.Op                `json:"lock_held_by,omitempty"`
	LastOperationKind  string                 `json:"last_operation_kind,omitempty"`
	LastOperationOpID  string                 `json:"last_operation_op_id,omitempty"`
	LastOperationState string                 `json:"last_operation_state,omitempty"`
	Extra              map[string]interface{} `json:"extra,omitempty"`
}

// ServiceStatus describes one compose service from `docker compose ps`.
type ServiceStatus struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Image string `json:"image,omitempty"`
}

// Options configures Server.
type Options struct {
	Cfg       *config.Config
	Auth      *auth.Policy
	Audit     *audit.Logger
	Ops       *ops.Manager
	Status    StatusProvider
	StateDir  string // for /v1/operations/{id}/logs
	AuditPath string // for GET /v1/audit

	// Runner is the command runner used by D1.6b handlers. May be
	// nil only in unit tests that exercise non-D1.6b paths; the
	// production constructor in main wires a real *runner.Runner.
	Runner *runner.Runner

	// HealthProbeFactory builds a fresh health.Probe per restore
	// operation. May be nil in tests that don't exercise restore.
	HealthProbeFactory func() health.Probe
}

// Server is the agent's HTTP server. Construct with New, run with
// Serve.
type Server struct {
	opts Options

	mu       sync.Mutex
	listener net.Listener
	httpSrv  *http.Server
}

// New constructs a Server. Returns an error if any required option is
// nil.
func New(opts Options) (*Server, error) {
	if opts.Cfg == nil {
		return nil, errors.New("server: Cfg required")
	}
	if opts.Auth == nil {
		return nil, errors.New("server: Auth required")
	}
	if opts.Audit == nil {
		return nil, errors.New("server: Audit required")
	}
	if opts.Ops == nil {
		return nil, errors.New("server: Ops required")
	}
	if opts.Status == nil {
		return nil, errors.New("server: Status required")
	}
	if opts.StateDir == "" {
		return nil, errors.New("server: StateDir required")
	}
	if opts.AuditPath == "" {
		return nil, errors.New("server: AuditPath required")
	}
	return &Server{opts: opts}, nil
}

// listen creates the UDS listener with mode 0660. Removes a stale
// socket file at the path if present.
func listen(path string) (net.Listener, error) {
	// /run is system-managed (0755 typically); mkdir is best-effort
	// for non-/run socket paths in tests. Mode 0750 is fine for any
	// non-/run path the operator points us at.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("server: mkdir socket parent: %w", err)
	}
	// Refuse symlinks at the socket path entirely — even a symlink
	// pointing to a real socket could be a redirect to an
	// attacker-controlled endpoint. Lstat (not Stat) so the symlink
	// itself shows up.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("server: socket path %q is a symlink; refusing to remove or follow", path)
		}
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("server: socket path %q exists and is not a socket; refusing to remove", path)
		}
		// Stale socket from a prior run — safe to remove.
		if rerr := os.Remove(path); rerr != nil {
			return nil, fmt.Errorf("server: remove stale socket: %w", rerr)
		}
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, fmt.Errorf("server: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // 0660 is the documented socket mode
		_ = ln.Close()
		return nil, fmt.Errorf("server: chmod socket: %w", err)
	}
	return ln, nil
}

// Serve binds the UDS, installs the HTTP handler, and serves until ctx
// is cancelled or the listener errors.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := listen(s.opts.Cfg.SocketPath)
	if err != nil {
		return err
	}

	mux := s.routes()
	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey{}, c)
		},
	}

	s.mu.Lock()
	s.listener = ln
	s.httpSrv = httpSrv
	s.mu.Unlock()

	// Shutdown on ctx done. The shutdown grace timer must be detached
	// from ctx (which is already cancelled when this fires), so we
	// build a fresh background context with a short bound. The
	// goroutine has the ctx parameter in scope only to await
	// cancellation; the Shutdown call itself uses its own context.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	err = httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the server and removes the socket file. Safe to call
// multiple times.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
		s.httpSrv = nil
	}
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
	_ = os.Remove(s.opts.Cfg.SocketPath)
	return nil
}

// routes installs the D1.6a route set. Future endpoints are explicitly
// 404'd here so a stray client request never falls through to the
// catch-all. Every /v1/* path is authenticated — including the explicit
// 404 endpoints — so an unauthorised peer cannot enumerate the surface
// (peer gets 403, never 404).
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/health", s.withAuth(s.handleHealth))
	mux.HandleFunc("GET /v1/status", s.withAuth(s.handleStatus))
	mux.HandleFunc("GET /v1/audit", s.withAuth(s.handleAudit))
	mux.HandleFunc("GET /v1/operations/", s.withAuth(s.handleOperationsRouter))

	// D1.6b operation endpoints.
	mux.HandleFunc("POST /v1/backups", s.withAuth(s.handleBackupCreate))
	mux.HandleFunc("GET /v1/backups", s.withAuth(s.handleBackupList))
	mux.HandleFunc("POST /v1/restores/dryrun", s.withAuth(s.handleRestoreDryRun))
	mux.HandleFunc("POST /v1/restores/commit", s.withAuth(s.handleRestoreCommit))
	mux.HandleFunc("POST /v1/cleanups", s.withAuth(s.handleCleanup))

	// Future endpoints — explicit 404, authenticated so an
	// unauthorised peer gets 403 consistently.
	notImpl := s.withAuth(func(w http.ResponseWriter, r *http.Request, _ auth.PeerInfo) {
		s.notImplemented(w, r)
	})
	for _, p := range []string{
		"/v1/upgrades/check",
		"/v1/upgrades/apply",
		"/v1/rollbacks",
	} {
		mux.HandleFunc(p, notImpl)
	}

	// Authenticated catch-all under /v1/* so unknown /v1 paths get a
	// peer-rejection rather than leaking that the path doesn't exist.
	mux.HandleFunc("/v1/", s.withAuth(func(w http.ResponseWriter, r *http.Request, _ auth.PeerInfo) {
		s.notFound(w, r)
	}))

	// Anything outside /v1/* is unauthenticated 404 — these aren't
	// agent endpoints at all.
	mux.HandleFunc("/", s.notFound)

	return mux
}

// withAuth wraps a handler with the SO_PEERCRED gate. Unauthorised
// peers get 403 with no body (no leak about which UIDs are allowed).
func (s *Server) withAuth(h func(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// http.Server gives us the underlying conn via context.
		conn, ok := r.Context().Value(connContextKey{}).(net.Conn)
		if !ok || conn == nil {
			http.Error(w, "{\"error\":\"forbidden\"}", http.StatusForbidden)
			return
		}
		peer, err := auth.Peer(conn)
		if err != nil {
			http.Error(w, "{\"error\":\"forbidden\"}", http.StatusForbidden)
			return
		}
		if err := s.opts.Auth.Allow(peer); err != nil {
			http.Error(w, "{\"error\":\"forbidden\"}", http.StatusForbidden)
			return
		}
		h(w, r, peer)
	}
}

type connContextKey struct{}

// handleHealth responds with a small JSON document.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request, _ auth.PeerInfo) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"agent_version": Version,
	})
}

// handleStatus delegates to the StatusProvider.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ auth.PeerInfo) {
	st, err := s.opts.Status.Snapshot(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "status_provider_failed"})
		return
	}
	if st.AgentVersion == "" {
		st.AgentVersion = Version
	}
	writeJSON(w, http.StatusOK, st)
}

// handleAudit returns the most recent N events. ?limit=N (default 100, max 1000).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ auth.PeerInfo) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			http.Error(w, "{\"error\":\"invalid_limit\"}", http.StatusBadRequest)
			return
		}
		if n > 1000 {
			n = 1000
		}
		limit = n
	}
	events, err := audit.Recent(s.opts.AuditPath, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit_read_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"events": events, "count": len(events)})
}

// handleOperationsRouter dispatches /v1/operations/{id} and
// /v1/operations/{id}/logs.
func (s *Server) handleOperationsRouter(w http.ResponseWriter, r *http.Request, _ auth.PeerInfo) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/operations/")
	if rest == "" {
		s.notFound(w, r)
		return
	}
	if strings.HasSuffix(rest, "/logs") {
		opID := strings.TrimSuffix(rest, "/logs")
		s.handleOperationLogs(w, r, opID)
		return
	}
	s.handleOperationGet(w, r, rest)
}

func (s *Server) handleOperationGet(w http.ResponseWriter, _ *http.Request, opID string) {
	if !validOpID(opID) {
		http.Error(w, "{\"error\":\"invalid_op_id\"}", http.StatusBadRequest)
		return
	}
	op := s.opts.Ops.Get(opID)
	if op == nil {
		http.Error(w, "{\"error\":\"op_not_found\"}", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

func (s *Server) handleOperationLogs(w http.ResponseWriter, _ *http.Request, opID string) {
	if !validOpID(opID) {
		http.Error(w, "{\"error\":\"invalid_op_id\"}", http.StatusBadRequest)
		return
	}
	logPath := filepath.Join(s.opts.StateDir, "operations", opID+".log")
	f, err := os.Open(logPath) // #nosec G304 G703 -- opID validated to ULID via validOpID, joined under StateDir
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "{\"error\":\"log_not_found\"}", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "log_read_failed"})
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = copyStream(w, f)
}

// notImplemented is the explicit handler for endpoints scoped to
// D1.6b/c/d but not yet implemented in this slice.
func (s *Server) notImplemented(w http.ResponseWriter, r *http.Request) {
	http.Error(w, fmt.Sprintf(`{"error":"not_implemented","path":%q}`, r.URL.Path), http.StatusNotFound)
}

// notFound is the catch-all for unknown paths.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, fmt.Sprintf(`{"error":"not_found","path":%q}`, r.URL.Path), http.StatusNotFound)
}

// validOpID accepts only canonical ULIDs (26 chars,
// Base32-Crockford alphabet, no lowercase, no I/L/O/U). Uses
// ulid.ParseStrict so the surface for path-injection in logs is
// bound to exactly the IDs the agent itself emits.
func validOpID(s string) bool {
	if len(s) != 26 {
		return false
	}
	if _, err := ulid.ParseStrict(s); err != nil {
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
