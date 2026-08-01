package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// Route prefixes. Gateway addresses a specific server by opaque id in the path;
// Management is a single fixed path. Each listener serves ONLY its own capability's
// path space — a Management listener never routes a Gateway path and vice versa.
const (
	gatewayPathPrefix = "/mcp/gateway/"
	managementPath    = "/mcp/management"
)

// Listener is one capability's dedicated, bounded HTTP listener. It owns its own
// socket, TLS config, worker pool + admission queue, pipeline (session manager +
// binding store + counters) and shutdown state. Nothing mutable is shared with the
// other capability's listener, so saturation or failure in one can never exhaust or
// degrade the other.
type Listener struct {
	cfg        ListenerConfig
	listenerID string
	pipe       *pipeline
	ctr        *counters
	lim        RuntimeLimits
	clock      func() time.Time

	srv   *http.Server
	netln net.Listener

	// sem bounds concurrent in-flight requests; queue bounds admitted-but-waiting
	// requests beyond the workers. Both are per-listener, so one capability's queue
	// filling up never blocks the other.
	sem   chan struct{}
	queue chan struct{}

	stopCh chan struct{}
	done   chan struct{}
}

// newListener builds a capability listener from a validated config. It constructs
// the dedicated pipeline and the bounded pools but does NOT bind a socket (bind is
// separate so startup can be transactional).
func newListener(cfg ListenerConfig, deps Deps, listenerID string, rev uint64) (*Listener, error) {
	ctr := &counters{}
	ctr.setPhase(PhaseStarting)
	pipe, err := newPipeline(cfg, deps, listenerID, ctr, rev)
	if err != nil {
		return nil, err
	}
	clock := deps.now
	l := &Listener{
		cfg:        cfg,
		listenerID: listenerID,
		pipe:       pipe,
		ctr:        ctr,
		lim:        cfg.Limits,
		clock:      clock,
		sem:        make(chan struct{}, cfg.Limits.MaxConcurrent()),
		queue:      make(chan struct{}, cfg.Limits.QueueDepth()),
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	l.srv = &http.Server{
		Handler:           l,
		ReadHeaderTimeout: cfg.Limits.ReadHeaderTimeout(),
		ReadTimeout:       cfg.Limits.ReadTimeout(),
		WriteTimeout:      cfg.Limits.WriteTimeout(),
		IdleTimeout:       cfg.Limits.IdleTimeout(),
		MaxHeaderBytes:    cfg.Limits.MaxHeaderBytes(),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				ctr.acceptedConns.Add(1)
			}
		},
	}
	if cfg.TLS != nil {
		tc := cfg.TLS.Clone()
		tc.ClientAuth = cfg.ClientCertMode.tlsAuth()
		l.srv.TLSConfig = tc
	}
	return l, nil
}

// bind opens the listener's socket (but does not serve). Binding both listeners
// before serving either makes an address/port conflict a clean, pre-serve failure
// the Runtime can roll back.
func (l *Listener) bind() error {
	ln, err := net.Listen("tcp", l.cfg.Addr())
	if err != nil {
		return err
	}
	l.netln = ln
	return nil
}

// serve starts the accept loop (and the bounded session sweeper) in the background.
func (l *Listener) serve() {
	l.ctr.setPhase(PhaseReady)
	go l.sweepLoop()
	go func() {
		defer close(l.done)
		var err error
		if l.srv.TLSConfig != nil {
			err = l.srv.ServeTLS(l.netln, "", "")
		} else {
			err = l.srv.Serve(l.netln)
		}
		if err != nil && err != http.ErrServerClosed {
			l.ctr.setPhase(PhaseDegraded)
		}
	}()
}

// sweepLoop expires idle sessions and stale outstanding requests on a bounded
// cadence. It exits when the listener stops (no goroutine leak). It runs ONLY on an
// enabled+serving listener — a disabled runtime starts no sweeper.
func (l *Listener) sweepLoop() {
	interval := l.lim.SessionTTL() / 4
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case <-t.C:
			l.pipe.sessions.Sweep()
		}
	}
}

// stop drains in-flight requests (bounded by ctx), stops the sweeper, and closes the
// socket. It never blocks shutdown forever: the http.Server.Shutdown deadline caps
// the drain and remaining connections are force-closed.
func (l *Listener) stop(ctx context.Context) {
	l.ctr.setPhase(PhaseDraining)
	close(l.stopCh)
	err := l.srv.Shutdown(ctx)
	if err != nil {
		// Deadline hit: force-close remaining connections rather than hang.
		l.ctr.shutdownCancels.Add(1)
		_ = l.srv.Close() //nolint:errcheck // best-effort force close on drain timeout
	}
	<-l.done
	l.ctr.setPhase(PhaseStopped)
}

// ServeHTTP is the listener's HTTP entrypoint (steps 1–3 + transport extraction,
// then the pipeline for steps 4–15). Every request/HTTP2 stream flows through here,
// so Host/Origin is re-checked per request/stream inside the pipeline.
func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Step 1: admission — bounded worker pool + queue, before any expensive work.
	ctx, cancel := context.WithTimeout(r.Context(), l.lim.RequestDeadline())
	defer cancel()
	release, ok := l.admit(ctx)
	if !ok {
		l.ctr.admissionRejected.Add(1)
		l.ctr.requestsRejected.Add(1)
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	defer release()

	// Steps 2–3 + transport extraction.
	req, status := l.extractRequest(w, r)
	if status != 0 {
		l.ctr.requestsRejected.Add(1)
		writeStatus(w, status)
		return
	}
	// Steps 4–15.
	out := l.pipe.Process(req, l.clock())
	l.writeOutcome(w, out)
}

// admit acquires a queue slot then a worker slot, bounded by ctx (the per-request
// deadline). It returns a release func and true on admission, or false when the
// queue is full or the deadline elapses while waiting for a worker.
func (l *Listener) admit(ctx context.Context) (func(), bool) {
	select {
	case l.queue <- struct{}{}:
	default:
		return nil, false // queue full — shed load
	}
	l.ctr.queued.Add(1)
	select {
	case l.sem <- struct{}{}:
		<-l.queue
		l.ctr.queued.Add(-1)
		l.ctr.inFlight.Add(1)
		return func() {
			<-l.sem
			l.ctr.inFlight.Add(-1)
		}, true
	case <-ctx.Done():
		<-l.queue
		l.ctr.queued.Add(-1)
		l.ctr.timeouts.Add(1)
		return nil, false
	}
}

// extractRequest reads the transport-level fields into a pipeline Request. It reads
// the body under a hard byte cap (413 on overflow) and routes the path to this
// listener's capability (404 on a foreign/malformed path). It NEVER trusts a
// forwarded Host/Origin header or a client-supplied certificate thumbprint. A
// non-zero returned status means a transport-level rejection.
func (l *Listener) extractRequest(w http.ResponseWriter, r *http.Request) (Request, int) {
	// mTLS defense-in-depth: a require-cert listener must have a verified peer cert.
	if l.cfg.ClientCertMode == ClientCertRequire {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return Request{}, http.StatusUnauthorized
		}
	}
	serverID, status := l.route(r)
	if status != 0 {
		return Request{}, status
	}
	body, ok := readBounded(w, r, l.lim.MaxBodyBytes())
	if !ok {
		return Request{}, http.StatusRequestEntityTooLarge
	}
	req := Request{
		HTTPMethod:           r.Method,
		Capability:           l.cfg.Capability,
		Host:                 r.Host, // the real Host / :authority, never X-Forwarded-Host
		Origin:               r.Header.Get("Origin"),
		OriginPresent:        len(r.Header.Values("Origin")) > 0,
		Path:                 r.URL.Path,
		ServerID:             serverID,
		SessionID:            r.Header.Get("Mcp-Session-Id"),
		HasSession:           r.Header.Get("Mcp-Session-Id") != "",
		ProtocolVersion:      r.Header.Get("MCP-Protocol-Version"),
		HasVersionHeader:     r.Header.Get("MCP-Protocol-Version") != "",
		AuthorizationHeaders: r.Header.Values("Authorization"),
		BearerInQuery:        hasQueryCredential(r),
		DPoPProof:            r.Header.Get("DPoP"),
		HasDPoP:              r.Header.Get("DPoP") != "",
		PeerCertThumbprint:   peerThumbprint(r, l.cfg.ClientCertMode),
		CanonicalURI:         canonicalURI(r),
		Body:                 body,
	}
	return req, 0
}

// route resolves the request path to this listener's capability and, for Gateway,
// extracts the opaque server id from the path. A path outside this listener's
// capability space is a 404.
func (l *Listener) route(r *http.Request) (string, int) {
	if l.cfg.Capability == protocol.Management {
		if r.URL.Path != managementPath {
			return "", http.StatusNotFound
		}
		return "", 0
	}
	if !strings.HasPrefix(r.URL.Path, gatewayPathPrefix) {
		return "", http.StatusNotFound
	}
	rest := strings.TrimPrefix(r.URL.Path, gatewayPathPrefix)
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", http.StatusNotFound
	}
	return rest, 0
}

// writeOutcome writes the pipeline outcome to the HTTP response. It NEVER opens a
// stream: it writes a status and an optional JSON body only.
func (l *Listener) writeOutcome(w http.ResponseWriter, out Outcome) {
	if out.NewSession && out.SessionID != "" {
		w.Header().Set("Mcp-Session-Id", out.SessionID)
	}
	if len(out.ResponseBody) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(out.Status)
	if len(out.ResponseBody) > 0 {
		_, _ = w.Write(out.ResponseBody) //nolint:errcheck // client disconnect is not actionable
	}
}

// health returns this listener's typed health snapshot (active-session count read
// live from the session manager).
func (l *Listener) health() HealthSnapshot {
	snap := l.ctr.snapshot(l.cfg.Capability.String(), l.listenerID)
	snap.ActiveSessions = int64(l.pipe.sessions.SessionCount())
	return snap
}

// readBounded reads the request body under a hard byte cap. It returns ok=false when
// the body exceeds the cap (the caller returns 413).
func readBounded(w http.ResponseWriter, r *http.Request, maxBytes int) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, false
	}
	return body, true
}

// hasQueryCredential reports whether a bearer credential appears in the query string
// (a forbidden location the pipeline rejects). Detecting it here lets the pipeline
// emit the specific credential_in_query rejection.
func hasQueryCredential(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("access_token") != "" || q.Get("token") != "" || q.Get("bearer") != ""
}

// peerThumbprint derives the canonical unpadded base64url SHA-256 thumbprint of the
// verified peer certificate. It is the ONLY source of the observed thumbprint — a
// client-supplied thumbprint header is never consulted — and no private-key material
// is ever touched. Returns "" when no client cert is requested or presented.
func peerThumbprint(r *http.Request, mode ClientCertMode) string {
	if mode == ClientCertNone || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// canonicalURI builds the absolute request URI used for the DPoP htu binding.
func canonicalURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// writeStatus writes a bare status with no body and no stream.
func writeStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}
