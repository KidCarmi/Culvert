package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"sync"
	"time"
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
	lim        Limits
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
// the Runtime can roll back. The socket is wrapped in a hard concurrent-connection
// limiter (MaxConns) so a connection flood cannot exhaust file descriptors or
// per-connection goroutines regardless of the request-level pools.
func (l *Listener) bind() error {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", l.cfg.Addr())
	if err != nil {
		return err
	}
	l.netln = newLimitListener(ln, l.cfg.Limits.MaxConns())
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
			// Unbind identities whose sessions the sweep reclaimed (the binding store
			// has no per-session sweep hook), so it tracks the live session set.
			l.pipe.reconcileBindings()
		}
	}
}

// stop drains in-flight requests (bounded by ctx), stops the sweeper, and closes the
// socket. It never blocks shutdown forever: the http.Server.Shutdown deadline caps
// the drain and remaining connections are force-closed.
func (l *Listener) stop(ctx context.Context) {
	l.ctr.setPhase(PhaseDraining)
	close(l.stopCh)
	// Bound the drain by the smaller of the caller's deadline and this listener's own
	// ShutdownTimeout, so one listener's slow drain can never consume the whole budget.
	dctx, cancel := context.WithTimeout(ctx, l.lim.ShutdownTimeout())
	defer cancel()
	if err := l.srv.Shutdown(dctx); err != nil {
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

// extractRequest builds a pipeline Request from the transport-level fields. It does
// NOT read the body or resolve the route — both are deferred to the pipeline so they
// run only AFTER Host/Origin, method dispatch and path/capability have passed (a
// cross-origin/foreign-route/unsupported-method request never buffers its body). The
// body is exposed as a bounded reader the pipeline reads at its byte-limit step. It
// NEVER trusts a forwarded Host/Origin header or a client-supplied certificate
// thumbprint. A non-zero returned status means a transport-level rejection.
func (l *Listener) extractRequest(w http.ResponseWriter, r *http.Request) (req Request, status int) {
	// mTLS defense-in-depth: a require-cert listener must have a verified peer cert.
	if l.cfg.ClientCertMode == ClientCertRequire {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return Request{}, http.StatusUnauthorized
		}
	}
	// Cap the body at the server layer too (defense-in-depth); the pipeline applies
	// the authoritative byte limit when it actually reads it.
	body := http.MaxBytesReader(w, r.Body, int64(l.lim.MaxBodyBytes())+1)
	req = Request{
		HTTPMethod:           r.Method,
		Capability:           l.cfg.Capability,
		Host:                 r.Host, // the real Host / :authority, never X-Forwarded-Host
		Origin:               r.Header.Get("Origin"),
		OriginPresent:        len(r.Header.Values("Origin")) > 0,
		Path:                 r.URL.Path,
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
		BodyReader:           body,
	}
	return req, 0
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

// limitListener wraps a net.Listener with a hard cap on concurrently-open
// connections (MaxConns). Accept blocks until a slot frees, and each accepted
// connection releases its slot exactly once on Close — so a connection flood is
// bounded to MaxConns live sockets/goroutines regardless of the request-level
// worker pool. (A minimal, dependency-free equivalent of x/net/netutil.)
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(inner net.Listener, maxConns int) net.Listener {
	if maxConns <= 0 {
		return inner
	}
	return &limitListener{Listener: inner, sem: make(chan struct{}, maxConns)}
}

// Accept acquires a connection slot (blocking) then accepts; the slot is released
// when the returned connection is closed.
func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: l.releaseOnce()}, nil
}

// releaseOnce returns a func that frees exactly one slot the first time it is called.
func (l *limitListener) releaseOnce() func() {
	var once sync.Once
	return func() { once.Do(func() { <-l.sem }) }
}

type limitConn struct {
	net.Conn
	release func()
}

// Close releases the connection's slot exactly once, then closes the socket.
func (c *limitConn) Close() error {
	c.release()
	return c.Conn.Close()
}
