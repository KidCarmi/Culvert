package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
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

	// challenge is the precomputed WWW-Authenticate value emitted on a 401 when the
	// capability publishes OAuth Protected Resource Metadata (RFC 9728). Empty ⇒ no
	// challenge header (byte-identical to the pre-metadata behavior).
	challenge string

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
		challenge:  cfg.Metadata.challenge(),
	}
	l.srv = &http.Server{
		Handler:           l,
		ReadHeaderTimeout: cfg.Limits.ReadHeaderTimeout(),
		ReadTimeout:       cfg.Limits.ReadTimeout(),
		WriteTimeout:      cfg.Limits.WriteTimeout(),
		IdleTimeout:       cfg.Limits.IdleTimeout(),
		MaxHeaderBytes:    cfg.Limits.MaxHeaderBytes(),
		// OVN-07. Attach a per-connection request budget. HTTP/2 multiplexing makes
		// MaxConns meaningless as a bound on concurrent REQUESTS: ServeTLS
		// auto-enables h2 and one accepted socket can carry hundreds of concurrent
		// streams into an admission path sized for MaxConcurrent workers, saturating
		// the capability while consuming ONE of the MaxConns slots that were supposed
		// to bound it. Measured against the real listener: 186 concurrent requests
		// from a single connection.
		//
		// http.Server.HTTP2.MaxConcurrentStreams is NOT used for this: it is silently
		// ignored on the ServeTLS auto-h2 path in this Go toolchain (verified
		// empirically — setting it to 8 still admitted 200 concurrent streams), so
		// relying on it would be a control that only looks configured.
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, connBudgetKey{}, newConnBudget(cfg.Limits.MaxConcurrent()))
		},
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
	// SEC-MCP-02, completion. ctx bounds every stage that OBSERVES it -- but the
	// request-BODY read does not: pipeline.readBody blocks in io.ReadAll on the
	// socket, and the budget is only re-checked after that read returns. A client
	// that sends a well-formed header and then stalls its POST body therefore holds
	// a worker slot AND a per-connection budget slot for as long as the socket stays
	// open, which is ReadTimeout -- and LimitConfig.Validate deliberately does not
	// tie ReadTimeout to RequestDeadline, so an operator may legitimately configure
	// ReadTimeout far above it. Enough concurrent slow uploads then exhaust
	// MaxConcurrent despite the end-to-end deadline, which is precisely the
	// amplification OVN-07's per-connection budget exists to prevent.
	//
	// Pushing the SAME deadline down to the socket closes it: the blocked read is
	// interrupted by the kernel at the request deadline, readBody classifies it as a
	// timeout rather than an over-cap body, and both slots are released.
	//
	// The error is deliberately not fatal to the request. On a real net/http server
	// (HTTP/1 and HTTP/2 alike) SetReadDeadline is supported; it returns
	// ErrNotSupported only for a synthetic ResponseWriter such as
	// httptest.ResponseRecorder, where there is no socket to bound and ReadTimeout
	// still applies. Failing the request there would break every unit test to guard
	// against a condition that cannot occur in production, so the real behaviour is
	// pinned by a test over a REAL listener instead.
	if dl, ok := ctx.Deadline(); ok {
		_ = http.NewResponseController(w).SetReadDeadline(dl)
	}
	// Counted at the TRANSPORT entrypoint, not inside pipeline.Process: the three
	// early returns below (connection budget, queue admission, header extraction)
	// each move requestsRejected without ever reaching the pipeline, so a total
	// incremented only in Process could be exceeded by the rejected counter under
	// overload or an ambiguous-header flood — which inverts every rejection-rate
	// dashboard built on the pair. The metric's contract is "requests received".
	l.ctr.requestsTotal.Add(1)
	// OVN-07: a single connection may not have more requests in flight than the
	// listener has workers. Taken BEFORE the shared queue so one connection's excess
	// streams cannot occupy queue slots either. This bounds the AMPLIFICATION; it
	// does not make admission fair across sources (RISK-026).
	if relConn, ok := acquireConnBudget(ctx); ok {
		defer relConn()
	} else {
		l.ctr.timeouts.Add(1)
		l.ctr.requestsRejected.Add(1)
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	release, ok := l.admit(ctx)
	if !ok {
		l.ctr.admissionRejected.Add(1)
		l.ctr.requestsRejected.Add(1)
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	defer release()

	// Protected Resource Metadata (RFC 9728): a GET to the capability's well-known
	// path returns the bounded PUBLIC document. It is served over the (already
	// TLS/mTLS-terminated) connection but requires no bearer token — it is precisely
	// the document a token-less client reads to learn how to obtain one. It never
	// runs the request pipeline, opens a stream, mutates a session, or reads a body.
	// Match on the ESCAPED path: WellKnownPath is derived from the resource's
	// EscapedPath, so a resource whose path carries percent-encoding still resolves
	// (comparing the decoded r.URL.Path would miss it).
	if r.Method == http.MethodGet && l.cfg.Metadata.servesWellKnown(r.URL.EscapedPath()) {
		l.writeProtectedResourceMetadata(w)
		return
	}

	// Steps 2–3 + transport extraction.
	req, status, reason, dupHeader := l.extractRequest(w, r)
	if status != 0 {
		l.ctr.requestsRejected.Add(1)
		// A transport-level rejection that carries a classified reason is recorded on
		// the same denial path as a pipeline rejection. Without this the duplicate
		// singleton-header refusal — a deliberate header-confusion attempt — moved
		// only the generic rejected counter and was invisible to denial telemetry.
		//
		// The durable denial record is written for EVERY classified reason; only the
		// COUNTER is split. authFailures answers "are credentials being attacked?", so
		// it is charged solely for the two credential-bearing headers; a duplicated
		// Origin, Mcp-Session-Id or Mcp-Protocol-Version is header confusion, counted
		// as such, and would otherwise have made routine protocol traffic
		// indistinguishable from a credential attack on the same series.
		switch reason {
		case mcperr.ReasonNone:
			// Unclassified transport refusal (e.g. a require-cert listener with no
			// verified peer): the generic rejected counter above is the whole record.
		case mcperr.ReasonAmbiguousRequestHeader:
			l.ctr.ambiguousHeaders.Add(1)
			if isCredentialHeader(dupHeader) {
				l.ctr.authFailures.Add(1)
			}
			l.pipe.routeAuthDenial(reason)
		default:
			l.ctr.authFailures.Add(1)
			l.pipe.routeAuthDenial(reason)
		}
		if status == http.StatusUnauthorized && l.challenge != "" {
			w.Header().Set("WWW-Authenticate", l.challenge)
		}
		writeStatus(w, status)
		return
	}
	// Steps 4–15, under the SAME deadline context that bounded admission. Before
	// SEC-MCP-02 this ctx was built, used only for admit(), and then cancelled by the
	// deferred cancel above while every expensive stage ran unbounded.
	out := l.pipe.Process(ctx, req, l.clock())
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
func (l *Listener) extractRequest(w http.ResponseWriter, r *http.Request) (req Request, status int, reason mcperr.Reason, dupHeader string) {
	// SEC-MCP-04. Anti-ambiguity, BEFORE any value is read: a singleton
	// security-relevant header presented more than once is rejected whole. A
	// first-value-wins reading lets an intermediary and this gateway resolve the
	// same conflict differently (the classic request-smuggling / header-confusion
	// shape), so no value is picked. Authorization already had this rule inside
	// parseCredential; applying it uniformly here is what makes the posture real.
	if h, dup := duplicateSingletonHeader(r.Header); dup {
		// CLASSIFIED, not just refused. This rejection happens at the transport layer
		// and returns before the pipeline, so nothing downstream can count it — and a
		// deliberate header-confusion attempt would otherwise move only the generic
		// rejected-request counter, indistinguishable from a malformed body. The
		// reason travels back to the caller so the denial is recorded on the same
		// observable path as every other classified rejection.
		//
		// The NAME travels back too, and is used only to decide which counter the
		// episode is charged to (never echoed to the client — telling a prober which
		// of its duplicated headers was noticed is free reconnaissance). The guarded
		// set spans Origin, Mcp-Session-Id and Mcp-Protocol-Version as well as the two
		// credential-bearing headers, and charging all five to authFailures would let
		// ordinary protocol-version or session-header duplication read as a credential
		// attack on culvert_mcp_auth_failures_total.
		return Request{}, http.StatusBadRequest, mcperr.ReasonAmbiguousRequestHeader, h
	}
	// mTLS defense-in-depth: a require-cert listener must have a verified peer cert.
	if l.cfg.ClientCertMode == ClientCertRequire {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return Request{}, http.StatusUnauthorized, mcperr.ReasonNone, ""
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
	return req, 0, mcperr.ReasonNone, ""
}

// writeOutcome writes the pipeline outcome to the HTTP response. It NEVER opens a
// stream: it writes a status and an optional JSON body only.
func (l *Listener) writeOutcome(w http.ResponseWriter, out Outcome) {
	if out.NewSession && out.SessionID != "" {
		w.Header().Set("Mcp-Session-Id", out.SessionID)
	}
	// RFC 9728 §5.1: a 401 from an authentication failure advertises where the
	// client can discover the resource's authorization server(s). Emitted only when
	// the capability publishes metadata; never on a non-401 or an unconfigured
	// listener, and it carries no token, tenant, or credential data.
	if out.Status == http.StatusUnauthorized && l.challenge != "" {
		w.Header().Set("WWW-Authenticate", l.challenge)
	}
	if len(out.ResponseBody) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(out.Status)
	if len(out.ResponseBody) > 0 {
		_, _ = w.Write(out.ResponseBody) //nolint:errcheck // client disconnect is not actionable
	}
}

// writeProtectedResourceMetadata writes the bounded PUBLIC RFC 9728 document. The
// body is precomputed from operator config (never from the request), so the Host
// header cannot influence the advertised resource or authorization servers. It
// opens no stream and never touches a session.
func (l *Listener) writeProtectedResourceMetadata(w http.ResponseWriter) {
	body := l.cfg.Metadata.documentJSON()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) //nolint:errcheck // client disconnect is not actionable
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

// singletonSecurityHeaderNames are the request headers whose value feeds a
// security decision and which a conforming client sends at most once. Adding a
// header that participates in an authentication, authorization, routing or
// origin decision to the request path REQUIRES adding it here — see
// TestSecurity_GuardedSingletonSetIsComplete.
//
// Canonical MIME form (http.Header keys are canonicalized on Set/Add), so the
// lookup is exact and case-insensitivity is handled by net/http itself.
var singletonSecurityHeaderNames = [...]string{
	"Origin",               // cross-origin / DNS-rebinding decision
	"Dpop",                 // sender-constraint proof
	"Mcp-Session-Id",       // session resolution
	"Mcp-Protocol-Version", // version admission
	"Authorization",        // the credential itself
}

// credentialHeaderNames are the singleton security headers that carry the caller's
// credential or its proof of possession. Duplication of one of these is the shape
// of a credential attack; duplication of the others is header confusion. The split
// exists so culvert_mcp_auth_failures_total keeps answering one question.
var credentialHeaderNames = [...]string{"Authorization", "Dpop"}

// isCredentialHeader reports whether name (any case) carries a credential.
func isCredentialHeader(name string) bool {
	if name == "" {
		return false
	}
	c := http.CanonicalHeaderKey(name)
	for _, h := range credentialHeaderNames {
		if h == c {
			return true
		}
	}
	return false
}

// isSingletonSecurityHeader reports whether name (any case) is one of the guarded
// singleton security headers.
func isSingletonSecurityHeader(name string) bool {
	c := http.CanonicalHeaderKey(name)
	for _, h := range singletonSecurityHeaderNames {
		if h == c {
			return true
		}
	}
	return false
}

// duplicateSingletonHeader returns the first guarded singleton header that appears
// more than once. Duplication alone is the trigger — two IDENTICAL values are just
// as ambiguous to a middlebox that forwards only one of them.
func duplicateSingletonHeader(h http.Header) (string, bool) {
	for _, name := range singletonSecurityHeaderNames {
		if len(h.Values(name)) > 1 {
			return name, true
		}
	}
	return "", false
}

// connBudgetKey is the context key carrying a connection's request budget.
type connBudgetKey struct{}

// connBudget bounds the number of requests ONE connection may have in flight.
// HTTP/1.1 is naturally limited to one, but an HTTP/2 connection multiplexes, so
// without this a single socket could occupy the whole worker pool and queue.
//
// The bound is the worker-pool size, and that is not a fairness policy: beyond
// MaxConcurrent, additional concurrent requests on one connection cannot make
// progress anyway, so this admits no work that could have proceeded.
type connBudget struct{ sem chan struct{} }

func newConnBudget(n int) *connBudget {
	if n <= 0 {
		n = 1
	}
	return &connBudget{sem: make(chan struct{}, n)}
}

// acquireConnBudget takes one slot from the calling connection's budget, bounded
// by the request context so a saturated connection cannot park a stream past its
// deadline. A request with no budget in context (a unit-test call that never went
// through the server) is admitted — the budget is a transport-layer bound, and
// failing closed there would break every direct pipeline test without adding any
// protection to a real connection.
func acquireConnBudget(ctx context.Context) (func(), bool) {
	b, _ := ctx.Value(connBudgetKey{}).(*connBudget)
	if b == nil {
		return func() {}, true
	}
	select {
	case b.sem <- struct{}{}:
		return func() { <-b.sem }, true
	case <-ctx.Done():
		return nil, false
	}
}
