package runtime

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/hostcheck"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/session"
)

// observeOnlyErrorCode is the stable JSON-RPC error code returned for a
// decision-point method (tools/list, tools/call) that reaches the observe
// boundary. It is a server-defined code (outside the reserved -32768..-32000 core
// range is discouraged, so a stable value in the implementation-defined server
// range is used) carrying the machine reason "observe_only".
const observeOnlyErrorCode = -32040

// Request is the transport-extracted, pipeline-ready view of ONE inbound MCP HTTP
// request (or HTTP/2 stream). The listener extracts these fields PER request/stream
// — Host/:authority and Origin are re-read every time so a reused H1.1 or H2
// connection can never smuggle a second request past the first request's Host/Origin
// check. It carries no raw token beyond the Authorization header value the PR-3
// validator consumes, and never a client-supplied certificate thumbprint.
type Request struct {
	HTTPMethod       string              // GET / POST / DELETE / ...
	Capability       protocol.Capability // the capability the route resolved to
	Host             string              // Host or HTTP/2 :authority (re-extracted per request/stream)
	OriginPresent    bool
	Origin           string
	Path             string // request path (capability/server routing)
	ServerID         string // Gateway: opaque server id extracted from the route
	SessionID        string // MCP-Session-Id (may be empty)
	HasSession       bool
	ProtocolVersion  string // MCP-Protocol-Version header value (may be empty)
	HasVersionHeader bool

	// Credential material — headers ONLY.
	AuthorizationHeaders []string // every Authorization header value (duplicates rejected)
	BearerInQuery        bool     // a bearer credential was seen in the query string (forbidden)
	DPoPProof            string
	HasDPoP              bool

	// mTLS — the thumbprint is derived by the listener from the VERIFIED peer
	// certificate; a client-supplied thumbprint header is never trusted.
	PeerCertThumbprint string
	CanonicalURI       string // absolute request URI for the DPoP htu binding

	// Body carries a pre-read request body (unit-test path). The live listener leaves
	// Body nil and supplies BodyReader instead, so the pipeline reads the body LAZILY
	// — only after Host/Origin (per request/stream), method dispatch, path/capability
	// and registry resolution have passed. A cross-origin/foreign-route/unsupported-
	// method request is therefore rejected WITHOUT ever buffering its body.
	Body       []byte
	BodyReader io.Reader // bounded reader (live path); read at step 9 only for an admitted POST route
}

// Outcome is the pipeline's terminal decision for one request. Status is the HTTP
// status the listener writes; ResponseBody is the (optional) response bytes;
// RetainStream is ALWAYS false. The Record is the sanitized observation already
// emitted to the sink (returned too for tests/health).
type Outcome struct {
	Status       int
	Disposition  Disposition
	Reason       mcperr.Reason
	HostReason   string
	RetainStream bool // always false
	ResponseBody []byte
	SessionID    string // set on a successful initialize (MCP-Session-Id to return)
	NewSession   bool
	Record       ObserveRecord
}

// pipeline is ONE capability's dedicated request processor. It owns that
// capability's session manager, identity binding store, host validator, auth config
// and counters; nothing mutable is shared with the other capability's pipeline.
type pipeline struct {
	capability protocol.Capability
	listenerID string
	host       *hostcheck.Validator
	authCfg    authn.CapabilityAuthConfig
	sessions   *session.Manager
	bindings   *identity.BindingStore
	lim        Limits
	sessLim    limits.Limits
	deps       Deps
	ctr        *counters
	rev        uint64
	idSeq      atomic.Uint64

	// policy is the OPTIONAL capability-local policy provider; policyEngine is this
	// pipeline's own pure evaluator (never shared mutable state). When policy is nil
	// the pipeline keeps the PR-5 observe-only disposition.
	policy       PolicyProvider
	policyEngine *policy.Engine

	// boundMu guards boundIDs — the set of session ids this pipeline has bound an
	// identity to. It lets reconcileBindings unbind identities for sessions the
	// kernel sweeper reclaimed (which has no per-binding hook), so the binding store
	// can never grow unbounded under ordinary successful traffic.
	boundMu  sync.Mutex
	boundIDs map[string]struct{}
}

// newPipeline builds a capability pipeline from a validated listener config. It
// constructs the host validator, the dedicated session manager (its own instance,
// never shared) and the dedicated binding store.
func newPipeline(cfg ListenerConfig, deps Deps, listenerID string, ctr *counters, rev uint64) (*pipeline, error) {
	hv, err := hostcheck.New(hostcheck.Config{
		AllowedHosts:   cfg.AllowedHosts,
		AllowedOrigins: cfg.AllowedOrigins,
		RequireOrigin:  cfg.RequireOrigin,
	})
	if err != nil {
		return nil, err
	}
	sl := cfg.sessionLimits()
	mgr := session.NewManager(sl, sl, deps.now)
	p := &pipeline{
		capability: cfg.Capability,
		listenerID: listenerID,
		host:       hv,
		authCfg:    cfg.AuthConfig,
		sessions:   mgr,
		bindings:   identity.NewBindingStore(),
		lim:        cfg.Limits,
		sessLim:    sl,
		deps:       deps,
		ctr:        ctr,
		rev:        rev,
		boundIDs:   make(map[string]struct{}),
	}
	if deps.Policy != nil {
		p.policy = deps.Policy
		p.policyEngine = newPolicyEngine()
	}
	return p, nil
}

// trackBinding records that sessionID now carries a bound identity (so a later
// sweep can unbind it).
func (p *pipeline) trackBinding(sessionID string) {
	p.boundMu.Lock()
	p.boundIDs[sessionID] = struct{}{}
	p.boundMu.Unlock()
}

// closeSession tears down a session the pipeline itself created (on a rejection
// after open, or a rollback): it closes the protocol session, unbinds its identity,
// and stops tracking it. It never affects another session.
func (p *pipeline) closeSession(sessionID string) {
	p.sessions.Close(sessionID)
	p.bindings.Unbind(sessionID)
	p.boundMu.Lock()
	delete(p.boundIDs, sessionID)
	p.boundMu.Unlock()
}

// reconcileBindings unbinds identities whose sessions the kernel sweeper has
// already reclaimed. It is a bounded scan the listener runs on the sweep cadence,
// so the binding store tracks the live session set rather than growing forever.
func (p *pipeline) reconcileBindings() {
	p.boundMu.Lock()
	ids := make([]string, 0, len(p.boundIDs))
	for id := range p.boundIDs {
		ids = append(ids, id)
	}
	p.boundMu.Unlock()
	for _, id := range ids {
		if _, live := p.sessions.Get(id); !live {
			p.bindings.Unbind(id)
			p.boundMu.Lock()
			delete(p.boundIDs, id)
			p.boundMu.Unlock()
		}
	}
}

// recBuilder accumulates the sanitized observation fields as the request flows
// through the pipeline; it is finalized exactly once (on the single reject/complete
// exit) so every disposition emits precisely one record.
type recBuilder struct {
	start time.Time
	rec   ObserveRecord
}

func (p *pipeline) newRecord(req Request, start time.Time) *recBuilder {
	return &recBuilder{start: start, rec: ObserveRecord{
		ObservationID: p.listenerID + "-" + strconv.FormatUint(p.idSeq.Add(1), 10),
		Capability:    p.capability,
		ListenerID:    p.listenerID,
		Class:         ClassUnknown,
		Start:         start,
		RequestBytes:  len(req.Body),
		RuntimeRev:    p.rev,
	}}
}

// Process runs the ordered request pipeline (steps 4–15 of the 15-step contract;
// the listener owns admission/TLS/header bounds — steps 1–3 — before calling in).
// A rejection at any step returns immediately WITHOUT touching later state
// (no session, no auth, no binding, no upstream — none of which exist here anyway).
func (p *pipeline) Process(req Request, now time.Time) Outcome {
	p.ctr.requestsTotal.Add(1)
	rb := p.newRecord(req, now)

	// Step 4–6: Host/:authority + Origin — on EVERY request/stream, before any
	// method dispatch (the DNS-rebinding / cross-origin defense, MCP-INSP-009).
	if out, ok := p.checkHostOrigin(req, rb); !ok {
		return out
	}
	// Transport method dispatch: only POST proceeds; GET/DELETE/other are terminal
	// 405 with zero retained streams.
	if req.HTTPMethod != "POST" {
		tr := decideTransportMethod(req.HTTPMethod)
		return p.reject(rb, tr.status, mcperr.ReasonHTTPMethodRejected, "")
	}
	return p.processPost(req, rb, now)
}

// checkHostOrigin performs steps 4–6. Returns ok=false and a rejection Outcome on
// a host/origin failure (403, zero stream).
func (p *pipeline) checkHostOrigin(req Request, rb *recBuilder) (Outcome, bool) {
	res := p.host.Check(req.Host, req.OriginPresent, req.Origin)
	if res.Allowed() {
		return Outcome{}, true
	}
	p.ctr.hostOriginFailures.Add(1)
	rb.rec.HostReason = res.Reason
	reason := mcperr.ReasonHostRejected
	if res.Reason == hostcheck.ReasonOriginRequired || res.Reason == hostcheck.ReasonOriginInvalid || res.Reason == hostcheck.ReasonOriginNotAllowed {
		reason = mcperr.ReasonOriginRejected
	}
	return p.reject(rb, 403, reason, res.Reason), false
}

// processPost runs steps 7–15 for a POST request.
func (p *pipeline) processPost(req Request, rb *recBuilder, now time.Time) Outcome {
	// Step 7: path/capability — the route's capability must match this listener's.
	if req.Capability != p.capability {
		return p.reject(rb, 404, mcperr.ReasonAdmissionRejected, "")
	}
	// Step 8: server-id / registry (Gateway only). Management must not access the
	// Gateway catalog/registry. The opaque server id is resolved from the route here,
	// BEFORE the body is read, and pinned onto the request for the auth/resource check.
	serverID, out, ok := p.resolveServer(req, rb)
	if !ok {
		return out
	}
	req.ServerID = serverID
	// Step 9: read + byte-limit the body. Reached ONLY after Host/Origin, method
	// dispatch, path/capability and registry resolution have passed — a rejected
	// request never buffers its body.
	body, ok := p.readBody(req)
	if !ok {
		return p.reject(rb, 413, mcperr.ReasonResourceLimit, "")
	}
	rb.rec.RequestBytes = len(body)
	// Step 10: PR-1 strict JSON-RPC decode.
	msg, err := jsonrpc.Decode(body, p.sessLim)
	if err != nil {
		return p.reject(rb, 400, mcperr.ReasonOf(err), "")
	}
	rb.rec.Class = classOf(msg.Class)
	// A response arriving on the client-facing leg is not a client-originated
	// request; the observe listener never correlates upstream responses (there is no
	// upstream). Reject a bare response frame.
	if msg.Class == jsonrpc.ClassResponse {
		return p.reject(rb, 400, mcperr.ReasonInvalidJSONRPC, "")
	}
	return p.processMessage(req, rb, msg, now)
}

// resolveServer performs step 8. For Gateway it resolves the opaque ServerID from
// the route against the live registry: the server must exist and be enabled, and
// the auth resource must match the server. Management carries no server authority.
func (p *pipeline) resolveServer(req Request, rb *recBuilder) (string, Outcome, bool) {
	if p.capability == protocol.Management {
		// Management is a single fixed path and carries no server authority.
		if req.ServerID != "" || (req.Path != "" && req.Path != managementPath) {
			return "", p.reject(rb, 404, mcperr.ReasonAdmissionRejected, ""), false
		}
		return "", Outcome{}, true
	}
	// Gateway: use an explicitly-supplied server id (unit tests) or parse it from the
	// route path (live listener). A malformed/foreign path resolves to no server.
	serverID := req.ServerID
	if serverID == "" {
		serverID = parseGatewayServerID(req.Path)
	}
	if serverID == "" {
		return "", p.reject(rb, 404, mcperr.ReasonRegistryServerUnavailable, ""), false
	}
	if p.deps.Registry == nil {
		return "", p.reject(rb, 404, mcperr.ReasonRegistryServerUnavailable, ""), false
	}
	rec, ok := p.deps.Registry.Current().Get(registry.ServerID(serverID))
	if !ok || !rec.Usable() {
		return "", p.reject(rb, 404, mcperr.ReasonRegistryServerUnavailable, ""), false
	}
	// The server is registered + enabled: safe to carry its opaque id in the record.
	rb.rec.ServerID = serverID
	return serverID, Outcome{}, true
}

// readBody obtains the request body: a pre-read Body (unit tests) or, on the live
// path, a bounded read of BodyReader. It returns ok=false when the body exceeds the
// configured byte cap (the caller returns 413).
func (p *pipeline) readBody(req Request) ([]byte, bool) {
	if req.Body != nil || req.BodyReader == nil {
		if len(req.Body) > p.lim.MaxBodyBytes() {
			return nil, false
		}
		return req.Body, true
	}
	// Read one byte past the cap so an exactly-at-cap body is accepted and an
	// over-cap body is detected without trusting the transport's own limiter alone.
	limited := io.LimitReader(req.BodyReader, int64(p.lim.MaxBodyBytes())+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) > p.lim.MaxBodyBytes() {
		return nil, false
	}
	return body, true
}

// parseGatewayServerID extracts the opaque server id from a Gateway route path
// (`/mcp/gateway/<server-id>[/...]`). Returns "" for a foreign or malformed path.
func parseGatewayServerID(path string) string {
	if !strings.HasPrefix(path, gatewayPathPrefix) {
		return ""
	}
	rest := path[len(gatewayPathPrefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// processMessage runs steps 11–15 for a decoded request/notification.
func (p *pipeline) processMessage(req Request, rb *recBuilder, msg jsonrpc.Message, now time.Time) Outcome {
	// Step 11: version / session / lifecycle — resolve or create the session and,
	// for initialize, negotiate the protocol version. `created` is true only for a
	// session this request just opened (an initialize), so a later-step rejection can
	// tear it down and never leave an unauthenticated session pinning the cap.
	sess, negotiated, created, out, ok := p.resolveSession(req, rb, msg)
	if !ok {
		return out
	}
	// Step 12: PR-3 auth + sender-constraint (+ step 13: immutable identity binding).
	ctx, err := p.authenticate(req, sess, now)
	if err != nil {
		if created {
			p.closeSession(sess.ID())
		}
		p.ctr.authFailures.Add(1)
		return p.reject(rb, statusForAuth(mcperr.ReasonOf(err)), mcperr.ReasonOf(err), "")
	}
	rb.rec.PrincipalHash = digest(ctx.Fingerprint())
	rb.rec.ClientID = ctx.Client().ClientID
	rb.rec.AuthResult = "ok"
	rb.rec.SessionDigest = digest(sess.ID())
	// Step 14: method admission (lifecycle + reviewed registry, via the session).
	adm, err := sess.Admit(protocol.ClientOriginated, msg.Class, msg.Method)
	if err != nil {
		if created {
			p.closeSession(sess.ID())
		}
		p.ctr.admissionRejected.Add(1)
		return p.reject(rb, statusForAdmission(mcperr.ReasonOf(err)), mcperr.ReasonOf(err), "")
	}
	rb.rec.Method = msg.Method // safe: an admitted method is one of the reviewed six
	// Step 15: disposition (observe-only in PR-5; decision-only policy in PR-6).
	return p.dispatch(rb, req, msg, sess, ctx, negotiated, adm, now)
}

// resolveSession performs step 11. On an initialize it opens a new session and
// negotiates the version; on any other method it looks up the session named by
// MCP-Session-Id. It returns the session, the negotiated version (initialize only),
// and a rejection Outcome when session/version resolution fails.
func (p *pipeline) resolveSession(req Request, rb *recBuilder, msg jsonrpc.Message) (sess *session.Session, v protocol.Version, created bool, out Outcome, ok bool) {
	if msg.Method == "initialize" && msg.Class == jsonrpc.ClassRequest {
		return p.openInitialize(req, rb, msg)
	}
	// Non-initialize: a valid session is mandatory.
	if !req.HasSession || req.SessionID == "" {
		cond := protocol.CondMissingSessionID
		if !req.HasVersionHeader {
			cond = protocol.CondSessionlessMissingVersion
		}
		d := protocol.DecideTransport(cond)
		return nil, "", false, p.reject(rb, d.Status, mcperr.ReasonUnsupportedVersion, ""), false
	}
	// A present-but-unsupported version header is a terminal 400.
	if req.HasVersionHeader && !protocol.IsSupported(protocol.Version(req.ProtocolVersion)) {
		d := protocol.DecideTransport(protocol.CondInvalidVersionHeader)
		return nil, "", false, p.reject(rb, d.Status, mcperr.ReasonUnsupportedVersion, ""), false
	}
	s, found := p.sessions.Get(req.SessionID)
	if !found {
		d := protocol.DecideTransport(protocol.CondUnknownOrTerminatedSession)
		return nil, "", false, p.reject(rb, d.Status, mcperr.ReasonInvalidLifecycle, ""), false
	}
	ver, _ := s.Version()
	rb.rec.ProtocolVer = string(ver)
	return s, ver, false, Outcome{}, true
}

// openInitialize opens a fresh session for an initialize request and negotiates the
// protocol version from the initialize body. On success it returns created=true so
// the caller tears the session down if a later step (auth/admission) rejects.
func (p *pipeline) openInitialize(req Request, rb *recBuilder, msg jsonrpc.Message) (*session.Session, protocol.Version, bool, Outcome, bool) {
	// A session id on an initialize means a client is re-initializing an existing
	// session — reject (initialize is a one-time bootstrap, enforced by lifecycle).
	if req.HasSession && req.SessionID != "" {
		if _, exists := p.sessions.Get(req.SessionID); exists {
			return nil, "", false, p.reject(rb, 400, mcperr.ReasonInvalidLifecycle, ""), false
		}
	}
	sid := p.newSessionID()
	sess, err := p.sessions.Open(sid, p.capability, protocol.ClientFacing)
	if err != nil {
		p.ctr.admissionRejected.Add(1)
		return nil, "", false, p.reject(rb, 429, mcperr.ReasonOf(err), ""), false
	}
	neg := protocol.Negotiate(requestedVersion(msg))
	if err := sess.SetNegotiatedVersion(neg.Selected); err != nil {
		p.closeSession(sid)
		return nil, "", false, p.reject(rb, 400, mcperr.ReasonOf(err), ""), false
	}
	rb.rec.ProtocolVer = string(neg.Selected)
	return sess, neg.Selected, true, Outcome{}, true
}

// dispatch performs step 15: the observe-only disposition. Kernel-terminal methods
// complete normally; decision-point methods (tools/list, tools/call) end in a
// deterministic observe-only rejection — never a policy call, credential
// materialization, upstream contact, or fabricated success.
func (p *pipeline) dispatch(rb *recBuilder, req Request, msg jsonrpc.Message, sess *session.Session, ctx *identity.ResolvedContext, negotiated protocol.Version, adm protocol.Admission, now time.Time) Outcome {
	if adm.Handling == protocol.HandlingDecisionPoint {
		// PR-6: if a policy provider is wired, evaluate the capability-local snapshot
		// (decision-only — never an upstream/credential/broker call). Otherwise keep
		// the PR-5 observe-only disposition.
		if p.policy != nil {
			return p.dispatchPolicy(rb, req, msg, ctx, now)
		}
		p.ctr.observeOnly.Add(1)
		body := observeOnlyError(msg.ID)
		return p.finish(rb, Outcome{
			Status: 200, Disposition: DispObserveOnly, Reason: mcperr.ReasonObserveOnly,
			ResponseBody: body,
		})
	}
	// Kernel-terminal.
	p.ctr.kernelTerminal.Add(1)
	return p.completeKernelTerminal(rb, msg, sess, negotiated)
}

// completeKernelTerminal answers a protocol-correct kernel-terminal method itself
// (initialize / ping / notifications-initialized / notifications-cancelled).
func (p *pipeline) completeKernelTerminal(rb *recBuilder, msg jsonrpc.Message, sess *session.Session, negotiated protocol.Version) Outcome {
	out := Outcome{Disposition: DispKernelTerminal, Reason: mcperr.ReasonNone}
	switch msg.Method {
	case "initialize":
		out.Status = 200
		out.ResponseBody = initializeResult(msg.ID, negotiated)
		out.SessionID = sess.ID()
		out.NewSession = true
	case "ping":
		out.Status = 200
		out.ResponseBody = pingResult(msg.ID)
	default:
		// notifications/initialized and notifications/cancelled carry no id and get
		// NO response body — a 202 Accepted acknowledges receipt.
		out.Status = 202
	}
	return p.finish(rb, out)
}

// reject finalizes a rejected request: it bumps the rejection counter, stamps the
// record's disposition/reason, emits the record, and returns the Outcome.
func (p *pipeline) reject(rb *recBuilder, status int, reason mcperr.Reason, hostReason string) Outcome {
	p.ctr.requestsRejected.Add(1)
	if hostReason != "" {
		rb.rec.HostReason = hostReason
	}
	return p.finish(rb, Outcome{Status: status, Disposition: DispRejected, Reason: reason})
}

// finish stamps the shared record fields, emits the sanitized record to the bounded
// sink (a sink failure is advisory — it never changes the disposition), and returns
// the Outcome carrying the record.
func (p *pipeline) finish(rb *recBuilder, out Outcome) Outcome {
	end := p.deps.now()
	rb.rec.Disposition = out.Disposition
	rb.rec.Reason = out.Reason
	rb.rec.DurationMS = end.Sub(rb.start).Milliseconds()
	if rb.rec.DurationMS < 0 {
		rb.rec.DurationMS = 0
	}
	p.emit(rb.rec)
	out.Record = rb.rec
	out.RetainStream = false
	return out
}

// emit sends a record to the injected sink without ever blocking the request path:
// a nil sink drops it, and a sink error only bumps the drop counter.
func (p *pipeline) emit(rec ObserveRecord) {
	sink := p.deps.Sink
	if sink == nil {
		return
	}
	if err := sink.Observe(rec); err != nil {
		p.ctr.observeDrops.Add(1)
	}
}

// newSessionID mints an unguessable session id from crypto/rand (128 bits),
// namespaced by the listener id. MCP recommends non-enumerable session ids; a
// counter would be trivially enumerable. On the vanishingly unlikely rand failure
// it falls back to the monotonic counter (still unique within the process).
func (p *pipeline) newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "s-" + p.listenerID + "-" + strconv.FormatUint(p.idSeq.Add(1), 10)
	}
	return "s-" + p.listenerID + "-" + hex.EncodeToString(b[:])
}

// requestedVersion extracts the requested protocolVersion from an initialize body.
// A missing/malformed value yields the empty version, which Negotiate counter-offers
// the primary for.
func requestedVersion(msg jsonrpc.Message) protocol.Version {
	if len(msg.Params) == 0 {
		return ""
	}
	var body struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(msg.Params, &body); err != nil {
		return ""
	}
	return protocol.Version(body.ProtocolVersion)
}

// classOf maps a jsonrpc class to the observe MessageClass.
func classOf(c jsonrpc.Class) MessageClass {
	switch c {
	case jsonrpc.ClassRequest:
		return ClassRequest
	case jsonrpc.ClassNotification:
		return ClassNotification
	case jsonrpc.ClassResponse:
		return ClassResponse
	default:
		return ClassUnknown
	}
}

// digest returns a bounded one-way hex digest of s (never the raw value). Used for
// principal/session values that must be correlatable but never disclosed.
func digest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
