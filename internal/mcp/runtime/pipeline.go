package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/hostcheck"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
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

	// Body — already byte-limited by the listener; re-asserted here.
	Body []byte
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
	lim        RuntimeLimits
	sessLim    limits.Limits
	deps       Deps
	ctr        *counters
	rev        uint64
	idSeq      atomic.Uint64
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
	return &pipeline{
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
	}, nil
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
	// Gateway catalog/registry.
	if out, ok := p.resolveServer(req, rb); !ok {
		return out
	}
	// Step 9: body byte limit (already enforced by the listener; re-asserted).
	if len(req.Body) > p.lim.MaxBodyBytes() {
		return p.reject(rb, 413, mcperr.ReasonResourceLimit, "")
	}
	// Step 10: PR-1 strict JSON-RPC decode.
	msg, err := jsonrpc.Decode(req.Body, p.sessLim)
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
func (p *pipeline) resolveServer(req Request, rb *recBuilder) (Outcome, bool) {
	if p.capability == protocol.Management {
		if req.ServerID != "" {
			return p.reject(rb, 404, mcperr.ReasonAdmissionRejected, ""), false
		}
		return Outcome{}, true
	}
	if req.ServerID == "" {
		return p.reject(rb, 404, mcperr.ReasonRegistryServerUnavailable, ""), false
	}
	if p.deps.Registry == nil {
		return p.reject(rb, 404, mcperr.ReasonRegistryServerUnavailable, ""), false
	}
	rec, ok := p.deps.Registry.Current().Get(registry.ServerID(req.ServerID))
	if !ok || !rec.Usable() {
		return p.reject(rb, 404, mcperr.ReasonRegistryServerUnavailable, ""), false
	}
	// The server is registered + enabled: safe to carry its opaque id in the record.
	rb.rec.ServerID = req.ServerID
	return Outcome{}, true
}

// processMessage runs steps 11–15 for a decoded request/notification.
func (p *pipeline) processMessage(req Request, rb *recBuilder, msg jsonrpc.Message, now time.Time) Outcome {
	// Step 11: version / session / lifecycle — resolve or create the session and,
	// for initialize, negotiate the protocol version.
	sess, negotiated, out, ok := p.resolveSession(req, rb, msg)
	if !ok {
		return out
	}
	// Step 12: PR-3 auth + sender-constraint (+ step 13: immutable identity binding).
	ctx, err := p.authenticate(req, sess, now)
	if err != nil {
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
		p.ctr.admissionRejected.Add(1)
		return p.reject(rb, statusForAdmission(mcperr.ReasonOf(err)), mcperr.ReasonOf(err), "")
	}
	rb.rec.Method = msg.Method // safe: an admitted method is one of the reviewed six
	// Step 15: observe-only disposition.
	return p.dispatch(rb, msg, sess, negotiated, adm)
}

// resolveSession performs step 11. On an initialize it opens a new session and
// negotiates the version; on any other method it looks up the session named by
// MCP-Session-Id. It returns the session, the negotiated version (initialize only),
// and a rejection Outcome when session/version resolution fails.
func (p *pipeline) resolveSession(req Request, rb *recBuilder, msg jsonrpc.Message) (*session.Session, protocol.Version, Outcome, bool) {
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
		return nil, "", p.reject(rb, d.Status, mcperr.ReasonUnsupportedVersion, ""), false
	}
	// A present-but-unsupported version header is a terminal 400.
	if req.HasVersionHeader && !protocol.IsSupported(protocol.Version(req.ProtocolVersion)) {
		d := protocol.DecideTransport(protocol.CondInvalidVersionHeader)
		return nil, "", p.reject(rb, d.Status, mcperr.ReasonUnsupportedVersion, ""), false
	}
	sess, ok := p.sessions.Get(req.SessionID)
	if !ok {
		d := protocol.DecideTransport(protocol.CondUnknownOrTerminatedSession)
		return nil, "", p.reject(rb, d.Status, mcperr.ReasonInvalidLifecycle, ""), false
	}
	v, _ := sess.Version()
	rb.rec.ProtocolVer = string(v)
	return sess, v, Outcome{}, true
}

// openInitialize opens a fresh session for an initialize request and negotiates the
// protocol version from the initialize body.
func (p *pipeline) openInitialize(req Request, rb *recBuilder, msg jsonrpc.Message) (*session.Session, protocol.Version, Outcome, bool) {
	// A session id on an initialize means a client is re-initializing an existing
	// session — reject (initialize is a one-time bootstrap, enforced by lifecycle).
	if req.HasSession && req.SessionID != "" {
		if _, exists := p.sessions.Get(req.SessionID); exists {
			return nil, "", p.reject(rb, 400, mcperr.ReasonInvalidLifecycle, ""), false
		}
	}
	sid := p.newSessionID()
	sess, err := p.sessions.Open(sid, p.capability, protocol.ClientFacing)
	if err != nil {
		p.ctr.admissionRejected.Add(1)
		return nil, "", p.reject(rb, 429, mcperr.ReasonOf(err), ""), false
	}
	neg := protocol.Negotiate(requestedVersion(msg))
	if err := sess.SetNegotiatedVersion(neg.Selected); err != nil {
		p.sessions.Close(sid)
		return nil, "", p.reject(rb, 400, mcperr.ReasonOf(err), ""), false
	}
	rb.rec.ProtocolVer = string(neg.Selected)
	return sess, neg.Selected, Outcome{}, true
}

// dispatch performs step 15: the observe-only disposition. Kernel-terminal methods
// complete normally; decision-point methods (tools/list, tools/call) end in a
// deterministic observe-only rejection — never a policy call, credential
// materialization, upstream contact, or fabricated success.
func (p *pipeline) dispatch(rb *recBuilder, msg jsonrpc.Message, sess *session.Session, negotiated protocol.Version, adm protocol.Admission) Outcome {
	if adm.Handling == protocol.HandlingDecisionPoint {
		// Observe-only: sanitized record + deterministic typed rejection.
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

// newSessionID mints a listener-unique, non-guessable-enough session id from the
// listener id + a monotonic counter. (The kernel session manager keys on it; it is
// never a security token.)
func (p *pipeline) newSessionID() string {
	return "s-" + p.listenerID + "-" + strconv.FormatUint(p.idSeq.Add(1), 10)
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
