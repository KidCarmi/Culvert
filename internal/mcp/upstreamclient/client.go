package upstreamclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// admittedMethods is the exact V1 upstream method set. Nothing else is sent.
var admittedMethods = map[string]bool{
	"initialize":                true,
	"notifications/initialized": true,
	"ping":                      true,
	"notifications/cancelled":   true,
	"tools/list":                true,
	"tools/call":                true,
}

// IdentityVerifier verifies a connected upstream peer's TLS identity against the
// server record's pinned identity. It is injected so a private-CA / self-signed
// internal MCP server can be pinned without a public chain.
type IdentityVerifier interface {
	// VerifyIdentity returns nil ONLY when the peer's verified TLS state matches the
	// pinned identity exactly. An empty pinnedIdentity means "standard chain +
	// hostname verification already applies" and this returns nil.
	VerifyIdentity(state tls.ConnectionState, pinnedIdentity string) error
}

// Config wires a Client. Resolver, Policy, and InspectionLimits are the PR-7
// destination controls; Identity verifies the pinned TLS identity.
type Config struct {
	Limits           Limits
	Resolver         destination.Resolver
	Policy           destination.Policy
	InspectionLimits limits.InspectionLimits
	Identity         IdentityVerifier
	RootCAs          *x509.CertPool // nil ⇒ system roots
	Clock            func() time.Time
}

// Target identifies the upstream server. Endpoint and PinnedIdentity come ONLY
// from the registered server record — never from a request.
type Target struct {
	ServerID       string
	Endpoint       string // https URL from the registered record
	PinnedIdentity string // TLS identity to verify (empty ⇒ standard verification)
}

// CallOptions carry per-call knobs.
type CallOptions struct {
	// Idempotent marks a read-only call that MAY be retried on a transport-ambiguous
	// pre-response failure. A write/destructive tools/call MUST leave this false.
	Idempotent bool
	// WireID is the independent upstream-leg JSON-RPC id (never assumed equal to the
	// client-leg id). Empty ⇒ the client assigns one.
	WireID string
	// AuthHeader is the OPTIONAL upstream Authorization header value — the
	// broker-materialized credential for the APPROVED SERVER (e.g. "Bearer <token>").
	// It is NEVER the client's own token (the client token is never forwarded); it is
	// set only from inside the broker materialization callback and lives only for the
	// duration of the request.
	AuthHeader string
	// PreSend, when non-nil, is the caller's authority predicate, re-asked at every point on this
	// path where an unbounded wait has just ended and nothing has yet been written. A non-nil error
	// aborts that leg with no request bytes on any connection.
	//
	// IT EXISTS BECAUSE THE WAITS HERE ARE UNBOUNDED. The executor's boundary guards (tool drift,
	// rollout authority, emergency kill) run immediately before Call, and the code there said
	// nothing sits between them and the send — true of that function, false of this one. A kill, a
	// demotion, a scope withdrawal or an approval revocation can land, return successfully, and the
	// waiting request then sends anyway (Codex P1, PR #1370, rounds 4 and 6).
	//
	// TWO SITES, covering different phases, neither able to stand in for the other:
	//
	//	roundTrip, before client.Do  — after `pool.acquire` (which ends only when ANOTHER request
	//	                               finishes) and after DNS resolution.
	//	pinnedDialTLS, after the TLS handshake — after the TCP connect and the handshake, with the
	//	                               connection established and nothing written.
	//
	// Neither substitutes for the other because they BRACKET DIFFERENT PHASES: the pool wait and
	// the DNS lookup are already behind the first site and the dialer never sees them, while the
	// connect and the handshake are still ahead of it and only the dialer can sit after them.
	//
	// Both run PER LEG: a retry is a second physical send, and re-sending on the strength of a
	// check made before an earlier leg is the same defect one loop iteration over. The dialer site
	// reaches every leg because each leg builds its OWN transport and releases its idle connections
	// when it ends (see roundTrip), so no leg can inherit a connection another leg opened.
	//
	// It is deliberately OPAQUE: this package learns nothing about generations, scopes, approvals
	// or kill state — it runs a predicate the executor owns and reports the error verbatim.
	//
	// IT MUST BE A PURE PREDICATE: ITS LIFETIME IS NOT Call's. The dialer site runs on whatever
	// goroutine net/http dials on (Transport.queueForDial -> go dialConnFor), and that goroutine
	// is not joined to the request: when the caller's context is cancelled while a dial is in
	// flight — a client disconnect, a request timeout — getConn returns at once and Call unwinds,
	// while the dial goroutine completes its handshake and calls this hook. So the hook may run
	// CONCURRENTLY with, and FINISH AFTER, Call's return (pinned by
	// TestPreSend_MayStillBeRunningAfterCallReturns).
	//
	// A caller must therefore NOT write anything it intends to read back after Call returns.
	// Captured variables are a data race; synchronising them removes the race and still is not a
	// hand-off, because a late hook can write after the only reader has gone. There is no need
	// for one: a refusal that GOVERNED the leg comes back as Call's own error, verbatim
	// (roundTrip returns it directly; the dialer site rides out through preSendRefusalErr), and
	// an error that reached the caller's goroutine happened-before the caller reads it. Put
	// everything the verdict needs to be diagnosed ON the error.
	PreSend func() error
	// AttemptID names the ONE potential physical tool invocation this call carries
	// (review §5). It is emitted as a request header so the controlled recording
	// upstream can attribute each received invocation to exactly one authorized
	// attempt — the correlation an independent witness needs to answer "did Culvert
	// cause exactly the effects it authorized?". It is non-secret, and empty for
	// lifecycle/discovery traffic, which carries no attempt.
	AttemptID string
}

// Response is the decoded, admitted upstream JSON-RPC response.
type Response struct {
	ID     jsonrpc.ID
	Result json.RawMessage
	Error  *jsonrpc.ErrorObject
	// RawBytes is the exact bounded response body (for downstream inspection/DLP).
	RawBytes []byte
}

// Client is the bounded upstream MCP client. It is safe for concurrent use; each
// server gets an independent bounded pool/queue/in-flight budget.
type Client struct {
	cfg       Config
	kernelLim limits.Limits

	mu    sync.Mutex
	pools map[string]*serverPool
}

// New constructs a Client. It fails closed on an invalid config.
func New(cfg Config, kernelLim limits.Limits) (*Client, error) {
	if !cfg.Limits.Valid() {
		return nil, mcperr.New(mcperr.ReasonListenerConfigInvalid, "upstreamclient", "invalid limits")
	}
	if cfg.Resolver == nil {
		return nil, mcperr.New(mcperr.ReasonListenerConfigInvalid, "upstreamclient", "nil resolver")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Identity == nil {
		cfg.Identity = spkiVerifier{}
	}
	return &Client{cfg: cfg, kernelLim: kernelLim, pools: map[string]*serverPool{}}, nil
}

// Admitted reports whether method is in the V1 upstream set.
func Admitted(method string) bool { return admittedMethods[method] }

// Call executes a single admitted upstream method against target and returns the
// decoded response. It fails closed with a classified, sanitized error; it never
// leaks a raw network error or forwards a client token.
func (c *Client) Call(ctx context.Context, target Target, method string, params json.RawMessage, opts CallOptions) (*Response, error) {
	// Each of these three refusals happens before any leg begins, so no request bytes
	// exist on any connection. Marking them lets the executor record
	// definitely_not_sent instead of sending a provably-undelivered attempt to witness
	// reconciliation that has nothing to establish (Codex round 14).
	if !Admitted(method) {
		return nil, markNeverSent(mcperr.New(mcperr.ReasonUpstreamTransportRejected, "upstreamclient", "method not admitted upstream"))
	}
	if target.Endpoint == "" || target.ServerID == "" {
		return nil, markNeverSent(mcperr.New(mcperr.ReasonUpstreamEndpointInvalid, "upstreamclient", "endpoint must come from the registered record"))
	}
	pool := c.poolFor(target.ServerID)
	release, err := pool.acquire(ctx)
	if err != nil {
		return nil, markNeverSent(err)
	}
	defer release()
	// The pool slot is held from here, so the wait above — which is unbounded in time, since it
	// ends only when another request finishes — is over. The caller's predicate is re-asked further
	// down, in roundTrip and again in the TLS dialer; see CallOptions.PreSend for why there and not
	// here (nothing between this line and those sites can have a side effect).

	budget := c.cfg.Limits.MaxReadRetries()
	// Retry-free mode is decided ONCE, outside the loop, from immutable validated
	// limits — not re-derived per attempt where a later edit could make it
	// conditional.
	retriesDisabled := c.cfg.Limits.RetriesDisabled()
	var lastErr error
	// call accumulates what is known about the WHOLE Call, not about its last leg.
	// Seeded with the vacuous truth "nothing has been sent yet", which the first fold
	// replaces with real evidence — the loop below always runs at least one leg before
	// call is read. See foldLegFacts for why the two facts fold in opposite
	// directions.
	call := legFacts{neverSent: true}
	for attempt := 0; ; attempt++ {
		resp, facts, err := c.attempt(ctx, target, method, params, opts)
		if err == nil {
			return resp, nil
		}
		// Fold this leg into what is known about the whole Call, then carry THAT out
		// with the error — never the bare leg. Two facts ride out here:
		//
		// responseObserved: a non-200, a malformed body or a truncated read are
		// failures of the ANSWER: the peer received the invocation and any side effect
		// it has already happened. Without it the executor could only infer receipt
		// from a successfully DECODED response, so a known-executed attempt was
		// recorded as may_have_been_sent and sent for witness reconciliation that had
		// nothing left to establish.
		//
		// neverSent: the mirror, and the one that must survive a RETRY correctly — see
		// foldLegFacts. It is a conjunction across legs precisely because the last leg
		// can be the one that sent nothing while an earlier one reached the peer.
		call = foldLegFacts(call, facts)
		lastErr = markLegFacts(err, call)
		// EXACTLY-ONE-PHYSICAL-SEND (First Controlled Canary, blocker #6).
		// This test precedes retryable() deliberately: retryable() consults the
		// method's idempotency and whether the failure arrived before any response,
		// and BOTH are attacker- or peer-influenced. A peer that reads the full
		// request and then drops the connection produces exactly the
		// idempotent+preResponse shape that authorizes a re-send — which would turn
		// one accepted budget reservation into a second side-effect-bearing tool
		// invocation, with no emergency-kill re-read between them. In retry-free
		// mode there is no classification that can reach a second attempt.
		if retriesDisabled {
			return nil, lastErr
		}
		// facts, NOT call: retry classification is about the leg that just failed.
		if !retryable(opts.Idempotent, attempt, budget, facts.preResponse) {
			return nil, lastErr
		}
	}
}

// poolFor returns (creating if needed) the bounded per-server pool.
func (c *Client) poolFor(serverID string) *serverPool {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pools[serverID]
	if !ok {
		p = newServerPool(c.cfg.Limits)
		c.pools[serverID] = p
	}
	return p
}

// attempt performs one upstream round-trip. It returns (response, legFacts, error).
func (c *Client) attempt(ctx context.Context, target Target, method string, params json.RawMessage, opts CallOptions) (*Response, legFacts, error) {
	// Version-negotiation state and the JSON-RPC framing are the caller's concern;
	// this method transports one already-built message. The wire id is independent.
	wireID := opts.WireID
	if wireID == "" {
		wireID = "u-" + target.ServerID + "-" + method
	}
	body, err := buildRequest(method, wireID, params)
	if err != nil {
		return nil, legFacts{}, err
	}
	raw, facts, err := c.roundTrip(ctx, target, body, opts.AuthHeader, opts.AttemptID, opts.PreSend)
	if err != nil {
		return nil, facts, err
	}
	msg, err := jsonrpc.Decode(raw, c.kernelLim)
	if err != nil {
		// A malformed/hostile upstream response rejects the whole response. The bytes
		// still CAME from the peer, so facts (responseObserved) is carried through
		// unchanged: an unintelligible answer is still an answer.
		return nil, facts, mcperr.Wrap(mcperr.ReasonUpstreamResponseInvalid, "upstreamclient", "upstream response decode", err)
	}
	if !msg.IsResponse() {
		return nil, facts, mcperr.New(mcperr.ReasonUpstreamResponseInvalid, "upstreamclient", "upstream did not return a response")
	}
	return &Response{ID: msg.ID, Result: msg.Result, Error: msg.Error, RawBytes: raw}, facts, nil
}

// buildRequest constructs a strict single-object JSON-RPC request. Notifications
// (initialized/cancelled) carry no id.
func buildRequest(method, wireID string, params json.RawMessage) ([]byte, error) {
	obj := map[string]any{"jsonrpc": "2.0", "method": method}
	if !isNotification(method) {
		obj["id"] = wireID
	}
	if len(params) > 0 {
		obj["params"] = params
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonUpstreamCallFailed, "upstreamclient", "marshal request", err)
	}
	return b, nil
}

func isNotification(method string) bool {
	return method == "notifications/initialized" || method == "notifications/cancelled"
}

// NegotiateVersion returns the version to offer upstream (the primary), and
// validates a server-selected version is supported (no downgrade to a rejected
// era). It reuses the protocol package's version rules.
func NegotiateVersion(serverSelected protocol.Version) (protocol.Version, error) {
	if serverSelected == "" {
		return protocol.VersionPrimary, nil
	}
	if !protocol.IsSupported(serverSelected) {
		return "", mcperr.New(mcperr.ReasonUpstreamVersionUnsupported, "upstreamclient", "upstream selected an unsupported version")
	}
	return serverSelected, nil
}
