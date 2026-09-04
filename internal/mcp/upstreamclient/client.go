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
	if !Admitted(method) {
		return nil, mcperr.New(mcperr.ReasonUpstreamTransportRejected, "upstreamclient", "method not admitted upstream")
	}
	if target.Endpoint == "" || target.ServerID == "" {
		return nil, mcperr.New(mcperr.ReasonUpstreamEndpointInvalid, "upstreamclient", "endpoint must come from the registered record")
	}
	pool := c.poolFor(target.ServerID)
	release, err := pool.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	budget := c.cfg.Limits.MaxReadRetries()
	// Retry-free mode is decided ONCE, outside the loop, from immutable validated
	// limits — not re-derived per attempt where a later edit could make it
	// conditional.
	retriesDisabled := c.cfg.Limits.RetriesDisabled()
	var lastErr error
	for attempt := 0; ; attempt++ {
		resp, preResponse, err := c.attempt(ctx, target, method, params, opts)
		if err == nil {
			return resp, nil
		}
		lastErr = err
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
		if !retryable(opts.Idempotent, attempt, budget, preResponse) {
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

// attempt performs one upstream round-trip. It returns (response, preResponse,
// error): preResponse is true when the failure occurred BEFORE any response was
// received (so an idempotent read may retry).
func (c *Client) attempt(ctx context.Context, target Target, method string, params json.RawMessage, opts CallOptions) (*Response, bool, error) {
	// Version-negotiation state and the JSON-RPC framing are the caller's concern;
	// this method transports one already-built message. The wire id is independent.
	wireID := opts.WireID
	if wireID == "" {
		wireID = "u-" + target.ServerID + "-" + method
	}
	body, err := buildRequest(method, wireID, params)
	if err != nil {
		return nil, false, err
	}
	raw, preResponse, err := c.roundTrip(ctx, target, body, opts.AuthHeader)
	if err != nil {
		return nil, preResponse, err
	}
	msg, err := jsonrpc.Decode(raw, c.kernelLim)
	if err != nil {
		// A malformed/hostile upstream response rejects the whole response.
		return nil, false, mcperr.Wrap(mcperr.ReasonUpstreamResponseInvalid, "upstreamclient", "upstream response decode", err)
	}
	if !msg.IsResponse() {
		return nil, false, mcperr.New(mcperr.ReasonUpstreamResponseInvalid, "upstreamclient", "upstream did not return a response")
	}
	return &Response{ID: msg.ID, Result: msg.Result, Error: msg.Error, RawBytes: raw}, false, nil
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
