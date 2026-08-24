package runtime

import (
	"context"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/session"
)

// parseCredential extracts the bearer credential from the request headers ONLY,
// enforcing the location and duplication rules the listener owns before any PR-3
// token validation:
//
//   - a token presented in the query string is a forbidden location (rejected as
//     credential_in_query) — checked first, so it can never be silently ignored;
//   - more than one Authorization header is ambiguous/conflicting and rejected;
//   - the single header must carry a well-formed "Bearer <token>" or "DPoP <token>"
//     scheme; any other/malformed scheme is rejected;
//   - an absent credential where one is required is rejected.
//
// It never returns or logs the raw token beyond placing it in the Credential the
// PR-3 validator consumes.
func parseCredential(req Request) (authn.Credential, error) {
	if req.BearerInQuery {
		return authn.Credential{}, mcperr.New(mcperr.ReasonCredentialInQuery, "runtime.auth", "bearer credential presented in the query string is forbidden")
	}
	if len(req.AuthorizationHeaders) > 1 {
		return authn.Credential{}, mcperr.New(mcperr.ReasonCredentialMissing, "runtime.auth", "multiple Authorization headers (ambiguous credential source)")
	}
	if len(req.AuthorizationHeaders) == 0 {
		return authn.Credential{}, mcperr.New(mcperr.ReasonCredentialMissing, "runtime.auth", "no Authorization header")
	}
	raw := strings.TrimSpace(req.AuthorizationHeaders[0])
	scheme, token, ok := splitScheme(raw)
	if !ok {
		return authn.Credential{}, mcperr.New(mcperr.ReasonCredentialMissing, "runtime.auth", "malformed Authorization header (no scheme/token)")
	}
	switch strings.ToLower(scheme) {
	case "bearer", "dpop":
		// ok — both are header-location credentials; the sender-constraint profile
		// (PR-3) decides whether a DPoP proof is required, not the scheme label.
	default:
		return authn.Credential{}, mcperr.New(mcperr.ReasonUnsupportedTokenType, "runtime.auth", "unsupported Authorization scheme")
	}
	if token == "" {
		return authn.Credential{}, mcperr.New(mcperr.ReasonCredentialMissing, "runtime.auth", "empty credential token")
	}
	return authn.Credential{Location: authn.LocationAuthorizationHeader, Type: guessTokenType(token), Token: token}, nil
}

// splitScheme splits "Scheme token" into its two parts. It requires exactly one
// separating run of spaces and a non-empty scheme; a bare token with no scheme is
// not a valid Authorization value.
func splitScheme(v string) (scheme, token string, ok bool) {
	i := strings.IndexByte(v, ' ')
	if i <= 0 {
		return "", "", false
	}
	scheme = v[:i]
	token = strings.TrimSpace(v[i+1:])
	return scheme, token, true
}

// guessTokenType classifies a credential by shape: a compact JWT is exactly three
// non-empty dot-separated segments; anything else is treated as opaque and
// validated via introspection. The PR-3 validator re-checks the shape, so a
// mis-guess fails closed rather than bypassing validation.
func guessTokenType(token string) authn.TokenType {
	parts := strings.Split(token, ".")
	if len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != "" {
		return authn.TokenJWT
	}
	return authn.TokenOpaque
}

// authenticate runs the PR-3 authentication pipeline for one request and binds the
// resolved identity to the session (one-identity-per-session). Because the observe
// listener has no out-of-band principal-assertion channel, it derives the asserted
// principals (subject/client/tenant) from the cryptographically-validated token
// claims and then calls authn.Authenticate, which re-validates the token and
// cross-checks those principals against it. This DOUBLE token validation reuses the
// PR-3 APIs verbatim (ValidateJWT/ValidateOpaque + Authenticate) and duplicates no
// JWT/opaque/DPoP/mTLS logic.
//
// The observed mTLS thumbprint is passed as an EXPLICIT binding derived by the
// listener from the verified peer certificate; a client-supplied thumbprint header
// is never trusted and no private-key material is ever passed. On success the
// immutable identity is bound to the session; a second, DIFFERENT identity on the
// same session is rejected (the binding is immutable).
func (p *pipeline) authenticate(ctx context.Context, req Request, sess *session.Session, now time.Time) (*identity.ResolvedContext, error) {
	cred, err := parseCredential(req)
	if err != nil {
		return nil, err
	}
	// SEC-MCP-05: bound the CPU-expensive stages. Signature verification /
	// introspection runs under AuthConcurrency; a DPoP proof adds an independent
	// verification whose own bound is DPoPConcurrency. Both are acquired for exactly
	// the work they bound and released immediately after, so a token flood cannot
	// convert the worker pool into unbounded crypto.
	//
	// The wait is bounded by the REQUEST CONTEXT (SEC-MCP-02): a queue that ignored
	// the deadline would reintroduce the very unbounded stage the deadline exists to
	// bound, and a slot holder that stalls (a hung introspector) would park every
	// waiter for the process lifetime.
	release, err := p.acquireSlot(ctx, p.authSem)
	if err != nil {
		return nil, err
	}
	defer release()
	if req.HasDPoP {
		releaseDPoP, derr := p.acquireSlot(ctx, p.dpopSem)
		if derr != nil {
			return nil, derr
		}
		defer releaseDPoP()
	}

	// First validation: token → normalized claims (PR-3), used only to derive the
	// asserted principals the second call cross-checks.
	claims, err := p.validateClaims(cred, now)
	if err != nil {
		return nil, err
	}
	authReq, err := p.buildAuthRequest(req, cred, claims)
	if err != nil {
		return nil, err
	}
	ident, err := authn.Authenticate(authReq, p.authCfg, p.deps.authDeps(), now)
	if err != nil {
		return nil, err
	}
	// Immutable session-identity binding. A rejected auth never reaches here, so a
	// failed authentication can never overwrite or delete an existing binding.
	if _, err := p.bindings.Bind(sess.ID(), ident); err != nil {
		return nil, err
	}
	// Track the bound session so a later kernel sweep can unbind it (the binding
	// store has no per-session sweep hook of its own).
	p.trackBinding(sess.ID())
	return ident, nil
}

// validateClaims runs the PR-3 token validator that matches the credential type.
func (p *pipeline) validateClaims(cred authn.Credential, now time.Time) (*authn.Claims, error) {
	switch cred.Type {
	case authn.TokenJWT:
		if p.deps.Keys == nil {
			return nil, mcperr.New(mcperr.ReasonUnsupportedTokenType, "runtime.auth", "no key resolver for JWT validation")
		}
		return authn.ValidateJWT(cred.Token, p.authCfg, p.deps.Keys, now)
	case authn.TokenOpaque:
		if p.deps.Introspector == nil {
			return nil, mcperr.New(mcperr.ReasonUnsupportedTokenType, "runtime.auth", "no introspector for opaque validation")
		}
		return authn.ValidateOpaque(cred.Token, p.authCfg, p.deps.Introspector, now)
	default:
		return nil, mcperr.New(mcperr.ReasonUnsupportedTokenType, "runtime.auth", "unsupported token type")
	}
}

// buildAuthRequest assembles the PR-3 AuthRequest from the validated claims and the
// request binding. The subject is modeled as a Human principal keyed by the token
// subject (a pure token cannot reliably distinguish a workload).
//
// SEC-MCP-01 — assurance. The observe runtime holds NO out-of-band evidence of the
// subject's authentication strength, so it does not compute one from the request
// shape. It asserts the maximum a verified sender binding could justify and lets
// authn.Authenticate CLAMP that to what it actually verified (effectiveAssurance),
// which is the single authoritative source. Deriving it here from header PRESENCE
// (the previous `req.HasDPoP || req.PeerCertThumbprint != ""`) made an UNVERIFIED
// `DPoP:` header — never validated at all under a BearerControlled profile —
// satisfy the operator's MinAssurance floor and every `principal.assurance` policy
// condition. Nothing in this function may read an unverified request field into the
// assurance decision again.
func (p *pipeline) buildAuthRequest(req Request, cred authn.Credential, claims *authn.Claims) (authn.AuthRequest, error) {
	tenant := identity.TenantID(claims.Tenant)
	assur := identity.AssuranceHigh // requested ceiling; authn clamps it to the verified constraint
	subject := identity.Subject{
		Kind: identity.SubjectHuman,
		Human: &identity.Human{
			Subject:   claims.Subject,
			Tenant:    tenant,
			Assurance: assur,
			Issuer:    claims.Issuer,
		},
	}
	client := identity.Client{
		ClientID:   claims.ClientID,
		Tenant:     tenant,
		Capability: p.capability,
	}
	authReq := authn.AuthRequest{
		Credential: cred,
		Subject:    subject,
		Client:     client,
		Tenant:     identity.Tenant{ID: tenant},
		Binding: authn.RequestBinding{
			HTTPMethod:             req.HTTPMethod,
			HTTPURI:                req.CanonicalURI,
			DPoPProof:              req.DPoPProof,
			ObservedCertThumbprint: req.PeerCertThumbprint,
		},
	}
	// Gateway resolves the opaque ServerID from the route; Management never carries
	// server/tool authority.
	if p.capability == protocol.Gateway {
		if req.ServerID == "" {
			return authn.AuthRequest{}, mcperr.New(mcperr.ReasonRegistryServerUnavailable, "runtime.auth", "gateway request without a server id")
		}
		sid := registry.ServerID(req.ServerID)
		authReq.Server = &sid
	}
	return authReq, nil
}

// acquireSlot takes one slot from a concurrency semaphore, WAITING rather than
// shedding (shedding would turn a tuning knob into an availability cliff) but only
// for as long as the request's own budget lasts. A request whose context ends
// while queued is refused with request_deadline_exceeded — the same classification
// the pipeline's stage-boundary budget checks produce — so a saturated or stalled
// verification stage can never park a caller indefinitely.
func (p *pipeline) acquireSlot(ctx context.Context, sem chan struct{}) (func(), error) {
	if ctx == nil {
		sem <- struct{}{}
		return func() { <-sem }, nil
	}
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		p.ctr.timeouts.Add(1)
		return nil, mcperr.New(mcperr.ReasonRequestDeadlineExceeded, "runtime.auth", "request budget elapsed while queued for a verification slot")
	}
}
