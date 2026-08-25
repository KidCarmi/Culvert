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
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
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
// claims and then completes authentication against that SAME verification via
// authn.AuthenticateVerified. The credential is validated EXACTLY ONCE (OVN-06);
// no JWT/opaque/DPoP/mTLS logic is duplicated here.
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
	//
	// OVN-02 — ORDER. The DPoP bound is acquired FIRST. Taking the auth slot and
	// then waiting for the DPoP slot while holding it is hold-and-wait: DPoP waiters
	// would occupy the auth pool while doing no authentication work, starving every
	// caller that needs only the auth bound as soon as DPoPConcurrency saturates.
	// Scarcest-first means a caller queued for DPoP holds nothing, and the number of
	// DPoP callers inside the auth pool is bounded by DPoPConcurrency.
	if dpopVerificationRuns(p.authCfg.SenderProfile(), req.HasDPoP) {
		releaseDPoP, derr := p.acquireSlot(ctx, p.dpopSem)
		if derr != nil {
			return nil, derr
		}
		defer releaseDPoP()
	}
	release, err := p.acquireSlot(ctx, p.authSem)
	if err != nil {
		return nil, err
	}
	defer release()

	// OVN-06. The credential is validated EXACTLY ONCE. The runtime has no
	// out-of-band principal channel, so it derives the asserted principals from the
	// validated claims and then completes authentication against the SAME
	// verification — rather than handing the raw token back to Authenticate, which
	// would verify the signature a second time. Measured, that second verification
	// was ~96 µs of a ~206 µs authenticated request (47%), 8.7 KB and 206 allocs,
	// for a result already known: a 2x amplification of the most expensive
	// attacker-reachable operation.
	//
	// Nothing is weakened. AuthenticateVerified still runs every non-cryptographic
	// check the combined API runs — cross-check, sender constraint, assurance clamp,
	// identity resolution — and refuses a verification that does not match the
	// presented credential, was made against a different capability config, or whose
	// token has since expired.
	verified, err := authn.ValidateCredential(cred, p.authCfg, p.deps.authDeps(), now)
	if err != nil {
		return nil, err
	}
	authReq, err := p.buildAuthRequest(req, cred, verified)
	if err != nil {
		return nil, err
	}
	ident, err := authn.AuthenticateVerified(verified, authReq, p.authCfg, p.deps.authDeps(), now)
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
// It takes the VerifiedCredential itself rather than a *authn.Claims: the proof
// object exposes value copies of the scalars needed here, so this function cannot
// mutate the claim set that AuthenticateVerified then cross-checks against.
func (p *pipeline) buildAuthRequest(req Request, cred authn.Credential, verified *authn.VerifiedCredential) (authn.AuthRequest, error) {
	tenant := identity.TenantID(verified.Tenant())
	assur := identity.AssuranceHigh // requested ceiling; authn clamps it to the verified constraint
	subject := identity.Subject{
		Kind: identity.SubjectHuman,
		Human: &identity.Human{
			Subject:   verified.Subject(),
			Tenant:    tenant,
			Assurance: assur,
			Issuer:    verified.Issuer(),
		},
	}
	client := identity.Client{
		ClientID:   verified.ClientID(),
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
		// A select whose cases are BOTH ready picks uniformly at random, so under
		// saturation a slot freeing at the instant the budget expires lands here half
		// the time -- and verification would then start on a request whose deadline
		// has already passed, defeating the bound and misclassifying the result as a
		// credential verdict instead of a timeout. Re-check and hand the slot straight
		// back; a request past its budget must not consume a scarce security bound.
		if ctx.Err() != nil {
			<-sem
			p.ctr.timeouts.Add(1)
			return nil, mcperr.New(mcperr.ReasonRequestDeadlineExceeded, "runtime.auth", "request budget elapsed before the verification slot was used")
		}
		return func() { <-sem }, nil
	case <-ctx.Done():
		p.ctr.timeouts.Add(1)
		return nil, mcperr.New(mcperr.ReasonRequestDeadlineExceeded, "runtime.auth", "request budget elapsed while queued for a verification slot")
	}
}

// dpopVerificationRuns reports whether this request will actually reach DPoP proof
// verification, and therefore whether it must consume a DPoPConcurrency slot.
//
// OVN-01. Gating on `HasDPoP` alone gated on an ATTACKER-SUPPLIED HEADER: under a
// bearer or mTLS profile the proof is never verified, and under DPoPRequired with
// no proof presented verifyDPoP errors before any cryptography — so a caller could
// consume a scarce security bound for work that is never performed. A bound that
// can be drained without doing the work it bounds is an amplifier, not a control.
//
// It mirrors authn.verifySenderConstraint exactly: BearerControlled and
// MTLSRequired never call verifyDPoP; DPoPRequired and DPoPOrMTLSRequired reach it
// only with a proof actually present. Keep the two in agreement — a slot taken
// where no verification runs is an amplifier, and verification running without a
// slot is an unbounded stage.
func dpopVerificationRuns(prof senderconstraint.Profile, hasProof bool) bool {
	if !hasProof {
		return false
	}
	return prof == senderconstraint.DPoPRequired || prof == senderconstraint.DPoPOrMTLSRequired
}
