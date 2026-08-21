package authn

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// Location is where the credential was presented. A bearer token in the query
// string is a forbidden location, rejected before any normal validation.
type Location uint8

const (
	// LocationUnknown — unspecified (rejected).
	LocationUnknown Location = iota
	// LocationAuthorizationHeader — the only supported bearer location.
	LocationAuthorizationHeader
	// LocationQueryString — forbidden; rejected as credential_in_query.
	LocationQueryString
	// LocationOther — any other explicitly unsupported location.
	LocationOther
)

// TokenType selects the validation path.
type TokenType uint8

const (
	// TokenJWT — a signed compact JWT.
	TokenJWT TokenType = iota
	// TokenOpaque — an opaque token validated via introspection metadata.
	TokenOpaque
)

// Credential is the presented token with its stated provenance. The raw Token is
// used only during validation and is never copied into the resolved context.
type Credential struct {
	Location Location
	Type     TokenType
	Token    string
}

// RequestBinding is the caller-supplied request metadata for sender-constraint
// verification (no network I/O). DPoPProof/HTTPMethod/HTTPURI/Nonce drive DPoP;
// ObservedCertThumbprint drives mTLS.
type RequestBinding struct {
	HTTPMethod             string
	HTTPURI                string
	Nonce                  string
	DPoPProof              string
	ObservedCertThumbprint string
}

// AuthRequest is the full input to Authenticate. The caller supplies the typed
// principals (which a token cannot express — e.g. Human vs Workload and their
// type-specific fields); Authenticate cross-checks their stable ids against the
// cryptographically-validated token before resolving the identity.
type AuthRequest struct {
	Credential Credential
	Subject    identity.Subject
	Agent      *identity.Agent
	Client     identity.Client
	Tenant     identity.Tenant
	Server     *registry.ServerID
	Tool       *identity.ToolRef
	Resource   *identity.ResourceRef
	Binding    RequestBinding
}

// Deps carries the caller-supplied validation dependencies (no network I/O).
type Deps struct {
	Keys         KeyResolver
	Introspector Introspector
	Registry     *registry.Registry
	Catalog      *catalog.Catalog
	Replay       *senderconstraint.ReplayCache
}

// Authenticate is the top-level composition: it rejects a forbidden credential
// location, validates the token (JWT or opaque), cross-checks the token ids
// against the caller's typed principals, verifies the required sender constraint,
// and resolves the immutable identity context. It returns the context or a typed
// rejection, and never returns the raw token.
func Authenticate(req AuthRequest, cfg CapabilityAuthConfig, deps Deps, now time.Time) (*identity.ResolvedContext, error) {
	switch req.Credential.Location {
	case LocationAuthorizationHeader:
		// ok
	case LocationQueryString:
		return nil, mcperr.New(mcperr.ReasonCredentialInQuery, "authn", "bearer token in query string is forbidden")
	default:
		return nil, mcperr.New(mcperr.ReasonCredentialMissing, "authn", "no credential in a supported location")
	}

	claims, err := validateToken(req.Credential, cfg, deps, now)
	if err != nil {
		return nil, err
	}
	if err := crossCheck(claims, req); err != nil {
		return nil, err
	}
	sender, err := verifySenderConstraint(req, cfg, claims, deps, now)
	if err != nil {
		return nil, err
	}
	in := identity.ResolveInput{
		Capability:        cfg.capability,
		Tenant:            req.Tenant,
		Subject:           req.Subject,
		Agent:             req.Agent,
		Client:            req.Client,
		Server:            req.Server,
		Tool:              req.Tool,
		Resource:          req.Resource,
		CanonicalResource: cfg.canonicalResource,
		Issuer:            claims.Issuer,
		Scopes:            claims.Scopes,
		Assurance:         subjectAssurance(req.Subject),
		SenderConstraint:  sender,
		Expiry:            time.Unix(claims.Expiry, 0),
		TokenDigest:       jose.SHA256B64URL([]byte(req.Credential.Token)),
	}
	if claims.HasAuthTime {
		in.AuthTime = time.Unix(claims.AuthTime, 0)
		in.HasAuthTime = true
	}
	if subjectAssurance(req.Subject) < cfg.minAssurance {
		return nil, mcperr.New(mcperr.ReasonDelegationChainInvalid, "authn", "subject assurance below the capability minimum")
	}
	return identity.Resolve(in, deps.Registry, deps.Catalog)
}

func validateToken(cred Credential, cfg CapabilityAuthConfig, deps Deps, now time.Time) (*Claims, error) {
	switch cred.Type {
	case TokenJWT:
		if deps.Keys == nil {
			return nil, mcperr.New(mcperr.ReasonUnsupportedTokenType, "authn", "no key resolver for JWT validation")
		}
		return ValidateJWT(cred.Token, cfg, deps.Keys, now)
	case TokenOpaque:
		if deps.Introspector == nil {
			return nil, mcperr.New(mcperr.ReasonUnsupportedTokenType, "authn", "no introspector for opaque validation")
		}
		return ValidateOpaque(cred.Token, cfg, deps.Introspector, now)
	default:
		return nil, mcperr.New(mcperr.ReasonUnsupportedTokenType, "authn", "unsupported token type")
	}
}

// crossCheck binds the caller's typed principals to the validated token: the
// token's sub/client/tenant must match the asserted subject/client/tenant ids.
func crossCheck(c *Claims, req AuthRequest) error {
	if subjectID(req.Subject) != c.Subject {
		return mcperr.New(mcperr.ReasonDelegationChainInvalid, "authn", "asserted subject does not match the token subject")
	}
	if req.Client.ClientID != c.ClientID {
		return mcperr.New(mcperr.ReasonDelegationChainInvalid, "authn", "asserted client does not match the token client")
	}
	if string(req.Tenant.ID) != c.Tenant {
		return mcperr.New(mcperr.ReasonTenantMismatch, "authn", "asserted tenant does not match the token tenant")
	}
	return nil
}

// verifySenderConstraint enforces the deployment profile against the token cnf and
// the request binding. The zero profile and every constrained profile fail closed
// when their required binding is absent.
func verifySenderConstraint(req AuthRequest, cfg CapabilityAuthConfig, claims *Claims, deps Deps, now time.Time) (identity.SenderConstraint, error) {
	prof := cfg.senderProfile
	switch prof {
	case senderconstraint.BearerControlled:
		return identity.SenderConstraint{Method: identity.ConfirmNone}, nil
	case senderconstraint.DPoPRequired:
		return verifyDPoP(req, cfg, claims, deps, now)
	case senderconstraint.MTLSRequired:
		return verifyMTLS(req, claims)
	case senderconstraint.DPoPOrMTLSRequired:
		if req.Binding.DPoPProof != "" {
			return verifyDPoP(req, cfg, claims, deps, now)
		}
		if req.Binding.ObservedCertThumbprint != "" || claims.CnfX5T != "" {
			return verifyMTLS(req, claims)
		}
		return identity.SenderConstraint{}, mcperr.New(mcperr.ReasonSenderConstraintRequired, "authn", "profile requires DPoP or mTLS; neither presented")
	default:
		return identity.SenderConstraint{}, mcperr.New(mcperr.ReasonSenderConstraintRequired, "authn", "sender-constraint profile is unset (fail closed)")
	}
}

func verifyDPoP(req AuthRequest, cfg CapabilityAuthConfig, claims *Claims, deps Deps, now time.Time) (identity.SenderConstraint, error) {
	if req.Binding.DPoPProof == "" {
		return identity.SenderConstraint{}, mcperr.New(mcperr.ReasonSenderConstraintRequired, "authn", "DPoP required but no proof presented")
	}
	if deps.Replay == nil {
		return identity.SenderConstraint{}, mcperr.New(mcperr.ReasonSenderConstraintRequired, "authn", "no replay cache; cannot admit a required DPoP proof (fail closed)")
	}
	res, err := senderconstraint.VerifyDPoP(senderconstraint.DPoPInput{
		Capability:  cfg.capability,
		ProofJWT:    req.Binding.DPoPProof,
		HTTPMethod:  req.Binding.HTTPMethod,
		HTTPURI:     req.Binding.HTTPURI,
		AccessToken: req.Credential.Token,
		ExpectedJKT: claims.CnfJKT,
		Issuer:      claims.Issuer,
		Client:      claims.ClientID,
		Nonce:       req.Binding.Nonce,
	}, deps.Replay, cfg.lim, now)
	if err != nil {
		return identity.SenderConstraint{}, err
	}
	return identity.SenderConstraint{Method: identity.ConfirmDPoP, Thumbprint: res.Thumbprint}, nil
}

func verifyMTLS(req AuthRequest, claims *Claims) (identity.SenderConstraint, error) {
	tp, err := senderconstraint.VerifyMTLS(senderconstraint.MTLSInput{
		ObservedThumbprint: req.Binding.ObservedCertThumbprint,
		TokenX5TS256:       claims.CnfX5T,
	})
	if err != nil {
		return identity.SenderConstraint{}, err
	}
	return identity.SenderConstraint{Method: identity.ConfirmMTLS, Thumbprint: tp}, nil
}

func subjectID(s identity.Subject) string {
	switch s.Kind {
	case identity.SubjectHuman:
		if s.Human != nil {
			return s.Human.Subject
		}
	case identity.SubjectWorkload:
		if s.Workload != nil {
			return s.Workload.Service
		}
	}
	return ""
}

func subjectAssurance(s identity.Subject) identity.AssuranceLevel {
	switch s.Kind {
	case identity.SubjectHuman:
		if s.Human != nil {
			return s.Human.Assurance
		}
	case identity.SubjectWorkload:
		// A workload earns high assurance ONLY when it carries attestation material;
		// an unattested workload cannot satisfy a high MinAssurance floor by merely
		// labelling itself a workload (that would be an assurance-escalation seam).
		if s.Workload != nil && s.Workload.Attestation != "" {
			return identity.AssuranceHigh
		}
		return identity.AssuranceLow
	}
	return identity.AssuranceUnknown
}
