package authn

import (
	"crypto/subtle"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// VerifiedCredential is unforgeable proof that ONE credential was
// cryptographically validated against ONE CapabilityAuthConfig.
//
// It exists to remove a genuine 2x amplification of the most expensive
// attacker-reachable operation (OVN-06). The observe runtime validated every
// request's token TWICE: once to derive the asserted principals, and again inside
// Authenticate, which re-validates. Measured on the live pipeline that was 2 full
// ECDSA P-256 verifications per request — ~96 µs of a ~206 µs authenticated
// request (47%), plus 8.7 KB and 206 allocations, for work whose result was
// already known.
//
// Every field is unexported and the ONLY constructor is ValidateCredential, so an
// ordinary caller cannot fabricate one or mutate one after the fact. It carries
// no capability of its own: presenting it to AuthenticateVerified re-runs every
// non-cryptographic check (cross-check, sender constraint, assurance clamp,
// identity resolution) exactly as Authenticate does.
type VerifiedCredential struct {
	cred   Credential
	claims *Claims
	cfgID  string
	at     time.Time
}

// The verified claim set is deliberately NOT exposed as a pointer.
//
// VerifiedCredential exists to be a proof that a credential was cryptographically
// validated, and AuthenticateVerified re-reads the stored claims to cross-check the
// principals a caller asserts. Handing out *Claims made that cross-check
// self-referential: a caller could validate a legitimate token, mutate the returned
// issuer, audiences, scopes, tenant or confirmation key, build an AuthRequest that
// matches the mutation, and pass both back — AuthenticateVerified re-checks only
// time and compares the assertions against those same mutated claims, so the
// issuer/audience/scope validation done at ValidateCredential no longer constrains
// what gets resolved.
//
// No caller today does that, and none can be induced to from outside the process —
// this is an API-safety defect, not a live bypass. But the whole point of the type
// is that holding one PROVES something, and a proof you can edit after the fact
// proves nothing.
//
// The accessors below return value copies of exactly the scalars the runtime needs
// to build an AuthRequest. Slice-valued claims (audiences, scopes) are deliberately
// absent: nothing outside this package needs them, and returning one would hand
// back shared backing memory — reintroducing the same defect in a subtler form. Add
// a new accessor only for a scalar, and only when a caller genuinely needs it.

// Issuer returns the validated `iss`.
func (v *VerifiedCredential) Issuer() string { return v.claims.Issuer }

// Subject returns the validated `sub`.
func (v *VerifiedCredential) Subject() string { return v.claims.Subject }

// ClientID returns the validated `client_id` (or `azp`).
func (v *VerifiedCredential) ClientID() string { return v.claims.ClientID }

// Tenant returns the validated tenant claim.
func (v *VerifiedCredential) Tenant() string { return v.claims.Tenant }

// ValidateCredential performs the ONE cryptographic validation of a credential
// against cfg: the forbidden-location check, then the JWT signature or opaque
// introspection path, then the capability policy (issuer / audience / scopes /
// lifetime). It makes NO identity or authorization decision.
func ValidateCredential(cred Credential, cfg CapabilityAuthConfig, deps Deps, now time.Time) (*VerifiedCredential, error) {
	if err := checkCredentialLocation(cred); err != nil {
		return nil, err
	}
	claims, err := validateToken(cred, cfg, deps, now)
	if err != nil {
		return nil, err
	}
	return &VerifiedCredential{cred: cred, claims: claims, cfgID: cfg.cfgID, at: now}, nil
}

// AuthenticateVerified completes authentication for an ALREADY-VALIDATED
// credential: it cross-checks the caller's asserted principals against the
// verified token, verifies the required sender constraint, clamps assurance to
// what was verified, and resolves the immutable identity.
//
// It is the second half of Authenticate, which is now DEFINED as
// ValidateCredential + AuthenticateVerified — so there is exactly one code path
// and the split cannot drift from the combined API.
//
// Four guards make the split safe. Each fails CLOSED:
//
//  1. a nil VerifiedCredential is refused (no "unverified means fine" branch);
//  2. the credential presented in req must be byte-identical to the one that was
//     verified — otherwise a caller could validate token A and authenticate token
//     B (the TOCTOU / swap);
//  3. the config identity must match the one the credential was verified against
//     — otherwise a token verified for Gateway could be presented under the
//     Management config, defeating capability isolation;
//  4. the time-based claims are RE-CHECKED against the caller's `now`, so a
//     credential verified earlier cannot be redeemed after it expires. This is
//     free (no cryptography) and removes the staleness class entirely.
func AuthenticateVerified(v *VerifiedCredential, req AuthRequest, cfg CapabilityAuthConfig, deps Deps, now time.Time) (*identity.ResolvedContext, error) {
	if v == nil || v.claims == nil {
		return nil, mcperr.New(mcperr.ReasonCredentialMissing, "authn", "no verified credential")
	}
	// The credential actually presented must be the one that was verified.
	if subtle.ConstantTimeCompare([]byte(v.cred.Token), []byte(req.Credential.Token)) != 1 ||
		v.cred.Location != req.Credential.Location || v.cred.Type != req.Credential.Type {
		return nil, mcperr.New(mcperr.ReasonCredentialMissing, "authn", "presented credential is not the verified one")
	}
	// The verification must have been performed against THIS capability config.
	if v.cfgID == "" || cfg.cfgID == "" || subtle.ConstantTimeCompare([]byte(v.cfgID), []byte(cfg.cfgID)) != 1 {
		return nil, mcperr.New(mcperr.ReasonCapabilityMismatch, "authn", "credential was verified against a different capability config")
	}
	// Time-based claims are re-checked against the CALLER's clock: a credential
	// verified at T must not be redeemable at T + lifetime.
	if err := validateTime(v.claims, cfg, now); err != nil {
		return nil, err
	}
	return resolveVerified(v, req, cfg, deps, now)
}

// resolveVerified runs the non-cryptographic remainder shared by Authenticate and
// AuthenticateVerified. Keeping it in ONE function is what makes the two entry
// points provably equivalent.
func resolveVerified(v *VerifiedCredential, req AuthRequest, cfg CapabilityAuthConfig, deps Deps, now time.Time) (*identity.ResolvedContext, error) {
	claims := v.claims
	if err := crossCheck(claims, req); err != nil {
		return nil, err
	}
	sender, err := verifySenderConstraint(req, cfg, claims, deps, now)
	if err != nil {
		return nil, err
	}
	// SEC-MCP-01. Effective assurance is a property of what was CRYPTOGRAPHICALLY
	// VERIFIED on THIS request, never of what the caller asserted.
	effective := effectiveAssurance(req.Subject, sender)
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
		Assurance:         effective,
		SenderConstraint:  sender,
		Expiry:            time.Unix(claims.Expiry, 0),
		TokenDigest:       tokenDigest(v.cred.Token),
	}
	if claims.HasAuthTime {
		in.AuthTime = time.Unix(claims.AuthTime, 0)
		in.HasAuthTime = true
	}
	if effective < cfg.minAssurance {
		return nil, mcperr.New(mcperr.ReasonDelegationChainInvalid, "authn", "subject assurance below the capability minimum")
	}
	return identity.Resolve(in, deps.Registry, deps.Catalog)
}

// checkCredentialLocation rejects a credential presented anywhere other than the
// Authorization header.
func checkCredentialLocation(cred Credential) error {
	switch cred.Location {
	case LocationAuthorizationHeader:
		return nil
	case LocationQueryString:
		return mcperr.New(mcperr.ReasonCredentialInQuery, "authn", "bearer token in query string is forbidden")
	default:
		return mcperr.New(mcperr.ReasonCredentialMissing, "authn", "no credential in a supported location")
	}
}
