package authn

import (
	"reflect"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// OVN-06. Authenticate must remain EXACTLY ValidateCredential +
// AuthenticateVerified. This is the equivalence argument for the split: there is
// one code path, so the two entry points cannot drift apart.
func TestVerified_SplitIsEquivalentToAuthenticate(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	cfg := gatewayConfig(t)
	deps := Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}
	req := bearerRequest(t, now, k, identity.AssuranceLow)

	combined, cerr := Authenticate(req, cfg, deps, now)
	if cerr != nil {
		t.Fatalf("Authenticate: %v", cerr)
	}
	v, err := ValidateCredential(req.Credential, cfg, deps, now)
	if err != nil {
		t.Fatalf("ValidateCredential: %v", err)
	}
	split, serr := AuthenticateVerified(v, req, cfg, deps, now)
	if serr != nil {
		t.Fatalf("AuthenticateVerified: %v", serr)
	}
	if combined.Fingerprint() != split.Fingerprint() {
		t.Fatal("split and combined paths resolved different identities")
	}
	if combined.TokenDigest() != split.TokenDigest() ||
		combined.Assurance() != split.Assurance() ||
		combined.SenderConstraint() != split.SenderConstraint() ||
		combined.CanonicalResource() != split.CanonicalResource() ||
		combined.Issuer() != split.Issuer() {
		t.Fatal("split and combined paths disagree on a resolved field")
	}
}

// A VerifiedCredential is not a bearer capability: presenting it alongside a
// DIFFERENT token must be refused. Otherwise a caller could validate a token it
// holds and then authenticate one it does not (the swap / TOCTOU).
func TestVerified_PresentedCredentialMustBeTheVerifiedOne(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	cfg := gatewayConfig(t)
	deps := Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}

	good := bearerRequest(t, now, k, identity.AssuranceLow)
	v, err := ValidateCredential(good.Credential, cfg, deps, now)
	if err != nil {
		t.Fatalf("ValidateCredential: %v", err)
	}

	// Same shape, different token bytes.
	other := good
	other.Credential.Token = good.Credential.Token + "x"
	if _, err := AuthenticateVerified(v, other, cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonCredentialMissing {
		t.Fatalf("a swapped token must be refused, got %v", err)
	}
	// A different presented LOCATION is equally a mismatch.
	loc := good
	loc.Credential.Location = LocationQueryString
	if _, err := AuthenticateVerified(v, loc, cfg, deps, now); err == nil {
		t.Fatal("a credential presented from a different location must be refused")
	}
}

// A credential verified for one capability must never be redeemable under
// another: that would defeat capability isolation at the one place the
// cryptographic check is skipped.
func TestVerified_CannotBeRedeemedUnderADifferentConfig(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	deps := Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}
	gw := gatewayConfig(t)
	req := bearerRequest(t, now, k, identity.AssuranceLow)

	v, err := ValidateCredential(req.Credential, gw, deps, now)
	if err != nil {
		t.Fatalf("ValidateCredential: %v", err)
	}
	if _, err := AuthenticateVerified(v, req, managementConfig(t), deps, now); mcperr.ReasonOf(err) != mcperr.ReasonCapabilityMismatch {
		t.Fatalf("cross-capability redemption must be refused, got %v", err)
	}

	// Even a SAME-capability config that differs in an acceptance-relevant field is
	// a different config: the identity is over content, not over the capability.
	narrowed, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.MTLSRequired,
		Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateVerified(v, req, narrowed, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonCapabilityMismatch {
		t.Fatalf("redemption under a differently-configured capability must be refused, got %v", err)
	}
}

// A verified credential must not outlive the token it verified. The time-based
// claims are re-checked against the redeeming caller's clock.
func TestVerified_ExpiresWithItsToken(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	cfg := gatewayConfig(t)
	deps := Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}
	req := bearerRequest(t, now, k, identity.AssuranceLow)

	v, err := ValidateCredential(req.Credential, cfg, deps, now)
	if err != nil {
		t.Fatalf("ValidateCredential: %v", err)
	}
	// baseGatewayClaims expires 10 minutes out; redeem an hour later.
	if _, err := AuthenticateVerified(v, req, cfg, deps, now.Add(time.Hour)); mcperr.ReasonOf(err) != mcperr.ReasonTokenExpired {
		t.Fatalf("a stale verified credential must be refused as expired, got %v", err)
	}
}

// Fail closed on a nil verification: there is no "unverified is fine" branch.
func TestVerified_NilIsRefused(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	req := bearerRequest(t, now, k, identity.AssuranceLow)
	if _, err := AuthenticateVerified(nil, req, gatewayConfig(t), Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}, now); err == nil {
		t.Fatal("a nil verified credential must be refused")
	}
}

// The forbidden-location rule still applies at validation time, before any
// cryptography.
func TestVerified_QueryLocationIsRefusedAtValidation(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	req := bearerRequest(t, now, k, identity.AssuranceLow)
	req.Credential.Location = LocationQueryString
	if _, err := ValidateCredential(req.Credential, gatewayConfig(t), Deps{Keys: resolverFor(k)}, now); mcperr.ReasonOf(err) != mcperr.ReasonCredentialInQuery {
		t.Fatalf("query-string credential must be refused, got %v", err)
	}
}

// The config identity must be a function of CONTENT, not of map iteration order:
// two independently-built identical configs must share it, and any
// acceptance-relevant difference must break it.
func TestVerified_ConfigIdentityIsContentAddressed(t *testing.T) {
	a, b := gatewayConfig(t), gatewayConfig(t)
	if a.cfgID == "" || a.cfgID != b.cfgID {
		t.Fatalf("identical configs must share an identity (%q vs %q)", a.cfgID, b.cfgID)
	}
	if gatewayConfig(t).cfgID == managementConfig(t).cfgID {
		t.Fatal("different capabilities must not share a config identity")
	}
	diff := func(in CapabilityConfigInput) string {
		c, err := NewCapabilityConfig(in)
		if err != nil {
			t.Fatal(err)
		}
		return c.cfgID
	}
	base := CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.BearerControlled,
		Limits: testAuthLimits(),
	}
	baseID := diff(base)
	mutations := map[string]func(*CapabilityConfigInput){
		"issuer":    func(i *CapabilityConfigInput) { i.TrustedIssuers = []string{"https://other/issuer"} },
		"client":    func(i *CapabilityConfigInput) { i.AcceptedClientIDs = []string{"other-client"} },
		"resource":  func(i *CapabilityConfigInput) { i.CanonicalResource = "/mcp/gateway/srv-2" },
		"scope":     func(i *CapabilityConfigInput) { i.RequiredScopes = []string{"gateway.tools.other"} },
		"profile":   func(i *CapabilityConfigInput) { i.SenderProfile = senderconstraint.DPoPRequired },
		"assurance": func(i *CapabilityConfigInput) { i.MinAssurance = identity.AssuranceHigh },
	}
	for name, mut := range mutations {
		in := base
		mut(&in)
		if diff(in) == baseID {
			t.Fatalf("changing %s did not change the config identity", name)
		}
	}
}

// A VerifiedCredential is a PROOF that a credential was cryptographically
// validated, and AuthenticateVerified cross-checks a caller's asserted principals
// against the claims it stores. Exposing those claims as a pointer made that
// cross-check self-referential: mutate the stored issuer/tenant/subject/client and
// the assertions that "match" are matching the mutation, not the validated token.
//
// The type must therefore expose no handle through which its verified state can be
// edited. This is a structural test because the property is an ABSENCE — no
// behavioural test can prove a method that does not exist.
func TestVerified_ExposesNoMutableHandleOnItsClaims(t *testing.T) {
	vt := reflect.TypeOf(&VerifiedCredential{})
	claimsType := reflect.TypeOf(Claims{})
	for i := 0; i < vt.NumMethod(); i++ {
		m := vt.Method(i)
		for r := 0; r < m.Type.NumOut(); r++ {
			out := m.Type.Out(r)
			// A pointer to the claim set, or the struct by value carrying its slices,
			// both hand back state the holder can change.
			if out == reflect.PointerTo(claimsType) || out == claimsType {
				t.Errorf("method %s returns %s: the verified claim set must not escape as a "+
					"mutable handle — expose value copies of the scalars a caller needs instead",
					m.Name, out)
			}
			if out.Kind() == reflect.Slice || out.Kind() == reflect.Map || out.Kind() == reflect.Pointer {
				t.Errorf("method %s returns %s: a slice, map or pointer shares backing state "+
					"with the proof object and reintroduces the same defect", m.Name, out)
			}
		}
	}
}

// The scalar accessors must report what was actually validated, so replacing the
// pointer with copies did not also disconnect them from the verified claims.
func TestVerified_ScalarAccessorsReportTheValidatedClaims(t *testing.T) {
	v := &VerifiedCredential{claims: &Claims{
		Issuer: "https://idp.example", Subject: "sub-1", ClientID: "client-1", Tenant: "tenant-1",
	}}
	if got := v.Issuer(); got != "https://idp.example" {
		t.Errorf("Issuer() = %q", got)
	}
	if got := v.Subject(); got != "sub-1" {
		t.Errorf("Subject() = %q", got)
	}
	if got := v.ClientID(); got != "client-1" {
		t.Errorf("ClientID() = %q", got)
	}
	if got := v.Tenant(); got != "tenant-1" {
		t.Errorf("Tenant() = %q", got)
	}
}
