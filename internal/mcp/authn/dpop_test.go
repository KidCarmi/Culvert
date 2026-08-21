package authn

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

func gatewayDPoPConfig(t testing.TB) CapabilityAuthConfig {
	t.Helper()
	cfg, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.DPoPRequired,
		Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// gwRegistry registers srv-1 so Gateway resolution succeeds.
func gwRegistry(t testing.TB) *registry.Registry {
	t.Helper()
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: "srv-1", Endpoint: "mcp://srv-1", PinnedIdentity: "spiffe://srv-1",
		Capability: protocol.Gateway, CredentialProfile: "cred-a",
	}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func dpopRequest(t testing.TB, now time.Time, sk, pk *esKey, proofClaims map[string]any, tokenExtra func(map[string]any)) AuthRequest {
	t.Helper()
	claims := baseGatewayClaims(now)
	claims["cnf"] = map[string]any{"jkt": jktOf(t, pk)}
	if tokenExtra != nil {
		tokenExtra(claims)
	}
	token := mintJWT(esHeader("k1"), claims, sk)
	// Fill proof defaults unless overridden.
	pc := map[string]any{
		"htm": "POST", "htu": "https://culvert.example/mcp/gateway/srv-1",
		"iat": now.Unix(), "jti": "proof-1", "ath": athOf(token),
	}
	for k, v := range proofClaims {
		pc[k] = v
	}
	return AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: token},
		Subject:    identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: identity.AssuranceHigh}},
		Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant:     identity.Tenant{ID: testTenant},
		Server:     serverPtr("srv-1"),
		Binding: RequestBinding{
			HTTPMethod: "POST", HTTPURI: "https://culvert.example/mcp/gateway/srv-1",
			DPoPProof: mintDPoP(pc, pk),
		},
	}
}

func TestDPoPValidAndReplay(t *testing.T) {
	now := fixedClock()
	sk, pk := newESKey(t, "k1"), newESKey(t, "pk")
	cfg := gatewayDPoPConfig(t)
	reg := gwRegistry(t)
	cache := senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })
	deps := Deps{Keys: resolverFor(sk), Registry: reg, Replay: cache}

	req := dpopRequest(t, now, sk, pk, nil, nil)
	ctx, err := Authenticate(req, cfg, deps, now)
	if err != nil {
		t.Fatalf("valid DPoP rejected: %v", err)
	}
	if ctx.SenderConstraint().Method != identity.ConfirmDPoP {
		t.Fatal("sender constraint not recorded as DPoP")
	}
	// Replaying the SAME proof (same jti) must be rejected.
	if _, err := Authenticate(req, cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonDPoPReplay {
		t.Fatalf("replayed proof must be dpop_replay, got %v", err)
	}
	// The SAME access token with a FRESH proof (new jti) must succeed — a valid
	// access token can be used on multiple requests; only the proof jti is one-time.
	token := req.Credential.Token
	freshProof := mintDPoP(map[string]any{
		"htm": "POST", "htu": "https://culvert.example/mcp/gateway/srv-1",
		"iat": now.Unix(), "jti": "proof-2", "ath": athOf(token),
	}, pk)
	req2 := req
	req2.Binding.DPoPProof = freshProof
	if _, err := Authenticate(req2, cfg, deps, now); err != nil {
		t.Fatalf("fresh proof for the same token must succeed, got %v", err)
	}
}

func TestDPoPNegativeMatrix(t *testing.T) {
	now := fixedClock()
	sk, pk := newESKey(t, "k1"), newESKey(t, "pk")
	cfg := gatewayDPoPConfig(t)
	reg := gwRegistry(t)
	deps := func() Deps {
		return Deps{Keys: resolverFor(sk), Registry: reg, Replay: senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })}
	}
	cases := []struct {
		name  string
		proof map[string]any
		want  mcperr.Reason
	}{
		{"wrong-method", map[string]any{"htm": "GET"}, mcperr.ReasonDPoPBindingMismatch},
		{"wrong-uri", map[string]any{"htu": "https://evil/x"}, mcperr.ReasonDPoPBindingMismatch},
		{"stale-iat", map[string]any{"iat": now.Add(-time.Hour).Unix()}, mcperr.ReasonDPoPMalformed},
		{"future-iat", map[string]any{"iat": now.Add(time.Hour).Unix()}, mcperr.ReasonDPoPMalformed},
		{"missing-jti", map[string]any{"jti": ""}, mcperr.ReasonDPoPMalformed},
		{"wrong-ath", map[string]any{"ath": "AAAA"}, mcperr.ReasonDPoPBindingMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := dpopRequest(t, now, sk, pk, tc.proof, nil)
			if _, err := Authenticate(req, cfg, deps(), now); mcperr.ReasonOf(err) != tc.want {
				t.Fatalf("reason = %v, want %v", mcperr.ReasonOf(err), tc.want)
			}
		})
	}
}

func TestDPoPWrongConfirmationThumbprint(t *testing.T) {
	now := fixedClock()
	sk, pk, other := newESKey(t, "k1"), newESKey(t, "pk"), newESKey(t, "other")
	cfg := gatewayDPoPConfig(t)
	deps := Deps{Keys: resolverFor(sk), Registry: gwRegistry(t), Replay: senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })}
	// Token cnf.jkt is pk, but the proof is signed by `other` → thumbprint mismatch.
	claims := baseGatewayClaims(now)
	claims["cnf"] = map[string]any{"jkt": jktOf(t, pk)}
	token := mintJWT(esHeader("k1"), claims, sk)
	req := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: token},
		Subject:    identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: identity.AssuranceHigh}},
		Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant:     identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
		Binding: RequestBinding{HTTPMethod: "POST", HTTPURI: "https://culvert.example/mcp/gateway/srv-1",
			DPoPProof: mintDPoP(map[string]any{"htm": "POST", "htu": "https://culvert.example/mcp/gateway/srv-1", "iat": now.Unix(), "jti": "p1", "ath": athOf(token)}, other)},
	}
	if _, err := Authenticate(req, cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonDPoPBindingMismatch {
		t.Fatalf("wrong confirmation thumbprint must be dpop_binding_mismatch, got %v", mcperr.ReasonOf(err))
	}
}

func TestSenderConstraintRequiredFailsClosed(t *testing.T) {
	now := fixedClock()
	sk := newESKey(t, "k1")
	cfg := gatewayDPoPConfig(t)
	deps := Deps{Keys: resolverFor(sk), Registry: gwRegistry(t), Replay: senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })}
	// No DPoP proof presented but the profile requires it.
	token := mintJWT(esHeader("k1"), baseGatewayClaims(now), sk)
	req := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: token},
		Subject:    identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: identity.AssuranceHigh}},
		Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant:     identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
	}
	if _, err := Authenticate(req, cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonSenderConstraintRequired {
		t.Fatalf("missing required DPoP must fail closed, got %v", mcperr.ReasonOf(err))
	}
}
