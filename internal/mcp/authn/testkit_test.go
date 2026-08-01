package authn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// --- test signing kit ------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// esKey is a test ES256 signer with its public JWK.
type esKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newESKey(t testing.TB, kid string) *esKey {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return &esKey{priv: p, kid: kid}
}

func (k *esKey) jwk() map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": b64(k.priv.X.Bytes()), "y": b64(k.priv.Y.Bytes()),
	}
}

func (k *esKey) signES256(signingInput []byte) []byte {
	h := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, h[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

// edKey is a test Ed25519 signer.
type edKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newEdKey(t testing.TB) *edKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return &edKey{priv: priv, pub: pub}
}

func ed25519Sign(k *edKey, msg []byte) []byte { return ed25519.Sign(k.priv, msg) }

func serverPtr(id registry.ServerID) *registry.ServerID { return &id }

// jktOf computes the RFC 7638 thumbprint of an ES256 key's public JWK.
func jktOf(t testing.TB, k *esKey) string {
	t.Helper()
	jb, _ := json.Marshal(k.jwk())
	n, err := canonical.Decode(jb, canonical.Bounds{MaxBytes: 4096, MaxDepth: 8, MaxObjectMembers: 16, MaxArrayElements: 8, MaxStringBytes: 2048})
	if err != nil {
		t.Fatalf("decode jwk: %v", err)
	}
	tp, err := jose.Thumbprint(n)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return tp
}

// athOf returns the DPoP ath value for an access token.
func athOf(token string) string { return jose.SHA256B64URL([]byte(token)) }

// mintJWT builds a signed compact JWT from header + claims maps (ES256).
func mintJWT(header, claims map[string]any, k *esKey) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(cb)
	sig := k.signES256([]byte(signingInput))
	return signingInput + "." + b64(sig)
}

// mintDPoP builds a signed DPoP proof (ES256) from the proof claims.
func mintDPoP(claims map[string]any, k *esKey) string {
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.jwk()}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(cb)
	sig := k.signES256([]byte(signingInput))
	return signingInput + "." + b64(sig)
}

// --- shared fixtures -------------------------------------------------------

const (
	testIssuer   = "https://idp.example/issuer"
	testTenant   = "tenant-a"
	testClientG  = "client-gateway"
	testClientM  = "client-management"
	gwResource   = "/mcp/gateway/srv-1"
	mgmtResource = "/mcp/management"
	gwScope      = "gateway.tools.call"
	mgmtScope    = "management.config.read"
)

func testAuthLimits() limits.AuthLimits { return limits.DefaultAuth() }

func gatewayConfig(t testing.TB) CapabilityAuthConfig {
	t.Helper()
	cfg, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.BearerControlled,
		Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatalf("gateway config: %v", err)
	}
	return cfg
}

func managementConfig(t testing.TB) CapabilityAuthConfig {
	t.Helper()
	cfg, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Management, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientM}, CanonicalResource: mgmtResource,
		RequiredScopes: []string{mgmtScope}, SenderProfile: senderconstraint.BearerControlled,
		Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatalf("management config: %v", err)
	}
	return cfg
}

// baseClaims returns a valid gateway claim set at time now.
func baseGatewayClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "user-1", "client_id": testClientG,
		"aud": gwResource, "scope": gwScope, "tenant": testTenant,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func esHeader(kid string) map[string]any { return map[string]any{"alg": "ES256", "kid": kid} }

// fixedClock returns a stable test time.
func fixedClock() time.Time { return time.Unix(1_700_000_000, 0) }
