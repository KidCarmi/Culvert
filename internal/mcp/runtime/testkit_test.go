package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// --- signing kit (ES256) ---------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

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

func (k *esKey) signES256(in []byte) []byte {
	h := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, h[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

func mintJWT(header, claims map[string]any, k *esKey) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	in := b64(hb) + "." + b64(cb)
	return in + "." + b64(k.signES256([]byte(in)))
}

// --- shared fixture constants ----------------------------------------------

const (
	testIssuer   = "https://idp.example/issuer"
	testTenant   = "tenant-a"
	testClientG  = "client-gateway"
	testClientM  = "client-management"
	testServerID = "srv-1"
	gwResource   = "/mcp/gateway/srv-1"
	mgmtResource = "/mcp/management"
	gwScope      = "gateway.tools.call"
	mgmtScope    = "management.config.read"
	gwHost       = "gw.example.com"
	mgmtHost     = "mgmt.example.com"
)

func fixedClock() time.Time { return time.Unix(1_700_000_000, 0) }

// gwToken mints a valid gateway access token for the fixed clock.
func gwToken(k *esKey) string {
	now := fixedClock()
	return mintJWT(
		map[string]any{"alg": "ES256", "kid": k.kid},
		map[string]any{
			"iss": testIssuer, "sub": "user-1", "client_id": testClientG,
			"aud": gwResource, "scope": gwScope, "tenant": testTenant,
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		}, k)
}

// mgmtToken mints a valid management access token for the fixed clock.
func mgmtToken(k *esKey) string {
	now := fixedClock()
	return mintJWT(
		map[string]any{"alg": "ES256", "kid": k.kid},
		map[string]any{
			"iss": testIssuer, "sub": "admin-1", "client_id": testClientM,
			"aud": mgmtResource, "scope": mgmtScope, "tenant": testTenant,
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		}, k)
}

// --- auth configs ----------------------------------------------------------

func gwAuthConfig(t testing.TB) authn.CapabilityAuthConfig {
	t.Helper()
	cfg, err := authn.NewCapabilityConfig(authn.CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.BearerControlled,
		Limits: limits.DefaultAuth(),
	})
	if err != nil {
		t.Fatalf("gw auth config: %v", err)
	}
	return cfg
}

func mgmtAuthConfig(t testing.TB) authn.CapabilityAuthConfig {
	t.Helper()
	cfg, err := authn.NewCapabilityConfig(authn.CapabilityConfigInput{
		Capability: protocol.Management, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientM}, CanonicalResource: mgmtResource,
		RequiredScopes: []string{mgmtScope}, SenderProfile: senderconstraint.BearerControlled,
		Limits: limits.DefaultAuth(),
	})
	if err != nil {
		t.Fatalf("mgmt auth config: %v", err)
	}
	return cfg
}

// --- deps ------------------------------------------------------------------

// testDeps builds runtime Deps with a registry holding srv-1, the trusted key,
// a bounded sink and the fixed clock.
func testDeps(t testing.TB, k *esKey, sink Sink) Deps {
	t.Helper()
	keys := authn.NewStaticKeyResolver()
	keys.Add(testIssuer, k.kid, k.priv.Public())
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: testServerID, Endpoint: "https://upstream.example/mcp",
		PinnedIdentity: "spiffe://upstream/srv-1", Capability: protocol.Gateway,
	}); err != nil {
		t.Fatalf("register srv-1: %v", err)
	}
	return Deps{
		Registry: reg,
		Catalog:  catalog.New(limits.DefaultCatalog()),
		Keys:     keys,
		Sink:     sink,
		Clock:    fixedClock,
	}
}

// --- listener configs ------------------------------------------------------

func gwListenerConfig(t testing.TB) ListenerConfig {
	t.Helper()
	return ListenerConfig{
		Enabled: true, Capability: protocol.Gateway,
		BindAddress: "127.0.0.1", Port: 1, AllowInsecure: true,
		AllowedHosts: []string{gwHost}, AuthConfig: gwAuthConfig(t),
		Limits: DefaultLimits(),
	}
}

func mgmtListenerConfig(t testing.TB) ListenerConfig {
	t.Helper()
	return ListenerConfig{
		Enabled: true, Capability: protocol.Management,
		BindAddress: "127.0.0.1", Port: 2, AllowInsecure: true,
		AllowedHosts: []string{mgmtHost}, AuthConfig: mgmtAuthConfig(t),
		Limits: DefaultLimits(),
	}
}

// --- pipeline builder for unit tests ---------------------------------------

func newGatewayPipeline(t testing.TB, deps Deps) *pipeline {
	t.Helper()
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(t), deps, "test-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	return p
}

// --- request builders ------------------------------------------------------

func initializeBody(id int) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
}

func pingBody(id int) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"ping"}`)
}

func toolsListBody(id int) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/list"}`)
}

func toolsCallBody(id int) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"x"}}`)
}

func initializedNotification() []byte {
	return []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

// gwRequest builds a well-formed Gateway POST Request carrying a bearer token.
func gwRequest(token string, body []byte) Request {
	return Request{
		HTTPMethod: "POST", Capability: protocol.Gateway, Host: gwHost,
		Path: gwResource, ServerID: testServerID,
		AuthorizationHeaders: []string{"Bearer " + token},
		CanonicalURI:         "https://" + gwHost + gwResource,
		Body:                 body,
	}
}
