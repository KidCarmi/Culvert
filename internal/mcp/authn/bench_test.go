package authn

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

func BenchmarkValidateJWT(b *testing.B) {
	now := fixedClock()
	k := newESKey(b, "k1")
	tok := mintJWT(esHeader("k1"), baseGatewayClaims(now), k)
	cfg := gatewayConfig(b)
	res := resolverFor(k)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ValidateJWT(tok, cfg, res, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateOpaque(b *testing.B) {
	now := fixedClock()
	cfg := gatewayConfig(b)
	in := fakeIntrospector{validOpaque(now)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ValidateOpaque("opaque", cfg, in, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplayInsert(b *testing.B) {
	now := time.Unix(1000, 0)
	c := senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })
	pk := senderconstraint.PartitionKey("iss", "client", "thumb")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = c.CheckAndAdd(protocol.Gateway, pk, "jti-"+itoaB(i), time.Minute)
	}
}

func BenchmarkResolveContext(b *testing.B) {
	reg := gwRegistry(b)
	sid := serverPtr("srv-1")
	in := identity.ResolveInput{
		Capability: protocol.Gateway, Tenant: identity.Tenant{ID: testTenant},
		Subject: identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant}},
		Client:  identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Server:  sid, CanonicalResource: gwResource,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := identity.Resolve(in, reg, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func itoaB(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
