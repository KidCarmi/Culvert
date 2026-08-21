package profile

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

const (
	tenantA = identity.TenantID("tenant-a")
	tenantB = identity.TenantID("tenant-b")
	srv1    = registry.ServerID("srv-1")
)

func gwRegistry(t testing.TB, owner registry.OwnerScope) *registry.Snapshot {
	t.Helper()
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: srv1, Endpoint: "mcp://srv-1", PinnedIdentity: "spiffe://srv-1",
		Capability: protocol.Gateway, CredentialProfile: "cred-a", OwnerScope: owner,
	}); err != nil {
		t.Fatal(err)
	}
	return reg.Current()
}

func validScope(t testing.TB) ResourceScope {
	t.Helper()
	rs, err := NewResourceScope([]string{"repo:foo", "repo:bar"})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func baseInput(t testing.TB) Input {
	t.Helper()
	return Input{
		ID: "prof-1", Provider: "prov-1", Tenant: tenantA, Environment: "prod",
		Server: srv1, Resources: validScope(t), Operations: []OperationClass{OpRead},
		Kind: KindBearerToken, Power: PowerReadOnly, MaxTTL: 30 * time.Minute,
		Cache:   CachePolicy{Enabled: true, Freshness: time.Minute},
		Failure: FailurePolicy{HighRiskFailClosed: true},
		Enabled: true,
	}
}

func TestNewProfileValid(t *testing.T) {
	reg := gwRegistry(t, registry.OwnerScope(tenantA))
	p, err := NewProfile(baseInput(t), reg, limits.DefaultCredential(), 1)
	if err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	if p.ID() != "prof-1" || p.Server() != srv1 || !p.Permits(OpRead) {
		t.Fatal("profile fields not populated")
	}
}

func TestNewProfileRejections(t *testing.T) {
	reg := gwRegistry(t, registry.OwnerScope(tenantA))
	lim := limits.DefaultCredential()
	cases := []struct {
		name  string
		patch func(*Input)
		want  mcperr.Reason
	}{
		{"empty-id", func(in *Input) { in.ID = "" }, mcperr.ReasonCredentialProfileMissing},
		{"empty-provider", func(in *Input) { in.Provider = "" }, mcperr.ReasonCredentialProfileMissing},
		{"missing-tenant", func(in *Input) { in.Tenant = "" }, mcperr.ReasonTenantMismatch},
		{"missing-env", func(in *Input) { in.Environment = "" }, mcperr.ReasonCredentialProfileMissing},
		{"missing-server", func(in *Input) { in.Server = "" }, mcperr.ReasonRegistryServerUnavailable},
		{"unregistered-server", func(in *Input) { in.Server = "srv-x" }, mcperr.ReasonRegistryServerUnavailable},
		{"bad-kind", func(in *Input) { in.Kind = KindUnset }, mcperr.ReasonCredentialKindUnsupported},
		{"empty-ops", func(in *Input) { in.Operations = nil }, mcperr.ReasonCredentialProfileMissing},
		{"bad-ttl", func(in *Input) { in.MaxTTL = 0 }, mcperr.ReasonCredentialProfileMissing},
		{"ttl-over-max", func(in *Input) { in.MaxTTL = 48 * time.Hour }, mcperr.ReasonCredentialProfileMissing},
		{"fail-open", func(in *Input) { in.Failure.HighRiskFailClosed = false }, mcperr.ReasonCredentialProfileMissing},
		{"op-exceeds-power", func(in *Input) { in.Operations = []OperationClass{OpWrite} }, mcperr.ReasonCredentialPowerExceeded},
		{"low-risk-fallback-no-cache", func(in *Input) {
			in.Cache = CachePolicy{Enabled: false}
			in.Failure = FailurePolicy{HighRiskFailClosed: true, AllowLowRiskCachedFallback: true}
		}, mcperr.ReasonCredentialProfileMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput(t)
			tc.patch(&in)
			if _, err := NewProfile(in, reg, lim, 1); mcperr.ReasonOf(err) != tc.want {
				t.Fatalf("reason = %v, want %v", mcperr.ReasonOf(err), tc.want)
			}
		})
	}
}

func TestNewProfileManagementServerRejected(t *testing.T) {
	// A Management-capability server (or non-Gateway) must be rejected.
	reg := registry.New(limits.DefaultCatalog())
	// Registry rejects non-Gateway in PR-2, so simulate an unusable server: register
	// Gateway then the mismatch path is covered by unregistered/disabled below. Here
	// assert an unregistered server (the Management broker never registers here).
	snap := reg.Current()
	if _, err := NewProfile(baseInput(t), snap, limits.DefaultCredential(), 1); mcperr.ReasonOf(err) != mcperr.ReasonRegistryServerUnavailable {
		t.Fatalf("unregistered server must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

func TestNewProfileDisabledServer(t *testing.T) {
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: srv1, Endpoint: "mcp://srv-1", PinnedIdentity: "spiffe://srv-1",
		Capability: protocol.Gateway, CredentialProfile: "c", OwnerScope: registry.OwnerScope(tenantA),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.SetEnabled(srv1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := NewProfile(baseInput(t), reg.Current(), limits.DefaultCredential(), 1); mcperr.ReasonOf(err) != mcperr.ReasonRegistryServerUnavailable {
		t.Fatalf("disabled server must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

func TestNewProfileCrossTenantServer(t *testing.T) {
	reg := gwRegistry(t, registry.OwnerScope(tenantB)) // server owned by tenant-b
	in := baseInput(t)                                 // profile tenant-a
	if _, err := NewProfile(in, reg, limits.DefaultCredential(), 1); mcperr.ReasonOf(err) != mcperr.ReasonTenantMismatch {
		t.Fatalf("cross-tenant server must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

func TestResourceScopeWildcardRejected(t *testing.T) {
	for _, bad := range [][]string{{"*"}, {"repo:*"}, {"repo:a", ""}, {"a?b"}} {
		if _, err := NewResourceScope(bad); err == nil {
			t.Fatalf("unsafe scope %v must be rejected", bad)
		}
	}
}

func TestScopeSubset(t *testing.T) {
	prof, _ := NewResourceScope([]string{"a", "b", "c"})
	in, _ := NewResourceScope([]string{"a", "c"})
	out, _ := NewResourceScope([]string{"a", "z"})
	if !ScopeSubset(in, prof) {
		t.Fatal("subset should hold")
	}
	if ScopeSubset(out, prof) {
		t.Fatal("broader scope must not be a subset")
	}
}

func TestValidateEffectiveScope(t *testing.T) {
	profScope, _ := NewResourceScope([]string{"a", "b"})
	bound := ScopeBound{Tenant: tenantA, Environment: "prod", Server: srv1, Resources: profScope, PowerCeiling: PowerReadOnly, RequireProof: true}
	good := EffectiveScope{Tenant: tenantA, Environment: "prod", Server: srv1, Resources: mustScope(t, "a"), Power: PowerReadOnly, HasScopeProof: true}
	if err := ValidateEffectiveScope(good, bound); err != nil {
		t.Fatalf("valid effective scope rejected: %v", err)
	}
	cases := []struct {
		name string
		eff  EffectiveScope
		want mcperr.Reason
	}{
		{"cross-tenant", EffectiveScope{Tenant: tenantB, Environment: "prod", Server: srv1, Resources: mustScope(t, "a"), Power: PowerReadOnly, HasScopeProof: true}, mcperr.ReasonCredentialScopeMismatch},
		{"cross-server", EffectiveScope{Tenant: tenantA, Environment: "prod", Server: "srv-2", Resources: mustScope(t, "a"), Power: PowerReadOnly, HasScopeProof: true}, mcperr.ReasonCredentialScopeMismatch},
		{"broader-power", EffectiveScope{Tenant: tenantA, Environment: "prod", Server: srv1, Resources: mustScope(t, "a"), Power: PowerWrite, HasScopeProof: true}, mcperr.ReasonCredentialPowerExceeded},
		{"broader-resource", EffectiveScope{Tenant: tenantA, Environment: "prod", Server: srv1, Resources: mustScope(t, "z"), Power: PowerReadOnly, HasScopeProof: true}, mcperr.ReasonCredentialScopeMismatch},
		{"missing-proof", EffectiveScope{Tenant: tenantA, Environment: "prod", Server: srv1, Resources: mustScope(t, "a"), Power: PowerReadOnly, HasScopeProof: false}, mcperr.ReasonCredentialScopeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateEffectiveScope(tc.eff, bound); mcperr.ReasonOf(err) != tc.want {
				t.Fatalf("reason = %v, want %v", mcperr.ReasonOf(err), tc.want)
			}
		})
	}
}

func mustScope(t testing.TB, sels ...string) ResourceScope {
	t.Helper()
	rs, err := NewResourceScope(sels)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
