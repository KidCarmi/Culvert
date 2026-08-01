package profile

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

func TestStoreAddAndGet(t *testing.T) {
	reg := gwRegistry(t, "")
	s := NewStore(limits.DefaultCredential())
	p, err := s.Add(baseInput(t), reg)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if p.Revision() != 1 || s.Current().Revision() != 1 {
		t.Fatal("revision not stamped")
	}
	got, ok := s.Current().Get("prof-1")
	if !ok || got.ID() != "prof-1" {
		t.Fatal("profile not retrievable")
	}
}

func TestStoreDuplicateRejected(t *testing.T) {
	reg := gwRegistry(t, "")
	s := NewStore(limits.DefaultCredential())
	if _, err := s.Add(baseInput(t), reg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(baseInput(t), reg); mcperr.ReasonOf(err) != mcperr.ReasonCredentialProfileAmbiguous {
		t.Fatalf("duplicate id must be rejected, got %v", mcperr.ReasonOf(err))
	}
	if s.Current().Revision() != 1 {
		t.Fatal("failed add must not advance the revision (no partial publication)")
	}
}

func TestStoreCapacity(t *testing.T) {
	reg := gwRegistry(t, "")
	lim, _ := limits.NewCredential(smallCredConfig(2, 2, 2))
	s := NewStore(lim)
	for i, id := range []ID{"a", "b"} {
		in := baseInput(t)
		in.ID = id
		if _, err := s.Add(in, reg); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	in := baseInput(t)
	in.ID = "c"
	if _, err := s.Add(in, reg); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("capacity must be enforced, got %v", mcperr.ReasonOf(err))
	}
}

func TestStoreSetEnabledStaleBaseRejected(t *testing.T) {
	reg := gwRegistry(t, "")
	s := NewStore(limits.DefaultCredential())
	if _, err := s.Add(baseInput(t), reg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetEnabled("prof-1", false, 99); mcperr.ReasonOf(err) != mcperr.ReasonCredentialVersionStale {
		t.Fatalf("stale base must be rejected, got %v", mcperr.ReasonOf(err))
	}
	p, err := s.SetEnabled("prof-1", false, 1)
	if err != nil || p.Enabled() {
		t.Fatalf("disable failed: %v enabled=%v", err, p.Enabled())
	}
}

func TestStoreSnapshotImmutableUnderCallerAlias(t *testing.T) {
	reg := gwRegistry(t, "")
	s := NewStore(limits.DefaultCredential())
	in := baseInput(t)
	sels := []string{"repo:foo", "repo:bar"}
	rs, _ := NewResourceScope(sels)
	in.Resources = rs
	in.Tools = []string{"tool-a"}
	if _, err := s.Add(in, reg); err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's slices AFTER add.
	sels[0] = "repo:HACKED"
	in.Tools[0] = "HACKED"
	got, _ := s.Current().Get("prof-1")
	for _, r := range got.Resources().Selectors() {
		if r == "repo:HACKED" {
			t.Fatal("caller alias mutated the stored resource scope")
		}
	}
	for _, tool := range got.Tools() {
		if tool == "HACKED" {
			t.Fatal("caller alias mutated the stored tool set")
		}
	}
}

func smallCredConfig(profiles, perTenant, perServer int) limits.CredentialConfig {
	c := defaultCredConfig()
	c.MaxProfiles = profiles
	c.MaxProfilesPerTenant = perTenant
	c.MaxProfilesPerServer = perServer
	return c
}

func defaultCredConfig() limits.CredentialConfig {
	return limits.CredentialConfig{
		MaxProfiles: 4096, MaxProviders: 64, MaxProfilesPerTenant: 512, MaxProfilesPerServer: 128,
		MaxCacheEntries: 8192, MaxCacheBytes: 64 << 20, MaxEnvelopeBytes: 64 << 10,
		MaxSecretFields: 16, MaxSecretFieldBytes: 16 << 10, MaxProviderConc: 64, MaxInflightPerProf: 8,
		MaxRotationAttempts: 3, MaxRetries: 3, MaxRetryDelay: 5 * time.Second, MaxCredentialTTL: time.Hour,
		MaxCacheFreshness: 5 * time.Minute, RotationGrace: 30 * time.Second, MaxTombstones: 8192, MaxCleanupPerOp: 64,
	}
}

// FuzzNewProfile proves profile validation never panics on arbitrary ids/scope and
// never mutates a shared registry snapshot.
func FuzzNewProfile(f *testing.F) {
	reg := gwRegistry(f, registry.OwnerScope("tenant-a"))
	lim := limits.DefaultCredential()
	f.Add("prof-1", "prov-1", "tenant-a", "prod", "repo:a")
	f.Add("", "", "", "", "")
	f.Fuzz(func(t *testing.T, id, prov, tenant, env, sel string) {
		rs, err := NewResourceScope([]string{sel})
		if err != nil {
			return
		}
		in := Input{
			ID: ID(id), Provider: ProviderID(prov), Tenant: identity.TenantID(tenant),
			Environment: Environment(env), Server: srv1, Resources: rs,
			Operations: []OperationClass{OpRead}, Kind: KindBearerToken, Power: PowerReadOnly,
			MaxTTL: time.Minute, Cache: CachePolicy{Enabled: true, Freshness: time.Minute}, Failure: FailurePolicy{HighRiskFailClosed: true}, Enabled: true,
		}
		_, _ = NewProfile(in, reg, lim, 1) // must not panic
	})
}
