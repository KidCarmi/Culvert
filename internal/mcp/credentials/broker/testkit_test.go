package broker

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/secret"
)

const (
	tenantA  = identity.TenantID("tenant-a")
	tenantB  = identity.TenantID("tenant-b")
	srv1     = registry.ServerID("srv-1")
	srvIdent = registry.Identity("spiffe://srv-1")
	profID   = profile.ID("prof-1")
	provID   = profile.ProviderID("prov-1")
)

func testKEK() *secret.Provider {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return secret.MemoryProvider(key)
}

func fixedClock() func() time.Time {
	now := time.Unix(1_700_000_000, 0)
	return func() time.Time { return now }
}

func gwRegistry(t testing.TB) *registry.Registry {
	t.Helper()
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: srv1, Endpoint: "mcp://srv-1", PinnedIdentity: srvIdent,
		Capability: protocol.Gateway, CredentialProfile: "cred-a", OwnerScope: registry.OwnerScope(tenantA),
	}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func newCatalog() *catalog.Catalog { return catalog.New(limits.DefaultCatalog()) }

func gwIdentity(t testing.TB, reg *registry.Registry, cat *catalog.Catalog) *identity.ResolvedContext {
	t.Helper()
	sid := srv1
	in := identity.ResolveInput{
		Capability: protocol.Gateway, Tenant: identity.Tenant{ID: tenantA},
		Subject: identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "u1", Tenant: tenantA, Issuer: "iss", Assurance: identity.AssuranceHigh}},
		Client:  identity.Client{ClientID: "c1", Tenant: tenantA, Capability: protocol.Gateway},
		Server:  &sid, CanonicalResource: "/mcp/gateway/srv-1", Issuer: "iss", TokenDigest: "digest-abc123",
	}
	ctx, err := identity.Resolve(in, reg, cat)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	return ctx
}

func profScope(t testing.TB) profile.ResourceScope {
	t.Helper()
	rs, err := profile.NewResourceScope([]string{"repo:foo"})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// addProfile stores a profile permitting read (low-risk, cache fallback) and write
// (high-risk), with a write power ceiling.
func addProfile(t testing.TB, store *profile.Store, reg *registry.Registry) profile.Profile {
	t.Helper()
	p, err := store.Add(profile.Input{
		ID: profID, Provider: provID, Tenant: tenantA, Environment: "prod", Server: srv1,
		Resources: profScope(t), Operations: []profile.OperationClass{profile.OpRead, profile.OpWrite},
		Kind: profile.KindBearerToken, Power: profile.PowerWrite, MaxTTL: 30 * time.Minute,
		Cache:    profile.CachePolicy{Enabled: true, Freshness: time.Minute},
		Rotation: profile.RotationPolicy{Enabled: true, Grace: 30 * time.Second, MaxAttempts: 3},
		Failure:  profile.FailurePolicy{HighRiskFailClosed: true, AllowLowRiskCachedFallback: true},
		Enabled:  true,
	}, reg.Current())
	if err != nil {
		t.Fatalf("add profile: %v", err)
	}
	return p
}

// leaseScope builds a valid effective scope for the profile at a given power.
func leaseScope(t testing.TB, power profile.CredentialPower) profile.EffectiveScope {
	t.Helper()
	rs, _ := profile.NewResourceScope([]string{"repo:foo"})
	return profile.EffectiveScope{
		Tenant: tenantA, Environment: "prod", Server: srv1,
		Resources: rs, Power: power, HasScopeProof: true,
	}
}

// memProvider builds an in-memory provider returning a bearer token with the given
// version/power/expiry.
func memProvider(t testing.TB, clk func() time.Time, power profile.CredentialPower, version profile.CredentialVersion, caps provider.Capabilities) *provider.InMemoryProvider {
	t.Helper()
	p := provider.NewInMemory(provID, caps)
	p.SetMaterial(profile.KindBearerToken,
		map[provider.FieldName][]byte{provider.FieldToken: []byte("UPSTREAM-" + string(version))},
		provider.Lease{Version: version, IssuedAt: clk(), Expiry: clk().Add(20 * time.Minute), Scope: leaseScope(t, power)})
	return p
}

// fakeGate is a deterministic pre-materialization gate.
type fakeGate struct {
	permit  bool
	durable bool
	err     error
	calls   int
}

func (g *fakeGate) Authorize(_ context.Context, _ CredentialPlan) (GateDecision, error) {
	g.calls++
	if g.err != nil {
		return GateDecision{}, g.err
	}
	return GateDecision{Permit: g.permit, DurableConfirmed: g.durable}, nil
}

func permitGate() *fakeGate { return &fakeGate{permit: true, durable: true} }

// harness bundles a wired broker for tests.
type harness struct {
	broker *Broker
	store  *profile.Store
	reg    *registry.Registry
	cat    *catalog.Catalog
	prov   *provider.InMemoryProvider
	id     *identity.ResolvedContext
	clk    func() time.Time
}

func newHarness(t testing.TB, caps provider.Capabilities, power profile.CredentialPower) *harness {
	t.Helper()
	clk := fixedClock()
	reg := gwRegistry(t)
	cat := newCatalog()
	store := profile.NewStore(limits.DefaultCredential())
	addProfile(t, store, reg)
	prov := memProvider(t, clk, power, "v1", caps)
	b := New(Deps{Profiles: store, Registry: reg, Catalog: cat, KEK: testKEK(), Clock: clk}, limits.DefaultCredential())
	if err := b.RegisterProvider(prov); err != nil {
		t.Fatal(err)
	}
	return &harness{broker: b, store: store, reg: reg, cat: cat, prov: prov, id: gwIdentity(t, reg, cat), clk: clk}
}

func (h *harness) readPlan(t testing.TB) CredentialPlan {
	t.Helper()
	pl, err := h.broker.Plan(PlanInput{Identity: h.id, Profile: profID, Environment: "prod", Operation: profile.OpRead})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return pl
}

func (h *harness) writePlan(t testing.TB) CredentialPlan {
	t.Helper()
	pl, err := h.broker.Plan(PlanInput{Identity: h.id, Profile: profID, Environment: "prod", Operation: profile.OpWrite})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return pl
}

// newHarnessWithProvider wires a harness using a caller-supplied provider.
func newHarnessWithProvider(t testing.TB, prov provider.Provider, power profile.CredentialPower) *harness {
	t.Helper()
	clk := fixedClock()
	reg := gwRegistry(t)
	cat := newCatalog()
	store := profile.NewStore(limits.DefaultCredential())
	addProfile(t, store, reg)
	b := New(Deps{Profiles: store, Registry: reg, Catalog: cat, KEK: testKEK(), Clock: clk}, limits.DefaultCredential())
	if err := b.RegisterProvider(prov); err != nil {
		t.Fatal(err)
	}
	return &harness{broker: b, store: store, reg: reg, cat: cat, id: gwIdentity(t, reg, cat), clk: clk}
}

// managementIdentity builds a Management-capability resolved identity.
func managementIdentity(t testing.TB) *identity.ResolvedContext {
	t.Helper()
	in := identity.ResolveInput{
		Capability: protocol.Management, Tenant: identity.Tenant{ID: tenantA},
		Subject:           identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "admin", Tenant: tenantA, Issuer: "iss", Assurance: identity.AssuranceHigh}},
		Client:            identity.Client{ClientID: "m1", Tenant: tenantA, Capability: protocol.Management},
		CanonicalResource: "/mcp/management", Issuer: "iss",
	}
	ctx, err := identity.Resolve(in, nil, nil)
	if err != nil {
		t.Fatalf("resolve management identity: %v", err)
	}
	return ctx
}

// gwIdentityTenant builds a Gateway identity for an arbitrary tenant (used for the
// cross-tenant broker check).
func gwIdentityTenant(t testing.TB, reg *registry.Registry, cat *catalog.Catalog, tenant identity.TenantID) *identity.ResolvedContext {
	t.Helper()
	sid := srv1
	in := identity.ResolveInput{
		Capability: protocol.Gateway, Tenant: identity.Tenant{ID: tenant},
		Subject: identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "u", Tenant: tenant, Issuer: "iss", Assurance: identity.AssuranceHigh}},
		Client:  identity.Client{ClientID: "c", Tenant: tenant, Capability: protocol.Gateway},
		Server:  &sid, CanonicalResource: "/mcp/gateway/srv-1", Issuer: "iss",
	}
	ctx, err := identity.Resolve(in, reg, cat)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	return ctx
}

// ingestTool ingests a single tool for srv-1 (it lands Quarantined by PR-2 policy).
func ingestTool(t testing.TB, cat *catalog.Catalog, reg *registry.Registry, name string) {
	t.Helper()
	raw := []byte(`{"tools":[{"name":"` + name + `","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}]}`)
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{ServerID: srv1, Identity: srvIdent, Raw: raw}); err != nil {
		t.Fatalf("ingest tool: %v", err)
	}
}

// recordingProvider records the last fetch request (to prove no raw token is passed).
type recordingProvider struct {
	*provider.InMemoryProvider
	lastReq provider.Request
}

func (r *recordingProvider) Fetch(ctx context.Context, req provider.Request) (*provider.Result, error) {
	r.lastReq = req
	return r.InMemoryProvider.Fetch(ctx, req)
}

func errorsNew(msg string) error { return &plainErr{msg} }

type plainErr struct{ s string }

func (e *plainErr) Error() string { return e.s }

// safeString renders a SafeResult's fields for canary scanning.
func safeString(res SafeResult) string {
	return res.PlanID + "|" + string(res.ProfileID) + "|" + string(res.ProviderID) + "|" +
		string(res.Version) + "|" + string(res.Server) + "|" + res.ToolRefHash + "|" +
		res.Rotation + "|" + res.Reason.Code()
}
