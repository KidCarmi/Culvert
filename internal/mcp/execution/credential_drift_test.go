package execution

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// Codex review of 7fd0869: a drift detected inside the broker's materialization
// callback (the CREDENTIAL path — a write/read tools/call carrying a credential
// profile, the ordinary enterprise shape) surfaced as a blocked result whose reason
// was ReasonOf(errToolDriftedBeforeCall) == ReasonNone, because the staleAtCall
// reclassification ran only on the no-credential (CommitThenAct error) branch.
// Clients and block telemetry then read `none` where the no-credential path reads
// `decision_snapshot_stale`. These tests drive the REAL credential path — Plan,
// the durable PR-8 gate, provider materialization, then the scoped callback — so the
// reclassification is exercised end to end, not asserted in isolation.

const (
	credDriftTenant = identity.TenantID("tenant-a")
	credDriftSrv    = registry.ServerID("srv-1")
	credDriftIdent  = registry.Identity("spiffe://srv-1")
	credDriftProf   = profile.ID("prof-1")
	credDriftProv   = profile.ProviderID("prov-1")
)

func credDriftClock() func() time.Time {
	now := time.Unix(1_700_000_000, 0)
	return func() time.Time { return now }
}

// credDriftSetup wires a broker whose Plan + Materialize SUCCEED and invoke the
// scoped callback with real bearer material, plus a resolved identity built from the
// SAME registry/catalog so the plan validates. Values mirror the broker package's
// own known-good materialize harness (TestMaterializeReadHappyPath).
func credDriftSetup(t *testing.T) (*broker.Broker, *identity.ResolvedContext) {
	t.Helper()
	clk := credDriftClock()
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: credDriftSrv, Endpoint: "mcp://srv-1", PinnedIdentity: credDriftIdent,
		Capability: protocol.Gateway, CredentialProfile: "cred-a", OwnerScope: registry.OwnerScope(credDriftTenant),
	}); err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(limits.DefaultCatalog())
	store := profile.NewStore(limits.DefaultCredential())
	rs, err := profile.NewResourceScope([]string{"repo:foo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(profile.Input{
		ID: credDriftProf, Provider: credDriftProv, Tenant: credDriftTenant, Environment: "prod", Server: credDriftSrv,
		Resources: rs, Operations: []profile.OperationClass{profile.OpRead, profile.OpWrite},
		Kind: profile.KindBearerToken, Power: profile.PowerWrite, MaxTTL: 30 * time.Minute,
		Cache:    profile.CachePolicy{Enabled: true, Freshness: time.Minute},
		Rotation: profile.RotationPolicy{Enabled: true, Grace: 30 * time.Second, MaxAttempts: 3},
		Failure:  profile.FailurePolicy{HighRiskFailClosed: true, AllowLowRiskCachedFallback: true},
		Enabled:  true,
	}, reg.Current()); err != nil {
		t.Fatal(err)
	}
	prov := provider.NewInMemory(credDriftProv, provider.Capabilities{})
	prov.SetMaterial(profile.KindBearerToken,
		map[provider.FieldName][]byte{provider.FieldToken: []byte("UPSTREAM-v1")},
		provider.Lease{
			Version: "v1", IssuedAt: clk(), Expiry: clk().Add(20 * time.Minute),
			Scope: profile.EffectiveScope{
				Tenant: credDriftTenant, Environment: "prod", Server: credDriftSrv,
				Resources: rs, Power: profile.PowerReadOnly, HasScopeProof: true,
			},
		})
	b := broker.New(broker.Deps{Profiles: store, Registry: reg, Catalog: cat, KEK: testKEK(), Clock: clk}, limits.DefaultCredential())
	if err := b.RegisterProvider(prov); err != nil {
		t.Fatal(err)
	}

	sid := credDriftSrv
	id, err := identity.Resolve(identity.ResolveInput{
		Capability: protocol.Gateway, Tenant: identity.Tenant{ID: credDriftTenant},
		Subject: identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{
			Subject: "u1", Tenant: credDriftTenant, Issuer: "iss", Assurance: identity.AssuranceHigh,
		}},
		Client:            identity.Client{ClientID: "c1", Tenant: credDriftTenant, Capability: protocol.Gateway},
		Server:            &sid,
		CanonicalResource: "/mcp/gateway/srv-1", Issuer: "iss", TokenDigest: "digest-abc123",
	}, reg, cat)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	return b, id
}

// credDriftInput builds an in-scope Canary ALLOW execution carrying a credential
// profile. The tool binding is left nil deliberately: a non-nil binding would need a
// catalog entry, and the drift the test exercises is signalled through the injected
// ToolStillCurrent hook, not the tool binding.
func credDriftInput(id *identity.ResolvedContext, hook func() bool) runtime.ExecInput {
	in := runtime.ExecInput{
		Capability: 0, // Gateway
		Method:     "tools/call",
		MessageID:  jsonrpc.ID{Kind: jsonrpc.IDString, Str: "c1"},
		RawParams:  []byte(`{"name":"read_file","arguments":{}}`),
		Decision:   policy.Decision{Action: policy.ActionAllow, Reason: policy.ReasonCode("MCP.POLICY.OK")},
		Input: policy.DecisionInput{
			Principal: policy.Principal{SubjectID: "u1", Tenant: string(credDriftTenant), Kind: policy.SubjectHuman},
			Client:    policy.Client{ClientID: "c1"},
			Server:    &policy.Server{ServerID: string(credDriftSrv), Environment: "prod"},
			Operation: policy.Operation{Class: policy.OpRead},
			Session:   policy.Session{Fingerprint: "sess1"},
		},
		Server: &registry.ServerRecord{
			ID: credDriftSrv, Endpoint: "https://srv-1.internal:443", PinnedIdentity: credDriftIdent,
			Enabled: true, Verification: registry.VerifyVerified,
		},
		Identity:         id,
		ToolStillCurrent: hook,
		SnapshotHash:     "snap1",
		Now:              time.Unix(0, 1),
	}
	in.Decision.Obligations.CredentialProfile = string(credDriftProf)
	return in
}

func credDriftState(t *testing.T) *rollout.State { return credDriftStateMode(t, rollout.ModeCanary) }

// credDriftStateMode builds a rollout state scoped to the credential-drift server in the
// given mode, so the credDrift harness can be exercised under Shadow as well as Canary.
func credDriftStateMode(t *testing.T, mode rollout.Mode) *rollout.State {
	t.Helper()
	st := rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits())
	cfg := rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: mode, ScopeRevision: 1,
		Scope:         rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{string(credDriftSrv)}},
		ConnectorMode: rollout.ConnectorLocalClient,
	}
	if err := st.SetConfig(cfg, "a", 1); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	return st
}

func credDriftExecutor(t *testing.T, b *broker.Broker, up *fakeUpstream) *Executor {
	t.Helper()
	return credDriftExecutorForState(t, b, up, credDriftState(t))
}

// credDriftExecutorForState builds the credential-drift executor under a caller-supplied
// rollout state, so a test can exercise the same real-materializing-broker harness in
// Shadow mode (proving Shadow's credential path never reaches upstream/materialize).
func credDriftExecutorForState(t *testing.T, b *broker.Broker, up *fakeUpstream, st *rollout.State) *Executor {
	t.Helper()
	e, err := New(Config{
		State: st, Upstream: up, Events: realEvents(t, nil), Broker: b,
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// The CONTROL: a CURRENT tool on the credential path materializes the broker's
// bearer credential and executes upstream with it. This proves the harness genuinely
// drives Plan → gate → materialize → scoped callback (so the drift case below is
// meaningful, not a plan/gate failure masquerading as a refusal).
func TestCredentialDrift_CurrentToolMaterializesAndExecutes(t *testing.T) {
	b, id := credDriftSetup(t)
	up := &fakeUpstream{}
	e := credDriftExecutor(t, b, up)

	out := e.Execute(context.Background(), credDriftInput(id, func() bool { return true }))

	if up.calls != 1 {
		t.Fatalf("credential path must materialize and execute a current tool, calls=%d", up.calls)
	}
	if up.lastAuth != "Bearer UPSTREAM-v1" {
		t.Fatalf("upstream must carry the materialized bearer credential, got %q", up.lastAuth)
	}
	if !out.Executed {
		t.Fatal("a current tool on the credential path must be marked executed")
	}
}

// The FIX: a tool that has DRIFTED, detected inside the broker's materialization
// callback, must be refused with decision_snapshot_stale — identical to the
// no-credential path — never `none`. Pre-fix the credential branch returned the
// materializeAndCall block verbatim (ReasonNone), so the staleness reason was lost
// on exactly the enterprise shape (an executed tools/call with a credential profile).
func TestCredentialDrift_DriftedToolIsRefusedAsDecisionStale(t *testing.T) {
	b, id := credDriftSetup(t)
	up := &fakeUpstream{}
	e := credDriftExecutor(t, b, up)

	checked := false
	out := e.Execute(context.Background(), credDriftInput(id, func() bool { checked = true; return false }))

	if !checked {
		t.Fatal("ToolStillCurrent was never consulted: the credential path did not reach the " +
			"materialization callback, so this test does not exercise the drift boundary")
	}
	if up.calls != 0 {
		t.Fatalf("a drifted tool must be refused BEFORE the upstream side effect, calls=%d", up.calls)
	}
	if out.Executed {
		t.Fatal("a drift refusal must not be reported as executed")
	}
	if out.Reason != mcperr.ReasonDecisionSnapshotStale {
		t.Fatalf("reason = %v, want %v — a credential-path drift must read as decision staleness, "+
			"never the ReasonNone the broker block carries", out.Reason, mcperr.ReasonDecisionSnapshotStale)
	}
}
