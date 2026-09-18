package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// ---------------------------------------------------------------------------
// BLOCKER #9 §6/§7/§8 — the EXECUTION-SIDE half of the credential-free proof.
//
// The readiness half (mcp_canary_credential_free_test.go) proves a credential-requiring
// experiment cannot become Ready. These gates prove the complementary runtime fact: on the
// canonical First-Canary path the credential machinery is never touched AND no Authorization
// header is sent — and, for the control, that a credential-REQUIRING execution forced through
// anyway fails closed with the upstream never reached.
//
// Everything runs through the REAL composed live executor (composeGatewayLiveTierInto), the REAL
// side-effect gate, and a REAL broker — never a nil broker, because production composes a real
// one and a proof against a composition production does not use would be vacuous.
// ---------------------------------------------------------------------------

// tripwireProvider is a credential provider that records any use and refuses. It is registered on
// the broker so that reaching the provider at all is observable AFTER the fact rather than only
// by the request failing — "nothing happened" and "the provider ran and errored" must not look
// the same.
type tripwireProvider struct{ calls atomic.Int64 }

func (p *tripwireProvider) ID() profile.ProviderID { return "tripwire" }
func (p *tripwireProvider) Capabilities() provider.Capabilities {
	return provider.Capabilities{}
}

func (p *tripwireProvider) Fetch(context.Context, provider.Request) (*provider.Result, error) {
	p.calls.Add(1)
	return nil, mcperr.New(mcperr.ReasonProviderUnavailable, "test.tripwire", "tripwire provider must never be reached")
}

func (p *tripwireProvider) Rotate(context.Context, provider.Request) (*provider.Result, error) {
	p.calls.Add(1)
	return nil, mcperr.New(mcperr.ReasonProviderUnavailable, "test.tripwire", "tripwire")
}

func (p *tripwireProvider) Revoke(context.Context, provider.RevokeRequest) error {
	p.calls.Add(1)
	return mcperr.New(mcperr.ReasonProviderUnavailable, "test.tripwire", "tripwire")
}

func (p *tripwireProvider) Inspect(context.Context, provider.Request) (provider.Lease, error) {
	p.calls.Add(1)
	return provider.Lease{}, mcperr.New(mcperr.ReasonProviderUnavailable, "test.tripwire", "tripwire")
}

// newTripwireBroker builds a REAL broker, composed exactly as newLiveProductionDeps composes the
// production one — same broker.New, same limits, same shared registry/catalog — with an EMPTY
// profile store and the tripwire provider registered.
//
// THE EMPTY PROFILE STORE IS THE INSTRUMENT, and it is what makes the zero-use claim decidable.
// broker.Plan resolves the policy-named profile out of that store, so ANY consultation of the
// credential path fails loudly and blocks the request. A credential-free request that still
// reaches the upstream therefore PROVES the broker was not consulted: had it been, this broker
// would have refused. That is a stronger statement than counting, and it needs no seam inside
// the broker.
//
// It also mirrors production more closely than a populated store would: the production broker is
// composed with an empty profile store and zero providers (mcp_live_production_deps.go), which is
// the honest pre-Canary posture.
func newTripwireBroker(t *testing.T) (*broker.Broker, *tripwireProvider) {
	t.Helper()
	reg := registry.New(limits.DefaultCatalog())
	cat := catalog.New(limits.DefaultCatalog())
	brk := broker.New(broker.Deps{
		Profiles: profile.NewStore(limits.DefaultCredential()),
		Registry: reg,
		Catalog:  cat,
		KEK:      liveTestKEK(),
		Clock:    func() time.Time { return time.Unix(0, 1) },
	}, limits.DefaultCredential())
	tw := &tripwireProvider{}
	if err := brk.RegisterProvider(tw); err != nil {
		t.Fatalf("register tripwire provider: %v", err)
	}
	return brk, tw
}

// ── §6 — the broker is never touched, and the request DOES reach the boundary ──

// TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery is the §6 proof.
//
// Four assertions, and the FIRST is the one that stops this being vacuous: the request must
// actually reach the pre-upstream execution boundary. A broken path that never gets near the
// broker would satisfy "the broker was not used" while proving nothing — which is exactly the
// failure mode §6 names.
func TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery(t *testing.T) {
	up := &recordingUpstream{}
	brk, tw := newTripwireBroker(t)
	cfg := armCanaryLiveTierBroker(t, up, func() *mcpLiveSideEffectGate {
		return liveRealGate(rollout.CapabilityGateway, true)
	}, 10, brk)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	if in.Decision.Obligations.CredentialProfile != "" {
		t.Fatal("fixture drifted: the canonical First-Canary decision must carry NO credential obligation")
	}
	out := ex.Execute(context.Background(), in, ex.Resolve(in))

	// (1) POSITIVE CONTROL — the request reached the side-effect boundary. Without this every
	// other assertion below is satisfied by a path that simply never ran.
	if up.callCount() != 1 {
		t.Fatalf("the canonical read-first request must reach the upstream exactly once "+
			"(otherwise the zero-use assertions below prove nothing), calls=%d out=%+v", up.callCount(), out)
	}
	if !out.Executed {
		t.Fatalf("the canonical request must be reported executed, out=%+v", out)
	}
	// (2) NO AUTHORIZATION HEADER reached the upstream leg.
	if got := up.authHeader(); got != "" {
		t.Fatalf("SECURITY: the canonical credential-free path sent an Authorization header (%q)", got)
	}
	// (3) The provider was never reached.
	if n := tw.calls.Load(); n != 0 {
		t.Fatalf("SECURITY: the credential provider was called %d times on a credential-free path", n)
	}
	// (4) The broker was never consulted. This broker's profile store is EMPTY, so a Plan call
	// would have failed and blocked the request; assertions (1)+(2) passing IS that proof, and
	// TestCredZeroUse_CredentialRequiredFailsClosedWithUpstreamZero establishes the premise it
	// rests on — that THIS composition does block when the credential path is entered.
}

// ── §7 — the credential-REQUIRED control ─────────────────────────────────────

// TestCredZeroUse_CredentialRequiredFailsClosedWithUpstreamZero is the §7 control against the
// SAME composition: a decision carrying a CredentialProfile obligation, forced through the real
// executor, must fail closed with the upstream never reached.
//
// It is the defense-in-depth half of the readiness fact: even if a credential-requiring
// experiment somehow reached execution, no request escapes unauthenticated. And it is what makes
// the zero-use gate above non-vacuous from the other direction — this composition CAN block, so
// the canonical path executing is a real signal.
func TestCredZeroUse_CredentialRequiredFailsClosedWithUpstreamZero(t *testing.T) {
	up := &recordingUpstream{}
	brk, tw := newTripwireBroker(t)
	cfg := armCanaryLiveTierBroker(t, up, func() *mcpLiveSideEffectGate {
		return liveRealGate(rollout.CapabilityGateway, true)
	}, 10, brk)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.Decision.Obligations.CredentialProfile = "cred-a"
	out := ex.Execute(context.Background(), in, ex.Resolve(in))

	if up.callCount() != 0 {
		t.Fatalf("SECURITY: a credential-required execution reached the upstream; calls=%d", up.callCount())
	}
	if out.Executed {
		t.Fatalf("a credential-required execution with no materializable credential must not execute, out=%+v", out)
	}
	if got := up.authHeader(); got != "" {
		t.Fatalf("SECURITY: an Authorization header was constructed for a refused execution (%q)", got)
	}
	// The provider may not be reached either: the refusal happens at Plan, before any fetch.
	if n := tw.calls.Load(); n != 0 {
		t.Fatalf("the refusal must happen at planning, before any provider call; provider calls=%d", n)
	}
}

// TestCredZeroUse_CredentialRequiredWithNoBrokerFailsClosed pins the OTHER composition shape —
// the one run.go's executePreconditionFailure guards — so the existing
// mcperr.ReasonCredentialProfileMissing behaviour stays intact (§7).
//
// This matters because production composes a NON-nil broker, so that guard is not the one
// production hits; both shapes must fail closed or the guarantee depends on which composition
// a node happens to have.
func TestCredZeroUse_CredentialRequiredWithNoBrokerFailsClosed(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10) // nil broker
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.Decision.Obligations.CredentialProfile = "cred-a"
	out := ex.Execute(context.Background(), in, ex.Resolve(in))

	if up.callCount() != 0 {
		t.Fatalf("SECURITY: a credential-required execution with NO broker reached the upstream; calls=%d", up.callCount())
	}
	if out.Executed {
		t.Fatalf("must not execute, out=%+v", out)
	}
	if out.Reason != mcperr.ReasonCredentialProfileMissing {
		t.Fatalf("the existing named refusal must be preserved: want %q got %q",
			mcperr.ReasonCredentialProfileMissing, out.Reason)
	}
}

// ── §8 — auxiliary MCP traffic ───────────────────────────────────────────────

// TestCredZeroUse_AuxiliaryTrafficCarriesNoAuthorization is the §8 proof, and it has two parts
// because the auxiliary methods split into two shapes.
//
// (1) LIFECYCLE — initialize / ping / notifications/initialized / notifications/cancelled — are
// KERNEL-TERMINAL: the Gateway answers them itself (pipeline.completeKernelTerminal) and they
// never reach upstreamclient at all, so they cannot carry a credential to an upstream by
// construction. Asserted structurally, because there is no call to observe.
//
// (2) DISCOVERY — tools/list — DOES reach the upstream, from execution.Discovery. Its
// CallOptions literal omits AuthHeader, which is a property of one line of code and exactly the
// kind of thing a later edit changes silently (campaign mutation M10). Asserted by driving the
// real Discovery against a recording upstream.
func TestCredZeroUse_AuxiliaryTrafficCarriesNoAuthorization(t *testing.T) {
	// (1) lifecycle methods are kernel-terminal: the Gateway answers them and no upstream leg
	// exists. Asserted against the protocol's own dispatch classification rather than by
	// observing a call that by construction never happens.
	aux := []struct {
		method string
		class  jsonrpc.Class
	}{
		{"initialize", jsonrpc.ClassRequest},
		{"ping", jsonrpc.ClassRequest},
		{"notifications/initialized", jsonrpc.ClassNotification},
		{"notifications/cancelled", jsonrpc.ClassNotification},
	}
	for _, a := range aux {
		adm := protocol.Admit(protocol.Gateway, protocol.ClientOriginated, a.class, a.method)
		if adm.Handling != protocol.HandlingKernelTerminal {
			t.Errorf("SECURITY: %q is no longer kernel-terminal (handling=%v). It now reaches a "+
				"dispatch that can forward upstream, so whether it carries an Authorization header "+
				"must be re-derived rather than assumed — auxiliary traffic rides no policy "+
				"decision and is therefore covered by no credential obligation.", a.method, adm.Handling)
		}
		if upstreamclient.ClassifyMethod(a.method).SideEffectBearing() {
			t.Errorf("premise drifted: %q is now side-effect bearing", a.method)
		}
	}
	// (2) discovery — the real Discovery, the real registry, a recording upstream.
	up := &recordingUpstream{}
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: "pin1",
		Capability: 0, OwnerScope: "t1",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, err := reg.VerifyIdentity("s1", "pin1"); err != nil {
		t.Fatalf("verify identity: %v", err)
	}
	d := &execution.Discovery{Registry: reg, Catalog: catalog.New(limits.DefaultCatalog()), Upstream: up}
	// The ingest will fail (the recording upstream returns a non-tools/list body); that is fine
	// and deliberate — this gate is about what was SENT, not about what came back.
	_, _ = d.Discover(context.Background(), "s1")
	if up.callCount() == 0 {
		t.Fatal("premise: discovery must have reached the upstream, or this gate proves nothing")
	}
	if got := up.lastMethod(); got != "tools/list" {
		t.Fatalf("premise: the discovery leg must be tools/list, got %q", got)
	}
	if got := up.authHeader(); got != "" {
		t.Fatalf("SECURITY: tools/list discovery carried an Authorization header (%q). Discovery "+
			"runs outside the policy decision, so a credential here is attached to NO decision and "+
			"is covered by no obligation.", got)
	}
}

// recordingUpstream accessors used by the gates above. They exist so the assertions read as
// questions about the wire rather than as struct-field pokes under a lock.
func (u *recordingUpstream) authHeader() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastAuth
}

func (u *recordingUpstream) lastMethod() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastMeth
}
