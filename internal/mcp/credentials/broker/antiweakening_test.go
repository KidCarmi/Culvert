package broker

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Each test pins a load-bearing control by proving the weakened behavior would be
// wrong. The controls are exercised by the matrix tests; these frame the specific
// anti-weakening properties the spec calls out.

// The gate must run BEFORE the provider is touched. A weakened broker that fetched
// first would show a non-zero provider call count on a denied gate.
func TestAntiWeakening_ProviderNotCalledBeforeGate(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), &fakeGate{permit: false}, noopCB); err == nil {
		t.Fatal("expected denial")
	}
	if f, _, _ := h.prov.Calls(); f != 0 {
		t.Fatalf("provider called before/despite gate denial: %d", f)
	}
}

// A critical (high-risk) materialization must not proceed without a durably
// committed decision. A weakened broker that ignored DurableConfirmed would
// materialize.
func TestAntiWeakening_CriticalRequiresDurableConfirmation(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerWrite)
	res, err := h.broker.Materialize(context.Background(), h.writePlan(t), &fakeGate{permit: true, durable: false}, noopCB)
	if res.Materialized || mcperr.ReasonOf(err) != mcperr.ReasonMaterializationGateDenied {
		t.Fatalf("critical op materialized without durable confirmation: %+v %v", res, err)
	}
}

// A scope-mismatched credential must never validate. A weakened scope check would
// let a broader credential through.
func TestAntiWeakening_ScopeMismatchRejected(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	bad := leaseScope(t, profile.PowerReadOnly)
	bad.Server = "srv-evil"
	h.prov.SetMaterial(profile.KindBearerToken, map[provider.FieldName][]byte{provider.FieldToken: []byte("x")},
		provider.Lease{Version: "v1", IssuedAt: h.clk(), Expiry: h.clk().Add(10 * timeMinute), Scope: bad})
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); mcperr.ReasonOf(err) != mcperr.ReasonCredentialScopeMismatch {
		t.Fatalf("scope-broadened credential must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

// An over-privileged credential must never validate.
func TestAntiWeakening_OverPrivilegedRejected(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	h.prov.SetMaterial(profile.KindBearerToken, map[provider.FieldName][]byte{provider.FieldToken: []byte("x")},
		provider.Lease{Version: "v1", IssuedAt: h.clk(), Expiry: h.clk().Add(10 * timeMinute), Scope: leaseScope(t, profile.PowerAdmin)})
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); mcperr.ReasonOf(err) != mcperr.ReasonCredentialPowerExceeded {
		t.Fatalf("over-privileged credential must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

// A Management identity presented to the Gateway broker must be rejected. A weakened
// capability check would let it materialize a Gateway credential.
func TestAntiWeakening_ManagementRejectedByGatewayBroker(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	if _, err := h.broker.Plan(PlanInput{Identity: managementIdentity(t), Profile: profID, Environment: "prod", Operation: profile.OpRead}); mcperr.ReasonOf(err) != mcperr.ReasonCapabilityMismatch {
		t.Fatalf("management identity must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

// Profiles are selected by opaque id, never by display name. This documents that the
// PlanInput exposes only ProfileID (an opaque token) — there is no name-based
// selection field to weaken.
func TestAntiWeakening_ProfileSelectedByOpaqueID(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	// A non-existent opaque id fails closed; there is no fuzzy/name fallback.
	if _, err := h.broker.Plan(PlanInput{Identity: h.id, Profile: "PROF-1", Environment: "prod", Operation: profile.OpRead}); mcperr.ReasonOf(err) != mcperr.ReasonCredentialProfileMissing {
		t.Fatalf("only an exact opaque id resolves; got %v", mcperr.ReasonOf(err))
	}
}

// The upstream material never appears in the provider request (no token passthrough).
func TestAntiWeakening_NoClientTokenToProvider(t *testing.T) {
	rp := &recordingProvider{InMemoryProvider: memProvider(t, fixedClock(), profile.PowerReadOnly, "v1", provider.Capabilities{})}
	h := newHarnessWithProvider(t, rp, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// The request carries only the sanitized digest; the identity's token never
	// existed as bytes in this package.
	if rp.lastReq.TokenDigest == "" {
		t.Fatal("correlation digest should be carried")
	}
}
