package broker

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Review fix (HIGH): a cached credential must be re-validated against the plan
// actually consuming it. A Write-power credential cached by a write op must NOT be
// served to a later low-risk read op (whose ceiling is read-only) — the read must
// fail closed exactly as a fresh fetch would.
func TestReviewFix_CacheServeRevalidatesPlan(t *testing.T) {
	get, _, _ := mutableClock()
	h, _ := brokerAt(t, get, profile.PowerWrite)
	// A write op (high-risk) fetches + caches a Write-power credential.
	if _, err := h.broker.Materialize(context.Background(), h.writePlan(t), permitGate(), noopCB); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A subsequent read op must not receive the write-power credential from cache.
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); mcperr.ReasonOf(err) != mcperr.ReasonCredentialPowerExceeded {
		t.Fatalf("read must reject the write-power cached credential, got %v", mcperr.ReasonOf(err))
	}
}

// Review fix: rotation must reject a successor whose lease TTL exceeds the profile
// maximum (short-lived bound), not just an already-expired one.
func TestReviewFix_RotationRejectsLongTTLSuccessor(t *testing.T) {
	get, _, base := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Successor expiry is a year out (profile MaxTTL is 30m).
	prov.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("v2")},
		provider.Lease{Version: "v2", IssuedAt: base, Expiry: base.Add(365 * 24 * time.Hour), Scope: leaseScope(t, profile.PowerReadOnly)})
	if _, err := h.broker.Rotate(context.Background(), profID); mcperr.ReasonOf(err) != mcperr.ReasonRotationFailed {
		t.Fatalf("long-TTL successor must fail rotation, got %v", mcperr.ReasonOf(err))
	}
}

// Review fix: rotation must enforce the profile's tool bound on the successor. A
// tool-scoped profile whose successor names a different tool must fail rotation.
func TestReviewFix_RotationEnforcesToolBound(t *testing.T) {
	get, _, base := mutableClock()
	reg := gwRegistry(t)
	cat := newCatalog()
	store := profile.NewStore(limits.DefaultCredential())
	rs, _ := profile.NewResourceScope([]string{"repo:foo"})
	if _, err := store.Add(profile.Input{
		ID: profID, Provider: provID, Tenant: tenantA, Environment: "prod", Server: srv1,
		Tools: []string{"tool-a"}, Resources: rs, Operations: []profile.OperationClass{profile.OpRead},
		Kind: profile.KindBearerToken, Power: profile.PowerReadOnly, MaxTTL: 30 * time.Minute,
		Cache: profile.CachePolicy{Enabled: true, Freshness: time.Minute}, Rotation: profile.RotationPolicy{Enabled: true, Grace: time.Second, MaxAttempts: 3},
		Failure: profile.FailurePolicy{HighRiskFailClosed: true}, Enabled: true,
	}, reg.Current()); err != nil {
		t.Fatal(err)
	}
	prov := provider.NewInMemory(provID, provider.Capabilities{CanRotate: true})
	// Successor effective scope names a FOREIGN tool "tool-b".
	sc := leaseScope(t, profile.PowerReadOnly)
	sc.Tools = []string{"tool-b"}
	prov.SetMaterial(profile.KindBearerToken, map[provider.FieldName][]byte{provider.FieldToken: []byte("v1")},
		provider.Lease{Version: "v1", IssuedAt: base, Expiry: base.Add(10 * time.Minute), Scope: leaseScope(t, profile.PowerReadOnly)})
	prov.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("v2")},
		provider.Lease{Version: "v2", IssuedAt: base, Expiry: base.Add(10 * time.Minute), Scope: sc})
	b := New(Deps{Profiles: store, Registry: reg, Catalog: cat, KEK: testKEK(), Clock: get}, limits.DefaultCredential())
	if err := b.RegisterProvider(prov); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Rotate(context.Background(), profID); mcperr.ReasonOf(err) != mcperr.ReasonRotationFailed {
		t.Fatalf("successor naming a foreign tool must fail rotation, got %v", mcperr.ReasonOf(err))
	}
}

// Review fix: a successor revoked mid-rotation must clear the rotation claim, so a
// later rotation is not stuck forever with rotation_in_progress.
func TestReviewFix_RotationNotStuckAfterSuccessorRevoked(t *testing.T) {
	get, _, base := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Pre-tombstone the successor version "v2" so publishSuccessor rejects it.
	if _, err := h.broker.RevokeVersion(context.Background(), profID, "v2"); err != nil {
		t.Fatal(err)
	}
	prov.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("v2")},
		provider.Lease{Version: "v2", IssuedAt: base, Expiry: base.Add(10 * time.Minute), Scope: leaseScope(t, profile.PowerReadOnly)})
	if _, err := h.broker.Rotate(context.Background(), profID); mcperr.ReasonOf(err) != mcperr.ReasonRotationFailed {
		t.Fatalf("revoked successor must fail rotation, got %v", mcperr.ReasonOf(err))
	}
	// A subsequent rotation with a fresh, non-revoked successor must NOT be stuck.
	prov.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("v3")},
		provider.Lease{Version: "v3", IssuedAt: base, Expiry: base.Add(10 * time.Minute), Scope: leaseScope(t, profile.PowerReadOnly)})
	if _, err := h.broker.Rotate(context.Background(), profID); err != nil {
		t.Fatalf("rotation must not be stuck after a revoked-successor failure, got %v", err)
	}
}

// Review fix: BaseRevision is the PROFILE revision, not the store snapshot revision.
// Adding another profile advances the store revision but must not make an existing
// plan input stale.
func TestReviewFix_BaseRevisionIsProfileRevision(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	profRev := h.store.Current().Revision() // == the only profile's revision (1)
	// Add a second, unrelated profile — advances the STORE revision to 2.
	rs, _ := profile.NewResourceScope([]string{"repo:foo"})
	if _, err := h.store.Add(profile.Input{
		ID: "prof-2", Provider: provID, Tenant: tenantA, Environment: "prod", Server: srv1,
		Resources: rs, Operations: []profile.OperationClass{profile.OpRead}, Kind: profile.KindBearerToken,
		Power: profile.PowerReadOnly, MaxTTL: 30 * time.Minute, Cache: profile.CachePolicy{Enabled: true, Freshness: time.Minute},
		Failure: profile.FailurePolicy{HighRiskFailClosed: true}, Enabled: true,
	}, h.reg.Current()); err != nil {
		t.Fatal(err)
	}
	if h.store.Current().Revision() == profRev {
		t.Fatal("store revision should have advanced")
	}
	// Planning prof-1 with its own (unchanged) profile revision must NOT be stale.
	if _, err := h.broker.Plan(PlanInput{Identity: h.id, Profile: profID, BaseRevision: profRev, Environment: "prod", Operation: profile.OpRead}); err != nil {
		t.Fatalf("plan with the profile's own revision must not be stale, got %v", err)
	}
}
