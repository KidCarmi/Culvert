package broker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestRotationSuccessKeepsCurrentUsable(t *testing.T) {
	get, _, base := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	// Establish the current version via a read.
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Configure a successor.
	prov.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("UPSTREAM-v2")},
		provider.Lease{Version: "v2", IssuedAt: base, Expiry: base.Add(20 * time.Minute), Scope: leaseScope(t, profile.PowerReadOnly)})
	res, err := h.broker.Rotate(context.Background(), profID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if res.Version != "v2" || res.Rotation != "active" {
		t.Fatalf("rotation result wrong: %+v", res)
	}
	// A read now serves v2.
	r2, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB)
	if err != nil || r2.Version != "v2" {
		t.Fatalf("post-rotation read: v=%v err=%v", r2.Version, err)
	}
}

func TestRotationFailedSuccessorKeepsCurrentActive(t *testing.T) {
	get, _, _ := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Successor fetch fails.
	prov.SetRotateError(provider.NewError(mcperr.ReasonProviderUnavailable, true))
	if _, err := h.broker.Rotate(context.Background(), profID); mcperr.ReasonOf(err) != mcperr.ReasonRotationFailed {
		t.Fatalf("failed rotation must report rotation_failed, got %v", mcperr.ReasonOf(err))
	}
	// The current version (v1) stays usable.
	r, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB)
	if err != nil || r.Version != "v1" {
		t.Fatalf("current must stay active after failed rotation: v=%v err=%v", r.Version, err)
	}
}

func TestRotationRejectsInvalidSuccessor(t *testing.T) {
	get, _, base := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Successor has a broader (cross-tenant) scope → validation fails, current stays.
	bad := leaseScope(t, profile.PowerReadOnly)
	bad.Tenant = tenantB
	prov.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("v2")},
		provider.Lease{Version: "v2", IssuedAt: base, Expiry: base.Add(20 * time.Minute), Scope: bad})
	if _, err := h.broker.Rotate(context.Background(), profID); mcperr.ReasonOf(err) != mcperr.ReasonRotationFailed {
		t.Fatalf("invalid successor must fail rotation, got %v", mcperr.ReasonOf(err))
	}
}

func TestConcurrentRotationsForDifferentProfilesIndependent(t *testing.T) {
	get, _, base := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	// Add a second profile + provider.
	if _, err := h.store.Add(profile.Input{
		ID: "prof-2", Provider: "prov-2", Tenant: tenantA, Environment: "prod", Server: srv1,
		Resources: profScope(t), Operations: []profile.OperationClass{profile.OpRead},
		Kind: profile.KindBearerToken, Power: profile.PowerReadOnly, MaxTTL: 30 * time.Minute,
		Cache: profile.CachePolicy{Enabled: true, Freshness: time.Minute}, Rotation: profile.RotationPolicy{Enabled: true, Grace: time.Second, MaxAttempts: 3},
		Failure: profile.FailurePolicy{HighRiskFailClosed: true}, Enabled: true,
	}, h.reg.Current()); err != nil {
		t.Fatal(err)
	}
	prov2 := provider.NewInMemory("prov-2", provider.Capabilities{CanRotate: true})
	prov2.SetMaterial(profile.KindBearerToken, map[provider.FieldName][]byte{provider.FieldToken: []byte("p2v1")},
		provider.Lease{Version: "p2v1", IssuedAt: base, Expiry: base.Add(20 * time.Minute), Scope: leaseScope(t, profile.PowerReadOnly)})
	prov2.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("p2v2")},
		provider.Lease{Version: "p2v2", IssuedAt: base, Expiry: base.Add(20 * time.Minute), Scope: leaseScope(t, profile.PowerReadOnly)})
	if err := h.broker.RegisterProvider(prov2); err != nil {
		t.Fatal(err)
	}
	prov.SetRotateMaterial(map[provider.FieldName][]byte{provider.FieldToken: []byte("v2")},
		provider.Lease{Version: "v2", IssuedAt: base, Expiry: base.Add(20 * time.Minute), Scope: leaseScope(t, profile.PowerReadOnly)})

	var wg sync.WaitGroup
	wg.Add(2)
	var e1, e2 error
	go func() { defer wg.Done(); _, e1 = h.broker.Rotate(context.Background(), profID) }()
	go func() { defer wg.Done(); _, e2 = h.broker.Rotate(context.Background(), "prof-2") }()
	wg.Wait()
	if e1 != nil || e2 != nil {
		t.Fatalf("independent rotations should both succeed: %v %v", e1, e2)
	}
}
