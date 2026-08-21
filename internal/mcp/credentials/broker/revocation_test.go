package broker

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestRevokeVersionBlocksFutureAndInvalidatesCache(t *testing.T) {
	get, _, _ := mutableClock()
	h, _ := brokerAt(t, get, profile.PowerReadOnly)
	// Establish + cache v1.
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	if h.broker.cache.size() == 0 {
		t.Fatal("expected a cached envelope")
	}
	// Revoke v1: cache invalidated, future use blocked.
	if _, err := h.broker.RevokeVersion(context.Background(), profID, "v1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if h.broker.cache.size() != 0 {
		t.Fatal("revocation must invalidate cache entries")
	}
	// A subsequent read tries to fetch fresh; the provider still returns v1 (now
	// tombstoned) → fail closed.
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); mcperr.ReasonOf(err) != mcperr.ReasonCredentialRevoked {
		t.Fatalf("revoked version must fail closed, got %v", mcperr.ReasonOf(err))
	}
}

func TestRevokeIdempotent(t *testing.T) {
	get, _, _ := mutableClock()
	h, _ := brokerAt(t, get, profile.PowerReadOnly)
	if _, err := h.broker.RevokeVersion(context.Background(), profID, "v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.broker.RevokeVersion(context.Background(), profID, "v1"); err != nil {
		t.Fatalf("repeated revoke must be idempotent: %v", err)
	}
}

func TestRevokeProfileBlocksEverything(t *testing.T) {
	get, _, _ := mutableClock()
	h, _ := brokerAt(t, get, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	h.broker.RevokeProfile(profID)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); mcperr.ReasonOf(err) != mcperr.ReasonCredentialRevoked {
		t.Fatalf("revoked profile must fail closed, got %v", mcperr.ReasonOf(err))
	}
}

func TestRevokeProviderFailureStillBlocksLocally(t *testing.T) {
	get, _, _ := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	prov.SetRevokeError(errorsNew("provider revoke boom"))
	res, err := h.broker.RevokeVersion(context.Background(), profID, "v1")
	if mcperr.ReasonOf(err) != mcperr.ReasonRevocationFailed {
		t.Fatalf("provider revoke failure should surface as revocation_failed, got %v", mcperr.ReasonOf(err))
	}
	if !res.Revoked {
		t.Fatal("local revocation must stand despite provider failure")
	}
	// Local use is blocked.
	if _, merr := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); mcperr.ReasonOf(merr) != mcperr.ReasonCredentialRevoked {
		t.Fatalf("local use must remain blocked, got %v", mcperr.ReasonOf(merr))
	}
}
