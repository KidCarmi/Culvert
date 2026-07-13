package integration

import (
	"context"
	"testing"

	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/test/harness"
)

// Exactly-once create: same idempotency key returns the existing op (R9-F2).
func TestIdempotency_ExactlyOnceCreate(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	mk := func() (domain.Operation, bool) {
		op, existed, err := k.Store.CreateOperation(ctx, domain.Operation{
			ID: "OP-fixed-1", Scope: k.Scope, Kind: domain.KindRestart, Level: domain.L2,
			WorkerID: harness.Worker0, Intent: "x", IdempotencyKey: "IDEM-SAME", InitiatingActor: "human:cli"})
		if err != nil {
			t.Fatal(err)
		}
		return op, existed
	}
	op1, e1 := mk()
	op2, e2 := mk()
	if e1 {
		t.Fatal("first create should not be a duplicate")
	}
	if !e2 {
		t.Fatal("second create with same idem must be a duplicate")
	}
	if op1.ID != op2.ID {
		t.Fatalf("duplicate returned different op: %s vs %s", op1.ID, op2.ID)
	}
}

// Optimistic CAS: a stale-version writer loses (no lost updates).
func TestOptimisticCAS_StaleWriterConflicts(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	base, _, _ := k.Store.CreateOperation(ctx, domain.Operation{ID: "OP-cas", Scope: k.Scope, Kind: domain.KindRestart,
		Level: domain.L2, WorkerID: harness.Worker0, Intent: "x", IdempotencyKey: "IDEM-cas", InitiatingActor: "human:cli"})
	stale, _ := k.Store.GetOperation(ctx, k.Scope, base.ID) // version 0 snapshot

	tx1, _ := k.Store.Begin(ctx)
	fresh := base
	if err := k.Store.Transition(ctx, tx1, &fresh, domain.StateDiscovering, "svc", domain.ActorService, "discovering", nil); err != nil {
		t.Fatal(err)
	}
	tx1.Commit(ctx) // version now 1

	tx2, _ := k.Store.Begin(ctx)
	defer tx2.Rollback(ctx)
	err := k.Store.Transition(ctx, tx2, &stale, domain.StateDiscovering, "svc", domain.ActorService, "discovering", nil)
	if domain.CodeOf(err) != domain.CodeConflict {
		t.Fatalf("stale writer should conflict, got %v", err)
	}
}

// Per-worker mutation lease: only one active lease per worker (uses SELECT FOR UPDATE).
func TestLease_SingleActivePerWorker(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	a, _, _ := k.Store.CreateOperation(ctx, domain.Operation{ID: "OP-la", Scope: k.Scope, Kind: domain.KindRestart, Level: domain.L2, WorkerID: harness.Worker0, Intent: "x", IdempotencyKey: "ia", InitiatingActor: "h"})
	b, _, _ := k.Store.CreateOperation(ctx, domain.Operation{ID: "OP-lb", Scope: k.Scope, Kind: domain.KindRestart, Level: domain.L2, WorkerID: harness.Worker0, Intent: "x", IdempotencyKey: "ib", InitiatingActor: "h"})

	tx, _ := k.Store.Begin(ctx)
	if err := k.Store.AcquireLease(ctx, tx, k.Scope, harness.Worker0, a.ID, "exec-1", 90_000_000_000); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)

	tx2, _ := k.Store.Begin(ctx)
	err := k.Store.AcquireLease(ctx, tx2, k.Scope, harness.Worker0, b.ID, "exec-2", 90_000_000_000)
	tx2.Rollback(ctx)
	if domain.CodeOf(err) != domain.CodeLeaseHeld {
		t.Fatalf("second op should be lease_held, got %v", err)
	}

	// after expiry, b can take it
	_ = k.Store.ForceExpireLease(ctx, k.Scope, harness.Worker0)
	tx3, _ := k.Store.Begin(ctx)
	if err := k.Store.AcquireLease(ctx, tx3, k.Scope, harness.Worker0, b.ID, "exec-2", 90_000_000_000); err != nil {
		t.Fatalf("after expiry b should acquire: %v", err)
	}
	tx3.Commit(ctx)
}

// Outbox commits atomically with the event and preserves order; an illegal
// transition writes NEITHER an event NOR an outbox row.
func TestOutbox_AtomicAndOrdered(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	op, _, _ := k.Store.CreateOperation(ctx, domain.Operation{ID: "OP-ob", Scope: k.Scope, Kind: domain.KindRestart, Level: domain.L2, WorkerID: harness.Worker0, Intent: "x", IdempotencyKey: "iob", InitiatingActor: "h"})
	tx, _ := k.Store.Begin(ctx)
	_ = k.Store.Transition(ctx, tx, &op, domain.StateDiscovering, "svc", domain.ActorService, "discovering", nil)
	_ = k.Store.Transition(ctx, tx, &op, domain.StatePlanning, "svc", domain.ActorService, "planning", nil)
	tx.Commit(ctx)

	// illegal transition in a fresh tx must add nothing
	before, _ := k.Store.ReadOutbox(ctx, k.Scope.TenantID)
	tx2, _ := k.Store.Begin(ctx)
	if err := k.Store.Transition(ctx, tx2, &op, domain.StateSucceeded, "svc", domain.ActorService, "bad", nil); domain.CodeOf(err) != domain.CodeIllegalTransition {
		t.Fatalf("expected illegal transition, got %v", err)
	}
	tx2.Rollback(ctx)
	after, _ := k.Store.ReadOutbox(ctx, k.Scope.TenantID)
	if len(before) != len(after) {
		t.Fatalf("illegal transition must not write outbox: %d -> %d", len(before), len(after))
	}

	topics, _ := k.Store.ReadOutbox(ctx, k.Scope.TenantID)
	want := []string{"operation.created", "operation.discovering", "operation.planning"}
	if len(topics) != len(want) {
		t.Fatalf("outbox topics: got %v want %v", topics, want)
	}
	for i := range want {
		if topics[i] != want[i] {
			t.Fatalf("outbox order[%d]: got %s want %s", i, topics[i], want[i])
		}
	}
}

// Tenant isolation: objects from tenant A are invisible in tenant B's scope.
func TestTenantIsolation(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	harness.SeedWorker(t, k.Store, harness.TenantB)
	scB := harness.Scope(harness.TenantB)

	opA, _, _ := k.Store.CreateOperation(ctx, domain.Operation{ID: "OP-tenantA", Scope: k.Scope, Kind: domain.KindRestart, Level: domain.L2, WorkerID: harness.Worker0, Intent: "x", IdempotencyKey: "itA", InitiatingActor: "h"})

	if _, err := k.Store.GetOperation(ctx, scB, opA.ID); domain.CodeOf(err) != domain.CodeNotFound {
		t.Fatalf("tenant B must not read tenant A's op, got %v", err)
	}
	if _, err := k.Store.GetOperation(ctx, k.Scope, opA.ID); err != nil {
		t.Fatalf("tenant A must read its own op: %v", err)
	}
}
