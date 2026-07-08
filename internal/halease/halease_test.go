package halease

// The conformance suite pins the Provider contract (ADR-0005 S1) and runs
// against BOTH implementations: Fake always, Etcd when
// CULVERT_TEST_ETCD_ENDPOINTS points at a reachable etcd (CI provides one;
// locally the etcd leg skips). Keeping one suite is the guarantee that the
// unit-test double and the production backend agree on semantics.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// expireFn force-expires the current lease so the suite can test
// expiry-reacquisition without depending on implementation TTL timing.
// The etcd leg implements it by waiting out a short real TTL.
type expireFn func(t *testing.T)

func testConformance(t *testing.T, p Provider, expire expireFn) {
	t.Helper()
	ctx := context.Background()

	// Free lease: Read reports no holder.
	st, err := p.Read(ctx)
	if err != nil {
		t.Fatalf("Read on free lease: %v", err)
	}
	if st.Holder != "" {
		t.Fatalf("free lease reports holder %q", st.Holder)
	}

	// First Acquire wins with a positive epoch.
	granted, st1, err := p.Acquire(ctx, "cp-a")
	if err != nil {
		t.Fatalf("Acquire(cp-a): %v", err)
	}
	if !granted {
		t.Fatal("first Acquire must be granted")
	}
	if st1.Holder != "cp-a" || st1.Epoch <= 0 {
		t.Fatalf("grant status = %+v, want holder=cp-a epoch>0", st1)
	}
	if st1.ValidFor <= 0 {
		t.Fatalf("grant ValidFor = %v, want > 0", st1.ValidFor)
	}

	// Second candidate is denied and sees the real holder.
	granted, st2, err := p.Acquire(ctx, "cp-b")
	if err != nil {
		t.Fatalf("Acquire(cp-b): %v", err)
	}
	if granted {
		t.Fatal("Acquire while held must be denied")
	}
	if st2.Holder != "cp-a" || st2.Epoch != st1.Epoch {
		t.Fatalf("denied status = %+v, want holder=cp-a epoch=%d", st2, st1.Epoch)
	}

	// Read agrees.
	st, err = p.Read(ctx)
	if err != nil {
		t.Fatalf("Read while held: %v", err)
	}
	if st.Holder != "cp-a" || st.Epoch != st1.Epoch {
		t.Fatalf("Read = %+v, want holder=cp-a epoch=%d", st, st1.Epoch)
	}

	// Holder renews fine; a non-holder / stale epoch cannot.
	ok, validFor, err := p.Renew(ctx, "cp-a", st1.Epoch)
	if err != nil {
		t.Fatalf("Renew by holder: %v", err)
	}
	if !ok || validFor <= 0 {
		t.Fatalf("Renew by holder = (%v, %v), want (true, >0)", ok, validFor)
	}
	if ok, _, err := p.Renew(ctx, "cp-b", st1.Epoch); err != nil || ok {
		t.Fatalf("Renew by non-holder = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, _, err := p.Renew(ctx, "cp-a", st1.Epoch-1); err != nil || ok {
		t.Fatalf("Renew with stale epoch = (%v, %v), want (false, nil)", ok, err)
	}

	// Expiry: the standby's Acquire now wins, and the FENCING PROPERTY
	// holds — the new epoch is strictly greater.
	expire(t)
	granted, st3, err := p.Acquire(ctx, "cp-b")
	if err != nil {
		t.Fatalf("Acquire(cp-b) after expiry: %v", err)
	}
	if !granted {
		t.Fatal("Acquire after expiry must be granted")
	}
	if st3.Holder != "cp-b" {
		t.Fatalf("post-expiry holder = %q, want cp-b", st3.Holder)
	}
	if st3.Epoch <= st1.Epoch {
		t.Fatalf("FENCING VIOLATION: new epoch %d not > old epoch %d", st3.Epoch, st1.Epoch)
	}

	// The old holder's Renew with the superseded epoch reports LOSS (not error).
	if ok, _, err := p.Renew(ctx, "cp-a", st1.Epoch); err != nil || ok {
		t.Fatalf("old holder Renew after supersession = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestFake_Conformance(t *testing.T) {
	f := NewFake(10 * time.Second)
	testConformance(t, f, func(*testing.T) { f.ExpireForTest() })
}

func TestFake_RenewExtendsExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	f := NewFake(10 * time.Second)
	f.SetNowForTest(func() time.Time { return now })

	granted, st, _ := f.Acquire(context.Background(), "cp-a")
	if !granted {
		t.Fatal("acquire")
	}
	// 8s later: still valid; renew pushes expiry out.
	now = now.Add(8 * time.Second)
	if ok, _, _ := f.Renew(context.Background(), "cp-a", st.Epoch); !ok {
		t.Fatal("renew at t+8s should succeed")
	}
	// 9s after the renew (t+17s; original expiry was t+10s): still valid.
	now = now.Add(9 * time.Second)
	if ok, _, _ := f.Renew(context.Background(), "cp-a", st.Epoch); !ok {
		t.Fatal("renew at t+17s should succeed after the t+8s extension")
	}
	// 11s of silence: expired; renew reports loss.
	now = now.Add(11 * time.Second)
	if ok, _, _ := f.Renew(context.Background(), "cp-a", st.Epoch); ok {
		t.Fatal("renew after TTL silence must report loss")
	}
}

func TestFake_ReadNeverMutates(t *testing.T) {
	f := NewFake(time.Minute)
	_, st1, _ := f.Acquire(context.Background(), "cp-a")
	for i := 0; i < 3; i++ {
		st, err := f.Read(context.Background())
		if err != nil || st.Epoch != st1.Epoch || st.Holder != "cp-a" {
			t.Fatalf("Read #%d = (%+v, %v)", i, st, err)
		}
	}
}

// TestEtcd_Conformance runs the same contract against a REAL etcd.
// Gated on CULVERT_TEST_ETCD_ENDPOINTS (comma-separated); skips otherwise.
// Uses a short real TTL so the expiry leg completes by actually waiting —
// etcd, not the test, is the lease-time authority.
func TestEtcd_Conformance(t *testing.T) {
	endpoints := os.Getenv("CULVERT_TEST_ETCD_ENDPOINTS")
	if endpoints == "" {
		t.Skip("CULVERT_TEST_ETCD_ENDPOINTS not set; skipping etcd integration leg")
	}
	p, err := NewEtcd(Config{
		Endpoints: strings.Split(endpoints, ","),
		TTL:       2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewEtcd: %v", err)
	}
	defer p.Close() //nolint:errcheck // test cleanup

	// Start from a clean key so the suite is re-runnable.
	cleanupLeaderKey(t, p)
	t.Cleanup(func() { cleanupLeaderKey(t, p) })

	testConformance(t, p, func(t *testing.T) {
		// Wait out the real TTL (plus etcd's grant rounding) so the key
		// vanishes server-side.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			st, err := p.Read(context.Background())
			if err == nil && st.Holder == "" {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatal("lease did not expire within 10s")
	})
}

// cleanupLeaderKey removes the leader key between runs (test hygiene only —
// production never deletes it; expiry does).
func cleanupLeaderKey(t *testing.T, p *Etcd) {
	t.Helper()
	if _, err := p.cli.Delete(context.Background(), leaderKey); err != nil {
		t.Fatalf("cleanup leader key: %v", err)
	}
}
