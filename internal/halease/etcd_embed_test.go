package halease

// Embedded-etcd integration leg (ADR-0005 S1): runs the SAME conformance
// suite as the Fake against a real single-node etcd embedded in-process —
// so the create_revision-as-epoch mapping, lease expiry, and denial paths
// are exercised by etcd's actual Raft state machine on every CI run, with
// no external infrastructure. go.etcd.io/etcd/server/v3 is a TEST-ONLY
// dependency (the shipped binary links only client/v3, and only once S2
// wires it).

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"go.etcd.io/etcd/server/v3/embed"
)

// startEmbeddedEtcd boots a single-node etcd on 127.0.0.1 ephemeral ports
// with all state under t.TempDir, and tears it down with the test.
func startEmbeddedEtcd(t *testing.T) (clientURL string) {
	t.Helper()
	cfg := embed.NewConfig()
	cfg.Dir = t.TempDir()
	cfg.LogLevel = "fatal" // teardown otherwise logs benign accept-after-close errors

	// Ephemeral ports: bind :0 and read back what the kernel assigned.
	curl := url.URL{Scheme: "http", Host: "127.0.0.1:0"}
	purl := url.URL{Scheme: "http", Host: "127.0.0.1:0"}
	cfg.ListenClientUrls = []url.URL{curl}
	cfg.ListenPeerUrls = []url.URL{purl}
	// Advertise/cluster URLs cannot be :0 — but a single-node cluster only
	// needs them self-consistent, so pin a fixed loopback peer port derived
	// from the test's temp state (etcd validates the initial-cluster map
	// against the advertised peer URL, not the listen URL).
	apurl := url.URL{Scheme: "http", Host: "127.0.0.1:23790"}
	cfg.AdvertisePeerUrls = []url.URL{apurl}
	cfg.ListenPeerUrls = []url.URL{apurl}
	cfg.InitialCluster = fmt.Sprintf("%s=%s", cfg.Name, apurl.String())

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatalf("start embedded etcd: %v", err)
	}
	t.Cleanup(e.Close)

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("embedded etcd not ready within 30s")
	}
	return e.Clients[0].Addr().String()
}

func TestEtcd_Conformance_Embedded(t *testing.T) {
	if testing.Short() {
		t.Skip("embedded etcd leg skipped in -short mode")
	}
	clientURL := startEmbeddedEtcd(t)

	p, err := NewEtcd(Config{
		Endpoints: []string{"http://" + clientURL},
		TTL:       2 * time.Second, // shortest practical; the expiry leg waits it out
	})
	if err != nil {
		t.Fatalf("NewEtcd: %v", err)
	}
	defer p.Close() //nolint:errcheck // test cleanup

	testConformance(t, p, func(t *testing.T) {
		// etcd — not the test — is the lease-time authority: wait until the
		// server actually deletes the lease-bound key.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			st, err := p.Read(context.Background())
			if err == nil && st.Holder == "" {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatal("lease did not expire within 15s")
	})
}

// TestEtcd_AcquireDenied_RevokesScratchLease pins the cleanup contract: a
// denied Acquire must not leak its pre-granted lease (leaked leases would
// accumulate on every standby retry, ~1 per retry interval, forever).
func TestEtcd_AcquireDenied_RevokesScratchLease(t *testing.T) {
	if testing.Short() {
		t.Skip("embedded etcd leg skipped in -short mode")
	}
	clientURL := startEmbeddedEtcd(t)
	p, err := NewEtcd(Config{Endpoints: []string{"http://" + clientURL}, TTL: 60 * time.Second})
	if err != nil {
		t.Fatalf("NewEtcd: %v", err)
	}
	defer p.Close() //nolint:errcheck // test cleanup

	ctx := context.Background()
	if granted, _, err := p.Acquire(ctx, "cp-a"); err != nil || !granted {
		t.Fatalf("seed acquire = (%v, %v)", granted, err)
	}
	before := countLeases(t, p)
	for i := 0; i < 5; i++ {
		if granted, _, err := p.Acquire(ctx, "cp-b"); err != nil || granted {
			t.Fatalf("denied acquire #%d = (%v, %v)", i, granted, err)
		}
	}
	after := countLeases(t, p)
	if after > before {
		t.Fatalf("denied Acquires leaked leases: %d -> %d", before, after)
	}
}

func countLeases(t *testing.T, p *Etcd) int {
	t.Helper()
	resp, err := p.cli.Leases(context.Background())
	if err != nil {
		t.Fatalf("list leases: %v", err)
	}
	return len(resp.Leases)
}
