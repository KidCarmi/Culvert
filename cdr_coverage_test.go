package main

// Coverage tests for the Sluice v0.2 wire-up + runtime enable plumbing
// (cdr_health.go propagation / renewal helpers, cdr_ui.go enrollment
// persistence helpers, cdr_pool.go dialEnrolledInstance edges).

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── propagateServerRotation ───────────────────────────────────────────────

func TestPropagateServerRotation_NewRotationSignal(t *testing.T) {
	resetCDRState(t)
	// Enroll an instance with primary fingerprint only (no rotation yet).
	inst, err := cdrInstances.Add(CDREnrolledInstance{
		Name:              "rot",
		Endpoint:          "sluice:8443",
		ServerFingerprint: "primaryfp",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = inst

	// Build a pooled client with Health advertising a NEW rotated fingerprint.
	pc, stop := newPooledFake(t, "rot", &fakeSluice{})
	defer stop()
	pc.setHealth(&pb.HealthResponse{
		Healthy:                     true,
		ServerFingerprint:           "primaryfp",
		RotatedFingerprint:          "secondaryfp",
		RotatedFingerprintUntilUnix: time.Now().Add(24 * time.Hour).Unix(),
	})
	withTempPool(t, pc)

	propagateServerRotation([]*cdrPooledClient{pc})

	got := cdrInstances.Get("rot")
	if got == nil {
		t.Fatal("instance gone after propagate")
	}
	if got.RotatedFingerprint != "secondaryfp" {
		t.Fatalf("RotatedFingerprint = %q, want secondaryfp", got.RotatedFingerprint)
	}
	if got.RotatedFingerprintUntilUnix == 0 {
		t.Fatal("grace window timestamp not persisted")
	}
}

func TestPropagateServerRotation_GraceWindowExpiredPromotes(t *testing.T) {
	resetCDRState(t)
	// Instance currently advertising a rotation window that just expired.
	_, err := cdrInstances.Add(CDREnrolledInstance{
		Name:                        "prom",
		Endpoint:                    "sluice:8443",
		ServerFingerprint:           "oldprimary",
		RotatedFingerprint:          "newprimary",
		RotatedFingerprintUntilUnix: time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, stop := newPooledFake(t, "prom", &fakeSluice{})
	defer stop()
	// Sluice's Health now reports "newprimary" as the primary.
	pc.setHealth(&pb.HealthResponse{
		Healthy:           true,
		ServerFingerprint: "newprimary",
	})
	withTempPool(t, pc)

	propagateServerRotation([]*cdrPooledClient{pc})

	got := cdrInstances.Get("prom")
	if got == nil {
		t.Fatal("instance gone")
	}
	if got.ServerFingerprint != "newprimary" {
		t.Fatalf("primary did not promote: %q", got.ServerFingerprint)
	}
	if got.RotatedFingerprint != "" {
		t.Fatalf("rotated field not cleared: %q", got.RotatedFingerprint)
	}
	if got.RotatedFingerprintUntilUnix != 0 {
		t.Fatalf("rotated window not cleared: %d", got.RotatedFingerprintUntilUnix)
	}
}

// ─── maybeRenewExpiringClients ─────────────────────────────────────────────

// TestMaybeRenewExpiring_SkipsHealthyCerts — when there are no certs
// on disk for an instance, the function gracefully skips (no panic,
// no renewal attempt).  Broader coverage of the "healthy cert, no
// renewal needed" branch happens when a cert with NotAfter > 30d is
// parsed.
func TestMaybeRenewExpiring_SkipsHealthyCerts(t *testing.T) {
	resetCDRState(t)
	pc, stop := newPooledFake(t, "skipme", &fakeSluice{})
	defer stop()
	withTempPool(t, pc)
	// No registry entry → guarded skip.
	maybeRenewExpiringClients([]*cdrPooledClient{pc})
	// Must not panic; renewInFlight must still be 0.
	if pc.renewInFlight.Load() != 0 {
		t.Fatal("no renewal should have been kicked off")
	}
}

// TestMaybeRenewExpiring_InstanceWithoutCertPath — the early-return
// guard fires when ClientCertPath is empty (pre-v0.1 registry entries).
func TestMaybeRenewExpiring_InstanceWithoutCertPath(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "pc", Endpoint: "x:1"})
	pc, stop := newPooledFake(t, "pc", &fakeSluice{})
	defer stop()
	withTempPool(t, pc)
	maybeRenewExpiringClients([]*cdrPooledClient{pc})
	if pc.renewInFlight.Load() != 0 {
		t.Fatal("no renewal with empty cert path")
	}
}

// ─── applyAggregateHealth / handleAllMembersFailed ─────────────────────────

func TestApplyAggregateHealth_HealthyAndQueueDepthGauge(t *testing.T) {
	atomicReset := func() {
		atomicStore(&statCDRInstanceHealthy, 0)
		atomicStore(&statCDRQueueDepth, 0)
	}
	atomicReset()
	defer atomicReset()

	applyAggregateHealth(probeAggregate{
		anyHealthy: true,
		minQueue:   7,
		bestResp:   &pb.HealthResponse{Healthy: true, Version: "v0.2.0"},
	})
	if atomicLoad(&statCDRInstanceHealthy) != 1 {
		t.Fatal("healthy gauge should be 1")
	}
	if atomicLoad(&statCDRQueueDepth) != 7 {
		t.Fatalf("queue depth = %d, want 7", atomicLoad(&statCDRQueueDepth))
	}
}

func TestApplyAggregateHealth_UnhealthyGauge(t *testing.T) {
	atomicStore(&statCDRInstanceHealthy, 1)
	defer atomicStore(&statCDRInstanceHealthy, 0)

	applyAggregateHealth(probeAggregate{anyHealthy: false, minQueue: -1})
	if atomicLoad(&statCDRInstanceHealthy) != 0 {
		t.Fatal("all-unhealthy should flip gauge to 0")
	}
}

func TestHandleAllMembersFailed_IncrementsAndClears(t *testing.T) {
	atomicStore(&cdrHealthFailures, 0)
	defer atomicStore(&cdrHealthFailures, 0)

	// First failure — log but not yet clear.
	handleAllMembersFailed(2)
	if atomicLoad(&cdrHealthFailures) != 1 {
		t.Fatalf("expected 1 fail, got %d", atomicLoad(&cdrHealthFailures))
	}

	// Enough to trigger stale clear.
	for i := 0; i < 3; i++ {
		handleAllMembersFailed(2)
	}
	if atomicLoad(&statCDRInstanceHealthy) != 0 {
		t.Fatal("gauge should be 0 after repeated failures")
	}
}

// ─── updateRegistryMetadataFromPool ────────────────────────────────────────

func TestUpdateRegistryMetadataFromPool_CopiesVersion(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "mp", Endpoint: "x:1"})
	pc, stop := newPooledFake(t, "mp", &fakeSluice{})
	defer stop()
	pc.setHealth(&pb.HealthResponse{Healthy: true, Version: "v0.2.0"})
	withTempPool(t, pc)

	updateRegistryMetadataFromPool([]*cdrPooledClient{pc})

	got := cdrInstances.Get("mp")
	if got == nil || got.Version != "v0.2.0" {
		t.Fatalf("registry version not updated: %+v", got)
	}
	if got.LastHealth.IsZero() {
		t.Fatal("LastHealth not set")
	}
}

// ─── shredCDRCerts path guard ──────────────────────────────────────────────

func TestShredCDRCerts_RefusesPathOutsideRoot(t *testing.T) {
	// Writes a file OUTSIDE cdrCertsRoot and verifies shredCDRCerts
	// leaves it alone.  Don't want a tampered instances.json to
	// coerce us into deleting arbitrary files.
	tmp, err := os.CreateTemp("", "culvert-shred-*")
	if err != nil {
		t.Fatal(err)
	}
	path := tmp.Name()
	_ = tmp.Close()
	t.Cleanup(func() { _ = os.Remove(path) })

	shredCDRCerts(&CDREnrolledInstance{
		CACertPath: path, // /tmp/... — NOT under cdrCertsRoot
	})

	// File must still exist.
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("shredCDRCerts removed a file outside cdrCertsRoot: %v", statErr)
	}
}

// ─── persistCDREnrollment happy path ───────────────────────────────────────

func TestPersistCDREnrollment_WritesBundleAndRegisters(t *testing.T) {
	resetCDRState(t)
	// Build a fake EnrollResponse with minimal PEM content — we only
	// exercise the file write path here, not cert parsing.
	fakeResp := &pb.EnrollResponse{
		CaCert:     []byte("CA-PEM"),
		ClientCert: []byte("CLIENT-PEM"),
		ClientKey:  []byte("KEY-PEM"),
	}
	// cdrInstanceCertsDir returns /data/integrations/sluice/<name>/
	// which the test env may not be able to create.  Skip gracefully
	// if we can't write there.
	tryPath, err := cdrInstanceCertsDir("cov-test")
	if err != nil || os.MkdirAll(tryPath, 0o700) != nil {
		t.Skipf("cannot write %s (test env restricted)", tryPath)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tryPath) })

	stored, perr := persistCDREnrollment(cdrEnrollRequest{
		Name:              "cov-test",
		Endpoint:          "sluice:8443",
		ServerFingerprint: strings.Repeat("ab", 32),
	}, fakeResp)
	if perr != nil {
		t.Fatalf("persistCDREnrollment: %v", perr)
	}
	if stored.Name != "cov-test" {
		t.Fatalf("stored.Name = %q", stored.Name)
	}
	// Files must exist at the expected paths.
	for _, f := range []string{"ca.pem", "client.pem", "client.key"} {
		p := filepath.Join(tryPath, f)
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("expected file %s: %v", p, statErr)
		}
	}
}

// ─── atomic helpers (aliases for readability) ───────────────────────────────

func atomicLoad(p *int64) int64   { return atomic.LoadInt64(p) }
func atomicStore(p *int64, v int64) { atomic.StoreInt64(p, v) }
