package main

// ha_reachability_test.go — PR-2 (A3/A8) reachability model, hardened after the
// adversarial panel. A standby may automatically promote ONLY on positive,
// attributed evidence the leader is unreachable. gRPC status codes cannot supply
// that (Unavailable collapses leader-down with TLS/cert/DNS faults; Deadline is
// slow-vs-dead), so every non-answering code is Ambiguous and a MODE-AWARE policy
// decides: legacy/unfenced HOLDS (fail-safe), fenced advances-as-candidate and the
// lease is the final authority. Local TLS-material faults are held via preflight.
// Owner decisions: ADR-0012 §6.2 #1–#5.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// legacyStandby builds an auto-failover-enabled, NON-lease standby with a working
// promote context, so a genuine threshold crossing WOULD promote — making
// "did not promote" assertions meaningful rather than vacuous.
func legacyStandby() *HAState {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.autoFailover = true
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{onPromote: func() error { return nil }, set: true}
	h.mu.Unlock()
	return h
}

// stubPreflight overrides the local-TLS preflight for a test and restores it.
func stubPreflight(t *testing.T, fn func(certFile, keyFile, caFile string) error) {
	t.Helper()
	orig := preflightLocalTLS
	preflightLocalTLS = fn
	t.Cleanup(func() { preflightLocalTLS = orig })
}

// --- Classifier: no gRPC code yields proven-unreachable. ---

func TestClassify_RemoteRejectedCodesAreReachable(t *testing.T) {
	for _, code := range []codes.Code{
		codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument,
		codes.FailedPrecondition, codes.AlreadyExists, codes.NotFound,
		codes.OutOfRange, codes.Unimplemented, codes.ResourceExhausted,
	} {
		if got := classifyLeaderReachability(status.Error(code, "rejected")); got != outcomeRemoteRejected {
			t.Errorf("%s classified %v, want outcomeRemoteRejected (leader answered)", code, got)
		}
	}
}

func TestClassify_AmbiguousCodesNeverProveUnreachable(t *testing.T) {
	// Unavailable (leader-down OR TLS/cert/DNS), DeadlineExceeded (slow-vs-dead),
	// and server-ambiguous codes must all be Ambiguous — never proven-unreachable.
	for _, code := range []codes.Code{
		codes.Unavailable, codes.DeadlineExceeded, codes.Unknown, codes.Internal,
		codes.Canceled, codes.DataLoss, codes.Aborted,
	} {
		got := classifyLeaderReachability(status.Error(code, "x"))
		if got != outcomeAmbiguous {
			t.Errorf("%s classified %v, want outcomeAmbiguous", code, got)
		}
		if got == outcomeLeaderUnreachableProven {
			t.Errorf("%s must never be proven-unreachable from a status code alone", code)
		}
	}
}

// --- Legacy/unfenced: ambiguous, timeouts, TLS, and local faults never promote. ---

func TestLegacy_AmbiguousHoldsStreakNeverPromotes(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), failCount: haStandbyMaxFail - 1}
	if s.handleSyncResult(false, outcomeAmbiguous) {
		t.Fatal("legacy ambiguous outcome promoted")
	}
	if s.failCount != haStandbyMaxFail-1 {
		t.Fatalf("legacy ambiguous moved the streak: failCount=%d, want %d (held)", s.failCount, haStandbyMaxFail-1)
	}
	if s.h.IsLeader() {
		t.Fatal("legacy ambiguous promoted the standby")
	}
	if !s.ambiguousWarned {
		t.Fatal("legacy ambiguous was not made operator-visible")
	}
}

func TestLegacy_DeadlineExceededIsAmbiguousAndHolds(t *testing.T) {
	// DeadlineExceeded classifies Ambiguous; in legacy mode it must HOLD.
	if got := classifyLeaderReachability(status.Error(codes.DeadlineExceeded, "timeout")); got != outcomeAmbiguous {
		t.Fatalf("DeadlineExceeded classified %v, want outcomeAmbiguous", got)
	}
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), failCount: haStandbyMaxFail - 1}
	out := classifyLeaderReachability(status.Error(codes.DeadlineExceeded, "timeout"))
	if s.handleSyncResult(false, out) || s.failCount != haStandbyMaxFail-1 || s.h.IsLeader() {
		t.Fatalf("legacy DeadlineExceeded must hold+not promote: failCount=%d leader=%v", s.failCount, s.h.IsLeader())
	}
}

func TestLegacy_TLSHandshakeUnavailableHolds(t *testing.T) {
	// A TLS/cert handshake failure surfaces as Unavailable → Ambiguous → hold.
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), failCount: haStandbyMaxFail - 1}
	out := classifyLeaderReachability(status.Error(codes.Unavailable, "authentication handshake failed: tls: unknown authority"))
	if s.handleSyncResult(false, out) || s.failCount != haStandbyMaxFail-1 || s.h.IsLeader() {
		t.Fatalf("legacy TLS-Unavailable must hold+not promote: failCount=%d leader=%v", s.failCount, s.h.IsLeader())
	}
}

func TestLegacy_RepeatedAmbiguousNeverCrossesThreshold(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background()}
	for i := 0; i < haStandbyMaxFail*4; i++ {
		if s.handleSyncResult(false, outcomeAmbiguous) {
			t.Fatalf("legacy promoted on repeated ambiguous at iteration %d", i)
		}
	}
	if s.failCount != 0 || s.h.IsLeader() {
		t.Fatalf("legacy repeated ambiguous accumulated: failCount=%d leader=%v", s.failCount, s.h.IsLeader())
	}
}

// --- Fenced: ambiguous makes a candidate; the LEASE is the final authority. ---

func TestFenced_AmbiguousPromotesOnlyWhenLeaseFree(t *testing.T) {
	tempHADir(t)
	h := freshStandby(halease.NewFake(time.Minute))
	defer h.Stop()
	s := &standbyLoopState{h: h, ctx: context.Background(), leaderAddr: "dead-leader:50051", failCount: haStandbyMaxFail - 1}
	if !s.handleSyncResult(false, outcomeAmbiguous) {
		t.Fatal("fenced ambiguous at threshold with a free lease must promote")
	}
	if !h.IsLeader() {
		t.Fatal("node should be leader after fence-arbitrated promotion")
	}
}

func TestFenced_AmbiguousCannotBypassHeldLease(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-leader"); !granted {
		t.Fatal("seed: leader must hold the lease")
	}
	h := freshStandby(f) // cp-standby; the leader already holds the fence
	defer h.Stop()
	s := &standbyLoopState{h: h, ctx: context.Background(), leaderAddr: "leader:50051", failCount: haStandbyMaxFail - 1}
	if s.handleSyncResult(false, outcomeAmbiguous) {
		t.Fatal("fenced ambiguous promoted while the leader holds the lease — fence bypassed")
	}
	if h.IsLeader() {
		t.Fatal("standby became leader despite a held fence")
	}
}

// --- Local TLS preflight: a local fault holds in BOTH modes. ---

func TestPreflight_FailureHoldsInLegacy(t *testing.T) {
	stubPreflight(t, func(_, _, _ string) error { return errLocalTLSPreflight })
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background(), leaderAddr: "leader:50051", failCount: haStandbyMaxFail - 1}
	if s.tick() {
		t.Fatal("local preflight failure exited the loop (promoted) in legacy mode")
	}
	if s.failCount != haStandbyMaxFail-1 || s.h.IsLeader() {
		t.Fatalf("preflight fault advanced/promoted: failCount=%d leader=%v", s.failCount, s.h.IsLeader())
	}
	if !s.localFaultWarned {
		t.Fatal("preflight fault not operator-visible")
	}
}

func TestPreflight_FailureHoldsInFencedMode(t *testing.T) {
	tempHADir(t)
	stubPreflight(t, func(_, _, _ string) error { return errLocalTLSPreflight })
	h := freshStandby(halease.NewFake(time.Minute))
	defer h.Stop()
	// Even in fenced mode, a LOCAL fault must never advance toward the fence.
	s := &standbyLoopState{h: h, ctx: context.Background(), leaderAddr: "leader:50051", failCount: haStandbyMaxFail - 1}
	for i := 0; i < haStandbyMaxFail*3; i++ {
		if s.tick() {
			t.Fatalf("fenced preflight fault promoted at iteration %d", i)
		}
	}
	if s.failCount != haStandbyMaxFail-1 || s.h.IsLeader() {
		t.Fatalf("fenced preflight fault advanced/promoted: failCount=%d leader=%v", s.failCount, s.h.IsLeader())
	}
}

func TestDefaultPreflight_ExpiredAndValidLocalCert(t *testing.T) {
	dir := t.TempDir()
	// Expired cert → LocalFailure.
	expCert, expKey := filepath.Join(dir, "exp-cert.pem"), filepath.Join(dir, "exp-key.pem")
	writeTestCert(t, expCert, expKey, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err := defaultPreflightLocalTLS(expCert, expKey, ""); err == nil {
		t.Fatal("expired local cert passed preflight")
	}
	// Valid cert → nil.
	okCert, okKey := filepath.Join(dir, "ok-cert.pem"), filepath.Join(dir, "ok-key.pem")
	writeTestCert(t, okCert, okKey, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := defaultPreflightLocalTLS(okCert, okKey, ""); err != nil {
		t.Fatalf("valid local cert failed preflight: %v", err)
	}
	// Empty material (dev/insecure) → nil (nothing to validate).
	if err := defaultPreflightLocalTLS("", "", ""); err != nil {
		t.Fatalf("empty material should pass preflight: %v", err)
	}
}

// --- Reset / recovery / concurrency. ---

func TestRemoteRejectedResetsStreak(t *testing.T) {
	tempHADir(t)
	h := freshStandby(halease.NewFake(time.Minute))
	defer h.Stop()
	s := &standbyLoopState{h: h, ctx: context.Background(), failCount: 2, localFaultWarned: true, ambiguousWarned: true}
	if s.handleSyncResult(false, outcomeRemoteRejected) {
		t.Fatal("remote-rejected (leader alive) exited the loop")
	}
	if s.failCount != 0 || s.localFaultWarned || s.ambiguousWarned {
		t.Fatalf("remote-rejected did not reset+re-arm: failCount=%d local=%v amb=%v", s.failCount, s.localFaultWarned, s.ambiguousWarned)
	}
}

func TestRecoveryAfterFaultResetsLatchesAndStreak(t *testing.T) {
	s := &standbyLoopState{h: legacyStandby(), ctx: context.Background()}
	s.localFaultWarned, s.ambiguousWarned, s.failCount = true, true, 0
	if s.handleSyncResult(true, outcomeLeaderReachable) {
		t.Fatal("successful sync exited the loop")
	}
	if s.failCount != 0 || s.localFaultWarned || s.ambiguousWarned || s.h.IsLeader() {
		t.Fatalf("recovery did not fully re-arm: failCount=%d local=%v amb=%v leader=%v",
			s.failCount, s.localFaultWarned, s.ambiguousWarned, s.h.IsLeader())
	}
}

// C1: a cancelled context (shutdown) must not be classified as a leader fault.
func TestSyncOnce_CancelledCtxDoesNotClassify(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &standbyLoopState{h: legacyStandby(), ctx: ctx, leaderAddr: "leader:50051"}
	s.syncOnce()
	if s.failCount != 0 || s.ambiguousWarned || s.localFaultWarned {
		t.Fatalf("cancelled-ctx syncOnce classified a fault: failCount=%d amb=%v local=%v",
			s.failCount, s.ambiguousWarned, s.localFaultWarned)
	}
}

// writeTestCert writes a self-signed ECDSA cert+key PEM pair with the given
// validity window (used to exercise the preflight expiry check deterministically).
func writeTestCert(t *testing.T, certPath, keyPath string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ha-standby-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
