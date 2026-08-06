package main

// dp_cert_rotation_retry_test.go — CHAOS-28 regression pins: caRotationNotify
// fires exactly once per CA fingerprint change, so a failed rotation-triggered
// cert renewal used to get no second chance — the node coasted on the dual-CA
// overlap until the 30-day expiry window (and bricked early if the CP retired
// the old CA first). The renewal loop must now retry a failed rotation renewal
// with bounded backoff until one attempt succeeds, then stop.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

func TestNextRotationRetryDelay_BoundedDoubling(t *testing.T) {
	cases := []struct {
		cur, want time.Duration
	}{
		{0, dpRotationRetryInitial},                  // first retry
		{-time.Second, dpRotationRetryInitial},       // defensive
		{dpRotationRetryInitial, 2 * time.Minute},    // doubles
		{2 * time.Minute, 4 * time.Minute},           // keeps doubling
		{31 * time.Minute, dpRotationRetryMax},       // 62m clamps to 1h
		{dpRotationRetryMax, dpRotationRetryMax},     // stays at cap
		{2 * dpRotationRetryMax, dpRotationRetryMax}, // defensive clamp
	}
	for _, tc := range cases {
		if got := nextRotationRetryDelay(tc.cur); got != tc.want {
			t.Errorf("nextRotationRetryDelay(%s) = %s, want %s", tc.cur, got, tc.want)
		}
	}
}

// newFakeRenewSigner returns a handler that signs the CSR from a RenewCert
// request with a fresh in-memory CA (365-day leaf), mirroring the fake CP in
// TestRenewDPCert_PersistsAndReconnects.
func newFakeRenewSigner(t *testing.T) func(req json.RawMessage) (json.RawMessage, error) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "rotation-retry-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	return func(req json.RawMessage) (json.RawMessage, error) {
		var r struct {
			NodeID string `json:"node_id"`
			CSR    string `json:"csr"`
		}
		if err := json.Unmarshal(req, &r); err != nil {
			t.Errorf("parse renewal request: %v", err)
			return nil, err
		}
		block, _ := pem.Decode([]byte(r.CSR))
		if block == nil {
			err := errors.New("CSR: no PEM block found")
			t.Errorf("parse CSR: %v", err)
			return nil, err
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Errorf("parse CSR: %v", err)
			return nil, err
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      csr.Subject,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			t.Errorf("sign renewal cert: %v", err)
			return nil, err
		}
		resp, _ := json.Marshal(map[string]any{
			"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
			"ca_pem":   string(caPEM),
			"epoch":    0,
		})
		return resp, nil
	}
}

// TestDPCertRenewalLoop_RotationRenewalRetriesUntilSuccess is the CHAOS-28
// end-to-end pin: the CP signals one CA rotation, the first two RenewCert
// RPCs fail (CP briefly unreachable — the common case right after a rotation),
// and the loop must keep retrying until the third succeeds, persist the
// renewed cert, then go quiet. Pre-fix, exactly one RPC was ever attempted
// and the cert on disk stayed stale.
func TestDPCertRenewalLoop_RotationRenewalRetriesUntilSuccess(t *testing.T) {
	captured := captureDPCertAlerts(t)
	restoreEpoch := resetDPLastSeenEpochForTest()
	defer restoreEpoch()

	// Shrink the backoff ladder so the retries land in test time. Mutated
	// before the loop goroutine starts and restored after it is joined.
	origInit, origMax := dpRotationRetryInitial, dpRotationRetryMax
	dpRotationRetryInitial, dpRotationRetryMax = 5*time.Millisecond, 20*time.Millisecond
	defer func() { dpRotationRetryInitial, dpRotationRetryMax = origInit, origMax }()

	dir := t.TempDir()
	// Fresh cert (300 days out): outside the 30-day window, so the loop's
	// immediate check and ticker path never issue an RPC — every observed
	// RenewCert call is rotation-driven.
	certPath, keyPath, caPath := writeDPCertKeyPair(t, dir, time.Now().Add(300*24*time.Hour))

	sign := newFakeRenewSigner(t)
	var calls atomic.Int32
	c := &DataPlaneClient{
		callForTest: func(_ context.Context, method string, req json.RawMessage) (json.RawMessage, error) {
			if method != methodRenewCert {
				err := errors.New("unexpected RPC method " + method)
				t.Error(err)
				return nil, err
			}
			if calls.Add(1) <= 2 {
				return nil, errors.New("CP unreachable")
			}
			return sign(req)
		},
	}

	// Drain any stale CA-rotation signal a previous test may have left in
	// the buffered global channel — the loop under test listens on it.
	select {
	case <-caRotationNotify:
	default:
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		dpCertRenewalLoop(ctx, c, "test-node", certPath, keyPath, caPath)
	}()
	defer func() {
		cancel()
		<-done // join before t.Cleanup restores the alert seam
	}()

	// One rotation event — exactly what applySnapshotClusterRuntime sends.
	caRotationNotify <- struct{}{}

	// The loop must retry past the two failures and persist the renewed cert.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if days, _ := certNeedsRenewal(certPath); days > 330 {
			break // renewed (~365d) — the pre-fix loop never gets here
		}
		if time.Now().After(deadline) {
			t.Fatalf("rotation renewal never succeeded after failures: %d RPC attempts, cert not renewed (CHAOS-28: failed rotation renewal is not retried)", calls.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected exactly 3 RenewCert attempts (1 initial + 2 retries), got %d", got)
	}

	// After success the retry ladder must disarm: no further RPCs across
	// many multiples of the (shrunken) max backoff.
	time.Sleep(10 * dpRotationRetryMax)
	if got := calls.Load(); got != 3 {
		t.Fatalf("retry kept firing after a successful renewal: %d RPC attempts, want 3", got)
	}

	// Fresh cert ⇒ the documented posture is log-only: no cert_expiry alert
	// (there is no expiry clock running against a 300-day cert).
	if got := captured.snapshot(); len(got) != 0 {
		t.Fatalf("rotation retries on a fresh cert must stay log-only, got %d alert(s): %+v", len(got), got)
	}
}
