package main

// dp_cert_renewal_test.go — CHAOS-12 regression tests: a renewed DP cert must
// actually reach the wire (post-renewal reconnect re-reads TLS material from
// disk), the renewal loop must check immediately at start (not 6h in), and a
// failing renewal on an expiring cert must fire a latched cert_expiry alert.

import (
	"bytes"
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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// writeDPCertKeyPair writes a self-signed cert + matching key (+ the cert
// again as the CA file) into dir, expiring at notAfter. The trio satisfies
// buildClientTLS, so a DataPlaneClient can be constructed over it (gRPC
// dials lazily — no listener is needed).
func writeDPCertKeyPair(t *testing.T, dir string, notAfter time.Time) (certPath, keyPath, caPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dp-renewal-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, "dp-node.crt")
	keyPath = filepath.Join(dir, "dp-node.key")
	caPath = filepath.Join(dir, "cluster-ca.crt")
	for _, f := range []struct {
		path string
		data []byte
	}{{certPath, certPEM}, {keyPath, keyPEM}, {caPath, certPEM}} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			t.Fatalf("write %s: %v", f.path, err)
		}
	}
	return certPath, keyPath, caPath
}

// alertCapture collects alerts delivered through the startupAlertFire seam.
// Mutex-guarded: the renewal loop fires alerts from its own goroutine.
type alertCapture struct {
	mu     sync.Mutex
	alerts []queuedStartupAlert
}

func (a *alertCapture) snapshot() []queuedStartupAlert {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]queuedStartupAlert(nil), a.alerts...)
}

// captureDPCertAlerts routes deferred startup alerts straight into a capture
// (flushed passthrough mode) and isolates the CHAOS-12 escalation latch.
func captureDPCertAlerts(t *testing.T) *alertCapture {
	t.Helper()
	startupAlertMu.Lock()
	oldQueue, oldFlushed := startupAlertQueue, startupAlertFlushed
	startupAlertQueue, startupAlertFlushed = nil, true
	startupAlertMu.Unlock()
	oldFire := startupAlertFire
	captured := &alertCapture{}
	startupAlertFire = func(event string, p AlertPayload) {
		captured.mu.Lock()
		captured.alerts = append(captured.alerts, queuedStartupAlert{event, p})
		captured.mu.Unlock()
	}
	dpCertExpiryAlert.mu.Lock()
	oldLevel := dpCertExpiryAlert.level
	dpCertExpiryAlert.level = 0
	dpCertExpiryAlert.mu.Unlock()
	t.Cleanup(func() {
		startupAlertMu.Lock()
		startupAlertQueue, startupAlertFlushed = oldQueue, oldFlushed
		startupAlertMu.Unlock()
		startupAlertFire = oldFire
		dpCertExpiryAlert.mu.Lock()
		dpCertExpiryAlert.level = oldLevel
		dpCertExpiryAlert.mu.Unlock()
	})
	return captured
}

func dpClientConn(c *DataPlaneClient) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

// TestReconnectActive_RereadsTLSAndKeepsConnOnFailure pins both halves of the
// reconnect contract: success swaps in a NEW connection built from the
// CURRENT on-disk material, and a failure (unreadable/garbage TLS files)
// keeps the existing connection — reconnect can only improve on the
// pre-renewal state, never drop the CP link.
func TestReconnectActive_RereadsTLSAndKeepsConnOnFailure(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caPath := writeDPCertKeyPair(t, dir, time.Now().Add(365*24*time.Hour))

	c, err := NewDataPlaneClient("test-node", "127.0.0.1:1", certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewDataPlaneClient: %v", err)
	}
	orig := dpClientConn(c)
	if orig == nil {
		t.Fatal("expected an initial connection")
	}

	if err := c.reconnectActive(); err != nil {
		t.Fatalf("reconnectActive with valid on-disk material: %v", err)
	}
	swapped := dpClientConn(c)
	if swapped == orig {
		t.Fatal("reconnectActive did not swap the connection — renewed TLS material would never be presented")
	}

	// Failure path: corrupt the on-disk cert; the connection must survive.
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("corrupt cert: %v", err)
	}
	if err := c.reconnectActive(); err == nil {
		t.Fatal("expected reconnectActive to fail on unreadable TLS material")
	}
	if dpClientConn(c) != swapped {
		t.Fatal("failed reconnect must keep the existing connection (fail-safe), not drop it")
	}
}

// TestReconnectActive_NoopOnStubClient — test-constructed clients (callForTest
// seam, no addresses) must not panic or dial.
func TestReconnectActive_NoopOnStubClient(t *testing.T) {
	c := &DataPlaneClient{}
	if err := c.reconnectActive(); err != nil {
		t.Fatalf("stub client reconnect should be a no-op, got: %v", err)
	}
}

// TestRenewDPCert_PersistsAndReconnects is the CHAOS-12 end-to-end: a
// successful RenewCert RPC must (a) persist cert/key/CA, (b) swap the gRPC
// connection so the renewed identity is presented without a process restart,
// and (c) clear the expiry-alert latch.
func TestRenewDPCert_PersistsAndReconnects(t *testing.T) {
	restore := resetDPLastSeenEpochForTest()
	defer restore()
	captured := captureDPCertAlerts(t)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeDPCertKeyPair(t, dir, time.Now().Add(10*24*time.Hour))

	c, err := NewDataPlaneClient("test-node", "127.0.0.1:1", certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("NewDataPlaneClient: %v", err)
	}
	orig := dpClientConn(c)

	// Pre-latch an alert level, as if earlier renewal attempts failed — the
	// successful renewal below must reset it.
	dpCertExpiryAlert.mu.Lock()
	dpCertExpiryAlert.level = 2
	dpCertExpiryAlert.mu.Unlock()

	// Fake CP: sign the CSR from the request with a fresh CA so the renewed
	// cert on disk genuinely pairs with the renewed key (buildClientTLS must
	// be able to load it during the post-renewal reconnect).
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "renewal-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	c.callForTest = func(_ context.Context, method string, req json.RawMessage) (json.RawMessage, error) {
		if method != methodRenewCert {
			t.Fatalf("unexpected RPC method %q", method)
		}
		var r struct {
			NodeID string `json:"node_id"`
			CSR    string `json:"csr"`
		}
		if err := json.Unmarshal(req, &r); err != nil {
			t.Fatalf("parse renewal request: %v", err)
		}
		block, _ := pem.Decode([]byte(r.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse CSR: %v", err)
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      csr.Subject,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			t.Fatalf("sign renewal cert: %v", err)
		}
		resp, _ := json.Marshal(map[string]any{
			"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
			"ca_pem":   string(caPEM),
			"epoch":    0,
		})
		return resp, nil
	}

	if err := renewDPCert(context.Background(), c, "test-node", certPath, keyPath, caPath, "test"); err != nil {
		t.Fatalf("renewDPCert: %v", err)
	}

	// (a) persisted: on-disk cert now expires ~365d out, CA replaced.
	days, needs := certNeedsRenewal(certPath)
	if needs || days < 300 {
		t.Fatalf("renewed cert on disk expires in %d days (needsRenewal=%v) — expected ~365", days, needs)
	}
	gotCA, _ := os.ReadFile(caPath)
	if !bytes.Equal(gotCA, caPEM) {
		t.Fatal("renewed CA was not persisted")
	}

	// (b) the connection was swapped — the renewed identity is live.
	if dpClientConn(c) == orig {
		t.Fatal("renewDPCert did not reconnect — renewed cert stays inert until process restart (CHAOS-12)")
	}

	// (c) the alert latch was reset.
	dpCertExpiryAlert.mu.Lock()
	level := dpCertExpiryAlert.level
	dpCertExpiryAlert.mu.Unlock()
	if level != 0 {
		t.Fatalf("expiry-alert latch = %d after successful renewal, want 0", level)
	}
	if got := captured.snapshot(); len(got) != 0 {
		t.Fatalf("no alerts expected on the success path, got %d", len(got))
	}
}

// TestAlertDPCertRenewalFailure_LatchesPerEscalation — one alert per
// escalation level (renewal window → final week → expired), never one per
// 6h tick; reset re-arms; fresh certs never alert.
func TestAlertDPCertRenewalFailure_LatchesPerEscalation(t *testing.T) {
	captured := captureDPCertAlerts(t)
	rpcErr := errors.New("RenewCert RPC: connection refused")
	dir := t.TempDir()

	fresh := writeTempCert(t, dir, time.Now().Add(-time.Hour), time.Now().Add(300*24*time.Hour))
	alertDPCertRenewalFailure("node-a", fresh, rpcErr)
	if got := captured.snapshot(); len(got) != 0 {
		t.Fatalf("fresh cert must not alert, got %d", len(got))
	}

	warnDir := t.TempDir()
	warn := writeTempCert(t, warnDir, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	alertDPCertRenewalFailure("node-a", warn, rpcErr)
	alertDPCertRenewalFailure("node-a", warn, rpcErr) // same level: latched
	got := captured.snapshot()
	if len(got) != 1 {
		t.Fatalf("renewal-window level should alert exactly once, got %d", len(got))
	}
	if got[0].event != "cert_expiry" || got[0].payload.Host != "node-a" {
		t.Fatalf("unexpected alert: %+v", got[0])
	}

	critDir := t.TempDir()
	crit := writeTempCert(t, critDir, time.Now().Add(-time.Hour), time.Now().Add(3*24*time.Hour))
	alertDPCertRenewalFailure("node-a", crit, rpcErr)
	alertDPCertRenewalFailure("node-a", crit, rpcErr)
	if got := captured.snapshot(); len(got) != 2 {
		t.Fatalf("final-week escalation should add exactly one alert, got %d total", len(got))
	}

	expDir := t.TempDir()
	expired := writeTempCert(t, expDir, time.Now().Add(-96*time.Hour), time.Now().Add(-48*time.Hour))
	alertDPCertRenewalFailure("node-a", expired, rpcErr)
	alertDPCertRenewalFailure("node-a", expired, rpcErr)
	if got := captured.snapshot(); len(got) != 3 {
		t.Fatalf("expired escalation should add exactly one alert, got %d total", len(got))
	}

	// Success resets the latch; the next failure alerts again.
	resetDPCertExpiryAlert()
	alertDPCertRenewalFailure("node-a", warn, rpcErr)
	if got := captured.snapshot(); len(got) != 4 {
		t.Fatalf("latch must re-arm after reset, got %d total", len(got))
	}
}

// TestDPCertRenewalLoop_ChecksImmediatelyAtStart — a node that boots inside
// its renewal window must attempt renewal right away, not 6 hours later
// (a node powered off past the window would otherwise idle toward expiry).
func TestDPCertRenewalLoop_ChecksImmediatelyAtStart(t *testing.T) {
	captured := captureDPCertAlerts(t)
	dir := t.TempDir()
	certPath, keyPath, caPath := writeDPCertKeyPair(t, dir, time.Now().Add(5*24*time.Hour))

	called := make(chan string, 1)
	c := &DataPlaneClient{
		callForTest: func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
			select {
			case called <- method:
			default:
			}
			return nil, errors.New("CP unreachable")
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

	select {
	case method := <-called:
		if method != methodRenewCert {
			t.Fatalf("unexpected RPC %q at loop start", method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop did not check cert expiry at start — first check would wait 6h (CHAOS-12)")
	}

	// The failed immediate check on a 5-day cert must also raise the latched
	// cert_expiry alert. Waiting for it here also quiesces the loop goroutine
	// (its next action is 6h away) before the deferred cancel/join.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := captured.snapshot(); len(got) == 1 {
			if got[0].event != "cert_expiry" {
				t.Fatalf("unexpected alert event %q", got[0].event)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed immediate renewal on an expiring cert did not fire the cert_expiry alert")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
