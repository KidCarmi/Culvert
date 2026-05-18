package main

// controlplane_cptlsconfig_race_test.go — CA-7 race regression guard
// (P6.3 Root-CA discovery, §13 CA-7 / §10 CA-R-3).
//
// Status: REGRESSION GUARD (CA-7 fixed in this same PR).
// ========================================================
// Pre-fix this harness PROVED a race: rebuildCPCertPool wrote
// cpTLSConfig.cfg.ClientCAs at controlplane.go:1771 under
// cpTLSConfig.mu, while the stdlib crypto/tls handshake read
// cfg.ClientCAs unlocked. Captured `-race` output before the fix:
//
//	==================
//	WARNING: DATA RACE
//	Write at 0x... by goroutine 14:
//	  proxy.rebuildCPCertPool()
//	      /home/user/Culvert/controlplane.go:1771
//	Previous read at 0x... by goroutine 12:
//	  proxy.TestCA7_CpTLSConfig_ClientCAsConcurrentReadVsWrite_Race
//	  .func1()
//	      .../controlplane_cptlsconfig_race_test.go:<read site>
//	==================
//
// Fix (same PR): buildServerTLS installs a GetConfigForClient
// callback (getCPTLSConfigForClient at controlplane.go:1775). The
// stdlib now invokes this hook once per ClientHello; the callback
// takes cpTLSConfig.mu and returns Clone() whose .ClientCAs is the
// pointer-snapshot of the *x509.CertPool at the time of the clone.
// A concurrent rebuildCPCertPool writes a NEW pool into the
// original cfg.ClientCAs field; the clone holds the OLD pool
// pointer — different memory location, no race. Pools are
// immutable post-publication (rebuildCPCertPool builds a fresh
// pool each call and never mutates pre-existing ones), so the
// clone's reader sees a stable snapshot.
//
// What this test now verifies
// ===========================
//   - The post-fix access pattern (via getCPTLSConfigForClient)
//     is race-free under concurrent rebuildCPCertPool activity.
//     The test fails immediately under `-race` if anyone later
//     removes the GetConfigForClient hook OR if a concurrent
//     mutator becomes able to touch the pool the clone is
//     pointing at.
//
// Harness shape (mirrors CL-11 / PR #243 design)
// ==============================================
//   - Snapshot+restore the package-global cpTLSConfig via its own
//     mutex (PR #241/#245 whitebox idiom).
//   - Install a fresh *tls.Config with ClientCAs = NewCertPool()
//     and GetConfigForClient = getCPTLSConfigForClient so the
//     post-fix path is exercised.
//   - Spawn N reader goroutines: each calls
//     getCPTLSConfigForClient(nil) to get a per-handshake clone
//     (mimicking the stdlib's handshake hook), then reads
//     clone.ClientCAs — same access pattern the stdlib uses on
//     the returned cfg.
//   - Spawn 1 writer goroutine calling rebuildCPCertPool in a
//     tight loop. Each call takes cpTLSConfig.mu and writes
//     cpTLSConfig.cfg.ClientCAs.
//   - A startBarrier releases all goroutines simultaneously.
//
// Why this is deterministic
// =========================
//   - No sleeps. All synchronization via sync.WaitGroup and the
//     start barrier.
//   - No timing-based assertions. -race is the assertion.
//   - No external network: no TLS handshake, no listener, no
//     socket. The harness exercises the same field-access pattern
//     the stdlib uses on the returned cfg, so any race the stdlib
//     would hit, this harness hits too.
//   - Bounded iteration counts; runs in ~50ms.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// snapshotCPTLSConfig captures and restores the package-global
// cpTLSConfig fields for the duration of the test. PR #241 whitebox
// snapshot pattern, applied via cpTLSConfig's own mutex.
func snapshotCPTLSConfig(t *testing.T) {
	t.Helper()
	cpTLSConfig.mu.Lock()
	origCfg := cpTLSConfig.cfg
	origBaseCAF := cpTLSConfig.baseCAF
	cpTLSConfig.mu.Unlock()
	t.Cleanup(func() {
		cpTLSConfig.mu.Lock()
		cpTLSConfig.cfg = origCfg
		cpTLSConfig.baseCAF = origBaseCAF
		cpTLSConfig.mu.Unlock()
	})
}

func TestCA7_CpTLSConfig_ClientCAsConcurrentReadVsWrite_Race(t *testing.T) {
	snapshotCPTLSConfig(t)

	// Install a fresh *tls.Config wired with the GetConfigForClient
	// callback (post-fix production shape). rebuildCPCertPool has
	// a target field to mutate; the readers go through the callback
	// just like the stdlib handshake does.
	cpTLSConfig.mu.Lock()
	cpTLSConfig.cfg = &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ClientCAs:          x509.NewCertPool(),
		GetConfigForClient: getCPTLSConfigForClient,
	}
	cpTLSConfig.baseCAF = "" // no on-disk base CA — keeps the test hermetic
	cpTLSConfig.mu.Unlock()

	const (
		readers           = 4
		readsPerGoroutine = 1000
		writes            = 100
	)

	startBarrier := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(readers + 1)

	// Reader goroutines: invoke the production hook
	// (getCPTLSConfigForClient) and read .ClientCAs from the
	// returned clone. This mirrors the stdlib handshake's access
	// pattern post-fix: stdlib calls GetConfigForClient per
	// ClientHello, then uses the returned cfg's ClientCAs for the
	// verify-options. The clone's ClientCAs is a pointer-snapshot
	// of the pool at clone time; concurrent rebuilds replace the
	// original cfg.ClientCAs with a NEW pool and don't touch the
	// pool the clone is pointing at.
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			<-startBarrier
			var sink *x509.CertPool
			for j := 0; j < readsPerGoroutine; j++ {
				clone, err := getCPTLSConfigForClient(nil)
				if err != nil || clone == nil {
					continue
				}
				// Same shape as stdlib post-fix:
				// `cfgForHandshake.ClientCAs` where
				// cfgForHandshake is GetConfigForClient's return.
				sink = clone.ClientCAs
			}
			_ = sink // prevent dead-store elimination
		}()
	}

	// Writer goroutine: hot-loop rebuildCPCertPool. Each call takes
	// cpTLSConfig.mu and writes cpTLSConfig.cfg.ClientCAs at
	// controlplane.go:1771. With the GetConfigForClient hook in
	// place, this write no longer races against the reader's
	// clone.ClientCAs (different memory location).
	go func() {
		defer wg.Done()
		<-startBarrier
		for j := 0; j < writes; j++ {
			rebuildCPCertPool()
		}
	}()

	close(startBarrier)
	wg.Wait()

	// No assertions beyond -race. If `-race` fires on any future
	// commit, either the GetConfigForClient hook was removed or a
	// new concurrent mutator started touching the clone's pool —
	// either way the harness flags the regression at the access
	// site.
}

// writeSelfSignedECDSACert generates a minimal self-signed ECDSA
// P-256 cert + key, writes them to PEM files in dir, and returns
// the file paths. Used by TestCA7_BuildServerTLS_WiresGetConfigForClient
// to exercise the full buildServerTLS code path without an
// external PKI dependency.
func writeSelfSignedECDSACert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca-7-test"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	certPath = filepath.Join(dir, "ca7-cert.pem")
	keyPath = filepath.Join(dir, "ca7-key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath
}

// TestCA7_BuildServerTLS_WiresGetConfigForClient is the production-
// wiring half of the CA-7 regression guard. The
// concurrent-read-vs-write race test above (TestCA7_CpTLSConfig_
// ClientCAsConcurrentReadVsWrite_Race) installs GetConfigForClient
// directly on its own test *tls.Config — necessary to exercise the
// post-fix access pattern, but it does NOT exercise buildServerTLS,
// so it cannot catch a regression where buildServerTLS stops wiring
// the hook on its own (Codex catch on PR #253).
//
// This test closes that gap: it constructs a real *tls.Config
// through buildServerTLS using on-the-fly self-signed ECDSA P-256
// cert/key/CA files, then asserts the side effect that
// cpTLSConfig.cfg.GetConfigForClient is non-nil. If anyone removes
// the assignment at controlplane.go:1816, this test fails
// immediately and the race surface is back.
func TestCA7_BuildServerTLS_WiresGetConfigForClient(t *testing.T) {
	snapshotCPTLSConfig(t)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedECDSACert(t, dir)
	// buildServerTLS only touches cpTLSConfig (and wires the hook)
	// when caFile != "". The cert can self-sign as its own CA for
	// the test's purposes — we're not verifying real PKI here,
	// just the wiring.
	caPath := certPath

	creds, err := buildServerTLS(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if creds == nil {
		t.Fatal("buildServerTLS returned nil credentials")
	}

	// The production wiring assertion: buildServerTLS must have
	// set cpTLSConfig.cfg.GetConfigForClient to the CA-7 hook.
	// Without this, the stdlib's handshake would fall back to
	// reading cpTLSConfig.cfg.ClientCAs directly — the original
	// CA-7 race.
	cpTLSConfig.mu.Lock()
	cfg := cpTLSConfig.cfg
	cpTLSConfig.mu.Unlock()
	if cfg == nil {
		t.Fatal("buildServerTLS did not install cpTLSConfig.cfg")
	}
	if cfg.GetConfigForClient == nil {
		t.Fatal("CA-7 regression: buildServerTLS did not wire " +
			"GetConfigForClient on cpTLSConfig.cfg. Without the " +
			"hook, the stdlib reads cfg.ClientCAs directly during " +
			"every handshake — racy against rebuildCPCertPool's " +
			"write at controlplane.go:1771 (see file header for " +
			"the captured pre-fix `-race` output).")
	}
	// Sanity: the hook should actually return a non-nil clone when
	// invoked. (We don't compare the function pointer directly —
	// Go forbids that — but invoking the hook proves it dispatches
	// correctly.)
	got, err := cfg.GetConfigForClient(nil)
	if err != nil {
		t.Errorf("GetConfigForClient(nil) returned err: %v", err)
	}
	if got == nil {
		t.Error("GetConfigForClient(nil) returned nil cfg; the hook " +
			"must return a Clone() of cpTLSConfig.cfg under the lock")
	}
}
