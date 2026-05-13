package main

// upstream_transport_contract_test.go — P5.2 / S6 contract tests
// pinning the post-startup state of upstreamTransport across the
// pool / mTLS / OCSP composition.
//
// These tests assert the CURRENT correct startup ordering before
// P5.3 changes the ownership model. The three contracts pinned:
//
//   1. Full startup composition: configure pool first, then apply
//      mTLS + OCSP. The resulting upstreamTransport carries Proxy
//      + TLSClientConfig with mTLS cert + OCSP callbacks + correct
//      MinVersion. This is the canonical operational state.
//   2. Within-loader composition: a single loadMTLSAndOCSP call
//      with both mTLS and OCSP configured produces a transport
//      whose TLSClientConfig has BOTH the client certificate AND
//      the OCSP verification callbacks (VerifyPeerCertificate +
//      VerifyConnection).
//   3. Preserve-existing + coexistence: when upstreamTransport
//      already has a TLSClientConfig (e.g. a pre-set trust
//      anchor / ServerName), applying mTLS + OCSP MUST reuse the
//      same pointer and not clobber pre-existing fields, while
//      adding the mTLS certificate and the OCSP callbacks on top.
//
// Test isolation reuses the existing helpers from
// mtls_ocsp_startup_test.go (resetMTLSOCSPGlobals, writeTestClientCert,
// ensureMTLSOCSPTestLogger) plus a local helper for the
// upstreamTransport.Proxy + upstreamPool snapshot, mirroring the
// pattern in upstream_test.go:TestApplyUpstreamProxy_SetsTransportProxy.
//
// No production code change. No network usage. No goroutines.

import (
	"crypto/tls"
	"testing"
	"time"
)

// snapshotUpstreamProxyAndPool saves the current upstreamTransport.Proxy
// closure and the current upstreamPool entries, restoring both on
// t.Cleanup so tests are safe under -shuffle=on / -count=2 even when
// other tests in the same binary also configure the pool.
func snapshotUpstreamProxyAndPool(t *testing.T) {
	t.Helper()
	origProxy := upstreamTransport.Proxy
	// upstreamPool has an internal sync.RWMutex; we cannot snapshot
	// its fields safely, so we restore by replaying Configure with
	// an empty slice on cleanup. This is the same approach the
	// existing TestApplyUpstreamProxy_SetsTransportProxy uses.
	t.Cleanup(func() {
		upstreamTransport.Proxy = origProxy
		upstreamPool.Configure(nil, 0, 0)
	})
}

// TestUpstreamTransport_StartupComposition_PoolThenMTLSOCSP pins the
// canonical full-startup state: pool configured first (writes Proxy),
// then mTLS + OCSP applied (writes TLSClientConfig + callbacks). The
// fields are disjoint, but BOTH must land on the same shared
// *http.Transport.
//
// Discovery §2.1: this is the order enforced today by main.go's call
// sequence (step 27 → step 29). If a future refactor reorders the
// calls or extracts the writes into separate transport instances,
// this test fails loudly. Pre-extraction contract pin.
func TestUpstreamTransport_StartupComposition_PoolThenMTLSOCSP(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	resetMTLSOCSPGlobals(t)
	snapshotUpstreamProxyAndPool(t)

	// Bootstrap: start from a clean transport (no pre-existing TLS
	// config) so the assertions reflect what a fresh process sees.
	upstreamTransport.TLSClientConfig = nil

	// Step 27 equivalent: configure the pool and install the proxy
	// closure on upstreamTransport.Proxy.
	upstreamPool.Configure(
		[]UpstreamEntry{{URL: "http://contract.test.invalid:3128"}},
		5,
		time.Minute,
	)
	applyUpstreamProxy()

	// Step 29 equivalent: apply mTLS + OCSP.
	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
		OCSPCheck:      true,
	})

	// Post-condition: every field the discovery report identified
	// must be present.
	if upstreamTransport.Proxy == nil {
		t.Error("upstreamTransport.Proxy is nil; applyUpstreamProxy did not install the closure")
	}
	tlsCfg := upstreamTransport.TLSClientConfig
	if tlsCfg == nil {
		t.Fatal("upstreamTransport.TLSClientConfig is nil; loadMTLSAndOCSP did not initialise it")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("TLSClientConfig.Certificates: got %d; want 1 (mTLS client cert)", len(tlsCfg.Certificates))
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("TLSClientConfig.VerifyPeerCertificate is nil; OCSP verifier was not wired")
	}
	if tlsCfg.VerifyConnection == nil {
		t.Error("TLSClientConfig.VerifyConnection is nil; OCSP session-resumption verifier was not wired")
	}
	// MinVersion is set to TLS12 by the mTLS branch when bootstrapping
	// from nil. The OCSP branch does not downgrade it.
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLSClientConfig.MinVersion: got %#x; want TLS1.2 (%#x)", tlsCfg.MinVersion, tls.VersionTLS12)
	}
	if !globalOCSP.Enabled() {
		t.Error("globalOCSP.Enabled() is false after loadMTLSAndOCSP with OCSPCheck=true")
	}
}

// TestUpstreamTransport_PostStartup_HasBothMTLSAndOCSP pins the
// within-loader composition: a single loadMTLSAndOCSP call with both
// mTLS and OCSP configured produces a TLSClientConfig whose
// Certificates slice carries the client cert AND whose
// VerifyPeerCertificate + VerifyConnection callbacks are set.
//
// Discovery §8: existing tests cover mTLS-only and OCSP-only paths
// but not their coexistence. This test fills that gap and is the
// canonical "happy path" contract pin.
func TestUpstreamTransport_PostStartup_HasBothMTLSAndOCSP(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	resetMTLSOCSPGlobals(t)

	upstreamTransport.TLSClientConfig = nil

	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
		OCSPCheck:      true,
	})

	tlsCfg := upstreamTransport.TLSClientConfig
	if tlsCfg == nil {
		t.Fatal("TLSClientConfig is nil after loadMTLSAndOCSP with both mTLS + OCSP")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("mTLS cert missing: Certificates len = %d, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("OCSP VerifyPeerCertificate missing")
	}
	if tlsCfg.VerifyConnection == nil {
		t.Error("OCSP VerifyConnection missing")
	}
	if !globalOCSP.Enabled() {
		t.Error("globalOCSP.Enabled() should be true")
	}
}

// TestUpstreamTransport_PreservesExistingTLSConfig_WithMTLSAndOCSP
// extends the existing TestLoadMTLSAndOCSP_PreservesExistingTLSConfig
// (which checked only mTLS preservation of ServerName). This variant
// asserts the THREE-way coexistence: pre-existing pointer + pre-set
// fields stay intact, AND the mTLS Certificate is added, AND the
// OCSP callbacks are added — all on the same *tls.Config instance.
//
// This is the contract that makes "apply OCSP at runtime after mTLS
// was set at startup" safe today (ui_security.go:1153). If a future
// refactor introduces a new TLSClientConfig instance during OCSP
// configuration, this test fails.
func TestUpstreamTransport_PreservesExistingTLSConfig_WithMTLSAndOCSP(t *testing.T) {
	ensureMTLSOCSPTestLogger(t)
	resetMTLSOCSPGlobals(t)

	// Operator pre-set their own TLS config — e.g. a corporate
	// ServerName pin and a stricter MinVersion than mTLS bootstrap
	// would choose.
	existing := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "p5-2-preset.contract.invalid",
	}
	upstreamTransport.TLSClientConfig = existing

	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
		OCSPCheck:      true,
	})

	tlsCfg := upstreamTransport.TLSClientConfig
	if tlsCfg != existing {
		t.Fatal("TLSClientConfig pointer was replaced; loadMTLSAndOCSP must reuse the existing pointer")
	}
	// Pre-existing fields preserved.
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion clobbered: got %#x; want pre-set TLS1.3 (%#x)", tlsCfg.MinVersion, tls.VersionTLS13)
	}
	if tlsCfg.ServerName != "p5-2-preset.contract.invalid" {
		t.Errorf("ServerName clobbered: got %q", tlsCfg.ServerName)
	}
	// mTLS added.
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("mTLS not added: Certificates len = %d, want 1", len(tlsCfg.Certificates))
	}
	// OCSP added on top.
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("OCSP VerifyPeerCertificate was not added to existing TLSClientConfig")
	}
	if tlsCfg.VerifyConnection == nil {
		t.Error("OCSP VerifyConnection was not added to existing TLSClientConfig")
	}
	if !globalOCSP.Enabled() {
		t.Error("globalOCSP.Enabled() should be true")
	}
}
