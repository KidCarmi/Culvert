package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func disarmMTLSDeferredLoadForTest() {
	mtlsDeferredLoad.mu.Lock()
	setMTLSDeferredLoadLocked("", "")
	mtlsDeferredLoad.mu.Unlock()
}

// isolateMTLSRetry gives the test a fresh upstream transport with no TLS
// template, no recorded client-cert status and nothing armed, and returns the
// certificate and key paths (which do not exist yet) plus a place to write a
// valid pair from.
func isolateMTLSRetry(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	dir := t.TempDir()
	return filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
}

// installMTLSTestPair writes a valid pair at the configured paths, the way an
// operator (or a late secret mount) would.
func installMTLSTestPair(t *testing.T, certPath string) {
	t.Helper()
	writeTestClientCert(t, filepath.Dir(certPath))
}

func runMTLSRetryToEnd(t *testing.T, ctx context.Context, delay func(int) time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { runMTLSClientCertLoadRetry(ctx, delay); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop did not finish")
	}
}

func upstreamTemplateCertCount() int {
	upstreamTransportWriteMu.Lock()
	defer upstreamTransportWriteMu.Unlock()
	if upstreamOpTLSCfg == nil {
		return 0
	}
	return len(upstreamOpTLSCfg.Certificates)
}

func mtlsDiagRow(t *testing.T) OperatorContractCheck {
	t.Helper()
	rows := checkUpstreamMTLSClientCert()
	if len(rows) != 1 {
		t.Fatalf("diagnostics rows = %+v, want exactly one", rows)
	}
	return rows[0]
}

// presentedClientCert reports whether an upstream that asks for a client
// certificate receives one from the TLS configuration the proxy currently
// publishes.
func presentedClientCert(t *testing.T) bool {
	t.Helper()
	var got atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.TLS != nil && len(r.TLS.PeerCertificates) > 0)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	// The published transport is read-only: dial with a clone of the TLS
	// configuration the proxy would use, plus this test server's root.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tc := getUpstreamTransport().TLSClientConfig; tc != nil {
		cfg = tc.Clone()
	}
	cfg.RootCAs = pool
	cfg.VerifyPeerCertificate, cfg.VerifyConnection = nil, nil
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upstream request: %v", err)
	}
	_ = resp.Body.Close()
	return got.Load()
}

// The operator-visible reproduction, through the real boot path: startup could
// not load the configured pair, so the node presents no client certificate.
// The files appear and the node presents the certificate with no restart. The
// diagnostics row clears only once it is actually installed, and the automatic
// load is attributed to system.
func TestMTLSClientCertRetry_CompletesAStartupFailureWithoutRestart(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)

	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})
	if h := mtlsClientCertHealth(); !h.configured || h.loaded || h.lastError == "" {
		t.Fatalf("precondition: the startup load must fail and be recorded, got %+v", h)
	}
	if !mtlsClientCertDeferredLoadPending() {
		t.Fatal("the failed startup load armed nothing")
	}
	if presentedClientCert(t) {
		t.Fatal("precondition: no client certificate is presented before the load")
	}
	if row := mtlsDiagRow(t); row.Status != diagWarn || strings.Contains(row.OperatorAction, "then restart Culvert") {
		t.Fatalf("diagnostics before the load = %+v, want a warning whose remedy is not a restart", row)
	}
	before := getUpstreamTransport()

	var attempts atomic.Int32
	runMTLSRetryToEnd(t, context.Background(), func(int) time.Duration {
		// The first attempt meets the missing files; the fix lands before
		// the second.
		if attempts.Add(1) == 2 {
			installMTLSTestPair(t, certPath)
		}
		return 0
	})
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2 (one failure, one success)", got)
	}

	h := mtlsClientCertHealth()
	if !h.loaded || h.lastError != "" || h.notAfter.IsZero() || h.file != certPath {
		t.Fatalf("status after the load = %+v, want loaded with an expiry and no error", h)
	}
	if mtlsClientCertDeferredLoadPending() {
		t.Fatal("the deferred load is still armed after it succeeded")
	}
	if getUpstreamTransport() == before {
		t.Fatal("no new upstream transport was published")
	}
	if upstreamTemplateCertCount() != 1 {
		t.Fatal("the operator TLS template does not carry the certificate")
	}
	if got := getUpstreamTransport().TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want the startup mTLS floor TLS 1.2", got)
	}
	// The business outcome: an upstream that asks for a client certificate
	// now receives one.
	if !presentedClientCert(t) {
		t.Fatal("no client certificate is presented after the automatic load")
	}
	// The test certificate is valid for an hour, so the row that remains is
	// the expiry warning; the failed-load row must be gone.
	for _, row := range checkUpstreamMTLSClientCert() {
		if strings.Contains(row.Message, "failed to load") {
			t.Fatalf("diagnostics still report a failed load after it succeeded: %+v", row)
		}
	}
	e, ok := findAuditByActionObject(t, "upstream_mtls.client_cert.auto_load", certPath)
	if !ok {
		t.Fatal("no system audit entry for the automatic load")
	}
	if e.Actor != "system" {
		t.Fatalf("automatic load attributed to %q, want system", e.Actor)
	}
}

// Unchanged success path: a startup load that succeeds arms nothing, and the
// loop returns at once without waiting or publishing.
func TestMTLSClientCertRetry_SuccessfulStartupArmsNothing(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)
	installMTLSTestPair(t, certPath)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})
	if !mtlsClientCertHealth().loaded {
		t.Fatal("precondition: the startup load must succeed")
	}
	if mtlsClientCertDeferredLoadPending() {
		t.Fatal("a successful startup armed a deferred load")
	}
	before := getUpstreamTransport()
	called := false
	runMTLSClientCertLoadRetry(context.Background(), func(int) time.Duration { called = true; return 0 })
	if called {
		t.Fatal("the loop waited although no deferred load is armed")
	}
	if getUpstreamTransport() != before {
		t.Fatal("the idle loop published a transport")
	}
	if _, ok := findAuditByActionObject(t, "upstream_mtls.client_cert.auto_load", certPath); ok {
		t.Fatal("a startup load was audited as an automatic load")
	}
}

// Restraint: nothing configured, and a one-sided configuration (which no file
// on disk can repair), arm nothing. The one-sided row keeps the restart remedy.
func TestMTLSClientCertRetry_IdleWhenUnconfiguredOrOneSided(t *testing.T) {
	for name, cfg := range map[string]mtlsOCSPStartupConfig{
		"unconfigured": {},
		"cert only":    {ClientCertFile: "/etc/culvert/client.crt"},
		"key only":     {ClientKeyFile: "/etc/culvert/client.key"},
		"ocsp only":    {OCSPCheck: true},
	} {
		t.Run(name, func(t *testing.T) {
			isolateMTLSRetry(t)
			loadMTLSAndOCSP(cfg)
			if mtlsClientCertDeferredLoadPending() {
				t.Fatal("a deferred load was armed")
			}
			called := false
			runMTLSClientCertLoadRetry(context.Background(), func(int) time.Duration { called = true; return 0 })
			if called {
				t.Fatal("the loop waited although nothing is armed")
			}
			if upstreamTemplateCertCount() != 0 {
				t.Fatal("a client certificate was installed")
			}
			if h := mtlsClientCertHealth(); h.configured {
				if row := mtlsDiagRow(t); !strings.Contains(row.OperatorAction, "then restart Culvert") {
					t.Fatalf("a one-sided configuration lost its restart remedy: %q", row.OperatorAction)
				}
			}
		})
	}
}

// Restraint: files that are present but are not a matching pair never install
// anything. The intent stays armed and the latest error stays on record.
func TestMTLSClientCertRetry_InvalidPairNeverInstalls(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)
	// A valid certificate with a key that does not belong to it.
	installMTLSTestPair(t, certPath)
	_, otherKey := writeTestClientCert(t, t.TempDir())
	if err := os.Rename(otherKey, keyPath); err != nil {
		t.Fatal(err)
	}
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})
	before := getUpstreamTransport()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	runMTLSRetryToEnd(t, ctx, func(int) time.Duration {
		if attempts.Add(1) == 4 {
			cancel() // three failed attempts are enough
			return time.Hour
		}
		return 0
	})
	if upstreamTemplateCertCount() != 0 || getUpstreamTransport() != before {
		t.Fatal("a mismatched pair was installed")
	}
	if !mtlsClientCertDeferredLoadPending() {
		t.Fatal("a failing pair must stay armed")
	}
	if h := mtlsClientCertHealth(); h.loaded || h.lastError == "" {
		t.Fatalf("the failure must stay on record, got %+v", h)
	}
	if _, ok := findAuditByActionObject(t, "upstream_mtls.client_cert.auto_load", certPath); ok {
		t.Fatal("a failed load was audited as a success")
	}
}

// Shutdown: a cancelled lifecycle ends the loop while it waits, and nothing is
// installed afterwards even if the files become readable.
func TestMTLSClientCertRetry_StopsOnCancelAndInstallsNothing(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)
	armMTLSClientCertDeferredLoad(certPath, keyPath)
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runMTLSClientCertLoadRetry(ctx, func(int) time.Duration {
			waiting <- struct{}{}
			return time.Hour
		})
		close(done)
	}()
	<-waiting
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop ignored cancellation")
	}
	installMTLSTestPair(t, certPath)
	if !attemptMTLSClientCertLoadRetry(ctx, 1) {
		t.Fatal("an attempt on a cancelled lifecycle must end the loop")
	}
	if upstreamTemplateCertCount() != 0 {
		t.Fatal("a certificate was installed after the lifecycle was cancelled")
	}
}

// The no-rotation boundary: when the template already carries a client
// certificate the retry never replaces it, even though its armed paths now
// hold a different valid pair. No transport is published and nothing audited.
func TestMTLSClientCertRetry_NeverReplacesAnInstalledCertificate(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)
	liveCert, liveKey := writeTestClientCert(t, t.TempDir())
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: liveCert, ClientKeyFile: liveKey})
	liveStatus := mtlsClientCertHealth()
	upstreamTransportWriteMu.Lock()
	liveDER := upstreamOpTLSCfg.Certificates[0].Certificate[0]
	upstreamTransportWriteMu.Unlock()

	armMTLSClientCertDeferredLoad(certPath, keyPath)
	installMTLSTestPair(t, certPath) // a different key pair
	before := getUpstreamTransport()

	runMTLSRetryToEnd(t, context.Background(), func(int) time.Duration { return 0 })

	upstreamTransportWriteMu.Lock()
	gotDER := upstreamOpTLSCfg.Certificates[0].Certificate[0]
	upstreamTransportWriteMu.Unlock()
	if !bytes.Equal(gotDER, liveDER) {
		t.Fatal("the installed client certificate was replaced")
	}
	if getUpstreamTransport() != before {
		t.Fatal("a refused load published a transport")
	}
	if got := mtlsClientCertHealth(); got != liveStatus {
		t.Fatalf("status changed on a refused load: %+v, want %+v", got, liveStatus)
	}
	if mtlsClientCertDeferredLoadPending() {
		t.Fatal("a refused load must disarm")
	}
	if _, ok := findAuditByActionObject(t, "upstream_mtls.client_cert.auto_load", certPath); ok {
		t.Fatal("a refused load was audited as a success")
	}
}

// The TLS floor is never lowered: with OCSP checking on (floor TLS 1.3) and a
// certificate that failed at startup, the automatic load keeps TLS 1.3 and
// keeps the OCSP verification hook.
func TestMTLSClientCertRetry_KeepsAnExistingTLSFloorAndOCSP(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath, OCSPCheck: true})
	installMTLSTestPair(t, certPath)
	runMTLSRetryToEnd(t, context.Background(), func(int) time.Duration { return 0 })

	cfg := getUpstreamTransport().TLSClientConfig
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatal("the certificate was not installed")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3 kept", cfg.MinVersion)
	}
	if cfg.VerifyPeerCertificate == nil && cfg.VerifyConnection == nil {
		t.Fatal("the OCSP verification hook was lost")
	}
	if !globalOCSP.Enabled() {
		t.Fatal("OCSP checking was disabled")
	}
}

// A runtime OCSP enable racing the automatic load: both land, in either order.
func TestMTLSClientCertRetry_ConcurrentWithTemplateSwap(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)
	armMTLSClientCertDeferredLoad(certPath, keyPath)
	installMTLSTestPair(t, certPath)

	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		<-start
		swapUpstreamTransport(func(old *http.Transport) *http.Transport {
			if upstreamOpTLSCfg == nil {
				upstreamOpTLSCfg = &tls.Config{MinVersion: tls.VersionTLS13}
			}
			upstreamOpTLSCfg.ServerName = "marker.invalid"
			return cloneTransport(old)
		})
		close(done)
	}()
	close(start)
	runMTLSRetryToEnd(t, context.Background(), func(int) time.Duration { return 0 })
	<-done

	cfg := getUpstreamTransport().TLSClientConfig
	if cfg == nil || len(cfg.Certificates) != 1 || cfg.ServerName != "marker.invalid" {
		t.Fatalf("one of the two template updates was lost: %+v", cfg)
	}
}

// Two attempts at once install exactly once and audit exactly once.
func TestMTLSClientCertRetry_DuplicateAttemptsInstallOnce(t *testing.T) {
	certPath, keyPath := isolateMTLSRetry(t)
	armMTLSClientCertDeferredLoad(certPath, keyPath)
	installMTLSTestPair(t, certPath)

	var loadedCount atomic.Int32
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			if _, loaded, err := tryMTLSClientCertDeferredLoad(); err == nil && loaded {
				loadedCount.Add(1)
			}
			done <- struct{}{}
		}()
	}
	<-done
	<-done
	if got := loadedCount.Load(); got != 1 {
		t.Fatalf("%d attempts reported an installation, want exactly 1", got)
	}
	if upstreamTemplateCertCount() != 1 {
		t.Fatal("the template does not carry exactly one certificate")
	}
}
