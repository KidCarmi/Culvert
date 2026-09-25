package main

// coverage_isolation_security_test.go — ISOLATED fixtures for security /
// admin-plane paths whose coverage previously depended on TEST ORDER.
//
// CI-REDESIGN stage 5B (roadmap/CI-REDESIGN.md) splits the root package's test
// suite across several processes ("shards"). Comparing the sharded coverage
// profile with the single-process one showed coverage blocks that were hit in
// one layout and not the other. Every block pinned here was reached only
// because some EARLIER test in the same process happened to leave process-
// global state behind (a loaded CA in the certMgr singleton, a loaded cluster
// CA, a recorded GeoIP load failure, a resolved frontendV2 state, a recorded
// crash, a degraded identity backend...) — or because of a scheduling
// accident. Their coverage was a property of co-location, not of any test
// deliberately exercising them.
//
// Each test below sets up EVERY global it needs itself, restores it via
// t.Cleanup, and asserts the observable behaviour of the path — so it passes
// alone, under -shuffle, and in any shard, and the block is covered because the
// behaviour is PINNED rather than because a neighbour ran first.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/geoip"
	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// ─── shared fixtures (prefixed covIsoSec to stay unique in package main) ─────

// covIsoSecInstallCA installs a fresh in-memory inspection CA into the global
// certMgr and restores the previous manager on cleanup.
func covIsoSecInstallCA(t *testing.T) *CertManager {
	t.Helper()
	prev := certMgr
	cm := ca.New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	certMgr = cm
	t.Cleanup(func() { certMgr = prev })
	return cm
}

// covIsoSecInstallEmptyCA installs a manager with NO CA loaded.
func covIsoSecInstallEmptyCA(t *testing.T) *CertManager {
	t.Helper()
	prev := certMgr
	cm := ca.New()
	certMgr = cm
	t.Cleanup(func() { certMgr = prev })
	return cm
}

// covIsoSecNoLoadFailure clears any recorded SSL-inspection load failure for
// the duration of the test (a leaked failure would force the "not ready" arm).
func covIsoSecNoLoadFailure(t *testing.T) {
	t.Helper()
	prev := sslInspectionLoadFailure()
	sslInspectionLoadError.Store("")
	t.Cleanup(func() { sslInspectionLoadError.Store(prev) })
}

// covIsoSecSelfSignedCA builds a self-signed CA certificate valid until notAfter.
func covIsoSecSelfSignedCA(t *testing.T, cn string, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

// covIsoSecSink records the single value a support collector writes.
type covIsoSecSink struct{ v any }

func (s *covIsoSecSink) WriteJSON(v any) error { s.v = v; return nil }

// covIsoSecCollectTLS runs the tls support collector and decodes its section.
func covIsoSecCollectTLS(t *testing.T) map[string]any {
	t.Helper()
	sink := &covIsoSecSink{}
	res := tlsCollector{}.Collect(context.Background(),
		support.CollectInput{Level: support.L1, Redactor: redaction.NewWithSalt([]byte("covIsoSec"))}, sink)
	if res.Status != support.StatusOK {
		t.Fatalf("tlsCollector status = %v, want OK", res.Status)
	}
	raw, err := json.Marshal(sink.v)
	if err != nil {
		t.Fatalf("marshal section: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal section: %v", err)
	}
	return m
}

// ─── 1. controlplane_tls.go — cluster CAs appended to the CP client pool ────

// TestCovIsoSec_BuildServerTLSAppendsClusterCAToClientPool pins
// controlplane_tls.go `if allCA := globalClusterCA.AllCACertsPEM(); len(allCA)
// > 0 { pool.AppendCertsFromPEM(allCA) }`. It used to be covered only when an
// earlier test had left a LOADED cluster CA in globalClusterCA before the CA-7
// buildServerTLS test ran; alone, that test sees an empty cluster CA. Here the
// cluster CA is installed explicitly, and the assertion is the security
// property: a certificate chaining to the cluster CA is trusted by the CP's
// client-auth pool, which it would NOT be from the operator CA file alone.
func TestCovIsoSec_BuildServerTLSAppendsClusterCAToClientPool(t *testing.T) {
	snapshotCPTLSConfig(t)
	now := time.Now()
	cc := newClusterCAWithWindow(t, t.TempDir(), now.Add(-time.Hour), now.Add(365*24*time.Hour))
	installClusterCA(t, cc)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedECDSACert(t, dir)

	// Control: the operator CA file alone does not trust the cluster CA.
	basePool, err := loadCertPool(certPath)
	if err != nil {
		t.Fatalf("loadCertPool: %v", err)
	}
	if _, err := cc.cert.Verify(x509.VerifyOptions{Roots: basePool}); err == nil {
		t.Fatal("control: operator CA pool must not already trust the cluster CA")
	}

	creds, err := buildServerTLS(certPath, keyPath, certPath)
	if err != nil {
		t.Fatalf("buildServerTLS: %v", err)
	}
	if creds == nil {
		t.Fatal("buildServerTLS returned nil credentials")
	}
	cpTLSConfig.mu.Lock()
	cfg := cpTLSConfig.cfg
	baseCAF := cpTLSConfig.baseCAF
	cpTLSConfig.mu.Unlock()
	if cfg == nil || cfg.ClientCAs == nil {
		t.Fatal("buildServerTLS did not install a client-CA pool")
	}
	if baseCAF != certPath {
		t.Errorf("baseCAF = %q, want %q", baseCAF, certPath)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if _, err := cc.cert.Verify(x509.VerifyOptions{Roots: cfg.ClientCAs}); err != nil {
		t.Errorf("cluster CA not trusted by the CP client pool: %v", err)
	}
}

// ─── 2. rootca_recovery.go — recovery re-persists a loaded CA ───────────────

// TestCovIsoSec_InspectionCARecoveryRePersistsLoadedCA pins the
// `case certMgr.Ready(): return certMgr.SaveCA(...)` arm of
// attemptInspectionCARecovery. Previously reached only when a preceding test
// had left a READY CA in certMgr; recovery tests that start from a fresh,
// not-ready manager take the LoadCA arm instead. The assertion is the rule the
// arm exists for: the LIVE CA is persisted to the configured bundle, and it is
// never replaced (a retry must never mint).
func TestCovIsoSec_InspectionCARecoveryRePersistsLoadedCA(t *testing.T) {
	cm := covIsoSecInstallCA(t)
	before := cm.CACertPEM()
	path := filepath.Join(t.TempDir(), "ca.bundle")
	phrase := t.Name() // bundle encryption input derived per test, not a literal

	if err := attemptInspectionCARecovery(rootCAStartupConfig{Path: path, Passphrase: phrase}); err != nil {
		t.Fatalf("attemptInspectionCARecovery: %v", err)
	}
	if got := certMgr.CACertPEM(); !bytes.Equal(got, before) {
		t.Fatal("recovery with a loaded CA replaced the live root; it must only re-persist it")
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: test-owned TempDir path
	if err != nil {
		t.Fatalf("bundle not written: %v", err)
	}
	if !ca.HasBundleMagic(data) {
		t.Error("bundle written without the PSCA envelope despite a passphrase")
	}
	reload := ca.New()
	if err := reload.LoadCA(path, phrase); err != nil {
		t.Fatalf("reload persisted bundle: %v", err)
	}
	if !bytes.Equal(reload.CACertPEM(), before) {
		t.Error("persisted bundle does not hold the live CA")
	}
}

// ─── 3 + 4. support_collectors_posture.go — tls collector with a CA ─────────

// TestCovIsoSec_TLSCollectorReportsLoadedCA pins the tls support collector's
// string-field extraction (`if v, ok := info[k].(string); ok { return v }`) and
// its expiry arm (`if exp := certMgr.CAExpiry(); !exp.IsZero() {...}`). Both
// are reachable only with a CA loaded in certMgr; the section was otherwise
// covered only when a support-bundle test happened to run after a test that
// left a CA installed. Both expiry outcomes are asserted: a fresh 10-year root
// (not due) and a near-expiry root (rotation due soon).
func TestCovIsoSec_TLSCollectorReportsLoadedCA(t *testing.T) {
	t.Run("fresh_root", func(t *testing.T) {
		cm := covIsoSecInstallCA(t)
		info := cm.CACertInfo()
		m := covIsoSecCollectTLS(t)
		if m["ca_ready"] != true {
			t.Errorf("ca_ready = %v, want true", m["ca_ready"])
		}
		for jsonKey, infoKey := range map[string]string{
			"ca_subject":            "subject",
			"ca_issuer":             "issuer",
			"ca_fingerprint_sha256": "fingerprint",
			"ca_not_before":         "notBefore",
			"ca_not_after":          "notAfter",
		} {
			want, _ := info[infoKey].(string)
			if want == "" {
				t.Fatalf("fixture: CACertInfo()[%q] empty", infoKey)
			}
			if m[jsonKey] != want {
				t.Errorf("%s = %v, want %q", jsonKey, m[jsonKey], want)
			}
		}
		days, _ := m["ca_expires_in_days"].(float64)
		if days < 3600 {
			t.Errorf("ca_expires_in_days = %v, want ~3650 for a fresh 10-year root", m["ca_expires_in_days"])
		}
		if m["rotation_due_soon"] != false {
			t.Errorf("rotation_due_soon = %v, want false", m["rotation_due_soon"])
		}
	})
	t.Run("near_expiry_root", func(t *testing.T) {
		cm := covIsoSecInstallEmptyCA(t)
		cert, key := covIsoSecSelfSignedCA(t, "covIsoSec Near-Expiry CA", time.Now().Add(10*24*time.Hour))
		cm.SetCAForTest(cert, key)
		m := covIsoSecCollectTLS(t)
		if m["ca_subject"] != "covIsoSec Near-Expiry CA" {
			t.Errorf("ca_subject = %v", m["ca_subject"])
		}
		days, _ := m["ca_expires_in_days"].(float64)
		if days < 9 || days > 10 {
			t.Errorf("ca_expires_in_days = %v, want 9..10", m["ca_expires_in_days"])
		}
		if m["rotation_due_soon"] != true {
			t.Errorf("rotation_due_soon = %v, want true inside 30d", m["rotation_due_soon"])
		}
	})
}

// ─── 5. support_telemetry_registry.go — CA-ready telemetry bit ──────────────

// TestCovIsoSec_SupportHealthCAReadyReflectsLoadedCA pins `if certMgr.Ready() {
// return 1 }` in readSupportHealthCAReady. The existing telemetry test pins the
// load-FAILURE arm; the ready arm needed a CA left in certMgr by some other
// test AND no failure recorded. Here both are set explicitly, with the
// not-ready manager as the control.
func TestCovIsoSec_SupportHealthCAReadyReflectsLoadedCA(t *testing.T) {
	covIsoSecNoLoadFailure(t)
	covIsoSecInstallEmptyCA(t)
	if got := readSupportHealthCAReady(); got != 0 {
		t.Fatalf("control: readSupportHealthCAReady() with no CA = %v, want 0", got)
	}
	covIsoSecInstallCA(t)
	if got := readSupportHealthCAReady(); got != 1 {
		t.Errorf("readSupportHealthCAReady() with a loaded CA = %v, want 1", got)
	}
}

// ─── 6 + 7. ui_security.go — writeCACertPEM ─────────────────────────────────

// TestCovIsoSec_WriteCACertPEMServesLoadedCA pins writeCACertPEM's success
// path. Whether the download handler saw a CA (and therefore which arm ran)
// depended on whatever certMgr the previous test left behind.
func TestCovIsoSec_WriteCACertPEMServesLoadedCA(t *testing.T) {
	cm := covIsoSecInstallCA(t)
	w := httptest.NewRecorder()
	writeCACertPEM(w)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != `attachment; filename="culvert-ca.pem"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if w.Body.String() != string(cm.CACertPEM()) {
		t.Error("body is not the loaded CA's PEM")
	}
}

// TestCovIsoSec_WriteCACertPEMWithoutCAIs503 pins the `pem == nil` arm (503
// "CA not initialised"), the complement of the test above: it was reached only
// when no earlier test had left a CA installed.
func TestCovIsoSec_WriteCACertPEMWithoutCAIs503(t *testing.T) {
	covIsoSecInstallEmptyCA(t)
	w := httptest.NewRecorder()
	writeCACertPEM(w)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "CA not initialised") {
		t.Errorf("body = %q, want the CA-not-initialised message", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct == "application/x-pem-file" {
		t.Error("a 503 must not advertise a PEM download")
	}
}

// ─── 8. ui_security.go — GeoIP status surfaces a load failure ───────────────

// TestCovIsoSec_GeoIPConfigSurfacesLoadError pins apiGeoIPConfig's
// `if msg, at, ok := geoip.LoadError(); ok {...}` arm. It was covered only
// when geoip_startup_test.go's missing-file loader test had run earlier in the
// same process and left the failure recorded.
//
// Restoration caveat: internal/geoip keeps the failure record in unexported
// package state with no reset seam — it is cleared only by a SUCCESSFUL
// InitGeoDB, which needs a real .mmdb and would also ENABLE the engine (a far
// worse leak). The recorded failure is the same state TestLoadGeoIP_Missing-
// FileIsNonFatal already leaves behind, it does not change geoip.Enabled(), and
// no test asserts its absence. Every OTHER global this test reads is untouched.
func TestCovIsoSec_GeoIPConfigSurfacesLoadError(t *testing.T) {
	enabledBefore := geoip.Enabled()
	start := time.Now().Truncate(time.Second)
	missing := filepath.Join(t.TempDir(), "covIsoSec-missing.mmdb")
	if err := geoip.InitGeoDB(missing); err == nil {
		t.Fatal("InitGeoDB on a missing file must fail")
	}
	if geoip.Enabled() != enabledBefore {
		t.Fatal("a failed InitGeoDB must not change Enabled()")
	}

	w := httptest.NewRecorder()
	apiGeoIPConfig(w, getReq("/api/geoip"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	msg, _ := m["lastError"].(string)
	if !strings.Contains(msg, "covIsoSec-missing.mmdb") {
		t.Errorf("lastError = %q, want the failing path's error", msg)
	}
	atStr, _ := m["lastErrorAt"].(string)
	at, err := time.Parse(time.RFC3339, atStr)
	if err != nil {
		t.Fatalf("lastErrorAt %q is not RFC3339: %v", atStr, err)
	}
	if at.Before(start) {
		t.Errorf("lastErrorAt %v predates the failing load at %v", at, start)
	}
}

// ─── 9 + 10. ui_frontend_v2.go — resolved-state cache ───────────────────────

// covIsoSecResetFrontendV2 clears the process-lifetime frontendV2 pointer for
// the test and restores whatever was there before.
func covIsoSecResetFrontendV2(t *testing.T) {
	t.Helper()
	prev := frontendV2.Load()
	frontendV2.Store(nil)
	t.Cleanup(func() { frontendV2.Store(prev) })
}

// TestCovIsoSec_EnsureFrontendV2ReturnsCachedState pins ensureFrontendV2's
// cached return (`if s := frontendV2.Load(); s != nil { return s }`).
// frontendV2 is a process-lifetime atomic.Pointer no test reset, so the cached
// arm ran only when a SECOND admin-UI-building test shared the process with
// the first. The property asserted is the contract: the env value is resolved
// exactly once — a later call with a DIFFERENT value returns the identical
// state and does not re-read it.
func TestCovIsoSec_EnsureFrontendV2ReturnsCachedState(t *testing.T) {
	covIsoSecResetFrontendV2(t)
	first := ensureFrontendV2("")
	if first == nil || first.status != frontendV2Disabled {
		t.Fatalf("first resolution = %+v, want disabled", first)
	}
	second := ensureFrontendV2("1")
	if second != first {
		t.Fatal("second ensureFrontendV2 did not return the cached state")
	}
	if second.status != frontendV2Disabled {
		t.Errorf("cached state status = %q; the env must not be re-read", second.status)
	}
	if frontendV2Current() != first {
		t.Error("frontendV2Current must return the resolved state")
	}
}

// TestCovIsoSec_FrontendV2CurrentBeforeResolutionIsDisabled pins
// frontendV2Current's fallback (`return &frontendV2State{status:
// frontendV2Disabled}`), reached only while frontendV2 is still nil — i.e. only
// when no earlier test in the process had built an admin UI handler. A handler
// consulted before resolution must behave as disabled (404), never as ready.
func TestCovIsoSec_FrontendV2CurrentBeforeResolutionIsDisabled(t *testing.T) {
	covIsoSecResetFrontendV2(t)
	st := frontendV2Current()
	if st == nil || st.status != frontendV2Disabled {
		t.Fatalf("frontendV2Current() = %+v, want disabled", st)
	}
	if frontendV2.Load() != nil {
		t.Error("frontendV2Current must not publish its fallback state")
	}
	w := httptest.NewRecorder()
	handleFrontendV2Shell(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app/", http.NoBody))
	if w.Code != http.StatusNotFound {
		t.Errorf("/app before resolution = %d, want 404", w.Code)
	}
}

// ─── 11. crashguard.go — no crash recorded ──────────────────────────────────

// TestCovIsoSec_LastCrashSnapshotEmptyWhenNoCrash pins lastCrashSnapshot's
// `if lastCrash == nil { return crashRecord{}, false }` arm. lastCrash is
// process-global and only ever set, so the empty arm ran only if no chaos /
// crashguard test had recorded a panic earlier in the process.
func TestCovIsoSec_LastCrashSnapshotEmptyWhenNoCrash(t *testing.T) {
	lastCrashMu.Lock()
	prev := lastCrash
	lastCrash = nil
	lastCrashMu.Unlock()
	t.Cleanup(func() {
		lastCrashMu.Lock()
		lastCrash = prev
		lastCrashMu.Unlock()
	})

	rec, ok := lastCrashSnapshot()
	if ok {
		t.Fatalf("lastCrashSnapshot() ok=true with no crash recorded (rec=%+v)", rec)
	}
	if rec != (crashRecord{}) {
		t.Errorf("lastCrashSnapshot() rec = %+v, want zero value", rec)
	}
	if got := lastCrashRedacted(redaction.NewWithSalt([]byte("covIsoSec"))); got != nil {
		t.Errorf("lastCrashRedacted() = %v, want nil with no crash", got)
	}

	// Control: once a record exists, the snapshot returns a COPY.
	lastCrashMu.Lock()
	lastCrash = &crashRecord{ID: "covIsoSec", Component: "test"}
	lastCrashMu.Unlock()
	rec, ok = lastCrashSnapshot()
	if !ok || rec.ID != "covIsoSec" {
		t.Fatalf("lastCrashSnapshot() = (%+v, %v), want the recorded crash", rec, ok)
	}
	rec.ID = "mutated"
	if again, _ := lastCrashSnapshot(); again.ID != "covIsoSec" {
		t.Error("lastCrashSnapshot must return a copy, not the stored record")
	}
}

// ─── 12. geoip.go — refreshAsync while a resolution is in flight ────────────

// TestCovIsoSec_RefreshAsyncJoinsInFlightResolution pins refreshAsync's
// `if !leader { return }` arm. It was reached only when a stale-serving refresh
// happened to race a resolution already in flight for the same host — a
// scheduling accident. Here the flight is claimed explicitly on a PRIVATE
// cache (no process-global state), so the non-leader arm is deterministic.
// The property: a second refresh neither disturbs the running flight, nor
// resolves, nor writes the cache.
func TestCovIsoSec_RefreshAsyncJoinsInFlightResolution(t *testing.T) {
	c := &hostIPCache{entries: map[string]hostIPEntry{}, inflight: map[string]*hostIPFlight{}}
	const host = "covisosec.example"

	fl, leader := c.joinFlight(host)
	if !leader {
		t.Fatal("fixture: first joinFlight must lead")
	}
	c.refreshAsync(host)

	c.mu.RLock()
	owner := c.inflight[host]
	_, cached := c.entries[host]
	c.mu.RUnlock()
	if owner != fl {
		t.Fatal("refreshAsync replaced the in-flight resolution")
	}
	if cached {
		t.Error("refreshAsync wrote the cache while another resolution was in flight")
	}
	select {
	case <-fl.done:
		t.Fatal("refreshAsync completed a flight it does not lead")
	default:
	}

	want := net.ParseIP("203.0.113.9")
	c.finishFlight(host, fl, want)
	<-fl.done
	if !fl.ip.Equal(want) {
		t.Errorf("flight ip = %v, want %v", fl.ip, want)
	}
	c.mu.RLock()
	_, stillInflight := c.inflight[host]
	c.mu.RUnlock()
	if stillInflight {
		t.Error("finished flight still registered")
	}
}

// ─── 13. metrics.go — identity-backend degraded gauge ───────────────────────

// covIsoSecSnapshotAuthBackendHealth saves the process-global identity-backend
// record, resets it, and restores the saved values on cleanup.
func covIsoSecSnapshotAuthBackendHealth(t *testing.T) {
	t.Helper()
	h := &authBackendHealth
	h.mu.Lock()
	unavailable, gated := h.unavailable, h.gatedDenials
	last, lastBackend, lastErr := h.last, h.lastBackend, h.lastErr
	var down map[string]bool
	if h.down != nil {
		down = make(map[string]bool, len(h.down))
		for k, v := range h.down {
			down[k] = v
		}
	}
	alertAt, logAt := h.alertAt, h.logAt
	h.mu.Unlock()

	resetAuthBackendHealthForTest()
	t.Cleanup(func() {
		h.mu.Lock()
		h.unavailable, h.gatedDenials = unavailable, gated
		h.last, h.lastBackend, h.lastErr = last, lastBackend, lastErr
		h.down = down
		h.alertAt, h.logAt = alertAt, logAt
		h.mu.Unlock()
	})
}

// TestCovIsoSec_MetricsReportIdentityBackendUnavailable pins `if
// abSnap.Degraded { abDegraded = 1 }` in handleMetrics. It was covered only
// when an LDAP/OIDC availability test had left a backend in the process-global
// "down" set before some metrics test scraped /metrics. The paging gauge must
// read 1 while a backend is unreachable, and 0 once a reach is observed.
func TestCovIsoSec_MetricsReportIdentityBackendUnavailable(t *testing.T) {
	covIsoSecSnapshotAuthBackendHealth(t)
	prevToken := metricsToken
	metricsToken = ""
	t.Cleanup(func() { metricsToken = prevToken })
	prevAlert := fireIdentityBackendUnreachableAlert
	fireIdentityBackendUnreachableAlert = func(string, string) {}
	t.Cleanup(func() { fireIdentityBackendUnreachableAlert = prevAlert })

	scrape := func() string {
		w := httptest.NewRecorder()
		handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
		if w.Code != http.StatusOK {
			t.Fatalf("metrics status = %d", w.Code)
		}
		return w.Body.String()
	}

	if body := scrape(); !strings.Contains(body, "\nculvert_auth_backend_unavailable 0\n") {
		t.Fatal("control: gauge must read 0 with no backend down")
	}
	noteAuthBackendUnavailable("ldap", "covIsoSec: dial refused")
	body := scrape()
	if !strings.Contains(body, "\nculvert_auth_backend_unavailable 1\n") {
		t.Error("culvert_auth_backend_unavailable must be 1 while a backend is unreachable")
	}
	if !strings.Contains(body, "\nculvert_auth_backend_unavailable_total 1\n") {
		t.Error("culvert_auth_backend_unavailable_total must count the outage")
	}
	noteAuthBackendReachable("ldap")
	if body := scrape(); !strings.Contains(body, "\nculvert_auth_backend_unavailable 0\n") {
		t.Error("gauge must clear on an observed reach")
	}
}

// ─── 14. admin_settings.go — persisted rate limit restored at boot ──────────

// TestCovIsoSec_ApplyAdminSecurityRestoresRateLimit pins applyAdminSecurity's
// `if s.RateLimitRPM > 0 {...}` arm. It ran only when some settings-load test
// happened to persist a non-zero rate limit; nothing exercised it on purpose.
// The assertion is the durability contract: the persisted limit (per minute)
// and exemption list are live after the restore, and invalid exemption entries
// are skipped rather than failing the boot.
func TestCovIsoSec_ApplyAdminSecurityRestoresRateLimit(t *testing.T) {
	prevRL := rl
	rl = newRateLimiter()
	prevCommit := requireCommitEnabled()
	prevLedger := rewriteSeedLedgerAtLoad
	t.Cleanup(func() {
		rl = prevRL
		setRequireCommit(prevCommit)
		rewriteSeedLedgerAtLoad = prevLedger
	})

	applyAdminSecurity(&AdminSettings{
		RateLimitRPM:        123,
		RateLimitExemptions: []string{"192.0.2.7", "198.51.100.0/24", "not-an-ip"},
	})

	if !rl.Enabled() {
		t.Fatal("rate limiter not enabled from persisted settings")
	}
	if rl.Limit() != 123 || rl.Window() != time.Minute {
		t.Errorf("limit/window = %d/%v, want 123/1m", rl.Limit(), rl.Window())
	}
	if !rl.IsExempt("192.0.2.7") {
		t.Error("single-IP exemption not restored")
	}
	if !rl.IsExempt("198.51.100.42") {
		t.Error("CIDR exemption not restored")
	}
	if rl.IsExempt("203.0.113.1") {
		t.Error("non-exempt client reported exempt")
	}
	for _, e := range rl.ListExemptions() {
		if e == "not-an-ip" {
			t.Error("invalid exemption entry must be skipped")
		}
	}
}
