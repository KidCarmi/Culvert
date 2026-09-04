package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeTestLeaf builds a self-signed leaf cert with the given validity window and
// SAN, returning the parsed *x509.Certificate — no network, deterministic enough
// for the summarize tests.
func makeTestLeaf(t *testing.T, cn, san string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{san},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsecert: %v", err)
	}
	return cert
}

// TestDiagnoseStorage_HealthyDir proves the storage verb reports ok on a writable
// data dir and fills the typed, versioned contract.
func TestDiagnoseStorage_HealthyDir(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	d := diagnoseStorage(time.Unix(1_700_000_000, 0))
	if d.SchemaVersion != diagnoseSchemaVersion {
		t.Fatalf("schema_version=%d want %d", d.SchemaVersion, diagnoseSchemaVersion)
	}
	if !d.OK {
		t.Fatalf("healthy dir reported not ok: %+v", d.Checks)
	}
	// Every declared check ran and passed; the writability probe left no file behind.
	names := map[string]bool{}
	for _, c := range d.Checks {
		names[c.Name] = true
		if !c.OK {
			t.Errorf("check %q not ok: %s", c.Name, c.Detail)
		}
	}
	for _, want := range []string{"free_space", "data_dir_writable", "bundles_dir_writable", "support_dir_writable"} {
		if !names[want] {
			t.Errorf("missing check %q", want)
		}
	}
	// No probe temp files leaked in the data dir.
	entries, _ := os.ReadDir(dataDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".diag-write-") {
			t.Errorf("writability probe leaked temp file %q", e.Name())
		}
	}
	// The probe must NOT have created the support tree — that is the bundle path's
	// job (at 0700). Running a diagnostic first must not mutate storage.
	for _, sub := range []string{"support", filepath.Join("support", "bundles")} {
		if _, err := os.Stat(filepath.Join(dataDir, sub)); !os.IsNotExist(err) {
			t.Errorf("storage probe created %q (err=%v) — diagnostic must not pre-seed the support tree", sub, err)
		}
	}
}

// TestDiagnoseStorage_ReadOnlyDirDegraded proves an unwritable target is flagged,
// not crashed — the whole point of the probe (a stat bit can lie; a real write can't).
func TestDiagnoseStorage_ReadOnlyDirDegraded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	prev := dataDir
	base := t.TempDir()
	ro := filepath.Join(base, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil { // read+execute, NO write
		t.Fatalf("mkdir ro: %v", err)
	}
	dataDir = ro
	t.Cleanup(func() {
		_ = os.Chmod(ro, 0o700) // restore so TempDir cleanup can remove it
		dataDir = prev
	})

	d := diagnoseStorage(time.Unix(1_700_000_000, 0))
	if d.OK {
		t.Fatal("read-only data dir reported ok — probe did not catch it")
	}
	var sawWriteFail bool
	for _, c := range d.Checks {
		if c.Name == "data_dir_writable" && !c.OK {
			sawWriteFail = true
		}
	}
	if !sawWriteFail {
		t.Fatalf("data_dir_writable did not fail on a 0500 dir: %+v", d.Checks)
	}
}

// TestDiagnoseStorage_API proves the handler enforces POST + operator RBAC, audits,
// and returns the typed body.
func TestDiagnoseStorage_API(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// GET is rejected (POST-only verb).
	getReq := roleReq(RoleOperator, http.MethodGet, "/api/diagnose/storage", nil)
	getRec := httptest.NewRecorder()
	apiDiagnoseStorage(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", getRec.Code)
	}

	// Viewer is below operator → 403.
	vReq := roleReq(RoleViewer, http.MethodPost, "/api/diagnose/storage", nil)
	vRec := httptest.NewRecorder()
	apiDiagnoseStorage(vRec, vReq)
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST code=%d want 403", vRec.Code)
	}

	// Operator POST → 200 with the typed contract.
	req := roleReq(RoleOperator, http.MethodPost, "/api/diagnose/storage", nil)
	rec := httptest.NewRecorder()
	apiDiagnoseStorage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator POST code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"schema_version"`) || !strings.Contains(rec.Body.String(), `"checks"`) {
		t.Fatalf("body missing typed fields: %s", rec.Body.String())
	}
}

// TestDiagnoseUpstream_DisabledIsOK proves that with no upstream pool (direct
// egress) the verb reports enabled=false and ok=true — direct is not a fault.
func TestDiagnoseUpstream_DisabledIsOK(t *testing.T) {
	d := diagnoseUpstream(time.Unix(1_700_000_000, 0))
	if d.SchemaVersion != diagnoseSchemaVersion {
		t.Fatalf("schema_version=%d want %d", d.SchemaVersion, diagnoseSchemaVersion)
	}
	if d.Enabled {
		t.Skip("upstream pool enabled in this environment; disabled-path assertion N/A")
	}
	if !d.OK {
		t.Fatalf("disabled pool (direct egress) reported not ok: %+v", d)
	}
	if d.Count != 0 || d.HealthyCount != 0 {
		t.Fatalf("disabled pool has proxies: count=%d healthy=%d", d.Count, d.HealthyCount)
	}
}

// TestUpstreamCounts_OpenCircuitNotUsable is the Codex #778 regression: a proxy
// whose Healthy flag is set but whose breaker is OPEN is NOT usable — the selection
// path skips it, so an all-circuits-open pool must diagnose as unavailable even
// though every proxy still reads "healthy".
func TestUpstreamCounts_OpenCircuitNotUsable(t *testing.T) {
	cases := []struct {
		name            string
		list            []UpstreamStatus
		healthy, usable int
	}{
		// 2F-C: Eligible is the pool's own selection verdict (credential
		// usable AND probe unprobed/healthy AND breaker admitting), so the
		// fixtures carry it exactly as List() derives it for each shape.
		{"all-open", []UpstreamStatus{{Healthy: true, Circuit: "open"}, {Healthy: true, Circuit: "open"}}, 2, 0},
		{"mixed", []UpstreamStatus{{Healthy: true, Circuit: "open"}, {Healthy: true, Circuit: "closed", Eligible: true}}, 2, 1},
		{"half-open-usable", []UpstreamStatus{{Healthy: true, Circuit: "half-open", Eligible: true}}, 1, 1},
		{"unhealthy", []UpstreamStatus{{Healthy: false, Circuit: "closed"}}, 0, 0},
		{"unprobed-new-entry", []UpstreamStatus{{Healthy: false, Circuit: "closed", Eligible: true}}, 0, 1},
		{"credential-unusable", []UpstreamStatus{{Healthy: true, Circuit: "closed", Eligible: false}}, 1, 0},
	}
	for _, c := range cases {
		h, u := upstreamCounts(c.list)
		if h != c.healthy || u != c.usable {
			t.Errorf("%s: got healthy=%d usable=%d want %d/%d", c.name, h, u, c.healthy, c.usable)
		}
	}
	// The OK derivation an enabled pool uses: all-circuits-open ⇒ not ok.
	if _, usable := upstreamCounts(cases[0].list); usable > 0 {
		t.Fatal("all-circuits-open reported a usable proxy")
	}
}

// TestDiagnoseUpstream_API proves POST + operator RBAC + typed contract, and that
// the response never carries proxy credentials (List() is redacted to host:port).
func TestDiagnoseUpstream_API(t *testing.T) {
	// Viewer is below operator → 403.
	vRec := httptest.NewRecorder()
	apiDiagnoseUpstream(vRec, roleReq(RoleViewer, http.MethodPost, "/api/diagnose/upstream", nil))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST code=%d want 403", vRec.Code)
	}
	// GET is rejected.
	gRec := httptest.NewRecorder()
	apiDiagnoseUpstream(gRec, roleReq(RoleOperator, http.MethodGet, "/api/diagnose/upstream", nil))
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	// Operator POST → 200, typed body, no credential shapes.
	rec := httptest.NewRecorder()
	apiDiagnoseUpstream(rec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/upstream", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("operator POST code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"schema_version"`) || !strings.Contains(body, `"proxies"`) {
		t.Fatalf("body missing typed fields: %s", body)
	}
	// A URL with embedded credentials must never appear (redaction is upstream, but
	// this pins the contract at the diagnose boundary).
	if strings.Contains(body, "@") && strings.Contains(body, "://") {
		t.Fatalf("possible credential in upstream diagnosis body: %s", body)
	}
}

// withStubResolver swaps the DNS seam for the test's duration.
func withStubResolver(t *testing.T, fn func(ctx context.Context, host string) ([]net.IPAddr, error)) {
	t.Helper()
	prev := diagnoseLookupIP
	diagnoseLookupIP = fn
	t.Cleanup(func() { diagnoseLookupIP = prev })
}

// TestDiagnoseDNS_PublicResolves proves a public-resolving host reports the
// addresses and ok=true.
func TestDiagnoseDNS_PublicResolves(t *testing.T) {
	withStubResolver(t, func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	d := diagnoseDNS(context.Background(), "example.com", time.Unix(1_700_000_000, 0))
	if !d.OK || d.Blocked || !d.Resolved {
		t.Fatalf("public host: ok=%v blocked=%v resolved=%v", d.OK, d.Blocked, d.Resolved)
	}
	if len(d.Addresses) != 1 || d.Addresses[0] != "93.184.216.34" {
		t.Fatalf("addresses=%v want [93.184.216.34]", d.Addresses)
	}
}

// TestDiagnoseDNS_PrivateTargetBlocked is the SSRF guard proof: a host resolving to
// a private IP is refused — blocked=true and NO addresses are exposed, so the probe
// cannot be used to map internal infra from the proxy.
func TestDiagnoseDNS_PrivateTargetBlocked(t *testing.T) {
	for _, priv := range []string{"10.0.0.5", "127.0.0.1", "192.168.1.10", "169.254.169.254", "::1"} {
		withStubResolver(t, func(_ context.Context, _ string) ([]net.IPAddr, error) {
			// Mix a public and a private address — a single private hit must block all.
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP(priv)}}, nil
		})
		d := diagnoseDNS(context.Background(), "rebind.evil.example", time.Unix(1_700_000_000, 0))
		if !d.Blocked {
			t.Fatalf("private target %s not blocked: %+v", priv, d)
		}
		if len(d.Addresses) != 0 {
			t.Fatalf("private target %s leaked addresses: %v", priv, d.Addresses)
		}
		if d.OK {
			t.Fatalf("private target %s reported ok", priv)
		}
	}
}

// TestDiagnoseDNS_InvalidHostRejected proves the handler rejects anything that is
// not a bare hostname (defence-in-depth before the resolver is ever called).
func TestDiagnoseDNS_InvalidHostRejected(t *testing.T) {
	called := false
	withStubResolver(t, func(_ context.Context, _ string) ([]net.IPAddr, error) {
		called = true
		return nil, nil
	})
	badHosts := []string{
		"", "http://example.com", "example.com:443", "a/b", "user@host", "has space", "x\ny",
		"_sip._tcp.internal",                 // SRV-style: underscore is not LDH (Codex #779)
		"a..b",                               // empty label
		"host.",                              // trailing dot ⇒ empty final label
		"-lead.example",                      // leading hyphen label
		"trail-.example",                     // trailing hyphen label
		strings.Repeat("a", 64) + ".example", // label > 63 bytes
	}
	for _, bad := range badHosts {
		rec := httptest.NewRecorder()
		apiDiagnoseDNS(rec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/dns", map[string]any{"host": bad}))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("host %q code=%d want 400", bad, rec.Code)
		}
	}
	if called {
		t.Fatal("resolver was invoked for an invalid host — validation must gate before resolution")
	}
}

// TestDiagnoseDNS_API proves POST + operator RBAC and the typed contract.
func TestDiagnoseDNS_API(t *testing.T) {
	withStubResolver(t, func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
	})
	// Viewer < operator → 403.
	vRec := httptest.NewRecorder()
	apiDiagnoseDNS(vRec, roleReq(RoleViewer, http.MethodPost, "/api/diagnose/dns", map[string]any{"host": "example.com"}))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}
	// GET → 405.
	gRec := httptest.NewRecorder()
	apiDiagnoseDNS(gRec, roleReq(RoleOperator, http.MethodGet, "/api/diagnose/dns", nil))
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	// Operator POST → 200 typed.
	rec := httptest.NewRecorder()
	apiDiagnoseDNS(rec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/dns", map[string]any{"host": "example.com"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("operator POST code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"schema_version"`) || !strings.Contains(rec.Body.String(), `"1.1.1.1"`) {
		t.Fatalf("body missing typed fields: %s", rec.Body.String())
	}
}

// TestSummarizeTLSState_SelfSignedUntrusted proves a valid but self-signed chain
// reports handshake_ok + populated leaf but chain_verified=false (not in system
// roots) — the diagnostic surfaces WHY without failing.
func TestSummarizeTLSState_SelfSignedUntrusted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	leaf := makeTestLeaf(t, "test-leaf", "svc.example", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	cs := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{leaf},
	}
	d := summarizeTLSState("svc.example", cs, now)
	if !d.HandshakeOK {
		t.Fatal("handshake_ok should be true")
	}
	if d.ChainVerified {
		t.Fatal("self-signed leaf should NOT verify against system roots")
	}
	if d.Expired {
		t.Fatal("cert within validity should not be expired")
	}
	if d.OK {
		t.Fatal("untrusted chain must not be ok")
	}
	if d.Leaf == nil || !strings.Contains(d.Leaf.Subject, "test-leaf") {
		t.Fatalf("leaf not summarized: %+v", d.Leaf)
	}
	if d.Version != tls.VersionName(tls.VersionTLS13) {
		t.Fatalf("version=%q", d.Version)
	}
	if d.DaysUntilExpiry < 89 || d.DaysUntilExpiry > 90 {
		t.Fatalf("days_until_expiry=%d want ~90", d.DaysUntilExpiry)
	}
}

// TestSummarizeTLSState_Expired proves an expired cert is flagged expired and not ok.
func TestSummarizeTLSState_Expired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	leaf := makeTestLeaf(t, "old", "old.example", now.Add(-90*24*time.Hour), now.Add(-24*time.Hour))
	cs := &tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{leaf}}
	d := summarizeTLSState("old.example", cs, now)
	if !d.Expired {
		t.Fatal("past-NotAfter cert should be expired")
	}
	if d.OK {
		t.Fatal("expired cert must not be ok")
	}
	if d.DaysUntilExpiry > 0 {
		t.Fatalf("days_until_expiry=%d want <= 0", d.DaysUntilExpiry)
	}
}

// TestDiagnoseTLS_PrivateBlocked is the SSRF guard proof: a private/loopback target
// is refused before any handshake — blocked=true, no leaf.
func TestDiagnoseTLS_PrivateBlocked(t *testing.T) {
	for _, target := range []string{"127.0.0.1:443", "10.0.0.1:8443", "192.168.0.1"} {
		d := diagnoseTLS(context.Background(), target, time.Unix(1_700_000_000, 0))
		if !d.Blocked {
			t.Errorf("private target %q not blocked: %+v", target, d)
		}
		if d.HandshakeOK || d.Leaf != nil {
			t.Errorf("private target %q reached handshake", target)
		}
	}
}

// TestDiagnoseTLS_PublicPathViaSeam drives the full path: a public-resolving host
// passes the context-bounded SSRF preflight (Codex #780) and the handshake seam
// yields a ConnectionState that is summarized. No real network.
func TestDiagnoseTLS_PublicPathViaSeam(t *testing.T) {
	withStubResolver(t, func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	now := time.Unix(1_700_000_000, 0).UTC()
	leaf := makeTestLeaf(t, "svc", "svc.example", now.Add(-time.Hour), now.Add(30*24*time.Hour))
	prev := tlsHandshakeProbe
	tlsHandshakeProbe = func(_ context.Context, _, _ string) (*tls.ConnectionState, error) {
		return &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: []*x509.Certificate{leaf}}, nil
	}
	t.Cleanup(func() { tlsHandshakeProbe = prev })

	d := diagnoseTLS(context.Background(), "svc.example:443", now)
	if d.Blocked {
		t.Fatal("public host wrongly blocked")
	}
	if !d.HandshakeOK || d.Leaf == nil {
		t.Fatalf("handshake not summarized: %+v", d)
	}
	if d.Port != "443" || d.Host != "svc.example" {
		t.Fatalf("host/port not carried: %q/%q", d.Host, d.Port)
	}
}

// TestDiagnoseTLS_InvalidTarget proves malformed host:port is rejected without a dial.
func TestDiagnoseTLS_InvalidTarget(t *testing.T) {
	for _, bad := range []string{"_sip._tcp.x:443", "example.com:0", "example.com:70000", "example.com:abc", "bad host:443"} {
		d := diagnoseTLS(context.Background(), bad, time.Unix(1_700_000_000, 0))
		if d.Error == "" || d.Blocked || d.HandshakeOK {
			t.Errorf("invalid target %q not rejected: %+v", bad, d)
		}
	}
}

// TestDiagnoseTLS_API proves POST + operator RBAC + typed contract. The 200 path
// uses a loopback target so the SSRF guard short-circuits before any network I/O.
func TestDiagnoseTLS_API(t *testing.T) {
	vRec := httptest.NewRecorder()
	apiDiagnoseTLS(vRec, roleReq(RoleViewer, http.MethodPost, "/api/diagnose/tls", map[string]any{"host": "example.com:443"}))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}
	gRec := httptest.NewRecorder()
	apiDiagnoseTLS(gRec, roleReq(RoleOperator, http.MethodGet, "/api/diagnose/tls", nil))
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	eRec := httptest.NewRecorder()
	apiDiagnoseTLS(eRec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/tls", map[string]any{"host": ""}))
	if eRec.Code != http.StatusBadRequest {
		t.Fatalf("empty host code=%d want 400", eRec.Code)
	}
	rec := httptest.NewRecorder()
	apiDiagnoseTLS(rec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/tls", map[string]any{"host": "127.0.0.1:443"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("operator POST code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"schema_version"`) || !strings.Contains(rec.Body.String(), `"blocked":true`) {
		t.Fatalf("body missing typed/blocked fields: %s", rec.Body.String())
	}
}

// TestNoShellInDiagnose is the structural no-shell wall (DIAGNOSTIC-COMMAND-FRAMEWORK
// §Absolute rule): the diagnose surface must never import os/exec or spawn a shell.
func TestNoShellInDiagnose(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "diagnose.go"))
	if err != nil {
		t.Fatalf("read diagnose.go: %v", err)
	}
	// The real primitives: a shell can only be spawned via one of these, so
	// scanning for them (not prose like "sh -c", which appears in comments) is the
	// structural gate.
	for _, forbidden := range []string{"os/exec", "exec.Command", "syscall.Exec"} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("diagnose.go references forbidden shell primitive %q — diagnose verbs must be typed operations, never a shell", forbidden)
		}
	}
}
