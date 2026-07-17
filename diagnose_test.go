package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
		{"all-open", []UpstreamStatus{{Healthy: true, Circuit: "open"}, {Healthy: true, Circuit: "open"}}, 2, 0},
		{"mixed", []UpstreamStatus{{Healthy: true, Circuit: "open"}, {Healthy: true, Circuit: "closed"}}, 2, 1},
		{"half-open-usable", []UpstreamStatus{{Healthy: true, Circuit: "half-open"}}, 1, 1},
		{"unhealthy", []UpstreamStatus{{Healthy: false, Circuit: "closed"}}, 0, 0},
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

// TestNoShellInDiagnose is the structural no-shell wall (DIAGNOSTIC-COMMAND-FRAMEWORK
// §Absolute rule): the diagnose surface must never import os/exec or spawn a shell.
func TestNoShellInDiagnose(t *testing.T) {
	src, err := os.ReadFile("diagnose.go")
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
