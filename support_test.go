package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// buildRealBundle assembles a bundle over the process-registered collectors
// (product + diagnostics) with no disk dependency.
func buildRealBundle(t *testing.T) *support.BuildResult {
	t.Helper()
	res, err := support.NewRunner().Build(context.Background(), support.BuildOptions{
		Version: version, GoVersion: runtime.Version(),
		Runtime: support.RuntimeInfo{NodeID: "test-node", Role: "standalone", Runtime: "compose"},
		Level:   support.L1, Nonce: "test-nonce", Clock: time.Now,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return res
}

func extractTarGz(t *testing.T, tgz []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = b
	}
	return out
}

func TestSupportBundle_MandatorySectionsPresent(t *testing.T) {
	res := buildRealBundle(t)
	if res.Manifest.Format != support.BundleFormat {
		t.Fatalf("format=%s want %s", res.Manifest.Format, support.BundleFormat)
	}
	ids := map[string]support.SectionEntry{}
	for _, s := range res.Manifest.Sections {
		ids[s.ID] = s
	}
	for _, want := range []string{"product", "health", "readiness", "diagnostics"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("manifest missing mandatory section %q", want)
		}
	}
	// readiness is declared PUBLIC; health is INTERNAL. Confirm the engine
	// records the actual post-redaction class per section.
	if c := ids["readiness"].ClassMax; c != "PUBLIC" {
		t.Fatalf("readiness class_max=%q want PUBLIC", c)
	}
	if c := ids["health"].ClassMax; c != "INTERNAL" {
		t.Fatalf("health class_max=%q want INTERNAL", c)
	}
	files := extractTarGz(t, res.TarGz)
	if _, ok := files[support.ManifestName]; !ok {
		t.Fatal("bundle missing manifest.json")
	}
	// product is L0/PUBLIC and must always succeed → its section file is present.
	if _, ok := files["sections/product.json"]; !ok {
		t.Fatal("bundle missing sections/product.json")
	}
	if !bytes.Contains(files["sections/product.json"], []byte(version)) {
		t.Fatal("product section does not report the version")
	}
}

// TestNoSecretInBundle is the seeded secret-leak wall for the Slice-1 sections.
// It decompresses the bundle and asserts no secret SHAPES appear in any section,
// and that the fail-closed redaction posture is recorded.
func TestNoSecretInBundle(t *testing.T) {
	res := buildRealBundle(t)
	files := extractTarGz(t, res.TarGz)

	// Concatenate every SECTION payload (not the manifest, which legitimately
	// contains hashes) and assert no credential shapes survived.
	var sections []byte
	for name, body := range files {
		if strings.HasPrefix(name, "sections/") {
			sections = append(sections, body...)
		}
	}
	// Match actual credential MATERIAL shapes, not English prose: a diagnostic
	// message may legitimately mention "private key" while carrying no key bytes.
	lower := bytes.ToLower(sections)
	for _, marker := range []string{"-----begin", "$2a$", "$2b$", "$2y$", "aws_secret", "hmac_key="} {
		if bytes.Contains(lower, []byte(marker)) {
			t.Fatalf("secret-shaped material %q found in a bundle section", marker)
		}
	}

	if !res.Manifest.Redaction.FailClosed {
		t.Fatal("manifest must record fail_closed=true")
	}
	for _, s := range res.Manifest.Sections {
		switch s.ClassMax {
		case "PUBLIC", "INTERNAL":
			// shareable
		default:
			t.Fatalf("section %s has class_max %q (must be <= INTERNAL for a shareable bundle)", s.ID, s.ClassMax)
		}
	}
}

// TestReusedCollectors_SectionsPresent locks the M1 reused-accessor collectors
// into a standard (L1) bundle.
func TestReusedCollectors_SectionsPresent(t *testing.T) {
	res := buildRealBundle(t)
	ids := map[string]bool{}
	for _, s := range res.Manifest.Sections {
		ids[s.ID] = true
	}
	for _, want := range []string{"config", "policy", "audit", "metrics", "logs"} {
		if !ids[want] {
			t.Errorf("standard bundle missing reused-accessor section %q", want)
		}
	}
}

// TestReusedSections_IdentifiersMasked proves the SENSITIVE-classified live
// identifiers (client IP, identity, destination host, full URI, audit actor/detail)
// are masked to salted tokens, never emitted raw — the fail-closed M1 posture.
func TestReusedSections_IdentifiersMasked(t *testing.T) {
	rd := redaction.NewWithSalt([]byte("fixed-salt"))
	le := logEntrySummary{
		IP: "203.0.113.9", Identity: "alice@corp.example", Host: "secret-host.internal",
		URI: "https://secret-host.internal/private", Method: "GET", Status: "OK",
	}
	out, _ := json.Marshal(rd.Struct(le))
	for _, raw := range []string{"203.0.113.9", "alice@corp.example", "secret-host.internal"} {
		if strings.Contains(string(out), raw) {
			t.Fatalf("log identifier %q leaked unmasked: %s", raw, out)
		}
	}
	if !strings.Contains(string(out), "mask_") {
		t.Fatalf("log identifiers were not masked: %s", out)
	}
	ae := auditEntrySummary{Time: "t", Actor: "10.9.8.7", Action: "x.y", Detail: "raw-detail-blob"}
	aout, _ := json.Marshal(rd.Struct(ae))
	for _, raw := range []string{"10.9.8.7", "raw-detail-blob"} {
		if strings.Contains(string(aout), raw) {
			t.Fatalf("audit field %q leaked unmasked: %s", raw, aout)
		}
	}
}

// TestSupportReport_PersistedAndServed proves the redaction report is persisted
// next to the manifest (counts-only, with the scrubbed tally) and served by the
// preview endpoint without unpacking the bundle.
func TestSupportReport_PersistedAndServed(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	res, err := createSupportBundle(context.Background())
	if err != nil {
		t.Fatalf("createSupportBundle: %v", err)
	}
	// Persisted on disk, counts-only, includes the scrubbed key.
	b, err := os.ReadFile(filepath.Join(supportBundlesDir(), res.BundleID, support.RedactionReportName))
	if err != nil {
		t.Fatalf("report not persisted: %v", err)
	}
	if !bytes.Contains(b, []byte(`"scrubbed"`)) {
		t.Fatalf("report missing scrubbed tally: %s", b)
	}
	var rep support.RedactionReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !rep.FailClosed || len(rep.Sections) == 0 {
		t.Fatalf("report shape: fail_closed=%v sections=%d", rep.FailClosed, len(rep.Sections))
	}

	// Endpoint: valid id → 200 with the report.
	req := httptest.NewRequest(http.MethodGet, "/api/support/bundles/"+res.BundleID+"/redaction-report", nil)
	req.SetPathValue("id", res.BundleID)
	rec := httptest.NewRecorder()
	apiSupportBundleReport(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"scrubbed"`) {
		t.Fatalf("endpoint code=%d body=%q", rec.Code, rec.Body.String())
	}
	// Unknown-but-well-formed id → 404 (a pre-report bundle behaves the same).
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.SetPathValue("id", "csb_aaaaaaaaaaaaaaaaaaaaaaaaaa")
	rec2 := httptest.NewRecorder()
	apiSupportBundleReport(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("missing report code=%d want 404", rec2.Code)
	}
	// Malformed id → 400.
	req3 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req3.SetPathValue("id", "../etc/passwd")
	rec3 := httptest.NewRecorder()
	apiSupportBundleReport(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("malformed id code=%d want 400", rec3.Code)
	}
}

// supportRoleReq builds a path-valued request carrying an injected admin-UI role
// (handlers are RBAC-gated; a bare request defaults to viewer).
func supportRoleReq(method, id string, role UIRole) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "/x", nil)
	req.SetPathValue("id", id)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, role))
	return req, httptest.NewRecorder()
}

// TestSupportBundle_PreviewGate proves the mandatory-preview lifecycle: a new
// bundle is PENDING (download 409) until an admin approves it, after which it is
// READY (download 200). Absent state grandfathers to READY; approve on a missing
// bundle 404s.
func TestSupportBundle_PreviewGate(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	res, err := createSupportBundle(context.Background())
	if err != nil {
		t.Fatalf("createSupportBundle: %v", err)
	}
	download := func() int {
		req, rec := supportRoleReq(http.MethodGet, res.BundleID, RoleOperator)
		apiSupportBundleItem(rec, req)
		return rec.Code
	}
	// Pending → download blocked with 409 (gate, not RBAC — operator is allowed).
	if code := download(); code != http.StatusConflict {
		t.Fatalf("pending download code=%d want 409", code)
	}
	// Approve (admin) → 204.
	areq, arec := supportRoleReq(http.MethodPost, res.BundleID, RoleAdmin)
	apiSupportBundleApprove(arec, areq)
	if arec.Code != http.StatusNoContent {
		t.Fatalf("approve code=%d body=%q", arec.Code, arec.Body.String())
	}
	// Ready → download 200.
	if code := download(); code != http.StatusOK {
		t.Fatalf("approved download code=%d want 200", code)
	}
	// An operator cannot approve (admin-gated).
	oreq, orec := supportRoleReq(http.MethodPost, res.BundleID, RoleOperator)
	apiSupportBundleApprove(orec, oreq)
	if orec.Code != http.StatusForbidden {
		t.Fatalf("operator approve code=%d want 403", orec.Code)
	}
	// Absent state file grandfathers to ready.
	if st := readBundleState("csb_absentnostatefilehere00"); st.State != bundleStateReady {
		t.Fatalf("absent-state grandfather=%q want ready", st.State)
	}
	// Approve on a well-formed but nonexistent bundle → 404.
	nreq, nrec := supportRoleReq(http.MethodPost, "csb_aaaaaaaaaaaaaaaaaaaaaaaaaa", RoleAdmin)
	apiSupportBundleApprove(nrec, nreq)
	if nrec.Code != http.StatusNotFound {
		t.Fatalf("approve missing code=%d want 404", nrec.Code)
	}
}

// TestBundlePermissions0600 is the M1 security gate: a persisted bundle must live
// in a 0700 dir with 0600 files — the bundle carries INTERNAL sections and must
// not be world/group-readable on the appliance FS.
func TestBundlePermissions0600(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	res, err := createSupportBundle(context.Background())
	if err != nil {
		t.Fatalf("createSupportBundle: %v", err)
	}
	dir := filepath.Join(supportBundlesDir(), res.BundleID)
	if fi, err := os.Stat(dir); err != nil {
		t.Fatalf("stat bundle dir: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("bundle dir perm=%o want 0700", perm)
	}
	for _, name := range []string{"bundle.csb.tgz", "manifest.json"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s perm=%o want 0600", name, perm)
		}
	}
	// No temp/partial artifact should survive a successful persist.
	if _, err := os.Stat(filepath.Join(dir, "manifest.json.tmp")); !os.IsNotExist(err) {
		t.Fatalf("manifest.json.tmp should not survive a committed bundle (err=%v)", err)
	}
}

// TestSupportBundle_RecoveryOneShot exercises `culvert --support-bundle <path>`:
// a headless L0 bundle written to disk with no server running.
func TestSupportBundle_RecoveryOneShot(t *testing.T) {
	out := filepath.Join(t.TempDir(), "recovery.csb.tgz")
	if err := runSupportBundleCommand(out); err != nil {
		t.Fatalf("runSupportBundleCommand: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	files := extractTarGz(t, data)
	if _, ok := files[support.ManifestName]; !ok {
		t.Fatal("recovery bundle missing manifest.json")
	}
	if _, ok := files["sections/product.json"]; !ok {
		t.Fatal("recovery bundle missing sections/product.json")
	}
	var man support.SupportBundleManifest
	if err := json.Unmarshal(files[support.ManifestName], &man); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if man.Format != support.BundleFormat {
		t.Fatalf("format=%s", man.Format)
	}
	// At L0 the diagnostics collector (MinLevel L1) must be gated out, not run.
	for _, s := range man.Sections {
		if s.ID == "diagnostics" && s.Status != support.StatusSkipped {
			t.Fatalf("diagnostics must be skipped at L0, got %s", s.Status)
		}
	}
}
