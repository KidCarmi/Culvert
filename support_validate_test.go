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
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/support"
)

// repackTarGz rewrites a .tgz applying mutate(name, content) to each regular
// file; returning nil content drops the entry. Used to forge tamper scenarios.
func repackTarGz(t *testing.T, tgz []byte, mutate func(name string, b []byte) []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("untar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		if h.Typeflag == tar.TypeReg {
			b = mutate(h.Name, b)
			if b == nil {
				continue
			}
		}
		nh := *h
		nh.Size = int64(len(b))
		if err := tw.WriteHeader(&nh); err != nil {
			t.Fatalf("wh: %v", err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatalf("w: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zw close: %v", err)
	}
	return out.Bytes()
}

// firstHashedSectionPath returns a section path that carries a SHA-256 (an
// actually-collected section) for tamper targeting.
func firstHashedSectionPath(t *testing.T, m *support.SupportBundleManifest) string {
	t.Helper()
	for i := range m.Sections {
		if m.Sections[i].SHA256 != "" {
			return m.Sections[i].Path
		}
	}
	t.Fatal("no hashed section in manifest")
	return ""
}

func TestValidateBundleTar_Clean(t *testing.T) {
	res := buildRealBundle(t)
	v := validateBundleTar(res.TarGz)
	if !v.OK {
		t.Fatalf("clean bundle failed validation: %+v", v)
	}
	if !v.FormatOK || !v.ManifestPresent || v.SectionsChecked == 0 {
		t.Fatalf("validation shape: %+v", v)
	}
	if v.SectionsOK != v.SectionsChecked {
		t.Fatalf("sections_ok=%d checked=%d", v.SectionsOK, v.SectionsChecked)
	}
}

func TestValidateBundleTar_TamperedSectionMismatch(t *testing.T) {
	res := buildRealBundle(t)
	target := firstHashedSectionPath(t, &res.Manifest)
	forged := repackTarGz(t, res.TarGz, func(name string, b []byte) []byte {
		if name == target {
			return append(append([]byte(nil), b...), []byte(`{"injected":true}`)...)
		}
		return b
	})
	v := validateBundleTar(forged)
	if v.OK {
		t.Fatal("tampered section passed validation")
	}
	if len(v.Mismatches) != 1 || v.Mismatches[0].Path != target {
		t.Fatalf("expected one mismatch on %q, got %+v", target, v.Mismatches)
	}
}

func TestValidateBundleTar_MissingSection(t *testing.T) {
	res := buildRealBundle(t)
	target := firstHashedSectionPath(t, &res.Manifest)
	forged := repackTarGz(t, res.TarGz, func(name string, b []byte) []byte {
		if name == target {
			return nil // drop the section file
		}
		return b
	})
	v := validateBundleTar(forged)
	if v.OK {
		t.Fatal("bundle with a dropped section passed validation")
	}
	if len(v.Missing) != 1 || v.Missing[0].Path != target {
		t.Fatalf("expected one missing on %q, got %+v", target, v.Missing)
	}
}

// TestValidateBundleTar_ManifestOnlyTamper proves an edit to manifest.json alone —
// section payloads byte-unchanged — is caught via the manifest self-hash (Codex #782).
func TestValidateBundleTar_ManifestOnlyTamper(t *testing.T) {
	res := buildRealBundle(t)
	forged := repackTarGz(t, res.TarGz, func(name string, b []byte) []byte {
		if name == support.ManifestName {
			var m support.SupportBundleManifest
			if json.Unmarshal(b, &m) != nil {
				t.Fatal("manifest parse")
			}
			m.CaseID = "FORGED-CASE" // edit a field WITHOUT recomputing manifest_sha256
			nb, _ := json.MarshalIndent(m, "", "  ")
			return nb
		}
		return b
	})
	v := validateBundleTar(forged)
	if v.ManifestHashOK {
		t.Fatal("manifest self-hash matched after a manifest-only edit")
	}
	if v.OK {
		t.Fatal("manifest-only tamper passed validation")
	}
}

// TestValidateBundleTar_DuplicateEntryRejected proves a tar carrying a second
// (forged) manifest.json is rejected rather than silently overriding (Codex #782).
func TestValidateBundleTar_DuplicateEntryRejected(t *testing.T) {
	res := buildRealBundle(t)
	// Append a duplicate manifest.json after the originals.
	var mBytes []byte
	for name, b := range extractTarGz(t, res.TarGz) {
		if name == support.ManifestName {
			mBytes = b
		}
	}
	if mBytes == nil {
		t.Fatal("no manifest to duplicate")
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	// Re-emit the original archive, then append a duplicate manifest entry.
	gz, _ := gzip.NewReader(bytes.NewReader(res.TarGz))
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("untar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		nh := *h
		nh.Size = int64(len(b))
		_ = tw.WriteHeader(&nh)
		_, _ = tw.Write(b)
	}
	dupHdr := &tar.Header{Name: support.ManifestName, Mode: 0o600, Size: int64(len(mBytes)), Typeflag: tar.TypeReg}
	_ = tw.WriteHeader(dupHdr)
	_, _ = tw.Write(mBytes)
	_ = tw.Close()
	_ = zw.Close()

	v := validateBundleTar(out.Bytes())
	if v.OK || v.Error == "" {
		t.Fatalf("duplicate manifest entry not rejected: %+v", v)
	}
	if !strings.Contains(v.Error, "duplicate") {
		t.Fatalf("error=%q want a duplicate-entry rejection", v.Error)
	}
}

func TestValidateBundleTar_GarbageInput(t *testing.T) {
	v := validateBundleTar([]byte("not a gzip stream"))
	if v.OK || v.Error == "" {
		t.Fatalf("garbage input should fail with an error: %+v", v)
	}
}

// TestSupportBundleValidate_API proves the endpoint: GET viewer, 404 unknown,
// 400 malformed id, and a clean persisted bundle validates ok.
func TestSupportBundleValidate_API(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	res, err := createSupportBundle(context.Background(), "standard", support.L1, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Clean bundle → ok.
	r := httptest.NewRequest(http.MethodGet, "/api/support/bundles/"+res.BundleID+"/validate", http.NoBody)
	r.SetPathValue("id", res.BundleID)
	rec := httptest.NewRecorder()
	apiSupportBundleValidate(rec, withRoleCtx(r, RoleViewer))
	if rec.Code != http.StatusOK {
		t.Fatalf("validate code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	var v bundleValidation
	if json.Unmarshal(rec.Body.Bytes(), &v) != nil || !v.OK {
		t.Fatalf("clean bundle not ok via API: %s", rec.Body.String())
	}

	// Unknown-but-well-formed id → 404.
	r2 := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	r2.SetPathValue("id", "csb_aaaaaaaaaaaaaaaaaaaaaaaaaa")
	rec2 := httptest.NewRecorder()
	apiSupportBundleValidate(rec2, withRoleCtx(r2, RoleViewer))
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("unknown id code=%d want 404", rec2.Code)
	}

	// Malformed id → 400.
	r3 := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	r3.SetPathValue("id", "../etc/passwd")
	rec3 := httptest.NewRecorder()
	apiSupportBundleValidate(rec3, withRoleCtx(r3, RoleViewer))
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("malformed id code=%d want 400", rec3.Code)
	}
}
