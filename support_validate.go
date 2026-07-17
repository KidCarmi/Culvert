package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/support"
)

// Bundle integrity validation (M4). A persisted csb/1 bundle records a SHA-256 for
// every collected section in its manifest. validateBundleTar re-derives those
// hashes from the tar's own bytes and compares — so a tampered or truncated
// section (or a swapped manifest) is detected offline, with no crypto and no
// network. This is the tamper-detect gate: the verdict is read-only integrity
// metadata (section ids + booleans), never section content, so it is viewer-safe.

// maxValidateDecompressed bounds the untar to defuse a decompression bomb on a
// hostile/tampered file. Real bundles are far smaller (collector byte budgets).
const maxValidateDecompressed = 128 << 20 // 128 MiB

type sectionCheck struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Status      string `json:"status"` // ok|mismatch|missing
	ExpectedSHA string `json:"expected_sha,omitempty"`
	ActualSHA   string `json:"actual_sha,omitempty"`
}

type bundleValidation struct {
	BundleID        string         `json:"bundle_id"`
	Format          string         `json:"format"`
	FormatOK        bool           `json:"format_ok"`
	ManifestPresent bool           `json:"manifest_present"`
	ManifestHashOK  bool           `json:"manifest_hash_ok"` // integrity.manifest_sha256 re-derives
	SectionsChecked int            `json:"sections_checked"`
	SectionsOK      int            `json:"sections_ok"`
	Mismatches      []sectionCheck `json:"mismatches,omitempty"`
	Missing         []sectionCheck `json:"missing,omitempty"`
	OK              bool           `json:"ok"`
	Error           string         `json:"error,omitempty"`
}

// validateBundleTar re-hashes each manifest-recorded section against the tar's
// actual bytes. Pure (no I/O beyond the in-memory reader) so it is fully testable.
func validateBundleTar(tgz []byte) bundleValidation {
	v := bundleValidation{}
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		v.Error = "gunzip: " + err.Error()
		return v
	}
	defer gz.Close() //nolint:errcheck // read-only reader

	// Untar into a bounded in-memory map. LimitReader caps total decompressed size
	// so a tampered tar cannot exhaust memory.
	files := map[string][]byte{}
	tr := tar.NewReader(io.LimitReader(gz, maxValidateDecompressed))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			v.Error = "untar: " + err.Error()
			return v
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			v.Error = "read: " + err.Error()
			return v
		}
		// Reject duplicate names: a well-formed csb/1 has none, and silently letting
		// a later entry override an earlier one would let an attacker append a second
		// forged manifest (or section) that the map read then compares against.
		if _, dup := files[h.Name]; dup {
			v.Error = "duplicate tar entry: " + h.Name
			return v
		}
		files[h.Name] = b
	}

	mb, ok := files[support.ManifestName]
	if !ok {
		v.Error = "manifest absent from bundle"
		return v
	}
	v.ManifestPresent = true
	var man support.SupportBundleManifest
	if err := json.Unmarshal(mb, &man); err != nil {
		v.Error = "manifest parse: " + err.Error()
		return v
	}
	v.BundleID = man.BundleID
	v.Format = man.Format
	v.FormatOK = man.Format == support.BundleFormat

	// Manifest self-hash: the runner records integrity.manifest_sha256 over the
	// manifest with its integrity fields zeroed (json.MarshalIndent, 2-space).
	// Re-derive it the same way so a manifest-only edit (case_id, a section's
	// status/class, collector metadata) is caught even when every section payload
	// is byte-unchanged. (This is a self-referential check, not a signature — it
	// catches corruption/naive tampering; cryptographic manifest signing is later.)
	expectedMH := man.Integrity.ManifestSHA256
	manForHash := man
	manForHash.Integrity = support.IntegrityInfo{}
	preHash, mErr := json.MarshalIndent(manForHash, "", "  ")
	if mErr == nil && expectedMH != "" {
		sum := sha256.Sum256(preHash)
		v.ManifestHashOK = hex.EncodeToString(sum[:]) == expectedMH
	}

	for i := range man.Sections {
		s := &man.Sections[i]
		if s.SHA256 == "" {
			continue // failed/skipped section — nothing was written, nothing to hash
		}
		v.SectionsChecked++
		content, present := files[s.Path]
		if !present {
			v.Missing = append(v.Missing, sectionCheck{ID: s.ID, Path: s.Path, Status: "missing", ExpectedSHA: s.SHA256})
			continue
		}
		sum := sha256.Sum256(content)
		actual := hex.EncodeToString(sum[:])
		if actual != s.SHA256 {
			v.Mismatches = append(v.Mismatches, sectionCheck{ID: s.ID, Path: s.Path, Status: "mismatch", ExpectedSHA: s.SHA256, ActualSHA: actual})
			continue
		}
		v.SectionsOK++
	}
	v.OK = v.FormatOK && v.ManifestPresent && v.ManifestHashOK && len(v.Mismatches) == 0 && len(v.Missing) == 0
	return v
}

// apiSupportBundleValidate re-derives and checks a persisted bundle's section
// hashes against its manifest (GET, viewer — the verdict carries no section
// content, only integrity metadata).
func apiSupportBundleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	tgz, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"))
	if err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}
	v := validateBundleTar(tgz)
	v.BundleID = id // authoritative id is the path segment, not the manifest field
	jsonOK(w, v)
}
