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

// untarSupportBundleFiles reads a bounded tar stream (the caller's
// io.LimitReader defuses a decompression bomb) into an in-memory name→bytes
// map. Returns a non-empty errMsg — pre-formatted exactly as validateBundleTar
// used to inline it — on any read failure or duplicate entry name: a
// well-formed csb/1 has no duplicates, and silently letting a later entry
// override an earlier one would let an attacker append a second forged
// manifest (or section) that the map read then compares against.
func untarSupportBundleFiles(tr *tar.Reader) (files map[string][]byte, errMsg string) {
	files = map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "untar: " + err.Error()
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, "read: " + err.Error()
		}
		if _, dup := files[h.Name]; dup {
			return nil, "duplicate tar entry: " + h.Name
		}
		files[h.Name] = b
	}
	return files, ""
}

// manifestSelfHashOK re-derives integrity.manifest_sha256 over the manifest
// with its integrity fields zeroed (json.MarshalIndent, 2-space) — mirroring
// how the runner computed it — and reports whether it matches. This is a
// self-referential check, not a signature: it catches a manifest-only edit
// (case_id, a section's status/class, collector metadata) even when every
// section payload is byte-unchanged; cryptographic manifest signing is later.
func manifestSelfHashOK(man support.SupportBundleManifest) bool {
	expectedMH := man.Integrity.ManifestSHA256
	if expectedMH == "" {
		return false
	}
	manForHash := man
	manForHash.Integrity = support.IntegrityInfo{}
	preHash, err := json.MarshalIndent(manForHash, "", "  ")
	if err != nil {
		return false
	}
	sum := sha256.Sum256(preHash)
	return hex.EncodeToString(sum[:]) == expectedMH
}

// checkBundleSection re-hashes one manifest-recorded section against its
// actual tar bytes and reports the outcome as a sectionCheck plus whether it
// passed. A section with no recorded SHA256 (failed/skipped — nothing was
// written) has nothing to check and is reported via the ok bool alone.
func checkBundleSection(s *support.SectionEntry, files map[string][]byte) (check sectionCheck, checked, ok bool) {
	if s.SHA256 == "" {
		return sectionCheck{}, false, false
	}
	content, present := files[s.Path]
	if !present {
		return sectionCheck{ID: s.ID, Path: s.Path, Status: "missing", ExpectedSHA: s.SHA256}, true, false
	}
	sum := sha256.Sum256(content)
	actual := hex.EncodeToString(sum[:])
	if actual != s.SHA256 {
		return sectionCheck{ID: s.ID, Path: s.Path, Status: "mismatch", ExpectedSHA: s.SHA256, ActualSHA: actual}, true, false
	}
	return sectionCheck{}, true, true
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
	tr := tar.NewReader(io.LimitReader(gz, maxValidateDecompressed))
	files, errMsg := untarSupportBundleFiles(tr)
	if errMsg != "" {
		v.Error = errMsg
		return v
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
	v.ManifestHashOK = manifestSelfHashOK(man)

	for i := range man.Sections {
		s := &man.Sections[i]
		check, checked, sectionOK := checkBundleSection(s, files)
		if !checked {
			continue // failed/skipped section — nothing was written, nothing to hash
		}
		v.SectionsChecked++
		switch {
		case sectionOK:
			v.SectionsOK++
		case check.Status == "missing":
			v.Missing = append(v.Missing, check)
		default:
			v.Mismatches = append(v.Mismatches, check)
		}
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
