package main

// D1.3b.1 — restore dry-run validation.
//
// Validates a backup tarball produced by D1.3a (PR #192) without writing
// anything to /data. Re-runs the same parse/cross-validation logic the
// real loaders apply, plus tarball-level checks (manifest schema,
// bidirectional presence, sha256/size/mode, cluster CA cross-validation,
// ca.bundle decrypt). Prints a restore plan summary on success.
//
// D1.3b.2 will add --confirm + the destructive commit path; this PR
// proves the validator first.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// restoreSchemaVersion is the manifest envelope version this PR accepts.
// Must match D1.3a's backupSchemaVersion. D1.3b.2/c may add migration
// logic; D1.3b.1 rejects any other value.
const restoreSchemaVersion = 1

// restoreSummary is the data shape printed by printRestoreSummary and
// returned to tests for assertion.
type restoreSummary struct {
	BackupPath        string
	SchemaVersion     int
	CreatedAt         string
	CulvertVersion    string
	TotalFiles        int
	Tier1Files        int
	Tier2Files        int
	AdminCount        int    // from ui_users.json (RoleAdmin entries)
	EnrolledDPCount   int    // from cluster.json (len(state.Nodes))
	CAFingerprint     string // sha256 of cluster-ca.crt's parsed cert.Raw
	CABundleEncrypted bool   // true if ca.bundle starts with caMagic
}

// runRestoreDryRun is the CLI entrypoint. Validates tarPath end-to-end,
// prints a plan to stdout on success, returns an error on any rule
// failure. Never writes to dataDir.
func runRestoreDryRun(tarPath, dataDir, passphrase string) error {
	summary, err := validateBackup(tarPath, dataDir, passphrase)
	if err != nil {
		return err
	}
	printRestoreSummary(os.Stdout, summary)
	return nil
}

// validateBackup runs every D1.3b.1 rule against the tarball at tarPath.
// dataDir is reserved for D1.3b.2's pre-commit cross-checks; D1.3b.1
// does not read it.
func validateBackup(tarPath, _ /*dataDir*/, passphrase string) (*restoreSummary, error) {
	files, order, err := readTarball(tarPath)
	if err != nil {
		return nil, err
	}

	manifest, err := parseAndValidateManifest(files, order)
	if err != nil {
		return nil, err
	}

	if err := validateBidirectionalPresence(manifest, files); err != nil {
		return nil, err
	}

	if err := validateFileChecksumsAndModes(manifest, files); err != nil {
		return nil, err
	}

	summary := &restoreSummary{
		BackupPath:     tarPath,
		SchemaVersion:  manifest.SchemaVersion,
		CreatedAt:      manifest.CreatedAt,
		CulvertVersion: manifest.CulvertVersion,
		TotalFiles:     len(manifest.Files),
	}
	for _, f := range manifest.Files {
		if f.Required {
			summary.Tier1Files++
		} else {
			summary.Tier2Files++
		}
	}

	if err := validateTier1Artifacts(files, passphrase, summary); err != nil {
		return nil, err
	}

	return summary, nil
}

// readTarball opens path, gunzips, reads every entry into memory, and
// returns the file map + header order. Path-traversal-guards every entry.
func readTarball(path string) (map[string][]byte, []string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-controlled path
	if err != nil {
		return nil, nil, fmt.Errorf("restore: open tarball: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var order []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("restore: tar read: %w", err)
		}
		// Absolute-path guard: tar entries must be relative under the
		// backup namespace. Reject anything starting with "/" so a
		// hand-crafted tarball can't try to write outside /data on
		// extraction (defense in depth — D1.3b.1 doesn't extract,
		// but the contract is shared with D1.3b.2 which will).
		if strings.HasPrefix(hdr.Name, "/") {
			return nil, nil, fmt.Errorf("restore: tarball entry has absolute path: %q", hdr.Name)
		}
		// Path-traversal guard: reject any component equal to "..".
		for _, part := range strings.Split(hdr.Name, "/") {
			if part == ".." {
				return nil, nil, fmt.Errorf("restore: tarball entry has path traversal: %q", hdr.Name)
			}
		}
		// Duplicate-entry guard: tar format allows multiple headers with
		// the same name; a map-based reader would silently overwrite the
		// earlier entry. Fail closed instead.
		if _, exists := files[hdr.Name]; exists {
			return nil, nil, fmt.Errorf("restore: duplicate tarball entry: %q", hdr.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, fmt.Errorf("restore: read %q: %w", hdr.Name, err)
		}
		files[hdr.Name] = body
		order = append(order, hdr.Name)
	}
	return files, order, nil
}

func parseAndValidateManifest(files map[string][]byte, order []string) (*backupManifest, error) {
	manifestBytes, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("restore: manifest.json missing from tarball")
	}
	if len(order) == 0 || order[0] != "manifest.json" {
		return nil, fmt.Errorf("restore: manifest.json must be the first tarball entry")
	}

	var manifest backupManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("restore: manifest unmarshal: %w", err)
	}
	if manifest.SchemaVersion != restoreSchemaVersion {
		return nil, fmt.Errorf("restore: unsupported schema_version %d (expected %d)", manifest.SchemaVersion, restoreSchemaVersion)
	}
	if manifest.CreatedAt == "" {
		return nil, fmt.Errorf("restore: manifest missing created_at")
	}
	if manifest.CulvertVersion == "" {
		return nil, fmt.Errorf("restore: manifest missing culvert_version")
	}
	if len(manifest.Files) == 0 {
		return nil, fmt.Errorf("restore: manifest contains no files (empty backup cannot restore)")
	}
	return &manifest, nil
}

func validateBidirectionalPresence(manifest *backupManifest, files map[string][]byte) error {
	// Forward: every manifest entry must be in the tarball; no duplicates.
	seen := map[string]bool{}
	for _, f := range manifest.Files {
		if seen[f.Path] {
			return fmt.Errorf("restore: duplicate manifest path: %q", f.Path)
		}
		seen[f.Path] = true
		if _, ok := files[f.Path]; !ok {
			return fmt.Errorf("restore: manifest references %q but missing from tarball", f.Path)
		}
	}
	// Reverse: every tarball entry (except manifest.json) must be in the manifest.
	for name := range files {
		if name == "manifest.json" {
			continue
		}
		if !seen[name] {
			return fmt.Errorf("restore: tarball contains %q but not referenced by manifest", name)
		}
	}
	return nil
}

func validateFileChecksumsAndModes(manifest *backupManifest, files map[string][]byte) error {
	for _, f := range manifest.Files {
		body := files[f.Path]
		if int64(len(body)) != f.Size {
			return fmt.Errorf("restore: %q size mismatch: manifest=%d tarball=%d", f.Path, f.Size, len(body))
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("restore: %q sha256 mismatch", f.Path)
		}
		if _, err := strconv.ParseInt(f.Mode, 8, 32); err != nil {
			return fmt.Errorf("restore: %q invalid mode %q: %w", f.Path, f.Mode, err)
		}
	}
	return nil
}

// validateTier1Artifacts runs per-artifact parse for every Tier 1 file
// present in the tarball. Each validator reuses the underlying parse
// logic from the real loaders so "valid for restore" matches "valid at
// startup."
func validateTier1Artifacts(files map[string][]byte, passphrase string, summary *restoreSummary) error {
	if body, ok := files["data/ui_users.json"]; ok {
		adminCount, err := validateUIUsersJSON(body)
		if err != nil {
			return fmt.Errorf("restore: ui_users.json: %w", err)
		}
		summary.AdminCount = adminCount
	}

	if body, ok := files["data/cluster.json"]; ok {
		dpCount, err := validateClusterJSON(body)
		if err != nil {
			return fmt.Errorf("restore: cluster.json: %w", err)
		}
		summary.EnrolledDPCount = dpCount
	}

	certBody, hasCert := files["data/cluster-ca.crt"]
	keyBody, hasKey := files["data/cluster-ca.key"]
	switch {
	case hasCert && hasKey:
		ca := &clusterCA{}
		if err := ca.loadFromPEM(certBody, keyBody); err != nil {
			return fmt.Errorf("restore: cluster CA pair: %w", err)
		}
		if ca.cert != nil {
			fp := sha256.Sum256(ca.cert.Raw)
			summary.CAFingerprint = "sha256:" + hex.EncodeToString(fp[:])
		}
	case hasCert != hasKey:
		return fmt.Errorf("restore: cluster CA partial pair in tarball (cert=%v key=%v)", hasCert, hasKey)
	}

	if body, ok := files["data/ca.bundle"]; ok {
		summary.CABundleEncrypted = len(body) >= 5 && [4]byte(body[:4]) == caMagic
		if err := validateCABundle(body, passphrase); err != nil {
			return fmt.Errorf("restore: ca.bundle: %w", err)
		}
	}
	return nil
}

func validateUIUsersJSON(data []byte) (int, error) {
	// Mirrors LoadUIUsersFile: try envelope, fall back to bare-array.
	var env uiUsersFileEnvelope
	if err := json.Unmarshal(data, &env); err == nil && env.Users != nil {
		return countAdmins(env.Users), nil
	}
	var records []uiUserRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return 0, fmt.Errorf("parse: %w", err)
	}
	return countAdmins(records), nil
}

func countAdmins(records []uiUserRecord) int {
	n := 0
	for _, r := range records {
		if r.Role == RoleAdmin {
			n++
		}
	}
	return n
}

func validateClusterJSON(data []byte) (int, error) {
	var st ClusterState
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, fmt.Errorf("parse: %w", err)
	}
	return len(st.Nodes), nil
}

func validateCABundle(data []byte, passphrase string) error {
	var plaintext []byte
	if len(data) >= 5 && [4]byte(data[:4]) == caMagic {
		// Encrypted bundle.
		if passphrase == "" {
			return fmt.Errorf("encrypted bundle but no passphrase available (set CULVERT_CA_PASSPHRASE)")
		}
		var err error
		plaintext, err = decryptBundle(data, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
	} else {
		plaintext = data
	}
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.importBundle(plaintext); err != nil {
		return fmt.Errorf("import: %w", err)
	}
	return nil
}

// printRestoreSummary writes the dry-run plan in a fixed shape so tests
// can assert on key lines. Uses fmt.Fprintf rather than logger because
// runRestoreDryRun is a one-shot CLI command that runs before logger
// initialization.
func printRestoreSummary(w io.Writer, s *restoreSummary) {
	fmt.Fprintf(w, "Restore plan (dry-run):\n\n")
	fmt.Fprintf(w, "Backup metadata:\n")
	fmt.Fprintf(w, "  Source:           %s\n", s.BackupPath)
	fmt.Fprintf(w, "  Schema version:   %d\n", s.SchemaVersion)
	fmt.Fprintf(w, "  Created at:       %s\n", s.CreatedAt)
	fmt.Fprintf(w, "  Culvert version:  %s\n", s.CulvertVersion)
	fmt.Fprintf(w, "\nManifest:\n")
	fmt.Fprintf(w, "  Files total:         %d\n", s.TotalFiles)
	fmt.Fprintf(w, "  Required (Tier 1):   %d\n", s.Tier1Files)
	fmt.Fprintf(w, "  Optional (Tier 2):   %d\n", s.Tier2Files)
	fmt.Fprintf(w, "\nValidation: PASS\n")
	if s.AdminCount > 0 {
		fmt.Fprintf(w, "  ui_users.json:                %d admin account(s)\n", s.AdminCount)
	}
	if s.EnrolledDPCount > 0 {
		fmt.Fprintf(w, "  cluster.json:                 %d enrolled DP(s)\n", s.EnrolledDPCount)
	}
	if s.CAFingerprint != "" {
		fmt.Fprintf(w, "  cluster CA cross-validation:  PASS (%s)\n", s.CAFingerprint)
	}
	if s.CABundleEncrypted {
		fmt.Fprintf(w, "  ca.bundle decrypt:            PASS (encrypted)\n")
	}
	fmt.Fprintf(w, "\nThis was a dry-run. No files were written. /data unchanged.\n")
	fmt.Fprintf(w, "D1.3b.2 will add --confirm to commit a restore.\n")
}
