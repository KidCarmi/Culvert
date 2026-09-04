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
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
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
	// 2F-D (C12): the manifest's credentialsOmitted marker and the exact
	// number of upstream entries the restored node will boot into the
	// requiresReplacement state (counted from the archived settings file).
	CredentialsOmitted              bool
	CredentialsRequiringReplacement int
}

// restoreMode selects which artifacts come from the tarball vs. are
// preserved from current /data when D1.3b.2's commit path runs. D1.3b.2a
// reasons about the same predicates in dry-run, but never writes.
type restoreMode int

const (
	modeFull restoreMode = iota
	modeTrustRootOnly
	modeStateOnly
)

func (m restoreMode) String() string {
	switch m {
	case modeFull:
		return "full"
	case modeTrustRootOnly:
		return "trust-root-only"
	case modeStateOnly:
		return "state-only"
	}
	return "unknown"
}

// parseRestoreMode normalizes the CLI string. Empty == default ("full").
func parseRestoreMode(s string) (restoreMode, error) {
	switch s {
	case "", "full":
		return modeFull, nil
	case "trust-root-only":
		return modeTrustRootOnly, nil
	case "state-only":
		return modeStateOnly, nil
	}
	return 0, fmt.Errorf("unknown mode %q (must be: full, trust-root-only, state-only)", s)
}

// fromTarball returns true iff the artifact at tarballPath would be
// taken from the tarball under this mode. The complement is preserved
// from current /data.
func (m restoreMode) fromTarball(tarballPath string) bool {
	isCABundle := tarballPath == "data/ca.bundle"
	isClusterCAPair := tarballPath == "data/cluster-ca.crt" || tarballPath == "data/cluster-ca.key"
	switch m {
	case modeFull:
		return true
	case modeTrustRootOnly:
		return isCABundle || isClusterCAPair
	case modeStateOnly:
		return !(isCABundle || isClusterCAPair)
	}
	return false
}

// restoreOpts groups the operator-supplied flags that govern dry-run
// analysis output. D1.3b.2a inspects them; D1.3b.2b will gate the
// destructive commit on the same flags.
type restoreOpts struct {
	Mode                 restoreMode
	AcceptDPReenrollment bool
	AllowCounterRollback bool
	// BackupPassphrase decrypts an encrypted (D1.4) backup blob. Empty
	// means "expect an unencrypted D1.3a backup"; the restore reader
	// detects encryption from magic bytes and demands a non-empty
	// passphrase only when the magic matches.
	BackupPassphrase string
}

// commitAnalysis is the read-only delta between current /data and the
// post-merge result that a commit (under restoreOpts.Mode) would produce.
// All fields are computed from in-memory tarball + on-disk reads of
// current /data; nothing is written.
type commitAnalysis struct {
	Mode restoreMode

	// Cluster CA delta.
	CurrentCAFingerprint  string // empty if current has no parseable cluster-ca.crt
	RestoredCAFingerprint string // empty if neither tarball nor current would contribute
	CAFingerprintChanged  bool
	CurrentEnrolledNodes  int

	// ui_users delta.
	CurrentUsers          []string // sorted, distinct
	RestoredUsers         []string // sorted, distinct, post-merge
	UsersAddedByRestore   []string // sorted: restored ∖ current
	UsersRemovedByRestore []string // sorted: current ∖ restored
	TOTPCounterRollbacks  []string // sorted usernames where restored.counter < current.counter

	// File source counts (informational for the summary).
	FilesFromTarball int
	FilesFromCurrent int

	// Guard outcomes (precomputed for the summary printer).
	DPGuardWouldBlock   bool // CAFingerprintChanged && CurrentEnrolledNodes > 0 && !AcceptDPReenrollment
	DPGuardActive       bool // would block OR was accepted
	TOTPGuardWouldBlock bool // len(TOTPCounterRollbacks) > 0 && !AllowCounterRollback
	TOTPGuardActive     bool
}

// runRestoreDryRun is the CLI entrypoint. Validates tarPath end-to-end,
// computes the mode-aware analysis, prints the plan to stdout, and
// returns nil on success. Returns an error on any validation rule
// failure. Never writes to dataDir.
func runRestoreDryRun(tarPath, dataDir, passphrase string, opts restoreOpts) error {
	summary, _, files, err := validateBackup(tarPath, dataDir, passphrase, opts.BackupPassphrase)
	if err != nil {
		return err
	}
	analysis, err := analyzeCommit(files, dataDir, opts)
	if err != nil {
		return err
	}
	printRestoreSummary(os.Stdout, summary, analysis)
	return nil
}

// validateBackup runs every D1.3b.1 rule against the tarball at tarPath.
// Returns the parsed summary, the parsed manifest (so commit-path
// staging can read per-file modes without re-parsing), the in-memory
// file map (so the caller can run further analysis without re-reading
// the tarball), and an error.
func validateBackup(tarPath, _ /*dataDir*/, passphrase, backupPassphrase string) (*restoreSummary, *backupManifest, map[string][]byte, error) {
	files, order, err := readTarball(tarPath, backupPassphrase)
	if err != nil {
		return nil, nil, nil, err
	}

	manifest, err := parseAndValidateManifest(files, order)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := validateBidirectionalPresence(manifest, files); err != nil {
		return nil, nil, nil, err
	}

	if err := validateFileChecksumsAndModes(manifest, files); err != nil {
		return nil, nil, nil, err
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
	summary.CredentialsOmitted = manifest.CredentialsOmitted
	if settings, ok := files[adminSettingsTarPath]; ok {
		summary.CredentialsRequiringReplacement = countUpstreamCredentialsRequiringReplacement(settings)
	}
	// A node-local key must never be restored from an archive (it is never
	// packed either; a hand-built tarball is refused rather than trusted).
	for path := range files {
		if isNodeLocalKeyArtifactPath(path) {
			return nil, nil, nil, fmt.Errorf("restore: tarball carries node-local key material %q; refusing (keys are never archived or restored)", path)
		}
	}

	if err := validateTier1Artifacts(files, passphrase, summary); err != nil {
		return nil, nil, nil, err
	}

	return summary, manifest, files, nil
}

// loadAndMaybeDecrypt reads the backup at path and returns the
// (possibly decrypted) tar.gz bytes. If the on-disk blob carries the
// D1.4 encrypted magic, the caller-supplied passphrase is required and
// the blob is decrypted in memory; the encrypted bytes are best-effort
// wiped before the decrypted bytes are returned. Plaintext is never
// written to disk.
func loadAndMaybeDecrypt(path, backupPassphrase string) ([]byte, error) {
	blob, err := os.ReadFile(path) // #nosec G304 -- operator-controlled path
	if err != nil {
		return nil, fmt.Errorf("restore: read tarball: %w", err)
	}
	if !isEncryptedBackupBlob(blob) {
		return blob, nil
	}
	if backupPassphrase == "" {
		return nil, fmt.Errorf("restore: encrypted backup detected but %s is not set", backupPassphraseEnv)
	}
	plain, derr := decryptBackupBlob(blob, backupPassphrase)
	if derr != nil {
		return nil, fmt.Errorf("restore: %w", derr)
	}
	zeroBytes(blob)
	return plain, nil
}

// readTarball opens path, decrypts (D1.4) or sniffs gzip (D1.3a) based
// on the magic of the first eight bytes, gunzips, reads every entry
// into memory, and returns the file map + header order.
// Path-traversal-guards every entry. Plaintext is never written to
// disk: when the file is encrypted, decryption produces an in-memory
// byte slice that's gunzipped via bytes.Reader.
func readTarball(path, backupPassphrase string) (map[string][]byte, []string, error) {
	blob, err := loadAndMaybeDecrypt(path, backupPassphrase)
	if err != nil {
		return nil, nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(blob))
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
		// Path-traversal guard: reject any entry whose path contains "..".
		// strings.Contains is the pattern CodeQL recognises as a zip-slip
		// sanitiser (CWE-22); the previous per-component split was
		// semantically equivalent but not traced across function boundaries
		// by the static analyser. Backup artifact names are controlled
		// system filenames (e.g. "ui_users.json", "ca.bundle") so the
		// slightly broader rejection of any ".." substring is intentional
		// and safe.
		if strings.Contains(hdr.Name, "..") {
			return nil, nil, fmt.Errorf("restore: tarball entry has path traversal: %q", hdr.Name)
		}
		// Duplicate-entry guard: tar format allows multiple headers with
		// the same name; a map-based reader would silently overwrite the
		// earlier entry. Fail closed instead.
		if _, exists := files[hdr.Name]; exists {
			return nil, nil, fmt.Errorf("restore: duplicate tarball entry: %q", hdr.Name)
		}
		// Restore namespace: every entry except manifest.json must live
		// under "data/". Defense in depth — D1.3a's pack code only
		// produces "data/..." paths, but a hand-crafted tarball can
		// violate this.
		if hdr.Name != "manifest.json" && !strings.HasPrefix(hdr.Name, "data/") {
			return nil, nil, fmt.Errorf("restore: tarball entry outside data/ namespace: %q", hdr.Name)
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

// guardWithinDir returns nil iff target lies inside (or equals) base.
// Defense-in-depth zip-slip guard at filesystem-write sites: even though
// readTarball already rejects ".." path components and absolute paths,
// CodeQL cannot trace those guards across the call boundary into
// stageArtifacts. A local re-check at the write site makes the
// invariant visible to static analysis (CWE-22).
func guardWithinDir(base, target string) error {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return fmt.Errorf("guard base abs: %w", err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("guard target abs: %w", err)
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return fmt.Errorf("guard rel: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("path %q escapes %q", target, base)
	}
	return nil
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
	// Restore namespace: every manifest entry must live under "data/".
	// Mirrors the readTarball check; runs early so a bad manifest
	// produces a clear namespace error rather than a downstream
	// presence/parse error.
	for _, f := range manifest.Files {
		if !strings.HasPrefix(f.Path, "data/") {
			return nil, fmt.Errorf("restore: manifest path outside data/ namespace: %q", f.Path)
		}
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
		// CA-3: when cluster CA key encryption is enabled (CULVERT_CLUSTER_CA_ENCRYPT),
		// the archived cluster-ca.key is a PSCA envelope, not plaintext PEM.
		// loadFromPEM only accepts plaintext, and this validator has no KEK, so
		// validate the cert alone for an encrypted key (cross-validation against
		// the key, and full KEK-based decrypt, are owned by the later
		// backup/restore PR). A plaintext key still gets full pair validation.
		if isEncryptedKeyFile(keyBody) {
			cert, err := parseAndValidateCACert(certBody)
			if err != nil {
				return fmt.Errorf("restore: cluster CA cert (encrypted key present): %w", err)
			}
			fp := sha256.Sum256(cert.Raw)
			summary.CAFingerprint = "sha256:" + hex.EncodeToString(fp[:])
		} else {
			ca := &clusterCA{}
			if err := ca.loadFromPEM(certBody, keyBody); err != nil {
				return fmt.Errorf("restore: cluster CA pair: %w", err)
			}
			if ca.cert != nil {
				fp := sha256.Sum256(ca.cert.Raw)
				summary.CAFingerprint = "sha256:" + hex.EncodeToString(fp[:])
			}
		}
	case hasCert != hasKey:
		return fmt.Errorf("restore: cluster CA partial pair in tarball (cert=%v key=%v)", hasCert, hasKey)
	}

	if body, ok := files["data/ca.bundle"]; ok {
		summary.CABundleEncrypted = ca.HasBundleMagic(body)
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
	if ca.HasBundleMagic(data) {
		// Encrypted bundle.
		if passphrase == "" {
			return fmt.Errorf("encrypted bundle but no passphrase available (set CULVERT_CA_PASSPHRASE)")
		}
		var err error
		plaintext, err = ca.DecryptBundle(data, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
	} else {
		plaintext = data
	}
	cm := ca.New()
	if err := cm.ImportBundle(plaintext); err != nil {
		return fmt.Errorf("import: %w", err)
	}
	return nil
}

// analyzeCommit reads current dataDir (read-only) and computes the delta
// between current state and what a commit under opts.Mode would produce.
// Never writes anything. Returns a commitAnalysis suitable for guard
// inspection and summary printing.
func analyzeCommit(files map[string][]byte, dataDir string, opts restoreOpts) (*commitAnalysis, error) {
	a := &commitAnalysis{Mode: opts.Mode}

	// Per-mode merge: count how many files come from the tarball vs.
	// from current /data. Manifest paths drive the count.
	//
	// D1.3b.2b NOTE: this counter is intentionally manifest-driven —
	// it answers "of the paths in the backup, which would the mode
	// pull from current /data?" When the stager lands, it must walk
	// /data directly to copy every preserved artifact, not only paths
	// that happen to also exist in the backup manifest. Otherwise an
	// artifact present in current /data but absent from the backup
	// (e.g. a feature added between snapshot and now, in
	// trust-root-only mode) would be lost during stage.
	for path := range files {
		if path == "manifest.json" {
			continue
		}
		if opts.Mode.fromTarball(path) {
			a.FilesFromTarball++
		} else {
			a.FilesFromCurrent++
		}
	}

	// Cluster CA fingerprint delta. A restored fingerprint of "" is NOT
	// "unchanged" when a CA currently exists — it means the mode routes
	// the CA from the tarball (full/trust-root-only) and the tarball has
	// none (a legitimate first-run-optional backup), so committing would
	// remove the current CA entirely. That is at least as disruptive to
	// enrolled DPs as a fingerprint swap, so it must still trip the guard
	// (requiring only a.CurrentCAFingerprint != "" catches it, since ""
	// != a.RestoredCAFingerprint is trivially true whenever the current
	// fingerprint is non-empty and differs, empty-vs-empty included).
	a.CurrentCAFingerprint = currentCAFingerprint(dataDir)
	a.RestoredCAFingerprint = restoredCAFingerprint(files, dataDir, opts.Mode)
	a.CAFingerprintChanged = a.CurrentCAFingerprint != "" &&
		a.CurrentCAFingerprint != a.RestoredCAFingerprint

	// Enrolled DPs in current cluster.json (read-only).
	a.CurrentEnrolledNodes = currentEnrolledNodeCount(dataDir)

	// DP re-enrollment guard.
	dpWouldNeedFlag := a.CAFingerprintChanged && a.CurrentEnrolledNodes > 0
	a.DPGuardActive = dpWouldNeedFlag
	a.DPGuardWouldBlock = dpWouldNeedFlag && !opts.AcceptDPReenrollment

	// ui_users analysis (post-merge).
	currentUsers := readUsersForAnalysis(currentUIUsersBody(dataDir))
	restoredUsers := readUsersForAnalysis(restoredUIUsersBody(files, dataDir, opts.Mode))
	a.CurrentUsers = sortedUsernames(currentUsers)
	a.RestoredUsers = sortedUsernames(restoredUsers)
	a.UsersAddedByRestore = setDifference(a.RestoredUsers, a.CurrentUsers)
	a.UsersRemovedByRestore = setDifference(a.CurrentUsers, a.RestoredUsers)

	// TOTP counter rollback: present in both, restored counter < current.
	for username, restoredCounter := range restoredUsers {
		if currentCounter, ok := currentUsers[username]; ok {
			if restoredCounter < currentCounter {
				a.TOTPCounterRollbacks = append(a.TOTPCounterRollbacks, username)
			}
		}
	}
	sort.Strings(a.TOTPCounterRollbacks)
	totpWouldNeedFlag := len(a.TOTPCounterRollbacks) > 0
	a.TOTPGuardActive = totpWouldNeedFlag
	a.TOTPGuardWouldBlock = totpWouldNeedFlag && !opts.AllowCounterRollback

	return a, nil
}

func currentCAFingerprint(dataDir string) string {
	body, err := os.ReadFile(filepath.Join(dataDir, "cluster-ca.crt")) // #nosec G304 -- operator-controlled
	if err != nil {
		return ""
	}
	return computeCAFingerprintFromPEM(body)
}

func restoredCAFingerprint(files map[string][]byte, dataDir string, mode restoreMode) string {
	if mode.fromTarball("data/cluster-ca.crt") {
		return computeCAFingerprintFromPEM(files["data/cluster-ca.crt"])
	}
	return currentCAFingerprint(dataDir)
}

func computeCAFingerprintFromPEM(certPEM []byte) string {
	if len(certPEM) == 0 {
		return ""
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func currentEnrolledNodeCount(dataDir string) int {
	body, err := os.ReadFile(filepath.Join(dataDir, "cluster.json")) // #nosec G304 -- operator-controlled
	if err != nil {
		return 0
	}
	var st ClusterState
	if err := json.Unmarshal(body, &st); err != nil {
		return 0
	}
	return len(st.Nodes)
}

func currentUIUsersBody(dataDir string) []byte {
	body, err := os.ReadFile(filepath.Join(dataDir, "ui_users.json")) // #nosec G304 -- operator-controlled
	if err != nil {
		return nil
	}
	return body
}

func restoredUIUsersBody(files map[string][]byte, dataDir string, mode restoreMode) []byte {
	if mode.fromTarball("data/ui_users.json") {
		return files["data/ui_users.json"]
	}
	return currentUIUsersBody(dataDir)
}

// readUsersForAnalysis parses ui_users.json bytes (envelope-then-bare-array)
// into a map of username → totp_last_counter. Empty map on parse failure
// or absent file (caller decides what that means).
func readUsersForAnalysis(data []byte) map[string]int64 {
	out := map[string]int64{}
	if len(data) == 0 {
		return out
	}
	var env uiUsersFileEnvelope
	if err := json.Unmarshal(data, &env); err == nil && env.Users != nil {
		for _, u := range env.Users {
			out[u.Username] = u.TOTPLastCounter
		}
		return out
	}
	var records []uiUserRecord
	if err := json.Unmarshal(data, &records); err == nil {
		for _, u := range records {
			out[u.Username] = u.TOTPLastCounter
		}
	}
	return out
}

func sortedUsernames(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// setDifference returns sorted (a ∖ b). Both inputs must be pre-sorted
// (sortedUsernames does this).
func setDifference(a, b []string) []string {
	bSet := make(map[string]struct{}, len(b))
	for _, x := range b {
		bSet[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, in := bSet[x]; !in {
			out = append(out, x)
		}
	}
	return out
}

// printRestoreSummary writes the dry-run plan in a fixed shape so tests
// can assert on key lines. Mode-aware: includes per-mode merge counts,
// CA fingerprint delta, DP roster delta, TOTP rollback lines, and guard
// status. Uses fmt.Fprintf rather than logger because runRestoreDryRun
// is a one-shot CLI command that runs before logger initialization.
func printRestoreSummary(w io.Writer, s *restoreSummary, a *commitAnalysis) {
	fmt.Fprintf(w, "Restore plan (dry-run, --mode=%s):\n\n", a.Mode)
	fmt.Fprintf(w, "Backup metadata:\n")
	fmt.Fprintf(w, "  Source:           %s\n", s.BackupPath)
	fmt.Fprintf(w, "  Schema version:   %d\n", s.SchemaVersion)
	fmt.Fprintf(w, "  Created at:       %s\n", s.CreatedAt)
	fmt.Fprintf(w, "  Culvert version:  %s\n", s.CulvertVersion)

	fmt.Fprintf(w, "\nManifest:\n")
	fmt.Fprintf(w, "  Files total:         %d\n", s.TotalFiles)
	fmt.Fprintf(w, "  Required (Tier 1):   %d\n", s.Tier1Files)
	fmt.Fprintf(w, "  Optional (Tier 2):   %d\n", s.Tier2Files)

	fmt.Fprintf(w, "\nMode-specific merge:\n")
	fmt.Fprintf(w, "  From tarball:    %d file(s)\n", a.FilesFromTarball)
	fmt.Fprintf(w, "  From current:    %d file(s)\n", a.FilesFromCurrent)

	fmt.Fprintf(w, "\nCluster CA:\n")
	if a.CurrentCAFingerprint == "" {
		fmt.Fprintf(w, "  Current:    (none on disk)\n")
	} else {
		fmt.Fprintf(w, "  Current:    %s (%d enrolled DP(s))\n", a.CurrentCAFingerprint, a.CurrentEnrolledNodes)
	}
	if a.RestoredCAFingerprint == "" {
		fmt.Fprintf(w, "  Restored:   (none would be present)\n")
	} else {
		fmt.Fprintf(w, "  Restored:   %s\n", a.RestoredCAFingerprint)
	}
	switch {
	case a.DPGuardWouldBlock:
		fmt.Fprintf(w, "  ⚠ DP re-enrollment required: %d DP(s) would need to re-enroll.\n", a.CurrentEnrolledNodes)
		fmt.Fprintf(w, "    Pass --accept-dp-reenrollment to allow commit (D1.3b.2).\n")
	case a.DPGuardActive:
		fmt.Fprintf(w, "  ⓘ DP re-enrollment accepted: %d DP(s) will need to re-enroll under restored CA.\n", a.CurrentEnrolledNodes)
	case a.CAFingerprintChanged:
		fmt.Fprintf(w, "  CA fingerprint changes; no enrolled DPs affected.\n")
	default:
		fmt.Fprintf(w, "  CA fingerprint unchanged.\n")
	}

	fmt.Fprintf(w, "\nAdmin accounts:\n")
	fmt.Fprintf(w, "  Current:   %d (%s)\n", len(a.CurrentUsers), strings.Join(a.CurrentUsers, ", "))
	fmt.Fprintf(w, "  Restored:  %d (%s)\n", len(a.RestoredUsers), strings.Join(a.RestoredUsers, ", "))
	if len(a.UsersAddedByRestore) > 0 {
		fmt.Fprintf(w, "  Will be added:    %s\n", strings.Join(a.UsersAddedByRestore, ", "))
	}
	if len(a.UsersRemovedByRestore) > 0 {
		fmt.Fprintf(w, "  Will be removed:  %s\n", strings.Join(a.UsersRemovedByRestore, ", "))
	}

	fmt.Fprintf(w, "\nTOTP counter rollbacks:\n")
	switch {
	case a.TOTPGuardWouldBlock:
		fmt.Fprintf(w, "  ⚠ %d user(s) would have TOTP counter roll back: %s\n", len(a.TOTPCounterRollbacks), strings.Join(a.TOTPCounterRollbacks, ", "))
		fmt.Fprintf(w, "    Pass --allow-counter-rollback to allow commit (D1.3b.2).\n")
	case a.TOTPGuardActive:
		fmt.Fprintf(w, "  ⓘ %d user(s) accepted TOTP counter rollback: %s\n", len(a.TOTPCounterRollbacks), strings.Join(a.TOTPCounterRollbacks, ", "))
	default:
		fmt.Fprintf(w, "  none.\n")
	}

	printRestoreUpstreamCredentials(w, s)

	fmt.Fprintf(w, "\nValidation: PASS\n")
	if s.AdminCount > 0 {
		fmt.Fprintf(w, "  ui_users.json:                %d admin account(s) in restored manifest\n", s.AdminCount)
	}
	if s.EnrolledDPCount > 0 {
		fmt.Fprintf(w, "  cluster.json:                 %d enrolled DP(s) in restored manifest\n", s.EnrolledDPCount)
	}
	if s.CAFingerprint != "" {
		fmt.Fprintf(w, "  cluster CA cross-validation:  PASS (%s)\n", s.CAFingerprint)
	}
	if s.CABundleEncrypted {
		fmt.Fprintf(w, "  ca.bundle decrypt:            PASS (encrypted)\n")
	}

	fmt.Fprintf(w, "\nThis was a dry-run. No files were written. /data unchanged.\n")
	fmt.Fprintf(w, "D1.3b.2b will add --confirm to commit a restore.\n")
}

// printRestoreUpstreamCredentials is the 2F-D (C12) section of the dry-run
// report: the manifest marker and the exact count of entries the restored
// node will boot into requiresReplacement. Counts only.
func printRestoreUpstreamCredentials(w io.Writer, s *restoreSummary) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("\nUpstream credentials:\n")
	if s.CredentialsOmitted {
		p("  archive: credentials omitted (never archived)\n")
	} else {
		p("  archive: pre-2F-D backup (no credentialsOmitted marker)\n")
	}
	p("  credentials requiring replacement: %d\n", s.CredentialsRequiringReplacement)
	if s.CredentialsRequiringReplacement > 0 {
		p("  ⓘ Each affected parent proxy boots ineligible (requiresReplacement) until its credential is set again\n")
		p("    through POST /api/upstream/entries/{id}/credential (replace) or cleared (clear). No parent is ever sent unauthenticated.\n")
	}
	p("  node-local credential key: never restored, deleted or overwritten\n")
}

// ─── D1.3b.2b: destructive commit path ──────────────────────────────────────

// commitInjectBetweenRenames is a test seam — production keeps it nil.
// Tests set it before calling runRestoreCommit to simulate a failure
// (or process death) between rename A and rename B, exercising the
// recovery-message code path. Set via t.Cleanup back to nil.
var commitInjectBetweenRenames func() error

// restoreNow is the clock used to derive the staging/.bak suffix. It is
// a package var so tests can pin it: the suffix has 1-second resolution,
// and a test that pre-creates a `.bak.<ts>` dir to force a collision must
// derive the SAME instant the code uses, otherwise a second-boundary race
// between the two time reads makes the test flaky.
var restoreNow = time.Now

// runRestoreCommit performs a destructive restore: validate, analyze,
// enforce guards, stage, swap. Caller must stop the proxy first
// (offline restore only). On success, current /data has been replaced
// by the restored content and the prior /data is preserved at
// /data.bak.<timestamp>.
//
// Step ordering (single failure boundary at the swap):
//
//  1. validate  (D1.3b.1; no /data writes)
//  2. analyze   (D1.3b.2a; no /data writes)
//  3. guards    (D1.3b.2a precomputed; reject if WouldBlock)
//  4. summary   (mode-aware; informational)
//  5. stage     (mkdir /data.staging.<ts>; write per mode predicate)
//  6. rename A  (current /data → /data.bak.<ts>)
//  7. rename B  (staging → /data) + parent-dir fsync
//  8. final     (print success + .bak path)
//
// If 1–5 fail: /data unchanged, staging cleaned up.
// If 6 fails: /data unchanged, staging cleaned up.
// If 7 fails (or process is killed between 6 and 7): /data does not
// exist; error message names the exact `mv` recovery command.
func runRestoreCommit(tarPath, dataDir, passphrase string, opts restoreOpts) error {
	// Steps 1–2 (reuse).
	summary, manifest, files, err := validateBackup(tarPath, dataDir, passphrase, opts.BackupPassphrase)
	if err != nil {
		return err
	}
	analysis, err := analyzeCommit(files, dataDir, opts)
	if err != nil {
		return err
	}

	// Step 3: enforce guards before any destructive operation.
	if analysis.DPGuardWouldBlock {
		return fmt.Errorf("restore: cluster CA fingerprint changes (current=%s → restored=%s); %d DP(s) currently enrolled will need to re-enroll. Pass --accept-dp-reenrollment to proceed",
			analysis.CurrentCAFingerprint, analysis.RestoredCAFingerprint, analysis.CurrentEnrolledNodes)
	}
	if analysis.TOTPGuardWouldBlock {
		return fmt.Errorf("restore: TOTP counter rollback for %d user(s) (%s); recently-used codes could be replayed. Pass --allow-counter-rollback to proceed",
			len(analysis.TOTPCounterRollbacks), strings.Join(analysis.TOTPCounterRollbacks, ", "))
	}

	// Step 4: print summary so the operator sees the plan one last time.
	printRestoreSummary(os.Stdout, summary, analysis)

	// Anchor paths now so failure messages can name them. Suffix is
	// timestamp + PID so:
	//   - same-second retries from different processes don't collide
	//   - the operator can copy-paste the printed paths verbatim
	//   - staging and bak share a correlated suffix
	suffix := fmt.Sprintf("%s-%d", restoreNow().UTC().Format("20060102T150405Z"), os.Getpid())
	stagingDir := dataDir + ".staging." + suffix
	bakPath := dataDir + ".bak." + suffix

	// Collision pre-check: refuse to proceed if either path already
	// exists on disk. Catches stale state from a prior failed restore
	// (e.g. operator killed the process mid-stage) and prevents
	// accidental reuse of either dir.
	if _, err := os.Stat(stagingDir); err == nil {
		return fmt.Errorf("restore: staging path %q already exists; remove it before retrying", stagingDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("restore: stat staging path %q: %w", stagingDir, err)
	}
	if _, err := os.Stat(bakPath); err == nil {
		return fmt.Errorf("restore: backup path %q already exists; remove it before retrying", bakPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("restore: stat backup path %q: %w", bakPath, err)
	}

	fmt.Fprintf(os.Stdout, "\nCommitting restore now.\n")
	fmt.Fprintf(os.Stdout, "  Staging dir: %s\n", stagingDir)
	fmt.Fprintf(os.Stdout, "  Backup of current /data will be at: %s\n\n", bakPath)

	// Step 5: stage to disk.
	if err := stageArtifacts(stagingDir, dataDir, files, manifest, opts.Mode); err != nil {
		_ = os.RemoveAll(stagingDir) // #nosec G104 -- best-effort cleanup
		return fmt.Errorf("restore: stage failed: %w", err)
	}

	// Step 6: rename current /data → .bak.
	if err := os.Rename(dataDir, bakPath); err != nil {
		_ = os.RemoveAll(stagingDir) // #nosec G104 -- best-effort cleanup
		return fmt.Errorf("restore: rename current %s → %s: %w", dataDir, bakPath, err)
	}

	// Critical window: /data does not exist between renames. On failure
	// here, clean up staging so the operator's only recovery path is the
	// .bak (no ambiguity between option A "revert via .bak" and option B
	// "promote staging"). The .bak is preserved either way.
	if commitInjectBetweenRenames != nil {
		if err := commitInjectBetweenRenames(); err != nil {
			_ = os.RemoveAll(stagingDir) // #nosec G104 -- best-effort cleanup
			return fmt.Errorf("restore: COMMIT INTERRUPTED — %s does not exist; manual recovery: mv %s %s ; injected: %w",
				dataDir, bakPath, dataDir, err)
		}
	}

	// Step 7: rename staging → /data.
	if err := os.Rename(stagingDir, dataDir); err != nil {
		_ = os.RemoveAll(stagingDir) // #nosec G104 -- best-effort cleanup
		return fmt.Errorf("restore: COMMIT INTERRUPTED — %s does not exist; manual recovery: mv %s %s ; rename staging→/data failed: %w",
			dataDir, bakPath, dataDir, err)
	}

	// Parent-dir fsync (best-effort, mirrors atomicWriteFile pattern).
	if d, derr := os.Open(filepath.Dir(dataDir)); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	// Step 8.
	fmt.Fprintf(os.Stdout, "\nRestore committed.\n")
	fmt.Fprintf(os.Stdout, "  Previous /data preserved at: %s\n", bakPath)
	fmt.Fprintf(os.Stdout, "  (.bak is NOT auto-deleted; remove manually when no longer needed.)\n")
	return nil
}

// checkInterruptedRestore is the boot-time guard for RISK-005. A restore commit
// killed in the critical window (after `os.Rename(dataDir → .bak)` and before
// `os.Rename(staging → dataDir)`, runRestoreCommit steps 6–7) leaves dataDir
// ABSENT while its `<dataDir>.bak.<ts>-<pid>` sibling (the previous data, moved
// aside) — and usually a matching `.staging.<ts>-<pid>` (the new data, staged
// but not yet promoted) — remain on disk. Starting normally in that state would
// create a fresh empty dataDir and SILENTLY lose the operator's data, with the
// recovery `.bak` only discoverable by hand.
//
// This guard, called once at startup after the one-shot CLI commands (so
// --list-restore-leftovers / --cleanup-restore-leftovers still run), refuses to
// boot when dataDir is missing AND an interrupted-restore `.bak` sibling exists,
// printing the exact recovery moves. It reuses the D1.3c leftover scanner
// (discoverLeftovers), which only admits safe, exact-name, sibling directories.
//
// A genuine fresh install (dataDir absent, NO `.bak` sibling) is unaffected:
// the guard returns nil and normal first-run initialization proceeds.
func checkInterruptedRestore(dataDir string) error {
	if _, err := os.Stat(dataDir); err == nil {
		return nil // dataDir present — normal boot
	} else if !os.IsNotExist(err) {
		return nil // unexpected stat error — don't block boot on a transient FS issue
	}
	// dataDir is absent. Scan for interrupted-restore siblings.
	leftovers, _, err := discoverLeftovers(dataDir)
	if err != nil {
		return nil // cannot scan the parent dir — nothing to assert
	}
	var newestBak, newestStaging *leftover
	for i := range leftovers {
		lo := &leftovers[i]
		switch lo.Kind {
		case leftoverBak:
			if newestBak == nil || lo.Timestamp.After(newestBak.Timestamp) {
				newestBak = lo
			}
		case leftoverStaging:
			if newestStaging == nil || lo.Timestamp.After(newestStaging.Timestamp) {
				newestStaging = lo
			}
		}
	}
	// Only a `.bak` (the moved-aside previous data) marks an interrupted
	// restore. No `.bak` ⇒ a genuine fresh install — let boot proceed.
	if newestBak == nil {
		return nil
	}
	msg := fmt.Sprintf("interrupted restore detected: data directory %q is missing, but the previous "+
		"data was preserved at %q (a restore commit was killed before it finished). "+
		"Recover by choosing ONE, then start Culvert again:\n"+
		"    REVERT to the previous data:            mv %q %q",
		dataDir, newestBak.Path, newestBak.Path, dataDir)
	if newestStaging != nil {
		msg += fmt.Sprintf("\n    COMPLETE the restore (promote staged):  mv %q %q", newestStaging.Path, dataDir)
	}
	msg += "\n    (run --list-restore-leftovers to inspect all leftovers)"
	return fmt.Errorf("%s", msg)
}

// stageArtifacts creates stagingDir and populates it according to the
// mode predicate. Pass 1 writes tarball-sourced artifacts using each
// file's manifest mode. Pass 2 walks current dataDir for preserve-
// from-current artifacts using each live file's existing mode (this is
// the gap flagged in PR #194 review — must walk live /data, not just
// paths in the manifest).
//
// current second) is intentionally inlined so the mode predicate,
// mkdir, per-file mode resolution, and atomicWriteFile contract are
// all visible at one call site. Extracting helpers would scatter the
// staging contract across functions and obscure the per-pass invariants.
//
//nolint:gocognit,cyclop,funlen // Two-pass structure (tarball first, walk-
func stageArtifacts(stagingDir, dataDir string, files map[string][]byte, manifest *backupManifest, mode restoreMode) error {
	// os.Mkdir (exclusive), not os.MkdirAll, for the staging root —
	// fail closed if a prior failed restore left a same-named dir on
	// disk so we never reuse stale staging content. Subdirectories
	// inside staging still use MkdirAll (created on demand).
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		return fmt.Errorf("mkdir staging (exclusive): %w", err)
	}

	// Index manifest modes by path so pass 1 doesn't scan per-file.
	manifestMode := map[string]os.FileMode{}
	for _, f := range manifest.Files {
		perm, perr := strconv.ParseUint(f.Mode, 8, 32)
		if perr != nil {
			return fmt.Errorf("invalid manifest mode %q for %s: %w", f.Mode, f.Path, perr)
		}
		manifestMode[f.Path] = os.FileMode(perm) & os.ModePerm
	}

	written := map[string]bool{}

	// Pass 1 — tarball-sourced artifacts. Mode comes from the manifest
	// so the restored file mirrors what the operator backed up (e.g.
	// 0o644 for version.txt vs 0o600 for everything else).
	for path, body := range files {
		if path == "manifest.json" {
			continue
		}
		if !mode.fromTarball(path) {
			continue
		}
		rel := strings.TrimPrefix(path, "data/")
		target := filepath.Join(stagingDir, rel)
		// Defense-in-depth zip-slip guard at the write site. readTarball
		// already rejects ".." components and absolute paths, but those
		// guards are cross-function so CodeQL cannot trace them. A local
		// re-check here makes the invariant visible to static analysis
		// (and to any future caller wiring a different reader in).
		if err := guardWithinDir(stagingDir, target); err != nil {
			return fmt.Errorf("stage tarball %s: %w", path, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("mkdir for %s: %w", rel, err)
		}
		perm, ok := manifestMode[path]
		if !ok {
			// Defense in depth: every tarball entry is required to be
			// in the manifest by validateBidirectionalPresence; if the
			// indexer somehow missed it, fail closed rather than fall
			// back to a hardcoded mode.
			return fmt.Errorf("stage tarball %s: missing manifest mode entry", path)
		}
		if err := atomicWriteFile(target, body, perm); err != nil {
			return fmt.Errorf("stage tarball %s: %w", path, err)
		}
		written[path] = true
	}

	// Pass 2 — preserve-from-current artifacts. Walk live dataDir so
	// files present in current /data but absent from the backup
	// manifest are still preserved (e.g. files added by features
	// introduced after the backup snapshot, in non-full modes).
	walkErr := filepath.Walk(dataDir, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Skip symlinks for the same reason D1.3a's pack does:
			// don't follow into surprise targets.
			return nil
		}
		rel, relErr := filepath.Rel(dataDir, p)
		if relErr != nil {
			return relErr
		}
		tarballPath := "data/" + filepath.ToSlash(rel)
		if mode.fromTarball(tarballPath) && !isNodeLocalKeyArtifactPath(tarballPath) {
			// Tarball-source — pass 1 handled it (or it's a tarball
			// path that simply isn't in current /data). Node-local key
			// files are the exception in EVERY mode (2F-D, C12): they are
			// never archived, so the node keeps its own — a restore must
			// never delete or overwrite .upstream_cred_key (or a KEK).
			return nil
		}
		if written[tarballPath] {
			return nil
		}
		// #nosec G304,G122 -- offline restore only (service stopped per
		// design), operator-controlled /data tree walked from dataDir,
		// symlinks already skipped above so the walked path cannot
		// escape /data via TOCTOU. Refactoring to a root-scoped API
		// (os.Root) is full-restore-flow surgery and out of D1.3b.2b
		// scope.
		body, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read current %s: %w", p, err)
		}
		target := filepath.Join(stagingDir, rel)
		// Defense-in-depth zip-slip guard (mirrors pass 1). filepath.Walk
		// already returns paths under dataDir, but the local re-check
		// makes the invariant visible to static analysis.
		if err := guardWithinDir(stagingDir, target); err != nil {
			return fmt.Errorf("stage current %s: %w", p, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("mkdir for %s: %w", rel, err)
		}
		// Preserve current file's mode — restored copy should mirror
		// what was on disk before the restore.
		if err := atomicWriteFile(target, body, info.Mode().Perm()); err != nil {
			return fmt.Errorf("stage current %s: %w", p, err)
		}
		written[tarballPath] = true
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("stage from current: %w", walkErr)
	}
	return nil
}
