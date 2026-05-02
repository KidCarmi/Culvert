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
	Mode                  restoreMode
	AcceptDPReenrollment  bool
	AllowCounterRollback  bool
}

// commitAnalysis is the read-only delta between current /data and the
// post-merge result that a commit (under restoreOpts.Mode) would produce.
// All fields are computed from in-memory tarball + on-disk reads of
// current /data; nothing is written.
type commitAnalysis struct {
	Mode restoreMode

	// Cluster CA delta.
	CurrentCAFingerprint   string // empty if current has no parseable cluster-ca.crt
	RestoredCAFingerprint  string // empty if neither tarball nor current would contribute
	CAFingerprintChanged   bool
	CurrentEnrolledNodes   int

	// ui_users delta.
	CurrentUsers           []string // sorted, distinct
	RestoredUsers          []string // sorted, distinct, post-merge
	UsersAddedByRestore    []string // sorted: restored ∖ current
	UsersRemovedByRestore  []string // sorted: current ∖ restored
	TOTPCounterRollbacks   []string // sorted usernames where restored.counter < current.counter

	// File source counts (informational for the summary).
	FilesFromTarball int
	FilesFromCurrent int

	// Guard outcomes (precomputed for the summary printer).
	DPGuardWouldBlock     bool // CAFingerprintChanged && CurrentEnrolledNodes > 0 && !AcceptDPReenrollment
	DPGuardActive         bool // would block OR was accepted
	TOTPGuardWouldBlock   bool // len(TOTPCounterRollbacks) > 0 && !AllowCounterRollback
	TOTPGuardActive       bool
}

// runRestoreDryRun is the CLI entrypoint. Validates tarPath end-to-end,
// computes the mode-aware analysis, prints the plan to stdout, and
// returns nil on success. Returns an error on any validation rule
// failure. Never writes to dataDir.
func runRestoreDryRun(tarPath, dataDir, passphrase string, opts restoreOpts) error {
	summary, files, err := validateBackup(tarPath, dataDir, passphrase)
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
// Returns the parsed summary, the in-memory file map (so the caller can
// run further analysis without re-reading the tarball), and an error.
func validateBackup(tarPath, _ /*dataDir*/, passphrase string) (*restoreSummary, map[string][]byte, error) {
	files, order, err := readTarball(tarPath)
	if err != nil {
		return nil, nil, err
	}

	manifest, err := parseAndValidateManifest(files, order)
	if err != nil {
		return nil, nil, err
	}

	if err := validateBidirectionalPresence(manifest, files); err != nil {
		return nil, nil, err
	}

	if err := validateFileChecksumsAndModes(manifest, files); err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}

	return summary, files, nil
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

// analyzeCommit reads current dataDir (read-only) and computes the delta
// between current state and what a commit under opts.Mode would produce.
// Never writes anything. Returns a commitAnalysis suitable for guard
// inspection and summary printing.
func analyzeCommit(files map[string][]byte, dataDir string, opts restoreOpts) (*commitAnalysis, error) {
	a := &commitAnalysis{Mode: opts.Mode}

	// Per-mode merge: count how many files come from the tarball vs.
	// from current /data. Manifest paths drive the count.
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

	// Cluster CA fingerprint delta.
	a.CurrentCAFingerprint = currentCAFingerprint(dataDir)
	a.RestoredCAFingerprint = restoredCAFingerprint(files, dataDir, opts.Mode)
	a.CAFingerprintChanged = a.CurrentCAFingerprint != "" &&
		a.RestoredCAFingerprint != "" &&
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
