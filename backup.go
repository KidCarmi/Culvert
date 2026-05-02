package main

// D1.3a — backup/export only. Pack selected /data artifacts into a
// gzipped tarball with a manifest.json at the head. CLI-only, no
// destructive ops, no restore, no admin API. Restore is D1.3b.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// backupSchemaVersion is the manifest envelope version. D1.3a writes 1.
// D1.3b will accept 1 unconditionally and reject anything else.
const backupSchemaVersion = 1

// backupManifest is the schema-versioned envelope written first into
// each tarball. Fields are documented in
// roadmap/D1.3-backup-restore-design.md.
type backupManifest struct {
	SchemaVersion  int                  `json:"schema_version"`
	CreatedAt      string               `json:"created_at"`
	CulvertVersion string               `json:"culvert_version"`
	Files          []backupManifestFile `json:"files"`
}

type backupManifestFile struct {
	Path     string `json:"path"`     // tarball path, e.g. "data/ca.bundle"
	Size     int64  `json:"size"`     // bytes
	SHA256   string `json:"sha256"`   // hex-encoded
	Mode     string `json:"mode"`     // octal string, e.g. "0600"
	Required bool   `json:"required"` // Tier 1 (true) vs Tier 2 (false)
}

// backupArtifact describes one artifact to consider for backup.
type backupArtifact struct {
	SrcPath          string // path on disk
	TarPath          string // path within the tarball
	Required         bool   // Tier 1 (true) vs Tier 2 (false)
	OptionalFirstRun bool   // missing is OK on a fresh install
	IsDir            bool   // recursive walk
}

// defaultBackupArtifacts returns the static Tier-1 + Tier-2 list rooted
// at dataDir. Tier-3 (logs, hashcache, runtime caches, threat feed,
// etc.) is intentionally absent — see the design doc for the full list
// and rationale.
func defaultBackupArtifacts(dataDir string) []backupArtifact {
	p := func(name string) string { return filepath.Join(dataDir, name) }
	return []backupArtifact{
		// ── Tier 1 — required, but all first-run-optional in practice
		// (Culvert can be backed up before any of these are bootstrapped).
		{SrcPath: p("ca.bundle"), TarPath: "data/ca.bundle", Required: true, OptionalFirstRun: true},
		{SrcPath: p("cluster-ca.crt"), TarPath: "data/cluster-ca.crt", Required: true, OptionalFirstRun: true},
		{SrcPath: p("cluster-ca.key"), TarPath: "data/cluster-ca.key", Required: true, OptionalFirstRun: true},
		{SrcPath: p("cluster.json"), TarPath: "data/cluster.json", Required: true, OptionalFirstRun: true},
		{SrcPath: p("ui_users.json"), TarPath: "data/ui_users.json", Required: true, OptionalFirstRun: true},
		{SrcPath: p("config_versions"), TarPath: "data/config_versions", Required: true, OptionalFirstRun: true, IsDir: true},

		// ── Tier 2 — optional if present.
		{SrcPath: p("policy.json"), TarPath: "data/policy.json"},
		{SrcPath: p("policy.json.meta"), TarPath: "data/policy.json.meta"},
		{SrcPath: p("bandwidth.json"), TarPath: "data/bandwidth.json"},
		{SrcPath: p("node_groups.json"), TarPath: "data/node_groups.json"},
		{SrcPath: p("categories.json"), TarPath: "data/categories.json"},
		{SrcPath: p("category_groups.json"), TarPath: "data/category_groups.json"},
		{SrcPath: p("blocklist.txt"), TarPath: "data/blocklist.txt"},
		{SrcPath: p("blocklist.txt.mode"), TarPath: "data/blocklist.txt.mode"},
		{SrcPath: p("blocklist.txt.manual"), TarPath: "data/blocklist.txt.manual"},
		{SrcPath: p("blocklist.txt.exceptions"), TarPath: "data/blocklist.txt.exceptions"},
		{SrcPath: p("pac.json"), TarPath: "data/pac.json"},
		{SrcPath: p("scan_exclusions.json"), TarPath: "data/scan_exclusions.json"},
		{SrcPath: p("alert_settings.json"), TarPath: "data/alert_settings.json"},
		{SrcPath: p("admin_settings.json"), TarPath: "data/admin_settings.json"},
		{SrcPath: p("ssl_bypass.json"), TarPath: "data/ssl_bypass.json"},
		{SrcPath: p("dpi_patterns.json"), TarPath: "data/dpi_patterns.json"},
	}
}

// runBackup is the CLI entrypoint. Packs the default Tier-1+2 artifact
// list rooted at dataDir into outPath, atomically (writes to outPath+".tmp"
// then renames). Unencrypted (D1.3a).
func runBackup(outPath, dataDir string) error {
	return runBackupWith(outPath, defaultBackupArtifacts(dataDir), "")
}

// runBackupEncrypted is the encrypted CLI entrypoint (D1.4). Same packing
// path as runBackup, but the resulting tar.gz is sealed with AES-256-GCM
// using a passphrase-derived key (PBKDF2-SHA256, 600k iterations).
// Refuses to overwrite an existing output file (matches D1.3a semantics).
func runBackupEncrypted(outPath, dataDir, passphrase string) error {
	return runBackupWith(outPath, defaultBackupArtifacts(dataDir), passphrase)
}

type packedFile struct {
	hdr  *tar.Header
	body []byte
}

// runBackupWith reads each artifact's full body into memory in pass 1, builds
// the manifest (which depends on every file's sha256), and then writes the
// tarball in pass 2 with the manifest as the first entry.
//
// Memory tradeoff: total in-memory cost is the sum of all packed file sizes.
// For typical /data this is a few MB (config_versions × ~1KB each). If
// config_versions/ ever grows pathologically large, this should switch to a
// streaming pass-1 (hash-only, no body retention) followed by pass-2 re-read.
// Out of scope for D1.3a — typical operator deployments are well under 100MB.
func runBackupWith(outPath string, artifacts []backupArtifact, passphrase string) error {
	// Refuse to overwrite an existing output file. Operators must remove
	// the prior backup or choose a different path. Prevents accidental
	// destruction of the only backup via a typo.
	if _, statErr := os.Stat(outPath); statErr == nil {
		return fmt.Errorf("backup: output path %q already exists; remove it or choose a different path", outPath)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("backup: stat output path %q: %w", outPath, statErr)
	}

	manifestFiles, packed, missingStrict, missingFirstRun, err := collectArtifacts(artifacts)
	if err != nil {
		return err
	}
	if len(missingStrict) > 0 {
		sort.Strings(missingStrict)
		return fmt.Errorf("backup: required artifact(s) missing on disk: %s", strings.Join(missingStrict, ", "))
	}
	// runBackup is a one-shot CLI command that runs before the global
	// logger is initialized; emit warnings directly to stderr.
	for _, m := range missingFirstRun {
		fmt.Fprintf(os.Stderr, "Backup: required artifact missing on disk: %q (skipping; first-run-optional)\n", m)
	}

	// Sort manifest entries for determinism.
	sort.Slice(manifestFiles, func(i, j int) bool { return manifestFiles[i].Path < manifestFiles[j].Path })

	manifest := backupManifest{
		SchemaVersion:  backupSchemaVersion,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		CulvertVersion: version,
		Files:          manifestFiles,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: marshal manifest: %w", err)
	}

	if passphrase != "" {
		return writeEncryptedBackupTarball(outPath, manifestBytes, packed, passphrase)
	}
	return writeBackupTarball(outPath, manifestBytes, packed)
}

//nolint:gocognit,nestif // Per-artifact branch (file vs dir, present vs missing,
// required vs optional, first-run-optional vs strict) is intentionally unrolled
// so each case is grep-able in error messages. Splitting further would
// scatter the missing-required accounting that callers depend on.
func collectArtifacts(artifacts []backupArtifact) (
	manifestFiles []backupManifestFile,
	packed []packedFile,
	missingStrict []string,
	missingFirstRun []string,
	err error,
) {
	for _, a := range artifacts {
		// Lstat (not Stat) so symlinked top-level artifacts are detected
		// before we follow them. The packOne symlink check below depends
		// on info.Mode() reporting ModeSymlink for symlinks; os.Stat would
		// transparently resolve the link and report the target's type,
		// bypassing the guard. filepath.Walk already uses Lstat internally
		// for the recursive case (config_versions/), so this aligns the
		// two paths.
		info, statErr := os.Lstat(a.SrcPath)
		if statErr != nil {
			if !os.IsNotExist(statErr) {
				return nil, nil, nil, nil, fmt.Errorf("backup: stat %q: %w", a.SrcPath, statErr)
			}
			if a.Required {
				if a.OptionalFirstRun {
					missingFirstRun = append(missingFirstRun, a.SrcPath)
				} else {
					missingStrict = append(missingStrict, a.SrcPath)
				}
			}
			continue
		}

		if a.IsDir {
			if !info.IsDir() {
				return nil, nil, nil, nil, fmt.Errorf("backup: %q expected directory, got file", a.SrcPath)
			}
			if walkErr := filepath.Walk(a.SrcPath, func(path string, fi os.FileInfo, werr error) error {
				if werr != nil {
					return werr
				}
				if fi.IsDir() {
					return nil
				}
				rel, relErr := filepath.Rel(a.SrcPath, path)
				if relErr != nil {
					return relErr
				}
				tarPath := filepath.ToSlash(filepath.Join(a.TarPath, rel))
				return packOne(path, tarPath, fi, a.Required, &manifestFiles, &packed)
			}); walkErr != nil {
				return nil, nil, nil, nil, fmt.Errorf("backup: walk %q: %w", a.SrcPath, walkErr)
			}
			continue
		}

		if info.IsDir() {
			return nil, nil, nil, nil, fmt.Errorf("backup: %q expected file, got directory", a.SrcPath)
		}
		if perr := packOne(a.SrcPath, a.TarPath, info, a.Required, &manifestFiles, &packed); perr != nil {
			return nil, nil, nil, nil, perr
		}
	}
	return manifestFiles, packed, missingStrict, missingFirstRun, nil
}

func packOne(srcPath, tarPath string, info os.FileInfo, required bool, manifestFiles *[]backupManifestFile, packed *[]packedFile) error {
	// Path-traversal guard: refuse any tarPath whose path components include
	// ".." — defense in depth against pathological filenames in walked
	// directories. Component-level check (won't reject legitimate filenames
	// that contain ".." substrings like "foo..bar.json").
	for _, part := range strings.Split(tarPath, "/") {
		if part == ".." {
			return fmt.Errorf("backup: refusing to pack path with traversal: %q", tarPath)
		}
	}
	// Symlinks in the source dir would cause os.ReadFile below to follow
	// them, potentially reading outside /data (e.g. a symlink in
	// config_versions/ pointing at /etc/passwd). Skip with a warning.
	if info.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintf(os.Stderr, "Backup: skipping symlink %q (refusing to follow)\n", srcPath)
		return nil
	}
	body, err := os.ReadFile(srcPath) // #nosec G304 -- operator-controlled path; symlinks rejected above
	if err != nil {
		return fmt.Errorf("backup: read %q: %w", srcPath, err)
	}
	sum := sha256.Sum256(body)
	perm := info.Mode().Perm()
	*manifestFiles = append(*manifestFiles, backupManifestFile{
		Path:     tarPath,
		Size:     int64(len(body)),
		SHA256:   hex.EncodeToString(sum[:]),
		Mode:     fmt.Sprintf("%04o", perm),
		Required: required,
	})
	*packed = append(*packed, packedFile{
		hdr: &tar.Header{
			Name:     tarPath,
			Mode:     int64(perm),
			Size:     int64(len(body)),
			ModTime:  info.ModTime(),
			Typeflag: tar.TypeReg,
		},
		body: body,
	})
	return nil
}

//nolint:funlen // Cleanup-on-error is repeated per close site (tw, gz, out) by
// design — defer-stacks would re-order Close calls and obscure the failure
// path. Splitting into smaller helpers would push the gz/tw/out lifetimes
// across function boundaries, complicating reasoning about partial state.
func writeBackupTarball(outPath string, manifestBytes []byte, packed []packedFile) error {
	tmpPath := outPath + ".tmp"
	out, err := os.Create(tmpPath) // #nosec G304 -- operator-controlled path
	if err != nil {
		return fmt.Errorf("backup: create output: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmpPath) }

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	mhdr := &tar.Header{
		Name:     "manifest.json",
		Mode:     0o600,
		Size:     int64(len(manifestBytes)),
		ModTime:  time.Now().UTC(),
		Typeflag: tar.TypeReg,
	}
	if werr := tw.WriteHeader(mhdr); werr != nil {
		_ = tw.Close()
		_ = gz.Close()
		_ = out.Close()
		cleanup()
		return fmt.Errorf("backup: write manifest header: %w", werr)
	}
	if _, werr := tw.Write(manifestBytes); werr != nil {
		_ = tw.Close()
		_ = gz.Close()
		_ = out.Close()
		cleanup()
		return fmt.Errorf("backup: write manifest body: %w", werr)
	}

	for _, pf := range packed {
		if werr := tw.WriteHeader(pf.hdr); werr != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = out.Close()
			cleanup()
			return fmt.Errorf("backup: write %q header: %w", pf.hdr.Name, werr)
		}
		if _, werr := tw.Write(pf.body); werr != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = out.Close()
			cleanup()
			return fmt.Errorf("backup: write %q body: %w", pf.hdr.Name, werr)
		}
	}

	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = out.Close()
		cleanup()
		return fmt.Errorf("backup: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		_ = out.Close()
		cleanup()
		return fmt.Errorf("backup: close gzip: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		cleanup()
		return fmt.Errorf("backup: sync output: %w", err)
	}
	if err := out.Close(); err != nil {
		cleanup()
		return fmt.Errorf("backup: close output: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		cleanup()
		return fmt.Errorf("backup: rename: %w", err)
	}
	// Parent-dir fsync makes the rename durable on POSIX (matches D1.1a's
	// atomicWriteFile pattern). Best-effort: ENOTSUP on some filesystems and
	// Windows is silently ignored — the rename has already published the
	// file at the application level.
	if d, derr := os.Open(filepath.Dir(outPath)); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

//nolint:funlen // Mirrors writeBackupTarball's per-step error+cleanup
// shape; splitting would scatter the cleanup calls and obscure failure
// paths. writeEncryptedBackupTarball builds the same tar.gz envelope
// as writeBackupTarball but in memory, then seals it with AES-256-GCM
// using a passphrase-derived key (D1.4). The atomic outPath+".tmp" →
// rename → parent-dir fsync sequence matches the unencrypted path so
// no-overwrite and durability semantics are identical.
func writeEncryptedBackupTarball(outPath string, manifestBytes []byte, packed []packedFile, passphrase string) error {
	// Build the unencrypted tar.gz in memory.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	mhdr := &tar.Header{
		Name:     "manifest.json",
		Mode:     0o600,
		Size:     int64(len(manifestBytes)),
		ModTime:  time.Now().UTC(),
		Typeflag: tar.TypeReg,
	}
	if werr := tw.WriteHeader(mhdr); werr != nil {
		return fmt.Errorf("backup encrypt: write manifest header: %w", werr)
	}
	if _, werr := tw.Write(manifestBytes); werr != nil {
		return fmt.Errorf("backup encrypt: write manifest body: %w", werr)
	}
	for _, pf := range packed {
		if werr := tw.WriteHeader(pf.hdr); werr != nil {
			return fmt.Errorf("backup encrypt: write %q header: %w", pf.hdr.Name, werr)
		}
		if _, werr := tw.Write(pf.body); werr != nil {
			return fmt.Errorf("backup encrypt: write %q body: %w", pf.hdr.Name, werr)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("backup encrypt: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("backup encrypt: close gzip: %w", err)
	}

	// Seal the in-memory tar.gz under the passphrase.
	encrypted, err := encryptBackupBlob(buf.Bytes(), passphrase)
	if err != nil {
		return fmt.Errorf("backup encrypt: %w", err)
	}
	// Best-effort wipe of the plaintext gzip buffer; the underlying
	// arrays may already have been GC-mirrored, but we do the right
	// thing within stdlib semantics.
	zeroBytes(buf.Bytes())

	// Atomic write — same shape as writeBackupTarball.
	tmpPath := outPath + ".tmp"
	out, err := os.Create(tmpPath) // #nosec G304 -- operator-controlled path
	if err != nil {
		return fmt.Errorf("backup encrypt: create output: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := out.Write(encrypted); err != nil {
		_ = out.Close()
		cleanup()
		return fmt.Errorf("backup encrypt: write: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		cleanup()
		return fmt.Errorf("backup encrypt: sync: %w", err)
	}
	if err := out.Close(); err != nil {
		cleanup()
		return fmt.Errorf("backup encrypt: close: %w", err)
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		cleanup()
		return fmt.Errorf("backup encrypt: rename: %w", err)
	}
	if d, derr := os.Open(filepath.Dir(outPath)); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
