// Release Catalog Distribution — P1.5 Slice d (air-gap BundleCatalogProvider).
//
// BundleCatalogProvider is a TRANSPORT that stages the CATALOG portion of a
// signed offline release bundle (a tar / tar.gz archive carried into an
// air-gapped site) into a fresh temp dir, which the caller then hands to
// LoadVerifiedCatalog (the P1.3 trust boundary) exactly like any other source.
// Verification is identical to online — only the transport differs (plan §8).
//
// Unlike the HTTP provider, the bundle is COMPLETE before any parse, so no
// two-phase gate is needed (plan §5.1: local/bundle providers stage-then-verify
// unchanged). The provider therefore does NO trust work at all — it only moves
// bytes, under a hostile-archive discipline:
//   - any absolute / traversal ("..") / backslash / NUL entry name rejects the
//     whole bundle (never silently skipped);
//   - any symlink or hardlink entry rejects the whole bundle;
//   - catalog entries must be regular files within per-file and total bounds;
//   - non-catalog entries (the future image blobs, plan §8) are skipped
//     WITHOUT reading their content;
//   - index.json is required; index.json.sig and index.json.sigstore are staged
//     when present — the enforce/permissive decision for a missing signature
//     belongs to the P1.3 mode at verify time, not to the transport.
//
// Scope (roadmap/D1.6d-P1.5-catalog-distribution-plan.md — Slice d): catalog
// extraction + staging + cleanup only. NO image docker-load (the bundle slice
// that loads images MUST bind loaded-image-digest == authenticated list_digest,
// P1.3 §7 — recorded there, not here), NO outer bundle signature, NO GUI/API,
// NO dispatch, NO agent changes, NO HTTP changes.
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	// bundleMaxCatalogFiles bounds how many catalog files one bundle may stage
	// (1 index + 1 sig + manifests) so a hostile archive cannot exhaust inodes.
	bundleMaxCatalogFiles = 1024
	// bundleMaxTotalBytes bounds the TOTAL staged bytes (per-file bound is
	// catalogMaxReadBytes); a hostile archive cannot fill the disk.
	bundleMaxTotalBytes = 64 << 20 // 64 MiB
)

// BundleCatalogProvider stages the catalog files out of an offline release
// bundle archive at a fixed local path (operator-imported).
type BundleCatalogProvider struct {
	path      string
	stageBase string // parent dir for the temp staging dir ("" ⇒ os.TempDir())
}

// NewBundleCatalogProvider builds a provider over a local bundle archive path.
func NewBundleCatalogProvider(bundlePath string) *BundleCatalogProvider {
	return &BundleCatalogProvider{path: bundlePath}
}

// Stage extracts index.json, index.json.sig (when present), and manifests/* from
// the bundle into a fresh temp dir and returns its path. The CALLER owns the
// returned dir and must remove it after handing it to LoadVerifiedCatalog. On
// ANY failure the staging dir is removed before return (atomic cleanup).
func (p *BundleCatalogProvider) Stage(ctx context.Context) (stagingDir string, err error) {
	f, err := os.Open(p.path) // #nosec G304 G703 -- operator-supplied local bundle path (import action), not request input
	if err != nil {
		return "", fmt.Errorf("release catalog: open bundle: %w", err)
	}
	defer func() { _ = f.Close() }()

	rd, err := bundleReader(f)
	if err != nil {
		return "", err
	}

	stage, err := os.MkdirTemp(p.stageBase, "catalog-bundle-stage-*")
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := os.MkdirAll(filepath.Join(stage, "manifests"), 0o750); err != nil {
		return "", err
	}

	if err := extractCatalogEntries(ctx, tar.NewReader(rd), stage); err != nil {
		return "", err
	}

	committed = true
	return stage, nil
}

// bundleReader sniffs the gzip magic and returns a plain or gunzipping reader.
func bundleReader(f *os.File) (io.Reader, error) {
	br := bufio.NewReader(f)
	magic, err := br.Peek(2)
	if err != nil {
		return nil, fmt.Errorf("release catalog: read bundle: %w", err)
	}
	if magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("release catalog: gunzip bundle: %w", err)
		}
		return gz, nil
	}
	return br, nil
}

// extractCatalogEntries walks the tar stream, hard-rejecting hostile entries and
// staging only the catalog files (everything else is skipped unread).
func extractCatalogEntries(ctx context.Context, tr *tar.Reader, stage string) error {
	var (
		files      int
		totalBytes int64
		sawIndex   bool
	)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("release catalog: read bundle: %w", err)
		}
		if err := rejectHostileEntry(hdr); err != nil {
			return err
		}

		dst, isIndex, ok := classifyBundleEntry(hdr)
		if !ok {
			continue // not a catalog file (future image blobs etc.) — skipped unread
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("release catalog: bundle entry %q is not a regular file", hdr.Name)
		}
		if hdr.Size > catalogMaxReadBytes {
			return fmt.Errorf("release catalog: bundle entry %q exceeds the %d-byte bound", hdr.Name, catalogMaxReadBytes)
		}
		files++
		totalBytes += hdr.Size
		if files > bundleMaxCatalogFiles {
			return fmt.Errorf("release catalog: bundle exceeds %d catalog files", bundleMaxCatalogFiles)
		}
		if totalBytes > bundleMaxTotalBytes {
			return fmt.Errorf("release catalog: bundle catalog content exceeds the %d-byte total bound", int64(bundleMaxTotalBytes))
		}
		if err := writeBundleFile(filepath.Join(stage, dst), tr, hdr.Size); err != nil {
			return fmt.Errorf("release catalog: stage %q: %w", hdr.Name, err)
		}
		sawIndex = sawIndex || isIndex
	}
	if !sawIndex {
		return errors.New("release catalog: bundle has no index.json")
	}
	return nil
}

// rejectHostileEntry hard-fails the whole bundle on traversal/absolute/escape
// names and on link entries — these are NEVER silently skipped.
func rejectHostileEntry(hdr *tar.Header) error {
	name := hdr.Name
	if strings.ContainsRune(name, 0) || strings.ContainsRune(name, '\\') {
		return fmt.Errorf("release catalog: bundle entry name %q contains forbidden characters", sanitizeLog(name))
	}
	if path.IsAbs(name) {
		return fmt.Errorf("release catalog: bundle entry %q has an absolute path", sanitizeLog(name))
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("release catalog: bundle entry %q escapes the bundle root (traversal)", sanitizeLog(name))
	}
	switch hdr.Typeflag {
	case tar.TypeSymlink, tar.TypeLink:
		return fmt.Errorf("release catalog: bundle entry %q is a link; links are forbidden", sanitizeLog(name))
	}
	return nil
}

// classifyBundleEntry maps a tar entry to its staging-relative destination.
// ok=false means "not a catalog file" (skip unread). Directories are skipped.
// A manifests/ entry must be a BARE name one level deep (P1.2 §4.5).
func classifyBundleEntry(hdr *tar.Header) (dst string, isIndex, ok bool) {
	name := strings.TrimPrefix(path.Clean(hdr.Name), "./")
	if hdr.Typeflag == tar.TypeDir {
		return "", false, false
	}
	switch {
	case name == "index.json":
		return "index.json", true, true
	case name == "index.json.sig":
		return "index.json.sig", false, true
	case name == "index.json.sigstore":
		// Keyless (Sigstore) sidecar (P2b) — staged alongside .sig so an air-gap
		// bundle's keyless signature survives import and LoadVerifiedCatalog can
		// verify it under the Sigstore scheme.
		return "index.json.sigstore", false, true
	case strings.HasPrefix(name, "manifests/"):
		ref := strings.TrimPrefix(name, "manifests/")
		if catalogValidateManifestRef(ref) != nil {
			return "", false, false // nested/odd manifests path — not a catalog file
		}
		return path.Join("manifests", ref), false, true
	default:
		return "", false, false
	}
}

// writeBundleFile copies one bounded entry to dst. dst is built from a fixed
// stage dir + a classifyBundleEntry-validated relative name.
func writeBundleFile(dst string, r io.Reader, size int64) (err error) {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 G703 -- fixed stage dir + validated bare names
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	n, err := io.Copy(out, io.LimitReader(r, catalogMaxReadBytes+1))
	if err != nil {
		return err
	}
	if n > catalogMaxReadBytes || n != size {
		return fmt.Errorf("entry size mismatch (%d bytes copied, header said %d)", n, size)
	}
	return nil
}
