// Release Catalog Runtime — Slice 1 (Catalog Load + Resolve).
//
// A pure, in-process, UNSIGNED, local-source, read-only release catalog. It
// parses the release index + referenced manifests, validates them fail-closed,
// verifies each manifest's content hash against its RAW bytes, and builds the
// forward (channel → release) and reverse (pinned ref → release) indexes the
// rest of the release layer depends on.
//
// Scope (roadmap/D1.6d-P1.2-release-catalog-runtime-plan.md): Catalog Load +
// Resolve only. NO signatures, NO network/refresh, NO GUI, NO agent calls, NO
// upgrade dispatch, NO rollback-candidate computation, NO CP→DP propagation.
//
// Control-Plane-only: nothing here is wired into the proxy/data-plane path by
// this slice; it returns a DIGEST (`repo@sha256:…`, the agent's native
// currency) and has no release/channel awareness on the agent side.
//
// Integrity ≠ authenticity: the manifest_sha256 check (§4.9) is a content hash,
// NOT a signature. It catches corruption/drift but is worthless against a
// tampering attacker, and the INDEX itself has no integrity protection until a
// later slice signs it. Do not treat a loaded catalog as authenticated.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// catalogSchemaMajor is the highest supported MAJOR schema version. An
	// index or manifest with schema_version < 1 or > this is rejected
	// (unsupported major); additive changes within a supported major surface
	// only as unknown fields, which are tolerated (§4.0).
	catalogSchemaMajor = 1
	// catalogMaxReadBytes bounds every index/manifest read so a corrupt or
	// hostile source cannot OOM the loader. Forward-safe for the network/bundle
	// sources a later slice will add behind the same interface (§3).
	catalogMaxReadBytes = 1 << 20 // 1 MiB
	// catalogMaxIDLen bounds release_id and channel keys. release_id is
	// otherwise opaque, but an unbounded value is a log/SIEM/GUI-injection
	// vector once it flows downstream (§4.7).
	catalogMaxIDLen = 128
)

var (
	catalogListDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	catalogSHA256HexRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	catalogRepoRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*$`)
	catalogSemverRE     = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+].*)?$`)
)

// Channel is a curated release-catalog pointer. The set is closed; unknown
// channel keys in an index are ignored (forward-compat), never honored.
type Channel string

const (
	ChannelRecommended Channel = "recommended"
	ChannelLTS         Channel = "lts"
	ChannelCritical    Channel = "critical"
)

// Severity classifies a release. Known values are normal/critical; any other
// on-disk value is retained as SeverityUnknown (neither suppressed nor
// escalated) so a forward catalog still loads (§4.0).
type Severity string

const (
	SeverityNormal   Severity = "normal"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

// CatalogSource abstracts where the catalog bytes come from. The only concrete
// implementation in this slice is a local directory (symlink-refusing,
// size-bounded); a registry/bundle source is a later slice.
type CatalogSource interface {
	// ReadIndex returns the raw index.json bytes (bounded).
	ReadIndex() ([]byte, error)
	// ReadManifest returns the raw bytes for the manifest named by an index
	// entry's manifest_ref (a bare name; the implementation must reject
	// separators/traversal and refuse symlinks).
	ReadManifest(ref string) ([]byte, error)
}

// Release is a fully-resolved catalog record.
type Release struct {
	ReleaseID  string
	VersionID  string
	Severity   Severity
	Repo       string
	ListDigest string // bare "sha256:<64hex>" manifest-list digest
	// PinnedRef is the AGENT-FACING image_ref, derived at load as
	// Repo + "@" + ListDigest = "repo@sha256:<64hex>". It satisfies the agent's
	// validatePinnedDigestRef / image_allowlist SHAPE (P1.4); repo-EQUALITY
	// with a deployment's proxy_repo is the dispatch layer's responsibility,
	// not this slice's.
	PinnedRef      string
	MinUpgradeFrom string
	ChangelogURL   string
	Notes          string
}

// Catalog is an immutable, read-only release catalog built by LoadCatalog. All
// query methods are pure and side-effect-free.
type Catalog struct {
	byReleaseID map[string]Release
	byPinnedRef map[string]string // PinnedRef → ReleaseID (reverse index)
	channels    map[Channel]string
	generatedAt time.Time
}

// ResolvedRelease is the forward-resolution result handed (by a later slice)
// directly to the agent's upgrades.apply / rollbacks.
type ResolvedRelease struct {
	ReleaseID string
	VersionID string
	Severity  Severity
	PinnedRef string
}

// CurrentView is the derived "what is running now" result. Known is true ONLY
// when the supplied running digest exactly matched a catalog PinnedRef.
type CurrentView struct {
	Known     bool
	ReleaseID string
	VersionID string
}

// ReleaseView is a digest-free enumeration entry for a future GUI.
type ReleaseView struct {
	ReleaseID string
	VersionID string
	Severity  Severity
	Channels  []Channel
}

// ─── on-disk shapes (timestamps kept as strings for clean parse errors) ──────

type catalogIndexFile struct {
	SchemaVersion int                 `json:"schema_version"`
	GeneratedAt   string              `json:"generated_at"`
	Channels      map[string]string   `json:"channels"`
	Releases      []catalogIndexEntry `json:"releases"`
}

type catalogIndexEntry struct {
	ReleaseID      string `json:"release_id"`
	VersionID      string `json:"version_id"`
	ManifestRef    string `json:"manifest_ref"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type catalogManifestFile struct {
	SchemaVersion int    `json:"schema_version"`
	ReleaseID     string `json:"release_id"`
	VersionID     string `json:"version_id"`
	Severity      string `json:"severity"`
	CreatedAt     string `json:"created_at"`
	Image         struct {
		Repo       string   `json:"repo"`
		ListDigest string   `json:"list_digest"`
		Platforms  []string `json:"platforms"`
	} `json:"image"`
	MinUpgradeFrom string `json:"min_upgrade_from"`
	ChangelogURL   string `json:"changelog_url"`
	Notes          string `json:"notes"`
}

// LoadCatalog reads, validates, and indexes a catalog from src. It is
// fail-closed for everything except the closed forward-compatible set (unknown
// extra fields, unknown channel keys, unknown severity): any required-field or
// shape failure, hash mismatch, duplicate identity, dangling required
// reference, or unsupported major returns a nil catalog and a non-nil error
// (never a partial catalog).
//
// The body is a single linear validation pipeline; splitting it would scatter
// the fail-closed ordering the contract pins.
//
//nolint:gocyclo,cyclop // single-pass fail-closed validation pipeline
func LoadCatalog(src CatalogSource) (*Catalog, error) {
	idxBytes, err := src.ReadIndex()
	if err != nil {
		return nil, fmt.Errorf("release catalog: read index: %w", err)
	}
	var idx catalogIndexFile
	if err := json.Unmarshal(idxBytes, &idx); err != nil {
		return nil, fmt.Errorf("release catalog: parse index: %w", err)
	}
	if err := catalogCheckSchemaMajor("index", idx.SchemaVersion); err != nil {
		return nil, err
	}
	genAt, err := time.Parse(time.RFC3339, idx.GeneratedAt)
	if err != nil {
		return nil, fmt.Errorf("release catalog: index generated_at: %w", err)
	}
	if len(idx.Releases) == 0 {
		return nil, errors.New("release catalog: index has no releases")
	}

	cat := &Catalog{
		byReleaseID: make(map[string]Release, len(idx.Releases)),
		byPinnedRef: make(map[string]string, len(idx.Releases)),
		channels:    make(map[Channel]string),
		generatedAt: genAt,
	}

	for i := range idx.Releases {
		e := idx.Releases[i]
		if err := catalogValidateID("release_id", e.ReleaseID); err != nil {
			return nil, err
		}
		if e.VersionID == "" {
			return nil, fmt.Errorf("release catalog: release %q: empty version_id", e.ReleaseID)
		}
		if !catalogSHA256HexRE.MatchString(e.ManifestSHA256) {
			return nil, fmt.Errorf("release catalog: release %q: manifest_sha256 must be 64 lowercase hex", e.ReleaseID)
		}
		if _, dup := cat.byReleaseID[e.ReleaseID]; dup {
			return nil, fmt.Errorf("release catalog: duplicate release_id %q", e.ReleaseID)
		}

		manBytes, err := src.ReadManifest(e.ManifestRef)
		if err != nil {
			return nil, fmt.Errorf("release catalog: release %q: read manifest: %w", e.ReleaseID, err)
		}
		// Hash binding over the RAW bytes as read — never re-marshaled JSON.
		sum := sha256.Sum256(manBytes)
		if hex.EncodeToString(sum[:]) != e.ManifestSHA256 {
			return nil, fmt.Errorf("release catalog: release %q: manifest_sha256 mismatch (corruption or drift)", e.ReleaseID)
		}
		var man catalogManifestFile
		if err := json.Unmarshal(manBytes, &man); err != nil {
			return nil, fmt.Errorf("release catalog: release %q: parse manifest: %w", e.ReleaseID, err)
		}
		rel, err := catalogBuildRelease(e, man)
		if err != nil {
			return nil, err
		}
		if _, dup := cat.byPinnedRef[rel.PinnedRef]; dup {
			return nil, fmt.Errorf("release catalog: duplicate pinned ref %q (one digest must map to one release)", rel.PinnedRef)
		}
		cat.byReleaseID[rel.ReleaseID] = rel
		cat.byPinnedRef[rel.PinnedRef] = rel.ReleaseID
	}

	// Channels: ignore unknown keys (forward-compat); a KNOWN key must resolve.
	for key, relID := range idx.Channels {
		ch, known := catalogKnownChannel(key)
		if !known {
			continue
		}
		if _, ok := cat.byReleaseID[relID]; !ok {
			return nil, fmt.Errorf("release catalog: channel %q points to unknown release_id %q (dangling)", key, relID)
		}
		cat.channels[ch] = relID
	}

	return cat, nil
}

// catalogBuildRelease validates a single manifest against its index entry and
// returns the derived Release (or a fail-closed error).
func catalogBuildRelease(e catalogIndexEntry, man catalogManifestFile) (Release, error) {
	if err := catalogCheckSchemaMajor("manifest "+e.ReleaseID, man.SchemaVersion); err != nil {
		return Release{}, err
	}
	// Cross-consistency: a swapped/mismatched manifest is caught here.
	if man.ReleaseID != e.ReleaseID || man.VersionID != e.VersionID {
		return Release{}, fmt.Errorf("release catalog: manifest for %q has release_id/version_id %q/%q, index entry says %q/%q",
			e.ReleaseID, man.ReleaseID, man.VersionID, e.ReleaseID, e.VersionID)
	}
	if !catalogSemverRE.MatchString(man.VersionID) {
		return Release{}, fmt.Errorf("release catalog: release %q: version_id %q is not semver", e.ReleaseID, man.VersionID)
	}
	if err := catalogValidateRepo(man.Image.Repo); err != nil {
		return Release{}, fmt.Errorf("release catalog: release %q: %w", e.ReleaseID, err)
	}
	if !catalogListDigestRE.MatchString(man.Image.ListDigest) {
		return Release{}, fmt.Errorf("release catalog: release %q: image.list_digest must be sha256:<64 lowercase hex>", e.ReleaseID)
	}
	if man.CreatedAt == "" {
		return Release{}, fmt.Errorf("release catalog: release %q: created_at is required", e.ReleaseID)
	}
	if _, err := time.Parse(time.RFC3339, man.CreatedAt); err != nil {
		return Release{}, fmt.Errorf("release catalog: release %q: created_at: %w", e.ReleaseID, err)
	}
	if man.MinUpgradeFrom != "" && !catalogSemverRE.MatchString(man.MinUpgradeFrom) {
		return Release{}, fmt.Errorf("release catalog: release %q: min_upgrade_from %q is not semver", e.ReleaseID, man.MinUpgradeFrom)
	}

	pinnedRef := man.Image.Repo + "@" + man.Image.ListDigest
	// §4.14a: the derived ref must match the agent's repo@sha256:<64hex> shape
	// (a pinned cross-component contract; implied by repo + list_digest checks).
	if !strings.HasPrefix(pinnedRef, man.Image.Repo+"@") ||
		!catalogListDigestRE.MatchString(strings.TrimPrefix(pinnedRef, man.Image.Repo+"@")) {
		return Release{}, fmt.Errorf("release catalog: release %q: derived pinned ref %q is not repo@sha256:<64hex>", e.ReleaseID, pinnedRef)
	}

	return Release{
		ReleaseID:      man.ReleaseID,
		VersionID:      man.VersionID,
		Severity:       catalogParseSeverity(man.Severity),
		Repo:           man.Image.Repo,
		ListDigest:     man.Image.ListDigest,
		PinnedRef:      pinnedRef,
		MinUpgradeFrom: man.MinUpgradeFrom,
		ChangelogURL:   man.ChangelogURL,
		Notes:          man.Notes,
	}, nil
}

func catalogCheckSchemaMajor(what string, v int) error {
	if v < 1 || v > catalogSchemaMajor {
		return fmt.Errorf("release catalog: %s schema_version %d is unsupported (supported major: %d)", what, v, catalogSchemaMajor)
	}
	return nil
}

func catalogKnownChannel(key string) (Channel, bool) {
	switch Channel(key) {
	case ChannelRecommended, ChannelLTS, ChannelCritical:
		return Channel(key), true
	}
	return "", false
}

func catalogParseSeverity(s string) Severity {
	switch Severity(s) {
	case SeverityNormal, SeverityCritical:
		return Severity(s)
	}
	return SeverityUnknown
}

// catalogValidateID bounds an opaque identifier (release_id / channel key):
// printable ASCII (0x21–0x7e: no control chars, no whitespace, no non-ASCII),
// non-empty, length ≤ catalogMaxIDLen.
func catalogValidateID(field, id string) error {
	if id == "" {
		return fmt.Errorf("release catalog: %s is empty", field)
	}
	if len(id) > catalogMaxIDLen {
		return fmt.Errorf("release catalog: %s exceeds %d bytes", field, catalogMaxIDLen)
	}
	for _, r := range id {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("release catalog: %s %q must be printable ASCII with no whitespace", field, id)
		}
	}
	return nil
}

// catalogValidateRepo enforces a bare repository: no tag (no ':' after the
// final '/'; a registry host:port before the path is allowed), no @digest. Same
// spirit as the agent's proxy_repo rule (P1.4).
func catalogValidateRepo(repo string) error {
	if repo == "" {
		return errors.New("image.repo is empty")
	}
	if len(repo) > 255 {
		return fmt.Errorf("image.repo %q is too long", repo)
	}
	if strings.ContainsAny(repo, "@") || strings.Contains(repo, "sha256:") {
		return fmt.Errorf("image.repo %q must be a bare repository (no @digest)", repo)
	}
	if !catalogRepoRE.MatchString(repo) {
		return fmt.Errorf("image.repo %q has an invalid repository shape", repo)
	}
	if i := strings.LastIndexByte(repo, '/'); strings.IndexByte(repo[i+1:], ':') >= 0 {
		return fmt.Errorf("image.repo %q must not include a tag", repo)
	}
	return nil
}

// ─── local-directory source (symlink-refusing, size-bounded) ─────────────────

type dirCatalogSource struct{ dir string }

// NewDirCatalogSource returns a CatalogSource backed by a local directory
// containing index.json and manifests/<name>.json. It refuses symlinks and
// bounds every read.
func NewDirCatalogSource(dir string) CatalogSource { return &dirCatalogSource{dir: dir} }

func (s *dirCatalogSource) ReadIndex() ([]byte, error) {
	return catalogReadBounded(filepath.Join(s.dir, "index.json"))
}

func (s *dirCatalogSource) ReadManifest(ref string) ([]byte, error) {
	if err := catalogValidateManifestRef(ref); err != nil {
		return nil, err
	}
	return catalogReadBounded(filepath.Join(s.dir, "manifests", ref))
}

func catalogValidateManifestRef(ref string) error {
	if ref == "" {
		return errors.New("release catalog: empty manifest_ref")
	}
	if ref != filepath.Base(ref) || strings.ContainsAny(ref, `/\`) ||
		ref == "." || ref == ".." || strings.ContainsRune(ref, 0) {
		return fmt.Errorf("release catalog: manifest_ref %q must be a bare filename (no path separators/traversal)", ref)
	}
	return nil
}

// catalogReadBounded reads a regular file, refusing symlinks (Lstat + O_NOFOLLOW)
// and capping the read at catalogMaxReadBytes.
func catalogReadBounded(path string) ([]byte, error) {
	base := filepath.Base(path)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("release catalog: %s is a symlink; refusing to follow", base)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("release catalog: %s is not a regular file", base)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- path joined under a fixed dir; ref shape-validated; symlinks refused
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, catalogMaxReadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > catalogMaxReadBytes {
		return nil, fmt.Errorf("release catalog: %s exceeds the %d-byte read bound", base, catalogMaxReadBytes)
	}
	return data, nil
}
