package main

// saas_feed_genstore.go — F3b-2: immutable generation storage.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md — the F3b-2 slice
// (downloader / verify / immutable-generation storage), §B.4 (on-disk contract)
// and §B.5 S1–S2 (build the generation off-path, re-verify stored bytes, atomic
// rename → generations/<id>, fsync parent). This file owns ONLY the durable,
// node-local immutable-generation write; it performs NO network I/O, NO Sigstore
// verification (the caller in saas_feed_client.go has already fully verified the
// candidate), NO floor write/advance, NO activation-record commit, NO live
// cutover, and NO GC. It is UNWIRED until F3b-3 composes it.
//
// Immutability & atomicity (§B.5). A generation is built in a staging directory
// created UNDER the generations parent (same filesystem, so the final rename is
// atomic and never crosses devices). Each file is written via fileutil.AtomicWrite
// (temp → fsync → rename → parent-dir fsync), then READ BACK and byte/digest
// verified. The staging dir is fsynced, atomically renamed to the final immutable
// path, the parent dir is fsynced, and the final dir is read back and re-validated.
// A temporary/partial generation NEVER appears at the committed path: os.Rename is
// the single commit point, and a non-existent-target rename is the only way the
// final path comes into being.
//
// No-overwrite + idempotency + conflict (task required outcome / §B.7 content
// selection is digest-driven). An EXISTING generation at the target id is NEVER
// overwritten. It is treated as idempotent ONLY after a full byte + digest
// re-validation proves it is byte-identical to the candidate. A same-id generation
// whose stored bytes/digests differ from the candidate is a HARD CONFLICT (two
// different contents claiming one immutable id) — reported, never resolved by
// overwrite.
//
// Generation id (§B.3/§B.4). The id is the decimal feed_version string; the dir is
// generations/<feed_version>. The id is bound to the feed version, and the stored
// generation.json metadata record binds it to the manifest+artifact SHA-256 digests
// — so a later slice re-derives the floor record's (generation_id, manifest_sha256,
// artifact_sha256) triple from the persisted evidence without any network access.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// ─── constants ──────────────────────────────────────────────────────────────────

const (
	// genMetaSchemaVersion is the only supported generation-metadata schema.
	genMetaSchemaVersion = 1

	// The immutable files of a generation. The first four are the §B.4 on-disk
	// contract: the two signed-evidence files (manifest envelope + artifact), the
	// artifact Sigstore bundle, and snapshot.normalized.json — the feed-owned
	// normalized category layer F3b-3 composes with overrides at activation, derived
	// deterministically from the VERIFIED artifact and staged before the commit rename
	// (so it never has to be added later by mutating the immutable dir). generation.json
	// is the additional canonical verified metadata / commit-intent record the F3b-2
	// slice requires — it binds the signed digests so F3b-3 re-verifies offline.
	genFileManifestEnvelope   = "manifest.envelope.json"
	genFileArtifact           = "artifact.json"
	genFileArtifactBundle     = "artifact.json.sigstore"
	genFileSnapshotNormalized = "snapshot.normalized.json"
	genFileMeta               = "generation.json"

	genFilePerm os.FileMode = 0o600 // generation files are 0600.
	genDirPerm  os.FileMode = 0o700 // the generations/<id> dir is 0700.

	// genStagePrefix marks a staging directory owned by this engine. Cleanup only
	// ever removes paths under this prefix (safe cleanup of owned staging paths).
	genStagePrefix = ".stage-"
)

// ─── structured errors ───────────────────────────────────────────────────────────

var (
	errGenRoot        = errors.New("saas feed generation: empty generations root")
	errGenVersion     = errors.New("saas feed generation: invalid feed_version")
	errGenDigest      = errors.New("saas feed generation: invalid sha-256 digest")
	errGenSizeBound   = errors.New("saas feed generation: byte payload exceeds bound")
	errGenConflict    = errors.New("saas feed generation: existing generation has different bytes/identity (hard conflict)")
	errGenReadBack    = errors.New("saas feed generation: read-back verification failed")
	errGenStage       = errors.New("saas feed generation: staging failed")
	errGenCommit      = errors.New("saas feed generation: commit (rename) failed")
	errGenPartial     = errors.New("saas feed generation: partial existing generation is not committed")
	errGenUnexpected  = errors.New("saas feed generation: unexpected stored layout")
	errGenNotVerified = errors.New("saas feed generation: candidate bytes did not re-derive the expected digests")
)

// ─── candidate + metadata ────────────────────────────────────────────────────────

// generationCandidate is the fully-verified, digest-bound input to Persist. The
// caller (saas_feed_client.go) has already run the complete F0 §6 verify — the
// signatures over EnvelopeBytes and ArtifactBytes passed against the pinned
// identity, and the manifest binds the artifact by size + SHA-256. Persist re-binds
// the raw bytes to the digests defensively (verify-before-persist parity) and never
// trusts a field without the bytes proving it.
type generationCandidate struct {
	FeedVersion    int64
	GenerationID   string // == decimal FeedVersion
	GeneratedAt    string // canonical whole-second UTC RFC3339 (from the verified manifest)
	ExpiresAt      string
	ManifestSHA256 string // sha256(EnvelopeBytes), lowercase hex
	ArtifactSHA256 string // sha256(ArtifactBytes) == manifest.ArtifactSHA256
	ArtifactSize   int64
	CategoryCount  int
	HostCount      int

	EnvelopeBytes []byte // exact wire manifest envelope
	ArtifactBytes []byte // exact wire artifact
	BundleBytes   []byte // exact wire artifact Sigstore bundle
	SnapshotBytes []byte // canonical normalized feed-layer snapshot (derived from the VERIFIED artifact)
}

// generationMeta is the canonical verified metadata / commit-intent record persisted
// as generation.json. It carries enough SIGNED-EVIDENCE binding (version + both
// digests + counts + timestamps + pinned constants) for F3b-3 to re-verify the
// immutable generation offline and to reconstruct the floor record. Its bytes are
// canonical (fixed field order, no HTML escaping, no trailing newline) so the record
// is byte-stable across writers.
type generationMeta struct {
	SchemaVersion  int    `json:"schema_version"`
	Protocol       string `json:"protocol"`
	Feed           string `json:"feed"`
	FeedVersion    int64  `json:"feed_version"`
	GeneratedAt    string `json:"generated_at"`
	ExpiresAt      string `json:"expires_at"`
	GenerationID   string `json:"generation_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	ArtifactSize   int64  `json:"artifact_size"`
	CategoryCount  int    `json:"category_count"`
	HostCount      int    `json:"host_count"`
}

func (c generationCandidate) meta() generationMeta {
	return generationMeta{
		SchemaVersion:  genMetaSchemaVersion,
		Protocol:       urlcatfeed.Protocol,
		Feed:           urlcatfeed.FeedID,
		FeedVersion:    c.FeedVersion,
		GeneratedAt:    c.GeneratedAt,
		ExpiresAt:      c.ExpiresAt,
		GenerationID:   c.GenerationID,
		ManifestSHA256: c.ManifestSHA256,
		ArtifactSHA256: c.ArtifactSHA256,
		ArtifactSize:   c.ArtifactSize,
		CategoryCount:  c.CategoryCount,
		HostCount:      c.HostCount,
	}
}

// validate checks the candidate is internally consistent BEFORE any filesystem
// action: version ≥ 1, id == decimal version, digests are 64-hex and re-derive from
// the raw bytes, size matches, and no payload exceeds the protocol bound.
func (c generationCandidate) validate() error {
	if c.FeedVersion < 1 {
		return fmt.Errorf("%w: %d", errGenVersion, c.FeedVersion)
	}
	if c.GenerationID != strconv.FormatInt(c.FeedVersion, 10) {
		return fmt.Errorf("%w: id %q != feed_version %d", errGenVersion, c.GenerationID, c.FeedVersion)
	}
	if !validSHA256Hex(c.ManifestSHA256) || !validSHA256Hex(c.ArtifactSHA256) {
		return errGenDigest
	}
	if err := c.validatePayloadBounds(); err != nil {
		return err
	}
	// Re-bind bytes → digests (never trust the field without the bytes proving it).
	if sha256Hex(c.EnvelopeBytes) != c.ManifestSHA256 {
		return fmt.Errorf("%w: manifest envelope", errGenNotVerified)
	}
	if sha256Hex(c.ArtifactBytes) != c.ArtifactSHA256 {
		return fmt.Errorf("%w: artifact", errGenNotVerified)
	}
	return nil
}

// validatePayloadBounds checks each raw payload is present and within its protocol
// ceiling: envelope + bundle ≤ MaxBundleBytes, artifact == declared size ∈ (0, cap],
// and the derived normalized snapshot ≤ the artifact ceiling.
func (c generationCandidate) validatePayloadBounds() error {
	if len(c.EnvelopeBytes) == 0 || len(c.EnvelopeBytes) > urlcatfeed.MaxBundleBytes {
		return fmt.Errorf("%w: envelope %d", errGenSizeBound, len(c.EnvelopeBytes))
	}
	if int64(len(c.ArtifactBytes)) != c.ArtifactSize || c.ArtifactSize <= 0 || c.ArtifactSize > urlcatfeed.MaxArtifactSize {
		return fmt.Errorf("%w: artifact %d (declared %d)", errGenSizeBound, len(c.ArtifactBytes), c.ArtifactSize)
	}
	if len(c.BundleBytes) == 0 || len(c.BundleBytes) > urlcatfeed.MaxBundleBytes {
		return fmt.Errorf("%w: bundle %d", errGenSizeBound, len(c.BundleBytes))
	}
	// The normalized snapshot is derived from the verified artifact, so it is bounded by
	// the same artifact ceiling; it must be present (F3b-3 needs the feed-owned layer).
	if len(c.SnapshotBytes) == 0 || len(c.SnapshotBytes) > urlcatfeed.MaxArtifactSize {
		return fmt.Errorf("%w: snapshot %d", errGenSizeBound, len(c.SnapshotBytes))
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ─── filesystem seam (injectable durability) ─────────────────────────────────────

// genFS is the narrow durability seam. Production delegates to fileutil.AtomicWrite
// (temp → fsync → rename → parent-dir fsync) and the os primitives. Tests inject
// failures at any boundary (mkdir, stage-tmp, atomic write, rename, dir sync,
// read-back) to prove no partial state ever appears committed.
type genFS struct {
	mkdirAll    func(path string, perm os.FileMode) error
	mkdirTemp   func(dir, pattern string) (string, error)
	atomicWrite func(path string, data []byte, perm os.FileMode) error
	rename      func(oldpath, newpath string) error
	syncDir     func(path string) error
	readFile    func(path string) ([]byte, error)
	stat        func(path string) (os.FileInfo, error)
	removeAll   func(path string) error
}

func osGenFS() genFS {
	return genFS{
		mkdirAll:    os.MkdirAll,
		mkdirTemp:   os.MkdirTemp,
		atomicWrite: fileutil.AtomicWrite,
		rename:      os.Rename,
		syncDir:     fsyncDir,
		readFile:    os.ReadFile, // #nosec G304 -- fixed constructed paths under the generations root
		stat:        os.Stat,
		removeAll:   os.RemoveAll,
	}
}

// isBenignDirSyncErr reports whether a directory fsync error is one of the portable
// "this FS does not support directory fsync" codes that fileutil.AtomicWrite also
// tolerates (EINVAL / ENOTSUP / EOPNOTSUPP).
func isBenignDirSyncErr(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

// fsyncDir opens dir and fsyncs it (best-effort like fileutil's parent-dir sync:
// EINVAL/ENOTSUP are tolerated because directory fsync is not portable).
func fsyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- fixed constructed dir under the generations root
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil && !isBenignDirSyncErr(syncErr) {
		return syncErr
	}
	if closeErr != nil && syncErr == nil {
		return closeErr
	}
	return nil
}

// ─── the generation store ────────────────────────────────────────────────────────

// generationStore owns the generations root + the durability seam. Persist is the
// only mutator; it is safe for concurrent use (a per-id write mutex serializes
// in-process advances of the SAME id so two concurrent acquisitions converge to one
// committed dir, and cross-process safety comes from the atomic no-overwrite rename).
type generationStore struct {
	fs   genFS
	root string // <dataDir>/saas_feed/generations
	// locks serialize in-process writers per generation id.
	locks *keyedMutex
}

func newGenerationStore(root string) (*generationStore, error) {
	return newGenerationStoreFS(osGenFS(), root)
}

func newGenerationStoreFS(fs genFS, root string) (*generationStore, error) {
	if root == "" {
		return nil, errGenRoot
	}
	return &generationStore{fs: fs, root: root, locks: newKeyedMutex()}, nil
}

// genPersistOutcome classifies the durable result.
type genPersistOutcome int

const (
	genPersistCommitted  genPersistOutcome = iota // a NEW immutable generation was created
	genPersistIdempotent                          // an existing generation was byte/digest-identical
)

func (o genPersistOutcome) String() string {
	if o == genPersistIdempotent {
		return "idempotent"
	}
	return "committed"
}

type genPersistResult struct {
	Outcome genPersistOutcome
	Dir     string // absolute committed generation directory
}

// finalDir is the immutable committed path for id.
func (s *generationStore) finalDir(id string) string {
	return filepath.Join(s.root, id)
}

// Persist durably stores the verified candidate as an immutable generation and
// returns the committed dir. It is transactional: on any staging/write/read-back/
// rename failure it removes the owned staging dir and returns an error, having
// created NO committed path. Cancellation at any stage is classified (context error)
// and likewise leaves nothing committed. An existing generation short-circuits to a
// byte/digest re-validation (idempotent) or a hard conflict — never an overwrite.
func (s *generationStore) Persist(ctx context.Context, cand generationCandidate) (genPersistResult, error) {
	if err := cand.validate(); err != nil {
		return genPersistResult{}, err
	}
	// Serialize in-process writers of the same id so concurrent acquisitions of the
	// SAME generation converge (idempotent) instead of racing two stagings into one
	// rename target.
	unlock := s.locks.lock(cand.GenerationID)
	defer unlock()

	if err := ctx.Err(); err != nil {
		return genPersistResult{}, err
	}
	final := s.finalDir(cand.GenerationID)

	// If a committed generation already exists, never overwrite: validate-existing.
	if _, err := s.fs.stat(final); err == nil {
		return s.reconcileExisting(cand, final)
	} else if !errors.Is(err, os.ErrNotExist) {
		return genPersistResult{}, fmt.Errorf("saas feed generation: stat %s: %w", final, err)
	}

	// Fresh commit path: stage → write+readback each file → sync staging → rename →
	// sync parent → final read-back.
	return s.stageAndCommit(ctx, cand, final)
}

// stageAndCommit builds the generation off-path and atomically renames it into place.
func (s *generationStore) stageAndCommit(ctx context.Context, cand generationCandidate, final string) (genPersistResult, error) {
	// The generations root must exist so the staging dir (its child) shares the same
	// filesystem as the final path — a cross-device rename is impossible by construction.
	if err := s.fs.mkdirAll(s.root, genDirPerm); err != nil {
		return genPersistResult{}, fmt.Errorf("%w: mkdir root: %v", errGenStage, err)
	}
	stage, err := s.fs.mkdirTemp(s.root, genStagePrefix+cand.GenerationID+"-*")
	if err != nil {
		return genPersistResult{}, fmt.Errorf("%w: mkdir temp: %v", errGenStage, err)
	}
	committed := false
	defer func() {
		if !committed {
			// Safe cleanup of an OWNED staging path only (never the final dir, never a
			// sibling): stage was returned by our mkdirTemp under genStagePrefix.
			_ = s.fs.removeAll(stage)
		}
	}()

	if err := s.writeStagedFiles(ctx, stage, cand.files()); err != nil {
		return genPersistResult{}, err
	}

	// Sync the staging directory (belt over AtomicWrite's per-file parent sync) so all
	// four entries are durable before the commit rename.
	if err := ctx.Err(); err != nil {
		return genPersistResult{}, err
	}
	if err := s.fs.syncDir(stage); err != nil {
		return genPersistResult{}, fmt.Errorf("%w: sync staging: %v", errGenStage, err)
	}

	// Commit: the SINGLE atomic rename. A non-existent target is required for the
	// commit to create the immutable path (a raced create is handled by ENOTEMPTY →
	// reconcileExisting below).
	if err := ctx.Err(); err != nil {
		return genPersistResult{}, err
	}
	if err := s.fs.rename(stage, final); err != nil {
		// A concurrent writer (another process/goroutine) may have committed the same
		// id first: the rename onto a now-existing dir fails. Fall back to validate-
		// existing so the loser converges to idempotent/conflict, not an error. `stage`
		// is still ours and un-renamed, so `committed` stays false and the defer cleans
		// it up (the winner owns `final`, which we never touch).
		if info, statErr := s.fs.stat(final); statErr == nil && info != nil {
			return s.reconcileExisting(cand, final)
		}
		return genPersistResult{}, fmt.Errorf("%w: %v", errGenCommit, err)
	}
	committed = true

	// Sync the parent (generations root) so the rename is durable.
	if err := s.fs.syncDir(s.root); err != nil {
		return genPersistResult{}, fmt.Errorf("%w: sync parent: %v", errGenCommit, err)
	}
	// Final read-back: re-validate the committed dir against the candidate.
	if err := s.validateStored(final, cand); err != nil {
		return genPersistResult{}, fmt.Errorf("%w: post-commit: %v", errGenReadBack, err)
	}
	return genPersistResult{Outcome: genPersistCommitted, Dir: final}, nil
}

// writeStagedFiles writes each generation file into the staging dir and immediately
// reads it back + byte-verifies it (write → sync → close → read-back; AtomicWrite
// fsyncs the file + staging dir). Cancellation is honored before each write.
func (s *generationStore) writeStagedFiles(ctx context.Context, stage string, files []genFile) error {
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		p := filepath.Join(stage, f.name)
		if err := s.fs.atomicWrite(p, f.data, genFilePerm); err != nil {
			return fmt.Errorf("%w: write %s: %v", errGenStage, f.name, err)
		}
		if err := s.readBackBytes(p, f.data); err != nil {
			return fmt.Errorf("%w: %s: %v", errGenReadBack, f.name, err)
		}
	}
	return nil
}

// reconcileExisting validates an existing committed generation against the candidate:
// byte/digest-identical ⇒ idempotent; any difference ⇒ hard conflict; a structurally
// incomplete existing dir ⇒ partial (never treated as committed success).
func (s *generationStore) reconcileExisting(cand generationCandidate, final string) (genPersistResult, error) {
	if err := s.validateStored(final, cand); err != nil {
		if errors.Is(err, errGenConflict) {
			return genPersistResult{}, err
		}
		// A present-but-incomplete/mismatching existing dir is not a committed
		// generation we may claim; surface it (F3b-3 recovery/GC decides), never
		// overwrite here.
		return genPersistResult{}, fmt.Errorf("%w: %v", errGenPartial, err)
	}
	return genPersistResult{Outcome: genPersistIdempotent, Dir: final}, nil
}

// validateStored reads all four files from dir and asserts they byte-match the
// candidate. A digest mismatch on the signed evidence is a HARD CONFLICT (a different
// content claims this immutable id); a missing/short file is a structural error.
func (s *generationStore) validateStored(dir string, cand generationCandidate) error {
	want := cand.files()
	for _, f := range want {
		got, err := s.fs.readFile(filepath.Join(dir, f.name))
		if err != nil {
			return fmt.Errorf("%w: read %s: %v", errGenUnexpected, f.name, err)
		}
		if !bytes.Equal(got, f.data) {
			// The two signed-evidence files (envelope, artifact) and the meta record
			// differ ⇒ a different generation claims this id.
			return fmt.Errorf("%w: %s differs", errGenConflict, f.name)
		}
	}
	return nil
}

// readBackBytes re-reads path and asserts an exact byte match.
func (s *generationStore) readBackBytes(path string, want []byte) error {
	got, err := s.fs.readFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("byte mismatch on read-back")
	}
	return nil
}

// genFile is one immutable file of a generation.
type genFile struct {
	name string
	data []byte
}

// files returns the four immutable files in a FIXED order (deterministic staging).
// The metadata record is encoded canonically so its bytes are byte-stable.
func (c generationCandidate) files() []genFile {
	metaBytes, _ := floorCanonicalBytes(c.meta()) // canonical; meta has no unencodable fields
	return []genFile{
		{genFileManifestEnvelope, c.EnvelopeBytes},
		{genFileArtifact, c.ArtifactBytes},
		{genFileArtifactBundle, c.BundleBytes},
		{genFileSnapshotNormalized, c.SnapshotBytes},
		{genFileMeta, metaBytes},
	}
}

// ─── keyed mutex ─────────────────────────────────────────────────────────────────

// keyedMutex serializes work per string key without holding a global lock during the
// critical section. Used to serialize in-process writers of the SAME generation id.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedEntry
}

type keyedEntry struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() *keyedMutex { return &keyedMutex{m: make(map[string]*keyedEntry)} }

// lock acquires the per-key mutex and returns an unlock func that releases it and
// garbage-collects the entry when no waiters remain.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	e := k.m[key]
	if e == nil {
		e = &keyedEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}
