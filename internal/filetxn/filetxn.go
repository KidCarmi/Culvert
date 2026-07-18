// Package filetxn provides recoverable all-old/all-new publication for a
// small set of files. Callers serialize transactions and publish memory only
// after Commit succeeds.
//
// Guarantee boundary (see docs/adr/0012-durable-config-publication.md):
// filetxn provides DISK atomicity and durability only. It does NOT provide
// in-memory / reader-visibility atomicity — a caller that swaps several
// in-memory generations after Commit must provide its own reader isolation
// (invariant #11). Recovery is deterministic and idempotent, and no journal
// state — superseded, corrupt, or unparseable — may permanently wedge startup
// (invariant #5): a committed-but-superseded journal degrades to cleanup, and
// an untrusted journal is quarantined aside rather than obeyed or fataled.
package filetxn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const formatVersion = 1

// quarantineSuffix is appended to a journal that Recover cannot trust. Moving
// it aside (rather than deleting or obeying it) keeps forensic evidence while
// guaranteeing the next boot sees a clean slate — an untrusted journal can
// therefore fail one recovery observably, but never wedge startup permanently.
const quarantineSuffix = ".corrupt"

// ErrSimulatedCrash is returned by a WithBoundaryHook callback to model a
// power-loss at a specific transaction boundary. Apply/Commit propagate it
// without triggering rollback so a test can inspect the interrupted on-disk
// state and then drive Recover.
var ErrSimulatedCrash = errors.New("simulated file transaction crash")

// ErrJournalQuarantined reports that Recover found an untrusted journal
// (unparseable, checksum mismatch, or structurally invalid) and moved it aside
// to <journal>.corrupt instead of acting on it. It is observable and, because
// the journal has been renamed away, non-recurring: a subsequent Recover of the
// same path is a clean no-op. Callers decide whether to treat it as fatal;
// boot-time recovery must NOT (that is the A1 wedge this fixes).
var ErrJournalQuarantined = errors.New("file transaction journal quarantined")

// Write is a single file to publish within a transaction: its destination
// path, the new content, and the file mode to apply.
type Write struct {
	Path string
	Data []byte
	Mode fs.FileMode
}

type artifact struct {
	Path         string      `json:"path"`
	BeforeExists bool        `json:"before_exists"`
	BeforeMode   fs.FileMode `json:"before_mode,omitempty"`
	Before       []byte      `json:"before,omitempty"`
	BeforeSHA256 string      `json:"before_sha256,omitempty"`
	AfterSHA256  string      `json:"after_sha256"`
	AfterMode    fs.FileMode `json:"after_mode"`
}

type record struct {
	Format    int        `json:"format"`
	Kind      string     `json:"kind"`
	Committed bool       `json:"committed"`
	Files     []artifact `json:"files"`
	Checksum  string     `json:"checksum"`
}

type boundaryHook func(string) error

type options struct{ hook boundaryHook }

// Option configures a transaction created by Begin.
type Option func(*options)

// WithBoundaryHook installs a callback invoked at each named transaction
// boundary (after-journal, before-write-N, after-write-N, before-commit,
// after-commit, before-finish). Returning an error — typically
// ErrSimulatedCrash — interrupts the transaction there. It exists for
// deterministic crash-point fault injection in tests.
func WithBoundaryHook(h func(string) error) Option {
	return func(o *options) { o.hook = h }
}

// Txn is an in-progress file transaction. It is not safe for concurrent use;
// callers serialize transactions over the same files.
type Txn struct {
	journal string
	writes  []Write
	record  record
	hook    boundaryHook
}

// Begin snapshots the current (before-image) state of each artifact, writes a
// durable journal, and returns a transaction ready to Apply. Any pre-existing
// journal at journalPath is recovered first; an untrusted one is quarantined
// aside so a fresh transaction can proceed. The writes must have distinct,
// journal-disjoint paths.
func Begin(journalPath, kind string, writes []Write, opts ...Option) (*Txn, error) {
	if journalPath == "" || kind == "" || len(writes) == 0 {
		return nil, errors.New("file transaction requires journal, kind, and writes")
	}
	journalPath, err := filepath.Abs(filepath.Clean(journalPath))
	if err != nil {
		return nil, fmt.Errorf("resolve journal path: %w", err)
	}
	if _, err := os.Stat(journalPath); err == nil {
		// A prior journal is recovered before starting a new transaction. A
		// quarantined (untrusted) prior journal is moved aside by Recover, so
		// it is safe to proceed with the fresh transaction the caller is
		// explicitly requesting — the new journal is authoritative.
		if err := Recover(journalPath); err != nil && !errors.Is(err, ErrJournalQuarantined) {
			return nil, fmt.Errorf("recover prior transaction: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat journal: %w", err)
	}

	cfg := options{}
	for _, opt := range opts {
		opt(&cfg)
	}
	t := &Txn{journal: journalPath, writes: make([]Write, len(writes)), hook: cfg.hook}
	t.record = record{Format: formatVersion, Kind: kind, Files: make([]artifact, len(writes))}
	seen := make(map[string]struct{}, len(writes))
	for i, write := range writes {
		w, a, err := prepareWrite(write, journalPath, seen)
		if err != nil {
			return nil, fmt.Errorf("write %d: %w", i, err)
		}
		t.writes[i] = w
		t.record.Files[i] = a
	}
	if err := t.writeRecord(); err != nil {
		return nil, err
	}
	if err := t.boundary("after-journal"); err != nil {
		return nil, err
	}
	return t, nil
}

// prepareWrite validates a single write, detaches its candidate bytes, and
// captures the artifact's before-image. seen tracks already-claimed paths to
// reject duplicates within one transaction.
func prepareWrite(write Write, journalPath string, seen map[string]struct{}) (Write, artifact, error) {
	if write.Path == "" || write.Mode.Perm() == 0 {
		return Write{}, artifact{}, errors.New("invalid write")
	}
	path, err := filepath.Abs(filepath.Clean(write.Path))
	if err != nil {
		return Write{}, artifact{}, fmt.Errorf("resolve artifact path: %w", err)
	}
	if path == journalPath {
		return Write{}, artifact{}, fmt.Errorf("artifact path collides with journal: %q", path)
	}
	if _, ok := seen[path]; ok {
		return Write{}, artifact{}, fmt.Errorf("duplicate artifact path %q", path)
	}
	seen[path] = struct{}{}
	candidate := append([]byte(nil), write.Data...)
	a := artifact{Path: path, AfterSHA256: digest(candidate), AfterMode: write.Mode.Perm()}
	if err := captureBeforeImage(&a, path); err != nil {
		return Write{}, artifact{}, err
	}
	return Write{Path: path, Data: candidate, Mode: write.Mode}, a, nil
}

// captureBeforeImage records the current content and mode of path into a so the
// transaction can be rolled back. A missing file is recorded as a non-existent
// before-image (rollback will remove the artifact).
func captureBeforeImage(a *artifact, path string) error {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		info, statErr := os.Stat(path)
		if statErr != nil {
			return fmt.Errorf("stat artifact %s: %w", path, statErr)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact %s is not a regular file", path)
		}
		a.BeforeExists, a.Before, a.BeforeMode, a.BeforeSHA256 = true, data, info.Mode().Perm(), digest(data)
	case errors.Is(err, os.ErrNotExist):
	default:
		return fmt.Errorf("snapshot artifact %s: %w", path, err)
	}
	return nil
}

// Apply durably writes every artifact's new content. On any failure it rolls
// back to the before-images (except a simulated crash, which is left for
// Recover). Call Commit after Apply succeeds.
func (t *Txn) Apply() error {
	for i, write := range t.writes {
		if err := t.boundary(fmt.Sprintf("before-write-%d", i)); err != nil {
			return t.handleApplyError(err)
		}
		if err := durableWrite(write.Path, write.Data, write.Mode); err != nil {
			return t.handleApplyError(fmt.Errorf("write artifact %s: %w", write.Path, err))
		}
		if err := t.boundary(fmt.Sprintf("after-write-%d", i)); err != nil {
			return t.handleApplyError(err)
		}
	}
	return nil
}

// Commit flips the journal's durable commit marker. Once it returns, recovery
// keeps the new generation; before it, recovery restores the old. The caller
// publishes in-memory state only after Commit succeeds.
func (t *Txn) Commit() error {
	if err := t.boundary("before-commit"); err != nil {
		return t.handleApplyError(err)
	}
	t.record.Committed = true
	if err := t.writeRecord(); err != nil {
		t.record.Committed = false
		return errors.Join(err, t.Abort())
	}
	return t.boundary("after-commit")
}

// Abort restores every artifact to its before-image and removes the journal.
// It is safe to call on an uncommitted transaction to discard it.
func (t *Txn) Abort() error {
	t.record.Committed = false
	if err := t.writeRecord(); err != nil {
		return fmt.Errorf("mark transaction uncommitted: %w", err)
	}
	if err := restore(t.record.Files); err != nil {
		return err
	}
	return durableRemove(t.journal)
}

// Finish removes the journal of a committed transaction, completing publication.
// It errors if called before Commit.
func (t *Txn) Finish() error {
	if !t.record.Committed {
		return errors.New("finish uncommitted file transaction")
	}
	if err := t.boundary("before-finish"); err != nil {
		return err
	}
	return durableRemove(t.journal)
}

// Recover reconciles a journal against on-disk state. It is a pure function of
// that state and is safe to run repeatedly (idempotent): a missing journal is a
// no-op, and once Recover returns it has either restored, kept, or quarantined —
// a second call finds no journal and no-ops.
//
// No journal state permanently wedges boot:
//   - uncommitted            -> restore before-images, remove journal
//   - committed & current    -> keep new generation, remove journal
//   - committed & superseded -> the recorded generation was replaced by a newer
//     authoritative write (e.g. an inline policy save over the same file);
//     the transaction's effect is moot, so remove the journal (A1 fix). We
//     cannot distinguish legitimate supersession from silent corruption of a
//     committed artifact; degrading to cleanup is the ratified tradeoff (a rare
//     undetectable corruption) over the alternative (a guaranteed boot DoS).
//   - untrusted (unparseable / checksum / structural) -> quarantine aside and
//     return ErrJournalQuarantined (A1 fix) rather than fataling.
func Recover(journalPath string, opts ...Option) error {
	data, err := os.ReadFile(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read journal: %w", err)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return quarantine(journalPath, fmt.Sprintf("parse journal: %v", err))
	}
	if reason := validateJournal(rec); reason != "" {
		return quarantine(journalPath, reason)
	}
	if rec.Committed {
		reason, err := reconcileCommitted(rec.Files)
		if err != nil {
			return err
		}
		if reason != "" {
			return quarantine(journalPath, reason)
		}
		// Every artifact either matches the committed generation or was
		// superseded by a newer write; the journal has served its purpose.
	} else if err := restore(rec.Files); err != nil {
		return err
	}
	return durableRemove(journalPath)
}

// validateJournal returns a non-empty quarantine reason if the parsed record is
// not structurally trustworthy (bad format, checksum, or artifact metadata).
func validateJournal(rec record) string {
	if rec.Format != formatVersion || rec.Kind == "" || len(rec.Files) == 0 {
		return "invalid file transaction journal"
	}
	want, err := recordChecksum(rec)
	if err != nil || !validDigest(rec.Checksum) || rec.Checksum != want {
		return "file transaction journal checksum mismatch"
	}
	seen := make(map[string]struct{}, len(rec.Files))
	for _, a := range rec.Files {
		if reason := validateArtifact(a); reason != "" {
			return reason
		}
		if _, ok := seen[a.Path]; ok {
			return fmt.Sprintf("duplicate journal artifact %q", a.Path)
		}
		seen[a.Path] = struct{}{}
	}
	return ""
}

// validateArtifact returns a non-empty quarantine reason if a single journal
// artifact's metadata is malformed or its before-image fails its own digest.
func validateArtifact(a artifact) string {
	if a.Path == "" || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || !validDigest(a.AfterSHA256) || a.AfterMode.Perm() == 0 {
		return "invalid file transaction artifact"
	}
	if a.BeforeExists {
		if a.BeforeMode.Perm() == 0 || !validDigest(a.BeforeSHA256) || digest(a.Before) != a.BeforeSHA256 {
			return fmt.Sprintf("invalid before-image for %s", a.Path)
		}
	} else if a.BeforeMode.Perm() != 0 || len(a.Before) != 0 || a.BeforeSHA256 != "" {
		return fmt.Sprintf("unexpected before-image for missing artifact %s", a.Path)
	}
	return ""
}

// reconcileCommitted verifies each artifact of a committed transaction. An
// absent or digest-superseded artifact is benign (a newer authoritative write
// replaced it — the A1 supersession case) and yields cleanup by the caller. A
// content-match with a mode mismatch is anomalous and returns a quarantine
// reason; a genuine read/stat I/O fault returns an error.
func reconcileCommitted(files []artifact) (reason string, err error) {
	for _, a := range files {
		current, rerr := os.ReadFile(a.Path)
		if errors.Is(rerr, os.ErrNotExist) {
			continue // superseded (removed/replaced): nothing to keep.
		}
		if rerr != nil {
			return "", fmt.Errorf("verify committed artifact %s: %w", a.Path, rerr)
		}
		if digest(current) != a.AfterSHA256 {
			continue // superseded by a newer authoritative write (A1).
		}
		info, serr := os.Stat(a.Path)
		if serr != nil {
			return "", fmt.Errorf("stat committed artifact %s: %w", a.Path, serr)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != a.AfterMode.Perm() {
			return fmt.Sprintf("committed artifact mode mismatch: %s", a.Path), nil
		}
	}
	return "", nil
}

func (t *Txn) handleApplyError(err error) error {
	if errors.Is(err, ErrSimulatedCrash) {
		return err
	}
	return errors.Join(err, t.Abort())
}

func (t *Txn) writeRecord() error {
	checksum, err := recordChecksum(t.record)
	if err != nil {
		return err
	}
	t.record.Checksum = checksum
	data, err := json.Marshal(t.record)
	if err != nil {
		return fmt.Errorf("marshal journal: %w", err)
	}
	if err := durableWrite(t.journal, data, 0o600); err != nil {
		return fmt.Errorf("write journal: %w", err)
	}
	return nil
}

func (t *Txn) boundary(point string) error {
	if t.hook == nil {
		return nil
	}
	return t.hook(point)
}

// quarantine renames an untrusted journal aside and durably persists the rename,
// then reports ErrJournalQuarantined wrapping the reason. A missing journal (a
// concurrent recovery already moved it) is not itself an error.
func quarantine(journalPath, reason string) error {
	dest := journalPath + quarantineSuffix
	if err := os.Rename(journalPath, dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(fmt.Errorf("%w: %s", ErrJournalQuarantined, reason), fmt.Errorf("quarantine journal to %s: %w", dest, err))
	}
	// Best-effort durability of the rename; a sync failure must not turn a
	// quarantine (already safer than the prior fatal) back into a hard error.
	_ = syncDir(filepath.Dir(journalPath))
	return fmt.Errorf("%w: %s", ErrJournalQuarantined, reason)
}

func restore(files []artifact) error {
	var errs []error
	for _, a := range files {
		if a.BeforeExists {
			if err := durableWrite(a.Path, a.Before, a.BeforeMode); err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", a.Path, err))
			}
		} else if err := durableRemove(a.Path); err != nil {
			errs = append(errs, fmt.Errorf("remove new artifact %s: %w", a.Path, err))
		}
	}
	return errors.Join(errs...)
}

func durableWrite(path string, data []byte, mode fs.FileMode) error {
	// AtomicWrite already fsyncs the file before rename and the parent directory
	// after, using the tolerant classification below. Re-syncing the directory
	// here would be a redundant second fsync (A2) — and, if done intolerantly,
	// would fail on filesystems AtomicWrite deliberately tolerates.
	return fileutil.AtomicWrite(path, data, mode)
}

func durableRemove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsyncs a directory to durably persist a create/rename/remove within
// it, mirroring fileutil.AtomicWrite's tolerance (A2): opening a directory for
// sync is not portable, and some filesystems (tmpfs, overlay, many NFS mounts)
// reject directory fsync outright. Those cases are a successful no-op, not a
// durability failure. A genuine I/O error (EIO, ENOSPC, ...) is still reported.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		// Best-effort: opening a directory for sync is not portable.
		return nil
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil && !isBenignDirSyncErr(syncErr) {
		return fmt.Errorf("dir fsync %s: %w", path, syncErr)
	}
	if closeErr != nil && syncErr == nil {
		return fmt.Errorf("dir close %s: %w", path, closeErr)
	}
	return nil
}

// isBenignDirSyncErr reports whether a directory-fsync error means "this
// filesystem does not support directory fsync" rather than a real durability
// failure. It matches the errno set fileutil.AtomicWrite tolerates so that
// filetxn is never less portable than the primitive it builds on.
func isBenignDirSyncErr(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func recordChecksum(rec record) (string, error) {
	rec.Checksum = ""
	data, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("marshal journal checksum: %w", err)
	}
	return digest(data), nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
