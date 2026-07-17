// Package journal is the durable, crash-safe operation journal that closes
// RISK-022: it records the write-ahead phase + rollback digests of an in-flight
// state-changing op so that, after an agent crash / host reboot / OOM mid-apply,
// startup reconciliation can drive Docker back to a known-good state instead of
// leaving the appliance on an ungated image with no recovery.
//
// Design authority: roadmap/RISK-022-crash-recovery-journal-plan.md and
// roadmap/MAINTENANCE-AGENT-RESILIENCE-HARDENING.md (Tier 1). This file is the
// infrastructure slice: schema + a fail-closed atomic writer + read/list/remove.
// Wiring (write points, MarkAllInterrupted, ReconcileOnStartup) lands in later
// slices.
//
// The maint binary is its own Go module, so it cannot import the root
// internal/fileutil; this package owns a stdlib-only atomic writer that fsyncs
// both the file AND its parent directory (POSIX durability), mirroring the audit
// logger's fsync discipline.
package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Phase is the write-ahead state of a journaled op. It records whether the op
// has entered the mutating window (the fixed-tag advance in tagAndUp), which the
// reconciler uses — together with the live running digest — to decide between a
// no-op, a resume, or a fail-safe rollback.
type Phase string

// Phase values, in the order an upgrades.apply / rollbacks.create flow reaches
// them. Everything up to and including PhasePulled is a SAFE boundary: the fixed
// tag has NOT advanced, so a crash there needs no Docker reconciliation.
const (
	PhaseAdmitted   Phase = "admitted"   // op begun, nothing mutated
	PhaseCaptured   Phase = "captured"   // prior (rollback) digest known
	PhaseResolved   Phase = "resolved"   // target digest known
	PhasePulled     Phase = "pulled"     // new image local; tag NOT advanced (safe boundary)
	PhaseRestarting Phase = "restarting" // WRITE-AHEAD barrier: fsync'd immediately BEFORE the tag advance
	PhaseRestarted  Phase = "restarted"  // up returned; tag advanced, health not gated
	PhaseVerified   Phase = "verified"   // health + verify passed; success imminent
)

// validPhases is the closed set accepted by Write, so a typo or a
// forward-incompatible value can never be persisted.
var validPhases = map[Phase]struct{}{
	PhaseAdmitted: {}, PhaseCaptured: {}, PhaseResolved: {}, PhasePulled: {},
	PhaseRestarting: {}, PhaseRestarted: {}, PhaseVerified: {},
}

// Record is the durable per-op journal entry. One file per live op at
// <reconcileDir>/<op_id>.json. Manifest digests are bare sha256 hex; refs are
// repo@sha256:<digest>. All fields are plain data — no secrets (params never
// reach the journal).
//
// TargetImageID/PriorImageID are the image CONFIG digests (the `sha256:…` form
// `docker inspect .Image` reports). They are the class-INVARIANT identity of an
// image — identical whether the image was pulled by tag (manifest-LIST digest)
// or by per-platform digest — so PR-E reconcile keys "is the target/prior live?"
// on them, avoiding the false-rollback that a manifest-digest-only comparison
// suffers across the seed/tag-pull vs digest-pull lineage (design §0 P0-A/B).
// They MUST be captured at apply time (a crashed op's prior config digest cannot
// be reconstructed afterward), which is why they live in the record.
type Record struct {
	OpID          string    `json:"op_id"`
	Kind          string    `json:"kind"`                      // "upgrades.apply" | "rollbacks.create"
	Mode          string    `json:"mode,omitempty"`            // "" | "image" | "data" (rollbacks.create)
	Phase         Phase     `json:"phase"`                     // write-ahead state
	TargetRef     string    `json:"target_ref,omitempty"`      // repo@sha256:<digest> we move TO
	TargetDigest  string    `json:"target_digest,omitempty"`   // bare sha256 (manifest)
	TargetImageID string    `json:"target_image_id,omitempty"` // sha256:<hex> image config digest (class-invariant)
	PriorRef      string    `json:"prior_ref,omitempty"`       // repo@sha256:<digest> rollback target
	PriorDigest   string    `json:"prior_digest,omitempty"`    // bare sha256 (manifest)
	PriorImageID  string    `json:"prior_image_id,omitempty"`  // sha256:<hex> image config digest (class-invariant)
	Actor         string    `json:"actor,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

const (
	dirMode  = 0o750
	fileMode = 0o640
	fileExt  = ".json"
)

// ErrCorruptRecord marks a journal file that exists but cannot be parsed. It is
// surfaced (never silently skipped) so the reconciler can fail closed: a
// danger-window op with an unreadable record must halt startup, not be ignored
// as "nothing to reconcile".
var ErrCorruptRecord = errors.New("journal: corrupt record")

// Journal reads and writes op records under <stateDir>/reconcile/.
type Journal struct {
	dir string
}

// New creates the reconcile directory (0750) and returns a Journal rooted there.
// It fsyncs the PARENT (stateDir) so the newly-created reconcile/ directory entry
// is durable: otherwise a crash after the first record write on a fresh install
// (which fsyncs reconcile/ and the file, but not stateDir) could lose the whole
// reconcile/ directory, reopening the first-operation recovery gap.
func New(stateDir string) (*Journal, error) {
	dir := filepath.Join(stateDir, "reconcile")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("journal: mkdir %s: %w", dir, err)
	}
	if err := fsyncDir(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	return &Journal{dir: dir}, nil
}

// Dir returns the reconcile directory (for tests / diagnostics).
func (j *Journal) Dir() string { return j.dir }

// pathFor builds the on-disk path for opID, rejecting any op_id that is not a
// strict ULID (closes path traversal — the op_id is the only untrusted input
// that reaches a filesystem path here).
func (j *Journal) pathFor(opID string) (string, error) {
	if _, err := ulid.ParseStrict(opID); err != nil {
		return "", fmt.Errorf("journal: invalid op_id %q: %w", opID, err)
	}
	return filepath.Join(j.dir, opID+fileExt), nil
}

// Write persists rec atomically and durably (fsync file + parent dir). It is
// FAIL-CLOSED: any error (marshal, ENOSPC, fsync) is returned so the caller
// aborts the op BEFORE the mutation the record was meant to guard — a silently
// skipped write-ahead barrier would reopen the RISK-022 window under exactly the
// disk-full condition the journal exists to survive.
func (j *Journal) Write(rec Record) error {
	if _, ok := validPhases[rec.Phase]; !ok {
		return fmt.Errorf("journal: invalid phase %q", rec.Phase)
	}
	path, err := j.pathFor(rec.OpID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("journal: marshal: %w", err)
	}
	return atomicWrite(path, data, fileMode)
}

// Read returns the record for opID. found=false (nil error) when no file exists;
// ErrCorruptRecord when the file exists but does not parse.
func (j *Journal) Read(opID string) (rec *Record, found bool, err error) {
	path, err := j.pathFor(opID)
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is ULID-validated under the reconcile dir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("journal: read %s: %w", filepath.Base(path), err)
	}
	var r Record
	if uerr := json.Unmarshal(data, &r); uerr != nil {
		return nil, true, fmt.Errorf("%w %s: %v", ErrCorruptRecord, filepath.Base(path), uerr)
	}
	// A record that parses but carries an unknown phase is SEMANTICALLY corrupt
	// (or forward-incompatible): Write refuses such a phase, so Read must too. The
	// reconciler's safe-boundary vs danger-window decision keys on Phase, so an
	// unrecognized value must fail closed, not be treated as a valid record.
	if _, ok := validPhases[r.Phase]; !ok {
		return nil, true, fmt.Errorf("%w %s: unknown phase %q", ErrCorruptRecord, filepath.Base(path), r.Phase)
	}
	return &r, true, nil
}

// List returns every live record. It is FAIL-CLOSED on corruption: a single
// present-but-unparseable file returns ErrCorruptRecord (with no partial list),
// so the reconciler refuses to proceed rather than silently ignore an in-flight
// op whose record rotted. Non-.json entries and directories are skipped.
func (j *Journal) List() ([]Record, error) {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("journal: readdir: %w", err)
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), fileExt) {
			continue
		}
		opID := strings.TrimSuffix(e.Name(), fileExt)
		rec, found, rerr := j.Read(opID)
		if rerr != nil {
			return nil, rerr // corrupt or invalid-name file — fail closed
		}
		if found {
			out = append(out, *rec)
		}
	}
	return out, nil
}

// Remove deletes opID's record and fsyncs the parent directory so the unlink is
// durable — a crash after a non-durable unlink could re-materialize a completed
// op's record and make the reconciler roll back a healthy, finished upgrade.
// Removing an absent record is not an error (idempotent terminal cleanup).
func (j *Journal) Remove(opID string) error {
	path, err := j.pathFor(opID)
	if err != nil {
		return err
	}
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Errorf("journal: remove %s: %w", filepath.Base(path), rerr)
	}
	return fsyncDir(j.dir)
}

// atomicWrite writes data to path via a temp file in the same directory, then
// chmod → fsync(file) → rename → fsync(parent dir). Stdlib-only (the maint
// module can't import internal/fileutil). Best-effort temp cleanup on any error.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".journal-*.tmp")
	if err != nil {
		return fmt.Errorf("journal: create temp: %w", err)
	}
	tmpName := tmp.Name()
	// If anything below fails before the rename, remove the temp. After a
	// successful rename tmpName no longer exists, so this is a harmless no-op.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("journal: write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("journal: chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("journal: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("journal: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("journal: rename: %w", err)
	}
	return fsyncDir(dir)
}

// fsyncDir fsyncs a directory so a create/rename/unlink within it is durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- reconcile dir, agent-owned
	if err != nil {
		return fmt.Errorf("journal: open dir for fsync: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("journal: fsync dir: %w", err)
	}
	return nil
}
