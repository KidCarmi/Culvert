// Package journal is the durable, crash-safe operation journal that closes
// RISK-022: it records the write-ahead phase + rollback digests of an in-flight
// state-changing op so that, after an agent crash / host reboot / OOM mid-apply,
// startup reconciliation can drive Docker back to a known-good state instead of
// leaving the appliance on an ungated image with no recovery.
//
// Design authority: roadmap/RISK-022-crash-recovery-journal-plan.md and
// roadmap/MAINTENANCE-AGENT-RESILIENCE-HARDENING.md (Tier 1). This file is the
// infrastructure slice: schema + a fail-closed atomic writer + read/list/remove.
// The write points and the startup report are wired (main.go initJournal,
// docs/adr/0061). Nothing acts on a record at boot unless the operator opted in
// with reconcile_on_startup = "converge" (server/startup_reconcile.go, AGT-900).
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
	"sync"
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

// RestoreStage is how far a restore-class operation (restore.commit, or
// rollbacks.create mode=data, which runs the same stages) got. It is written
// AHEAD of each step: the value names the step that was about to start, or the
// recorded result of the commit command. It is a key beside Phase, not a new
// Phase, for the reason RollbackArmed is: an agent that predates it ignores the
// key, whereas an unknown phase makes every older agent refuse to serve. A
// restore record's Phase stays PhaseAdmitted.
type RestoreStage string

// RestoreStage values, in the order the restore flow reaches them.
const (
	RestoreStageAdmitted     RestoreStage = "admitted"      // admitted; no command has run
	RestoreStagePreflight    RestoreStage = "preflight"     // about to run the read-only dry-run; the stack is still up
	RestoreStageStopping     RestoreStage = "stopping"      // about to ask Docker to stop the stack (`compose down`)
	RestoreStageCommitting   RestoreStage = "committing"    // about to run the commit command; its result is not recorded
	RestoreStageCommitted    RestoreStage = "committed"     // the commit command returned success: the data directory was replaced
	RestoreStageCommitFailed RestoreStage = "commit_failed" // the commit command returned an error
	RestoreStageStarting     RestoreStage = "starting"      // committed; about to start the stack (`compose up`)
	RestoreStageStarted      RestoreStage = "started"       // committed; `compose up` returned; the health check had not passed
	// RestoreStageUnknown is what Read substitutes for a value this build does
	// not know (a record written by a newer agent). No running operation writes
	// it. It reports as "how far the restore got is not known", which is the
	// conservative reading, and it keeps the record writable: startup rewrites
	// every record it finds, and Write refuses a value outside the closed set.
	RestoreStageUnknown RestoreStage = "unknown"
)

// validRestoreStages is the closed set accepted by Write. "" is a record that
// carries no stage: every upgrade and image-rollback record, and a restore-class
// record written by (or rewritten by) an agent that predates the key.
var validRestoreStages = map[RestoreStage]struct{}{
	"": {}, RestoreStageAdmitted: {}, RestoreStagePreflight: {}, RestoreStageStopping: {},
	RestoreStageCommitting: {}, RestoreStageCommitted: {}, RestoreStageCommitFailed: {},
	RestoreStageStarting: {}, RestoreStageStarted: {}, RestoreStageUnknown: {},
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
	Kind          string    `json:"kind"`                      // "upgrades.apply" | "rollbacks.create" | "restore.commit"
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

	// Interruption bookkeeping. Written ONLY by agent startup, for a record it
	// found with no process behind it; a running op never sets these, and its
	// read-modify-write phase updates carry them through unchanged. All three
	// are omitted from a record no startup has seen, so a record written by
	// this build is readable by one that predates the fields, and the reverse.
	//
	// InterruptedAt is the first startup that found the record. InterruptedSeen
	// counts every startup that found it (a restart loop shows as a growing
	// count). InterruptAudited is true once the interruption has been written
	// to the audit log, so later startups do not repeat the entry.
	InterruptedAt    *time.Time `json:"interrupted_at,omitempty"`
	InterruptedSeen  int        `json:"interrupted_seen,omitempty"`
	InterruptAudited bool       `json:"interrupt_audited,omitempty"`

	// RollbackArmed is set, best-effort, by an upgrades.apply's inline rollback
	// immediately BEFORE its rollback_restart stage moves the fixed tag back to
	// the prior image. It is the durable evidence that the agent had already
	// decided the target failed its gate, so a startup reconcile must never
	// adopt the target of such a record. If it cannot be written the rollback
	// still runs and the record stays unarmed, which the reconcile never acts on.
	// It is an optional key, not a new Phase:
	// an agent that predates it ignores the key (encoding/json drops unknown
	// fields), whereas an unknown phase makes every older agent refuse to serve.
	RollbackArmed bool `json:"rollback_armed,omitempty"`

	// Startup-reconcile bookkeeping (reconcile_on_startup = "converge" only;
	// absent otherwise, so an "off" agent writes records byte-identical to
	// before). Optional keys an older agent ignores.
	//
	// ReconcileAttempts counts the reconcile actions that changed Docker
	// (realign, finish_rollback). It is written FAIL-CLOSED before the action
	// (write-ahead): no durable count, no action. A deferred or report-only
	// verdict does not count. It is content from an unauthenticated file: the
	// reconciler treats a negative value as exhausted.
	ReconcileAttempts int        `json:"reconcile_attempts,omitempty"`
	LastReconcileAt   *time.Time `json:"last_reconcile_at,omitempty"`
	// ReconcileDecision is "<action>/<reason>" of the last decision; and
	// ReconcileOutcome the outcome of the last reconcile of a record that was
	// kept. Diagnostics only: nothing reads them back to decide.
	ReconcileDecision string `json:"reconcile_decision,omitempty"`
	ReconcileOutcome  string `json:"reconcile_outcome,omitempty"`

	// RestoreStage is set only on restore-class records (see RestoreStage).
	// Omitted when empty, so an upgrade or image-rollback record is
	// byte-identical to what it was before the key existed.
	RestoreStage RestoreStage `json:"restore_stage,omitempty"`

	// Intent and Cut attribute an interruption to one docker command of this
	// operation (intent.go). Absent on every record whose operation has not
	// begun such a command.
	Intent *CommandIntent `json:"intent,omitempty"`
	Cut    *CommandCut    `json:"cut,omitempty"`

	// Terminal bookkeeping (ADR-0062 slice 1). Written by the operation's own
	// process when it ends, never by a running stage: TerminalOutcome and
	// TerminalAt BEFORE the terminal audit entry, TerminalAudited after it.
	// A record that carries a TerminalOutcome did not die: it ended, and
	// either its removal was cut short (startup finishes it) or it was KEPT
	// because the operation could not prove the state it left safe.
	//
	// TerminalOutcome is "succeeded" or "failed:<failure_reason>".
	// TerminalSafe is the operation's own verdict, taken in memory at its end,
	// that the end state is proven safe (always true for a success): the
	// record may be removed once the terminal audit is durable. Absent means
	// not proven, which keeps the record. TerminalAudited is true once the
	// terminal audit entry is known to be durable.
	//
	// These keys stay at schema 1 on purpose (no Schema bump, no fence). An
	// agent released before ADR-0062 slice 2 drops them when it rewrites the
	// record at a start, and is left with what it always understood: an
	// ordinary interrupted record, which it reports, audits as interrupted and
	// keeps until a later success retires it. That is the conservative
	// reading of every one of them, so nothing an older agent does with the
	// record is less safe than what this build does.
	TerminalOutcome string     `json:"terminal_outcome,omitempty"`
	TerminalAt      *time.Time `json:"terminal_at,omitempty"`
	TerminalSafe    bool       `json:"terminal_safe,omitempty"`
	TerminalAudited bool       `json:"terminal_audited,omitempty"`

	// Schema is the record format (schema.go). Absent means 1, the format of
	// every agent before ADR-0062. A record at SchemaFenced or above is written
	// only behind the downgrade fence; one above SchemaCurrent came from a
	// newer agent and is read-only here.
	Schema int `json:"schema,omitempty"`

	// extra holds the keys of a record read from a file that this build does
	// not declare, so a rewrite carries them through unchanged (schema.go).
	extra map[string]json.RawMessage
	// restoreStageRaw is a restore stage this build does not know, kept so a
	// rewrite writes it back instead of the "unknown" Read substituted.
	restoreStageRaw string
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
	// writeErrForTest, when set, is returned by Write (SetWriteErrorForTest).
	writeErrForTest error
	// inFlight: operations of THIS process that are inside a compose command
	// (BeginCommand .. EndCommand). Guarded by flightMu.
	flightMu sync.Mutex
	inFlight map[string]struct{}
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
	if rec.FromNewerAgent() {
		return fmt.Errorf("%w (op %s, schema %d > %d)", ErrNewerSchema, rec.OpID, rec.Schema, SchemaCurrent)
	}
	if _, ok := validPhases[rec.Phase]; !ok {
		return fmt.Errorf("journal: invalid phase %q", rec.Phase)
	}
	if _, ok := validRestoreStages[rec.RestoreStage]; !ok {
		return fmt.Errorf("journal: invalid restore stage %q", rec.RestoreStage)
	}
	path, err := j.pathFor(rec.OpID)
	if err != nil {
		return err
	}
	dropped := false
	if rec.Intent != nil && !j.commandInFlight(rec.OpID) {
		// An intent this process is not inside: its close could not be written
		// earlier, and a read-modify-write is now carrying it. It must not
		// reach disk again as "in flight" (intent.go). An agent START never
		// gets here with one: it takes the intent before it writes.
		rec.Intent, dropped = nil, true
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("journal: marshal: %w", err)
	}
	if rec.EffectiveSchema() >= SchemaFenced {
		// Fail-closed: the fence is durable before the first record an older
		// agent must not act on.
		if ferr := j.ensureFence(); ferr != nil {
			return ferr
		}
	}
	if j.writeErrForTest != nil {
		return j.writeErrForTest
	}
	if err := atomicWrite(path, data, fileMode); err != nil {
		return err
	}
	if dropped {
		j.releaseIntentFenceIfUnused()
	}
	return nil
}

// SetWriteErrorForTest makes every later Write fail with err (nil restores
// normal writes). Tests only: a disk that fills up between two writes cannot
// be produced with file modes when the tests run as root.
func (j *Journal) SetWriteErrorForTest(err error) { j.writeErrForTest = err }

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
	// An unknown restore stage does NOT fail closed. The stage is read only to
	// word a report, never to decide a Docker action, so refusing to serve over
	// it would take the whole API down for a value a newer agent wrote. It is
	// replaced by the one member of the closed set that claims nothing.
	if _, ok := validRestoreStages[r.RestoreStage]; !ok {
		r.restoreStageRaw = string(r.RestoreStage)
		r.RestoreStage = RestoreStageUnknown
	}
	// The file name is the record's identity: Write derives the path from
	// OpID, so the two agree for every record this package wrote. The name has
	// passed the strict-ULID check; the op_id INSIDE the file is unchecked
	// content. Carry the name, so a caller that reports the record or writes
	// it back acts on the file it read and never on an id the content chose.
	r.OpID = opID
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
		if opID == fenceOpID || opID == intentFenceOpID {
			continue // a downgrade fence is not an operation (schema.go, intent.go)
		}
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
	// A record a newer agent wrote is never removed here: its fields may say
	// that the state it describes is not safe in a way this build cannot read.
	if rec, found, rerr := j.Read(opID); rerr == nil && found && rec.FromNewerAgent() {
		return fmt.Errorf("%w (op %s, schema %d > %d)", ErrNewerSchema, opID, rec.Schema, SchemaCurrent)
	}
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Errorf("journal: remove %s: %w", filepath.Base(path), rerr)
	}
	if err := fsyncDir(j.dir); err != nil {
		return err
	}
	// The record is gone either way; a fence that could not be released stays,
	// which only keeps older agents out a little longer.
	_ = j.releaseFenceIfUnused()
	j.releaseIntentFenceIfUnused()
	return nil
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
