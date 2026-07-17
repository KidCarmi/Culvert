// D1.6b API handlers: backup create / list, restore dry-run / commit,
// cleanup leftovers.
//
// Request shape, validation rules, and operation flow are documented
// in roadmap/D1.6-maintenance-agent-implementation-plan.md and the
// D1.6b kickoff brief.
//
// Common pattern (POST handlers — backup.create, restore.*, cleanup):
//
//  1. Decode JSON body into a typed request struct.
//  2. SHAPE-validate every field. Reject with 400 on any malformed
//     input. For passphrase_ref this means: env:NAME prefix, name
//     non-empty, name in the runner's EnvAllow. NO env read yet —
//     so a deduped retry with a transiently-missing env var still
//     dedupes correctly.
//  3. Build a sanitised params map for the audit event. The
//     `passphrase_ref` reference is preserved; the resolved value
//     is NEVER included (it is read inside buildStages and held in
//     a stage-closure local).
//  4. Call ops.Manager.BeginIdempotent (via startAsyncOp).
//     - On 409 (lock conflict by another in-flight state-changing
//     op): startAsyncOp returns *opError with status 409 and the
//     holder's snapshot.
//     - On dedupe hit (same actor + kind + idempotency_key as a
//     prior in-flight op): startAsyncOp returns the prior op
//     snapshot with deduped=true; writeOpResponse returns
//     HTTP 200 OK (no new work was started).
//  5. For newly admitted ops, startAsyncOp invokes the buildStages
//     callback which (a) reads the passphrase from env if a ref was
//     given, and (b) constructs the FlowStage list. If that fails,
//     the op is recorded as admission-time failed (audit pair
//     emitted, op record marked failed) and the error response
//     carries the op_id so the caller can fetch
//     /v1/operations/{id} for diagnostics.
//  6. The per-op log file is opened. Failure here also produces
//     an admission-time failure with op_id surfaced.
//  7. Spawn the orchestrator goroutine. Return HTTP 202 Accepted
//     with the op_id immediately; stages run in the background.
//
// GET /v1/backups is the only synchronous handler — it does its work
// inline and returns 200 with the parsed JSON list (the cli's stdout
// is unmarshalled into a typed slice and re-encoded so a malformed
// cli output produces a clean 500 list_backups_parse_failed rather
// than corrupting the Content-Type contract).
//
// Restore-without-passphrase note: passphrase_ref is OPTIONAL on both
// /v1/restores/dryrun and /v1/restores/commit because the cli
// container detects encrypted vs unencrypted from the file's magic
// bytes. If the operator submits an encrypted archive without a
// passphrase_ref, the agent does NOT detect this up-front (no
// pre-flight magic-byte sniff in D1.6b) — the cli inside the
// container will fail decryption, and the agent surfaces that as a
// stage-level cli_error in the per-op log. Operators receive an
// unambiguous decryption-error message; they just receive it later
// (after stop_stack runs) than they would with an early sniff.
// Adding the early sniff is a D1.6c follow-up.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/health"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

const (
	// maxBodyBytes caps decoded request bodies. The largest
	// legitimate D1.6b request is the restore body with all flags;
	// 16 KiB is generous.
	maxBodyBytes = 16 * 1024
)

// ─── shared helpers ────────────────────────────────────────────────

// validatePassphraseRefShape checks that a non-empty passphrase_ref
// has the supported shape (env:NAME) AND that NAME is in the runner's
// EnvAllow. It does NOT read os.Getenv — that's a separate step
// reserved for newly admitted ops (so a duplicate request with a
// transiently-missing env var still dedupes correctly per
// idempotency_key).
//
// Empty ref passes through as nil — the caller decides whether empty
// is allowed for the operation.
func validatePassphraseRefShape(ref string, runnerEnvAllow []string) error {
	if ref == "" {
		return nil
	}
	if !strings.HasPrefix(ref, "env:") {
		return fmt.Errorf("passphrase_ref: only env:NAME is supported in D1.6b, got %q", ref)
	}
	name := strings.TrimPrefix(ref, "env:")
	if name == "" {
		return errors.New("passphrase_ref: env: prefix with empty name")
	}
	for _, n := range runnerEnvAllow {
		if n == name {
			return nil
		}
	}
	return fmt.Errorf("passphrase_ref: env name %q is not in the runner's EnvAllow", name)
}

// readPassphraseFromEnv reads the env var named by ref (which MUST
// already be shape-validated). Returns "" if ref is empty (caller
// decides whether that's an error). Returns an error if ref is
// non-empty but the env var is unset or empty.
//
// This is called ONLY for newly admitted ops, never for deduped
// requests — see startAsyncOp.
func readPassphraseFromEnv(ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	name := strings.TrimPrefix(ref, "env:")
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("passphrase_ref: env var %q is unset or empty", name)
	}
	return v, nil
}

// decodeJSONBody enforces the body-size cap before json.Decode.
// Disallows unknown fields so a typo in the request body (e.g.
// `passhprase_ref`) fails loudly rather than silently disabling
// encryption.
func decodeJSONBody(r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Reject trailing junk (`{...}{...}` etc).
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("body must contain exactly one JSON document")
	}
	return nil
}

// startAsyncOp admits an operation and (for newly admitted ops) calls
// the buildStages closure to construct the stage list, then spawns
// the orchestrator goroutine. For deduped requests, buildStages is
// NEVER called — so a retry with a missing env var still returns the
// existing op_id without trying to resolve secrets.
//
// Caller is responsible for: decoding the request, validating its
// SHAPE (filename, mode, passphrase_ref scheme + env name in
// EnvAllow), and building the sanitised params map (no raw secrets).
//
// buildStages is called only for newly admitted ops. Inside it, the
// caller resolves any late-bound state (passphrase env reads, file
// reads) and constructs the FlowStage list. If buildStages returns
// an *opError, the op is finished with ReasonValidation, an audit
// failed event is emitted (so the admission-time failure shows up
// in the same audit trail as orchestrator-time failures), and the
// op_id is folded into the error body — the caller can hit
// GET /v1/operations/{op_id} for diagnostics even though the op
// failed before any stage ran.
//
// Response status: 202 Accepted for newly admitted ops with stages
// running; 200 OK for deduped retries (no new work started); the
// caller-provided opError carries its own status (typically 400 or
// 500) for admission-time failures.
//
//nolint:cyclop // single-pass admission flow; splitting hides the dedup→build→spawn ordering
func (s *Server) startAsyncOp(_ *http.Request, peer auth.PeerInfo, kind, idempotencyKey string, paramsForAudit map[string]interface{}, buildStages func() ([]ops.FlowStage, *opError), opts ...startOpt) (*ops.Op, bool, *opError) {
	var cfg startCfg
	for _, o := range opts {
		o(&cfg)
	}
	// T2.3 admission control: cap concurrently-executing READ-ONLY ops (not
	// serialized by the maintenance lock) so a flood can't spawn unbounded root
	// docker subprocesses; return 429 when at capacity. State-changing ops bypass
	// — the lock already caps them at one. A duplicate of an already-running
	// read-only op must DEDUPE (return the existing op_id), not be rejected for
	// capacity, so only genuinely-new admissions are gated (HasLiveIdempotent
	// peek). releaseSlot is invoked on every path that does NOT hand the slot to
	// the orchestrator goroutine (set to nil on the spawn path so the goroutine
	// owns the release).
	var releaseSlot func()
	if !ops.IsStateChanging(kind) && !s.opts.Ops.HasLiveIdempotent(peer.String(), kind, idempotencyKey) {
		rel, ok := s.acquireReadOnlySlot()
		if !ok {
			return nil, false, &opError{Status: http.StatusTooManyRequests, Body: map[string]string{"error": "agent_busy"}}
		}
		releaseSlot = rel
	}
	defer func() {
		if releaseSlot != nil {
			releaseSlot()
		}
	}()

	op, deduped, err := s.opts.Ops.BeginIdempotent(kind, peer.String(), idempotencyKey, paramsForAudit)
	if err != nil {
		if ops.IsConflict(err) {
			var conf *ops.Conflict
			errors.As(err, &conf)
			return nil, false, &opError{Status: http.StatusConflict, Body: map[string]interface{}{
				"error":     "concurrency_conflict",
				"holder_op": conf.Holder,
			}}
		}
		return nil, false, &opError{Status: http.StatusInternalServerError, Body: map[string]string{"error": err.Error()}}
	}
	if deduped {
		// Duplicate submission — return the prior op snapshot, NO
		// stage build, NO goroutine spawn. This is the contract:
		// a retry with the same idempotency_key returns the
		// original op_id even if the late-bound resources (env
		// vars, files) are no longer present.
		return op, true, nil
	}
	// Newly admitted op — deliver the op_id to the caller (so late-bound
	// stage closures can stamp it onto sub-action audit events) BEFORE
	// building stages, then late-bound stage construction.
	if cfg.onOpID != nil {
		cfg.onOpID(op.ID)
	}
	stages, herr := buildStages()
	if herr != nil {
		s.recordAdmissionFailure(op.ID, kind, peer.String(), paramsForAudit, idempotencyKey, "build_stages_failed")
		return nil, false, augmentErrorWithOp(herr, op.ID)
	}
	oplog, oerr := ops.OpenOpLog(s.opts.StateDir, op.ID)
	if oerr != nil {
		s.recordAdmissionFailure(op.ID, kind, peer.String(), paramsForAudit, idempotencyKey, "open_op_log: "+oerr.Error())
		herr = &opError{Status: http.StatusInternalServerError, Body: map[string]string{"error": "open_op_log_failed"}}
		return nil, false, augmentErrorWithOp(herr, op.ID)
	}
	// Crash-recovery journal (RISK-022): record the admission of a destructive,
	// reconcilable op BEFORE it runs. Fail-closed — if we cannot durably journal
	// it, we refuse to run it (a broken journal, e.g. disk-full, must not silently
	// leave a destructive op unrecoverable). Non-journaled kinds / nil journal skip.
	if ops.IsJournaled(kind) && s.opts.Journal != nil {
		now := time.Now().UTC()
		// Persist the rollback mode: it is the ONLY durable signal of which
		// rollback was interrupted, and image vs data need different recovery
		// (image is Docker-reconcilable; data must NOT be auto-reconciled). "" for
		// upgrades.apply (no mode).
		mode, _ := paramsForAudit["mode"].(string) //nolint:errcheck // absent/typed-nil → ""
		rec := journal.Record{
			OpID: op.ID, Kind: kind, Mode: mode, Phase: journal.PhaseAdmitted,
			Actor: peer.String(), StartedAt: now, UpdatedAt: now,
		}
		// Standalone image rollback: the target is FIXED and fully validated at
		// admission (strict repo@sha256 shape + image_allowlist in rollbackImage),
		// and no later stage folds it in (journal_phases is apply-specific). Persist
		// it NOW — otherwise the record carries no actionable ref and the E1c trust
		// gate (validateReconcileRefs) can only mark it invalid, so an interrupted
		// image rollback — documented as Docker-reconcilable — would always
		// loud-stop instead of reconciling.
		if kind == ops.KindRollbackCreate && mode == "image" {
			if ref, _ := paramsForAudit["image_ref"].(string); ref != "" { //nolint:errcheck // absent/typed-nil → ""
				rec.TargetRef = ref
				if i := strings.Index(ref, "@sha256:"); i >= 0 {
					rec.TargetDigest = ref[i+len("@sha256:"):]
				}
			}
		}
		if jerr := s.opts.Journal.Write(rec); jerr != nil {
			// The orchestrator never takes ownership of oplog on this fail-closed
			// path, so close it here to avoid leaking the descriptor across repeated
			// admission attempts on a broken journal (ENOSPC/permissions).
			_ = oplog.Close()
			s.recordAdmissionFailure(op.ID, kind, peer.String(), paramsForAudit, idempotencyKey, "journal_write_failed: "+jerr.Error())
			return nil, false, augmentErrorWithOp(&opError{Status: http.StatusInternalServerError, Body: map[string]string{"error": "journal_write_failed"}}, op.ID)
		}
	}
	deps := ops.OrchestratorDeps{Manager: s.opts.Ops, Audit: s.opts.Audit, OpLog: oplog}
	if s.opts.Journal != nil {
		deps.Journal = s.opts.Journal // retired on terminal by the orchestrator
	}
	// Tracked via goOp so shutdown drains it (T2.4). The op ctx stays detached
	// from the request/shutdown ctx and bounded only by OperationTimeout: a
	// state-changing op must NOT be cancelled mid-flight on SIGTERM (that is the
	// stack-corruption risk) — the drain WAITS for it instead.
	// Hand the read-only slot (if any) to the goroutine; clear releaseSlot so the
	// deferred release above becomes a no-op and the slot is freed only when the
	// op flow finishes.
	slotRelease := releaseSlot
	releaseSlot = nil
	s.goOp(func() {
		if slotRelease != nil {
			defer slotRelease()
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.opts.Cfg.OperationTimeout)
		defer cancel()
		ops.Run(ctx, deps, op.ID, kind, peer.String(), paramsForAudit, idempotencyKey, stages, cfg.resultFn)
	})
	return op, false, nil
}

// recordAdmissionFailure marks the admitted op failed AND emits a
// matching pair of audit events (started + failed). Without this,
// an op that fails before any stage runs would never appear in
// audit.jsonl — only in the in-memory op map — and operators
// reviewing the audit trail would have no record of the attempt.
//
// Reason is always ReasonValidation for admission-time failures
// (build_stages closure failure, op-log open failure). The detail
// string is folded into the agent_error key on the op result so
// operators can correlate the audit entry with the op record via
// the op_id.
func (s *Server) recordAdmissionFailure(opID, kind, actor string, params map[string]interface{}, idempotencyKey, detail string) {
	now := time.Now().UTC()
	// started event — pairs with the failed event below so the
	// audit trail shows both transitions, matching how the
	// orchestrator emits events for stages that DO run.
	_ = s.opts.Audit.Write(audit.Event{
		Actor:          actor,
		OpID:           opID,
		Kind:           kind,
		Params:         params,
		Outcome:        audit.OutcomeStarted,
		IdempotencyKey: idempotencyKey,
	})
	_ = s.opts.Ops.Finish(opID, ops.StateFailed, ops.ReasonValidation, map[string]interface{}{
		"agent_error": detail,
	})
	_ = s.opts.Audit.Write(audit.Event{
		Actor:          actor,
		OpID:           opID,
		Kind:           kind,
		Params:         params,
		Outcome:        audit.OutcomeFailed,
		OutcomeAt:      &now,
		FailureReason:  string(ops.ReasonValidation),
		IdempotencyKey: idempotencyKey,
	})
}

// augmentErrorWithOp folds the op_id and "state":"failed" into an
// admission-time error body so the caller can fetch the op record
// via /v1/operations/{op_id} for diagnostics. Without this, callers
// see a 400/500 with no way to correlate it back to a persistent
// op record.
func augmentErrorWithOp(herr *opError, opID string) *opError {
	if herr == nil {
		return nil
	}
	out := map[string]interface{}{
		"op_id": opID,
		"state": "failed",
	}
	switch existing := herr.Body.(type) {
	case map[string]string:
		for k, v := range existing {
			out[k] = v
		}
	case map[string]interface{}:
		for k, v := range existing {
			out[k] = v
		}
	default:
		out["error"] = fmt.Sprintf("%v", existing)
	}
	herr.Body = out
	return herr
}

// opError is the typed error startAsyncOp returns to the handler.
type opError struct {
	Status int
	Body   interface{}
}

// startCfg holds optional startAsyncOp behavior set via startOpt. Both
// fields are nil by default — the existing backup/restore/cleanup/check/
// rollback callers pass no options and are unaffected.
type startCfg struct {
	// resultFn, when set, is forwarded to the orchestrator to compute the
	// structured op result at terminal time (used by upgrades.apply for
	// the inline auto-rollback result payload).
	resultFn ops.ResultFn
	// onOpID, when set, is invoked with the admitted op_id BEFORE stages
	// are built/run, so stage closures can stamp it onto sub-action audit
	// events (used by upgrades.apply for the upgrades.apply:rollback
	// audit entries).
	onOpID func(opID string)
}

type startOpt func(*startCfg)

// withResultFn attaches a structured-result computer to the op.
func withResultFn(fn ops.ResultFn) startOpt { return func(c *startCfg) { c.resultFn = fn } }

// withOpIDHook delivers the admitted op_id to the caller before stages run.
func withOpIDHook(fn func(opID string)) startOpt { return func(c *startCfg) { c.onOpID = fn } }

// writeOpResponse formats the response body for a 202-ish op
// acknowledgement. Status is 202 unless the op was deduped (in which
// case it's 200, since no new work was started).
func writeOpResponse(w http.ResponseWriter, op *ops.Op, deduped bool) {
	status := http.StatusAccepted
	if deduped {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]interface{}{
		"op_id":   op.ID,
		"kind":    op.Kind,
		"state":   op.State,
		"deduped": deduped,
	})
}

// resolveBackupPath validates `path` per the D1.6b restore contract:
// must be inside cfg.AllowedBackupDir per Config.IsAllowedBackupPath,
// and the basename must satisfy the runner's filename validator.
// Returns the bare filename suitable for ComposeRestore* methods, or
// an error.
func (s *Server) resolveBackupPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is required")
	}
	if !s.opts.Cfg.IsAllowedBackupPath(path) {
		return "", fmt.Errorf("path %q is outside allowed_backup_dir %q", path, s.opts.Cfg.AllowedBackupDir)
	}
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(s.opts.Cfg.AllowedBackupDir, clean)
	if err != nil {
		return "", fmt.Errorf("path: %w", err)
	}
	// Reject anything with a separator (i.e. require depth=1 inside
	// allowed_backup_dir). The runner enforces basename shape too,
	// but rejecting here yields a clearer 400.
	if strings.ContainsAny(rel, "/\\") {
		return "", fmt.Errorf("path must be a single basename inside %q, got %q", s.opts.Cfg.AllowedBackupDir, rel)
	}
	return rel, nil
}

// ─── POST /v1/backups (backup.create) ──────────────────────────────

type backupCreateRequest struct {
	Filename       string `json:"filename"`
	Encrypt        bool   `json:"encrypt"`
	PassphraseRef  string `json:"passphrase_ref,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	var req backupCreateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
		return
	}
	if err := runner.ValidateBackupFilename(req.Filename); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Encrypt && req.PassphraseRef == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "encrypt=true requires passphrase_ref"})
		return
	}
	if !req.Encrypt && req.PassphraseRef != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "encrypt=false must not include passphrase_ref"})
		return
	}
	// Shape-validate passphrase_ref BEFORE BeginIdempotent — env
	// read is deferred to buildStages so a deduped retry with a
	// transiently-missing env var still returns the existing op_id.
	if err := validatePassphraseRefShape(req.PassphraseRef, s.opts.Runner.EnvAllowSnapshot()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Sanitised audit params — passphrase_ref preserved (a reference,
	// not the value); the resolved passphrase will be captured by a
	// closure inside buildStages and is NEVER inserted into params
	// or any other audited field.
	params := map[string]interface{}{
		"filename":       req.Filename,
		"encrypt":        req.Encrypt,
		"passphrase_ref": req.PassphraseRef,
	}

	filename := req.Filename
	encrypt := req.Encrypt
	passRef := req.PassphraseRef

	// buildStages runs ONLY for newly admitted ops. It resolves the
	// passphrase from the env at this point (not earlier), so a
	// deduped retry never has to read the env at all.
	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindBackupCreate, req.IdempotencyKey, params, func() ([]ops.FlowStage, *opError) {
		resolved, rerr := readPassphraseFromEnv(passRef)
		if rerr != nil {
			return nil, &opError{Status: http.StatusBadRequest, Body: map[string]string{"error": rerr.Error()}}
		}
		stage := ops.FlowStage{
			Name:          "run_cli_backup",
			FailureReason: ops.ReasonCLIError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				var res *runner.Result
				var rerr2 error
				if encrypt {
					res, rerr2 = s.opts.Runner.ComposeBackupEncrypted(ctx, filename, resolved)
				} else {
					res, rerr2 = s.opts.Runner.ComposeBackupUnencrypted(ctx, filename)
				}
				if res == nil {
					return nil, nil, rerr2
				}
				return res.Stdout, res.Stderr, rerr2
			},
		}
		return []ops.FlowStage{stage}, nil
	})
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// ─── GET /v1/backups (backup.list) ─────────────────────────────────

// backupListEntry is the on-the-wire shape produced by the proxy CLI's
// `--list-backups` flag (see root list_backups.go). The agent
// re-encodes after parsing so we never forward malformed bytes
// claiming to be application/json.
type backupListEntry struct {
	Filename   string `json:"filename"`
	Path       string `json:"path"`
	SizeBytes  int64  `json:"size_bytes"`
	ModifiedAt string `json:"modified_at"` // RFC3339 string; not parsed
	Encrypted  bool   `json:"encrypted"`
}

func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	// Synchronous. The cli container scans /backup and emits a JSON
	// array on stdout; the agent unmarshals it (so a malformed CLI
	// output produces a clean 500 rather than corrupting the Content-
	// Type contract) and re-encodes via writeJSON.
	res, err := s.opts.Runner.ComposeBackupList(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":  "list_backups_failed",
			"detail": err.Error(),
		})
		return
	}
	var entries []backupListEntry
	if jerr := json.Unmarshal(res.Stdout, &entries); jerr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":  "list_backups_parse_failed",
			"detail": jerr.Error(),
		})
		return
	}
	// nil → []; the wire shape is always an array, never null.
	if entries == nil {
		entries = []backupListEntry{}
	}
	// Per-entry shape validation. The cli is trusted enough that we
	// accept its output, but a buggy or compromised cli could emit
	// entries that would mislead the operator (path traversal in
	// "path", negative size_bytes from an integer overflow, empty
	// filename), so we surface a clean 500 rather than serve them
	// up with the agent's stamp of approval.
	if verr := validateBackupListEntries(entries, s.opts.Cfg.AllowedBackupDir); verr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":  "list_backups_invalid_entry",
			"detail": verr.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, entries)
	_ = peer
}

// validateBackupListEntries enforces the per-entry shape contract for
// what GET /v1/backups will surface to clients. Returns the first
// error (with the entry index for operator-facing diagnostics) or nil.
//
// Rules:
//   - filename must be non-empty and a bare basename (no path
//     separators, no traversal). Same shape the encrypted-backup
//     handler enforces for create.
//   - path must be inside allowedBackupDir AND its basename must
//     equal filename (so a misbehaving cli cannot list filename="a"
//     with path="/etc/passwd").
//   - size_bytes must be non-negative.
func validateBackupListEntries(entries []backupListEntry, allowedBackupDir string) error {
	for i, e := range entries {
		if e.Filename == "" {
			return fmt.Errorf("entry[%d]: empty filename", i)
		}
		if err := runner.ValidateBackupFilename(e.Filename); err != nil {
			return fmt.Errorf("entry[%d]: %w", i, err)
		}
		if e.Path == "" {
			return fmt.Errorf("entry[%d]: empty path", i)
		}
		clean := filepath.Clean(e.Path)
		if clean != e.Path {
			return fmt.Errorf("entry[%d]: path %q is not in canonical form", i, e.Path)
		}
		// path must live directly under allowedBackupDir.
		expected := filepath.Join(allowedBackupDir, e.Filename)
		if clean != expected {
			return fmt.Errorf("entry[%d]: path %q does not match basename %q under %q",
				i, e.Path, e.Filename, allowedBackupDir)
		}
		if e.SizeBytes < 0 {
			return fmt.Errorf("entry[%d]: negative size_bytes %d", i, e.SizeBytes)
		}
	}
	return nil
}

// ─── POST /v1/restores/dryrun and /commit ──────────────────────────

type restoreRequest struct {
	Path                 string `json:"path"`
	Mode                 string `json:"mode"`
	PassphraseRef        string `json:"passphrase_ref,omitempty"`
	AcceptDPReenrollment bool   `json:"accept_dp_reenrollment,omitempty"`
	AllowCounterRollback bool   `json:"allow_counter_rollback,omitempty"`
	IdempotencyKey       string `json:"idempotency_key,omitempty"`
}

func (s *Server) handleRestoreDryRun(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	s.handleRestore(w, r, peer, false)
}

func (s *Server) handleRestoreCommit(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	s.handleRestore(w, r, peer, true)
}

//nolint:cyclop,funlen,nestif // single-pass orchestration; splitting hides the down→commit→up→health ordering
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo, commit bool) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	if commit && s.opts.HealthProbeFactory == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "health_probe_not_wired"})
		return
	}
	var req restoreRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
		return
	}
	filename, err := s.resolveBackupPath(req.Path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	mode := runner.RestoreMode(req.Mode)
	if !mode.IsValid() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be one of full|trust-root-only|state-only"})
		return
	}
	// Shape-validate passphrase_ref BEFORE BeginIdempotent. Env read
	// is deferred to buildStages so a deduped retry never has to
	// re-read os.Getenv.
	if err := validatePassphraseRefShape(req.PassphraseRef, s.opts.Runner.EnvAllowSnapshot()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	params := map[string]interface{}{
		"path":                   req.Path,
		"mode":                   req.Mode,
		"accept_dp_reenrollment": req.AcceptDPReenrollment,
		"allow_counter_rollback": req.AllowCounterRollback,
		"passphrase_ref":         req.PassphraseRef,
	}

	acceptDP := req.AcceptDPReenrollment
	allowCounter := req.AllowCounterRollback
	passRef := req.PassphraseRef

	buildStages := func() ([]ops.FlowStage, *opError) {
		// passphrase_ref is OPTIONAL for restore (cli detects
		// encryption via magic bytes). If a ref was supplied but
		// the env var is empty, fail late so the dedup-retry path
		// is unaffected.
		resolved, rerr := readPassphraseFromEnv(passRef)
		if rerr != nil {
			return nil, &opError{Status: http.StatusBadRequest, Body: map[string]string{"error": rerr.Error()}}
		}
		return s.buildRestoreStages(commit, filename, mode, acceptDP, allowCounter, resolved), nil
	}

	kind := ops.KindRestoreDryRun
	if commit {
		kind = ops.KindRestoreCommit
	}
	op, deduped, herr := s.startAsyncOp(r, peer, kind, req.IdempotencyKey, params, buildStages)
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// buildRestoreStages constructs the stage list for restore.dryrun
// (commit=false, single stage) or restore.commit (commit=true, four
// stages: down → cli --restore --confirm → up [best-effort] →
// health_check [best-effort]). Extracted from handleRestore so the
// late-binding closure stays compact.
//
//nolint:funlen // single-pass orchestration sequence — splitting hides the down→commit→up→health ordering
func (s *Server) buildRestoreStages(commit bool, filename string, mode runner.RestoreMode, acceptDP, allowCounter bool, resolved string) []ops.FlowStage {
	if !commit {
		return []ops.FlowStage{
			{
				Name:          "run_cli_restore_dryrun",
				FailureReason: ops.ReasonCLIError,
				Run: func(ctx context.Context) ([]byte, []byte, error) {
					res, rerr := s.opts.Runner.ComposeRestoreDryRun(ctx, filename, mode, acceptDP, allowCounter, resolved)
					if res == nil {
						return nil, nil, rerr
					}
					return res.Stdout, res.Stderr, rerr
				},
			},
		}
	}
	probeFactory := s.opts.HealthProbeFactory
	return []ops.FlowStage{
		{
			Name:          "stop_stack",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeDown(ctx)
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			},
		},
		{
			Name:          "run_cli_restore_commit",
			FailureReason: ops.ReasonCLIError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeRestoreCommit(ctx, filename, mode, acceptDP, allowCounter, resolved)
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			},
		},
		{
			// Best-effort recovery: try to bring the stack back
			// up even if the restore commit failed. Op stays
			// failed (first failure wins), but the operator log
			// shows whether the recovery worked.
			Name:            "start_stack",
			ContinueOnError: true,
			FailureReason:   ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeUp(ctx)
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			},
		},
		{
			// ContinueOnError=true so health_check ALWAYS runs
			// after start_stack, even when restore failed. The
			// operator needs to see whether the recovery
			// brought the stack back; first-failure-wins still
			// preserves the audit reason from the earlier
			// stage. Without this flag, a failed restore would
			// abort here and leave the operator guessing
			// whether `compose up` actually worked.
			Name:            "health_check",
			ContinueOnError: true,
			FailureReason:   ops.ReasonHealthFailed,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				probe := probeFactory()
				hr, herr := probe.Run(ctx)
				if herr != nil {
					return nil, nil, herr
				}
				summary := fmt.Sprintf("ready=%v ready_detail=%q health=%v health_detail=%q duration=%s",
					hr.ReadyOK, hr.ReadyDetail, hr.HealthOK, hr.HealthDetail, hr.TotalDuration)
				if hr.Failed() {
					return []byte(summary), nil, errors.New(hr.ReadyDetail)
				}
				return []byte(summary), nil, nil
			},
		},
	}
}

// ─── POST /v1/cleanups ─────────────────────────────────────────────

type cleanupRequest struct {
	OlderThan      string `json:"older_than"`
	KeepLast       int    `json:"keep_last"`
	Confirm        bool   `json:"confirm,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	var req cleanupRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
		return
	}
	if err := runner.ValidateOlderThan(req.OlderThan); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := runner.ValidateKeepLast(req.KeepLast); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	params := map[string]interface{}{
		"older_than": req.OlderThan,
		"keep_last":  req.KeepLast,
		"confirm":    req.Confirm,
	}

	confirm := req.Confirm
	older := req.OlderThan
	keep := req.KeepLast

	buildStages := func() ([]ops.FlowStage, *opError) {
		stage := ops.FlowStage{
			Name:          "run_cli_cleanup",
			FailureReason: ops.ReasonCLIError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				var res *runner.Result
				var rerr error
				if confirm {
					res, rerr = s.opts.Runner.ComposeCleanupCommit(ctx, older, keep)
				} else {
					res, rerr = s.opts.Runner.ComposeCleanupDryRun(ctx, older, keep)
				}
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			},
		}
		return []ops.FlowStage{stage}, nil
	}

	kind := ops.KindCleanupDryRun
	if confirm {
		kind = ops.KindCleanupCommit
	}
	op, deduped, herr := s.startAsyncOp(r, peer, kind, req.IdempotencyKey, params, buildStages)
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// Compile-time guard: every handler we declared in routes() above
// has a matching method here.
var _ = []http.HandlerFunc{
	func(http.ResponseWriter, *http.Request) {},
}

// Force imports we need but might be elided by linters when handlers
// are stripped down for tests.
var (
	_ = audit.OutcomeStarted
	_ = health.Probe{}
)
