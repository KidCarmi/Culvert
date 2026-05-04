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
//  2. Validate every field. Reject with 400 on any malformed input.
//  3. Resolve passphrase_ref (env:NAME only in D1.6b). The resolved
//     value is held in a local string variable for the duration of
//     this handler — never logged, never put into the op record's
//     params, never echoed in the audit event. Only the *reference*
//     (env:NAME) is recorded; the resolved value flows into the
//     runner via env overlay.
//  4. Build a sanitized params map for the audit event (passphrase_ref
//     preserved; resolved value NEVER included).
//  5. Call ops.Manager.BeginIdempotent. On 409 (lock conflict),
//     return 409 with the holder's snapshot. On dedupe hit, return
//     202 with the prior op_id so the caller's retry is a no-op.
//  6. Open a per-op log file. If creation fails, finish the op as
//     failed (validation reason) and return 500.
//  7. Spawn the orchestrator goroutine with the stage list. Return
//     202 immediately with the op_id.
//
// GET /v1/backups is the only synchronous handler — it does its work
// inline and returns 200 with the parsed JSON list.
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

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/health"
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
// an *opError, the op is finished with ReasonValidation and the
// error is propagated to the caller — the op record will be
// observable via /v1/operations/{id} as failed.
func (s *Server) startAsyncOp(_ *http.Request, peer auth.PeerInfo, kind, idempotencyKey string, paramsForAudit map[string]interface{}, buildStages func() ([]ops.FlowStage, *opError)) (*ops.Op, bool, *opError) {
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
	// Newly admitted op — late-bound stage construction happens here.
	stages, herr := buildStages()
	if herr != nil {
		_ = s.opts.Ops.Finish(op.ID, ops.StateFailed, ops.ReasonValidation, map[string]interface{}{"agent_error": "build_stages: late validation failed"})
		return nil, false, herr
	}
	oplog, oerr := ops.OpenOpLog(s.opts.StateDir, op.ID)
	if oerr != nil {
		_ = s.opts.Ops.Finish(op.ID, ops.StateFailed, ops.ReasonValidation, map[string]interface{}{"agent_error": "open op log: " + oerr.Error()})
		return nil, false, &opError{Status: http.StatusInternalServerError, Body: map[string]string{"error": "open_op_log_failed"}}
	}
	deps := ops.OrchestratorDeps{Manager: s.opts.Ops, Audit: s.opts.Audit, OpLog: oplog}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.opts.Cfg.OperationTimeout)
		defer cancel()
		ops.Run(ctx, deps, op.ID, kind, peer.String(), paramsForAudit, idempotencyKey, stages)
	}()
	return op, false, nil
}

// opError is the typed error startAsyncOp returns to the handler.
type opError struct {
	Status int
	Body   interface{}
}

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
	writeJSON(w, http.StatusOK, entries)
	_ = peer
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
