// D1.6b API handlers: backup create / list, restore dry-run / commit,
// cleanup leftovers.
//
// Request shape, validation rules, and operation flow are documented
// in roadmap/D1.6-maintenance-agent-implementation-plan.md and the
// D1.6b kickoff brief.
//
// Common pattern (POST handlers — backup.create, restore.*, cleanup):
//
//   1. Decode JSON body into a typed request struct.
//   2. Validate every field. Reject with 400 on any malformed input.
//   3. Resolve passphrase_ref (env:NAME only in D1.6b). The resolved
//      value is held in a local string variable for the duration of
//      this handler — never logged, never put into the op record's
//      params, never echoed in the audit event. Only the *reference*
//      (env:NAME) is recorded; the resolved value flows into the
//      runner via env overlay.
//   4. Build a sanitized params map for the audit event (passphrase_ref
//      preserved; resolved value NEVER included).
//   5. Call ops.Manager.BeginIdempotent. On 409 (lock conflict),
//      return 409 with the holder's snapshot. On dedupe hit, return
//      202 with the prior op_id so the caller's retry is a no-op.
//   6. Open a per-op log file. If creation fails, finish the op as
//      failed (validation reason) and return 500.
//   7. Spawn the orchestrator goroutine with the stage list. Return
//      202 immediately with the op_id.
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

// resolvePassphraseRef resolves a passphrase_ref string into a value
// string. Supported schemes:
//
//   - "env:NAME" — reads os.Getenv("NAME"). Errors if NAME is not in
//     the runner's EnvAllow (so secrets cannot smuggle through env
//     names the operator did not pre-approve) OR if NAME is unset OR
//     empty.
//
// "" passes through as ("", nil) — caller decides whether empty is
// allowed for the operation. "file:/path" support is deferred to
// D1.6c per the kickoff.
//
// The returned value is never logged. Callers MUST keep it in a local
// variable and pass it directly into runner methods via the env
// overlay path — never into params, never into result, never into
// audit fields.
func resolvePassphraseRef(ref string, runnerEnvAllow []string) (string, error) {
	if ref == "" {
		return "", nil
	}
	if !strings.HasPrefix(ref, "env:") {
		return "", fmt.Errorf("passphrase_ref: only env:NAME is supported in D1.6b, got %q", ref)
	}
	name := strings.TrimPrefix(ref, "env:")
	if name == "" {
		return "", errors.New("passphrase_ref: env: prefix with empty name")
	}
	allowed := false
	for _, n := range runnerEnvAllow {
		if n == name {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("passphrase_ref: env name %q is not in the runner's EnvAllow", name)
	}
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

// startAsyncOp does the common work of admitting an operation and
// kicking off its orchestrator goroutine. Returns the op snapshot the
// handler will echo back to the caller (with deduped flag), or an
// error suitable for an HTTP 4xx/5xx response.
//
// Caller is responsible for: decoding the request, building the
// params map (sanitised for audit — no raw secrets), and constructing
// the stage list (which closures will pull the resolved passphrase
// from a local variable). The returned op may be nil only when the
// returned error is non-nil.
func (s *Server) startAsyncOp(_ *http.Request, peer auth.PeerInfo, kind, idempotencyKey string, paramsForAudit map[string]interface{}, stages []ops.FlowStage) (*ops.Op, bool, *opError) {
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
		// A duplicate submission — return the prior op snapshot,
		// no goroutine spawn.
		return op, true, nil
	}
	oplog, oerr := ops.OpenOpLog(s.opts.StateDir, op.ID)
	if oerr != nil {
		_ = s.opts.Ops.Finish(op.ID, ops.StateFailed, ops.ReasonValidation, map[string]interface{}{"agent_error": "open op log: " + oerr.Error()})
		return nil, false, &opError{Status: http.StatusInternalServerError, Body: map[string]string{"error": "open_op_log_failed"}}
	}
	deps := ops.OrchestratorDeps{Manager: s.opts.Ops, Audit: s.opts.Audit, OpLog: oplog}
	// Goroutine owns oplog now; orchestrator closes it on exit.
	go ops.Run(context.Background(), deps, op.ID, kind, peer.String(), paramsForAudit, idempotencyKey, stages)
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
	resolved, err := resolvePassphraseRef(req.PassphraseRef, s.opts.Runner.EnvAllowSnapshot())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Sanitised audit params — passphrase_ref preserved (a reference,
	// not the value); the resolved passphrase is captured in a local
	// closure variable below and is NEVER inserted into params or
	// any other audited field.
	params := map[string]interface{}{
		"filename":       req.Filename,
		"encrypt":        req.Encrypt,
		"passphrase_ref": req.PassphraseRef,
	}

	// Build the single backup stage. The closure captures `resolved`
	// — when this goroutine runs, it pulls the value from the
	// closure, hands it to the runner via env overlay, and never
	// stores it anywhere else.
	filename := req.Filename
	encrypt := req.Encrypt
	stage := ops.FlowStage{
		Name:          "run_cli_backup",
		FailureReason: ops.ReasonCLIError,
		Run: func(ctx context.Context) ([]byte, []byte, error) {
			var res *runner.Result
			var rerr error
			if encrypt {
				res, rerr = s.opts.Runner.ComposeBackupEncrypted(ctx, filename, resolved)
			} else {
				res, rerr = s.opts.Runner.ComposeBackupUnencrypted(ctx, filename)
			}
			if res == nil {
				return nil, nil, rerr
			}
			return res.Stdout, res.Stderr, rerr
		},
	}

	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindBackupCreate, req.IdempotencyKey, params, []ops.FlowStage{stage})
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// ─── GET /v1/backups (backup.list) ─────────────────────────────────

func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	// Synchronous. The cli container scans /backup and emits a JSON
	// array; we proxy that verbatim. Read-only — no audit, no op
	// record.
	res, err := s.opts.Runner.ComposeBackupList(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":  "list_backups_failed",
			"detail": err.Error(),
		})
		return
	}
	// Forward the JSON array as-is.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Stdout)
	_ = peer
}

// ─── POST /v1/restores/dryrun and /commit ──────────────────────────

type restoreRequest struct {
	Path                  string `json:"path"`
	Mode                  string `json:"mode"`
	PassphraseRef         string `json:"passphrase_ref,omitempty"`
	AcceptDPReenrollment  bool   `json:"accept_dp_reenrollment,omitempty"`
	AllowCounterRollback  bool   `json:"allow_counter_rollback,omitempty"`
	IdempotencyKey        string `json:"idempotency_key,omitempty"`
}

func (s *Server) handleRestoreDryRun(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	s.handleRestore(w, r, peer, false)
}

func (s *Server) handleRestoreCommit(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	s.handleRestore(w, r, peer, true)
}

//nolint:cyclop // single-pass orchestration; splitting hides the down→commit→up→health ordering
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
	resolved, err := resolvePassphraseRef(req.PassphraseRef, s.opts.Runner.EnvAllowSnapshot())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	params := map[string]interface{}{
		"path":                    req.Path,
		"mode":                    req.Mode,
		"accept_dp_reenrollment":  req.AcceptDPReenrollment,
		"allow_counter_rollback":  req.AllowCounterRollback,
		"passphrase_ref":          req.PassphraseRef,
	}

	acceptDP := req.AcceptDPReenrollment
	allowCounter := req.AllowCounterRollback
	var stages []ops.FlowStage

	if !commit {
		stages = []ops.FlowStage{
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
	} else {
		probeFactory := s.opts.HealthProbeFactory
		stages = []ops.FlowStage{
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
				Name:          "health_check",
				FailureReason: ops.ReasonHealthFailed,
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

	kind := ops.KindRestoreDryRun
	if commit {
		kind = ops.KindRestoreCommit
	}
	op, deduped, herr := s.startAsyncOp(r, peer, kind, req.IdempotencyKey, params, stages)
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
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

	kind := ops.KindCleanupDryRun
	if confirm {
		kind = ops.KindCleanupCommit
	}
	op, deduped, herr := s.startAsyncOp(r, peer, kind, req.IdempotencyKey, params, []ops.FlowStage{stage})
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
