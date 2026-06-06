// D1.6c: POST /v1/rollbacks mode=data — roll /data back by restoring a
// backup. This is a WRAP of the existing restore.commit primitive, run
// under the rollbacks.create op kind. It is NOT a second restore
// implementation:
//
//   - validation reuses runner.ValidateBackupFilename + the same
//     allowed-backup-dir containment + runner.RestoreMode +
//     validatePassphraseRefShape that restore.commit uses;
//   - execution reuses buildRestoreStages(commit=true, …) verbatim
//     (stop_stack → run_cli_restore_commit → start_stack → health_check),
//     which forwards the accept_dp_reenrollment / allow_counter_rollback
//     safety flags to the CLI and inherits its WouldBlock fail-closed
//     guards;
//   - the only additions are an explicit pre-stage existence check (so a
//     typoed filename fails 400 BEFORE the stack is stopped — strictly
//     safer than restore.commit), light outcome OBSERVATION (not changed
//     behavior) for the result, and a report summary stage.
//
// Standalone-only: there is no inline/auto data rollback. The apply
// inline-rollback path (#378) is image-only and must never reach here.
package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"culvert-maint/internal/auth"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// dataRollbackAccumulator OBSERVES the wrapped restore stages for the
// result/summary. It never changes restore behavior.
type dataRollbackAccumulator struct {
	committed     bool   // run_cli_restore_commit returned nil error (the /data swap happened)
	healthSummary string // health_check stage's summary line
}

// rollbackData handles mode=data: restore /data from a backup via the
// shared restore.commit machinery.
func (s *Server) rollbackData(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo, req rollbackRequest) {
	// Filename-specific resolution (the rollback contract sends a bare
	// basename, not a /backup/… path — see D1.6c data-rollback plan §1).
	if err := runner.ValidateBackupFilename(req.Filename); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	joined := filepath.Join(s.opts.Cfg.AllowedBackupDir, req.Filename)
	if !s.opts.Cfg.IsAllowedBackupPath(joined) { // defense-in-depth containment
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("filename %q resolves outside allowed_backup_dir %q", req.Filename, s.opts.Cfg.AllowedBackupDir),
		})
		return
	}
	// Explicit existence check BEFORE any stage — a typoed/absent backup
	// must fail 400 with the stack untouched, never stop_stack then
	// cli_error (data-rollback plan §4; stricter than restore.commit).
	if _, err := os.Stat(joined); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("backup %q not found in %s", req.Filename, s.opts.Cfg.AllowedBackupDir),
		})
		return
	}

	modeStr := req.RestoreMode
	if modeStr == "" {
		modeStr = "full" // contract default
	}
	mode := runner.RestoreMode(modeStr)
	if !mode.IsValid() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "restore_mode must be one of full|trust-root-only|state-only"})
		return
	}
	// Same passphrase_ref shape gate as restore.commit (empty is allowed;
	// the CLI detects encryption and fails closed without a passphrase).
	if err := validatePassphraseRefShape(req.PassphraseRef, s.opts.Runner.EnvAllowSnapshot()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	params := map[string]interface{}{
		"mode":                   "data",
		"filename":               req.Filename,
		"restore_mode":           modeStr,
		"accept_dp_reenrollment": req.AcceptDPReenrollment,
		"allow_counter_rollback": req.AllowCounterRollback,
		"passphrase_ref":         req.PassphraseRef, // reference only, never the value
	}

	filename := req.Filename
	acceptDP := req.AcceptDPReenrollment
	allowCounter := req.AllowCounterRollback
	passRef := req.PassphraseRef
	acc := &dataRollbackAccumulator{}

	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindRollbackCreate, req.IdempotencyKey, params,
		func() ([]ops.FlowStage, *opError) {
			resolved, rerr := readPassphraseFromEnv(passRef)
			if rerr != nil {
				return nil, &opError{Status: http.StatusBadRequest, Body: map[string]string{"error": rerr.Error()}}
			}
			return s.buildDataRollbackStages(filename, mode, acceptDP, allowCounter, resolved, acc), nil
		},
		withResultFn(func(state ops.State, _ ops.FailureReason) map[string]interface{} {
			return map[string]interface{}{
				"mode":                     "data",
				"filename":                 filename,
				"restore_mode":             modeStr,
				"dp_reenrollment_accepted": acceptDP,
				"counter_rollback_allowed": allowCounter,
				"restore_committed":        acc.committed,
				"succeeded":                state == ops.StateSucceeded,
				"health":                   acc.healthSummary,
			}
		}),
	)
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// buildDataRollbackStages returns the SHARED restore.commit stages
// (buildRestoreStages(commit=true,…)) — verbatim — with two of them
// decorated to OBSERVE their outcome (not change it) for the result, plus
// an appended report summary. This is the wrap-not-fork boundary: the
// restore logic (ComposeDown/ComposeRestoreCommit/ComposeUp/health) is
// reused exactly; only success/output is recorded.
func (s *Server) buildDataRollbackStages(filename string, mode runner.RestoreMode, acceptDP, allowCounter bool, resolved string, acc *dataRollbackAccumulator) []ops.FlowStage {
	stages := s.buildRestoreStages(true, filename, mode, acceptDP, allowCounter, resolved)
	for i := range stages {
		switch stages[i].Name {
		case "run_cli_restore_commit":
			inner := stages[i].Run
			stages[i].Run = func(ctx context.Context) ([]byte, []byte, error) {
				out, errout, err := inner(ctx)
				if err == nil {
					acc.committed = true // the /data swap happened
				}
				return out, errout, err
			}
		case "health_check":
			inner := stages[i].Run
			stages[i].Run = func(ctx context.Context) ([]byte, []byte, error) {
				out, errout, err := inner(ctx)
				if len(out) > 0 {
					acc.healthSummary = string(out)
				}
				return out, errout, err
			}
		}
	}
	return append(stages, ops.FlowStage{
		Name:            "report",
		ContinueOnError: true,
		FailureReason:   ops.ReasonCommandError,
		Run: func(_ context.Context) ([]byte, []byte, error) {
			summary := fmt.Sprintf(
				"rollback mode=data filename=%q restore_mode=%s committed=%v health=[%s]",
				filename, mode, acc.committed, acc.healthSummary,
			)
			return []byte(summary), nil, nil
		},
	})
}
