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
//   - additions: a container-backed existence PREFLIGHT (the backup-list
//     command — the /backup volume lives in the cli container, not on the
//     agent host, so a host os.Stat is wrong), so a typoed/absent backup
//     fails 404 BEFORE the stack is stopped; light outcome OBSERVATION
//     (not changed behavior) for the result; and a report summary stage.
//     The preflight degrades to restore.commit behavior if the list is
//     unavailable, so it is never worse than restore.commit.
//
// Standalone-only: there is no inline/auto data rollback. The apply
// inline-rollback path (#378) is image-only and must never reach here.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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
	// ValidateBackupFilename guarantees a separator-free basename, so it
	// cannot escape AllowedBackupDir — the same containment guarantee
	// resolveBackupPath gives restore.commit. We do NOT host-stat the
	// backup: allowed_backup_dir is the path as seen by the `cli`
	// CONTAINER (the `culvert-backups` volume is mounted only in `cli`,
	// not on the agent host), so a host os.Stat would reject every valid
	// rollback. Existence is validated by the CLI inside the container at
	// restore time — exactly like restore.commit.
	if err := runner.ValidateBackupFilename(req.Filename); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
	// Container-backed existence preflight: ask the cli to list /backup
	// (the volume lives in the cli container, not on the agent host) and
	// confirm the named backup is present BEFORE admitting the op. A typo
	// fails 404 here — the stack is never stopped. If the list itself is
	// unavailable we DEGRADE to restore.commit behavior (proceed; the CLI
	// validates at restore time) so data rollback is never worse than
	// restore.commit. Read-only + online (the proxy stays up).
	if herr := s.preflightBackupExists(r.Context(), req.Filename); herr != nil {
		writeJSON(w, herr.Status, herr.Body)
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

// preflightBackupExists confirms the named backup is present in the cli
// container's /backup volume, using the existing backup-list command (no
// new sudoers/template). Returns a 404 opError if the list is available
// and the backup is NOT in it (the typo case — caught before stop_stack).
// If the list cannot be obtained/parsed it returns nil (DEGRADE: proceed,
// and let the restore CLI validate existence at restore time, exactly as
// restore.commit does — so a flaky list never blocks a valid rollback).
func (s *Server) preflightBackupExists(ctx context.Context, filename string) *opError {
	res, err := s.opts.Runner.ComposeBackupList(ctx)
	if err != nil || res == nil {
		return nil // can't verify → degrade to restore.commit behavior
	}
	var entries []backupListEntry
	if json.Unmarshal(res.Stdout, &entries) != nil {
		return nil // unparseable list → degrade
	}
	for i := range entries {
		if entries[i].Filename == filename {
			return nil // exists
		}
	}
	return &opError{Status: http.StatusNotFound, Body: map[string]string{
		"error": fmt.Sprintf("backup %q not found in the backup store", filename),
	}}
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
