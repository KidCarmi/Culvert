// What the report of an interrupted restore-class operation says, per stage.
//
// One table (restoreFactsFor) maps the stage a record durably reached onto the
// four statements an operator needs, and restoreActionFor words what to do. No
// statement here comes from Docker or from the data volume: the agent cannot
// read the volume, and what Docker says now is reported separately
// (compose_stack_up, pinned_tag). Where the journal cannot vouch for something
// the report says "unknown" rather than the likely answer.
//
// The table, in flow order:
//
//	stage          stack_touched  data_changed  previous_state
//	admitted       false          no            in_place
//	preflight      false          no            in_place
//	stopping       true           no            in_place
//	committing     true           unknown       recoverable_at_next_proxy_start_or_manual
//	commit_failed  true           unknown       recoverable_at_next_proxy_start_or_manual
//	committed      true           yes           kept_in_backup_dir
//	starting       true           yes           kept_in_backup_dir
//	started        true           yes           kept_in_backup_dir
//	unrecorded     (absent)       unknown       unknown
//
// Why commit_failed is "unknown" and not "no": the commit command returning an
// error does not establish that the data directory is as it was. On the shipped
// topology the command puts the previous content back itself and then that is
// true, but the same error is what the agent sees when the stage timeout killed
// the docker client (the restore's container keeps running and may yet commit)
// and when putting the content back failed (the intent record is left for the
// next proxy start). Telling those apart would mean parsing the command's
// prose; the report does not guess.
package server

import (
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// restoreFacts is one row of the table above.
type restoreFacts struct {
	stage         string
	stackTouched  *bool
	dataChanged   string
	previousState string
	restartSafe   string
}

const (
	restartSafeUntouched = "This operation did not stop the proxy and did not change the data directory: " +
		"starting or restarting the proxy is not affected by it."
	restartSafeStopped = "Yes, as far as the data is concerned: the data directory was not changed, so the proxy starts on the content it had. " +
		"Which image starts is a separate matter; see operator_action."
	restartSafeUnsettled = "It depends on the deployment, which the agent cannot see. On the shipped Docker Compose deployment " +
		"(the data directory is the volume's mount point and the proxy image has the in-place restore): yes — the proxy undoes an " +
		"unfinished in-place restore before it reads the data directory, or refuses to start and changes nothing (it also refuses while " +
		"the restore's container is still running); if the restore had in fact committed, it starts on the restored content. " +
		"With an older proxy image, or a data directory that is not a mount point: not known to be safe — a restore cut between its two " +
		"renames leaves no data directory and the proxy refuses to start; follow \"Recovering from an interrupted restore\" (§ 8b) in " +
		"docs/operator/docker-compose-backup-restore.md first."
	restartSafeCommitted = "Yes: the restore committed, and the proxy starts on the restored content. " +
		"The agent never health-checked the proxy on it."
	restartSafeUnrecorded = "Unknown: this record does not say how far the restore got. Treat it as a restore whose commit result was never recorded. " +
		restartSafeUnsettled
)

func boolPtr(b bool) *bool { return &b }

// restoreFactsFor returns the row for a recorded stage. Every value outside the
// known set — none recorded, or journal.RestoreStageUnknown — is "unrecorded".
func restoreFactsFor(stage journal.RestoreStage) restoreFacts {
	switch stage {
	case journal.RestoreStageAdmitted, journal.RestoreStagePreflight:
		return restoreFacts{string(stage), boolPtr(false), DataChangedNo, PreviousInPlace, restartSafeUntouched}
	case journal.RestoreStageStopping:
		return restoreFacts{string(stage), boolPtr(true), DataChangedNo, PreviousInPlace, restartSafeStopped}
	case journal.RestoreStageCommitting, journal.RestoreStageCommitFailed:
		return restoreFacts{string(stage), boolPtr(true), DataChangedUnknown, PreviousRecoverable, restartSafeUnsettled}
	case journal.RestoreStageCommitted, journal.RestoreStageStarting, journal.RestoreStageStarted:
		return restoreFacts{string(stage), boolPtr(true), DataChangedYes, PreviousKeptInBackupDir, restartSafeCommitted}
	default:
		return restoreFacts{RestoreStageUnrecorded, nil, DataChangedUnknown, PreviousUnknown, restartSafeUnrecorded}
	}
}

// setRestoreFacts fills the restore-class fields of the report.
func (o *InterruptedOperation) setRestoreFacts(stage journal.RestoreStage) {
	f := restoreFactsFor(stage)
	o.RestoreStage = f.stage
	o.StackTouched = f.stackTouched
	o.DataChanged = f.dataChanged
	o.PreviousState = f.previousState
	o.RestartSafe = f.restartSafe
}

const (
	// restoreStartAdvice keeps the existing warning about `docker compose up`
	// accurate for a stack this operation stopped: with the proxy down there is
	// no running image to compare the fixed tag with, so the check is the tag
	// itself and the list of interrupted image changes.
	restoreStartAdvice = " Before starting the stack by hand, read GET /v1/status: if an interrupted upgrade or image rollback is also listed, " +
		"or pinned_tag.image_id is not the image you expect the proxy to run (running_image and pinned_tag.matches_running are reported only " +
		"while the proxy runs), deal with that first — `docker compose up -d` starts whatever image the fixed tag is on, with no health gate."
	restoreTail = " The agent has not changed Docker or the data directory since it restarted, and this entry stays until a later restore or " +
		"data rollback commits and passes its health check, or a later upgrade or image rollback succeeds."

	restoreActionUntouched = "The restore stopped before it asked Docker to stop the stack and before it touched the data directory. " +
		"There is nothing to recover; submit it again if it is still wanted." + restoreTail
	restoreActionStopped = "The restore asked Docker to stop the stack and stopped before its commit command ran: the data directory was not changed, " +
		"and the agent has not started the stack again. Check compose_stack_up in GET /v1/status (a stop that was cut short can leave the proxy running). " +
		"If the proxy is down, either submit the restore again — it stops, restores, starts and health-checks the stack — or start the stack yourself." +
		restoreStartAdvice + restoreTail
	// restoreSettle is the procedure for a data directory whose state the
	// journal cannot vouch for.
	restoreSettle = "First make sure the restore is over: it runs in a `cli` container that outlives the agent, so `docker ps -a` must show none of this " +
		"compose project still running. Then, on the shipped Docker Compose deployment, start the proxy or submit the restore again: an unfinished " +
		"in-place restore is undone before the data directory is read (or the proxy refuses to start and its log says why), and " +
		"<data>/.restore/last-outcome.json then says `committed` or `rolled_back`. With a proxy image that predates the in-place restore, or a data " +
		"directory that is not a volume mount point, follow \"Recovering from an interrupted restore\" (§ 8b) in " +
		"docs/operator/docker-compose-backup-restore.md BEFORE starting anything."
	restoreActionCommitting = "The restore's commit command was started and its result was never recorded: the data directory may hold its previous content, " +
		"the restored content, or an unfinished swap, and the agent has not started the stack again. " + restoreSettle + restoreStartAdvice + restoreTail
	restoreActionCommitFailed = "The restore's commit command returned an error, and the agent died before it started the stack again. The command normally " +
		"puts the previous content back itself and changes nothing, but the agent cannot vouch for that: the same error is reported when the command was cut " +
		"off (its container may still be running) or could not put the content back. Its own message is in GET /v1/operations/{op_id}/logs. " +
		restoreSettle + restoreStartAdvice + restoreTail
	restoreActionUnrecorded = "A restore was interrupted, and its journal record does not say how far it got (the record passed through an agent " +
		"version that does not keep that). Treat it as a restore whose commit result was never recorded. " + restoreSettle + restoreStartAdvice + restoreTail
	restoreActionCommitted = "The restore committed: the data directory holds the restored content, and the previous content is kept in the restore's backup " +
		"directory (the cli's --list-restore-leftovers lists it; nothing was deleted). The agent died before the stack had been started and had passed the " +
		"health check, so nobody has checked the proxy on the restored data. Check compose_stack_up in GET /v1/status; if the proxy is down, start the stack " +
		"and check its health yourself. Do not submit the restore again merely to start the stack: it would restore the same backup a second time." +
		restoreStartAdvice + restoreTail
)

// restoreActionFor words the operator action for a reported restore stage
// (InterruptedOperation.RestoreStage). A data-rollback record that does not say
// how far it got keeps the advice a data rollback has always had.
func restoreActionFor(kind, stage string) string {
	switch journal.RestoreStage(stage) {
	case journal.RestoreStageAdmitted, journal.RestoreStagePreflight:
		return restoreActionUntouched
	case journal.RestoreStageStopping:
		return restoreActionStopped
	case journal.RestoreStageCommitting:
		return restoreActionCommitting
	case journal.RestoreStageCommitFailed:
		return restoreActionCommitFailed
	case journal.RestoreStageCommitted, journal.RestoreStageStarting, journal.RestoreStageStarted:
		return restoreActionCommitted
	default:
		if kind == ops.KindRestoreCommit {
			return restoreActionUnrecorded
		}
		return actionData
	}
}
