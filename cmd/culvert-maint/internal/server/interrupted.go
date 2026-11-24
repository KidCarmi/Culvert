// Reporting for operations a previous agent process left unfinished.
//
// A journal record with no process behind it is the durable evidence that an
// image change — or a restore (interrupted_restore.go) — was cut short. This
// file turns one into what an operator needs in order to act: how far the operation got, whether Docker may have been
// changed, which image a rollback would name, and what the agent itself did
// about it — which, with the default reconcile_on_startup = "off", is nothing.
// Acting on a record at boot is the separate, opt-in "converge" reconcile
// (startup_reconcile.go, contract AGT-900, ADR-0061).
//
// The journal is a file on disk, so every string in a record is unchecked
// content. Nothing is copied to an API response as found: the kind and mode
// are matched against the closed sets, image ids against their exact shape,
// and the image references are released only after validateReconcileRefs —
// the same gate the reconciler would have to pass before handing them to
// docker — has accepted them.
package server

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// Docker-state classes of an interrupted operation. They say what the JOURNAL
// establishes about Docker, not what Docker says now (see RunningImage and
// Status.PinnedTag for that).
const (
	// DockerStateUnchanged: the operation stopped before the write-ahead
	// barrier, so it had not moved the fixed tag or recreated the container.
	DockerStateUnchanged = "unchanged"
	// DockerStateIndeterminate: the operation had durably recorded its intent
	// to move the fixed tag, or is of a kind that records no progress. The tag
	// may be ahead of the running container, or the container may be running
	// an image that never passed the health gate.
	DockerStateIndeterminate = "indeterminate"
	// DockerStateDataIndeterminate: a restore-class operation (a data rollback
	// or restore.commit). Docker IMAGES are not involved: the operation moves
	// no tag. This class says only that, on the image axis docker_state is
	// about; what is known about the stack and the data directory is in
	// restore_stage, stack_touched, data_changed and previous_state.
	//
	// restore.commit reuses this class instead of getting a sibling. The value
	// already tells a consumer "not an image problem; look at the data", which
	// is exactly as true of a restore as of a data rollback (they run the same
	// stages), and a new class would be one an existing consumer does not know
	// and would have to treat as the image-style default. It is not replaced by
	// "unchanged" for a restore that stopped before touching anything either:
	// that would change what a data-rollback record has always reported, and
	// data_changed = "no" says it without ambiguity.
	DockerStateDataIndeterminate = "data_indeterminate"
)

// data_changed values of a restore-class report: what the journal establishes
// about the data directory.
const (
	// DataChangedNo: the operation stopped before its commit command was started.
	DataChangedNo = "no"
	// DataChangedYes: the commit command returned success.
	DataChangedYes = "yes"
	// DataChangedUnknown: the commit command was started and either its result
	// was never recorded, or it returned an error (see restoreFactsFor), or the
	// record does not say how far the restore got.
	DataChangedUnknown = "unknown"
)

// previous_state values: where the content the data directory held BEFORE the
// restore is now.
const (
	// PreviousInPlace: still the live content; the restore did not touch it.
	PreviousInPlace = "in_place"
	// PreviousKeptInBackupDir: the restore committed and kept it beside the new
	// content (<data>/.restore/<name>.bak.<ts>-<pid> on the shipped topology, a
	// <data>.bak.<ts>-<pid> sibling otherwise) until an operator cleans it up.
	PreviousKeptInBackupDir = "kept_in_backup_dir"
	// PreviousRecoverable: the swap may be unfinished. On the shipped topology
	// the next start of the proxy puts the previous content back before it
	// reads the directory, or refuses to start; otherwise it is manual.
	PreviousRecoverable = "recoverable_at_next_proxy_start_or_manual"
	// PreviousUnknown: the record does not say how far the restore got.
	PreviousUnknown = "unknown"
)

// RestoreStageUnrecorded is the restore_stage reported for a restore-class
// record that carries no stage this build knows: one written by an agent that
// predates the key (every data-rollback record before it), one an older agent
// rewrote at a start (which drops the key), or one from a newer agent.
const RestoreStageUnrecorded = "unrecorded"

// Running-image classes: how the running proxy image relates to the record.
const (
	RunningIsTarget    = "target"    // the image the operation was moving to
	RunningIsPrior     = "prior"     // the image that was running before it
	RunningIsOther     = "other"     // neither
	RunningIsAmbiguous = "ambiguous" // the record's own identifiers conflict
	RunningIsUnknown   = "unknown"   // Docker could not be read, or the record names no image
)

// AuditActorStartup is the audit actor for entries the agent writes on its own
// behalf at startup when the record names none.
const AuditActorStartup = "agent:startup"

// InterruptedOperation is the operator-facing report of one journal record
// left by a previous agent process.
type InterruptedOperation struct {
	OpID  string `json:"op_id"`
	Kind  string `json:"kind"`
	Mode  string `json:"mode,omitempty"`
	Actor string `json:"actor,omitempty"`

	// JournalPhase is the last phase the operation recorded before it stopped.
	JournalPhase string `json:"journal_phase"`
	// DockerState is one of the DockerState* classes.
	DockerState string `json:"docker_state"`

	StartedAt      time.Time  `json:"started_at"`
	LastProgressAt time.Time  `json:"last_progress_at"`
	InterruptedAt  *time.Time `json:"interrupted_at,omitempty"`
	// AgentStartsSeen counts the agent starts that found this record.
	AgentStartsSeen int `json:"agent_starts_seen"`
	// DiedInCommand is the docker command ("compose up", "compose down") of
	// this operation that the agent process died inside, as found by the
	// agent process that is answering (set by GET /v1/status from that
	// process's memory, never from the record). Absent when the last command
	// had returned, when no command had been begun, and once the agent has
	// restarted: by then the state of the stack can no longer be put down to
	// that command.
	DiedInCommand string `json:"died_in_command,omitempty"`

	// RefsValid reports whether the record's image references passed the
	// repo-bound digest gate. The references and image ids below are present
	// only when it is true.
	RefsValid     bool   `json:"refs_valid"`
	RefsNote      string `json:"refs_note,omitempty"`
	TargetRef     string `json:"target_ref,omitempty"`
	PriorRef      string `json:"prior_ref,omitempty"`
	TargetImageID string `json:"target_image_id,omitempty"`
	PriorImageID  string `json:"prior_image_id,omitempty"`

	// RunningImage is one of the RunningIs* classes. Set by GET /v1/status
	// from a live read; empty in the operation result written at startup,
	// which does not consult Docker.
	RunningImage string `json:"running_image,omitempty"`

	// DockerReconciled is false unless the opt-in startup reconcile verified,
	// by image id, that it converged Docker for this record (see SetReconcile);
	// with the default reconcile_on_startup = "off" it is always false. It is
	// stated rather than implied so a consumer cannot read "failed" as
	// "rolled back".
	DockerReconciled bool   `json:"docker_reconciled"`
	OperatorAction   string `json:"operator_action"`

	// ReconcileOutcome is the opt-in startup reconcile's outcome for this
	// record (reconcile_on_startup = "converge" only; absent otherwise). A
	// record the reconcile converged is retired and no longer listed, so a
	// listed one carries recovery_required, deferred, abandoned or
	// converged_not_retired.
	ReconcileOutcome string `json:"reconcile_outcome,omitempty"`

	// The fields below are set only for a restore-class operation
	// (restore.commit, rollbacks.create mode=data) and are absent from every
	// other report. They are derived from the journal record alone.

	// RestoreStage is the last stage the restore recorded before it stopped
	// (journal.RestoreStage), or "unrecorded".
	RestoreStage string `json:"restore_stage,omitempty"`
	// StackTouched: whether this operation asked Docker to stop the stack. Nil
	// (absent) when the record does not say how far the restore got. It is what
	// the operation did, not what Docker says now: see compose_stack_up.
	StackTouched *bool `json:"stack_touched,omitempty"`
	// DataChanged is one of the DataChanged* values.
	DataChanged string `json:"data_changed,omitempty"`
	// PreviousState is one of the Previous* values.
	PreviousState string `json:"previous_state,omitempty"`
	// RestartSafe says what happens if the operator starts the proxy now. It
	// is a sentence, not a flag: the answer depends on the deployment, which
	// the agent cannot see (it has no access to the data volume).
	RestartSafe string `json:"restart_safe,omitempty"`
}

// SetReconcile records the startup reconcile's result for this record.
// DockerReconciled becomes true only when the reconcile verified convergence by
// image id. When the reconcile changed Docker without converging, the default
// advice ("the agent has not changed Docker") would be false, so it is
// replaced.
func (o *InterruptedOperation) SetReconcile(r ReconcileRecord) {
	o.ReconcileOutcome = r.Outcome
	o.DockerReconciled = r.DockerReconciled
	if len(r.Actions) > 0 && !r.DockerReconciled {
		o.OperatorAction = "The startup reconcile ran a Docker command for this operation (" + r.Decision + ") but could not verify " +
			"that Docker converged (" + r.Reason + "). Compare pinned_tag and running_image in GET /v1/status before acting, and do not " +
			"run `docker compose up` by hand: it starts whatever image the fixed tag is on."
	}
}

var (
	reportImageIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reportActorRE   = regexp.MustCompile(`[^A-Za-z0-9._:@=,()\- ]`)
)

const reportActorMaxLen = 128

// DescribeInterrupted builds the report for rec. proxyRepo is the configured
// repository the image references must be bound to.
func DescribeInterrupted(rec *journal.Record, proxyRepo string) InterruptedOperation {
	out := InterruptedOperation{
		OpID:            rec.OpID,
		Kind:            reportKind(rec.Kind),
		Mode:            reportMode(rec.Mode),
		Actor:           reportActor(rec.Actor),
		JournalPhase:    string(rec.Phase),
		StartedAt:       rec.StartedAt,
		LastProgressAt:  rec.UpdatedAt,
		InterruptedAt:   rec.InterruptedAt,
		AgentStartsSeen: rec.InterruptedSeen,
	}

	out.DockerState = dockerStateOf(out.Kind, out.Mode, rec.Phase)
	if isRestoreRecord(out.Kind, out.Mode) {
		out.setRestoreFacts(rec.RestoreStage)
	}

	switch {
	case rec.TargetRef == "" && rec.TargetDigest == "" && rec.PriorRef == "" && rec.PriorDigest == "":
		out.RefsNote = "the operation had not recorded an image reference when it stopped"
	default:
		if ok, _ := validateReconcileRefs(rec, proxyRepo); ok {
			out.RefsValid = true
			out.TargetRef = rec.TargetRef
			out.PriorRef = rec.PriorRef
			out.TargetImageID = reportImageID(rec.TargetImageID)
			out.PriorImageID = reportImageID(rec.PriorImageID)
		} else {
			// The gate's own reason quotes the rejected reference; it is not
			// repeated here.
			out.RefsNote = "the recorded image references failed validation and are withheld; read the journal record on the host"
		}
	}
	out.OperatorAction = operatorActionFor(&out)
	return out
}

// ResultMap renders the report as an operation result
// ({"interrupted": {...}}), JSON-shaped so the ops manager can snapshot it.
func (o *InterruptedOperation) ResultMap() map[string]interface{} {
	raw, err := json.Marshal(o)
	if err != nil {
		return map[string]interface{}{"interrupted": map[string]interface{}{"op_id": o.OpID}}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]interface{}{"interrupted": map[string]interface{}{"op_id": o.OpID}}
	}
	return map[string]interface{}{"interrupted": m}
}

// AuditParams is the subset recorded in the audit log: identifiers and
// classes only.
func (o *InterruptedOperation) AuditParams() map[string]interface{} {
	p := map[string]interface{}{
		"journal_phase":     o.JournalPhase,
		"docker_state":      o.DockerState,
		"docker_reconciled": false,
		"refs_valid":        o.RefsValid,
		"started_at":        o.StartedAt.UTC().Format(time.RFC3339),
	}
	if o.Mode != "" {
		p["mode"] = o.Mode
	}
	if o.RestoreStage != "" {
		p["restore_stage"] = o.RestoreStage
		p["data_changed"] = o.DataChanged
		p["previous_state"] = o.PreviousState
		if o.StackTouched != nil {
			p["stack_touched"] = *o.StackTouched
		}
	}
	if o.TargetRef != "" {
		p["target_ref"] = o.TargetRef
	}
	if o.PriorRef != "" {
		p["prior_ref"] = o.PriorRef
	}
	return p
}

// ClassifyRunning relates the running proxy image to rec. runningImageID is
// the container's image id and runningRepoDigests its repo@sha256 references,
// both as a successful live capture reported them; pass captured=false when
// there was none. The comparison is the reconcile core's sameImage, so the
// report and a future reconciler cannot disagree about what "target" means.
func ClassifyRunning(rec *journal.Record, proxyRepo string, captured bool, runningImageID string, runningRepoDigests []string) string {
	if !captured {
		return RunningIsUnknown
	}
	if ok, _ := validateReconcileRefs(rec, proxyRepo); !ok {
		return RunningIsUnknown
	}
	running := bareDigests(runningRepoDigests)
	var target, prior []string
	if rec.TargetDigest != "" {
		target = []string{rec.TargetDigest}
	}
	if rec.PriorDigest != "" {
		prior = []string{rec.PriorDigest}
	}
	isTarget := sameImage(runningImageID, reportImageID(rec.TargetImageID), running, target)
	isPrior := sameImage(runningImageID, reportImageID(rec.PriorImageID), running, prior)
	switch {
	case isTarget && isPrior:
		// One image under both names is a re-apply of what was running. Two
		// different digests that both match means the record's ids conflict
		// (the target id is captured before the image is verified).
		if rec.TargetDigest == rec.PriorDigest {
			return RunningIsTarget
		}
		return RunningIsAmbiguous
	case isTarget:
		return RunningIsTarget
	case isPrior:
		return RunningIsPrior
	default:
		return RunningIsOther
	}
}

func dockerStateOf(kind, mode string, phase journal.Phase) string {
	switch {
	case isRestoreRecord(kind, mode):
		return DockerStateDataIndeterminate
	case kind == ops.KindUpgradeApply && safeBoundary(phase):
		return DockerStateUnchanged
	default:
		// An upgrade at or past the barrier; an image rollback, which records
		// no phase beyond admission although it moves the tag; or a kind this
		// build does not know.
		return DockerStateIndeterminate
	}
}

// SetRunningImage records the live running-image class and re-derives the
// operator action, which depends on it: with the target already running, the
// advice that fits a proxy still on the previous image would be wrong.
func (o *InterruptedOperation) SetRunningImage(class string) {
	o.RunningImage = class
	o.OperatorAction = operatorActionFor(o)
}

const (
	actionNoChange = "The operation stopped before it changed Docker. Submit it again if it is still wanted."
	actionData     = "A data rollback was interrupted. The agent does not repair the data directory. " +
		"If the proxy does not start, follow \"Recovering from an interrupted restore\" in docs/operator/docker-compose-backup-restore.md before submitting another operation."
	actionTail = " The agent has not changed Docker, and this entry stays until a later upgrade or image rollback succeeds. " +
		"Until then do not run `docker compose up` by hand: it starts whatever image the fixed tag is on."
	actionRollbackKnown   = "POST /v1/rollbacks with mode=image and image_ref=prior_ref (re-pins the previous image and health-gates it)"
	actionRollbackUnknown = "POST /v1/rollbacks with mode=image and a known-good image_ref (the record names no previous image)"
)

func operatorActionFor(o *InterruptedOperation) string {
	switch o.DockerState {
	case DockerStateUnchanged:
		return actionNoChange
	case DockerStateDataIndeterminate:
		return restoreActionFor(o.Kind, o.RestoreStage)
	}
	rollback := actionRollbackUnknown
	if o.PriorRef != "" {
		rollback = actionRollbackKnown
	}
	switch o.RunningImage {
	case RunningIsTarget:
		// An apply of the image that is already running is reported
		// already-current and skips the health gate, so it is not offered as
		// a way to gate this image.
		return "The proxy is running the target image, which the agent never health-gated. Submitting the same upgrade again " +
			"is reported already-current and does not gate it. Check the proxy's health yourself; to go back, " + rollback + "." + actionTail
	case RunningIsPrior:
		return "The proxy is still running the previous image. If pinned_tag.matches_running is false, the fixed tag is ahead of it " +
			"on an image that never passed the health gate. Either submit the upgrade again (re-pins the target and health-gates it) or " +
			rollback + "." + actionTail
	default:
		return "The fixed tag may be on an image that never passed the health gate. Compare pinned_tag and running_image in GET /v1/status, " +
			"then either submit the upgrade again or " + rollback + "." + actionTail
	}
}

func reportKind(kind string) string {
	if ops.IsJournaled(kind) {
		return kind
	}
	return "unknown"
}

func reportMode(mode string) string {
	switch mode {
	case "", "image", "data":
		return mode
	default:
		return "unknown"
	}
}

func reportActor(actor string) string {
	actor = reportActorRE.ReplaceAllString(actor, "_")
	if len(actor) > reportActorMaxLen {
		actor = actor[:reportActorMaxLen]
	}
	return strings.TrimSpace(actor)
}

func reportImageID(id string) string {
	if reportImageIDRE.MatchString(id) {
		return id
	}
	return ""
}
