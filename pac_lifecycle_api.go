package main

// pac_lifecycle_api.go — the 2F-B trustable-publish lifecycle for PAC profiles
// (docs/design/FRONTEND-MIGRATION-PLAN.md, 2F contract C1/C2/C8).
//
// The durable, cluster-synced active profile store (pacProfiles) is the ONLY
// authoritative commit point. A publish or rollback runs as ONE serialized
// decision under pacProfilesAPIMu:
//
//   fence (2F-A) → guard → bound DIRECT challenge → persist INTENT (node-local)
//   → mutate the active store (persist-before-swap) → CLASSIFY the outcome
//   against the in-memory authoritative snapshot → persist COMMITTED →
//   post-commit effects, each behind its own durable marker.
//
// Classification uses the active revision plus ProfileSpecDigest only
// (never the compiled artifact, never a file mtime):
//   (Expected+1, Candidate)      committed  → durable progression below
//   (Expected,   ExpectedSpec)   aborted    → nothing happened
//   anything else                ambiguous  → refuse until an admin repair
//
// Durable progression of a committed operation (2F-B correction, C1):
//   pending → committed → [history] → [config version] → [cluster publish]
//           → success audit → recorded
// Every bracketed effect advances a persisted OpProgress marker AFTER it
// landed, so a crash at any boundary is completed — never duplicated — by
// reconciliation (startup, lifecycle GET, before every operation). The
// config-version effect is keyed by operationId in the version note (the
// version store itself is the dedup record); the success audit names the
// operationId and historyState and is deduplicated against the audit ring.
// Any lifecycle write failure after the proven commit is reported as
// published:true / historyState:pending_reconciliation — never as "not
// published" — and an aborted or ambiguous operation never emits a success
// audit or a config version. Every decided operation is kept (bounded) with
// the exact response it produced, so a repeated operationId is at-most-once
// and answers with the recorded result.
//
// A corrupt lifecycle file is a durable, visible history_reset (see
// pac.HistoryReset): the active store stays the sole authority, affected
// profiles report historyState history_reset, and publish/rollback are
// refused until an admin acknowledges the loss for that profile, bound to
// the active revision + ProfileSpecDigest reviewed.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

// ── Candidate-bound DIRECT confirmation (C2) ──────────────────────────────

// pacChallengeBinding is EVERYTHING a typed DIRECT confirmation authorizes.
// The opaque challenge token is a versioned canonical digest of it; on retry
// the server recomputes the binding from live state under the publish lock
// and refuses with a fresh challenge if any field changed.
type pacChallengeBinding struct {
	ProfileID                string   `json:"profileId"`
	Action                   string   `json:"action"`
	TargetN                  int64    `json:"targetN"`
	CandidateSpecDigest      string   `json:"candidateSpecDigest"`
	ExpectedActiveRevision   int64    `json:"expectedActiveRevision"`
	ExpectedActiveSpecDigest string   `json:"expectedActiveSpecDigest"`
	PoolDigest               string   `json:"poolDigest"`
	ArtifactDigest           string   `json:"artifactDigest"`
	NewDirectPaths           []string `json:"newDirectPaths"`
}

func (b pacChallengeBinding) normalized() pacChallengeBinding {
	paths := append([]string(nil), b.NewDirectPaths...)
	sort.Strings(paths)
	if paths == nil {
		paths = []string{}
	}
	b.NewDirectPaths = paths
	return b
}

// token is the opaque, versioned challenge: no secret is involved because
// the binding is recomputed server-side on every retry — the token only
// proves the client echoed exactly what it reviewed.
func (b pacChallengeBinding) token() string {
	d := pac.CanonicalDigest("pac-direct-challenge/v1", b.normalized())
	return "v1:" + strings.TrimPrefix(d, "sha256:")
}

// confirmValue is the server-selected typed word: the profile id plus the
// first 8 hex characters of the candidate spec digest, so it changes with
// the candidate and a predictable id alone can never authorize.
func (b pacChallengeBinding) confirmValue() string {
	d := strings.TrimPrefix(b.CandidateSpecDigest, "sha256:")
	if len(d) > 8 {
		d = d[:8]
	}
	return b.ProfileID + ":" + d
}

func pacChallengeChanged(old, cur pacChallengeBinding) []string {
	old, cur = old.normalized(), cur.normalized()
	var changed []string
	add := func(name string, differs bool) {
		if differs {
			changed = append(changed, name)
		}
	}
	add("profileId", old.ProfileID != cur.ProfileID)
	add("action", old.Action != cur.Action)
	add("targetN", old.TargetN != cur.TargetN)
	add("candidateSpecDigest", old.CandidateSpecDigest != cur.CandidateSpecDigest)
	add("expectedActiveRevision", old.ExpectedActiveRevision != cur.ExpectedActiveRevision)
	add("expectedActiveSpecDigest", old.ExpectedActiveSpecDigest != cur.ExpectedActiveSpecDigest)
	add("poolDigest", old.PoolDigest != cur.PoolDigest)
	add("artifactDigest", old.ArtifactDigest != cur.ArtifactDigest)
	add("newDirectPaths", strings.Join(old.NewDirectPaths, "\x00") != strings.Join(cur.NewDirectPaths, "\x00"))
	return changed
}

// pacConfirm is the client's echo of a challenge plus the typed value.
type pacConfirm struct {
	Challenge string               `json:"challenge"`
	Value     string               `json:"value"`
	Binding   *pacChallengeBinding `json:"binding"`
}

func writePACChallenge(w http.ResponseWriter, code, msg string, cur pacChallengeBinding, changed []string) {
	cur = cur.normalized()
	body := map[string]any{
		"error":        msg,
		"code":         code,
		"confirmField": "confirm",
		"challenge":    cur.token(),
		"confirmValue": cur.confirmValue(),
		"binding":      cur,
	}
	if len(changed) > 0 {
		body["changed"] = changed
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	json.NewEncoder(w).Encode(body) //nolint:errcheck // best-effort body
}

// pacVerifyConfirm decides whether c authorizes exactly cur. It writes the
// refusal (409 confirm_required / challenge_stale) and returns false
// otherwise. consumed reports a challenge already spent by a committed
// operation (single-use through the decided-operation record).
func pacVerifyConfirm(w http.ResponseWriter, cur pacChallengeBinding, c *pacConfirm, consumed func(string) bool) bool {
	const direct = "this change introduces new DIRECT (full security-path bypass) paths"
	if c == nil || c.Binding == nil || c.Challenge == "" {
		pacPublishConfirmRequiredTotal.Add(1)
		writePACChallenge(w, "confirm_required", direct+"; review the binding and retype confirmValue into confirm.value", cur, nil)
		return false
	}
	echoed := c.Binding.normalized()
	if echoed.token() != c.Challenge {
		pacPublishConfirmRequiredTotal.Add(1)
		writePACChallenge(w, "confirm_required", "the echoed challenge does not match its binding; review the fresh challenge", cur, nil)
		return false
	}
	if consumed != nil && consumed(c.Challenge) {
		writePACChallenge(w, "challenge_stale", "this challenge was already consumed by a committed operation", cur, []string{"challenge"})
		return false
	}
	if changed := pacChallengeChanged(echoed, cur); len(changed) > 0 {
		writePACChallenge(w, "challenge_stale", "the reviewed candidate changed since the challenge was issued: "+strings.Join(changed, ", "), cur, changed)
		return false
	}
	if c.Value != cur.confirmValue() {
		pacPublishConfirmRequiredTotal.Add(1)
		writePACChallenge(w, "confirm_required", "the typed confirmation value does not match confirmValue", cur, nil)
		return false
	}
	return true
}

// ── Lifecycle request / responses ─────────────────────────────────────────

type pacLifecycleRequest struct {
	Action        string      `json:"action"` // save_draft | publish | rollback | repair | acknowledge_history_reset
	OperationID   string      `json:"operationId"`
	Draft         pac.Profile `json:"draft"`
	Confirm       *pacConfirm `json:"confirm"`
	ConfirmDirect string      `json:"confirmDirect"` // RETIRED (2F-A): accepted syntactically, never authorizes
	TargetN       int64       `json:"targetN"`
	Reason        string      `json:"reason"`
	Resolution    string      `json:"resolution"` // repair: accept_active
	// 2F-A fence tokens (pac_fence.go).
	DraftRevision          int64  `json:"draftRevision"`
	ExpectedActiveRevision int64  `json:"expectedActiveRevision"`
	CollectionEtag         string `json:"collectionEtag"`
	// 2F-B correction: acknowledge_history_reset binds to the active
	// ProfileSpecDigest reviewed (with expectedActiveRevision).
	ExpectedActiveSpecDigest string `json:"expectedActiveSpecDigest"`
}

// pacHistoryState is the node-local history's truth about a profile.
func pacHistoryState(id string, lc *pac.ProfileLifecycle, activeOK bool) string {
	switch {
	case pacLifecycle.ResetAffects(id, activeOK):
		return pac.HistoryStateReset
	case lc.Ambiguous != nil:
		return pac.HistoryStateAmbiguous
	case lc.PendingOp != nil:
		return pac.HistoryStatePendingReconciliation
	default:
		return pac.HistoryStateRecorded
	}
}

func pacLifecycleGet(w http.ResponseWriter, id string) {
	pacProfilesAPIMu.Lock()
	lc, _ := pacLifecycle.Get(id)
	if lc.PendingOp != nil {
		pacReconcileLocked(lc, pacEffectsAll)
		lc, _ = pacLifecycle.Get(id)
	}
	cfg := pacProfiles.Get()
	active, activeOK := pacProfiles.ProfileByID(id)
	historyState := pacHistoryState(id, lc, activeOK)
	reset := pacLifecycle.HistoryResetRecord()
	pacProfilesAPIMu.Unlock()

	var diff *pac.ProfileDiff
	if lc.DraftDirty && activeOK {
		d := pac.DiffProfiles(active, true, lc.Draft)
		diff = &d
	}
	pools := map[string]pac.Pool{}
	for i := range cfg.Pools {
		pools[cfg.Pools[i].ID] = cfg.Pools[i]
	}
	poolChanged := false
	if rev, has := lc.ActiveRevision(); has && rev.PoolDigest != "" && activeOK {
		poolChanged = pac.PoolDigest(pac.ReferencedPools(active, pools)) != rev.PoolDigest
	}
	activeSpecDigest := ""
	if activeOK {
		activeSpecDigest = pac.ProfileSpecDigest(active)
	}
	ops := make([]pac.DecidedOp, 0, len(lc.Operations))
	for i := len(lc.Operations) - 1; i >= 0 && len(ops) < 20; i-- {
		o := lc.Operations[i]
		o.Result = nil // the recorded body is replayed by operationId, not listed
		ops = append(ops, o)
	}
	resp := map[string]any{
		"profileId":    id,
		"activeExists": activeOK,
		"active":       active,
		"draft":        lc.Draft,
		"draftDirty":   lc.DraftDirty,
		"activeN":      lc.ActiveN,
		"revisions":    lc.Revisions,
		"draftDiff":    diff,
		// 2F-A tokens.
		"draftRevision":  lc.DraftRevision,
		"activeRevision": active.Revision,
		"collectionEtag": pac.ConfigETag(cfg),
		// 2F-B truth: node-local state machine + identity.
		"state":            lc.State(),
		"historyState":     historyState,
		"pendingOp":        lc.PendingOp,
		"ambiguous":        lc.Ambiguous,
		"operations":       ops,
		"activeSpecDigest": activeSpecDigest,
		"poolChangedSince": poolChanged,
		"scope":            "node-local",
	}
	if reset != nil {
		resp["historyReset"] = pacHistoryResetView(reset, id)
	}
	if prev, hasPrev := lc.PreviousRevision(); hasPrev {
		resp["previousRevision"] = prev.N
	}
	jsonOK(w, resp)
}

// pacHistoryResetView is the store-level reset record as the API shows it
// (the acknowledgement for THIS profile, if any, plus the scope).
func pacHistoryResetView(r *pac.HistoryReset, id string) map[string]any {
	v := map[string]any{
		"at": r.At, "quarantinedTo": r.QuarantinedTo, "cause": r.Cause,
		"scoped": r.Scoped, "activeAtReset": r.ActiveAtReset,
		"acknowledgedProfiles": len(r.Acknowledged),
		"ackAction":            "acknowledge_history_reset",
	}
	if ack, ok := r.Acknowledged[id]; ok {
		v["acknowledged"] = ack
	}
	return v
}

func pacLifecyclePost(w http.ResponseWriter, r *http.Request, id string) {
	var req pacLifecycleRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Reason) > pacMaxReasonLen {
		req.Reason = req.Reason[:pacMaxReasonLen]
	}
	req.OperationID = pacFenceStr(r, "operationId", req.OperationID)
	req.DraftRevision = pacFenceInt(r, "draftRevision", req.DraftRevision)
	req.ExpectedActiveRevision = pacFenceInt(r, "expectedActiveRevision", req.ExpectedActiveRevision)
	req.CollectionEtag = pacFenceStr(r, "collectionEtag", req.CollectionEtag)
	switch req.Action {
	case "save_draft":
		pacLifecycleSaveDraft(w, r, id, req.Draft, req.DraftRevision)
	case "publish", "rollback", "repair", "acknowledge_history_reset":
		if _, err := uuid.Parse(req.OperationID); err != nil {
			http.Error(w, "operationId must be a UUID (required for publish, rollback, repair and acknowledge_history_reset)", http.StatusBadRequest)
			return
		}
		if req.Action == "acknowledge_history_reset" {
			pacAcknowledgeHistoryReset(w, r, id, &req)
			return
		}
		pacLifecycleOperation(w, r, id, &req)
	default:
		http.Error(w, "unknown or non-mutating action: "+sanitizeLog(req.Action)+" (use /api/pac/analyze for diff/impact)", http.StatusBadRequest)
	}
}

func pacLifecycleSaveDraft(w http.ResponseWriter, r *http.Request, id string, draft pac.Profile, token int64) {
	draft.ID = id
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	lc, found := pacLifecycle.Get(id)
	// 2F-A fence: an existing draft must be echoed by the draftRevision it
	// was loaded at (428 absent, 409 stale); the FIRST save_draft creates the
	// record; a non-zero token for a record that no longer exists is 404.
	switch {
	case found && lc.DraftRevision > 0:
		if !pacCheckRevision(w, "draftRevision", token, lc.DraftRevision) {
			return
		}
	case token != 0:
		http.NotFound(w, r)
		return
	}
	lc.TouchDraft(draft)
	if err := pacLifecycle.Put(lc); err != nil {
		http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	auditEvent(r, "pac.profile_draft", id, fmt.Sprintf("dirty=%t rules=%d", lc.DraftDirty, len(lc.Draft.Rules)))
	jsonOK(w, map[string]any{"draftDirty": lc.DraftDirty, "draft": lc.Draft, "draftRevision": lc.DraftRevision})
}

// pacReplayDecided answers a repeated decided operationId with the recorded
// response (at-most-once).
func pacReplayDecided(w http.ResponseWriter, d pac.DecidedOp) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(d.Status)
	if len(d.Result) > 0 {
		_, _ = w.Write(d.Result)
	}
}

// pacLifecycleOperation runs publish / rollback / repair as one serialized
// decision under pacProfilesAPIMu.
func pacLifecycleOperation(w http.ResponseWriter, r *http.Request, id string, req *pacLifecycleRequest) {
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	lc, _ := pacLifecycle.Get(id)
	if lc.PendingOp != nil {
		if !pacReconcileLocked(lc, pacEffectsAll) {
			writePACFenceRefusal(w, http.StatusConflict, "operation_pending",
				"a previous operation is still pending reconciliation (its record could not be persisted, or a required post-commit effect — config version / cluster publication — could not be completed yet); retry once it can complete",
				map[string]any{"operationId": lc.PendingOp.OperationID, "state": lc.PendingOp.State, "progress": lc.PendingOp.Progress})
			return
		}
		lc, _ = pacLifecycle.Get(id)
	}
	if d, ok := lc.Decided(req.OperationID); ok {
		pacReplayDecided(w, d)
		return
	}
	if req.Action == "repair" {
		pacRepairLocked(w, r, id, lc, req)
		return
	}
	active, hasActive := pacProfiles.ProfileByID(id)
	if pacLifecycle.ResetAffects(id, hasActive) {
		pacWriteHistoryResetRefusal(w, id, active)
		return
	}
	if lc.Ambiguous != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort body
			"error":       "the lifecycle of this profile is AMBIGUOUS: a previous operation's outcome could not be classified from the authoritative active state; an admin repair (resolution accept_active) is required before any publish or rollback",
			"code":        "lifecycle_ambiguous",
			"operationId": lc.Ambiguous.Op.OperationID,
			"observed":    map[string]any{"revision": lc.Ambiguous.ObservedRevision, "specDigest": lc.Ambiguous.ObservedSpecDigest},
			"expected":    map[string]any{"revision": lc.Ambiguous.Op.ExpectedActiveRevision, "specDigest": lc.Ambiguous.Op.ExpectedActiveSpecDigest},
			"candidate":   map[string]any{"revision": lc.Ambiguous.Op.ExpectedActiveRevision + 1, "specDigest": lc.Ambiguous.Op.CandidateSpecDigest},
		})
		return
	}
	pacRunOperationLocked(w, r, id, lc, req)
}

// pacWriteHistoryResetRefusal refuses publish/rollback on a profile whose
// node-local history was reset, naming the acknowledgement binding.
func pacWriteHistoryResetRefusal(w http.ResponseWriter, id string, active pac.Profile) {
	body := map[string]any{
		"error": "the node-local publish history of this profile was found corrupt and quarantined; the ACTIVE profile is untouched and still authoritative, but publish/rollback are refused until an admin acknowledges the lost history (action acknowledge_history_reset bound to the current active revision and activeSpecDigest)",
		"code":  "history_reset", "historyState": pac.HistoryStateReset, "ackAction": "acknowledge_history_reset",
		"current": map[string]any{"revision": active.Revision, "activeSpecDigest": pac.ProfileSpecDigest(active)},
	}
	if r := pacLifecycle.HistoryResetRecord(); r != nil {
		body["historyReset"] = pacHistoryResetView(r, id)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	json.NewEncoder(w).Encode(body) //nolint:errcheck // best-effort body
}

// pacAcknowledgeHistoryReset records the admin's acknowledgement that a
// profile's node-local history was lost. The acknowledgement authorizes
// exactly the active (revision, ProfileSpecDigest) the admin reviewed; it
// never rewrites the active store; a persistence failure leaves the reset
// active and fails the request.
func pacAcknowledgeHistoryReset(w http.ResponseWriter, r *http.Request, id string, req *pacLifecycleRequest) {
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	active, hasActive := pacProfiles.ProfileByID(id)
	reset := pacLifecycle.HistoryResetRecord()
	if reset == nil {
		writePACFenceRefusal(w, http.StatusConflict, "not_history_reset", "no history reset is recorded; nothing to acknowledge", map[string]any{"historyState": pac.HistoryStateRecorded})
		return
	}
	if ack, ok := reset.Acknowledged[id]; ok {
		// Idempotent: the loss was already acknowledged for this profile.
		jsonOK(w, map[string]any{"acknowledged": true, "operationId": ack.OperationID, "historyState": pac.HistoryStateRecorded,
			"activeRevision": ack.ActiveRevision, "activeSpecDigest": ack.ActiveSpecDigest, "replayed": true})
		return
	}
	if !hasActive {
		writePACFenceRefusal(w, http.StatusConflict, "active_absent", "no active profile exists; a history reset only affects active profiles", map[string]any{"historyState": pac.HistoryStateRecorded})
		return
	}
	if !pacLifecycle.ResetAffects(id, hasActive) {
		writePACFenceRefusal(w, http.StatusConflict, "not_history_reset", "this profile is not affected by the recorded history reset", map[string]any{"historyState": pac.HistoryStateRecorded})
		return
	}
	digest := pac.ProfileSpecDigest(active)
	if req.ExpectedActiveRevision != active.Revision || req.ExpectedActiveSpecDigest != digest {
		var changed []string
		if req.ExpectedActiveRevision != active.Revision {
			changed = append(changed, "expectedActiveRevision")
		}
		if req.ExpectedActiveSpecDigest != digest {
			changed = append(changed, "expectedActiveSpecDigest")
		}
		writePACFenceRefusal(w, http.StatusConflict, "history_reset_stale",
			"the acknowledgement is bound to a different active profile than the one currently active; review the current revision and activeSpecDigest and acknowledge again",
			map[string]any{"current": map[string]any{"revision": active.Revision, "activeSpecDigest": digest}, "changed": changed})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ack := pac.HistoryResetAck{OperationID: req.OperationID, By: sessionAdmin(r), At: now, ActiveRevision: active.Revision, ActiveSpecDigest: digest}
	err := pacLifecyclePersist("ack")
	if err == nil {
		err = pacLifecycle.AcknowledgeReset(id, ack)
	}
	if err != nil {
		logger.Printf("PAC: history-reset acknowledgement for %q could not be persisted: %v", sanitizeLog(id), err)
		http.Error(w, "the acknowledgement could not be persisted; the history reset stays in effect: "+err.Error(), http.StatusInternalServerError)
		return
	}
	auditEvent(r, "pac.profile_history_reset_ack", id,
		fmt.Sprintf("operationId=%s activeRevision=%d activeSpecDigest=%s quarantinedTo=%s", req.OperationID, active.Revision, digest, strings.ReplaceAll(reset.QuarantinedTo, "\n", "")))
	jsonOK(w, map[string]any{"acknowledged": true, "operationId": req.OperationID, "historyState": pac.HistoryStateRecorded,
		"activeRevision": active.Revision, "activeSpecDigest": digest})
}

// pacRunOperationLocked is the shared publish/rollback core (see the file
// header for the sequence).
func pacRunOperationLocked(w http.ResponseWriter, r *http.Request, id string, lc *pac.ProfileLifecycle, req *pacLifecycleRequest) {
	active, hasActive := pacProfiles.ProfileByID(id)
	// 2F-A fence: echo the active profile's revision (or, for a first
	// publish, the collection token).
	if !pacLifecycleFence(w, active, hasActive, req.ExpectedActiveRevision, req.CollectionEtag) {
		return
	}
	pools := pacProfiles.PoolMap()
	candidate, reason, ok := pacResolveCandidate(w, id, lc, req)
	if !ok {
		return
	}
	chk := pac.EvaluatePublish(candidate, pools, active, hasActive)
	if !chk.OK && !chk.RequiresConfirmation {
		pacPublishBlockedTotal.Add(1)
		logger.Printf("PAC: %s blocked by guardrails for %q", sanitizeLog(req.Action), sanitizeLog(id))
		writePACIssues(w, req.Action+" blocked by guardrails", chk.Issues)
		return
	}
	// Identity (C8) + candidate-bound confirmation (C2).
	expectedSpec := ""
	if hasActive {
		expectedSpec = pac.ProfileSpecDigest(active)
	}
	binding := pacChallengeBinding{
		ProfileID: id, Action: req.Action, TargetN: req.TargetN,
		CandidateSpecDigest: pac.ProfileSpecDigest(candidate), ExpectedActiveRevision: active.Revision,
		ExpectedActiveSpecDigest: expectedSpec, PoolDigest: pac.PoolDigest(pac.ReferencedPools(candidate, pools)),
		ArtifactDigest: chk.Digest, NewDirectPaths: chk.NewDirectPaths,
	}
	challengeToken := ""
	if chk.RequiresConfirmation {
		if !pacVerifyConfirm(w, binding, req.Confirm, lc.ChallengeCommitted) {
			return
		}
		challengeToken = req.Confirm.Challenge
	}
	// Candidate config, validated BEFORE any durable step.
	cfg := pacCandidateConfig(id, candidate, active.Revision+1)
	if issues := pac.ValidateProfilesConfig(cfg); len(issues) > 0 {
		writePACIssues(w, "validation failed", issues)
		return
	}
	// Durable INTENT (node-local) before the authoritative mutation.
	op := pac.PendingOp{
		OperationID: req.OperationID, Action: req.Action, ProfileID: id,
		ExpectedActiveRevision: active.Revision, ExpectedActiveSpecDigest: expectedSpec,
		CandidateSpecDigest: binding.CandidateSpecDigest, CandidateSpec: candidate,
		PoolDigest: binding.PoolDigest, ArtifactDigest: chk.Digest,
		ChallengePoolDigest: binding.PoolDigest, ChallengeArtifactDigest: chk.Digest, Challenge: challengeToken,
		TargetN: req.TargetN, Actor: sessionAdmin(r), AuditActor: auditActor(r), Reason: reason,
		TS: time.Now().UTC().Format(time.RFC3339), State: pac.OpPending,
	}
	pacCommitOperationLocked(w, r, id, lc, &op, cfg)
}

// pacCommitOperationLocked is the durable half of a publish/rollback: intent
// → authoritative commit → classification → durable committed → post-commit
// effects (see the file header).
func pacCommitOperationLocked(w http.ResponseWriter, r *http.Request, id string, lc *pac.ProfileLifecycle, op *pac.PendingOp, cfg pac.ProfilesConfig) {
	if !pacPersistIntent(w, lc, op) {
		return
	}
	pacLifecycleStage("intent_persisted")

	// The authoritative commit, classified against the in-memory snapshot.
	setErr := pacProfiles.Set(cfg)
	observed, observedOK := pacProfiles.ProfileByID(id)
	class := pac.ClassifyOutcome(op, observed, observedOK)
	if setErr == nil && class != pac.OpCommitted {
		class = pac.OpAmbiguous // "success" that the authoritative snapshot does not show is unknown, never a success
	}
	switch class {
	case pac.OpAborted:
		pacWriteAborted(w, id, lc, op, setErr, op.TS)
		return
	case pac.OpAmbiguous:
		pacWriteOutcomeUnknown(w, id, op.Action, op, setErr)
		return
	}
	pacLifecycleStage("active_committed")
	// Durable COMMITTED, then the post-commit effects behind their markers.
	if !pacPersistCommittedLocked(lc, op, observed.Revision) {
		pacWritePendingReconciliation(w, id, op, observed, lc.DraftRevision)
		return
	}
	pacLifecycleStage("committed_persisted")
	markAuditEmitted(r) // C2c: the success audit is emitted (now or by reconciliation) for a proven commit
	state, n := pacCompleteCommittedLocked(lc, op, pacEffectsAll, false)
	if state != pac.HistoryStateRecorded {
		pacWritePendingReconciliation(w, id, op, observed, lc.DraftRevision)
		return
	}
	if op.Action == "publish" {
		pacPublishesTotal.Add(1)
		logger.Printf("PAC: published profile %q revision %d (digest %s)", sanitizeLog(id), n, op.ArtifactDigest)
	} else {
		pacRollbacksTotal.Add(1)
		logger.Printf("PAC: rolled back profile %q to revision %s (new revision %d)", sanitizeLog(id), sanitizeLog(fmt.Sprintf("%d", op.TargetN)), n)
	}
	jsonOK(w, pacOperationResult(op, n, observed, lc.DraftRevision, pac.HistoryStateRecorded))
}

// pacWritePendingReconciliation answers a PROVEN commit whose node-local
// effects could not all be made durable: published:true, never a failure.
func pacWritePendingReconciliation(w http.ResponseWriter, id string, op *pac.PendingOp, observed pac.Profile, draftRevision int64) {
	logger.Printf("PAC: %s of %q committed but its history/effects are pending reconciliation", sanitizeLog(op.Action), sanitizeLog(id))
	jsonOK(w, pacOperationResult(op, op.HistoryN, observed, draftRevision, pac.HistoryStatePendingReconciliation))
}

// pacResolveCandidate returns the spec a publish/rollback commits.
func pacResolveCandidate(w http.ResponseWriter, id string, lc *pac.ProfileLifecycle, req *pacLifecycleRequest) (candidate pac.Profile, reason string, ok bool) {
	if req.Action == "publish" {
		candidate = req.Draft
		candidate.ID = id
		return candidate, req.Reason, true
	}
	if lc.ActiveN == 0 && len(lc.Revisions) == 0 {
		http.Error(w, "no publish history for profile: "+sanitizeLog(id), http.StatusNotFound)
		return candidate, "", false
	}
	target, found := lc.RevisionByN(req.TargetN)
	if !found {
		http.Error(w, fmt.Sprintf("revision %d not found for profile %s", req.TargetN, sanitizeLog(id)), http.StatusNotFound)
		return candidate, "", false
	}
	candidate = target.Spec
	candidate.ID = id
	return candidate, "rollback to revision " + fmt.Sprintf("%d", req.TargetN), true
}

// pacCandidateConfig is the whole-config candidate with the profile replaced
// (or appended) at the given active revision.
func pacCandidateConfig(id string, candidate pac.Profile, revision int64) pac.ProfilesConfig {
	published := candidate
	published.Revision = revision
	cfg := pacProfiles.Get()
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID == id {
			cfg.Profiles[i] = published
			return cfg
		}
	}
	cfg.Profiles = append(cfg.Profiles, published)
	return cfg
}

// pacPersistIntent durably records the intent; on failure nothing has
// changed and the caller answers 500.
func pacPersistIntent(w http.ResponseWriter, lc *pac.ProfileLifecycle, op *pac.PendingOp) bool {
	lc.PendingOp = op
	err := pacLifecyclePersist("intent")
	if err == nil {
		err = pacLifecycle.Put(lc)
	}
	if err != nil {
		lc.PendingOp = nil
		http.Error(w, "operation intent could not be persisted; nothing was changed: "+err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

func pacWriteAborted(w http.ResponseWriter, id string, lc *pac.ProfileLifecycle, op *pac.PendingOp, setErr error, now string) {
	result := map[string]any{"error": "active profile write failed; nothing was changed", "code": "active_write_failed", "operationId": op.OperationID}
	if setErr != nil {
		result["error"] = "active profile write failed; nothing was changed: " + setErr.Error()
	}
	raw, _ := json.Marshal(result) //nolint:errcheck // plain map
	lc.PendingOp = nil
	lc.RecordDecided(pac.DecidedOp{OperationID: op.OperationID, Action: op.Action, State: pac.OpAborted, TS: now, Status: http.StatusInternalServerError, Result: raw})
	if err := pacLifecycle.Put(lc); err != nil {
		logger.Printf("PAC: abort record persist failed for %q: %v", sanitizeLog(id), err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(raw)
}

func pacWriteOutcomeUnknown(w http.ResponseWriter, id, action string, op *pac.PendingOp, setErr error) {
	logger.Printf("PAC: %s outcome for %q could not be proven (setErr=%v); intent retained as pending", sanitizeLog(action), sanitizeLog(id), setErr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort body
		"error": "the outcome of the active write could not be proven; the operation is retained as pending and will be reconciled",
		"code":  "outcome_unknown", "operationId": op.OperationID, "state": pac.OpPending,
	})
}

// pacOperationResult is the response of a committed publish/rollback.
func pacOperationResult(op *pac.PendingOp, n int64, active pac.Profile, draftRevision int64, historyState string) map[string]any {
	res := map[string]any{
		"operationId":      op.OperationID,
		"activeRevision":   active.Revision,
		"activeSpecDigest": pac.ProfileSpecDigest(active),
		"digest":           op.ArtifactDigest,
		"draftRevision":    draftRevision,
		"historyState":     historyState,
		"scope":            "node-local-history",
	}
	if op.Action == "rollback" {
		res["rolledBack"] = true
		res["toRevision"] = op.TargetN
		res["newRevision"] = n
	} else {
		res["published"] = true
		res["revision"] = n
	}
	return res
}

// ── Durable committed progression ────────────────────────────────────────

// pacEffectsMode selects which post-commit effects a reconciliation may run.
type pacEffectsMode int

const (
	// pacEffectsNodeLocal runs only the node-local steps (committed marker +
	// history). Used by the startup loader, which runs BEFORE the other
	// config stores are loaded — capturing a config version or publishing a
	// cluster snapshot there would record a partial configuration.
	pacEffectsNodeLocal pacEffectsMode = iota
	// pacEffectsAll runs every effect (request path, lifecycle GET, pre-op
	// reconciliation, and the post-load startup pass).
	pacEffectsAll
)

// pacPersistCommittedLocked advances a proven intent to durable committed.
func pacPersistCommittedLocked(lc *pac.ProfileLifecycle, op *pac.PendingOp, observedRevision int64) bool {
	op.State = pac.OpCommitted
	op.ObservedRevision = observedRevision
	op.CommittedAt = time.Now().UTC().Format(time.RFC3339)
	lc.PendingOp = op
	err := pacLifecyclePersist("committed")
	if err == nil {
		err = pacLifecycle.Put(lc)
	}
	if err != nil {
		logger.Printf("PAC: committed marker for %s of %q could not be persisted: %v", sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), err)
		return false
	}
	return true
}

// pacCompleteCommittedLocked drives a durably COMMITTED intent through its
// post-commit effects, each persisted as a marker AFTER it landed, and
// finally records the operation. It returns the resulting historyState
// (recorded, or pending_reconciliation when a lifecycle write failed — the
// remaining effects are completed by the next reconciliation) and the
// revision number recorded in history (0 when not yet recorded).
func pacCompleteCommittedLocked(lc *pac.ProfileLifecycle, op *pac.PendingOp, mode pacEffectsMode, reconciled bool) (historyState string, revisionN int64) {
	lc.PendingOp = op
	persist := func(stage string) bool {
		err := pacLifecyclePersist(stage)
		if err == nil {
			err = pacLifecycle.Put(lc)
		}
		if err != nil {
			logger.Printf("PAC: %s progress (%s) for %s of %q could not be persisted; pending reconciliation: %v", sanitizeLog(op.Action), stage, sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), err)
			return false
		}
		return true
	}
	// 1. Node-local history (idempotent by operationId).
	if !op.Progress.History {
		op.HistoryN = lc.FinalizeCommitted(op)
		op.Progress.History = true
		if !persist("finalize") {
			return pac.HistoryStatePendingReconciliation, 0
		}
		pacLifecycleStage("history_recorded")
	}
	n := op.HistoryN
	if mode == pacEffectsNodeLocal {
		return pac.HistoryStatePendingReconciliation, n
	}
	// 2. Config version, keyed by operationId (the version store dedups).
	// The marker advances ONLY on proven success; a refused or failed capture
	// leaves the operation pending and is retried by the next reconciliation.
	if !op.Progress.ConfigVersion {
		if err := pacSaveConfigVersionOnce(op.Actor, "pac.profile_"+op.Action, op.OperationID); err != nil {
			logger.Printf("PAC: config version for %s of %q not captured; pending reconciliation: %v", sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), err)
			return pac.HistoryStatePendingReconciliation, n
		}
		op.Progress.ConfigVersion = true
		if !persist("progress") {
			return pac.HistoryStatePendingReconciliation, n
		}
		pacLifecycleStage("version_recorded")
	}
	// 3. Cluster publication (content-idempotent: the active store already
	// carries the committed profile) + the per-profile alert latch. Same
	// rule: a rejected publication keeps the operation pending.
	if !op.Progress.Cluster {
		err := pacEffect("cluster")
		if err == nil {
			err = publishCurrentConfigSnapshot()
		}
		if err != nil {
			logger.Printf("PAC: cluster publication for %s of %q failed; pending reconciliation: %v", sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), err)
			return pac.HistoryStatePendingReconciliation, n
		}
		pacResetProfileAlert(op.ProfileID)
		op.Progress.Cluster = true
		if !persist("progress") {
			return pac.HistoryStatePendingReconciliation, n
		}
		pacLifecycleStage("cluster_published")
	}
	// 4. Success audit (names operationId + truthful historyState), then the
	// terminal record. Both derive from the operation's OWN proven outcome
	// (candidate spec at the observed revision), never from whatever is
	// active at reconciliation time, so a recovered record equals the one
	// the request path would have produced. The audit is deduplicated
	// against the ring so a terminal write that fails and is retried never
	// repeats it.
	committed := op.CandidateSpec
	committed.Revision = op.ObservedRevision
	pacAuditCommitted(op, n, committed, reconciled)
	result := pacOperationResult(op, n, committed, lc.DraftRevision, pac.HistoryStateRecorded)
	raw, _ := json.Marshal(result) //nolint:errcheck // plain map
	lc.PendingOp = nil
	lc.RecordDecided(pac.DecidedOp{OperationID: op.OperationID, Action: op.Action, State: pac.OpRecorded, TS: op.TS, Status: http.StatusOK, Result: raw, Challenge: op.Challenge})
	if !persist("record") {
		lc.PendingOp = op
		return pac.HistoryStatePendingReconciliation, n
	}
	pacLifecycleStage("finalized")
	return pac.HistoryStateRecorded, n
}

// pacSaveConfigVersionOnce captures a config version for the operation
// unless one keyed by its operationId already exists. It reports whether a
// version keyed by the operation now durably exists.
func pacSaveConfigVersionOnce(actor, action, operationID string) error {
	note := "operationId=" + operationID
	for _, m := range configVersions.List() {
		if m.Note == note {
			return nil
		}
	}
	return saveConfigVersionNoteResult(actor, action, note)
}

// pacAuditCommitted emits the success audit for a proven commit exactly once
// per operation (ring-deduplicated by operationId).
func pacAuditCommitted(op *pac.PendingOp, n int64, active pac.Profile, reconciled bool) {
	action := "pac.profile_" + op.Action
	ring := auditGet()
	for i := range ring {
		if ring[i].Action == action && strings.Contains(ring[i].Detail, "operationId="+op.OperationID+" ") {
			return
		}
	}
	detail := fmt.Sprintf("operationId=%s revision=%d activeRevision=%d activeSpecDigest=%s historyState=%s",
		op.OperationID, n, active.Revision, pac.ProfileSpecDigest(active), pac.HistoryStateRecorded)
	if op.Action == "rollback" {
		detail += fmt.Sprintf(" toRevision=%d", op.TargetN)
	}
	if reconciled {
		detail += " reconciled=true"
	}
	if op.Reason != "" {
		detail += " reason=" + strings.ReplaceAll(strings.ReplaceAll(op.Reason, "\n", " "), "\r", " ")
	}
	actor := op.AuditActor
	if actor == "" {
		actor = op.Actor
	}
	now := time.Now()
	entry := AuditEntry{TS: now.UnixMilli(), Time: now.Format("2006-01-02 15:04:05"), Actor: actor, Action: action, Object: op.ProfileID, Detail: detail}
	if after, err := json.Marshal(active); err == nil {
		entry.After = string(after)
	}
	auditAdd(entry)
}

// pacReconcileLocked settles a pending intent against the authoritative
// active state (under pacProfilesAPIMu) and completes a committed one's
// effects (per mode). It returns false when the settled record could not be
// persisted (memory is then unchanged too).
func pacReconcileLocked(lc *pac.ProfileLifecycle, mode pacEffectsMode) bool {
	op := lc.PendingOp
	if op == nil {
		return true
	}
	active, ok := pacProfiles.ProfileByID(op.ProfileID)
	now := time.Now().UTC().Format(time.RFC3339)
	if !op.Committed() {
		switch pac.ClassifyOutcome(op, active, ok) {
		case pac.OpCommitted:
			if !pacPersistCommittedLocked(lc, op, active.Revision) {
				return false
			}
			logger.Printf("PAC: reconciled %s %s of %q as COMMITTED", sanitizeLog(op.Action), sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID))
		case pac.OpAborted:
			raw, _ := json.Marshal(map[string]any{"error": "the operation never reached the active store", "code": "aborted", "operationId": op.OperationID}) //nolint:errcheck // plain map
			lc.PendingOp = nil
			lc.RecordDecided(pac.DecidedOp{OperationID: op.OperationID, Action: op.Action, State: pac.OpAborted, TS: now, Status: http.StatusInternalServerError, Result: raw})
			logger.Printf("PAC: reconciled %s %s of %q as ABORTED", sanitizeLog(op.Action), sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID))
			return pacPutReconciled(lc, op)
		default:
			digest := ""
			if ok {
				digest = pac.ProfileSpecDigest(active)
			}
			lc.Ambiguous = &pac.AmbiguousOp{Op: *op, ObservedRevision: active.Revision, ObservedSpecDigest: digest, ObservedAt: now}
			lc.PendingOp = nil
			logger.Printf("PAC: reconciled %s %s of %q as AMBIGUOUS (observed revision %d); publish/rollback refused until repair", sanitizeLog(op.Action), sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), active.Revision)
			return pacPutReconciled(lc, op)
		}
	}
	state, n := pacCompleteCommittedLocked(lc, op, mode, true)
	if state == pac.HistoryStateRecorded {
		logger.Printf("PAC: reconciled %s %s of %q as RECORDED (revision %d)", sanitizeLog(op.Action), sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), n)
		return true
	}
	return mode == pacEffectsNodeLocal && op.Progress.History
}

func pacPutReconciled(lc *pac.ProfileLifecycle, op *pac.PendingOp) bool {
	if err := pacLifecycle.Put(lc); err != nil {
		logger.Printf("PAC: reconciliation record for %q could not be persisted: %v", sanitizeLog(op.ProfileID), err)
		return false
	}
	return true
}

// pacSettleLifecycleIntents is the startup loader's pass (BEFORE the other
// config stores are loaded): classify every in-flight intent against the
// authoritative active store just loaded and complete the node-local steps
// only. The post-load pass (pacReconcileAllLifecycles) completes the rest.
func pacSettleLifecycleIntents() {
	pacReconcileEvery(pacEffectsNodeLocal)
}

// pacReconcileAllLifecycles completes every pending or committed intent's
// effects. main.go runs it once every config store is loaded (a config
// version captured earlier would record a partial configuration); the
// lifecycle GET and every operation run the same reconciliation per profile.
func pacReconcileAllLifecycles() {
	pacReconcileEvery(pacEffectsAll)
}

func pacReconcileEvery(mode pacEffectsMode) {
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	for _, lc := range pacLifecycle.All() {
		if lc.PendingOp != nil {
			pacReconcileLocked(lc, mode)
		}
	}
}

// pacRepairLocked records the OBSERVED active profile as a repaired revision
// and clears the ambiguity. It never rewrites the active store.
func pacRepairLocked(w http.ResponseWriter, r *http.Request, id string, lc *pac.ProfileLifecycle, req *pacLifecycleRequest) {
	if req.Resolution != "accept_active" {
		http.Error(w, `repair requires resolution "accept_active"`, http.StatusBadRequest)
		return
	}
	if lc.Ambiguous == nil {
		writePACFenceRefusal(w, http.StatusConflict, "not_ambiguous", "the lifecycle is not ambiguous; nothing to repair", map[string]any{"state": lc.State()})
		return
	}
	active, ok := pacProfiles.ProfileByID(id)
	if !ok {
		writePACFenceRefusal(w, http.StatusConflict, "active_absent", "no active profile exists to accept", map[string]any{"state": lc.State()})
		return
	}
	pools := pacProfiles.PoolMap()
	art := pac.CompileProfile(active, pools)
	now := time.Now().UTC().Format(time.RFC3339)
	n := lc.Repair(active, pac.PoolDigest(pac.ReferencedPools(active, pools)), art.Digest, sessionAdmin(r), now, req.OperationID)
	result := map[string]any{"repaired": true, "operationId": req.OperationID, "revision": n, "activeRevision": active.Revision,
		"activeSpecDigest": pac.ProfileSpecDigest(active), "historyState": pac.HistoryStateRecorded, "scope": "node-local-history"}
	raw, _ := json.Marshal(result) //nolint:errcheck // plain map
	lc.RecordDecided(pac.DecidedOp{OperationID: req.OperationID, Action: "repair", State: pac.OpRecorded, TS: now, Status: http.StatusOK, Result: raw})
	if err := pacLifecycle.Put(lc); err != nil {
		http.Error(w, "repair record could not be persisted: "+err.Error(), http.StatusInternalServerError)
		return
	}
	auditEvent(r, "pac.profile_repair", id, fmt.Sprintf("operationId=%s resolution=accept_active revision=%d activeRevision=%d historyState=%s", req.OperationID, n, active.Revision, pac.HistoryStateRecorded))
	jsonOK(w, result)
}

// pacLifecycleFence applies the 2F-A precondition to publish and rollback.
func pacLifecycleFence(w http.ResponseWriter, active pac.Profile, hasActive bool, expectedActive int64, collectionEtag string) bool {
	if hasActive {
		return pacCheckRevision(w, "revision", expectedActive, active.Revision)
	}
	return pacCheckEtag(w, "collectionEtag", collectionEtag, pac.ConfigETag(pacProfiles.Get()))
}
