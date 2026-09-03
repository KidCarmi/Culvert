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
//   against the in-memory authoritative snapshot → finalize history →
//   audit + config version.
//
// Classification uses the active revision plus ProfileSpecDigest only
// (never the compiled artifact, never a file mtime):
//   (Expected+1, Candidate)      committed  → finalize idempotently
//   (Expected,   ExpectedSpec)   aborted    → nothing happened
//   anything else                ambiguous  → refuse until an admin repair
// A finalization failure after a proven commit is reported as
// published:true / historyState:pending_reconciliation — never as "not
// published". Pending intents are reconciled at startup, on every lifecycle
// GET and before every publish/rollback. Every decided operation is kept
// (bounded) with the exact response it produced, so a repeated operationId is
// at-most-once and answers with the recorded result.

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
	Action        string      `json:"action"` // save_draft | publish | rollback | repair
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
}

func pacLifecycleGet(w http.ResponseWriter, id string) {
	pacProfilesAPIMu.Lock()
	lc, _ := pacLifecycle.Get(id)
	if lc.PendingOp != nil {
		pacReconcileLocked(lc)
		lc, _ = pacLifecycle.Get(id)
	}
	cfg := pacProfiles.Get()
	active, activeOK := pacProfiles.ProfileByID(id)
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
		"pendingOp":        lc.PendingOp,
		"ambiguous":        lc.Ambiguous,
		"operations":       ops,
		"activeSpecDigest": activeSpecDigest,
		"poolChangedSince": poolChanged,
		"scope":            "node-local",
	}
	if prev, hasPrev := lc.PreviousRevision(); hasPrev {
		resp["previousRevision"] = prev.N
	}
	jsonOK(w, resp)
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
	case "publish", "rollback", "repair":
		if _, err := uuid.Parse(req.OperationID); err != nil {
			http.Error(w, "operationId must be a UUID (required for publish, rollback and repair)", http.StatusBadRequest)
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
		if !pacReconcileLocked(lc) {
			writePACFenceRefusal(w, http.StatusConflict, "operation_pending",
				"a previous operation is still pending reconciliation and its record could not be persisted; retry",
				map[string]any{"operationId": lc.PendingOp.OperationID})
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
	before := pacProfiles.Get()
	cfg := pacCandidateConfig(id, candidate, active.Revision+1)
	if issues := pac.ValidateProfilesConfig(cfg); len(issues) > 0 {
		writePACIssues(w, "validation failed", issues)
		return
	}
	// Durable INTENT (node-local) before the authoritative mutation.
	now := time.Now().UTC().Format(time.RFC3339)
	op := pac.PendingOp{
		OperationID: req.OperationID, Action: req.Action, ProfileID: id,
		ExpectedActiveRevision: active.Revision, ExpectedActiveSpecDigest: expectedSpec,
		CandidateSpecDigest: binding.CandidateSpecDigest, CandidateSpec: candidate,
		PoolDigest: binding.PoolDigest, ArtifactDigest: chk.Digest,
		ChallengePoolDigest: binding.PoolDigest, ChallengeArtifactDigest: chk.Digest, Challenge: challengeToken,
		TargetN: req.TargetN, Actor: sessionAdmin(r), Reason: reason, TS: now, State: pac.OpPending,
	}
	if !pacPersistIntent(w, lc, &op) {
		return
	}
	pacLifecycleStage("intent_persisted")

	// The authoritative commit, classified against the in-memory snapshot.
	setErr := pacProfiles.Set(cfg)
	observed, observedOK := pacProfiles.ProfileByID(id)
	class := pac.ClassifyOutcome(&op, observed, observedOK)
	if setErr == nil && class != pac.OpCommitted {
		class = pac.OpAmbiguous // "success" that the authoritative snapshot does not show is unknown, never a success
	}
	switch class {
	case pac.OpAborted:
		pacWriteAborted(w, id, lc, &op, setErr, now)
		return
	case pac.OpAmbiguous:
		pacWriteOutcomeUnknown(w, id, req.Action, &op, setErr)
		return
	}
	pacLifecycleStage("active_committed")
	pacAfterActiveCommit(r, "pac.profile_"+req.Action, id, before, cfg)
	pacFinalizeCommitted(w, id, lc, &op, observed, chk.Digest, now)
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

// pacFinalizeCommitted records the proven commit in history and answers. A
// finalization failure is reported as published:true /
// pending_reconciliation — the active profile IS committed.
func pacFinalizeCommitted(w http.ResponseWriter, id string, lc *pac.ProfileLifecycle, op *pac.PendingOp, observed pac.Profile, artifactDigest, now string) {
	n := lc.FinalizeCommitted(op)
	result := pacOperationResult(op, n, observed, lc.DraftRevision, "recorded")
	raw, _ := json.Marshal(result) //nolint:errcheck // plain map
	lc.PendingOp = nil
	lc.RecordDecided(pac.DecidedOp{OperationID: op.OperationID, Action: op.Action, State: pac.OpRecorded, TS: now, Status: http.StatusOK, Result: raw, Challenge: op.Challenge})
	err := pacLifecyclePersist("finalize")
	if err == nil {
		err = pacLifecycle.Put(lc)
	}
	if err != nil {
		logger.Printf("PAC: %s of %q committed but history finalization failed: %v", sanitizeLog(op.Action), sanitizeLog(id), err)
		result["historyState"] = "pending_reconciliation"
		jsonOK(w, result)
		return
	}
	pacLifecycleStage("finalized")
	if op.Action == "publish" {
		pacPublishesTotal.Add(1)
		logger.Printf("PAC: published profile %q revision %d (digest %s)", sanitizeLog(id), n, artifactDigest)
	} else {
		pacRollbacksTotal.Add(1)
		logger.Printf("PAC: rolled back profile %q to revision %s (new revision %d)", sanitizeLog(id), sanitizeLog(fmt.Sprintf("%d", op.TargetN)), n)
	}
	jsonOK(w, result)
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

// pacReconcileLocked settles a pending intent against the authoritative
// active state (under pacProfilesAPIMu). It returns false when the settled
// record could not be persisted (memory is then unchanged too).
func pacReconcileLocked(lc *pac.ProfileLifecycle) bool {
	op := lc.PendingOp
	if op == nil {
		return true
	}
	active, ok := pacProfiles.ProfileByID(op.ProfileID)
	now := time.Now().UTC().Format(time.RFC3339)
	switch pac.ClassifyOutcome(op, active, ok) {
	case pac.OpCommitted:
		n := lc.FinalizeCommitted(op)
		raw, _ := json.Marshal(pacOperationResult(op, n, active, lc.DraftRevision, "recorded")) //nolint:errcheck // plain map
		lc.PendingOp = nil
		lc.RecordDecided(pac.DecidedOp{OperationID: op.OperationID, Action: op.Action, State: pac.OpRecorded, TS: now, Status: http.StatusOK, Result: raw, Challenge: op.Challenge})
		logger.Printf("PAC: reconciled %s %s of %q as COMMITTED (revision %d)", sanitizeLog(op.Action), sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), n)
	case pac.OpAborted:
		raw, _ := json.Marshal(map[string]any{"error": "the operation never reached the active store", "code": "aborted", "operationId": op.OperationID}) //nolint:errcheck // plain map
		lc.PendingOp = nil
		lc.RecordDecided(pac.DecidedOp{OperationID: op.OperationID, Action: op.Action, State: pac.OpAborted, TS: now, Status: http.StatusInternalServerError, Result: raw})
		logger.Printf("PAC: reconciled %s %s of %q as ABORTED", sanitizeLog(op.Action), sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID))
	default:
		digest := ""
		if ok {
			digest = pac.ProfileSpecDigest(active)
		}
		lc.Ambiguous = &pac.AmbiguousOp{Op: *op, ObservedRevision: active.Revision, ObservedSpecDigest: digest, ObservedAt: now}
		lc.PendingOp = nil
		logger.Printf("PAC: reconciled %s %s of %q as AMBIGUOUS (observed revision %d); publish/rollback refused until repair", sanitizeLog(op.Action), sanitizeLog(op.OperationID), sanitizeLog(op.ProfileID), active.Revision)
	}
	if err := pacLifecycle.Put(lc); err != nil {
		logger.Printf("PAC: reconciliation record for %q could not be persisted: %v", sanitizeLog(op.ProfileID), err)
		return false
	}
	return true
}

// pacReconcileAllLifecycles settles every pending intent at startup (after
// the profile and lifecycle stores are loaded).
func pacReconcileAllLifecycles() {
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	for _, lc := range pacLifecycle.All() {
		if lc.PendingOp != nil {
			pacReconcileLocked(lc)
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
		"activeSpecDigest": pac.ProfileSpecDigest(active), "historyState": "recorded", "scope": "node-local-history"}
	raw, _ := json.Marshal(result) //nolint:errcheck // plain map
	lc.RecordDecided(pac.DecidedOp{OperationID: req.OperationID, Action: "repair", State: pac.OpRecorded, TS: now, Status: http.StatusOK, Result: raw})
	if err := pacLifecycle.Put(lc); err != nil {
		http.Error(w, "repair record could not be persisted: "+err.Error(), http.StatusInternalServerError)
		return
	}
	auditEvent(r, "pac.profile_repair", id, fmt.Sprintf("resolution=accept_active revision=%d activeRevision=%d", n, active.Revision))
	jsonOK(w, result)
}

// pacLifecycleFence applies the 2F-A precondition to publish and rollback.
func pacLifecycleFence(w http.ResponseWriter, active pac.Profile, hasActive bool, expectedActive int64, collectionEtag string) bool {
	if hasActive {
		return pacCheckRevision(w, "revision", expectedActive, active.Revision)
	}
	return pacCheckEtag(w, "collectionEtag", collectionEtag, pac.ConfigETag(pacProfiles.Get()))
}
