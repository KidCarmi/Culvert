package pac

// publish.go — the draft/publish revision lifecycle for steering profiles
// (initiative PR 3). A profile has a mutable DRAFT (edited freely) and a
// stack of IMMUTABLE published revisions. Publish validates + compiles the
// draft, snapshots it with an artifact digest, and makes it Active. Rollback
// re-activates the previous immutable revision. The served /pac/{id}.pac
// always reflects the ACTIVE revision.
//
// This is a lightweight lifecycle, not a workflow engine: no approval
// states, no assignees — just Draft → Validate → Publish(Active) →
// Rollback, with an append-only immutable revision history.

import "time"

// PublishedRevision is one immutable published snapshot of a profile.
type PublishedRevision struct {
	// N is the monotonic revision number (1-based, never reused).
	N int64 `json:"n"`
	// Spec is the exact profile content published at revision N (immutable).
	Spec Profile `json:"spec"`
	// Digest is the SHA-256 of the compiled artifact at publish time — the
	// convergence oracle and the "restore exact prior artifact" anchor.
	Digest string `json:"digest"`
	// Author is the admin identity that published this revision.
	Author string `json:"author"`
	// Reason is the operator-supplied change reason.
	Reason string `json:"reason,omitempty"`
	// TS is the publish timestamp (RFC3339); set by the caller (the engine
	// takes no wall clock).
	TS string `json:"ts"`
	// 2F-B identity + provenance (C8/C1): the configuration digest the
	// authoritative commit was classified on, the referenced-pool digest at
	// commit time (poolChangedSince is derived from it), the operation that
	// produced the revision, and whether it was recorded by an admin repair.
	OperationID string `json:"operationId,omitempty"`
	SpecDigest  string `json:"specDigest,omitempty"`
	PoolDigest  string `json:"poolDigest,omitempty"`
	Repaired    bool   `json:"repaired,omitempty"`
}

// ProfileLifecycle carries a profile's draft + immutable published history.
// The persisted pac_profiles.json ProfilesConfig continues to hold the
// ACTIVE profile spec (so serving and cluster sync are unchanged); this
// lifecycle metadata persists alongside it in pac_profiles_lifecycle.json.
type ProfileLifecycle struct {
	// ProfileID ties the lifecycle to its profile.
	ProfileID string `json:"profileId"`
	// Draft is the mutable working copy (edited by PUT). It becomes a
	// published revision on Publish.
	Draft Profile `json:"draft"`
	// DraftDirty reports whether the draft diverges from the active revision.
	DraftDirty bool `json:"draftDirty"`
	// ActiveN is the currently-serving published revision number (0 = none
	// published yet).
	ActiveN int64 `json:"activeN"`
	// Revisions is the append-only immutable history, oldest first.
	Revisions []PublishedRevision `json:"revisions"`
	// DraftRevision is the draft's optimistic-concurrency token (2F-A). It
	// advances by one whenever the draft is replaced (save_draft, publish,
	// rollback); a save_draft must echo the value it loaded, so two admins
	// editing the same draft cannot silently overwrite each other. Records
	// persisted before 2F-A load as 1 (see LifecycleStore.Load).
	DraftRevision int64 `json:"draftRevision"`
	// 2F-B operation model (intent.go): the durable in-flight intent, the
	// unresolved ambiguity (if any) and the bounded decided-operation ring.
	PendingOp  *PendingOp   `json:"pendingOp,omitempty"`
	Ambiguous  *AmbiguousOp `json:"ambiguous,omitempty"`
	Operations []DecidedOp  `json:"operations,omitempty"`
}

// ActiveRevision returns the currently-serving revision and true, or false
// when nothing is published yet.
func (lc *ProfileLifecycle) ActiveRevision() (PublishedRevision, bool) {
	return lc.revisionByN(lc.ActiveN)
}

// PreviousRevision returns the revision published immediately before the
// active one (the rollback target) and true, or false when there is none.
func (lc *ProfileLifecycle) PreviousRevision() (PublishedRevision, bool) {
	for i := range lc.Revisions {
		if lc.Revisions[i].N == lc.ActiveN && i > 0 {
			return lc.Revisions[i-1], true
		}
	}
	return PublishedRevision{}, false
}

func (lc *ProfileLifecycle) revisionByN(n int64) (PublishedRevision, bool) {
	for i := range lc.Revisions {
		if lc.Revisions[i].N == n {
			return lc.Revisions[i], true
		}
	}
	return PublishedRevision{}, false
}

// nextRevisionN returns the next monotonic revision number (max+1), so
// numbers are never reused even after a rollback re-activates an older one.
func (lc *ProfileLifecycle) nextRevisionN() int64 {
	var highest int64
	for i := range lc.Revisions {
		if lc.Revisions[i].N > highest {
			highest = lc.Revisions[i].N
		}
	}
	return highest + 1
}

// maxRevisionsPerProfile bounds the immutable history (mirrors the 50-version
// config-version store) so a long-lived, frequently-published profile cannot
// grow the node-local lifecycle file/memory without bound. Oldest revisions
// are dropped first; nextRevisionN stays monotonic because it maxes over the
// kept set, whose newest entry (the highest N) is always preserved.
const maxRevisionsPerProfile = 50

func (lc *ProfileLifecycle) trimRevisions() {
	if len(lc.Revisions) > maxRevisionsPerProfile {
		// Copy into a fresh slice so the dropped tail's backing array is freed.
		lc.Revisions = append([]PublishedRevision(nil),
			lc.Revisions[len(lc.Revisions)-maxRevisionsPerProfile:]...)
	}
}

// PublishGuardCode identifies why a publish was refused.
type PublishGuardCode = string

// Publish guard codes (stable API strings).
const (
	GuardValidationFailed = "validation_failed"
	GuardNoProxyRoute     = "no_proxy_route"
	GuardSecureDirect     = "secure_mode_direct"
	GuardMissingPool      = "missing_pool"
	GuardCompileFailed    = "compile_failed"
	GuardDigestFailed     = "digest_failed"
	GuardNewDirectPaths   = "new_direct_paths" // requires typed confirmation
)

// PublishCheck is the result of evaluating the publish guardrails against a
// candidate draft. OK reports whether publish may proceed without operator
// confirmation; RequiresConfirmation is set when the only blocker is
// new-DIRECT-path introduction (high-friction confirm, not a hard failure).
type PublishCheck struct {
	OK                   bool              `json:"ok"`
	RequiresConfirmation bool              `json:"requiresConfirmation"`
	Issues               []ValidationIssue `json:"issues,omitempty"`
	// Digest is the compiled artifact digest of the candidate (empty when
	// compilation/validation failed).
	Digest string `json:"digest,omitempty"`
	// NewDirectPaths lists rule descriptions whose publish would newly make
	// DIRECT reachable that the active revision did not (drives the typed
	// confirmation).
	NewDirectPaths []string `json:"newDirectPaths,omitempty"`
}

// EvaluatePublish runs the safe-publish guardrails for draft against the
// active revision (activeSpec; ok=false when nothing is published yet).
// pools is the current pool map. It never mutates anything.
func EvaluatePublish(draft Profile, pools map[string]Pool, activeSpec Profile, hasActive bool) PublishCheck {
	var chk PublishCheck

	// Validate the draft as a single-profile config against the pools.
	cfg := ProfilesConfig{Profiles: []Profile{draft}}
	for id, p := range pools {
		_ = id
		cfg.Pools = append(cfg.Pools, p)
	}
	if issues := ValidateProfilesConfig(cfg); len(issues) > 0 {
		chk.Issues = issues
		return chk
	}

	// A referenced pool must exist and be non-empty (no valid proxy route).
	if pool, ok := pools[draft.PoolID]; !ok || len(pool.Endpoints) == 0 {
		chk.Issues = append(chk.Issues, ValidationIssue{Field: "profiles", Entry: "profile " + draft.ID,
			Code: GuardMissingPool, Message: "referenced pool is missing or empty; no valid proxy route"})
		return chk
	}

	// Compile the draft; a non-empty digest must be producible.
	art := CompileProfile(draft, pools)
	if art.Digest == "" {
		chk.Issues = append(chk.Issues, ValidationIssue{Field: "profiles", Entry: "profile " + draft.ID,
			Code: GuardDigestFailed, Message: "could not produce an artifact digest"})
		return chk
	}
	chk.Digest = art.Digest

	// Secure mode must not be able to produce DIRECT (compiler enforces this,
	// but the guard makes the refusal explicit and testable).
	if draft.AvailabilityMode == ModeSecure && secureArtifactHasDirect(art.JS) {
		chk.Issues = append(chk.Issues, ValidationIssue{Field: "profiles", Entry: "profile " + draft.ID,
			Code: GuardSecureDirect, Message: "secure mode must never emit DIRECT"})
		return chk
	}

	// New-DIRECT-path detection: if the draft can yield DIRECT where the
	// active revision could not, require a typed confirmation.
	chk.NewDirectPaths = newDirectPaths(draft, activeSpec, hasActive)
	if len(chk.NewDirectPaths) > 0 {
		chk.RequiresConfirmation = true
		return chk
	}
	chk.OK = true
	return chk
}

// secureArtifactHasDirect reports whether compiled secure-mode JS contains a
// DIRECT beyond the sanctioned dotless-plain-host guard.
func secureArtifactHasDirect(js string) bool {
	const guard = `if (isPlainHostName(host) && host.indexOf(":") === -1) return "DIRECT";`
	stripped := replaceOnce(js, guard, "")
	return containsSub(stripped, `"DIRECT"`)
}

// newDirectPaths returns rule descriptions that introduce a DIRECT capability
// absent from the active revision (mode change to availability, or a new
// DIRECT-action rule). When there is no active revision, ANY DIRECT capability
// is "new".
func newDirectPaths(draft, active Profile, hasActive bool) []string {
	var out []string
	draftAvail := draft.AvailabilityMode == ModeAvailability
	activeAvail := hasActive && active.AvailabilityMode == ModeAvailability
	if draftAvail && !activeAvail {
		out = append(out, "availability mode appends DIRECT to the terminal chain")
	}
	// A flip to private-networks-direct (non-secure) routes the ENTIRE
	// RFC-1918/loopback space to DIRECT, bypassing inspection — the same
	// class of new-DIRECT exposure DiffProfiles already flags SecuritySensitive.
	// It must drive the typed confirmation too, or the guardrail and the diff
	// disagree and the confirmation is bypassable via a private-net flip.
	if draft.PrivateNetworks == PrivateDirect && draft.AvailabilityMode != ModeSecure &&
		(!hasActive || active.PrivateNetworks != PrivateDirect) {
		out = append(out, "private-networks=direct sends all RFC-1918/loopback destinations DIRECT")
	}
	activeDirect := map[string]bool{}
	if hasActive {
		for i := range active.Rules {
			if active.Rules[i].Action == ActionDirect {
				activeDirect[ruleKey(&active.Rules[i])] = true
			}
		}
	}
	for i := range draft.Rules {
		r := &draft.Rules[i]
		if r.Action == ActionDirect && draft.AvailabilityMode != ModeSecure && !activeDirect[ruleKey(r)] {
			out = append(out, "rule "+itoa(i+1)+" ("+r.Kind+" "+r.Pattern+") → DIRECT")
		}
	}
	return out
}

func ruleKey(r *Rule) string {
	return r.Kind + "|" + r.Pattern + "|" + r.Scheme + "|" + itoa(r.Port)
}

// Publish appends draft as a new immutable revision, makes it active, and
// clears the dirty flag. The caller supplies the validated digest, author,
// reason, and timestamp (the engine takes no wall clock). Returns the new
// revision number.
func (lc *ProfileLifecycle) Publish(draft Profile, digest, author, reason, ts string) int64 {
	n := lc.nextRevisionN()
	draft.Revision = n
	lc.Revisions = append(lc.Revisions, PublishedRevision{
		N: n, Spec: draft, Digest: digest, Author: author, Reason: reason, TS: ts,
	})
	lc.trimRevisions()
	lc.Draft = draft
	lc.DraftRevision++
	lc.ActiveN = n
	lc.DraftDirty = false
	return n
}

// Rollback re-activates a prior published revision by number. It does NOT
// rewrite history — it records a NEW revision that is a copy of the target
// spec (so revision numbers stay monotonic and the timeline shows the
// rollback), authored by the caller. Returns the new revision number and true,
// or false when targetN is not a published revision.
func (lc *ProfileLifecycle) Rollback(targetN int64, author, ts string) (int64, bool) {
	target, ok := lc.revisionByN(targetN)
	if !ok {
		return 0, false
	}
	n := lc.nextRevisionN()
	spec := target.Spec
	spec.Revision = n
	lc.Revisions = append(lc.Revisions, PublishedRevision{
		N: n, Spec: spec, Digest: target.Digest, Author: author,
		Reason: "rollback to revision " + itoa(int(targetN)), TS: ts,
	})
	lc.trimRevisions()
	lc.Draft = spec
	lc.DraftRevision++
	lc.ActiveN = n
	lc.DraftDirty = false
	return n, true
}

// TouchDraft records a draft edit (marks dirty). The caller stores the edited
// Draft separately; this just flags divergence from the active revision.
func (lc *ProfileLifecycle) TouchDraft(draft Profile) {
	lc.Draft = draft
	lc.DraftRevision++
	active, ok := lc.ActiveRevision()
	lc.DraftDirty = !ok || !sameProfileSpec(&draft, &active.Spec)
}

func sameProfileSpec(a, b *Profile) bool {
	if a.Name != b.Name || a.Description != b.Description || a.Enabled != b.Enabled ||
		a.PoolID != b.PoolID || a.PrivateNetworks != b.PrivateNetworks ||
		a.AvailabilityMode != b.AvailabilityMode || len(a.Rules) != len(b.Rules) {
		return false
	}
	for i := range a.Rules {
		if a.Rules[i] != b.Rules[i] {
			return false
		}
	}
	return true
}

// small dependency-free string helpers (avoid importing strings twice across
// files with different aliases; keep the engine self-contained).
func replaceOnce(s, old, repl string) string {
	i := indexSub(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + repl + s[i+len(old):]
}

func containsSub(s, sub string) bool { return indexSub(s, sub) >= 0 }

func indexSub(s, sub string) int {
	if sub == "" {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

var _ = time.RFC3339 // timestamps are caller-supplied; engine takes no clock
