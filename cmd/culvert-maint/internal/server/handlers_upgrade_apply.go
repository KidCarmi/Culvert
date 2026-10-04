// D1.6c API handler: POST /v1/upgrades/apply (destructive upgrade apply).
//
// Flow (with inline auto-rollback, #375):
//
//	capture_before: capture the actual running digest and baseline.
//	resolve_target → docker manifest inspect <image_ref> → target digest
//	                 set; compute already_current (running ∩ target).
//	preflight_dependencies → refuse (nothing changed) while a service the
//	                 proxy depends on is unhealthy: `compose up` would
//	                 remove the proxy and leave the new one stopped.
//	preflight_space → refuse (nothing pulled) when the Docker data root
//	                 has less free space than ~3x the target's compressed
//	                 size + headroom. Then require signed target/baseline
//	                 authorization and durably persist recovery evidence.
//	pre_backup     → if requested AND not already_current: encrypted
//	                 backup; a failure ABORTS before any pull/restart.
//	pull           → docker pull <pinned repo@sha256> (P1.4; sudo-boundary
//	                 bound). The retag is deferred to restart.
//	restart        → docker tag … culvert/proxy:pinned + docker compose up -d
//	                 (retag adjacent to up, so a timeout between pull and
//	                 restart never advances the fixed tag).
//	health_gate    → internal/health probe; a post-restart failure marks
//	                 the op health_failed AND triggers inline rollback.
//	verify         → re-capture the running image; the pinned digest is
//	                 HARD-verified. A failure also triggers inline rollback.
//	recovery:rollback_* → when the upgrade failed POST-RESTART and a valid
//	                 prior target exists and rollback_on_failure is set, the
//	                 SHARED image-rollback core (pull→restart→health→verify)
//	                 re-pins the prior digest, inside this op + lock. A
//	                 failed rollback promotes failure_reason to
//	                 rollback_failed (narrow override); a successful one
//	                 leaves health_failed (service restored). See
//	                 inline_rollback.go + rollback_stages.go.
//	report         → operator-facing summary line (always emitted).
//
// already_current is a runtime decision (it depends on what is actually
// running), so the pull/restart/health/verify stages each no-op when the
// running image already matches the target rather than being omitted at
// build time.
//
// Hygiene (#351/#357): only PARSED digests reach the op log — never the
// raw inspect JSON. The pin survives sudo via the env_keep Defaults in
// packaging/sudoers/culvert-maint (plan § 2.3.1).
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"

	"culvert-maint/internal/auth"
	"culvert-maint/internal/health"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// upgradeApplyRequest is the POST /v1/upgrades/apply body.
type upgradeApplyRequest struct {
	ReleaseProof      *releaseproof.Evidence `json:"release_proof,omitempty"`
	PriorReleaseProof *releaseproof.Evidence `json:"prior_release_proof,omitempty"`
	ImageRef          string                 `json:"image_ref"`
	PreBackup         bool                   `json:"pre_backup"`
	PassphraseRef     string                 `json:"passphrase_ref,omitempty"`
	// RollbackOnFailure enables inline auto-rollback when the upgrade
	// fails its post-restart health/verify gate. A pointer so omitted
	// (nil) DEFAULTS TO TRUE (opt-out); pass false to disable (#375 §1).
	RollbackOnFailure *bool  `json:"rollback_on_failure,omitempty"`
	IdempotencyKey    string `json:"idempotency_key,omitempty"`
}

//nolint:cyclop // ordered refusal ladder includes the independent release trust gate
func (s *Server) handleUpgradeApply(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	if s.opts.HealthProbeFactory == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "health_probe_not_wired"})
		return
	}
	var req upgradeApplyRequest
	if err := decodeJSONBodyLimit(r, &req, maxProofBodyBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
		return
	}
	// Argv-safety shape, then the operator's image_allowlist policy gate.
	// Both pass before any runner method — and therefore any sudo — runs.
	if err := runner.ValidateImageRef(req.ImageRef); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.opts.Cfg.ImageAllowlist == nil || !s.opts.Cfg.ImageAllowlist.MatchString(req.ImageRef) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("image_ref %q is not permitted by image_allowlist", req.ImageRef),
		})
		return
	}
	if err := s.checkRelease(req.ImageRef, req.ReleaseProof); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	// pre_backup uses the encrypted backup path, so it requires a
	// passphrase_ref; without pre_backup a passphrase_ref is meaningless.
	if req.PreBackup {
		if req.PassphraseRef == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pre_backup=true requires passphrase_ref"})
			return
		}
		if err := validatePassphraseRefShape(req.PassphraseRef, s.opts.Runner.EnvAllowSnapshot()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	} else if req.PassphraseRef != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pre_backup=false must not include passphrase_ref"})
		return
	}

	// Inline auto-rollback is opt-out: nil (omitted) → true (#375 §1).
	rollbackOnFailure := req.RollbackOnFailure == nil || *req.RollbackOnFailure

	// Self-heal preflight (record-only, never blocks): if no compose override is
	// configured, the `restart` stage recreates the proxy with a single `-f` and
	// will DROP any override-supplied socket wiring — after which the CP can no
	// longer reach this agent. We RECORD it in op params (also on /v1/status) for
	// a CP/GUI consumer rather than refuse, because a host may legitimately run
	// without the socket (e.g. wiring baked into its base compose, or a local-only
	// operator). The agent cannot introspect the proxy's mounts (that would need a
	// new, format-unlocked `docker inspect` sudoers line), so this config-derived
	// flag is the signal.
	composeOverrideConfigured := s.opts.Cfg.ComposeOverrideFile != ""

	params := map[string]interface{}{
		"image_ref":                   req.ImageRef,
		"pre_backup":                  req.PreBackup,
		"passphrase_ref":              req.PassphraseRef,
		"rollback_on_failure":         rollbackOnFailure,
		"compose_override_configured": composeOverrideConfigured,
	}

	// acc/racc are shared between the stage closures and the result
	// computer; acc.actor/opID feed the upgrades.apply:rollback audit.
	acc := &upgradeApplyAccumulator{actor: peer.String(), releaseProof: req.ReleaseProof, priorReleaseProof: req.PriorReleaseProof}
	racc := &rollbackAccumulator{}

	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindUpgradeApply, req.IdempotencyKey, params,
		func() ([]ops.FlowStage, *opError) {
			var resolved string
			if req.PreBackup {
				rp, rerr := readPassphraseFromEnv(req.PassphraseRef)
				if rerr != nil {
					return nil, &opError{Status: http.StatusBadRequest, Body: map[string]string{"error": rerr.Error()}}
				}
				resolved = rp
			}
			return s.buildUpgradeApplyStages(acc, racc, req.ImageRef, req.PreBackup, resolved, rollbackOnFailure), nil
		},
		withOpIDHook(func(id string) { acc.opID = id }),
		withResultFn(func(state ops.State, _ ops.FailureReason) map[string]interface{} {
			return s.upgradeApplyResult(acc, racc, state)
		}),
	)
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// stageRun is the FlowStage.Run signature, aliased for the apply helpers.
type stageRun = func(context.Context) ([]byte, []byte, error)

// upgradeApplyAccumulator carries parsed digests + decisions across the
// apply stages. It holds ONLY parsed identifiers — never raw inspect JSON.
type upgradeApplyAccumulator struct {
	releaseProof        *releaseproof.Evidence
	priorReleaseProof   *releaseproof.Evidence
	targetDigests       []string // bare sha256, from manifest inspect
	pinnedRef           string   // repo@sha256:<digest> actually pulled/restarted
	pinnedDigest        string   // bare sha256 of pinnedRef
	priorImageID        string   // running image config digest (before)
	priorDigests        []string // bare sha256 of the running RepoDigests (before)
	alreadyCurrent      bool
	runningAfterID      string
	runningAfterDigests []string
	healthSummary       string
	// preserved is the health.Baseline taken before the restart: the
	// /ready rows that were "ok" and must be "ok" again for health_gate
	// to pass (owner review, PR #1528). Empty ⇒ 2xx alone gates.
	targetCompressed int64 // registry size of the pinned target (0 = unknown)
	preserved        []string
	before           *health.Snapshot // the full pre-restart /ready answer (nil: stack did not answer)
	baselineDetail   string

	// Inline auto-rollback state (#375). Set/read across stages + the
	// result computer; acc.opID/actor feed the rollback audit sub-action.
	opID                     string
	actor                    string
	priorRef                 string // full repo@sha256:<digest> rollback target (before)
	priorCaptureReason       string // "" if priorRef valid, else no_prior_digest / ambiguous_prior_digest
	upgradeFailedPostRestart bool   // set by restart(on error)/health_gate/verify — the running image is now new/indeterminate, so rollback may fire
	rollbackAttempted        bool
	rollbackRestarted        bool // rollback_restart succeeded (new image is the prior one)
	rollbackSucceeded        bool
	rollbackFailed           bool   // a rollback stage errored
	rollbackSkipReason       string // post-restart skip: disabled / no_prior_digest / ambiguous_prior_digest
}

// buildUpgradeApplyStages constructs the destructive apply flow.
// Production authorization requires requestedRef to be a signed pinned digest.
// Tag resolution remains for isolated orchestration tests only; production
// signature policy never authorizes a mutable tag.
//
//nolint:funlen // single-pass orchestration; splitting hides the capture→resolve→backup→pull→restart→health→verify ordering
func (s *Server) buildUpgradeApplyStages(acc *upgradeApplyAccumulator, racc *rollbackAccumulator, requestedRef string, preBackup bool, resolvedPassphrase string, rollbackOnFailure bool) []ops.FlowStage {
	preBackupFilename := "pre-upgrade-" + time.Now().UTC().Format("20060102T150405Z") + ".tar.gz.enc"

	stages := []ops.FlowStage{
		{
			// Capture what is ACTUALLY running before we touch anything.
			// Missing or ambiguous baseline fails signed authorization.
			// Recovery evidence is persisted before the first side effect.
			Name:          "capture_before",
			FailureReason: ops.ReasonCommandError,
			Run:           s.captureBefore(acc),
		},
		{
			// Remote registry lookup → target digest set, then PIN a
			// concrete repo@sha256:<digest>. A digest request is used
			// as-is; a tag is resolved to a digest. A failure here fails
			// the op: we cannot determine (or pin) what to upgrade to.
			Name:          "resolve_target",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeManifestInspect(ctx, requestedRef)
				if res == nil {
					return nil, nil, rerr
				}
				acc.targetDigests = extractDigests(res.Stdout)
				if rerr != nil {
					return []byte("resolve_target: remote inspect failed"), res.Stderr, rerr
				}
				if d := digestRE.FindString(requestedRef); d != "" {
					// Already a digest ref — pin it verbatim.
					acc.pinnedRef = requestedRef
					acc.pinnedDigest = d
				} else {
					// Tag ref — resolve to a single, host-correct manifest
					// descriptor digest STRUCTURALLY. We must NOT pick
					// targetDigests[0]: extractDigests scrapes every sha256
					// token from the verbose JSON (including layer/config
					// blob digests inside the embedded manifest bodies), and
					// a multi-arch image offers one descriptor per platform.
					// resolveTargetManifestDigest reads Descriptor.digest and
					// disambiguates by host platform, failing closed on any
					// ambiguity rather than pinning an arbitrary digest.
					pd, derr := resolveTargetManifestDigest(res.Stdout)
					if derr != nil {
						return []byte("resolve_target: " + derr.Error() + " for tag " + requestedRef), res.Stderr,
							fmt.Errorf("resolve_target: %w", derr)
					}
					acc.pinnedDigest = pd
					acc.pinnedRef = imageRepo(requestedRef) + "@" + acc.pinnedDigest
				}
				acc.targetCompressed = targetCompressedBytes(res.Stdout, acc.pinnedDigest)
				if containsString(acc.priorDigests, acc.pinnedDigest) {
					acc.alreadyCurrent = true
				}
				// Target pinned — fold TargetRef/TargetDigest into the journal record.
				s.advanceJournalPhaseBestEffort(acc, journal.PhaseResolved)
				return []byte(fmt.Sprintf("resolve_target: requested_ref=%q pinned_ref=%q target_digests=%s already_current=%v",
					requestedRef, acc.pinnedRef, joinDigests(acc.targetDigests), acc.alreadyCurrent)), res.Stderr, nil
			},
		},
		{
			// Refuse before anything is touched when a dependency of the
			// proxy is unhealthy: `compose up` would leave the proxy
			// stopped (see preflightDependencies). Not post-restart, so no
			// rollback fires.
			Name:          "preflight_dependencies",
			FailureReason: ops.ReasonValidation,
			Run:           skipIfCurrent(acc, "preflight_dependencies", s.preflightDependencies()),
		},
		{
			// Refuse before the pull when the Docker data root cannot hold
			// the target: a full root disk crashed the running proxy and
			// left Docker unable to restart it (see preflight_space.go).
			Name:          "preflight_space",
			FailureReason: ops.ReasonValidation,
			Run:           s.preflightAuthorizedSpace(acc, requestedRef),
		},
		{
			// Encrypted pre-upgrade backup. Skipped when already current
			// or not requested. A failure ABORTS — nothing is pulled.
			Name:          "pre_backup",
			FailureReason: ops.ReasonCLIError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				if acc.alreadyCurrent {
					return []byte("pre_backup: skipped (already current)"), nil, nil
				}
				if !preBackup {
					return []byte("pre_backup: skipped (pre_backup=false)"), nil, nil
				}
				res, rerr := s.opts.Runner.ComposeBackupEncrypted(ctx, preBackupFilename, resolvedPassphrase)
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			},
		},
		{
			// P1.4: pull the repo-bound pinned digest (sudo-boundary
			// pattern-matched argv, not an env var). The retag to the fixed
			// culvert/proxy:pinned tag is deliberately deferred to `restart`
			// so a timeout BETWEEN pull and restart never advances the tag.
			Name:          "pull",
			FailureReason: ops.ReasonCommandError,
			Run: skipIfCurrent(acc, "pull", func(ctx context.Context) ([]byte, []byte, error) {
				// Local-first: a pinned digest is content-addressed, so a digest
				// already in the local store needs no registry round trip (the
				// same no-offline floor the rollback core applies). Absent ⇒ pull,
				// byte-identical to the pre-change behaviour.
				if s.imagePresentLocally(ctx, acc.pinnedRef) {
					s.advanceJournalPhaseBestEffort(acc, journal.PhasePulled)
					return []byte("pull: skipped (image present locally)"), nil, nil
				}
				if err := s.knownRelease(acc.pinnedRef); err != nil {
					return nil, nil, err
				}
				res, rerr := s.opts.Runner.ComposePullDigest(ctx, acc.pinnedRef)
				if res == nil {
					return nil, nil, rerr
				}
				if rerr == nil {
					// New image is local; the fixed tag has NOT advanced — this is
					// the last SAFE boundary (a crash here needs no reconciliation).
					s.advanceJournalPhaseBestEffort(acc, journal.PhasePulled)
				}
				return res.Stdout, res.Stderr, rerr
			}),
		},
		{
			// P1.4: retag the pulled digest to culvert/proxy:pinned and
			// recreate the stack IN THE SAME STAGE. Keeping the retag
			// adjacent to `up` means the fixed tag is advanced only when the
			// restart it belongs to is actually running — a timeout between
			// pull and restart cannot strand the tag ahead of the daemon. A
			// `docker compose up -d` failure is INDETERMINATE (the container
			// may have been recreated on the new image before failing), so
			// it is treated as post-restart and inline rollback fires.
			Name:          "restart",
			FailureReason: ops.ReasonCommandError,
			Run:           skipIfCurrent(acc, "restart", s.restartWithBarrier(acc)),
		},
		{
			// Health gate. On a post-restart failure the op is marked
			// health_failed AND inline rollback is triggered.
			Name:          "health_gate",
			FailureReason: ops.ReasonHealthFailed,
			Run: skipIfCurrent(acc, "health_gate", func(ctx context.Context) ([]byte, []byte, error) {
				probe := s.opts.HealthProbeFactory()
				probe.Preserve, probe.Before = acc.preserved, acc.before
				hr, herr := probe.Run(ctx)
				if herr != nil {
					acc.upgradeFailedPostRestart = true
					return nil, nil, herr
				}
				acc.healthSummary = fmt.Sprintf("ready=%v ready_detail=%q health=%v health_detail=%q preserved=[%s] duration=%s",
					hr.ReadyOK, hr.ReadyDetail, hr.HealthOK, hr.HealthDetail, strings.Join(acc.preserved, ","), hr.TotalDuration)
				if hr.Failed() {
					// Post-restart failure: the new image is running but
					// unhealthy → this is what triggers inline rollback.
					acc.upgradeFailedPostRestart = true
					return []byte(acc.healthSummary), nil, errors.New(hr.ReadyDetail)
				}
				return []byte(acc.healthSummary), nil, nil
			}),
		},
		{
			// Post-restart verification (the #351 output-side guarantee):
			// the running image's RepoDigest must include the pinned
			// digest. The pin is always a concrete digest, so this is a
			// hard check for both tag and digest requests.
			Name:          "verify",
			FailureReason: ops.ReasonHealthFailed,
			Run:           skipIfCurrent(acc, "verify", s.verifyRunningImage(acc)),
		},
	}

	// Inline auto-rollback: the SHARED image-rollback core, decorated as
	// recovery stages (see inlineRollbackStages).
	stages = append(stages, s.inlineRollbackStages(acc, racc, rollbackOnFailure)...)

	// Always emit the operator-facing summary, even after a failure, so
	// the op log records both the upgrade and rollback outcome.
	stages = append(stages, ops.FlowStage{
		Name:            "report",
		ContinueOnError: true,
		FailureReason:   ops.ReasonCommandError,
		Run: func(_ context.Context) ([]byte, []byte, error) {
			summary := fmt.Sprintf(
				"upgrade_apply requested_ref=%q pinned_ref=%q already_current=%v pre_backup=%v target_digests=%s prior_digests=%s running_after=%s health=[%s] | rollback attempted=%v succeeded=%v target=%s final_running=%s",
				requestedRef, acc.pinnedRef, acc.alreadyCurrent, preBackup,
				joinDigests(acc.targetDigests), joinDigests(acc.priorDigests),
				joinDigests(acc.runningAfterDigests), acc.healthSummary,
				acc.rollbackAttempted, acc.rollbackSucceeded, acc.rollbackTargetDigest(),
				joinDigests(acc.finalRunningDigests(racc)),
			)
			return []byte(summary), nil, nil
		},
	})
	return stages
}

// captureBefore records what is ACTUALLY running before anything is
// touched, the inline-rollback target, and the /ready baseline the
// health gate must preserve. Capture records missing state; the caller then
// refuses apply when a signed observed baseline cannot be established.
func (s *Server) captureBefore(acc *upgradeApplyAccumulator) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
		if err != nil {
			acc.priorCaptureReason = "no_prior_digest"
			// Capture step done (no prior to record); advance the journal.
			s.advanceJournalPhaseBestEffort(acc, journal.PhaseCaptured)
			return []byte("capture_before: no running proxy captured (" + errString(err) + ")"), nil, nil
		}
		acc.priorImageID = ri.RunningImageID
		acc.priorDigests = bareDigests(ri.RepoDigests)
		s.deriveRollbackTarget(acc, ri)
		// What the running stack reports as healthy now is what the
		// upgrade must preserve. Best-effort: no answer ⇒ nothing to keep.
		acc.before, acc.baselineDetail = s.opts.HealthProbeFactory().Baseline(ctx)
		if acc.before != nil {
			acc.preserved = acc.before.Preserved
		}
		// Prior (rollback target) now known — fold it into the journal record.
		s.advanceJournalPhaseBestEffort(acc, journal.PhaseCaptured)
		return []byte(fmt.Sprintf("capture_before: running_image_id=%s prior_digests=%s prior_ref=%q rollback_target=%s %s",
			ri.RunningImageID, joinDigests(acc.priorDigests), acc.priorRef, rollbackTargetNote(acc), acc.baselineDetail)), nil, nil
	}
}

// skipIfCurrent wraps a stage Run so it no-ops (success) when the running
// image already matches the target. already_current is a runtime decision,
// so pull/restart/health/verify are skipped here rather than omitted at
// build time.
func skipIfCurrent(acc *upgradeApplyAccumulator, label string, run stageRun) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		if acc.alreadyCurrent {
			return []byte(label + ": skipped (already current)"), nil, nil
		}
		return run(ctx)
	}
}

// verifyRunningImage re-captures the running proxy image after the restart
// and HARD-verifies that its RepoDigest includes the pinned digest. The
// pin is always concrete (resolve_target turns a tag into a digest), so
// this is a hard check for both tag and digest requests.
func (s *Server) verifyRunningImage(acc *upgradeApplyAccumulator) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
		if err != nil {
			acc.upgradeFailedPostRestart = true
			return []byte("verify: post-restart capture failed"), nil,
				fmt.Errorf("post-restart capture failed: %w", err)
		}
		acc.runningAfterID = ri.RunningImageID
		acc.runningAfterDigests = bareDigests(ri.RepoDigests)
		if acc.pinnedDigest != "" && !containsString(acc.runningAfterDigests, acc.pinnedDigest) {
			acc.upgradeFailedPostRestart = true
			return []byte(fmt.Sprintf("verify: running digests=%s do NOT include pinned %s",
					joinDigests(acc.runningAfterDigests), acc.pinnedDigest)), nil,
				fmt.Errorf("post-restart running image does not match pinned digest %s", acc.pinnedDigest)
		}
		// Health + verify passed; success is imminent (the op still has the
		// report stage, and terminal removal will retire the record).
		s.advanceJournalPhaseBestEffort(acc, journal.PhaseVerified)
		return []byte(fmt.Sprintf("verify: running_image_id=%s running_digests=%s",
			ri.RunningImageID, joinDigests(acc.runningAfterDigests))), nil, nil
	}
}

// imageRepo returns the repository portion of an image reference,
// dropping any `@digest` or `:tag`. The tag is the `:` that follows the
// last `/` (so a registry host:port is preserved). For
// `ghcr.io/kidcarmi/culvert:v1` → `ghcr.io/kidcarmi/culvert`.
func imageRepo(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		return ref[:i]
	}
	slash := strings.LastIndexByte(ref, '/')
	if colon := strings.LastIndexByte(ref, ':'); colon > slash {
		return ref[:colon]
	}
	return ref
}

// bareDigests extracts the bare sha256 token from each full
// `repo@sha256:…` reference, dropping anything malformed.
func bareDigests(repoRefs []string) []string {
	out := make([]string, 0, len(repoRefs))
	for _, ref := range repoRefs {
		if d := digestRE.FindString(ref); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// digestSetsIntersect reports whether two bare-digest sets share a member.
func digestSetsIntersect(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, d := range a {
		set[d] = struct{}{}
	}
	for _, d := range b {
		if _, ok := set[d]; ok {
			return true
		}
	}
	return false
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// preflightAuthorizedSpace persists trust only after the read-only space gate.
// A normal ENOSPC preflight refusal therefore needs no agent restart to retry.
// Authorization remains mandatory before backup, pull, retag, or success.
func (s *Server) preflightAuthorizedSpace(acc *upgradeApplyAccumulator, requestedRef string) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		out, stderr, err := skipIfCurrent(acc, "preflight_space", s.preflightSpace(acc))(ctx)
		if err != nil {
			return out, stderr, err
		}
		return out, stderr, s.prepareRelease(requestedRef, acc.releaseProof, acc.priorRef, acc.priorReleaseProof)
	}
}
