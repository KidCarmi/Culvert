// D1.6c API handler: POST /v1/upgrades/apply (destructive upgrade apply).
//
// Flow (with inline auto-rollback, #375):
//
//	capture_before → CaptureRunningProxyImage (#357); best-effort — a
//	                 stack that is down is a valid state, not a failure.
//	                 Also derives the inline-rollback target (priorRef).
//	resolve_target → docker manifest inspect <image_ref> → target digest
//	                 set; compute already_current (running ∩ target).
//	pre_backup     → if requested AND not already_current: encrypted
//	                 backup; a failure ABORTS before any pull/restart.
//	pull           → docker compose pull proxy, CULVERT_PROXY_IMAGE pinned.
//	restart        → docker compose up -d, CULVERT_PROXY_IMAGE pinned.
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

	"culvert-maint/internal/auth"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// upgradeApplyRequest is the POST /v1/upgrades/apply body.
type upgradeApplyRequest struct {
	ImageRef      string `json:"image_ref"`
	PreBackup     bool   `json:"pre_backup"`
	PassphraseRef string `json:"passphrase_ref,omitempty"`
	// RollbackOnFailure enables inline auto-rollback when the upgrade
	// fails its post-restart health/verify gate. A pointer so omitted
	// (nil) DEFAULTS TO TRUE (opt-out); pass false to disable (#375 §1).
	RollbackOnFailure *bool  `json:"rollback_on_failure,omitempty"`
	IdempotencyKey    string `json:"idempotency_key,omitempty"`
}

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
	if err := decodeJSONBody(r, &req); err != nil {
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

	params := map[string]interface{}{
		"image_ref":           req.ImageRef,
		"pre_backup":          req.PreBackup,
		"passphrase_ref":      req.PassphraseRef,
		"rollback_on_failure": rollbackOnFailure,
	}

	imageRef := req.ImageRef
	preBackup := req.PreBackup
	passRef := req.PassphraseRef

	// acc/racc are shared between the stage closures and the result
	// computer; acc.actor/opID feed the upgrades.apply:rollback audit.
	acc := &upgradeApplyAccumulator{actor: peer.String()}
	racc := &rollbackAccumulator{}

	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindUpgradeApply, req.IdempotencyKey, params,
		func() ([]ops.FlowStage, *opError) {
			var resolved string
			if preBackup {
				rp, rerr := readPassphraseFromEnv(passRef)
				if rerr != nil {
					return nil, &opError{Status: http.StatusBadRequest, Body: map[string]string{"error": rerr.Error()}}
				}
				resolved = rp
			}
			return s.buildUpgradeApplyStages(acc, racc, imageRef, preBackup, resolved, rollbackOnFailure), nil
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
	targetDigests       []string // bare sha256, from manifest inspect
	pinnedRef           string   // repo@sha256:<digest> actually pulled/restarted
	pinnedDigest        string   // bare sha256 of pinnedRef
	priorImageID        string   // running image config digest (before)
	priorDigests        []string // bare sha256 of the running RepoDigests (before)
	alreadyCurrent      bool
	runningAfterID      string
	runningAfterDigests []string
	healthSummary       string

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
// requestedRef is the operator's original image_ref (tag or digest); the
// flow resolves it to a concrete repo@sha256:<digest> pin (acc.pinnedRef)
// and pulls/restarts/verifies against THAT, never the raw tag.
//
//nolint:funlen // single-pass orchestration; splitting hides the capture→resolve→backup→pull→restart→health→verify ordering
func (s *Server) buildUpgradeApplyStages(acc *upgradeApplyAccumulator, racc *rollbackAccumulator, requestedRef string, preBackup bool, resolvedPassphrase string, rollbackOnFailure bool) []ops.FlowStage {
	preBackupFilename := "pre-upgrade-" + time.Now().UTC().Format("20060102T150405Z") + ".tar.gz.enc"

	stages := []ops.FlowStage{
		{
			// Capture what is ACTUALLY running before we touch anything.
			// A capture failure (stack down / fresh deploy) is a valid
			// state, not an op failure — we proceed without a prior. Also
			// derive the inline-rollback target (priorRef) here.
			Name:          "capture_before",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
				if err != nil {
					acc.priorCaptureReason = "no_prior_digest"
					return []byte("capture_before: no running proxy captured (" + errString(err) + ")"), nil, nil
				}
				acc.priorImageID = ri.RunningImageID
				acc.priorDigests = bareDigests(ri.RepoDigests)
				s.deriveRollbackTarget(acc, ri.PriorRef())
				return []byte(fmt.Sprintf("capture_before: running_image_id=%s prior_digests=%s prior_ref=%q rollback_target=%s",
					ri.RunningImageID, joinDigests(acc.priorDigests), acc.priorRef, rollbackTargetNote(acc))), nil, nil
			},
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
					// Tag ref — resolve to a digest and build the pin.
					// (Multi-arch caveat: manifest inspect --verbose reports
					// per-platform descriptors, so this resolves to one of
					// them; CP/GUI will send list digests — see D1.6c plan.)
					if len(acc.targetDigests) == 0 {
						return []byte("resolve_target: no digest resolved for tag " + requestedRef), res.Stderr,
							errors.New("resolve_target: could not resolve a digest for tag " + requestedRef)
					}
					// targetDigests already carry the `sha256:` prefix.
					acc.pinnedDigest = acc.targetDigests[0]
					acc.pinnedRef = imageRepo(requestedRef) + "@" + acc.pinnedDigest
				}
				if digestSetsIntersect(acc.priorDigests, acc.targetDigests) {
					acc.alreadyCurrent = true
				}
				return []byte(fmt.Sprintf("resolve_target: requested_ref=%q pinned_ref=%q target_digests=%s already_current=%v",
					requestedRef, acc.pinnedRef, joinDigests(acc.targetDigests), acc.alreadyCurrent)), res.Stderr, nil
			},
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
			Name:          "pull",
			FailureReason: ops.ReasonCommandError,
			Run: skipIfCurrent(acc, "pull", func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposePull(ctx, acc.pinnedRef)
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			}),
		},
		{
			Name:          "restart",
			FailureReason: ops.ReasonCommandError,
			Run: skipIfCurrent(acc, "restart", func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeUpWithImage(ctx, acc.pinnedRef)
				if rerr != nil {
					// `docker compose up -d` failure is INDETERMINATE: the
					// container may have been (partially) recreated on the
					// new image before failing. Treat it as post-restart so
					// inline rollback fires — re-pinning the prior digest is
					// safe whether the old image is still up (harmless
					// re-apply) or the new one came up broken (real recovery).
					acc.upgradeFailedPostRestart = true
				}
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			}),
		},
		{
			// Health gate. On a post-restart failure the op is marked
			// health_failed AND inline rollback is triggered.
			Name:          "health_gate",
			FailureReason: ops.ReasonHealthFailed,
			Run: skipIfCurrent(acc, "health_gate", func(ctx context.Context) ([]byte, []byte, error) {
				hr, herr := s.opts.HealthProbeFactory().Run(ctx)
				if herr != nil {
					acc.upgradeFailedPostRestart = true
					return nil, nil, herr
				}
				acc.healthSummary = fmt.Sprintf("ready=%v ready_detail=%q health=%v health_detail=%q duration=%s",
					hr.ReadyOK, hr.ReadyDetail, hr.HealthOK, hr.HealthDetail, hr.TotalDuration)
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
