// D1.6c API handler: POST /v1/upgrades/apply (destructive upgrade apply).
//
// The smallest safe destructive flow (no rollback in this MVP):
//
//	capture_before → CaptureRunningProxyImage (#357); best-effort — a
//	                 stack that is down is a valid state, not a failure.
//	resolve_target → docker manifest inspect <image_ref> → target digest
//	                 set; compute already_current (running ∩ target).
//	pre_backup     → if requested AND not already_current: encrypted
//	                 backup; a failure ABORTS before any pull/restart.
//	pull           → docker compose pull proxy, CULVERT_PROXY_IMAGE pinned.
//	restart        → docker compose up -d, CULVERT_PROXY_IMAGE pinned.
//	health_gate    → internal/health probe; failure FAILS the op
//	                 (health_failed). No rollback in this slice.
//	verify         → re-capture the running image. An exact @sha256: ref
//	                 is HARD-verified against the pin; a tag ref is soft
//	                 (records the landed digest — multi-arch list-vs-
//	                 platform digests are conservatively non-comparable).
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
	"time"

	"culvert-maint/internal/auth"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// upgradeApplyRequest is the POST /v1/upgrades/apply body.
type upgradeApplyRequest struct {
	ImageRef       string `json:"image_ref"`
	PreBackup      bool   `json:"pre_backup"`
	PassphraseRef  string `json:"passphrase_ref,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
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

	params := map[string]interface{}{
		"image_ref":      req.ImageRef,
		"pre_backup":     req.PreBackup,
		"passphrase_ref": req.PassphraseRef,
	}

	imageRef := req.ImageRef
	preBackup := req.PreBackup
	passRef := req.PassphraseRef

	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindUpgradeApply, req.IdempotencyKey, params, func() ([]ops.FlowStage, *opError) {
		var resolved string
		if preBackup {
			rp, rerr := readPassphraseFromEnv(passRef)
			if rerr != nil {
				return nil, &opError{Status: http.StatusBadRequest, Body: map[string]string{"error": rerr.Error()}}
			}
			resolved = rp
		}
		return s.buildUpgradeApplyStages(imageRef, preBackup, resolved), nil
	})
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
	priorImageID        string   // running image config digest (before)
	priorDigests        []string // bare sha256 of the running RepoDigests (before)
	alreadyCurrent      bool
	runningAfterID      string
	runningAfterDigests []string
	healthSummary       string
}

// buildUpgradeApplyStages constructs the destructive apply flow. exactDigest
// is non-empty only for an `@sha256:` image_ref, which enables hard
// post-restart verification; a tag ref verifies softly.
//
//nolint:funlen // single-pass orchestration; splitting hides the capture→resolve→backup→pull→restart→health→verify ordering
func (s *Server) buildUpgradeApplyStages(imageRef string, preBackup bool, resolvedPassphrase string) []ops.FlowStage {
	acc := &upgradeApplyAccumulator{}
	exactDigest := digestRE.FindString(imageRef) // "" for a tag ref
	preBackupFilename := "pre-upgrade-" + time.Now().UTC().Format("20060102T150405Z") + ".tar.gz.enc"

	return []ops.FlowStage{
		{
			// Capture what is ACTUALLY running before we touch anything.
			// A capture failure (stack down / fresh deploy) is a valid
			// state, not an op failure — we proceed without a prior.
			Name:          "capture_before",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
				if err != nil {
					return []byte("capture_before: no running proxy captured (" + errString(err) + ")"), nil, nil
				}
				acc.priorImageID = ri.RunningImageID
				acc.priorDigests = bareDigests(ri.RepoDigests)
				return []byte(fmt.Sprintf("capture_before: running_image_id=%s prior_digests=%s",
					ri.RunningImageID, joinDigests(acc.priorDigests))), nil, nil
			},
		},
		{
			// Remote registry lookup → target digest set. A failure here
			// fails the op: we cannot determine what we are upgrading to.
			Name:          "resolve_target",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeManifestInspect(ctx, imageRef)
				if res == nil {
					return nil, nil, rerr
				}
				acc.targetDigests = extractDigests(res.Stdout)
				if rerr != nil {
					return []byte("resolve_target: remote inspect failed"), res.Stderr, rerr
				}
				if digestSetsIntersect(acc.priorDigests, acc.targetDigests) {
					acc.alreadyCurrent = true
				}
				return []byte(fmt.Sprintf("resolve_target: target_digests=%s already_current=%v",
					joinDigests(acc.targetDigests), acc.alreadyCurrent)), res.Stderr, nil
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
				res, rerr := s.opts.Runner.ComposePull(ctx, imageRef)
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
				res, rerr := s.opts.Runner.ComposeUpWithImage(ctx, imageRef)
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			}),
		},
		{
			// Health gate. On failure the op fails (health_failed); there
			// is NO rollback in this slice.
			Name:          "health_gate",
			FailureReason: ops.ReasonHealthFailed,
			Run: skipIfCurrent(acc, "health_gate", func(ctx context.Context) ([]byte, []byte, error) {
				hr, herr := s.opts.HealthProbeFactory().Run(ctx)
				if herr != nil {
					return nil, nil, herr
				}
				acc.healthSummary = fmt.Sprintf("ready=%v ready_detail=%q health=%v health_detail=%q duration=%s",
					hr.ReadyOK, hr.ReadyDetail, hr.HealthOK, hr.HealthDetail, hr.TotalDuration)
				if hr.Failed() {
					return []byte(acc.healthSummary), nil, errors.New(hr.ReadyDetail)
				}
				return []byte(acc.healthSummary), nil, nil
			}),
		},
		{
			// Post-restart verification (the #351 output-side guarantee).
			// Exact digest refs are HARD-verified; tag refs are soft.
			Name:          "verify",
			FailureReason: ops.ReasonHealthFailed,
			Run:           skipIfCurrent(acc, "verify", s.verifyRunningImage(acc, exactDigest)),
		},
		{
			// Always emit the operator-facing summary, even after a
			// failure, so the op log records the outcome.
			Name:            "report",
			ContinueOnError: true,
			FailureReason:   ops.ReasonCommandError,
			Run: func(_ context.Context) ([]byte, []byte, error) {
				summary := fmt.Sprintf(
					"upgrade_apply image_ref=%q already_current=%v pre_backup=%v target_digests=%s prior_digests=%s running_after=%s health=[%s]",
					imageRef, acc.alreadyCurrent, preBackup,
					joinDigests(acc.targetDigests), joinDigests(acc.priorDigests),
					joinDigests(acc.runningAfterDigests), acc.healthSummary,
				)
				return []byte(summary), nil, nil
			},
		},
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

// verifyRunningImage re-captures the running proxy image after the restart.
// An exact `@sha256:` pin (exactDigest != "") is HARD-verified; a tag ref
// is soft (records the landed digest — multi-arch list-vs-platform digests
// are not directly comparable, and health already gated).
func (s *Server) verifyRunningImage(acc *upgradeApplyAccumulator, exactDigest string) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
		if err != nil {
			return []byte("verify: post-restart capture failed"), nil,
				fmt.Errorf("post-restart capture failed: %w", err)
		}
		acc.runningAfterID = ri.RunningImageID
		acc.runningAfterDigests = bareDigests(ri.RepoDigests)
		if exactDigest != "" && !containsString(acc.runningAfterDigests, exactDigest) {
			return []byte(fmt.Sprintf("verify: running digests=%s do NOT include pinned %s",
					joinDigests(acc.runningAfterDigests), exactDigest)), nil,
				fmt.Errorf("post-restart running image does not match pinned digest %s", exactDigest)
		}
		return []byte(fmt.Sprintf("verify: running_image_id=%s running_digests=%s",
			ri.RunningImageID, joinDigests(acc.runningAfterDigests))), nil, nil
	}
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
