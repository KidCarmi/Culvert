// D1.6c API handler: POST /v1/rollbacks (mode=image only — MVP).
//
// Image rollback re-pins the proxy to a PRIOR pinned digest (the one a
// completed upgrades.apply recorded; the CP recalls it and supplies it
// here) and recreates the stack:
//
//	capture_before → record what is running now (best-effort, summary only)
//	pull           → docker compose pull proxy, CULVERT_PROXY_IMAGE=<target>
//	restart        → docker compose up -d,    CULVERT_PROXY_IMAGE=<target>
//	health_gate    → internal/health probe; failure → health_failed
//	verify         → re-capture; HARD-verify running RepoDigest ⊇ target
//	report         → operator-facing summary (always emitted)
//
// This composes the apply primitives (ComposePull + ComposeUpWithImage +
// CaptureRunningProxyImage) — NO new runner template or sudoers entry.
// The target MUST be a strict `repo@sha256:<digest>` (a rollback target
// is never a tag). No backup is taken (rollback IS the recovery action),
// there is no inline auto-rollback, and data-mode is not implemented yet.
//
// Hygiene (#351/#357): only parsed digests reach the op log.
package server

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"culvert-maint/internal/auth"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// rollbackDigestRefRE requires a strict pinned digest reference,
// `<repo>@sha256:<64hex>`. A rollback target must be exact — a tag (which
// `image_allowlist` would otherwise accept) is never a valid target.
var rollbackDigestRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// rollbackRequest is the POST /v1/rollbacks body.
type rollbackRequest struct {
	Mode           string `json:"mode"`
	ImageRef       string `json:"image_ref"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	if s.opts.HealthProbeFactory == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "health_probe_not_wired"})
		return
	}
	var req rollbackRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
		return
	}
	if req.Mode != "image" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "mode must be \"image\" (data-mode rollback is not yet implemented)",
		})
		return
	}
	// Argv-safety, then strict digest-ref shape, then the operator's
	// image_allowlist. All three pass before any runner method runs.
	if err := runner.ValidateImageRef(req.ImageRef); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !rollbackDigestRefRE.MatchString(req.ImageRef) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "image_ref must be a pinned digest reference repo@sha256:<digest> (a tag is not a valid rollback target)",
		})
		return
	}
	if s.opts.Cfg.ImageAllowlist == nil || !s.opts.Cfg.ImageAllowlist.MatchString(req.ImageRef) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("image_ref %q is not permitted by image_allowlist", req.ImageRef),
		})
		return
	}

	params := map[string]interface{}{
		"mode":      "image",
		"image_ref": req.ImageRef,
	}
	targetRef := req.ImageRef

	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindRollbackCreate, req.IdempotencyKey, params, func() ([]ops.FlowStage, *opError) {
		return s.buildImageRollbackStages(targetRef), nil
	})
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// buildImageRollbackStages constructs the standalone image-mode rollback
// flow, pinned to targetRef (a strict repo@sha256:<digest>): a
// capture_before + the SHARED imageRollbackStages core (pull → restart →
// health → verify) + a report. The core is shared verbatim with apply's
// inline auto-rollback so the two cannot drift (#375 §8).
func (s *Server) buildImageRollbackStages(targetRef string) []ops.FlowStage {
	acc := &rollbackAccumulator{}

	stages := []ops.FlowStage{
		{
			// Record what is running before the rollback. A capture
			// failure (stack down) is not fatal — the target is fixed.
			Name:          "capture_before",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
				if err != nil {
					return []byte("capture_before: no running proxy captured (" + errString(err) + ")"), nil, nil
				}
				acc.priorDigests = bareDigests(ri.RepoDigests)
				return []byte("capture_before: prior_digests=" + joinDigests(acc.priorDigests)), nil, nil
			},
		},
	}
	stages = append(stages, s.imageRollbackStages(func() string { return targetRef }, acc)...)
	stages = append(stages, ops.FlowStage{
		Name:            "report",
		ContinueOnError: true,
		FailureReason:   ops.ReasonCommandError,
		Run: func(_ context.Context) ([]byte, []byte, error) {
			summary := fmt.Sprintf(
				"rollback mode=image target_ref=%q prior_digests=%s running_after=%s health=[%s]",
				targetRef, joinDigests(acc.priorDigests), joinDigests(acc.runningAfterDigests), acc.healthSummary,
			)
			return []byte(summary), nil, nil
		},
	})
	return stages
}
