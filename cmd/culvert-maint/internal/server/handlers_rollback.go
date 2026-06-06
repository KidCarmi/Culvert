// D1.6c API handler: POST /v1/rollbacks (mode=image | mode=data).
//
// mode=image re-pins the proxy to a PRIOR pinned digest and recreates the
// stack (capture → pull → restart → health → verify); it composes the
// apply primitives with NO new runner template or sudoers entry.
//
// mode=data rolls /data back by restoring a backup. It is a WRAP of the
// existing restore.commit primitive — same validation, same
// buildRestoreStages(commit=true,…), same ComposeRestoreCommit, same
// WouldBlock safety gates, same stop→restore→up→health flow — run under
// the rollbacks.create op kind. It is NOT a second restore implementation
// (see data_rollback.go) and is STANDALONE-ONLY (never auto-invoked).
//
// Hygiene (#351/#357): only parsed digests reach the op log; the
// passphrase value never does.
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

// rollbackRequest is the POST /v1/rollbacks body. ImageRef is used for
// mode=image; the Filename/RestoreMode/PassphraseRef/safety-flag fields
// for mode=data (they map 1:1 to restore.commit).
type rollbackRequest struct {
	Mode     string `json:"mode"`
	ImageRef string `json:"image_ref"`

	// mode=data fields (see data_rollback.go).
	Filename             string `json:"filename"`
	RestoreMode          string `json:"restore_mode,omitempty"`
	PassphraseRef        string `json:"passphrase_ref,omitempty"`
	AcceptDPReenrollment bool   `json:"accept_dp_reenrollment,omitempty"`
	AllowCounterRollback bool   `json:"allow_counter_rollback,omitempty"`

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
	switch req.Mode {
	case "image":
		s.rollbackImage(w, r, peer, req)
	case "data":
		s.rollbackData(w, r, peer, req)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": `mode must be "image" or "data"`,
		})
	}
}

// rollbackImage handles mode=image: re-pin to a prior digest.
func (s *Server) rollbackImage(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo, req rollbackRequest) {
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
