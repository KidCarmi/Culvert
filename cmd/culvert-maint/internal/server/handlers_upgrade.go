// D1.6c API handler: POST /v1/upgrades/check (read-only upgrade check).
//
// This is the first D1.6c slice. /v1/upgrades/apply and /v1/rollbacks
// remain 404 (see server.go's notImpl list) until their slices land.
//
// Flow (read-only — no maintenance lock, mirrors plan § 3.5):
//
//	remote_inspect → docker manifest inspect --verbose <image_ref>
//	                 → parse registry-side digest(s)
//	local_inspect  → docker image inspect <image_ref>
//	                 → parse locally-present digest(s); ABSENCE IS NORMAL
//	                   (a not-yet-pulled image is a valid check outcome,
//	                   never a failure)
//	compare        → up_to_date = the local and remote digest sets
//	                 intersect. Multi-arch note: a multi-arch ref's
//	                 local RepoDigest is the manifest-LIST digest while
//	                 `manifest inspect --verbose` reports per-platform
//	                 descriptor digests, so they will not intersect and
//	                 up_to_date is conservatively false (worst case the
//	                 operator is advised to pull when already current —
//	                 harmless for a read-only check). Authoritative
//	                 list-digest comparison is refined in the apply slice.
//
// Validation of image_ref is two-layered: this handler enforces the
// operator's image_allowlist (policy); the runner enforces
// validateImageRefShape (argv safety) as defense-in-depth.
//
// Operation details (both inspects' raw JSON, plus a compare summary
// line carrying up_to_date and the digest sets) are written to the
// per-op log and surfaced verbatim via GET /v1/operations/{id}/logs.
// The op record's structured `result` is intentionally left to a
// follow-up slice; this slice adds no ops/orchestrator surface.
package server

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"culvert-maint/internal/auth"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// digestRE matches a docker content digest token (sha256:<64 hex>). Used
// to extract digests defensively from `docker image inspect` and
// `docker manifest inspect --verbose` output without binding to a single
// exact JSON shape (the two commands differ, and the manifest verbose
// shape varies between single- and multi-arch refs).
var digestRE = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// upgradeCheckRequest is the POST /v1/upgrades/check body.
type upgradeCheckRequest struct {
	ImageRef       string `json:"image_ref"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

func (s *Server) handleUpgradeCheck(w http.ResponseWriter, r *http.Request, peer auth.PeerInfo) {
	if s.opts.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runner_not_wired"})
		return
	}
	var req upgradeCheckRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decode: " + err.Error()})
		return
	}
	// Argv-safety shape first (defense-in-depth), then the operator's
	// image_allowlist policy gate. Both must pass before any runner
	// method — and therefore any sudo — is invoked.
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

	params := map[string]interface{}{
		"image_ref": req.ImageRef,
	}

	imageRef := req.ImageRef
	buildStages := func() ([]ops.FlowStage, *opError) {
		return s.buildUpgradeCheckStages(imageRef), nil
	}

	op, deduped, herr := s.startAsyncOp(r, peer, ops.KindUpgradeCheck, req.IdempotencyKey, params, buildStages)
	if herr != nil {
		writeJSON(w, herr.Status, herr.Body)
		return
	}
	writeOpResponse(w, op, deduped)
}

// buildUpgradeCheckStages constructs the three-stage read-only flow. The
// two inspect stages write their parsed digests into a shared
// accumulator (closure-captured); the compare stage reads it and emits
// the operator-facing summary into the op log.
func (s *Server) buildUpgradeCheckStages(imageRef string) []ops.FlowStage {
	acc := &upgradeCheckAccumulator{}
	return []ops.FlowStage{
		{
			// Remote registry lookup. A failure here (network, auth,
			// unknown tag) DOES fail the op — the operator asked
			// "is there a newer image?" and we could not answer.
			Name:          "remote_inspect",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeManifestInspect(ctx, imageRef)
				if res == nil {
					return nil, nil, rerr
				}
				acc.remoteDigests = extractDigests(res.Stdout)
				return res.Stdout, res.Stderr, rerr
			},
		},
		{
			// Local image lookup. ContinueOnError so a remote failure
			// still lets us record the local view, AND the closure
			// itself swallows the runner error: a not-present image
			// exits non-zero, which is a legitimate "absent" answer,
			// not an operation failure.
			Name:            "local_inspect",
			ContinueOnError: true,
			FailureReason:   ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeImageInspect(ctx, imageRef)
				if res == nil {
					// Genuine runner misconfiguration (e.g. template
					// missing) — surface as a note, not a hard fail,
					// so the check still reports the remote digest.
					acc.localPresent = false
					return []byte("local_inspect: " + errString(rerr)), nil, nil
				}
				// A non-zero exit (rerr != nil) means the image is not
				// present locally — a valid "absent" answer, not a
				// failure. Either way we capture the output for the op
				// log and never propagate an error from this stage.
				acc.localDigests = extractDigests(res.Stdout)
				acc.localPresent = len(acc.localDigests) > 0
				return res.Stdout, res.Stderr, nil
			},
		},
		{
			// Pure-Go comparison. Always runs (ContinueOnError) so the
			// summary is emitted even if the remote lookup failed.
			Name:            "compare",
			ContinueOnError: true,
			FailureReason:   ops.ReasonCommandError,
			Run: func(_ context.Context) ([]byte, []byte, error) {
				summary := acc.summary(imageRef)
				return []byte(summary), nil, nil
			},
		},
	}
}

// upgradeCheckAccumulator collects the parsed digests across the two
// inspect stages so the compare stage can render a single summary.
type upgradeCheckAccumulator struct {
	remoteDigests []string
	localDigests  []string
	localPresent  bool
}

// upToDate reports whether the local and remote digest sets intersect.
func (a *upgradeCheckAccumulator) upToDate() bool {
	if len(a.remoteDigests) == 0 || len(a.localDigests) == 0 {
		return false
	}
	remote := make(map[string]struct{}, len(a.remoteDigests))
	for _, d := range a.remoteDigests {
		remote[d] = struct{}{}
	}
	for _, d := range a.localDigests {
		if _, ok := remote[d]; ok {
			return true
		}
	}
	return false
}

// summary renders the operator-facing compare line for the op log. It
// never includes anything secret — only image refs and content digests.
func (a *upgradeCheckAccumulator) summary(imageRef string) string {
	return fmt.Sprintf(
		"upgrade_check image_ref=%q up_to_date=%v local_present=%v remote_digests=%s local_digests=%s",
		imageRef, a.upToDate(), a.localPresent,
		joinDigests(a.remoteDigests), joinDigests(a.localDigests),
	)
}

// extractDigests returns the sorted, de-duplicated set of sha256 content
// digests found in raw docker inspect output. Defensive against the
// shape differences between `image inspect` and
// `manifest inspect --verbose`.
func extractDigests(raw []byte) []string {
	matches := digestRE.FindAllString(string(raw), -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// joinDigests renders a digest set for the summary line. "none" when
// empty so the log line is unambiguous.
func joinDigests(ds []string) string {
	if len(ds) == 0 {
		return "none"
	}
	return strings.Join(ds, ",")
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
