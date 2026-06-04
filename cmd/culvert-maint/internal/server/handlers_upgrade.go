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
//	                 → parse locally-present digest(s). ABSENCE IS NORMAL
//	                   (a not-yet-pulled image is a valid check outcome,
//	                   never a failure) — but ONLY a clean docker
//	                   "no such image" stderr counts as absent. Any other
//	                   failure (Docker daemon down, sudoers/permission,
//	                   timeout, runner misconfig) is NOT proof of absence
//	                   and FAILS the op clearly rather than being reported
//	                   as local_present=false.
//	compare        → local_cache_up_to_date = the local and remote digest
//	                 sets intersect. Multi-arch note: a multi-arch ref's
//	                 local RepoDigest is the manifest-LIST digest while
//	                 `manifest inspect --verbose` reports per-platform
//	                 descriptor digests, so they will not intersect and
//	                 local_cache_up_to_date is conservatively false (worst
//	                 case the operator is advised to pull when already
//	                 current — harmless for a read-only check).
//
// SCOPE / SEMANTICS (deliberately narrow — read-only slice):
// The verdict is local_cache_up_to_date, NOT up_to_date. It compares the
// requested ref against the LOCAL IMAGE CACHE only — it does NOT inspect
// the image the running Compose stack is actually executing. A stack
// that has pulled the new image but not yet been restarted still reports
// local_cache_up_to_date=true. This is NOT proof the running service is
// upgraded.
//
// TODO(apply-slice, D1.6 plan § 3.5.1): the upgrade-apply slice must
// capture the RUNNING service image digest (status-derived ref, a new
// sudoers/validation surface not constrained by image_allowlist) before
// upgrading — both to give an authoritative running-vs-remote verdict
// and to pin the pre-upgrade digest for rollback. Until then, treat
// local_cache_up_to_date as a cache hint, not a deployment guarantee.
//
// Validation of image_ref is two-layered: this handler enforces the
// operator's image_allowlist (policy); the runner enforces
// validateImageRefShape (argv safety) as defense-in-depth.
//
// Operation details written to the per-op log (and surfaced via
// GET /v1/operations/{id}/logs) are the PARSED digest sets plus the
// compare summary line — never the raw `docker image inspect` /
// `docker manifest inspect --verbose` JSON. That JSON can carry image
// metadata beyond digests (Config.Env, labels, build info), so a
// badly built image must not be able to leak it through the op log;
// only content digests and the local_cache_up_to_date/local_present
// summary are recorded. Each inspect stage's stderr is preserved so a
// genuine failure (network/auth/permission) stays diagnosable. The op
// record's structured `result` is intentionally left to a follow-up
// slice; this slice adds no ops/orchestrator surface.
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
				// Record only the parsed digest set, never the raw
				// inspect JSON (image metadata leak hazard). stderr is
				// preserved so a remote failure stays diagnosable.
				line := []byte("remote_inspect: remote_digests=" + joinDigests(acc.remoteDigests))
				return line, res.Stderr, rerr
			},
		},
		{
			// Local image lookup. ContinueOnError so the compare stage
			// still runs (and emits the summary) regardless of how this
			// stage ends. Three outcomes are distinguished:
			//
			//   1. exit 0                  → image present locally.
			//   2. clean "no such image"   → image absent locally; a
			//                                 valid check outcome, op
			//                                 succeeds (local_present=false).
			//   3. any other failure       → Docker unavailable, sudoers
			//      (daemon down, permission,  broken, timeout, runner
			//       timeout, runner misconf)  misconfig — NOT proof the
			//                                 image is absent. We must NOT
			//                                 silently report local_present
			//                                 =false (that would feed a
			//                                 misleading up-to-date result);
			//                                 instead surface the error so
			//                                 the op fails clearly.
			Name:            "local_inspect",
			ContinueOnError: true,
			FailureReason:   ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposeImageInspect(ctx, imageRef)
				if rerr == nil && res != nil {
					// (1) Exit 0 → image is present locally. Record only
					// the parsed digest set, never the raw inspect JSON
					// (image metadata leak hazard).
					acc.localDigests = extractDigests(res.Stdout)
					acc.localPresent = true
					line := fmt.Sprintf("local_inspect: local_digests=%s local_present=true",
						joinDigests(acc.localDigests))
					return []byte(line), res.Stderr, nil
				}
				// (2) A clean "no such image" on stderr is the only
				// failure that means "absent locally". Key off the
				// stderr signature, not the exit code, so a daemon /
				// permission / timeout failure (which does NOT carry
				// this signature) cannot be misread as absent.
				if res != nil && imageNotFoundRE.Match(res.Stderr) {
					acc.localPresent = false
					return []byte("local_inspect: local_digests=none local_present=false (image not present locally)"),
						res.Stderr, nil
				}
				// (3) Environment / permission / timeout / runner
				// failure — surface it. ContinueOnError keeps the
				// compare stage running for the summary, but the non-nil
				// error marks the op failed (ReasonCommandError) so the
				// operator is never handed an upgrade verdict derived
				// from an unverified local view.
				acc.localCheckFailed = true
				acc.localCheckErr = errString(rerr)
				var stderr []byte
				if res != nil {
					stderr = res.Stderr
				}
				line := "local_inspect: local check FAILED (not a clean not-found): " + acc.localCheckErr
				return []byte(line), stderr, rerr
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

// imageNotFoundRE recognises docker's "image absent locally" signature
// on the stderr of `docker image inspect <ref>`. A not-yet-pulled image
// exits non-zero with "Error: No such image: <ref>" (older daemons may
// say "no such object"). This is the ONLY failure that legitimately
// means "absent"; every other failure (daemon down, sudoers/permission,
// timeout, runner misconfig) lacks this signature and must surface
// rather than be reported as absent.
var imageNotFoundRE = regexp.MustCompile(`(?i)no such (image|object)`)

// upgradeCheckAccumulator collects the parsed digests across the two
// inspect stages so the compare stage can render a single summary.
// localCheckFailed records an environment/permission/timeout failure of
// the local inspect (distinct from a clean "absent"); when set, the
// upgrade verdict is unknown rather than a confident up-to-date answer.
type upgradeCheckAccumulator struct {
	remoteDigests    []string
	localDigests     []string
	localPresent     bool
	localCheckFailed bool
	localCheckErr    string
}

// localCacheUpToDate reports whether the local image cache and the
// remote registry digest sets intersect. It is deliberately NOT named
// upToDate: it speaks only to the local image cache, not to the image
// the running Compose stack is actually executing (see summary's note).
// A failed local check yields false (the verdict is unknown).
func (a *upgradeCheckAccumulator) localCacheUpToDate() bool {
	if a.localCheckFailed {
		return false
	}
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
//
// The verdict is reported as local_cache_up_to_date, NOT up_to_date: it
// compares the requested ref against the LOCAL IMAGE CACHE only. A
// pulled-but-not-restarted stack still reports true, so this is NOT
// proof the running Compose stack has been upgraded. Authoritative
// running-image comparison (and digest pinning for rollback) lands with
// the upgrade-apply slice (D1.6 plan § 3.5.1).
func (a *upgradeCheckAccumulator) summary(imageRef string) string {
	if a.localCheckFailed {
		return fmt.Sprintf(
			"upgrade_check image_ref=%q local_cache_up_to_date=unknown local_check=failed local_check_err=%q remote_digests=%s\n"+
				"note: the local image check FAILED (not a clean not-found) — upgrade status is UNKNOWN; this is NOT proof the running stack is or is not on the latest image.",
			imageRef, a.localCheckErr, joinDigests(a.remoteDigests),
		)
	}
	return fmt.Sprintf(
		"upgrade_check image_ref=%q local_cache_up_to_date=%v local_present=%v remote_digests=%s local_digests=%s\n"+
			"note: local_cache_up_to_date reflects the LOCAL IMAGE CACHE only — it is NOT proof the running Compose stack has been restarted onto this digest (a pulled-but-not-restarted stack still reports true). Running-image comparison + digest pinning land with the upgrade-apply slice.",
		imageRef, a.localCacheUpToDate(), a.localPresent,
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
