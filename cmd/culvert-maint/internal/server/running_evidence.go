package server

import "culvert-maint/internal/runner"

// Evidence-based final running image (owner decision 2, roadmap/FINAL-RUNNING-DIGEST-PROPOSAL.md
// option C). The upgrade result used to INFER `final_running_digest` from accumulator flags,
// so it could name an image no capture ever showed (48 of 172 modelled paths disagreed with
// the container actually running). It now reports only what a capture showed AFTER the last
// `docker compose up`, and says `unverified` otherwise.
//
// An evidence capture is the most recent successful CaptureRunningProxyImage with no
// `compose up` invocation after it, whatever that `up` returned. `docker tag`, pull and the
// backup `cli` run do not recreate the proxy container (the shipped compose file gives `cli`
// no depends_on), so they do not invalidate evidence.

// Values of the result's final_running_state.
const (
	finalRunningVerified   = "verified"   // a capture after the last `up` established the running image
	finalRunningUnverified = "unverified" // no such capture exists: the running image is not known
)

// runningEvidence tracks the most recent capture of the running proxy image and whether a
// `compose up` ran after it. The zero value means "nothing captured yet". A nil
// *runningEvidence ignores every call, which is how the standalone rollback handler keeps
// its behaviour unchanged.
type runningEvidence struct {
	captured bool
	imageID  string   // the container's image id, as `docker inspect {{json .Image}}` reports it
	repoRefs []string // full repo@sha256 references of that image (RepoDigests)
	stale    bool     // a `compose up` was invoked after the capture
}

// noteCapture records a successful capture of the running proxy image.
func (e *runningEvidence) noteCapture(ri *runner.RunningProxyImage) {
	if e == nil || ri == nil {
		return
	}
	e.captured, e.imageID, e.stale = true, ri.RunningImageID, false
	e.repoRefs = append([]string(nil), ri.RepoDigests...)
}

// noteUp records that `docker compose up` is about to run: any earlier capture may no longer
// describe the running container, whatever `up` returns.
func (e *runningEvidence) noteUp() {
	if e != nil {
		e.stale = true
	}
}

// current reports whether the latest capture still describes the running container.
func (e *runningEvidence) current() bool {
	return e != nil && e.captured && !e.stale
}

// finalRunning is the reported final running image.
type finalRunning struct {
	state   string // finalRunningVerified | finalRunningUnverified
	digest  string // bare sha256 REGISTRY digest of the verified image, or ""
	imageID string // the verified image's id, or ""
}

// finalRunningFrom turns the evidence into the reported value. The digest is a registry
// digest only: it is taken from a repo@sha256 reference that passes the same gate as the
// rollback target (rollbackDigestRefRE + the image allowlist). A local-only reference (the
// containerd image store adds `culvert/proxy@sha256:…` for every local tag) is not a registry
// digest, so a verified image without an allow-listed reference reports digest "" and is
// identified by image_id alone.
func (s *Server) finalRunningFrom(e *runningEvidence) finalRunning {
	if !e.current() {
		return finalRunning{state: finalRunningUnverified}
	}
	fr := finalRunning{state: finalRunningVerified, imageID: e.imageID}
	for _, ref := range e.repoRefs {
		if rollbackDigestRefRE.MatchString(ref) && s.opts.Cfg.ImageAllowlist != nil && s.opts.Cfg.ImageAllowlist.MatchString(ref) {
			fr.digest = digestRE.FindString(ref)
			break
		}
	}
	return fr
}
