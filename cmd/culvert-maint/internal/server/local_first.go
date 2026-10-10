// Local-first image resolution (RISK-022 PR-E design §4 / avail F4 — the
// "no-offline floor").
//
// A rollback's pull used to hit the registry UNCONDITIONALLY, so the fault that
// made an upgrade fail (a registry/network outage, a GC'd prior) was frequently
// the same fault that then made the recovery fail — leaving the unhealthy new
// image running with failed(rollback_failed). A pinned digest reference is
// CONTENT-ADDRESSED: if `docker image inspect <repo@sha256:…>` succeeds AND the
// local record carries that exact RepoDigest, the bytes the pull would fetch
// are already present, so skipping the pull cannot change what `docker tag` +
// `compose up` resolve. Any other inspect outcome (non-zero exit, unparseable
// output, a record that does not list the ref) falls back to the pull —
// byte-identical to the pre-change behaviour when the image is absent.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
)

// imageConfigDigestRE matches an image config digest (`sha256:` + 64 hex), the
// `Id` form `docker image inspect` reports.
var imageConfigDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// imagePresentLocally reports whether the exact pinned ref is in the local
// image store. It is deliberately strict: a successful inspect whose
// RepoDigests do not name the ref (an unexpected daemon output shape) is NOT
// treated as present — the fail-safe answer is "pull".
func (s *Server) imagePresentLocally(ctx context.Context, ref string) bool {
	res, err := s.opts.Runner.ComposeImageInspect(ctx, ref)
	if err != nil || res == nil {
		return false
	}
	return containsString(repoDigestsFromInspect(res.Stdout), ref)
}

// repoDigestsFromInspect decodes ONLY the RepoDigests arrays out of a
// `docker image inspect` JSON array; the rest of the record (Config.Env, labels)
// is never read. nil on any decode failure.
func repoDigestsFromInspect(stdout []byte) []string {
	var records []struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &records); err != nil {
		return nil
	}
	var out []string
	for i := range records {
		out = append(out, records[i].RepoDigests...)
	}
	return out
}

// imageIDFromInspect decodes the `Id` (config digest, `sha256:<hex>`) of the
// FIRST record in a `docker image inspect` JSON array, or "" when absent or
// malformed. Used by the reconciler to learn what the pinned tag resolves to.
func imageIDFromInspect(stdout []byte) string {
	var records []struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &records); err != nil || len(records) == 0 {
		return ""
	}
	if !imageConfigDigestRE.MatchString(records[0].ID) {
		return ""
	}
	return records[0].ID
}
