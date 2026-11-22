// Read-only inspection of the fixed proxy tag.
//
// PinnedTagImageID answers "which image would the next `docker compose up`
// start?" — the one fact CaptureRunningProxyImage cannot give, because a
// running container stays bound to the image it was created from when the tag
// moves. The two together are how GET /v1/status shows a fixed tag that an
// interrupted image change left ahead of (or behind) the running container.
//
// It adds no privileged surface: it is the existing image-inspect template
// with the literal pinnedProxyTag as its only argument, which the sudoers
// `docker image inspect *` line already admits. Nothing here pulls, tags or
// restarts.
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// PinnedTagImageID returns the image id (`sha256:<64hex>`) the fixed
// culvert/proxy:pinned tag currently resolves to. An absent tag, an
// unreachable daemon and unparseable output are all errors: the caller must
// report "unknown", never treat a failed read as a fact about the tag.
func (r *Runner) PinnedTagImageID(ctx context.Context) (string, error) {
	res, err := r.ComposeImageInspect(ctx, pinnedProxyTag)
	if err != nil {
		return "", fmt.Errorf("inspect pinned tag: %w", err)
	}
	if res == nil {
		return "", errors.New("inspect pinned tag: no result")
	}
	id, err := imageIDFromImageInspect(res.Stdout)
	if err != nil {
		return "", fmt.Errorf("inspect pinned tag: %w", err)
	}
	return id, nil
}

// imageIDFromImageInspect extracts the single image id from `docker image
// inspect` output. Like repoDigestsFromImageInspect it decodes only the field
// it needs, so Config.Env and labels are never read; an error reports only a
// length, never the payload.
func imageIDFromImageInspect(stdout []byte) (string, error) {
	var records []struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &records); err != nil {
		return "", errors.New("image inspect output was not a JSON array")
	}
	if len(records) != 1 {
		return "", fmt.Errorf("image inspect returned %d records, want 1", len(records))
	}
	if !imageConfigDigestRE.MatchString(records[0].ID) {
		return "", fmt.Errorf("image inspect: .Id is not a sha256 image id (got a %d-byte value)", len(records[0].ID))
	}
	return records[0].ID, nil
}
