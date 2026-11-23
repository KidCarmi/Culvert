// Read-only Docker facts for the opt-in startup reconcile (contract AGT-900).
//
// Everything here goes through templates and sudoers lines that already exist:
// `compose ps --format json`, the compose-cli `inspect-image` container inspect,
// and `docker image inspect <ref>`. Nothing pulls, tags or restarts.
//
// The one thing CaptureRunningProxyImage cannot say is WHY there is no proxy:
// it reports "daemon down" and "no container" as the same error. A reconciler
// must tell them apart (an unreadable daemon defers; a stack that is down is a
// fact), so ReadProxyContainer returns an error ONLY when Docker could not be
// read, and a ProxyContainer with Present=false when it was read and no proxy
// container exists.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

// ProxyContainer is what Docker says about the compose `proxy` container.
type ProxyContainer struct {
	// Present is false when `compose ps` succeeded and listed no proxy.
	Present bool
	// Running is true when the container's State is "running".
	Running bool
	// ImageID is the container's image id (`sha256:<64hex>`).
	ImageID string
	// RepoDigests are the image's `repo@sha256:…` references; best-effort, may
	// be empty.
	RepoDigests []string
}

// ReadProxyContainer reads the proxy container's presence, state and image.
// An error means Docker could not be read (or answered in a way that cannot be
// interpreted, such as two proxy containers); the caller must not treat it as
// a fact about the container.
func (r *Runner) ReadProxyContainer(ctx context.Context) (*ProxyContainer, error) {
	ps, err := r.ComposeStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("compose ps: %w", err)
	}
	if len(bytes.TrimSpace(ps.Stdout)) == 0 {
		return &ProxyContainer{}, nil
	}
	entries, err := parsePSEntries(ps.Stdout)
	if err != nil {
		return nil, fmt.Errorf("compose ps: %w", err)
	}
	var proxies []psEntry
	for i := range entries {
		if entries[i].name() == proxyServiceName {
			proxies = append(proxies, entries[i])
		}
	}
	switch {
	case len(proxies) == 0:
		return &ProxyContainer{}, nil
	case len(proxies) > 1:
		return nil, fmt.Errorf("compose ps: %d proxy containers", len(proxies))
	case proxies[0].ID == "":
		return nil, errors.New("compose ps: proxy container has no id")
	}
	insp, err := r.ComposeContainerInspect(ctx, proxies[0].ID)
	if err != nil {
		return nil, fmt.Errorf("container inspect: %w", err)
	}
	id, err := parseContainerImageID(insp.Stdout)
	if err != nil {
		return nil, fmt.Errorf("container inspect: %w", err)
	}
	pc := &ProxyContainer{Present: true, Running: strings.EqualFold(proxies[0].State, "running"), ImageID: id}
	if img, ierr := r.ComposeImageInspect(ctx, id); ierr == nil && img != nil {
		pc.RepoDigests = repoDigestsFromImageInspect(img.Stdout)
	}
	return pc, nil
}

// LocalImageID returns the id (`sha256:<64hex>`) of a LOCAL image named by ref
// (`docker image inspect <ref>`). An image that is not present locally, an
// unreachable daemon and unparseable output are all errors: the caller treats
// the id as unknown and never as "absent" proof. Never pulls.
func (r *Runner) LocalImageID(ctx context.Context, ref string) (string, error) {
	res, err := r.ComposeImageInspect(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("image inspect: %w", err)
	}
	if res == nil {
		return "", errors.New("image inspect: no result")
	}
	return imageIDFromImageInspect(res.Stdout)
}

// ProxyContainerListed reports whether `compose ps` lists a proxy container at
// all, in any state. `compose ps` lists containers that are running (or
// restarting or paused), not exited or merely created ones, so false means: no
// proxy container is running now. One docker call; an error means Docker could
// not be read and nothing is known.
func (r *Runner) ProxyContainerListed(ctx context.Context) (bool, error) {
	ps, err := r.ComposeStatus(ctx)
	if err != nil {
		return false, fmt.Errorf("compose ps: %w", err)
	}
	if len(bytes.TrimSpace(ps.Stdout)) == 0 {
		return false, nil
	}
	entries, err := parsePSEntries(ps.Stdout)
	if err != nil {
		return false, fmt.Errorf("compose ps: %w", err)
	}
	for i := range entries {
		if entries[i].name() == proxyServiceName {
			return true, nil
		}
	}
	return false, nil
}
