// Read-only Docker facts for the opt-in startup reconcile (contract AGT-900).
//
// Everything here goes through templates and sudoers lines that already exist:
// `compose ps --format json`, the compose-cli `inspect-image` container inspect,
// and `docker image inspect <ref>`, plus one read-only template of its own,
// `compose ps -a --format json` (ProxyCreatedLeftover). Nothing pulls, tags or
// restarts.
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
	// ContainerID is the container's id as `compose ps` lists it.
	ContainerID string
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
	pc := &ProxyContainer{Present: true, Running: strings.EqualFold(proxies[0].State, "running"), ContainerID: proxies[0].ID, ImageID: id}
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
// proxy container is running now. One docker call.
//
// false is a claim the caller acts on, so it is returned only for output that
// is understood completely: empty, or entries that every one decoded and named
// their service. Truncated output, a line that does not decode, an entry
// without a service name, or anything that is not ps JSON is an error: Docker
// could not be read and nothing is known.
func (r *Runner) ProxyContainerListed(ctx context.Context) (bool, error) {
	ps, err := r.ComposeStatus(ctx)
	if err != nil {
		return false, fmt.Errorf("compose ps: %w", err)
	}
	entries, err := strictPSEntries(ps)
	if err != nil {
		return false, fmt.Errorf("compose ps: %w", err)
	}
	for i := range entries {
		if entries[i].Service == proxyServiceName {
			return true, nil
		}
	}
	return false, nil
}

// ProxyCreatedLeftover reports whether `compose ps -a` lists a proxy service
// container (not a `compose run` one-off) in state "created": what Compose leaves behind when the process running a
// recreate dies between creating the new container and starting it (measured
// on real Docker at every kill point that leaves no proxy running). A
// deliberate `compose down` removes it and a `docker stop` leaves only an
// "exited" one, so it is the Docker-side evidence that an outage follows a
// death inside `compose up` (ADR-0062 slice 4, B1). One read-only docker call.
//
// true lets the startup reconcile start a container, so it is returned only
// for output understood completely (strictPSEntries); anything else is an
// error, and an error is never evidence.
func (r *Runner) ProxyCreatedLeftover(ctx context.Context) (bool, error) {
	tmpl := templateByID(TemplateComposeStatusAll)
	if tmpl == nil {
		return false, errors.New("runner: TemplateComposeStatusAll not registered")
	}
	ps, err := r.run(ctx, r.buildArgv(tmpl))
	if err != nil {
		return false, fmt.Errorf("compose ps -a: %w", err)
	}
	entries, err := strictPSEntries(ps)
	if err != nil {
		return false, fmt.Errorf("compose ps -a: %w", err)
	}
	for i := range entries {
		e := &entries[i]
		if e.Service != proxyServiceName || !strings.EqualFold(e.State, "created") {
			continue
		}
		oneOff, known := oneOffLabel(e.Labels)
		if !known {
			// Whether this is a service container or a one-off cannot be
			// told, so it is not evidence either way.
			return false, errors.New("compose ps -a: a created proxy container without a readable com.docker.compose.oneoff label")
		}
		if !oneOff {
			return true, nil
		}
	}
	return false, nil
}

// oneOffLabel reads com.docker.compose.oneoff from Compose's Labels string.
// A one-off container (`compose run`) whose start failed stays "created", and
// `compose down` does not remove one-offs (measured, Compose v5.7.1), so only
// a service container (oneoff=False) is evidence. Labels is "k=v,k=v,..."; a
// value may itself contain commas (config_files with an override), so the
// label is matched as a whole item. Anything but exactly one "True" or one
// "False" is unknown.
func oneOffLabel(labels string) (oneOff, known bool) {
	seen := 0
	for _, item := range strings.Split(labels, ",") {
		switch item {
		case "com.docker.compose.oneoff=True":
			oneOff, seen = true, seen+1
		case "com.docker.compose.oneoff=False":
			oneOff, seen = false, seen+1
		}
	}
	return oneOff, seen == 1
}

// strictPSEntries decodes `compose ps` output that must be understood
// completely: empty, or entries that every one decoded and named their
// service. Truncated output, a line that does not decode, or an entry without
// a service name is an error.
func strictPSEntries(ps *Result) ([]psEntry, error) {
	if ps == nil {
		return nil, errors.New("no result")
	}
	if ps.Truncated {
		return nil, errors.New("output truncated")
	}
	out := bytes.TrimSpace(ps.Stdout)
	if len(out) == 0 {
		return nil, nil
	}
	entries, err := parsePSEntries(out)
	if err != nil {
		return nil, err
	}
	if out[0] != '[' {
		lines := 0
		for _, l := range bytes.Split(out, []byte("\n")) {
			if len(bytes.TrimSpace(l)) > 0 {
				lines++
			}
		}
		if lines != len(entries) {
			return nil, fmt.Errorf("%d of %d lines understood", len(entries), lines)
		}
	}
	for i := range entries {
		if entries[i].Service == "" {
			return nil, errors.New("an entry names no service")
		}
	}
	return entries, nil
}
