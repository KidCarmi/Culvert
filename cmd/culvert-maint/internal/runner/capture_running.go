// Read-only capture primitive for the upgrade-apply slice (D1.6c).
//
// CaptureRunningProxyImage learns the identity of the image the running
// `proxy` container is ACTUALLY executing, by chaining three read-only
// docker commands:
//
//	docker compose ps --format json        → running proxy container id
//	docker inspect --format {{json .Image}} → image config digest (sha256:…)
//	docker image inspect <image-id>         → registry RepoDigests (best-effort)
//
// This is the authoritative running-image capture the apply slice needs
// (and that PR #351 deferred): it is bound to the running container, not
// to whatever a tag currently resolves to in the local cache. NOTHING in
// this file pulls, restarts, or mutates anything, and it does NOT
// activate /v1/upgrades/apply or /v1/rollbacks.
//
// Hygiene (carried from #351): the result carries ONLY parsed
// identifiers — container id, image config digest, full repo@sha256
// references. The raw `docker inspect` / `docker image inspect` JSON
// (which can contain Config.Env, labels, build metadata) is never
// returned, never logged, and never surfaced in errors.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// proxyServiceName is the compose service whose running image we
// capture. (Duplicated from internal/status rather than imported:
// internal/status imports internal/runner, so the reverse import is a
// cycle.)
const proxyServiceName = "proxy"

// imageConfigDigestRE matches a docker image config digest token
// (`sha256:` + 64 lowercase hex), the form `docker inspect`'s `.Image`
// returns.
var imageConfigDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// repoDigestRE matches a full repository digest reference
// (`<name>@sha256:<64hex>`). Only well-formed refs are kept as usable
// rollback pins; anything else is ignored.
var repoDigestRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// RunningProxyImage is the hygienic, parsed identity of the running
// `proxy` container's image. It carries ONLY parsed identifiers — never
// the raw inspect JSON.
type RunningProxyImage struct {
	// ContainerID is the running proxy container's id (12–64 hex).
	ContainerID string
	// RunningImageID is the container's image config digest
	// (`sha256:<64hex>`) — bound to the running container, immune to a
	// moving tag. This is the authoritative "what is actually running".
	RunningImageID string
	// RepoDigests are the full `repo@sha256:…` registry references for
	// the running image, parsed from `docker image inspect`. May be
	// empty for a locally-built image that was never pushed/pulled — a
	// legitimate state, not a capture failure.
	RepoDigests []string
}

// PriorRef returns the first full `repo@sha256:…` reference, or "" if
// none is available. Convenience for the future apply slice's rollback
// pin; policy when empty is the apply handler's decision.
func (ri *RunningProxyImage) PriorRef() string {
	if len(ri.RepoDigests) == 0 {
		return ""
	}
	return ri.RepoDigests[0]
}

// CaptureRunningProxyImage captures the identity of the image the
// running `proxy` container is executing. Read-only; acquires no
// maintenance lock.
//
// Steps 1 and 2 (ps → container id, inspect → image config digest) are
// REQUIRED: without the running container's image id there is nothing
// authoritative to compare against. Step 3 (image inspect → RepoDigests)
// is BEST-EFFORT: a missing or unreadable RepoDigest is a legitimate
// state, not a failure, so it leaves RepoDigests empty rather than
// erroring.
func (r *Runner) CaptureRunningProxyImage(ctx context.Context) (*RunningProxyImage, error) {
	psRes, err := r.ComposeStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("capture running proxy image: compose ps: %w", err)
	}
	cid, err := proxyContainerID(psRes.Stdout)
	if err != nil {
		return nil, fmt.Errorf("capture running proxy image: %w", err)
	}
	inspRes, err := r.ComposeContainerInspect(ctx, cid)
	if err != nil {
		return nil, fmt.Errorf("capture running proxy image: container inspect: %w", err)
	}
	imageID, err := parseContainerImageID(inspRes.Stdout)
	if err != nil {
		return nil, fmt.Errorf("capture running proxy image: %w", err)
	}
	out := &RunningProxyImage{ContainerID: cid, RunningImageID: imageID}
	// Best-effort registry digest. Failure/absence here does NOT fail the
	// capture — the running image id is already authoritative.
	if imgRes, imgErr := r.ComposeImageInspect(ctx, imageID); imgErr == nil && imgRes != nil {
		out.RepoDigests = repoDigestsFromImageInspect(imgRes.Stdout)
	}
	return out, nil
}

// psEntry mirrors the subset of `docker compose ps --format json` this
// capture needs. (Parallel to internal/status's composePSEntry; see the
// import-cycle note on proxyServiceName.)
type psEntry struct {
	Name    string `json:"Name"`
	Service string `json:"Service"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	ID      string `json:"ID"`
}

func (e psEntry) name() string {
	if e.Service != "" {
		return e.Service
	}
	return e.Name
}

// proxyContainerID parses `docker compose ps --format json` output
// (NDJSON or the array form some Compose versions emit) and returns the
// single running proxy container's id. Zero proxy entries, more than
// one, or a proxy entry with no id are all capture failures.
func proxyContainerID(stdout []byte) (string, error) {
	entries, err := parsePSEntries(stdout)
	if err != nil {
		return "", err
	}
	var ids []string
	for i := range entries {
		if entries[i].name() == proxyServiceName {
			ids = append(ids, entries[i].ID)
		}
	}
	switch len(ids) {
	case 0:
		return "", errors.New("no proxy service found in compose ps output")
	case 1:
		if ids[0] == "" {
			return "", errors.New("proxy service has no container id in compose ps output")
		}
		return ids[0], nil
	default:
		return "", fmt.Errorf("expected exactly one proxy container, found %d", len(ids))
	}
}

// parsePSEntries decodes both the NDJSON and JSON-array shapes of
// `docker compose ps --format json`.
func parsePSEntries(stdout []byte) ([]psEntry, error) {
	trimmed := bytes.TrimLeft(stdout, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("empty compose ps output")
	}
	if trimmed[0] == '[' {
		var entries []psEntry
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, fmt.Errorf("parse compose ps array: %w", err)
		}
		return entries, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var (
		entries    []psEntry
		candidates int
		firstErr   error
	)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		candidates++
		var e psEntry
		if err := json.Unmarshal(line, &e); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if candidates > 0 && len(entries) == 0 {
		return nil, fmt.Errorf("all compose ps NDJSON lines failed to decode: %w", firstErr)
	}
	return entries, nil
}

// parseContainerImageID decodes the output of
// `docker inspect --format '{{json .Image}}'` — a JSON-quoted string
// such as `"sha256:…"` — and returns the bare `sha256:<64hex>` id.
//
// On malformed input the error reports only the value's LENGTH, never
// its content, so an unexpected payload cannot leak into logs (#351).
func parseContainerImageID(stdout []byte) (string, error) {
	s := bytes.TrimSpace(stdout)
	if len(s) == 0 {
		return "", errors.New("container inspect returned no output")
	}
	var id string
	if err := json.Unmarshal(s, &id); err != nil {
		return "", errors.New("container inspect: .Image was not a JSON string")
	}
	if !imageConfigDigestRE.MatchString(id) {
		return "", fmt.Errorf("container inspect: .Image is not a sha256 image id (got a %d-byte value)", len(id))
	}
	return id, nil
}

// repoDigestsFromImageInspect parses the `RepoDigests` arrays out of
// `docker image inspect` output (a JSON array of image records) and
// returns the sorted, de-duplicated set of well-formed `repo@sha256:…`
// references. It decodes only the one field it needs — the rest of the
// record (Config.Env, labels, …) is never read, so nothing else can
// leak. A decode failure yields nil (best-effort).
func repoDigestsFromImageInspect(stdout []byte) []string {
	var records []struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &records); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for i := range records {
		for _, rd := range records[i].RepoDigests {
			if !repoDigestRE.MatchString(rd) {
				continue
			}
			if _, ok := seen[rd]; ok {
				continue
			}
			seen[rd] = struct{}{}
			out = append(out, rd)
		}
	}
	sort.Strings(out)
	return out
}
