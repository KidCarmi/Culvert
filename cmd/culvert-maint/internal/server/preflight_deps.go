package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"culvert-maint/internal/runner"
)

// preflightDependencies refuses an image change while a service the proxy
// depends on reports "unhealthy". `docker compose up -d` against an
// unhealthy `depends_on: service_healthy` dependency removes the running
// proxy, creates the new one and leaves it STOPPED, and an inline
// rollback runs the same `up` — so the op would turn a ClamAV outage into
// a proxy outage (measured, see runner.UnhealthyDependencies). Refusing
// here is a no-op for the stack.
//
// Best-effort in the other direction: when `compose ps` cannot answer,
// the op proceeds as it always did (capture_before has the same rule);
// only an explicit "unhealthy" refuses.
func (s *Server) preflightDependencies() stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		if missing, wrong := s.localOnlyImageProblems(ctx); len(missing) > 0 || len(wrong) > 0 {
			if len(wrong) > 0 {
				msg := fmt.Sprintf("preflight_dependencies: REFUSED — local image does not name the recorded bytes: %s. This host runs `compose up --no-build`, so the recreate would start whatever the tag names; nothing was changed. Restore the verified image (`sudo culvert-clamav-image ensure`), then retry",
					strings.Join(wrong, ","))
				return []byte(msg), nil, fmt.Errorf("local_image_mismatch: %s", strings.Join(wrong, ","))
			}
			msg := fmt.Sprintf("preflight_dependencies: REFUSED — required local image absent: %s. This host runs `compose up --no-build`, so the image is never built here and the recreate would fail; nothing was changed. Restore it from the verified local archive (`sudo culvert-clamav-image ensure`), then retry",
				strings.Join(missing, ","))
			return []byte(msg), nil, fmt.Errorf("local_image_absent: %s", strings.Join(missing, ","))
		}
		res, err := s.opts.Runner.ComposeStatus(ctx)
		if err != nil || res == nil {
			return []byte("preflight_dependencies: compose ps unavailable (" + errString(err) + "); proceeding"), nil, nil
		}
		bad, perr := runner.UnhealthyDependencies(res.Stdout)
		if perr != nil {
			return []byte("preflight_dependencies: compose ps unparseable (" + perr.Error() + "); proceeding"), nil, nil
		}
		if len(bad) > 0 {
			msg := fmt.Sprintf("preflight_dependencies: REFUSED — unhealthy: %s. `docker compose up` would remove the running proxy and leave the new one stopped; nothing was changed. Fix the dependency (e.g. `docker compose restart %s`), then retry",
				strings.Join(bad, ","), bad[0])
			return []byte(msg), nil, fmt.Errorf("dependency_unhealthy: %s", strings.Join(bad, ","))
		}
		return []byte("preflight_dependencies: no unhealthy dependency"), nil, nil
	}
}

// localOnlyImageProblems checks the configured local-only images on a
// compose_no_build host. missing: the daemon's own "no such image" signature
// (same evidence rule as the upgrade check's local_inspect — an inspect that
// cannot answer for another reason does not refuse; `compose up --no-build`
// still cannot build). wrong: an entry that records an image ID whose tag
// names a different image, or whose present tag cannot be resolved to an ID —
// presence alone proves nothing about which bytes `up` would start.
func (s *Server) localOnlyImageProblems(ctx context.Context) (missing, wrong []string) {
	if s.opts.Cfg == nil || !s.opts.Cfg.ComposeNoBuild {
		return nil, nil
	}
	for _, img := range s.opts.Cfg.LocalOnlyImages {
		res, err := s.opts.Runner.ComposeImageInspect(ctx, img.Ref)
		if err != nil {
			if res != nil && imageNotFoundRE.Match(res.Stderr) {
				missing = append(missing, img.Ref)
			}
			continue
		}
		if img.ID == "" {
			continue
		}
		if id := inspectedImageID(res); id != img.ID {
			wrong = append(wrong, img.Ref)
		}
	}
	return missing, wrong
}

// inspectedImageID is the Id of the single image a `docker image inspect`
// answered with, or "" when the answer cannot be read.
func inspectedImageID(res *runner.Result) string {
	if res == nil {
		return ""
	}
	var imgs []struct {
		ID string `json:"Id"`
	}
	if json.Unmarshal(res.Stdout, &imgs) != nil || len(imgs) != 1 {
		return ""
	}
	return imgs[0].ID
}
