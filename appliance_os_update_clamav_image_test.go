package main

import (
	"strings"
	"testing"
)

// Workstream C: every culvert-os-update stack start restores the baked ClamAV
// sidecar from its verified archive (culvert-clamav-image ensure) BEFORE
// `docker compose up`, and `up` carries --no-build. Without --no-build a
// missing sidecar tag makes Compose rebuild it from source (measured on
// Compose 5.6.0 and 5.6.1 in every missing-tag state: running, stopped by this
// script, removed), so an engine upgrade that lost the image store would have
// rebuilt new, unscanned bytes.

func TestOSUpdateStackStart_RestoresSidecarBeforeNoBuildUp(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T) (string, string, int)
	}{
		{"docker-upgrade", func(t *testing.T) (string, string, int) { return runOSUpdateDocker(t) }},
		{"resume-stack", func(t *testing.T) (string, string, int) {
			armResumeMarker(t)
			return runOSUpdate(t, "resume-stack")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, code := tc.run(t)
			if code != 0 {
				t.Fatalf("stack start failed (code %d):\n%s", code, out)
			}
			ensure, up := strings.Index(calls, "clamav-image ensure"), strings.Index(calls, "docker compose up")
			if ensure < 0 || up < 0 || ensure > up {
				t.Fatalf("the sidecar must be restored before `compose up` (ensure@%d up@%d):\n%s", ensure, up, calls)
			}
			for _, line := range strings.Split(calls, "\n") {
				if strings.HasPrefix(line, "docker compose") && strings.Contains(line, " up ") && !strings.HasSuffix(line, " up -d --no-build") {
					t.Fatalf("every appliance `compose up` must end in --no-build, got %q:\n%s", line, calls)
				}
			}
		})
	}
}

// A refused restore starts nothing: no `compose up` (which could not build the
// sidecar anyway, but would fail without the recorded reason), a non-zero exit,
// and the stack-resume marker kept so a later resume can retry once the
// verified image is back.
func TestOSUpdateStackStart_RefusedRestoreStartsNothing(t *testing.T) {
	armResumeMarker(t)
	out, calls, code := runOSUpdate(t, "resume-stack", "FAIL_CLAMAV_IMAGE=1")
	if code == 0 {
		t.Fatalf("a refused sidecar restore must fail the resume:\n%s", out)
	}
	if strings.Contains(calls, "docker compose up") {
		t.Fatalf("no `compose up` may run after a refused restore:\n%s", calls)
	}
	if !strings.Contains(out, "the stack was NOT started") {
		t.Fatalf("the refusal must say the stack was not started:\n%s", out)
	}
	if !strings.Contains(calls, "final:resume-marker-present") {
		t.Fatalf("the resume marker must survive a refused start:\n%s", calls)
	}
}

// The docker-upgrade recovery path re-holds the packages and retries the start
// through the same refusal; it never downgrades or builds.
func TestOSUpdateDocker_RefusedRestoreIsRecoveredWithoutUp(t *testing.T) {
	out, calls, code := runOSUpdateDocker(t, "FAIL_CLAMAV_IMAGE=1")
	if code == 0 {
		t.Fatalf("a refused sidecar restore after an engine upgrade must fail:\n%s", out)
	}
	if !strings.Contains(out, "Docker upgrade FAILED") || !strings.Contains(calls, "apt-mark hold") {
		t.Fatalf("the failure must reach the existing recovery path (holds restored):\n%s\n%s", out, calls)
	}
	if strings.Contains(calls, "docker compose up") {
		t.Fatalf("no `compose up` may run after a refused restore:\n%s", calls)
	}
}
