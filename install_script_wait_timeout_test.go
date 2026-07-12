package main

// install_script_wait_timeout_test.go — contract test between docker-compose.yml's
// clamav healthcheck `start_period` and scripts/install.sh's `docker compose up
// --wait --wait-timeout`.
//
// scripts/install.sh brings the stack up with:
//
//	docker compose up -d --wait --wait-timeout 180
//
// `--wait` blocks until EVERY service with a healthcheck reports healthy (or
// exits) — that includes the clamav sidecar, even though the proxy only
// depends_on clamav for start ORDER (no `condition: service_healthy`) and
// tolerates ClamAV being unreachable at runtime (per-request retry; see
// docker-compose.yml's own comment on the proxy service and
// docs/operator/docker-compose-backup-restore.md). clamav's healthcheck
// declares `start_period: 300s` because, per its own comment, first boot
// downloads ~250 MB of virus signatures — on a modest-bandwidth host (e.g. a
// 10 Mbps link: 250 MB ≈ 200s; a 5 Mbps link: ≈ 400s) that download alone can
// exceed the installer's 180s wait budget.
//
// When that happens, `docker compose up --wait` returns non-zero purely
// because clamav hasn't finished downloading signatures yet — NOT because
// anything is actually broken (the proxy itself is healthy and serving
// traffic). scripts/install.sh's fallback path only adds ~90s more before
// calling error() and exiting 1, printing a scary "Culvert failed to start"
// diagnostic dump on a fresh install that would have succeeded if the script
// had simply waited a bit longer.
//
// This exact hazard is independently confirmed by
// test/e2e/install-lifecycle/docker-compose.override.yml, which stubs out
// the real clamav image specifically to avoid it in CI ("the real image
// downloads ~250 MB of virus signatures on first boot (slow, memory-hungry,
// 300s start_period)") — but that override never ships to operators, so a
// real quick-start install has no such escape hatch.
//
// This test pins the numeric relationship (wait-timeout must cover clamav's
// start_period) so the two files can't drift back out of sync, the same
// pattern deploy_pinned_seed_test.go uses for the compose↔installer tag
// contract.

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

func TestInstallScript_ComposeWaitTimeout_CoversClamAVStartPeriod(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	install, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatalf("read scripts/install.sh: %v", err)
	}

	spMatch := regexp.MustCompile(`start_period:\s*(\d+)s`).FindSubmatch(compose)
	if spMatch == nil {
		t.Fatal("docker-compose.yml: could not find a `start_period: <N>s` healthcheck setting (expected on the clamav service)")
	}
	startPeriod, err := strconv.Atoi(string(spMatch[1]))
	if err != nil {
		t.Fatalf("parse start_period: %v", err)
	}

	wtMatch := regexp.MustCompile(`--wait-timeout\s+(\d+)`).FindSubmatch(install)
	if wtMatch == nil {
		t.Fatal("scripts/install.sh: could not find `docker compose up ... --wait --wait-timeout <N>`")
	}
	waitTimeout, err := strconv.Atoi(string(wtMatch[1]))
	if err != nil {
		t.Fatalf("parse --wait-timeout: %v", err)
	}

	if waitTimeout < startPeriod {
		t.Errorf("scripts/install.sh --wait-timeout=%ds is less than docker-compose.yml clamav start_period=%ds — "+
			"`docker compose up --wait` waits on EVERY service with a healthcheck (including clamav, which the proxy "+
			"does not actually require to be healthy), so a fresh install on a modest-bandwidth host can legitimately "+
			"still be downloading ClamAV's ~250 MB signature database when the wait budget expires. The installer then "+
			"reports a hard failure (dump_compose_diagnostics + error(), exit 1) on a deployment that was working fine "+
			"and just needed more time. Raise --wait-timeout to at least cover start_period.",
			waitTimeout, startPeriod)
	}
}
