package main

// install_script_is_fresh_deployment_test.go — regression coverage for the
// is_fresh_deployment() helper in scripts/install.sh, which gates whether a
// brand-new install also gets the SSL-inspection CA private key encrypted at
// rest (setup_at_rest_encryption only encrypts the CA key on a "fresh"
// deployment, to avoid disturbing an existing CA bundle on re-runs).
//
// This extracts the REAL is_fresh_deployment() function body out of
// scripts/install.sh (rather than duplicating it here) and exercises it
// against a real Docker daemon and REAL `docker compose` invocations (not
// hand-crafted volume labels) — an earlier version of this test manually
// labeled a fixture volume with a "working_dir" label that real Compose
// never sets, which masked a bug where the fix couldn't recognize a
// genuinely-existing volume created by real Compose at all. Exercising the
// real `docker compose up`/`config` path is the only way to catch that.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const fixtureImage = "culvert-installtest-fixture:latest"

var (
	fixtureImageOnce sync.Once
	fixtureImageErr  error
)

// requireDockerForTest skips the test when no Docker daemon is reachable —
// this test exercises real `docker compose` behavior and cannot be
// meaningfully mocked without losing the point of the regression it guards.
func requireDockerForTest(t *testing.T) {
	t.Helper()
	if err := exec.CommandContext(t.Context(), "docker", "info").Run(); err != nil {
		t.Skip("docker daemon not reachable in this environment — skipping")
	}
}

// ensureFixtureImage prepares a minimal local image with no registry/network
// dependency (docker import from an empty tar stream) — just enough for
// `docker compose up` to create the declared volume/network. The resulting
// container has no command and is expected to fail to start; that happens
// AFTER volume creation, so it doesn't affect what this test checks.
func ensureFixtureImage(t *testing.T) {
	t.Helper()
	fixtureImageOnce.Do(func() {
		if exec.CommandContext(t.Context(), "docker", "image", "inspect", fixtureImage).Run() == nil {
			return // already prepared by an earlier test in this run
		}
		cmd := exec.CommandContext(t.Context(), "sh", "-c", //nolint:gosec // fixed script, not external/user input
			"tar cv --files-from /dev/null | docker import - "+fixtureImage)
		if out, err := cmd.CombinedOutput(); err != nil {
			fixtureImageErr = fmt.Errorf("prepare fixture image: %w: %s", err, out)
		}
	})
	if fixtureImageErr != nil {
		t.Fatalf("%v", fixtureImageErr)
	}
}

// uniqueProjectDir returns a fresh directory whose BASENAME is unique across
// the whole test binary run (t.Name() + suffix). This matters because Docker
// Compose derives its default project name from the working directory's
// basename alone — and t.TempDir() leaf directories are just sequential
// counters ("001", "002", ...) that restart per test, so two different
// tests' t.TempDir() results can share the same basename despite having
// different parents. That would make Compose treat them as the SAME
// project (and thus the same "proxy-data" volume), cross-contaminating
// these tests. A basename derived from the test name avoids that collision.
func uniqueProjectDir(t *testing.T, suffix string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), t.Name()+"-"+suffix)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	return dir
}

// writeFixtureCompose writes a minimal docker-compose.yml declaring the same
// "proxy-data" named volume as the real docker-compose.yml, into dir.
func writeFixtureCompose(t *testing.T, dir string) {
	t.Helper()
	content := "services:\n" +
		"  x:\n" +
		"    image: " + fixtureImage + "\n" +
		"    volumes:\n" +
		"      - proxy-data:/data\n" +
		"volumes:\n" +
		"  proxy-data:\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(content), 0o644); err != nil { //nolint:gosec // test fixture, not sensitive
		t.Fatalf("write fixture compose file: %v", err)
	}
}

// composeUpBestEffort runs `docker compose up -d` in dir to create its
// declared volumes/networks. Its exit code is ignored: the fixture image has
// no command, so the container itself always fails to start — but that
// happens after Compose has already created the volume, which is all these
// tests need.
func composeUpBestEffort(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "docker", "compose", "up", "-d")
	cmd.Dir = dir
	cmd.CombinedOutput() //nolint:errcheck // best-effort fixture setup, container start failure is expected
}

// composeDown tears down whatever composeUpBestEffort created. Deliberately
// uses context.Background(), NOT t.Context() — t.Context() is already
// canceled by the time t.Cleanup callbacks run (this always runs from one),
// so an exec.CommandContext(t.Context(), ...) here would silently no-op and
// leak the volume/network this test created.
func composeDown(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "docker", "compose", "down", "-v", "--remove-orphans")
	cmd.Dir = dir
	cmd.CombinedOutput() //nolint:errcheck // best-effort cleanup
}

// runIsFreshDeployment extracts the real is_fresh_deployment() function body
// and runs it with dir as the working directory — exactly how
// scripts/install.sh calls it (after `cd "$INSTALL_DIR"`).
func runIsFreshDeployment(t *testing.T, dir string) string {
	t.Helper()
	fn := extractShellFunction(t, "scripts/install.sh", "is_fresh_deployment")
	script := fn + "\nif is_fresh_deployment; then echo FRESH; else echo NOTFRESH; fi\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) //nolint:gosec // fixed test script content, not external/user input
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestInstallScript_IsFreshDeployment_IgnoresUnrelatedProjectVolume proves
// that is_fresh_deployment() judges freshness for THIS install directory,
// not for the host as a whole. A second, unrelated compose project on the
// same host (e.g. a second Culvert install in a different directory) that
// also declares a "proxy-data" volume must not make a genuinely brand-new
// install directory misreport as "not fresh" — that would silently skip
// CA-key encryption on first install (setup_at_rest_encryption only
// encrypts CULVERT_CA_PASSPHRASE when is_fresh_deployment is true), leaving
// the SSL-inspection root CA private key unencrypted at rest by default.
func TestInstallScript_IsFreshDeployment_IgnoresUnrelatedProjectVolume(t *testing.T) {
	requireDockerForTest(t)
	ensureFixtureImage(t)

	unrelatedDir := uniqueProjectDir(t, "unrelated")
	writeFixtureCompose(t, unrelatedDir)
	composeUpBestEffort(t, unrelatedDir) // creates unrelatedDir's OWN real "proxy-data" volume
	t.Cleanup(func() { composeDown(t, unrelatedDir) })

	installDir := uniqueProjectDir(t, "install") // brand-new directory that never had a compose deployment
	writeFixtureCompose(t, installDir)

	if got := runIsFreshDeployment(t, installDir); got != "FRESH" {
		t.Fatalf("is_fresh_deployment() reported %q for a brand-new install dir (%s) just because an "+
			"UNRELATED project's own proxy-data volume (created at %s) exists on the host — freshness must be "+
			"scoped to this install's own compose project", got, installDir, unrelatedDir)
	}
}

// TestInstallScript_IsFreshDeployment_TrueWhenNoVolumeExists is the baseline
// sanity check: with no proxy-data volume for this project on the host at
// all, a brand-new install directory is correctly reported as fresh.
func TestInstallScript_IsFreshDeployment_TrueWhenNoVolumeExists(t *testing.T) {
	requireDockerForTest(t)
	ensureFixtureImage(t)

	installDir := uniqueProjectDir(t, "install")
	writeFixtureCompose(t, installDir)

	if got := runIsFreshDeployment(t, installDir); got != "FRESH" {
		t.Fatalf("is_fresh_deployment() = %q, want FRESH when no proxy-data volume exists for this project", got)
	}
}

// TestInstallScript_IsFreshDeployment_FalseForOwnExistingVolume proves the
// fix doesn't over-correct: when THIS install directory already has its own,
// REAL Compose-created proxy-data volume (a real re-run against an existing
// deployment), it must still report "not fresh" so the CA passphrase is left
// untouched.
func TestInstallScript_IsFreshDeployment_FalseForOwnExistingVolume(t *testing.T) {
	requireDockerForTest(t)
	ensureFixtureImage(t)

	installDir := uniqueProjectDir(t, "install")
	writeFixtureCompose(t, installDir)
	composeUpBestEffort(t, installDir) // creates installDir's own real "proxy-data" volume
	t.Cleanup(func() { composeDown(t, installDir) })

	if got := runIsFreshDeployment(t, installDir); got != "NOTFRESH" {
		t.Fatalf("is_fresh_deployment() = %q, want NOTFRESH when this install dir's own proxy-data volume already exists", got)
	}
}
