package main

// install_script_is_fresh_deployment_test.go — regression coverage for the
// is_fresh_deployment() helper in scripts/install.sh, which gates whether a
// brand-new install also gets the SSL-inspection CA private key encrypted at
// rest (setup_at_rest_encryption only encrypts the CA key on a "fresh"
// deployment, to avoid disturbing an existing CA bundle on re-runs).
//
// This extracts the REAL is_fresh_deployment() function body out of
// scripts/install.sh (rather than duplicating it here) and exercises it
// against a real Docker daemon, so the test tracks the actual installer
// script instead of a copy that can drift.

import (
	"os/exec"
	"strings"
	"testing"
)

// requireDockerForTest skips the test when no Docker daemon is reachable —
// this test exercises real `docker volume` behavior and cannot be
// meaningfully mocked without losing the point of the regression it guards.
func requireDockerForTest(t *testing.T) {
	t.Helper()
	if err := exec.CommandContext(t.Context(), "docker", "info").Run(); err != nil {
		t.Skip("docker daemon not reachable in this environment — skipping")
	}
}

// TestInstallScript_IsFreshDeployment_IgnoresUnrelatedProjectVolume proves
// that is_fresh_deployment() judges freshness for THIS install directory,
// not for the host as a whole. The current implementation runs a bare
// `docker volume ls` and pattern-matches any volume name ending in
// "proxy-data" anywhere on the host — with no scoping to the compose project
// being installed. A second, unrelated Culvert install (or any other compose
// stack that happens to declare a volume named "proxy-data") in a different
// directory on the same host makes a genuinely brand-new install directory
// misreport as "not fresh". That silently skips CA-key encryption on
// first install (setup_at_rest_encryption only encrypts
// CULVERT_CA_PASSPHRASE when is_fresh_deployment is true), leaving the
// SSL-inspection root CA private key unencrypted at rest by default.
func TestInstallScript_IsFreshDeployment_IgnoresUnrelatedProjectVolume(t *testing.T) {
	requireDockerForTest(t)
	fn := extractShellFunction(t, "scripts/install.sh", "is_fresh_deployment")

	// Simulate an unrelated compose project on the same host whose declared
	// volume also happens to be named "proxy-data" (e.g. a second Culvert
	// install living at a different path, or leftover volumes from a
	// previous install that was moved/reinstalled elsewhere).
	volName := "installscripttest_otherproject_proxy-data"
	rm := func() { exec.CommandContext(t.Context(), "docker", "volume", "rm", "-f", volName).Run() } //nolint:errcheck // best-effort cleanup
	rm()
	t.Cleanup(rm)

	createCmd := exec.CommandContext(t.Context(), "docker", "volume", "create", //nolint:gosec // fixed args, not user input
		"--label", "com.docker.compose.project=otherproject",
		"--label", "com.docker.compose.project.working_dir=/srv/unrelated-other-project",
		"--label", "com.docker.compose.volume=proxy-data",
		volName,
	)
	if out, err := createCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to create fixture volume: %v\n%s", err, out)
	}

	installDir := t.TempDir() // brand-new directory that never had a compose deployment

	script := fn + "\n" +
		"INSTALL_DIR='" + installDir + "'\n" +
		"if is_fresh_deployment; then echo FRESH; else echo NOTFRESH; fi\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) //nolint:gosec // fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}

	got := strings.TrimSpace(string(out))
	if got != "FRESH" {
		t.Fatalf("is_fresh_deployment() reported %q for a brand-new install dir (%s) just because an "+
			"UNRELATED project's volume (%s) ends in \"proxy-data\" — freshness must be scoped to this "+
			"install's own compose project, not matched against every volume on the host", got, installDir, volName)
	}
}

// TestInstallScript_IsFreshDeployment_TrueWhenNoVolumeExists is the baseline
// sanity check: with no proxy-data volume on the host at all, a brand-new
// install directory is correctly reported as fresh.
func TestInstallScript_IsFreshDeployment_TrueWhenNoVolumeExists(t *testing.T) {
	requireDockerForTest(t)
	fn := extractShellFunction(t, "scripts/install.sh", "is_fresh_deployment")

	installDir := t.TempDir()

	script := fn + "\n" +
		"INSTALL_DIR='" + installDir + "'\n" +
		"if is_fresh_deployment; then echo FRESH; else echo NOTFRESH; fi\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) //nolint:gosec // fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}

	if got := strings.TrimSpace(string(out)); got != "FRESH" {
		t.Fatalf("is_fresh_deployment() = %q, want FRESH when no proxy-data volume exists on the host", got)
	}
}

// TestInstallScript_IsFreshDeployment_FalseForOwnExistingVolume proves the
// fix doesn't over-correct: when THIS install directory already has its own
// proxy-data volume (a real re-run against an existing deployment), it must
// still report "not fresh" so the CA passphrase is left untouched.
func TestInstallScript_IsFreshDeployment_FalseForOwnExistingVolume(t *testing.T) {
	requireDockerForTest(t)
	fn := extractShellFunction(t, "scripts/install.sh", "is_fresh_deployment")

	installDir := t.TempDir()
	volName := "installscripttest_own_proxy-data"
	rm := func() { exec.CommandContext(t.Context(), "docker", "volume", "rm", "-f", volName).Run() } //nolint:errcheck // best-effort cleanup
	rm()
	t.Cleanup(rm)

	createCmd := exec.CommandContext(t.Context(), "docker", "volume", "create", //nolint:gosec // fixed args, not user input
		"--label", "com.docker.compose.project=culvert",
		"--label", "com.docker.compose.project.working_dir="+installDir,
		"--label", "com.docker.compose.volume=proxy-data",
		volName,
	)
	if out, err := createCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to create fixture volume: %v\n%s", err, out)
	}

	script := fn + "\n" +
		"INSTALL_DIR='" + installDir + "'\n" +
		"if is_fresh_deployment; then echo FRESH; else echo NOTFRESH; fi\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) //nolint:gosec // fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}

	if got := strings.TrimSpace(string(out)); got != "NOTFRESH" {
		t.Fatalf("is_fresh_deployment() = %q, want NOTFRESH when this install dir's own proxy-data volume already exists", got)
	}
}
