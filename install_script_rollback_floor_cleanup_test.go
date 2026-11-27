package main

// install_script_rollback_floor_cleanup_test.go — regression coverage for the
// anti-rollback floor staging in scripts/install.sh's seed_from_catalog().
//
// On a reinstall whose proxy-data volume survived, stage_rollback_floor copies
// /data/release_catalog_state.json into a throwaway "$INSTALL_DIR/.floor.XXXXXX"
// directory, records it in BOOTSTRAP_FLOOR_DIR, and seed_from_catalog's RETURN
// trap (cleanup_bootstrap_verifier) is meant to delete it. seed_from_catalog
// calls it as `floordir="$(stage_rollback_floor)"`, though, so the assignment to
// BOOTSTRAP_FLOOR_DIR happens in the command-substitution subshell and never
// reaches the shell that runs the cleanup. Every catalog reinstall then leaves a
// .floor.* directory in the stack dir, one more per re-run.
//
// This runs the REAL seed_from_catalog, stage_rollback_floor,
// proxy_data_volume_mountpoint, cleanup_bootstrap_verifier and
// catalog_fetch_disabled bodies extracted from scripts/install.sh, with only
// the external edges stubbed: sudo/docker, the network clock probe, and the
// verifier download (a fake verifier that records its argv and prints a
// well-formed repo@sha256 reference).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_SeedFromCatalog_RemovesStagedRollbackFloor(t *testing.T) {
	const script = "scripts/install.sh"
	var fns []string
	for _, name := range []string{
		"catalog_fetch_disabled",
		"proxy_data_volume_mountpoint",
		"stage_rollback_floor",
		"cleanup_bootstrap_verifier",
		"seed_from_catalog",
	} {
		fns = append(fns, extractShellFunctionBraceAware(t, script, name))
	}

	root := t.TempDir()
	installDir := filepath.Join(root, "stack")
	volMount := filepath.Join(root, "volume")
	verifierDir := filepath.Join(installDir, ".verifier.test")
	argvLog := filepath.Join(root, "verifier-argv")
	for _, d := range []string{installDir, volMount, verifierDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// A surviving proxy-data volume carrying a floor file: the reinstall case.
	if err := os.WriteFile(filepath.Join(volMount, "release_catalog_state.json"), []byte(`{"catalog_version":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	verifier := filepath.Join(verifierDir, "culvert-linux-amd64")
	verifierSrc := "#!/bin/bash\nprintf '%s\\n' \"$@\" > " + argvLog + "\n" +
		"echo ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("a", 64) + "\n"
	if err := os.WriteFile(verifier, []byte(verifierSrc), 0o700); err != nil { // #nosec G306 -- test-owned executable stub
		t.Fatal(err)
	}

	harness := `set -euo pipefail
INSTALL_DIR=` + installDir + `
VOL_MOUNT=` + volMount + `
CATALOG_URL=""
INSTALL_CHANNEL=stable
PROXY_REPO=ghcr.io/kidcarmi/culvert
PINNED_TAG=culvert/proxy:pinned
BOOTSTRAP_VERIFIER_BIN=""
BOOTSTRAP_VERIFIER_DIR=""
BOOTSTRAP_FLOOR_DIR=""
info() { :; }
warn() { echo "warn: $*" >&2; }
warn_if_clock_skewed() { :; }
acquire_bootstrap_verifier() {
  BOOTSTRAP_VERIFIER_BIN=` + verifier + `
  BOOTSTRAP_VERIFIER_DIR=` + verifierDir + `
}
sudo() { "$@"; }
docker() {
  case "$1 $2" in
    "volume ls") echo culvert_proxy-data ;;
    "volume inspect") echo "$VOL_MOUNT" ;;
    *) return 0 ;; # pull / tag
  esac
}
` + strings.Join(fns, "\n") + `
seed_from_catalog
`
	cmd := exec.CommandContext(t.Context(), "bash", "-c", harness) // #nosec G204 -- fixed test script content, not external/user input
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed_from_catalog failed: %v\n%s", err, out)
	}

	// Positive control: the floor really was staged and handed to the verifier,
	// so the cleanup assertion below is about a directory that existed.
	argv, err := os.ReadFile(argvLog) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("fake verifier was not run: %v", err)
	}
	if !strings.Contains(string(argv), "--data-dir\n"+installDir+"/.floor.") {
		t.Fatalf("verifier was not given the staged floor dir; argv:\n%s", argv)
	}

	left, err := filepath.Glob(filepath.Join(installDir, ".floor.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("seed_from_catalog left the staged rollback-floor dir(s) behind in the stack dir: %v", left)
	}
	if _, err := os.Stat(verifierDir); !os.IsNotExist(err) {
		t.Fatalf("verifier dir should be removed by the same cleanup (control); stat err = %v", err)
	}
}
