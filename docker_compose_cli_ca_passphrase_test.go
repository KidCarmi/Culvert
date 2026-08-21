package main

// docker_compose_cli_ca_passphrase_test.go — deployment-artifact contract for
// CULVERT_CA_PASSPHRASE passthrough into the `cli` service in
// docker-compose.yml.
//
// main.go's one-shot restore dispatch (handleOneShotCommands) reads the CA
// passphrase directly from the process environment via
// os.Getenv(caPassphraseEnv) ("CULVERT_CA_PASSPHRASE") and threads it into
// both runRestoreDryRun and runRestoreCommit, which route through
// validateCABundle (restore.go). Whenever the backup's `data/ca.bundle` is
// an encrypted PSCA envelope (ca.HasBundleMagic) — true for every backup
// taken from a deployment with SSL inspection enabled, since that feature
// requires CULVERT_CA_PASSPHRASE per README.md and docs/operator/*  —
// validateCABundle hard-fails restore (dry-run AND commit) with
// "encrypted bundle but no passphrase available (set CULVERT_CA_PASSPHRASE)"
// unless that env var is present in the `cli` container's process
// environment. docs/operator/docker-compose-backup-restore.md §4/§5/§6
// documents this exact validation step ("CA bundle decrypts (when present,
// with CULVERT_CA_PASSPHRASE)") but its worked examples forward only
// CULVERT_BACKUP_PASSPHRASE via `-e`.
//
// docker-compose.yml's `proxy` service explicitly forwards
// CULVERT_CA_PASSPHRASE (and CULVERT_LOG_PASSPHRASE, CULVERT_SESSION_SECRET)
// from the host/.env via `${VAR:-}` interpolation in its `environment:`
// block, but the `cli` service — sharing the same /data volume and the same
// backup/restore feature surface — has no `environment:` block at all.
// Compose only injects env vars a service's `environment:` (or `env_file:`)
// section explicitly names, so an operator who has CULVERT_CA_PASSPHRASE set
// in `.env` (required for the `proxy` service on any SSL-inspecting
// deployment) gets no passthrough to `cli`, and restore fails outright on
// exactly the deployment shape the feature exists to protect — even though
// the operator followed the documented `.env` setup and the documented
// restore invocation verbatim.

import (
	"os"
	"regexp"
	"testing"
)

// TestDockerComposeForwardsCAPassphraseToCLI proves that the `cli` service's
// environment block in docker-compose.yml forwards CULVERT_CA_PASSPHRASE
// from the host/.env into the container, the same way the `proxy` service
// already does. Without this, restoring a backup taken from an
// SSL-inspecting deployment fails both dry-run and commit with "encrypted
// bundle but no passphrase available" on the standard docker-compose
// deployment path, even though the operator supplied the documented
// CULVERT_CA_PASSPHRASE via `.env`.
func TestDockerComposeForwardsCAPassphraseToCLI(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	s := string(compose)

	// Isolate the cli service block: from "\n  cli:" up to the next
	// top-level (2-space-indented) key, mirroring the scoping approach in
	// docker_compose_session_secret_test.go /
	// install_script_compose_command_flags_scope_test.go.
	cliHeader := regexp.MustCompile(`(?m)^ {2}cli:`)
	loc := cliHeader.FindStringIndex(s)
	if loc == nil {
		t.Fatal("docker-compose.yml has no top-level `cli:` service")
	}
	rest := s[loc[1]:]
	nextKey := regexp.MustCompile(`(?m)^ {2}[a-zA-Z0-9_-]+:`)
	if end := nextKey.FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}

	// Require an ACTIVE forwarding entry, not just the variable name
	// anywhere in the block: a commented-out line or a hardcoded
	// non-forwarding value would satisfy a bare substring match without
	// actually passing the host/.env value through.
	activeForward := regexp.MustCompile(`(?m)^\s*-\s*CULVERT_CA_PASSPHRASE=\$\{CULVERT_CA_PASSPHRASE:-\}\s*$`)
	if !activeForward.MatchString(rest) {
		t.Fatalf("docker-compose.yml `cli` service `environment:` block does not have an active " +
			"`- CULVERT_CA_PASSPHRASE=${CULVERT_CA_PASSPHRASE:-}` entry — main.go's restore dispatch " +
			"reads CULVERT_CA_PASSPHRASE directly from the process environment, and restore " +
			"(dry-run and commit alike) hard-fails on any backup with an encrypted data/ca.bundle " +
			"(every backup from an SSL-inspecting deployment) unless the cli container inherits the " +
			"same CULVERT_CA_PASSPHRASE the operator already set in .env for the proxy service, but " +
			"Compose never injects an env var into a container unless it is actively named " +
			"(uncommented, interpolated) in that service's own `environment:` block")
	}
}
