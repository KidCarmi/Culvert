package main

// docker_compose_session_secret_test.go — deployment-artifact contract for
// CULVERT_SESSION_SECRET passthrough in docker-compose.yml.
//
// session.go:initSessionSecret() reads the HMAC session-signing key from the
// CULVERT_SESSION_SECRET environment variable (config.go:138-142 documents
// it as "Also readable from CULVERT_SESSION_SECRET"; docs/OPERATIONS.md §3
// tells operators to set it "on every node" so multi-node/HA admin sessions
// stay valid cluster-wide, and docs/enterprise/ENTERPRISE-PREREQUISITES.md
// lists it as a required prerequisite for clustered deployments).
//
// docker-compose.yml's proxy service explicitly forwards the two other
// env-sourced secrets — CULVERT_CA_PASSPHRASE and CULVERT_LOG_PASSPHRASE —
// from the host/.env into the container via `${VAR:-}` interpolation in its
// `environment:` block. CULVERT_SESSION_SECRET is missing from that list.
// Docker Compose only injects variables that are explicitly named in a
// service's `environment:` (or `env_file:`) section — setting
// CULVERT_SESSION_SECRET in the host shell or in `.env` has no effect on
// the container, since `.env` in the compose project directory is used only
// for `${...}` interpolation *within* the compose file itself. The result:
// there is no supported way to run the documented multi-node session-secret
// setup through the shipped quick-start docker-compose.yml — every node
// generates its own random key on every restart (session.go:38-56), so
// admin sessions never carry over across nodes or restarts as documented.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDockerComposeForwardsSessionSecretEnv proves that the proxy service's
// environment block in docker-compose.yml forwards CULVERT_SESSION_SECRET
// from the host/.env into the container, the same way it already forwards
// CULVERT_CA_PASSPHRASE and CULVERT_LOG_PASSPHRASE. Without this, setting
// CULVERT_SESSION_SECRET per docs/OPERATIONS.md §3 or
// docs/enterprise/ENTERPRISE-PREREQUISITES.md is silently ineffective on the
// standard docker-compose deployment path.
func TestDockerComposeForwardsSessionSecretEnv(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	s := string(compose)

	// Isolate the proxy service block: from "\n  proxy:" up to the next
	// top-level (2-space-indented) service header, mirroring the scoping
	// approach in install_script_compose_command_flags_scope_test.go.
	proxyHeader := regexp.MustCompile(`(?m)^  proxy:`)
	loc := proxyHeader.FindStringIndex(s)
	if loc == nil {
		t.Fatal("docker-compose.yml has no top-level `proxy:` service")
	}
	rest := s[loc[1]:]
	nextService := regexp.MustCompile(`(?m)^  [a-zA-Z0-9_-]+:`)
	if end := nextService.FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}

	if !strings.Contains(rest, "CULVERT_SESSION_SECRET") {
		t.Fatalf("docker-compose.yml proxy service `environment:` block does not forward "+
			"CULVERT_SESSION_SECRET (found CA_PASSPHRASE=%v, LOG_PASSPHRASE=%v) — "+
			"session.go reads this env var directly and docs/OPERATIONS.md §3 / "+
			"docs/enterprise/ENTERPRISE-PREREQUISITES.md instruct operators to set it on every "+
			"node, but Compose never injects an env var into the container unless it is named "+
			"in the service's `environment:` block, so the documented setup silently does nothing "+
			"on the standard docker-compose deployment",
			strings.Contains(rest, "CULVERT_CA_PASSPHRASE"), strings.Contains(rest, "CULVERT_LOG_PASSPHRASE"))
	}
}
