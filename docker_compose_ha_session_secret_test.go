package main

// docker_compose_ha_session_secret_test.go — deployment-artifact contract for
// CULVERT_SESSION_SECRET passthrough in docker-compose.ha.yml.
//
// session.go:initSessionSecret() reads the HMAC session-signing key from the
// CULVERT_SESSION_SECRET environment variable. docs/OPERATIONS.md §3 ("For
// multi-node deployments set CULVERT_SESSION_SECRET ... on every node so
// admin sessions are valid cluster-wide") and
// docs/enterprise/ENTERPRISE-PREREQUISITES.md both document it as required
// for clustered/HA deployments. docker-compose.ha.yml is Culvert's dedicated
// multi-node file (CP + Standby + DP workers, see its own header comment) —
// exactly the deployment this requirement targets.
//
// docker-compose.yml (the single-node quick-start file) already forwards
// CULVERT_SESSION_SECRET into the proxy container (see
// docker_compose_session_secret_test.go, fixed by a prior regression). That
// fix was never carried over to docker-compose.ha.yml's proxy service: the
// `environment:` block forwards CP_CERT/CP_KEY/CP_CA/HA_JOIN/HA_TOKEN/
// CULVERT_CA_PASSPHRASE/CULVERT_LOG_PASSPHRASE but not
// CULVERT_SESSION_SECRET. Docker Compose only injects variables that are
// explicitly named in a service's `environment:` (or `env_file:`) section,
// so setting CULVERT_SESSION_SECRET in the host shell/.env per the
// documented HA setup has no effect on the container — every CP/Standby
// node generates its own random signing key on every restart
// (session.go:38-56), and admin sessions never carry over across nodes or
// restarts as documented.
import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestDockerComposeHAForwardsSessionSecretEnv proves that the proxy
// service's environment block in docker-compose.ha.yml forwards
// CULVERT_SESSION_SECRET from the host/.env into the container, the same
// way it already forwards CULVERT_CA_PASSPHRASE and CULVERT_LOG_PASSPHRASE.
// Without this, following docs/OPERATIONS.md §3's documented multi-node
// setup is silently ineffective on docker-compose.ha.yml.
func TestDockerComposeHAForwardsSessionSecretEnv(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.ha.yml")
	if err != nil {
		t.Fatalf("read docker-compose.ha.yml: %v", err)
	}
	s := string(compose)

	// Isolate the proxy service block: from "\n  proxy:" up to the next
	// top-level (2-space-indented) service header, mirroring
	// docker_compose_session_secret_test.go's scoping approach.
	proxyHeader := regexp.MustCompile(`(?m)^ {2}proxy:`)
	loc := proxyHeader.FindStringIndex(s)
	if loc == nil {
		t.Fatal("docker-compose.ha.yml has no top-level `proxy:` service")
	}
	rest := s[loc[1]:]
	nextService := regexp.MustCompile(`(?m)^ {2}[a-zA-Z0-9_-]+:`)
	if end := nextService.FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}

	// Require an ACTIVE forwarding entry, not just the variable name
	// anywhere in the block: a commented-out line or a hardcoded
	// non-forwarding value would satisfy a bare substring match without
	// actually passing the host/.env value through.
	activeForward := regexp.MustCompile(`(?m)^\s*-\s*CULVERT_SESSION_SECRET=\$\{CULVERT_SESSION_SECRET:-\}\s*$`)
	if !activeForward.MatchString(rest) {
		t.Fatalf("docker-compose.ha.yml proxy service `environment:` block does not have an active "+
			"`- CULVERT_SESSION_SECRET=${CULVERT_SESSION_SECRET:-}` entry (found CA_PASSPHRASE=%v, "+
			"LOG_PASSPHRASE=%v) — session.go reads this env var directly and docs/OPERATIONS.md §3 "+
			"instructs operators to set it on every node for multi-node deployments, but Compose "+
			"never injects an env var into the container unless it is actively named (uncommented, "+
			"interpolated) in the service's `environment:` block, so the documented HA setup "+
			"silently does nothing on docker-compose.ha.yml",
			strings.Contains(rest, "CULVERT_CA_PASSPHRASE"), strings.Contains(rest, "CULVERT_LOG_PASSPHRASE"))
	}
}
