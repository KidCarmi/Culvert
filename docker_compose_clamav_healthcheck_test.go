package main

// docker_compose_clamav_healthcheck_test.go — deployment-artifact contract
// for the proxy service's ClamAV startup ordering in docker-compose.yml.
//
// docker-compose.yml documents two related promises about first-boot
// behavior:
//
//   - The top-of-file comment: "ClamAV downloads its virus definition
//     database on first boot (~250 MB)... (~2-5 min on first run...)".
//   - The proxy service's `depends_on` comment: "Wait for ClamAV to pass its
//     health check before starting the proxy... this just avoids
//     'unreachable' log noise on startup."
//
// Docker Compose's `depends_on` has two forms. The SHORT form (a plain list,
// `depends_on: [clamav]`) is equivalent to `condition: service_started` —
// it only waits for the dependency's container to start, not for its
// healthcheck to pass. Only the LONG form
// (`depends_on: { clamav: { condition: service_healthy } }`) actually waits
// for the healthcheck. docker-compose.yml's proxy service uses the short
// form, so on every fresh `docker compose up -d` (the documented quick
// start) the proxy starts immediately alongside ClamAV instead of waiting
// for it — producing exactly the "unreachable" log noise the comment says
// this is meant to avoid, for the full 2-5 minute first-boot signature
// download window.

import (
	"os"
	"regexp"
	"testing"
)

// TestDockerComposeProxyWaitsForClamAVHealth proves that the proxy service's
// `depends_on` entry for clamav in docker-compose.yml actually waits for
// ClamAV's healthcheck (long-form `condition: service_healthy`), matching
// the adjacent comment's documented behavior, rather than the Compose
// short-form list syntax which only waits for the container to start.
func TestDockerComposeProxyWaitsForClamAVHealth(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	s := string(compose)

	// Isolate the proxy service block: from "\n  proxy:" up to the next
	// top-level (2-space-indented) service header, mirroring the scoping
	// approach in docker_compose_session_secret_test.go /
	// install_script_compose_command_flags_scope_test.go.
	proxyHeader := regexp.MustCompile(`(?m)^ {2}proxy:`)
	loc := proxyHeader.FindStringIndex(s)
	if loc == nil {
		t.Fatal("docker-compose.yml has no top-level `proxy:` service")
	}
	rest := s[loc[1]:]
	nextService := regexp.MustCompile(`(?m)^ {2}[a-zA-Z0-9_-]+:`)
	if end := nextService.FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}

	// Require the long-form `depends_on: { clamav: { condition:
	// service_healthy } }` mapping, not just the string "clamav" appearing
	// under depends_on (which the short-form list also satisfies).
	healthyCondition := regexp.MustCompile(`(?ms)^\s*depends_on:\s*\n\s*clamav:\s*\n\s*condition:\s*service_healthy\s*$`)
	if !healthyCondition.MatchString(rest) {
		t.Fatalf("docker-compose.yml proxy service does not gate startup on ClamAV's healthcheck: " +
			"`depends_on` must use the long form (`clamav: {condition: service_healthy}`), not the " +
			"short-form list (`- clamav`), which only waits for the clamav container to START, not " +
			"for its healthcheck to pass. The proxy's own `depends_on` comment promises to 'wait for " +
			"ClamAV to pass its health check before starting the proxy' — the short form breaks that " +
			"promise on every fresh `docker compose up -d`, during the documented 2-5 minute first-boot " +
			"signature-download window.")
	}
}
