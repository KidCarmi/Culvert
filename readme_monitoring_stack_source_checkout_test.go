package main

// readme_monitoring_stack_source_checkout_test.go — the README's "Monitoring
// stack (optional)" quick-start section is unreachable from the very install
// path the same README recommends first: the one-line installer
// (scripts/install.sh), which provisions /srv/culvert WITHOUT cloning the
// source repo (README.md's own "no source checkout needed" description of
// step 2, mirrored in scripts/install.sh's header comment).
//
// The source-free bundle is a closed, tested contract
// (deploy_bundle_contract_test.go / TestProxyImageShipsDeployBundle): the
// Dockerfile's /app/deploy COPY lines ship only docker-compose.yml,
// docker-compose.maint-agent.yml, and packaging/ — never
// docker-compose.monitoring.yml. Independently, .dockerignore excludes the
// whole `deploy` directory from the build context, so even
// deploy/prometheus.yml and deploy/grafana/{dashboards,datasources} — the
// two bind-mounts docker-compose.monitoring.yml requires — never reach the
// image at all, let alone the bundle.
//
// So an operator who follows the README's recommended one-line install and
// then follows its "Monitoring stack (optional)" section verbatim runs
// `docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d`
// from /srv/culvert, where NEITHER docker-compose.monitoring.yml nor the
// deploy/ assets it references exist. Compose fails outright on a
// missing-file error. The monitoring stack only actually works from the
// separately-documented "Docker (manual)" path, which `git clone`s the full
// repository.
//
// This test does not touch the extraction contract (that would be a change
// to the installer's behavior). It pins the much smaller, correct fix: the
// README must tell the operator, at the point of the instruction, that this
// section needs a source checkout — exactly like the "Docker (manual)"
// section already has one.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestMonitoringStackDocumentsSourceCheckoutRequirement(t *testing.T) {
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	d := string(dockerfile)

	dockerignore, err := os.ReadFile(".dockerignore")
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	deployDirIgnored := false
	for _, line := range strings.Split(string(dockerignore), "\n") {
		if strings.TrimSpace(line) == "deploy" {
			deployDirIgnored = true
			break
		}
	}

	// If a future change starts shipping docker-compose.monitoring.yml (and
	// its deploy/ dependencies) inside the /app/deploy bundle, the
	// source-checkout caveat this test requires would no longer be accurate
	// and should be reconsidered along with removing it — not enforced here.
	if strings.Contains(d, "docker-compose.monitoring.yml") && !deployDirIgnored {
		t.Skip("docker-compose.monitoring.yml (and its deploy/ assets) now appear reachable from the " +
			"source-free bundle; the source-checkout caveat this test pins may no longer be needed")
	}

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	r := string(readme)

	header := regexp.MustCompile(`(?m)^#{2,3} Monitoring stack`)
	loc := header.FindStringIndex(r)
	if loc == nil {
		t.Fatal("README.md has no \"Monitoring stack\" section")
	}
	rest := r[loc[1]:]
	nextHeading := regexp.MustCompile(`(?m)^(#{1,6} |---\s*$)`)
	if end := nextHeading.FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}

	if !strings.Contains(strings.ToLower(rest), "source checkout") {
		t.Fatalf("README.md's \"Monitoring stack\" section does not warn that it requires a source "+
			"checkout. scripts/install.sh's recommended one-line install provisions /srv/culvert "+
			"without cloning the source repo, and its image-extracted /app/deploy bundle ships only "+
			"docker-compose.yml, docker-compose.maint-agent.yml, and packaging/ (see "+
			"deploy_bundle_contract_test.go) — docker-compose.monitoring.yml and the "+
			"deploy/prometheus.yml + deploy/grafana assets it bind-mounts are never present there. "+
			"An operator who follows the quick-start install and then this section verbatim gets a "+
			"missing-file failure from `docker compose`. Section text:\n%s", rest)
	}
}
