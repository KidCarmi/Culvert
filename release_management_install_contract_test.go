package main

import (
	"os"
	"strings"
	"testing"
)

func readContractFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func activeConfigLines(in string) string {
	var out []string
	for _, line := range strings.Split(in, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestReleaseManagementComposeForwardsSafeEnvOnly(t *testing.T) {
	compose := readContractFile(t, "docker-compose.yml")
	for _, want := range []string{
		"CULVERT_RELEASE_PROXY_REPO=${CULVERT_RELEASE_PROXY_REPO:-}",
		"CULVERT_RELEASE_CATALOG_TRUST_KEYS=${CULVERT_RELEASE_CATALOG_TRUST_KEYS:-}",
		"CULVERT_RELEASE_CATALOG_VERIFY=${CULVERT_RELEASE_CATALOG_VERIFY:-}",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("docker-compose.yml must forward %s so release wiring env takes effect in clean installs", want)
		}
	}
	if strings.Contains(compose, "CULVERT_MAINT_AGENT_URL") {
		t.Error("stock docker-compose.yml must not set CULVERT_MAINT_AGENT_URL; it is valid only with the maint-agent socket override")
	}
}

func TestReleaseManagementComposeDoesNotExposeDockerSocketToProxy(t *testing.T) {
	compose := readContractFile(t, "docker-compose.yml")
	proxyIdx := strings.Index(compose, "\n  proxy:")
	if proxyIdx < 0 {
		t.Fatal("docker-compose.yml missing proxy service")
	}
	tail := compose[proxyIdx:]
	nextService := strings.Index(tail[len("\n  proxy:"):], "\n  cli:")
	if nextService > 0 {
		tail = tail[:len("\n  proxy:")+nextService]
	}
	tail = activeConfigLines(tail)
	if strings.Contains(tail, "docker.sock") {
		t.Fatal("proxy service must never mount /var/run/docker.sock or any Docker socket")
	}
}

func TestReleaseManagementMaintAgentOverrideIsNarrow(t *testing.T) {
	override := readContractFile(t, "docker-compose.maint-agent.yml")
	for _, want := range []string{
		"/run/culvert-maint:/run/culvert-maint:ro",
		`CULVERT_MAINT_AGENT_URL: "unix:///run/culvert-maint/culvert-maint.sock"`,
		"${CULVERT_MAINT_GID:?",
	} {
		if !strings.Contains(override, want) {
			t.Errorf("docker-compose.maint-agent.yml missing %q", want)
		}
	}
	activeOverride := activeConfigLines(override)
	for _, forbidden := range []string{"docker.sock", "/var/run/docker.sock", "/run/docker.sock", "privileged: true"} {
		if strings.Contains(activeOverride, forbidden) {
			t.Fatalf("maint-agent override must not expose broad host/Docker privileges; found %q", forbidden)
		}
	}
}

func TestReleaseManagementInstallerWiresFailClosed(t *testing.T) {
	install := readContractFile(t, "scripts/install.sh")
	for _, want := range []string{
		"CULVERT_SKIP_RELEASE_AGENT_WIRING",
		"rootless|userns",
		`proxy_mounts_docker_socket`,
		`patch_allow_peers_numeric_uid`,
		`[[ "$proxy_uid" == "0" ]]`,
		`CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" /usr/local/bin/culvert-maint`,
		`docker compose -f docker-compose.yml -f docker-compose.maint-agent.yml up -d`,
		`verify_maint_agent_health_as_proxy_uid`,
		`MAINT_AGENT_WIRED=1`,
	} {
		if !strings.Contains(install, want) {
			t.Errorf("scripts/install.sh missing release-management fail-closed wiring contract %q", want)
		}
	}
	for _, forbidden := range []string{
		`allow_peers = ["root"]`,
		`allow_peers = ["*"]`,
		`allow_peers = ["docker"]`,
	} {
		if strings.Contains(install, forbidden) {
			t.Fatalf("installer must not create broad allow_peers entry %q", forbidden)
		}
	}
}

func TestReleaseManagementInstallerDoesNotAutoSeedCatalog(t *testing.T) {
	install := readContractFile(t, "scripts/install.sh")
	for _, forbidden := range []string{
		"release_catalog/index.json",
		"release-catalog/index.json",
		"curl -fsSL https://raw.githubusercontent.com/KidCarmi/Culvert/main/release_catalog",
		"CULVERT_RELEASE_CATALOG_URL",
	} {
		if strings.Contains(install, forbidden) {
			t.Fatalf("installer must not auto-seed or hide a default release catalog source; found %q", forbidden)
		}
	}
}
