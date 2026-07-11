package main

// deploy_bundle_contract_test.go — deployment-artifact contract for the
// source-free quick-start install (the /app/deploy image bundle).
//
// scripts/install.sh no longer clones the source repo: it pulls the public
// proxy image, seeds culvert/proxy:pinned, and extracts the deployment files
// (compose files + maintenance-agent packaging + agent binary) from the
// image's /app/deploy bundle. That only works if the Dockerfile actually
// ships the bundle and the .dockerignore lets the compose files into the
// build context. This source-scan test pins the three files to each other
// (mirrors deploy_pinned_seed_test.go) so none of them can drift alone:
// a missing COPY would silently send every fresh install down the legacy
// git-clone fallback, which requires the source repo to be publicly
// readable — the exact dependency the bundle exists to remove.

import (
	"os"
	"strings"
	"testing"
)

func TestProxyImageShipsDeployBundle(t *testing.T) {
	install, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatalf("read scripts/install.sh: %v", err)
	}
	s := string(install)
	if !strings.Contains(s, "/app/deploy") {
		t.Skip("scripts/install.sh no longer extracts /app/deploy; contract not applicable")
	}

	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	d := string(dockerfile)

	// The runtime image must carry everything extract_deploy_bundle and
	// extract_bundled_maint_bin expect to find under /app/deploy (WORKDIR
	// is /app, so the COPY destinations are ./deploy/...).
	for _, want := range []string{
		"AS maintbuilder", // static agent binary built from cmd/culvert-maint
		"COPY --chown=proxy:proxy docker-compose.yml docker-compose.maint-agent.yml ./deploy/",
		"COPY --chown=proxy:proxy packaging/ ./deploy/packaging/",
		"COPY --from=maintbuilder --chown=proxy:proxy /culvert-maint ./deploy/bin/culvert-maint",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("Dockerfile missing %q — scripts/install.sh extracts the /app/deploy bundle for source-free installs; without it every fresh install falls back to a git clone of the (possibly private) source repo", want)
		}
	}
}

func TestDockerignoreAdmitsComposeFilesForBundle(t *testing.T) {
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), "./deploy/") {
		t.Skip("Dockerfile no longer ships a deploy bundle; contract not applicable")
	}

	ignore, err := os.ReadFile(".dockerignore")
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	for _, line := range strings.Split(string(ignore), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "docker-compose*.yml" || trimmed == "docker-compose.yml" ||
			trimmed == "packaging" || trimmed == "packaging/" {
			t.Errorf(".dockerignore excludes %q, but the Dockerfile COPYs it into the /app/deploy bundle — the image build would fail (or silently ship a stale bundle via a cached layer)", trimmed)
		}
	}
}

func TestInstallerPrefersBundledAgentBinary(t *testing.T) {
	install, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatalf("read scripts/install.sh: %v", err)
	}
	s := string(install)
	if !strings.Contains(s, "/app/deploy") {
		t.Skip("scripts/install.sh no longer extracts /app/deploy; contract not applicable")
	}

	for _, want := range []string{
		// Source-free provisioning: system path reachable by the unprivileged
		// agent user — the fix for "Agent unreachable" on 0700-home installs.
		`INSTALL_DIR="${CULVERT_DIR:-/srv/culvert}"`,
		// Bundle extraction happens via docker create/cp of the PINNED tag,
		// so the extracted files always match the image the stack runs.
		`extract_deploy_bundle`,
		`extract_bundled_maint_bin`,
		`docker cp "$cid:/app/deploy/.`,
		`docker cp "$cid:/app/deploy/bin/culvert-maint"`,
		// The agent installs from the image bundle FIRST (survives the source
		// repo / release assets going private), positional-binary form.
		`bash "$maint_installer" "$bundled_bin"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("scripts/install.sh missing %q — the source-free install contract (image deploy bundle → /srv/culvert) is broken", want)
		}
	}
}

// TestPackagingBundleIsComplete pins that the packaging/ tree the Dockerfile
// copies into the bundle actually contains every file the maintenance-agent
// installer hard-requires at run time (it dies on a missing packaging file).
func TestPackagingBundleIsComplete(t *testing.T) {
	for _, f := range []string{
		"packaging/culvert-maint/install.sh",
		"packaging/culvert-maint/config.example.toml",
		"packaging/systemd/culvert-maint.service",
		"packaging/sudoers/culvert-maint",
	} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s missing: %v — packaging/culvert-maint/install.sh requires it, so the extracted deploy bundle could not install the agent", f, err)
		}
	}
}
