package main

// deploy_pinned_seed_test.go — deployment-artifact contract for the P1.4
// pinned proxy image tag.
//
// docker-compose.yml resolves the LOCAL-ONLY tag `culvert/proxy:pinned`
// (image selection happens at the sudo boundary; the tag is never published
// to a registry). Any host that runs `docker compose up` without the tag
// seeded fails with "pull access denied for culvert/proxy". The P1.4 rollout
// (June 2026) seeded the tag only in the maintenance-agent installer and
// missed scripts/install.sh, breaking every quick-start install until the
// seed step was added. This source-scan test pins the compose↔installer
// contract so the compose file can never again reference the pinned tag
// without the quick-start installer seeding it first.

import (
	"os"
	"strings"
	"testing"
)

func TestQuickStartInstallerSeedsPinnedTag(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	if !strings.Contains(string(compose), "image: culvert/proxy:pinned") {
		t.Skip("docker-compose.yml no longer pins culvert/proxy:pinned; contract not applicable")
	}

	install, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatalf("read scripts/install.sh: %v", err)
	}
	s := string(install)

	for _, want := range []string{
		`PINNED_TAG="culvert/proxy:pinned"`,  // the tag the compose file resolves
		`docker image inspect "$PINNED_TAG"`, // idempotence guard (already-seeded hosts untouched)
		`docker tag`,                         // registry / running-container seed path
		`CULVERT_PROXY_SEED_REF`,             // the ONLY supported offline path (preloaded image)
	} {
		if !strings.Contains(s, want) {
			t.Errorf("scripts/install.sh missing %q — docker-compose.yml resolves the LOCAL-ONLY tag culvert/proxy:pinned, so quick-start hosts fail `docker compose up` with pull-access-denied unless the installer seeds it", want)
		}
	}

	// No-local-build contract: the deployed binary and its docker-compose.yml MUST
	// come from the SAME published image (§6b extracts compose from the image's
	// /app/deploy bundle). Building the pinned tag from an arbitrary checkout — or
	// cloning HEAD to build — lets the compose drift a release ahead of the binary
	// and crash-loop the proxy ("flag provided but not defined"). Those paths were
	// removed; guard against their reintroduction.
	for _, forbidden := range []string{
		`docker build -t "$PINNED_TAG"`, // local build of the pinned tag
		`clone_source_into_install_dir`, // source-clone-then-build fallback
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("scripts/install.sh contains %q — Culvert must only deploy a signed PUBLISHED image (with a matching bundled compose), never a locally built one; offline hosts use CULVERT_PROXY_SEED_REF", forbidden)
		}
	}

	// The seed must run BEFORE the installer's `docker compose up`
	// invocation (`sudo docker compose up`, not the header-comment mention).
	seedIdx := strings.Index(s, `PINNED_TAG="culvert/proxy:pinned"`)
	upIdx := strings.Index(s, "sudo docker compose up")
	if seedIdx == -1 || upIdx == -1 {
		return // missing pieces already reported above
	}
	if seedIdx > upIdx {
		t.Errorf("scripts/install.sh seeds culvert/proxy:pinned at byte %d but runs `docker compose up` at byte %d — the seed must come first or the up fails with pull-access-denied", seedIdx, upIdx)
	}
}
