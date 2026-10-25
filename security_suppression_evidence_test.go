package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStaticArtifactEvidence(t *testing.T) {
	// #nosec G204 -- fixed repository evidence check; its fixtures are built in a temporary directory and never executed.
	cmd := exec.CommandContext(t.Context(), "python3", filepath.Join(pkgSourceDir(), ".github", "scripts", "test", "security-evidence-test.py"), "ArtifactEvidenceTests")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("artifact evidence: %v\n%s", err, output)
	}
}
