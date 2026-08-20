package main

import (
	"os"
	"regexp"
	"testing"
)

// TestDockerComposeHA_EnrollURLExampleMatchesParser pins docker-compose.ha.yml's
// documented ENROLL_URL example against the real `--enroll` flag parser
// (parseEnrollURL, dp_enrollment.go). Both real generators of an enrollment URL
// — the cluster-join command shown by the GUI (ui_cluster.go's apiClusterHA
// handler) and the onboarding curl script (bootstrap.go) — emit the shape
// "culvert://enroll/<cp-addr>/<token>?ca-fp=...". An operator who instead
// follows docker-compose.ha.yml's own hand-written example verbatim must land
// on the same shape, or a Data Plane worker set up by hand can never enroll
// against a real, working Control Plane.
func TestDockerComposeHA_EnrollURLExampleMatchesParser(t *testing.T) {
	data, err := os.ReadFile("docker-compose.ha.yml")
	if err != nil {
		t.Fatalf("read docker-compose.ha.yml: %v", err)
	}
	re := regexp.MustCompile(`Usage: ENROLL_URL=(\S+)`)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Fatal("docker-compose.ha.yml no longer documents an ENROLL_URL usage example — update this test")
	}
	example := string(m[1])

	info, err := parseEnrollURL(example)
	if err != nil {
		t.Fatalf("documented ENROLL_URL example %q does not parse: %v", example, err)
	}
	if info.CPAddr != "cp:50051" {
		t.Errorf("documented example %q resolves to CPAddr=%q, want %q (the placeholder host:port must land in CPAddr, not get swallowed into the token)",
			example, info.CPAddr, "cp:50051")
	}
	if info.Token != "TOKEN" {
		t.Errorf("documented example %q resolves to Token=%q, want %q",
			example, info.Token, "TOKEN")
	}
}
