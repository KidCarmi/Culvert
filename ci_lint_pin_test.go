package main

import (
	"os"
	"regexp"
	"testing"
)

// The advisory reviewdog lint (code-review.yml) and the blocking Fast-gate
// lint (pr-fast-gate.yml) must run the SAME golangci-lint. Left unpinned, the
// reviewdog action runs `latest`, whose newer rules post findings the gate
// passes — one inline comment per CI round, each a push. A bump is one change
// to both files.
func TestReviewdogLinterMatchesFastGatePin(t *testing.T) {
	gate, err := os.ReadFile(".github/workflows/pr-fast-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	review, err := os.ReadFile(".github/workflows/code-review.yml")
	if err != nil {
		t.Fatal(err)
	}
	gatePins := regexp.MustCompile(`golangci-lint/v2/cmd/golangci-lint@(v\d+\.\d+\.\d+)`).FindAllSubmatch(gate, -1)
	if len(gatePins) == 0 {
		t.Fatal("pr-fast-gate.yml installs no pinned golangci-lint; the selector stopped matching")
	}
	want := string(gatePins[0][1])
	for _, m := range gatePins {
		if string(m[1]) != want {
			t.Fatalf("pr-fast-gate.yml pins golangci-lint at both %s and %s", want, m[1])
		}
	}
	got := regexp.MustCompile(`(?m)^\s*golangci_lint_version:\s*(\S+)\s*$`).FindSubmatch(review)
	if got == nil {
		t.Fatalf("code-review.yml does not pin golangci_lint_version; the reviewdog action would run `latest` (want %s)", want)
	}
	if string(got[1]) != want {
		t.Fatalf("code-review.yml runs golangci-lint %s but the Fast gate pins %s", got[1], want)
	}
}
