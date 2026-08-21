package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Anti-drift wall for the CodeQL SAST gate's action pins.
//
// github/codeql-action is a monorepo: init, analyze and upload-sarif are
// published from ONE release and are NOT independently compatible. The action
// refuses to analyse a database that a different version initialised —
//
//	Loaded a configuration file for version '4.37.3', but running version '4.37.4'
//	CodeQL job status was configuration error.
//
// — and that outcome is the dangerous one, because it is a CONFIGURATION ERROR,
// not a finding. The job goes red without ever running a query, so the gate
// stops detecting anything while still looking like it ran. Every CodeQL alert
// "verified fixed" in that window was verified against a scanner that never
// executed.
//
// This is not hypothetical: it shipped. Dependabot treats each sub-action path
// as its own ecosystem, so PR #1024 bumped ONLY analyze from 4.37.3 to 4.37.4
// and left init behind, breaking the gate on every subsequent PR until it was
// noticed by a human reading a job log. An earlier commit (`ci: align CodeQL
// action revisions`) shows the same split had already happened once before.
//
// A version comparison is not enough — the trailing `# v3` comments Dependabot
// leaves are stale and disagree with the actual release — so the invariant is
// pinned on the immutable thing: the commit SHA.

// codeQLActionPin matches a pinned `github/codeql-action/<sub>@<sha>` use.
var codeQLActionPin = regexp.MustCompile(`github/codeql-action/([a-z-]+)@([0-9a-f]{40})`)

// TestCodeQLActionRevisionsAreAligned fails when the CodeQL workflow pins its
// sub-actions to more than one revision.
func TestCodeQLActionRevisionsAreAligned(t *testing.T) {
	const path = ".github/workflows/codeql.yml"

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	// sha → the sub-actions pinned to it, so the failure names both sides.
	bySHA := map[string][]string{}
	for _, m := range codeQLActionPin.FindAllStringSubmatch(string(raw), -1) {
		sub, sha := m[1], m[2]
		bySHA[sha] = append(bySHA[sha], sub)
	}

	if len(bySHA) == 0 {
		t.Fatalf("%s pins no github/codeql-action steps by SHA — either the SAST gate was removed "+
			"or a step regressed to a mutable tag/branch ref (supply-chain hazard)", path)
	}
	if len(bySHA) == 1 {
		return
	}

	shas := make([]string, 0, len(bySHA))
	for sha := range bySHA {
		shas = append(shas, sha)
	}
	sort.Strings(shas)

	var b strings.Builder
	b.WriteString("CodeQL action revisions have drifted apart in " + path + ":\n")
	for _, sha := range shas {
		subs := bySHA[sha]
		sort.Strings(subs)
		b.WriteString("  " + sha + " → " + strings.Join(subs, ", ") + "\n")
	}
	b.WriteString("\ngithub/codeql-action ships init/analyze/upload-sarif from ONE release and they are not\n" +
		"cross-compatible: analyze rejects a database another version initialised and the job ends as a\n" +
		"CONFIGURATION ERROR — red, but with zero queries executed, so SAST coverage is silently lost.\n" +
		"Dependabot bumps each sub-action path independently, so this drifts on its own. Align every\n" +
		"github/codeql-action/* pin in this workflow to the same commit SHA.")
	t.Fatal(b.String())
}

// TestCodeQLActionPinsAreImmutable keeps the supply-chain half of the contract:
// a CodeQL step must never be re-pinned to a mutable ref. `@v3` or `@main`
// would let a compromised or merely broken upstream tag silently change what
// runs inside a job that has `security-events: write`.
func TestCodeQLActionPinsAreImmutable(t *testing.T) {
	for _, path := range []string{
		".github/workflows/codeql.yml",
		".github/workflows/security-release-gate.yml",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.Contains(trimmed, "uses:") || !strings.Contains(trimmed, "github/codeql-action/") {
				continue
			}
			if !codeQLActionPin.MatchString(trimmed) {
				t.Errorf("%s:%d pins a CodeQL action to a mutable ref — use a 40-char commit SHA:\n\t%s",
					path, i+1, trimmed)
			}
		}
	}
}
