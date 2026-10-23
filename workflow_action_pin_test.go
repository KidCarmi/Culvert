package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Repository-wide supply-chain wall for GitHub Actions refs.
//
// WHY THIS IS A SECURITY GATE AND NOT HOUSEKEEPING. A `uses:` ref is the trust
// root of everything a step then does. A tag — `@v6`, `@v7.0.0` — is a MUTABLE
// pointer: whoever controls the upstream repository (or anyone who compromises
// it) can move it to a different commit, and every subsequent run of this
// repository's CI silently executes that commit instead. A 40-character commit
// SHA cannot be moved, so pinning by SHA is what makes "the action we reviewed"
// and "the action that runs" the same statement.
//
// The blast radius here is specifically the MERGE GATES. pr-api-governance.yml
// is designed to be a REQUIRED status check in branch protection (its own header
// says so), and api-contract.yml guards the OpenAPI surface. An action that can
// change what runs inside those jobs can make a blocking gate report green
// without having gated anything — the same failure shape
// codeql_action_pin_test.go was written for, where a broken CodeQL pin produced
// a job that looked like it ran and executed zero queries. A gate that can be
// made to pass without running is worse than no gate, because it is trusted.
//
// This repository already settled the question: over a hundred `uses:` refs
// across .github/ are SHA-pinned with a `# vX.Y.Z` comment, and
// TestCodeQLActionPinsAreImmutable enforces it for the SAST workflow. That
// convention was enforced per-file, so two workflows drifted and kept drifting:
// the dependency sweep that moved `actions/setup-go@v7` to `@v7.0.0` touched
// those exact lines and left them mutable, because nothing failed. This test is
// the repository-wide version, so a new workflow — or a bump that rewrites a
// ref — cannot reintroduce a mutable one without a red check.
//
// Scope is every workflow and every composite action under .github/. Local
// refs (`./.github/actions/...`) are this repository's own tree at this
// repository's own commit and need no pin.

// actionUsesLine captures the ref of a `uses:` step: `uses: <owner>/<repo>[/<path>]@<ref>`.
// Submatch 1 is the target, 2 is the ref; usesTargetRef below is the only reader.
var actionUsesLine = regexp.MustCompile(`^uses:\s*([^\s@]+)@([^\s#]+)`)

// usesTargetRef parses one already-trimmed line into (target, ref, ok).
//
// It guards on the submatch COUNT rather than on nil. A nil check happens to be
// sufficient for the pattern as written, but both callers then index m[2], so a
// later edit that drops or reorders a capture group would turn a lint-clean
// regex change into a panic inside the gate meant to outlive such edits. One
// parser, one length guard, and neither test indexes a submatch itself.
func usesTargetRef(trimmed string) (target, ref string, ok bool) {
	m := actionUsesLine.FindStringSubmatch(trimmed)
	if len(m) < 3 {
		return "", "", false
	}
	return m[1], m[2], true
}

// actionSHARef matches an immutable 40-hex commit pin.
var actionSHARef = regexp.MustCompile(`^[0-9a-f]{40}$`)

// mutableRefExceptions lists the `uses:` targets that MUST NOT be SHA-pinned,
// with the reason. Each entry is a deliberate, reviewed exception — never a
// convenience — and the test fails if an exception stops being needed, so the
// list cannot quietly become a dumping ground.
//
//   - slsa-framework/slsa-github-generator: the generator verifies its OWN
//     provenance against the tag it was invoked by and REFUSES to run from a
//     commit SHA ("unsupported ref"). Upstream documents referencing it by
//     semver tag as a requirement, not a preference, so a SHA pin here would
//     disable release provenance rather than harden it. The tag is still
//     constrained: it must be an exact `vMAJOR.MINOR.PATCH`, never a moving
//     major alias such as `@v2`.
var mutableRefExceptions = map[string]string{
	"slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml": "the SLSA generator verifies its own provenance against the invoking tag and refuses a SHA ref",
}

// exactSemverTag matches the one tag shape an exception may carry: a fully
// qualified release, not a mutable `@v2`-style major alias.
var exactSemverTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// actionRefFiles returns every workflow and composite-action definition under
// .github/, so a new file is covered the moment it lands rather than when
// someone remembers to add it to a list.
func actionRefFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(".github", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".yml", ".yaml":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk .github: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no workflow or action definitions found under .github — the scan would pass vacuously")
	}
	sort.Strings(files)
	return files
}

// TestWorkflowActionRefsArePinnedBySHA fails when any third-party `uses:` ref
// in .github/ resolves through a mutable tag or branch instead of a commit SHA.
func TestWorkflowActionRefsArePinnedBySHA(t *testing.T) {
	usedExceptions := map[string]bool{}
	scanned := 0

	for _, path := range actionRefFiles(t) {
		raw, err := os.ReadFile(path) //nolint:gosec // repository-local path from the .github walk
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			target, ref, ok := usesTargetRef(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")))
			if !ok {
				continue
			}
			if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "docker://") {
				// This repository's own tree, or an image ref governed by the
				// registry digest rules rather than by an action pin.
				continue
			}
			scanned++
			if reason, exempt := mutableRefExceptions[target]; exempt {
				usedExceptions[target] = true
				if !exactSemverTag.MatchString(ref) {
					t.Errorf("%s:%d %s is exempt from SHA pinning (%s) but its ref %q is not an exact "+
						"vMAJOR.MINOR.PATCH release — a moving major alias is mutable even here",
						path, i+1, target, reason, ref)
				}
				continue
			}
			if !actionSHARef.MatchString(ref) {
				t.Errorf("REGRESSION: %s:%d uses %s@%s — a MUTABLE ref. Whoever controls that tag "+
					"controls what runs in this job, and this file feeds a merge gate. Pin the "+
					"40-char commit SHA with a `# %s` comment, as every other ref in .github/ does.",
					path, i+1, target, ref, ref)
			}
		}
	}

	if scanned == 0 {
		t.Fatal("scanned no third-party `uses:` refs — the pattern stopped matching and this gate is vacuous")
	}
	for target, reason := range mutableRefExceptions {
		if !usedExceptions[target] {
			t.Errorf("mutableRefExceptions still exempts %s (%s) but nothing under .github/ uses it — "+
				"remove the entry so the exception list stays an exact allowlist", target, reason)
		}
	}
}

// TestWorkflowActionSHAPinsCarryAVersionComment keeps SHA pins REVIEWABLE. A
// bare 40-hex ref is immutable but opaque: a reviewer cannot tell v7.0.1 from an
// arbitrary commit on a fork, and Dependabot needs the comment to know which
// release a pin currently names. Every pin in .github/ already carries one; this
// stops the next one from omitting it.
func TestWorkflowActionSHAPinsCarryAVersionComment(t *testing.T) {
	for _, path := range actionRefFiles(t) {
		raw, err := os.ReadFile(path) //nolint:gosec // repository-local path from the .github walk
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
			target, ref, ok := usesTargetRef(trimmed)
			if !ok || !actionSHARef.MatchString(ref) {
				continue
			}
			if !strings.Contains(trimmed, "#") {
				t.Errorf("%s:%d pins %s by SHA with no `# vX.Y.Z` comment — the pin is immutable but "+
					"unreviewable:\n\t%s", path, i+1, target, trimmed)
			}
		}
	}
}
