package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
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
// ── Refs are enumerated by PARSING YAML, not by scanning lines ───────────────
//
// The first revision of this file matched `^uses:` on trimmed lines. That was a
// hole, and a measured one rather than a theoretical one (CodeRabbit on PR
// #1689, verified): YAML accepts a `uses` key written as `uses : x@v7`, as
// `"uses": x@v7` or `'uses': x@v7`, and as a flow mapping `- {uses: x@v7}`.
// All four are real `uses` keys that GitHub Actions honours, all four were
// invisible to that regex, and the other hundred matched refs kept the
// "scanned nothing" guard satisfied — so a mutable tag introduced in any of
// those spellings would have run in CI with this gate green. That is precisely
// the gate-that-looks-like-it-ran failure the header above is about, reached
// through the enumerator instead of around it.
//
// So the authoritative enumerator is the YAML parser, walking every mapping for
// a `uses` key wherever it appears — inside `steps`, and at `jobs.<id>.uses`
// for a reusable-workflow call, which is how the SLSA generator is invoked.
// It is the same choice release_workflow_invariants_test.go made for the same
// reason: "parsing the YAML structurally — NOT by fragile whole-file substring
// scans". Line numbers are recovered afterwards, for the message only, and
// never decide a verdict.
//
// Scope is every workflow and every composite action under .github/. Local
// refs (`./.github/actions/...`) are this repository's own tree at this
// repository's own commit and need no pin.

// actionSHARef matches an immutable 40-hex commit pin.
var actionSHARef = regexp.MustCompile(`^[0-9a-f]{40}$`)

// exactSemverTag matches the one tag shape an exception may carry: a fully
// qualified release, not a mutable `@v2`-style major alias.
var exactSemverTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// pinRevisionComment requires a SHA pin's trailing comment to IDENTIFY the
// pinned revision, so the pin is reviewable as well as immutable.
//
// `strings.Contains(line, "#")` was the first revision's check and it was
// wrong: it accepted `# TODO`, which names nothing, while this test's own name
// and failure message both promise the comment says which release the SHA is
// (CodeRabbit on PR #1689, verified).
//
// Two shapes are accepted because the tree legitimately holds both:
//
//   - a release tag, full or abbreviated — `# v7.0.1`, `# v4.4.1`, `# v3`,
//     `# v1`. Short forms are in real use (`# v3`, `# v4`, `# v1`), so
//     demanding vMAJOR.MINOR.PATCH here would fail pins that are correct.
//   - a branch plus the date it was pinned — `# main @ 2026-07-03`, which is
//     how ci.yml pins KidCarmi/Dependency-Obituary, an action with no releases.
//     It identifies the revision as precisely as a tag would and is not this
//     PR's to rewrite.
//
// `# TODO`, `# see above` and a bare `#` match neither.
var pinRevisionComment = regexp.MustCompile(`#\s*(v\d+(\.\d+){0,2}\b|[\w.\-/]+\s*@\s*\d{4}-\d{2}-\d{2})`)

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

// actionRef is one `uses:` reference discovered by the YAML walk.
type actionRef struct {
	file   string
	line   int // 0 when the raw text could not be located; messages only
	target string
	ref    string
	raw    string // the source line, for the comment check and the message
}

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

// collectUsesValues walks an already-decoded YAML tree and appends every value
// held under a `uses` key, at any depth. Depth-agnostic on purpose: a step's
// `uses`, a composite action's `uses` and a job-level reusable-workflow `uses`
// are the same trust decision and must not depend on this function knowing the
// schema that surrounds them.
func collectUsesValues(node any, out *[]string) {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			if strings.TrimSpace(key) == "uses" {
				if s, isStr := val.(string); isStr {
					*out = append(*out, strings.TrimSpace(s))
				}
			}
			collectUsesValues(val, out)
		}
	case map[any]any:
		for key, val := range v {
			if s, isStr := key.(string); isStr && strings.TrimSpace(s) == "uses" {
				if sv, isStr := val.(string); isStr {
					*out = append(*out, strings.TrimSpace(sv))
				}
			}
			collectUsesValues(val, out)
		}
	case []any:
		for i := range v {
			collectUsesValues(v[i], out)
		}
	}
}

// actionRefsIn parses one file and returns its third-party `uses:` refs.
//
// A local (`./…`) ref or a `docker://` image is skipped: the first is this
// repository's own tree at this commit, the second is governed by registry
// digest rules rather than by an action pin. A `uses` value with no `@` is
// skipped the same way — a local composite action may legitimately carry none.
func actionRefsIn(t *testing.T, path string) []actionRef {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // repository-local path from the .github walk
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var tree any
	if yerr := yaml.Unmarshal(raw, &tree); yerr != nil {
		// A file under .github/ that does not parse is itself a finding: this
		// gate cannot speak about refs it could not enumerate.
		t.Errorf("%s does not parse as YAML, so its action refs cannot be checked: %v", path, yerr)
		return nil
	}
	var values []string
	collectUsesValues(tree, &values)

	lines := strings.Split(string(raw), "\n")
	refs := make([]actionRef, 0, len(values))
	for _, val := range values {
		if strings.HasPrefix(val, "./") || strings.HasPrefix(val, "docker://") {
			continue
		}
		at := strings.LastIndex(val, "@")
		if at <= 0 || at == len(val)-1 {
			continue
		}
		r := actionRef{file: path, target: val[:at], ref: val[at+1:]}
		// Line number and source text for the message and the comment check.
		// Located, never trusted for the verdict: a miss leaves line 0 and an
		// empty raw, which the comment check treats as "no comment present".
		for i := range lines {
			if strings.Contains(lines[i], val) {
				r.line, r.raw = i+1, strings.TrimSpace(lines[i])
				break
			}
		}
		refs = append(refs, r)
	}
	return refs
}

// allActionRefs enumerates every third-party action ref under .github/.
func allActionRefs(t *testing.T) []actionRef {
	t.Helper()
	var all []actionRef
	for _, path := range actionRefFiles(t) {
		all = append(all, actionRefsIn(t, path)...)
	}
	if len(all) == 0 {
		t.Fatal("enumerated no third-party `uses:` refs — the YAML walk stopped finding them and this gate is vacuous")
	}
	return all
}

// where renders a ref's location for a failure message.
func (r actionRef) where() string {
	if r.line == 0 {
		return r.file
	}
	return fmt.Sprintf("%s:%d", r.file, r.line)
}

// TestWorkflowActionRefsArePinnedBySHA fails when any third-party `uses:` ref
// in .github/ resolves through a mutable tag or branch instead of a commit SHA.
func TestWorkflowActionRefsArePinnedBySHA(t *testing.T) {
	usedExceptions := map[string]bool{}

	for _, r := range allActionRefs(t) {
		if reason, exempt := mutableRefExceptions[r.target]; exempt {
			usedExceptions[r.target] = true
			if !exactSemverTag.MatchString(r.ref) {
				t.Errorf("%s %s is exempt from SHA pinning (%s) but its ref %q is not an exact "+
					"vMAJOR.MINOR.PATCH release — a moving major alias is mutable even here",
					r.where(), r.target, reason, r.ref)
			}
			continue
		}
		if !actionSHARef.MatchString(r.ref) {
			t.Errorf("REGRESSION: %s uses %s@%s — a MUTABLE ref. Whoever controls that tag "+
				"controls what runs in this job, and this file feeds a merge gate. Pin the "+
				"40-char commit SHA with a `# %s` comment, as every other ref in .github/ does.",
				r.where(), r.target, r.ref, r.ref)
		}
	}

	for target, reason := range mutableRefExceptions {
		if !usedExceptions[target] {
			t.Errorf("mutableRefExceptions still exempts %s (%s) but nothing under .github/ uses it — "+
				"remove the entry so the exception list stays an exact allowlist", target, reason)
		}
	}
}

// TestWorkflowActionSHAPinsCarryARevisionComment keeps SHA pins REVIEWABLE. A
// bare 40-hex ref is immutable but opaque: a reviewer cannot tell v7.0.1 from an
// arbitrary commit on a fork, and Dependabot needs the comment to know which
// release a pin currently names. Every pin in .github/ already carries one; this
// stops the next one from omitting it, or from naming nothing (see
// pinRevisionComment for why `# TODO` must not satisfy it).
func TestWorkflowActionSHAPinsCarryARevisionComment(t *testing.T) {
	for _, r := range allActionRefs(t) {
		if !actionSHARef.MatchString(r.ref) {
			continue
		}
		if !pinRevisionComment.MatchString(r.raw) {
			t.Errorf("%s pins %s by SHA with no comment naming the revision (`# v1.2.3` or "+
				"`# branch @ YYYY-MM-DD`) — the pin is immutable but unreviewable:\n\t%s",
				r.where(), r.target, r.raw)
		}
	}
}

// TestWorkflowActionRefEnumerationSeesEveryUsesKey is the negative control on
// the enumerator itself, and the reason this file no longer decides anything
// from a line scan.
//
// It asserts the YAML walk finds a `uses` ref in each of the spellings that
// defeated the previous line-based matcher. Without it, a future "simplification"
// back to a regex would restore the hole silently — the gate would still be
// green, because the refs it stopped seeing are exactly the ones it no longer
// reports on.
func TestWorkflowActionRefEnumerationSeesEveryUsesKey(t *testing.T) {
	for _, doc := range []string{
		"jobs:\n  j:\n    steps:\n      - uses: o/r@v1.2.3\n",
		"jobs:\n  j:\n    steps:\n      - uses : o/r@v1.2.3\n",
		"jobs:\n  j:\n    steps:\n      - \"uses\": o/r@v1.2.3\n",
		"jobs:\n  j:\n    steps:\n      - 'uses': o/r@v1.2.3\n",
		"jobs:\n  j:\n    steps:\n      - {uses: o/r@v1.2.3}\n",
		"jobs:\n  j:\n    uses: o/r@v1.2.3\n", // reusable-workflow call, no steps
	} {
		var tree any
		if err := yaml.Unmarshal([]byte(doc), &tree); err != nil {
			t.Errorf("fixture does not parse: %v\n%s", err, doc)
			continue
		}
		var got []string
		collectUsesValues(tree, &got)
		if len(got) != 1 || got[0] != "o/r@v1.2.3" {
			t.Errorf("enumerator missed a YAML-valid `uses` key: got %v, want [o/r@v1.2.3]\n%s", got, doc)
		}
	}
}
