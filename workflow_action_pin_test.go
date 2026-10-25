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
// ── Each occurrence is bound to its OWN line ─────────────────────────────────
//
// The revision-comment check reads the source line, because YAML discards
// comments. Binding a value to "the first line that contains it" was a second
// measured hole (CodeRabbit on PR #1689, verified): a file may use the SAME
// pinned action many times — `ci.yml` and `pr-fast-gate.yml` each carry 14
// `actions/checkout` steps, `qa-gate.yml` 11, and `pr-api-governance.yml`, which
// this very change edits, has two `actions/setup-go` steps. Every repeat
// resolved to the FIRST occurrence's line, so a later pin with no comment at all
// was checked against an earlier pin's `# v7.0.1` and passed. Reproduced by
// stripping the comment from the second `setup-go` in pr-api-governance.yml: the
// gate still reported ok. One ref is now emitted PER MATCHING LINE, so every
// occurrence is judged on its own text.
//
// ── Scope ────────────────────────────────────────────────────────────────────
//
// Every workflow and every composite action under .github/. Local refs
// (`./.github/actions/...`) are this repository's own tree at this repository's
// own commit and need no pin.
//
// A `docker://` ref is a container action and gets its own immutability rule —
// an image digest, not a commit SHA. It is checked rather than skipped
// (CodeRabbit on PR #1689): the first revision waved every `docker://` value
// through on the grounds that registry digest rules governed it, but those rules
// cover the RELEASE CATALOG's images, not a workflow's `uses`. Nothing in
// .github/ uses one today, so this closes a hole in the stated guarantee before
// it is exercised rather than after. See TestWorkflowDockerActionRefsArePinnedByDigest.

// actionSHARef matches an immutable 40-hex commit pin.
var actionSHARef = regexp.MustCompile(`^[0-9a-f]{40}$`)

// dockerDigestRef matches an immutable OCI image digest, the `docker://` form of
// the same guarantee a commit SHA gives a repository action.
var dockerDigestRef = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// dockerRefPrefix is the `uses:` scheme for a container action.
const dockerRefPrefix = "docker://"

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
// A local (`./…`) ref is skipped: it is this repository's own tree at this
// commit. Everything else is returned, INCLUDING a `docker://` container action
// and including a value with no `@` at all — `docker://alpine:latest` is exactly
// the mutable shape a gate must see, so "no @" cannot mean "skip".
//
// One ref is emitted PER MATCHING SOURCE LINE, not per YAML occurrence, so a
// file that uses the same pinned action fourteen times has each of those lines
// judged on its own comment instead of all fourteen inheriting the first one's.
// A value the YAML holds but whose text appears on NO line is returned with
// line 0 and an empty raw, which the comment check treats as "cannot verify"
// and refuses — the fail-closed direction, since the alternative is to pass a
// pin whose comment was never read.
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
	seen := map[string]bool{}
	for _, val := range values {
		if strings.HasPrefix(val, "./") || seen[val] {
			continue
		}
		seen[val] = true // distinct values only; the line walk below covers repeats
		target, ref := val, ""
		if at := strings.LastIndex(val, "@"); at > 0 && at < len(val)-1 {
			target, ref = val[:at], val[at+1:]
		}
		matched := false
		for i := range lines {
			if !strings.Contains(lines[i], val) {
				continue
			}
			matched = true
			refs = append(refs, actionRef{
				file: path, line: i + 1, target: target, ref: ref,
				raw: strings.TrimSpace(lines[i]),
			})
		}
		if !matched {
			refs = append(refs, actionRef{file: path, target: target, ref: ref})
		}
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

// spec renders the `uses:` value as written, so a ref with no `@` at all —
// `docker://alpine:latest` — is not reported with a dangling separator.
func (r actionRef) spec() string {
	if r.ref == "" {
		return r.target
	}
	return r.target + "@" + r.ref
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
		if strings.HasPrefix(r.target, dockerRefPrefix) {
			continue // container action: its own immutability rule, below
		}
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
			t.Errorf("REGRESSION: %s uses %s — a MUTABLE ref. Whoever controls that tag "+
				"controls what runs in this job, and this file feeds a merge gate. Pin the "+
				"40-char commit SHA with a `# %s` comment, as every other ref in .github/ does.",
				r.where(), r.spec(), r.ref)
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
		if r.line == 0 {
			t.Errorf("%s holds a SHA pin for %s that could not be located in the source text, so "+
				"its revision comment cannot be read — refusing rather than assuming one is present",
				r.file, r.target)
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

// TestWorkflowDockerActionRefsArePinnedByDigest holds a `docker://` container
// action to the same immutability standard as a repository action, by the means
// that applies to an image: a `@sha256:` digest rather than a commit SHA.
//
// WHY IT EXISTS WITH NOTHING TO CHECK. `.github/` currently contains no
// `docker://` ref, and the first revision of this gate skipped the scheme on the
// stated grounds that "registry digest rules" covered it. Those rules
// (release_catalog.go and its tests) govern the RELEASE CATALOG's published
// images — not what a workflow step pulls. So the gate's claim, that every
// third-party ref under .github/ is immutable, had a scheme-shaped hole in it:
// `uses: docker://alpine:latest` would have satisfied every applicable check.
//
// Writing the rule now, while the answer is "none", is cheap and is the only
// time it can be done without also having to fix a live ref. The fixture test
// below is what keeps this from being decoration: the real-file loop can be
// legitimately empty, so the FIXTURES are where the rule is proven to bite.
func TestWorkflowDockerActionRefsArePinnedByDigest(t *testing.T) {
	for _, r := range allActionRefs(t) {
		if !strings.HasPrefix(r.target, dockerRefPrefix) {
			continue
		}
		if !dockerDigestRef.MatchString(r.ref) {
			t.Errorf("REGRESSION: %s uses %s — a container action pinned by TAG, not by digest. "+
				"A tag is mutable in a registry exactly as it is in git, and the release catalog's "+
				"digest rules do not cover a workflow's `uses`. Pin it as "+
				"`%s…@sha256:<64 hex>`.", r.where(), r.spec(), dockerRefPrefix)
		}
	}
}

// TestWorkflowDockerDigestRuleBites proves the digest rule on fixtures, because
// the repository has no `docker://` ref for it to act on yet — without this the
// test above would pass vacuously for as long as that stays true, which is
// precisely how a rule written early rots before it is ever needed.
func TestWorkflowDockerDigestRuleBites(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name   string
		uses   string
		wantOK bool
	}{
		{"digest pinned", dockerRefPrefix + "alpine@" + digest, true},
		{"floating tag", dockerRefPrefix + "alpine:latest", false},
		{"pinned tag is still mutable", dockerRefPrefix + "alpine:3.21", false},
		{"no tag at all", dockerRefPrefix + "alpine", false},
		{"registry host with digest", dockerRefPrefix + "ghcr.io/o/i@" + digest, true},
		{"registry host with tag", dockerRefPrefix + "ghcr.io/o/i:v1", false},
		{"commit SHA is not an image digest", dockerRefPrefix + "alpine@3d3c42e5aac5ba805825da76410c181273ba90b1", false},
		{"short digest", dockerRefPrefix + "alpine@sha256:0123456789abcdef", false},
		{"uppercase digest", dockerRefPrefix + "alpine@SHA256:" + strings.Repeat("A", 64), false},
	} {
		doc := "jobs:\n  j:\n    steps:\n      - uses: " + tc.uses + "\n"
		var tree any
		if err := yaml.Unmarshal([]byte(doc), &tree); err != nil {
			t.Errorf("%s: fixture does not parse: %v", tc.name, err)
			continue
		}
		var values []string
		collectUsesValues(tree, &values)
		if len(values) != 1 {
			t.Errorf("%s: enumerator saw %v, want one value", tc.name, values)
			continue
		}
		ref := ""
		if at := strings.LastIndex(values[0], "@"); at > 0 && at < len(values[0])-1 {
			ref = values[0][at+1:]
		}
		if got := dockerDigestRef.MatchString(ref); got != tc.wantOK {
			t.Errorf("%s: %q → accepted=%v, want %v (ref %q)", tc.name, tc.uses, got, tc.wantOK, ref)
		}
	}
}
