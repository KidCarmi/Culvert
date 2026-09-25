package main

import (
	"os"
	"path"
	"path/filepath"
	"sort"
)

// Completeness is the part of the verdict that stands on its own: it proves the
// sharded evidence is COMPLETE against expectations derived from the current
// source and build configuration, WITHOUT an unsharded reference run.
//
// The unsharded comparison (compare.go) is kept as an audit mode, but an
// ordinary QA run does not have it — that is the point of sharding — so every
// check that used to rely on it has an independent source here:
//
//	root tests      the binary's own -test.list (plan/verifyPlan, unchanged)
//	root blocks     the build's empty-run profile of that same binary
//	lane packages   `go list ./...` minus the root (unchanged)
//	lane tests      the source enumerator (inventory.go), itself cross-checked
//	                against the root binary's -test.list on every run
//	lane blocks     the universe job's empty run of the lane's exact command
//
// Anything missing, truncated, foreign (another commit, toolchain, binary or
// kind of run) or incompatible (another coverage mode, another block set) is a
// problem, and a problem refuses the verdict.
type Completeness struct {
	RootUniverseBlocks int `json:"rootUniverseBlocks"`
	LaneUniverseBlocks int `json:"laneUniverseBlocks"`
	// SourceAgreesWithBinary records the enumerator's self-check on the root.
	SourceAgreesWithBinary bool `json:"sourceAgreesWithBinary"`
	LaneExpectedEntries    int  `json:"laneExpectedEntries"`
	LaneReportedEntries    int  `json:"laneReportedEntries"`
	// Explicit handling of legitimate edge packages: each is LISTED, so an
	// empty package is a recorded fact rather than an unnoticed zero.
	PackagesWithoutTests      []string `json:"packagesWithoutTests"`
	PackagesWithoutStatements []string `json:"packagesWithoutStatements"`
	// EmptyPackages have neither: `go test -cover` reports them as SKIPPED
	// ("[no test files]" with nothing to instrument), and that skip is
	// accepted for exactly these packages and no others.
	EmptyPackages []string `json:"emptyPackages"`
}

// empty is the set of legitimately empty lane packages.
func (c *Completeness) empty() map[string]bool {
	m := map[string]bool{}
	for _, p := range c.EmptyPackages {
		m[p] = true
	}
	return m
}

// checkRootUniverse: the merged root profile must carry EXACTLY the block set
// of the build's empty run of the same binary — keys and statement counts.
func checkRootUniverse(in verdictInput, rootProf *Profile, c *Completeness, fail func(string, ...any)) {
	if in.rootUniverse == nil {
		fail("root universe: missing — the build published no expected block set")
		return
	}
	c.RootUniverseBlocks = len(in.rootUniverse.Blocks)
	if rootProf == nil {
		fail("root universe: no root profile to check against it")
		return
	}
	if d := sameUniverse(in.rootUniverse, rootProf); d != "" {
		fail("root coverage is incomplete against the build's expected block set (expected vs merged): %s", d)
	}
}

// checkSourceAgreement runs the source enumerator's self-check: on the root
// package it must reproduce the binary's own -test.list exactly. If it cannot,
// its lane expectations cannot be trusted either.
func checkSourceAgreement(in verdictInput, c *Completeness, fail func(string, ...any)) {
	src, ok := in.source[in.manifest.Package]
	if !ok {
		fail("source inventory has no entry for the root package %s", in.manifest.Package)
		return
	}
	if d := agreesWithBinary(src, in.inv); d != "" {
		fail("source enumerator disagrees with the root binary's -test.list — lane test expectations are unreliable: %s", d)
		return
	}
	c.SourceAgreesWithBinary = true
}

// checkLaneEntries: every lane package reported exactly the top-level entries
// the source says it has — each once, none failed — and nothing else.
func checkLaneEntries(in verdictInput, res Results, c *Completeness, fail func(string, ...any)) {
	for _, p := range in.lanePkgs {
		src, ok := in.source[p]
		if !ok {
			fail("lane: no source inventory for %s", p)
			continue
		}
		c.LaneExpectedEntries += len(src.Tests)
		r := res[p]
		if r == nil {
			continue // already reported by checkLaneResults
		}
		want := map[string]bool{}
		for _, n := range src.Tests {
			want[n] = true
			t := r.Tests[n]
			switch {
			case t == nil:
				fail("lane: %s %s has no result — it never ran (or its events were lost)", p, n)
			case t.Reports != 1:
				fail("lane: %s %s reported %d results", p, n, t.Reports)
			case t.Status == statusFail:
				fail("lane: %s %s FAILED", p, n)
			}
		}
		for _, n := range sortedKeys(r.Tests) {
			c.LaneReportedEntries++
			if !want[n] {
				fail("lane: %s %s ran but is not in the package's source inventory", p, n)
			}
		}
	}
}

// judgeUniverse validates the lane universe's own evidence and returns its
// profile: same source/toolchain as the build, the universe KIND (not a lane
// directory passed off as one), the exact lane package set, every package
// built and passed with no test executed, and an atomic profile holding only
// lane-package blocks.
func judgeUniverse(in verdictInput, c *Completeness, fail func(string, ...any)) *Profile {
	for _, p := range in.lanePkgs {
		if src, ok := in.source[p]; ok && len(src.Tests) == 0 {
			c.PackagesWithoutTests = append(c.PackagesWithoutTests, p)
		}
	}
	var meta LaneMeta
	if err := readJSON(filepath.Join(in.universeDir, "meta.json"), &meta); err != nil {
		fail("universe: no usable evidence (%v) — failed, cancelled or never uploaded", err)
		return nil
	}
	if meta.Kind != universeRun.name {
		fail("universe: evidence is of kind %q, not %q", meta.Kind, universeRun.name)
	}
	checkPackageRunIdentity("universe", in, meta, fail)
	prof, err := readProfile(filepath.Join(in.universeDir, universeRun.profile))
	if err != nil {
		fail("universe: unusable coverage profile: %v", err)
		return nil
	}
	if prof.Mode != "atomic" {
		fail("universe: coverage mode %q, the lane is atomic", prof.Mode)
	}
	classifyUniverse(in, prof, c, fail)
	judgeUniverseEvents(in, c.empty(), fail)
	c.LaneUniverseBlocks = len(prof.Blocks)
	return prof
}

// classifyUniverse attributes every universe block to its lane package and
// records the packages with no instrumentable statement — and, of those, the
// ones with no tests either (EMPTY).
func classifyUniverse(in verdictInput, prof *Profile, c *Completeness, fail func(string, ...any)) {
	lane := map[string]bool{}
	for _, p := range in.lanePkgs {
		lane[p] = true
	}
	withBlocks := map[string]bool{}
	for k := range prof.Blocks {
		p := path.Dir(k.File)
		if !lane[p] {
			fail("universe: block %s belongs to no lane package", k)
			break
		}
		withBlocks[p] = true
	}
	noTests := map[string]bool{}
	for _, p := range c.PackagesWithoutTests {
		noTests[p] = true
	}
	for _, p := range in.lanePkgs {
		if withBlocks[p] {
			continue
		}
		c.PackagesWithoutStatements = append(c.PackagesWithoutStatements, p)
		if noTests[p] {
			c.EmptyPackages = append(c.EmptyPackages, p)
		}
	}
	sort.Strings(c.PackagesWithoutStatements)
	sort.Strings(c.EmptyPackages)
}

// judgeUniverseEvents: every lane package built and completed an empty run —
// passed, or (for an EMPTY package only) skipped — and no test executed.
func judgeUniverseEvents(in verdictInput, empty map[string]bool, fail func(string, ...any)) {
	f, err := os.Open(filepath.Join(in.universeDir, universeRun.events))
	if err != nil {
		fail("universe: no events (%v)", err)
		return
	}
	res, err := parseTestJSON(f)
	f.Close()
	if err != nil {
		fail("universe: %v", err)
		return
	}
	for _, p := range in.lanePkgs {
		r := res[p]
		switch {
		case r == nil:
			fail("universe: %s has no result", p)
		case r.Status == statusSkip && empty[p]:
		case r.Status != statusPass:
			fail("universe: %s did not build and pass an empty run (result %q)", p, r.Status)
		case len(r.Tests) > 0:
			fail("universe: %s executed %d test(s) in a run that selects none", p, len(r.Tests))
		}
	}
}

// checkPackageRunIdentity: a run over the non-root packages must come from the
// build's commit and toolchain, exit 0, and cover exactly `go list ./...`
// minus the root import path.
func checkPackageRunIdentity(what string, in verdictInput, meta LaneMeta, fail func(string, ...any)) {
	m := in.manifest
	if meta.Commit != m.Commit || meta.GoVersion != m.GoVersion || meta.GOOS != m.GOOS || meta.GOARCH != m.GOARCH {
		fail("%s: identity %s %s %s/%s differs from the build %s %s %s/%s", what, meta.Commit, meta.GoVersion, meta.GOOS, meta.GOARCH, m.Commit, m.GoVersion, m.GOOS, m.GOARCH)
	}
	if meta.ExitCode != 0 {
		fail("%s: go test exited %d", what, meta.ExitCode)
	}
	if meta.Excluded != m.Package || in.laneRoot != m.Package {
		fail("%s excluded %q (expected root %q per go list: %q)", what, meta.Excluded, m.Package, in.laneRoot)
	}
	if d := diffNames(in.lanePkgs, meta.Packages); d != "" {
		fail("%s package set differs from `go list ./...` minus the root: %s", what, d)
	}
}

// checkLaneUniverse: the lane's profile must carry EXACTLY the universe's
// block set. This is what makes an empty, truncated or partial lane profile a
// failure: a profile with no blocks at all used to be accepted.
func checkLaneUniverse(universe, laneProf *Profile, fail func(string, ...any)) {
	if universe == nil || laneProf == nil {
		return // each absence is reported where it was found
	}
	if d := sameUniverse(universe, laneProf); d != "" {
		fail("lane coverage is incomplete against the universe's expected block set (expected vs lane): %s", d)
	}
}
