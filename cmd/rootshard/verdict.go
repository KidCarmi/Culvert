package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// shardDirName is the per-shard evidence directory (and artifact name suffix).
func shardDirName(i int) string { return fmt.Sprintf("shard-%d", i) }

// Verdict is the pilot's machine-readable outcome.
type Verdict struct {
	OK       bool          `json:"ok"`
	Problems []string      `json:"problems"`
	Package  string        `json:"package"`
	Commit   string        `json:"commit"`
	Shards   []ShardReport `json:"shards"`
	Lane     LaneReport    `json:"lane"`
	Merged   coverageStats `json:"mergedCoverage"`
	Root     coverageStats `json:"rootCoverage"`
	Profiles int           `json:"profilesMerged"`
	// Completeness is what makes this verdict stand WITHOUT an unsharded
	// reference: see completeness.go.
	Completeness Completeness `json:"completeness"`
}

// ShardReport summarises one shard's evidence.
type ShardReport struct {
	Index       int     `json:"index"`
	Entries     int     `json:"entries"`
	Chunks      int     `json:"chunks"`
	Passed      int     `json:"passed"`
	Skipped     int     `json:"skipped"`
	TestSeconds float64 `json:"testSeconds"`
	Estimated   float64 `json:"estimatedSeconds"`
}

// LaneReport summarises the non-root package lane.
type LaneReport struct {
	Packages int                `json:"packages"`
	Seconds  float64            `json:"seconds"`
	Elapsed  map[string]float64 `json:"packageElapsed"`
}

// verdictInput locates every piece of evidence and every independent
// expectation it is judged against.
type verdictInput struct {
	plan         Plan
	manifest     Manifest
	inv          Inventory
	listSum      string
	shardsDir    string
	laneDir      string
	universeDir  string
	lanePkgs     []string
	laneRoot     string
	rootUniverse *Profile
	// source is the source-enumerated inventory of the root AND every lane
	// package, from the verdict's own checkout of the build's commit.
	source map[string]PkgInventory
}

// judge checks all evidence and merges coverage. It collects EVERY problem
// rather than stopping at the first, so one run shows everything wrong.
func judge(in verdictInput) (Verdict, Results, *Profile) {
	v := Verdict{Package: in.manifest.Package, Commit: in.manifest.Commit}
	fail := func(format string, a ...any) { v.Problems = append(v.Problems, fmt.Sprintf(format, a...)) }
	if in.listSum != in.manifest.ListSHA256 {
		fail("list.txt sha256 %s != manifest %s — the plan was not built from this binary's inventory", in.listSum, in.manifest.ListSHA256)
	}
	if err := verifyPlan(in.plan, in.inv); err != nil {
		fail("plan: %v", err)
	}
	if in.plan.Package != in.manifest.Package {
		fail("plan package %s != manifest package %s", in.plan.Package, in.manifest.Package)
	}
	results := Results{}
	var merged, shardUniverse *Profile
	for _, sp := range in.plan.Shards {
		rep, res, profs := judgeShard(in, sp, fail)
		v.Shards = append(v.Shards, rep)
		results.merge(res)
		for _, p := range profs {
			if shardUniverse == nil {
				shardUniverse = p
			} else if d := sameUniverse(shardUniverse, p); d != "" {
				fail("shard %d: root profile block universe differs from shard 0's: %s", sp.Index, d)
			}
			merged = mergeInto(merged, p, fail)
			v.Profiles++
		}
	}
	checkRootUniverse(in, shardUniverse, &v.Completeness, fail)
	checkSourceAgreement(in, &v.Completeness, fail)
	// The universe first: it decides which lane packages are legitimately
	// EMPTY (no tests and no statements), the one case in which `go test`
	// reports a package as skipped rather than passed.
	universe := judgeUniverse(in, &v.Completeness, fail)
	laneRep, laneRes, laneProf := judgeLane(in, &v.Completeness, fail)
	v.Lane = laneRep
	results.merge(laneRes)
	checkLaneUniverse(universe, laneProf, fail)
	if laneProf != nil {
		merged = mergeInto(merged, laneProf, fail)
		v.Profiles++
	}
	if merged != nil {
		v.Merged = merged.stats(nil)
		v.Root = merged.stats(func(f string) bool { return rootFile(in.manifest.Package, f) })
	}
	v.OK = len(v.Problems) == 0
	return v, results, merged
}

func mergeInto(dst, src *Profile, fail func(string, ...any)) *Profile {
	if dst == nil {
		d := &Profile{Mode: src.Mode, Blocks: map[blockKey]*blockVal{}}
		dst = d
	}
	if err := mergeProfile(dst, src); err != nil {
		fail("merge: %v", err)
	}
	return dst
}

// judgeShard verifies one shard: identity, every chunk's exit status and
// selection, every planned entry executed exactly once with no failure, and a
// usable coverage profile per chunk from THIS binary's root package.
func judgeShard(in verdictInput, sp ShardPlan, fail func(string, ...any)) (ShardReport, Results, []*Profile) {
	rep := ShardReport{Index: sp.Index, Entries: len(sp.Names), Chunks: len(sp.Chunks), Estimated: sp.EstimatedSeconds}
	dir := filepath.Join(in.shardsDir, shardDirName(sp.Index))
	var meta ShardMeta
	if err := readJSON(filepath.Join(dir, "meta.json"), &meta); err != nil {
		fail("shard %d: no usable evidence (%v) — failed, cancelled or never uploaded", sp.Index, err)
		return rep, Results{}, nil
	}
	m := in.manifest
	checkShardIdentity(sp.Index, meta, m, fail)
	rep.TestSeconds = meta.TestSeconds
	if len(meta.Chunks) != len(sp.Chunks) {
		fail("shard %d: ran %d of %d planned chunks", sp.Index, len(meta.Chunks), len(sp.Chunks))
	}
	results := Results{}
	var profs []*Profile
	for i, c := range sp.Chunks {
		if i < len(meta.Chunks) {
			cm := meta.Chunks[i]
			if cm.Index != c.Index || !cm.SelectionMatched || cm.ExitCode != 0 {
				fail("shard %d chunk %d: exit %d, selection matched %v %s", sp.Index, c.Index, cm.ExitCode, cm.SelectionMatched, cm.SelectionProblem)
			}
		}
		res, prof := judgeChunk(in, sp.Index, c, dir, fail)
		results.merge(res)
		if prof != nil {
			profs = append(profs, prof)
		}
	}
	rep.Passed, rep.Skipped = countOutcomes(results[m.Package])
	return rep, results, profs
}

// checkShardIdentity: the evidence must come from THIS build — the same
// binary, commit, toolchain and checkout path, and the shard it claims to be.
func checkShardIdentity(idx int, meta ShardMeta, m Manifest, fail func(string, ...any)) {
	switch {
	case meta.Shard != idx:
		fail("shard %d: evidence is labelled shard %d", idx, meta.Shard)
	case meta.BinarySHA256 != m.BinarySHA256:
		fail("shard %d: ran binary %s, built %s", idx, meta.BinarySHA256, m.BinarySHA256)
	case meta.Commit != m.Commit:
		fail("shard %d: commit %s, built %s", idx, meta.Commit, m.Commit)
	case meta.GoVersion != m.GoVersion || meta.GOOS != m.GOOS || meta.GOARCH != m.GOARCH || meta.WorkDir != m.WorkDir:
		fail("shard %d: environment %s %s/%s in %s differs from the build", idx, meta.GoVersion, meta.GOOS, meta.GOARCH, meta.WorkDir)
	}
}

func countOutcomes(p *PkgResult) (passed, skipped int) {
	if p == nil {
		return 0, 0
	}
	for _, t := range p.Tests {
		switch t.Status {
		case statusPass:
			passed++
		case statusSkip:
			skipped++
		}
	}
	return passed, skipped
}

func judgeChunk(in verdictInput, shard int, c Chunk, dir string, fail func(string, ...any)) (Results, *Profile) {
	where := fmt.Sprintf("shard %d chunk %d", shard, c.Index)
	res := Results{}
	f, err := os.Open(filepath.Join(dir, fmt.Sprintf("chunk-%d.json", c.Index)))
	if err != nil {
		fail("%s: no test events (%v)", where, err)
	} else {
		r, perr := parseTestJSON(f)
		f.Close()
		if perr != nil {
			fail("%s: %v", where, perr)
		} else {
			res = r
			checkChunkResults(in.manifest.Package, where, c.Names, res, fail)
		}
	}
	prof, err := readProfile(filepath.Join(dir, fmt.Sprintf("chunk-%d.cover.out", c.Index)))
	if err != nil {
		fail("%s: unusable coverage profile: %v", where, err)
		return res, nil
	}
	if prof.Mode != "atomic" {
		fail("%s: coverage mode %q, the race reference is atomic", where, prof.Mode)
	}
	if len(prof.Blocks) == 0 {
		fail("%s: coverage profile has no blocks", where)
	}
	for k := range prof.Blocks {
		if !rootFile(in.manifest.Package, k.File) {
			fail("%s: coverage block %s is outside the root package", where, k)
			break
		}
	}
	return res, prof
}

// checkChunkResults: exactly the planned names ran, once each, none failed,
// and the package itself passed. A missing result is missing EXECUTION (a
// crash or a lost selection); a skip is a result and is counted as one.
func checkChunkResults(pkg, where string, names []string, res Results, fail func(string, ...any)) {
	for p := range res {
		if p != pkg {
			fail("%s: events for unexpected package %s", where, p)
		}
	}
	p := res[pkg]
	if p == nil {
		fail("%s: no events for %s", where, pkg)
		return
	}
	if p.Status != statusPass {
		fail("%s: package result %q", where, p.Status)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
		t := p.Tests[n]
		switch {
		case t == nil:
			fail("%s: %s has no result — it never ran", where, n)
		case t.Reports != 1:
			fail("%s: %s reported %d results", where, n, t.Reports)
		case t.Status == statusFail:
			fail("%s: %s FAILED", where, n)
		}
	}
	for _, n := range sortedKeys(p.Tests) {
		if !want[n] {
			fail("%s: %s ran but was not selected by this chunk", where, n)
		}
	}
}

// judgeLane verifies the non-root lane: same source/toolchain identity, the
// exact expected package set, every package passed with exactly its source
// inventory of entries, and a usable profile with no root-package blocks (its
// completeness against the universe is checked by the caller).
func judgeLane(in verdictInput, c *Completeness, fail func(string, ...any)) (LaneReport, Results, *Profile) {
	rep := LaneReport{Elapsed: map[string]float64{}}
	dirs := splitNames(in.laneDir)
	if len(dirs) == 0 {
		fail("lane: no evidence directory named")
		return rep, Results{}, nil
	}
	// A lane may run as several parts (disjoint package subsets of ONE
	// command); together they must be exactly the lane, judged as one.
	res := Results{}
	var prof *Profile
	var pkgs []string
	usable := true
	for _, dir := range dirs {
		meta, pres, pprof, ok := judgeLanePart(in, dir, fail)
		if !ok {
			usable = false
			continue
		}
		pkgs = append(pkgs, meta.Packages...)
		rep.Packages += len(meta.Packages)
		if meta.Seconds > rep.Seconds {
			rep.Seconds = meta.Seconds
		}
		res.merge(pres)
		if pprof != nil {
			prof = mergeInto(prof, pprof, fail)
		}
	}
	if !usable {
		return rep, Results{}, nil
	}
	if d := diffNames(in.lanePkgs, pkgs); d != "" {
		fail("lane package set differs from `go list ./...` minus the root: %s", d)
	}
	rep.Elapsed = checkLaneResults(in, res, c.empty(), fail)
	checkLaneEntries(in, res, c, fail)
	if prof == nil {
		return rep, res, nil
	}
	if len(prof.Blocks) == 0 {
		fail("lane: coverage profile has no blocks")
	}
	return rep, res, prof
}

// judgeLanePart reads one lane part's evidence: its identity, events and a
// usable atomic profile with no root-package blocks. Package-set equality is
// judged over the union by judgeLane.
func judgeLanePart(in verdictInput, dir string, fail func(string, ...any)) (LaneMeta, Results, *Profile, bool) {
	var meta LaneMeta
	if err := readJSON(filepath.Join(dir, "meta.json"), &meta); err != nil {
		fail("lane %s: no usable evidence (%v) — failed, cancelled or never uploaded", dir, err)
		return meta, nil, nil, false
	}
	if meta.Kind != laneRun.name {
		fail("lane %s: evidence is of kind %q, not %q", dir, meta.Kind, laneRun.name)
	}
	checkPackageRunIdentity("lane "+dir, in, meta, meta.Packages, fail)
	f, err := os.Open(filepath.Join(dir, laneRun.events))
	if err != nil {
		fail("lane %s: no test events (%v)", dir, err)
		return meta, nil, nil, false
	}
	res, err := parseTestJSON(f)
	f.Close()
	if err != nil {
		fail("lane %s: %v", dir, err)
		return meta, nil, nil, false
	}
	prof, err := readProfile(filepath.Join(dir, laneRun.profile))
	if err != nil {
		fail("lane %s: unusable coverage profile: %v", dir, err)
		return meta, res, nil, true
	}
	if prof.Mode != "atomic" {
		fail("lane %s: coverage mode %q, the race reference is atomic", dir, prof.Mode)
	}
	for k := range prof.Blocks {
		if rootFile(in.manifest.Package, k.File) {
			fail("lane %s: coverage block %s belongs to the root package", dir, k)
			break
		}
	}
	return meta, res, prof, true
}

// checkLaneResults: every expected package passed; the root never ran here.
// A package-level `skip` is accepted ONLY for a listed empty package (no tests
// in its source AND no statements in the universe): that is what `go test
// -cover` reports for it, and nothing else may read as skipped.
func checkLaneResults(in verdictInput, res Results, empty map[string]bool, fail func(string, ...any)) map[string]float64 {
	elapsed := map[string]float64{}
	for _, p := range in.lanePkgs {
		r := res[p]
		switch {
		case r == nil:
			fail("lane: %s has no result — it never ran", p)
		case r.Status == statusSkip && empty[p]:
			elapsed[p] = r.Elapsed
		case r.Status != statusPass:
			fail("lane: %s result %q", p, r.Status)
		default:
			elapsed[p] = r.Elapsed
		}
	}
	if _, ok := res[in.manifest.Package]; ok {
		fail("lane ran the root package %s — it belongs to the shards", in.manifest.Package)
	}
	return elapsed
}

func cmdVerdict(args []string, stdout io.Writer) error {
	fl := newFlags("verdict")
	buildDir := fl.String("build-dir", "", "directory with manifest.json, list.txt, plan.json")
	shardsDir := fl.String("shards-dir", "", "directory holding shard-<i>/ evidence")
	laneDir := fl.String("lane-dir", "", "non-root lane evidence directory (comma-separated when the lane runs in parts)")
	universeDir := fl.String("universe-dir", "", "non-root lane universe evidence directory")
	outDir := fl.String("out-dir", "", "where to write verdict.json, results.json, merged.cover.out")
	commit := fl.String("commit", os.Getenv("GITHUB_SHA"), "commit THIS job checked out (the source the expectations are enumerated from)")
	goBin := fl.String("go", "go", "go command (for `go list ./...`)")
	if err := fl.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if err := required(fl, "build-dir", "shards-dir", "lane-dir", "universe-dir", "out-dir", "commit"); err != nil {
		return err
	}
	in := verdictInput{shardsDir: *shardsDir, laneDir: *laneDir, universeDir: *universeDir}
	if err := loadVerdictInput(*buildDir, *commit, *goBin, &in); err != nil {
		return err
	}
	v, results, merged := judge(in)
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if merged != nil {
		if err := writeProfile(filepath.Join(*outDir, "merged.cover.out"), merged); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(*outDir, "results.json"), results); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(*outDir, "verdict.json"), v); err != nil {
		return err
	}
	printVerdict(stdout, v)
	if !v.OK {
		return fmt.Errorf("pilot REJECTED: %d problem(s)", len(v.Problems))
	}
	return nil
}

// loadVerdictInput reads the build's evidence and derives every expectation
// the judge needs that does not come from the evidence being judged.
func loadVerdictInput(buildDir, commit, goBin string, in *verdictInput) error {
	if err := readJSON(filepath.Join(buildDir, "manifest.json"), &in.manifest); err != nil {
		return err
	}
	// The expectations below are enumerated from THIS checkout, so it must be
	// the source the evidence was built from.
	if commit != in.manifest.Commit {
		return fmt.Errorf("verdict checkout is %s but the build is %s — expectations would describe another tree", commit, in.manifest.Commit)
	}
	if err := loadRootUniverse(buildDir, in); err != nil {
		return err
	}
	if err := readJSON(filepath.Join(buildDir, "plan.json"), &in.plan); err != nil {
		return err
	}
	list, err := os.ReadFile(filepath.Join(buildDir, "list.txt"))
	if err != nil {
		return fmt.Errorf("read list: %w", err)
	}
	sum := sha256.Sum256(list)
	in.listSum = hex.EncodeToString(sum[:])
	if in.inv, err = parseList(strings.NewReader(string(list))); err != nil {
		return err
	}
	ctx := context.Background()
	if in.laneRoot, in.lanePkgs, err = nonRootPackages(ctx, goBin); err != nil {
		return err
	}
	all := append([]string{in.laneRoot}, in.lanePkgs...)
	if in.source, err = sourceInventory(ctx, goBin, laneBuildFlags, all); err != nil {
		return fmt.Errorf("source inventory: %w", err)
	}
	return nil
}

// loadRootUniverse reads the build's expected root block set and checks it is
// the one the manifest recorded. A missing universe is not an error HERE — the
// judge reports it as a problem, so it appears in verdict.json with the rest.
func loadRootUniverse(buildDir string, in *verdictInput) error {
	m := in.manifest
	if m.RootUniverse == "" {
		return nil
	}
	p := filepath.Join(buildDir, m.RootUniverse)
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	sum, _, err := fileSHA256(p)
	if err != nil {
		return err
	}
	if sum != m.RootUniverseSHA256 {
		return fmt.Errorf("root universe %s sha256 %s != manifest %s", p, sum, m.RootUniverseSHA256)
	}
	if in.rootUniverse, err = readProfile(p); err != nil {
		return err
	}
	if len(in.rootUniverse.Blocks) != m.RootUniverseBlocks {
		return fmt.Errorf("root universe has %d blocks, manifest recorded %d", len(in.rootUniverse.Blocks), m.RootUniverseBlocks)
	}
	return nil
}

func printVerdict(w io.Writer, v Verdict) {
	say(w, "pilot verdict for %s @ %s: ok=%v, %d profile(s) merged\n", v.Package, v.Commit, v.OK, v.Profiles)
	for _, s := range v.Shards {
		say(w, "  shard %d: %d entries (%d pass, %d skip) in %d chunk(s), %.1fs tests (estimate %.1fs)\n",
			s.Index, s.Entries, s.Passed, s.Skipped, s.Chunks, s.TestSeconds, s.Estimated)
	}
	say(w, "  lane: %d packages in %.1fs\n", v.Lane.Packages, v.Lane.Seconds)
	type pe struct {
		p string
		s float64
	}
	var slow []pe
	for p, s := range v.Lane.Elapsed {
		slow = append(slow, pe{p, s})
	}
	sort.Slice(slow, func(i, j int) bool { return slow[i].s > slow[j].s || (slow[i].s == slow[j].s && slow[i].p < slow[j].p) })
	for i := 0; i < len(slow) && i < 8; i++ {
		say(w, "    %8.1fs %s\n", slow[i].s, slow[i].p)
	}
	say(w, "  merged coverage: %.1f%% of %d statements (root package %.1f%%)\n", v.Merged.Percent, v.Merged.Statements, v.Root.Percent)
	c := v.Completeness
	say(w, "  completeness: root universe %d blocks, lane universe %d blocks; source enumerator agrees with the binary: %v; lane entries %d reported / %d expected\n",
		c.RootUniverseBlocks, c.LaneUniverseBlocks, c.SourceAgreesWithBinary, c.LaneReportedEntries, c.LaneExpectedEntries)
	say(w, "  packages without tests (%d): %s\n", len(c.PackagesWithoutTests), headList(c.PackagesWithoutTests, 8))
	say(w, "  packages without instrumentable statements (%d): %s\n", len(c.PackagesWithoutStatements), headList(c.PackagesWithoutStatements, 8))
	for _, p := range v.Problems {
		say(w, "::error::%s\n", p)
	}
}
