package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"sort"
)

// Comparison is the pilot-vs-unsharded-reference evidence.
type Comparison struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems"`
	Notes    []string `json:"notes"`

	RootReferenceEntries  int      `json:"rootReferenceEntries"`
	RootDiscoveredEntries int      `json:"rootDiscoveredEntries"`
	RootPilotEntries      int      `json:"rootPilotEntries"`
	ReferenceSkipped      []string `json:"referenceSkipped"`
	PilotSkipped          []string `json:"pilotSkipped"`
	SubtestsReference     int      `json:"subtestsReference"`
	SubtestsPilot         int      `json:"subtestsPilot"`
	SubtestsMissing       []string `json:"subtestsMissingFromPilot"`
	SubtestsExtra         []string `json:"subtestsOnlyInPilot"`
	PackagesReference     int      `json:"packagesReference"`
	PackagesPilot         int      `json:"packagesPilot"`

	ReferenceCoverage coverageStats `json:"referenceCoverage"`
	PilotCoverage     coverageStats `json:"pilotCoverage"`
	BlocksLost        []string      `json:"blocksCoveredOnlyInReference"`
	BlocksGained      []string      `json:"blocksCoveredOnlyInPilot"`
	FilesChanged      []FileDelta   `json:"filesWithDifferentCoverage"`
}

// FileDelta is one source file whose statement coverage differs.
type FileDelta struct {
	File      string  `json:"file"`
	Reference float64 `json:"reference"`
	Pilot     float64 `json:"pilot"`
}

// compareRuns holds the four inputs of a comparison.
type compareRuns struct {
	pkg                string
	inv                Inventory
	ref, pilot         Results
	refProf, pilotProf *Profile
}

// compare checks the pilot against the unsharded reference on the SAME
// commit. Inventory and result differences are problems; coverage-block
// differences are reported with their locations but are not by themselves a
// rejection, because counters and timing-dependent branches legitimately vary
// between any two runs — the coverage floors decide pass/fail, unchanged.
func compare(in compareRuns) Comparison {
	var c Comparison
	fail := func(format string, a ...any) { c.Problems = append(c.Problems, fmt.Sprintf(format, a...)) }
	note := func(format string, a ...any) { c.Notes = append(c.Notes, fmt.Sprintf(format, a...)) }
	compareRoot(in, &c, fail)
	comparePackages(in, &c, fail, note)
	compareCoverage(in, &c, fail)
	c.OK = len(c.Problems) == 0
	return c
}

func compareRoot(in compareRuns, c *Comparison, fail func(string, ...any)) {
	ref, pilot := in.ref[in.pkg], in.pilot[in.pkg]
	if ref == nil || pilot == nil {
		fail("root package %s missing from the reference (%v) or the pilot (%v)", in.pkg, ref != nil, pilot != nil)
		return
	}
	if ref.Status != statusPass {
		fail("the unsharded reference's root package result is %q — no passing baseline to compare with", ref.Status)
	}
	discovered := make([]string, len(in.inv.Runnable))
	for i, e := range in.inv.Runnable {
		discovered[i] = e.Name
	}
	refNames, pilotNames := sortedKeys(ref.Tests), sortedKeys(pilot.Tests)
	c.RootReferenceEntries, c.RootDiscoveredEntries, c.RootPilotEntries = len(refNames), len(discovered), len(pilotNames)
	if d := diffNames(discovered, refNames); d != "" {
		fail("binary inventory vs entries the reference executed: %s", d)
	}
	if d := diffNames(refNames, pilotNames); d != "" {
		fail("root entries executed: reference vs pilot: %s", d)
	}
	for _, n := range refNames {
		rt, pt := ref.Tests[n], pilot.Tests[n]
		if rt.Status == statusSkip {
			c.ReferenceSkipped = append(c.ReferenceSkipped, n)
		}
		if pt == nil {
			continue
		}
		if pt.Status == statusSkip {
			c.PilotSkipped = append(c.PilotSkipped, n+": "+pt.SkipNote)
		}
		if rt.Status != pt.Status {
			fail("%s: reference %s, pilot %s", n, rt.Status, pt.Status)
		}
	}
}

// comparePackages compares every package's status, top-level entries and
// subtest inventory.
func comparePackages(in compareRuns, c *Comparison, fail, note func(string, ...any)) {
	c.PackagesReference, c.PackagesPilot = len(in.ref), len(in.pilot)
	if d := diffNames(sortedKeys(in.ref), sortedKeys(in.pilot)); d != "" {
		fail("package set: reference vs pilot: %s", d)
	}
	for _, name := range sortedKeys(in.ref) {
		rp, pp := in.ref[name], in.pilot[name]
		if pp == nil {
			continue
		}
		compareSubtests(rp, pp, c, fail)
		if name == in.pkg {
			continue
		}
		if rp.Status != pp.Status {
			fail("%s: reference %s, pilot %s", name, rp.Status, pp.Status)
		}
		if d := diffNames(sortedKeys(rp.Tests), sortedKeys(pp.Tests)); d != "" {
			fail("%s entries: reference vs pilot: %s", name, d)
		}
		for _, n := range sortedKeys(rp.Tests) {
			if pt := pp.Tests[n]; pt != nil && pt.Status != rp.Tests[n].Status {
				fail("%s %s: reference %s, pilot %s", name, n, rp.Tests[n].Status, pt.Status)
			}
		}
	}
	if len(c.SubtestsMissing) > 0 {
		fail("%d subtest(s) ran in the reference but not in the pilot: %s", len(c.SubtestsMissing), headList(c.SubtestsMissing, 10))
	}
	if len(c.SubtestsExtra) > 0 {
		note("%d subtest(s) ran only in the pilot: %s", len(c.SubtestsExtra), headList(c.SubtestsExtra, 10))
	}
}

// compareSubtests records one package's subtest inventory and holds subtests
// present on both sides to the same rule as top-level entries: the OUTCOME must
// match, not just the name. A subtest that passed in the reference and skipped
// in the pilot (sharding changed the process state it depends on) executed a
// body the pilot did not, and its parent still reports pass — only this check
// sees it.
func compareSubtests(rp, pp *PkgResult, c *Comparison, fail func(string, ...any)) {
	c.SubtestsReference += len(rp.Subtests)
	c.SubtestsPilot += len(pp.Subtests)
	for _, s := range sortedKeys(rp.Subtests) {
		ps, ok := pp.Subtests[s]
		switch {
		case !ok:
			c.SubtestsMissing = append(c.SubtestsMissing, s)
		case ps != rp.Subtests[s]:
			fail("subtest %s: reference %s, pilot %s", s, rp.Subtests[s], ps)
		}
	}
	for _, s := range sortedKeys(pp.Subtests) {
		if _, ok := rp.Subtests[s]; !ok {
			c.SubtestsExtra = append(c.SubtestsExtra, s)
		}
	}
}

// compareCoverage: the block UNIVERSE must be identical (same commit, same
// build config ⇒ same instrumentation); the covered sets are compared block by
// block and every difference is listed with its location.
func compareCoverage(in compareRuns, c *Comparison, fail func(string, ...any)) {
	if in.refProf.Mode != in.pilotProf.Mode {
		fail("coverage mode: reference %q, pilot %q", in.refProf.Mode, in.pilotProf.Mode)
	}
	if d := sameUniverse(in.refProf, in.pilotProf); d != "" {
		fail("coverage block universe differs (reference vs pilot): %s", d)
	}
	c.ReferenceCoverage, c.PilotCoverage = in.refProf.stats(nil), in.pilotProf.stats(nil)
	for _, k := range in.refProf.sortedKeys() {
		pv, ok := in.pilotProf.Blocks[k]
		if !ok {
			continue
		}
		rc, pc := in.refProf.Blocks[k].Count > 0, pv.Count > 0
		switch {
		case rc && !pc:
			c.BlocksLost = append(c.BlocksLost, k.String())
		case pc && !rc:
			c.BlocksGained = append(c.BlocksGained, k.String())
		}
	}
	ref, pilot := perFile(in.refProf), perFile(in.pilotProf)
	for _, f := range sortedKeys(ref) {
		r, p := ref[f], pilot[f]
		if r.CoveredStatements != p.CoveredStatements {
			c.FilesChanged = append(c.FilesChanged, FileDelta{f, pct(r), pct(p)})
		}
	}
}

// perFile is statement-weighted coverage per source file, in one pass.
func perFile(p *Profile) map[string]coverageStats {
	out := map[string]coverageStats{}
	for k, v := range p.Blocks {
		s := out[k.File]
		s.Blocks++
		s.Statements += v.NumStmt
		if v.Count > 0 {
			s.CoveredBlocks++
			s.CoveredStatements += v.NumStmt
		}
		out[k.File] = s
	}
	return out
}

func pct(s coverageStats) float64 {
	if s.Statements == 0 {
		return 0
	}
	return math.Round(float64(s.CoveredStatements)/float64(s.Statements)*10000) / 100
}

func cmdCompare(args []string, stdout io.Writer) error {
	fs := newFlags("compare")
	refLog := fs.String("ref-log", "", "unsharded reference `go test -v ./...` log")
	refProf := fs.String("ref-profile", "", "unsharded reference coverage profile")
	pilotRes := fs.String("pilot-results", "", "results.json from verdict")
	pilotProf := fs.String("pilot-profile", "", "merged.cover.out from verdict")
	list := fs.String("list", "", "list.txt from build (the binary's inventory)")
	pkg := fs.String("pkg", "", "root import path")
	out := fs.String("out", "", "comparison.json to write")
	baseline := fs.String("baseline-out", "", "reference per-test/per-package timing JSON to write")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if err := required(fs, "ref-log", "ref-profile", "pilot-results", "pilot-profile", "list", "pkg", "out"); err != nil {
		return err
	}
	in := compareRuns{pkg: *pkg}
	var err error
	if in.inv, err = readInventory(*list); err != nil {
		return err
	}
	if in.ref, err = readVerboseLog(*refLog); err != nil {
		return err
	}
	if err := readJSON(*pilotRes, &in.pilot); err != nil {
		return err
	}
	if in.refProf, err = readProfile(*refProf); err != nil {
		return err
	}
	if in.pilotProf, err = readProfile(*pilotProf); err != nil {
		return err
	}
	if *baseline != "" {
		if err := writeJSON(*baseline, baselineTimings(in.ref, *pkg)); err != nil {
			return err
		}
	}
	c := compare(in)
	if err := writeJSON(*out, c); err != nil {
		return err
	}
	printComparison(stdout, c)
	if !c.OK {
		return fmt.Errorf("pilot differs from the unsharded reference: %d problem(s)", len(c.Problems))
	}
	return nil
}

func printComparison(w io.Writer, c Comparison) {
	say(w, "root entries: discovered %d, reference executed %d, pilot executed %d\n", c.RootDiscoveredEntries, c.RootReferenceEntries, c.RootPilotEntries)
	say(w, "skipped: reference %d, pilot %d\n", len(c.ReferenceSkipped), len(c.PilotSkipped))
	say(w, "subtests: reference %d, pilot %d (missing %d, extra %d)\n", c.SubtestsReference, c.SubtestsPilot, len(c.SubtestsMissing), len(c.SubtestsExtra))
	say(w, "packages: reference %d, pilot %d\n", c.PackagesReference, c.PackagesPilot)
	say(w, "coverage: reference %.1f%% (%d/%d blocks covered), pilot %.1f%% (%d/%d)\n",
		c.ReferenceCoverage.Percent, c.ReferenceCoverage.CoveredBlocks, c.ReferenceCoverage.Blocks,
		c.PilotCoverage.Percent, c.PilotCoverage.CoveredBlocks, c.PilotCoverage.Blocks)
	say(w, "blocks covered only in reference: %d; only in pilot: %d; files whose coverage differs: %d\n",
		len(c.BlocksLost), len(c.BlocksGained), len(c.FilesChanged))
	for i := 0; i < len(c.BlocksLost) && i < 40; i++ {
		say(w, "  lost   %s\n", c.BlocksLost[i])
	}
	for i := 0; i < len(c.BlocksGained) && i < 40; i++ {
		say(w, "  gained %s\n", c.BlocksGained[i])
	}
	for _, n := range c.Notes {
		say(w, "::notice::%s\n", n)
	}
	for _, p := range c.Problems {
		say(w, "::error::%s\n", p)
	}
}

// BaselineTimings is the reference's per-package and per-root-test timing.
type BaselineTimings struct {
	Packages  map[string]PackageTiming `json:"packages"`
	RootTests map[string]float64       `json:"rootTests"`
}

// PackageTiming is one package's reference outcome.
type PackageTiming struct {
	Status  string  `json:"status"`
	Elapsed float64 `json:"elapsed"`
	Tests   int     `json:"tests"`
}

func baselineTimings(r Results, pkg string) BaselineTimings {
	b := BaselineTimings{Packages: map[string]PackageTiming{}, RootTests: map[string]float64{}}
	for name, p := range r {
		b.Packages[name] = PackageTiming{p.Status, p.Elapsed, len(p.Tests)}
	}
	if p := r[pkg]; p != nil {
		for n, t := range p.Tests {
			b.RootTests[n] = t.Seconds
		}
	}
	return b
}

func readVerboseLog(p string) (Results, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	defer f.Close()
	r, err := parseVerboseLog(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return r, nil
}

func cmdTimings(args []string, stdout io.Writer) error {
	fs := newFlags("timings")
	logPath := fs.String("log", "", "reference `go test -v` log (artifact or downloaded job log)")
	pkg := fs.String("pkg", "", "root import path")
	source := fs.String("source", "", "provenance recorded in the file (run, commit)")
	out := fs.String("out", "", "timing file to write")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if err := required(fs, "log", "pkg", "source", "out"); err != nil {
		return err
	}
	r, err := readVerboseLog(*logPath)
	if err != nil {
		return err
	}
	p := r[*pkg]
	if p == nil || len(p.Tests) == 0 {
		return fmt.Errorf("log has no results for %s", *pkg)
	}
	if p.Status != statusPass {
		say(stdout, "warning: the reference's %s result is %q; timings are still usable as estimates\n", *pkg, p.Status)
	}
	t := Timings{Source: *source, Package: *pkg, Tests: map[string]float64{}}
	var total float64
	for n, tr := range p.Tests {
		t.Tests[n] = tr.Seconds
		total += tr.Seconds
	}
	if err := writeJSON(*out, t); err != nil {
		return err
	}
	names := sortedKeys(t.Tests)
	sort.SliceStable(names, func(i, j int) bool { return t.Tests[names[i]] > t.Tests[names[j]] })
	say(stdout, "%d root entries, %.1fs summed (package elapsed %.1fs); slowest:\n", len(names), total, p.Elapsed)
	for i := 0; i < len(names) && i < 10; i++ {
		say(stdout, "  %8.2fs %s\n", t.Tests[names[i]], names[i])
	}
	return nil
}
