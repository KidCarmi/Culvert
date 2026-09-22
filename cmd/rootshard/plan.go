package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Entry kinds. Only these run under -test.run; benchmarks are governed by
// their own lanes (benchgate, perf) and are excluded from the partition.
const (
	kindTest    = "test"
	kindFuzz    = "fuzz"
	kindExample = "example"
)

// maxRegexBytesDefault bounds ONE -test.run argument. Linux caps a single argv
// string at MAX_ARG_STRLEN (32 pages = 131072 bytes, NUL included); the root
// inventory alone is ~268 KB of names, so a two-shard plan would not fit in
// one argument. 96 KiB leaves headroom for the "-test.run=" prefix and is
// verified against the plan, never assumed.
const maxRegexBytesDefault = 96 * 1024

// planSchema versions the plan document.
const planSchema = 1

// Inventory is the runnable surface of ONE compiled test binary, discovered
// from that binary's own -test.list output — never from a source regex, which
// cannot see build tags, generated files or which examples carry an Output
// directive.
type Inventory struct {
	Runnable   []Entry  `json:"runnable"`
	Benchmarks []string `json:"benchmarks"`
}

// Entry is one top-level runnable entry. Subtests and fuzz seed cases are NOT
// entries: they run with their parent and are never split from it.
type Entry struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// parseList reads `<binary> -test.list .*` output. Every line must be a
// top-level entry name with a known prefix; anything else fails closed, since
// an unrecognised line is either a name this tool would silently drop or
// output the listing should never have produced.
func parseList(r io.Reader) (Inventory, error) {
	var inv Inventory
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		name := sc.Text()
		if err := validName(name); err != nil {
			return Inventory{}, fmt.Errorf("list line %d: %w", line, err)
		}
		if seen[name] {
			return Inventory{}, fmt.Errorf("list line %d: duplicate entry %q", line, name)
		}
		seen[name] = true
		switch {
		case strings.HasPrefix(name, "Benchmark"):
			inv.Benchmarks = append(inv.Benchmarks, name)
		case strings.HasPrefix(name, "Test"):
			inv.Runnable = append(inv.Runnable, Entry{name, kindTest})
		case strings.HasPrefix(name, "Fuzz"):
			inv.Runnable = append(inv.Runnable, Entry{name, kindFuzz})
		case strings.HasPrefix(name, "Example"):
			inv.Runnable = append(inv.Runnable, Entry{name, kindExample})
		default:
			return Inventory{}, fmt.Errorf("list line %d: %q is not a Test/Fuzz/Example/Benchmark entry", line, name)
		}
	}
	if err := sc.Err(); err != nil {
		return Inventory{}, fmt.Errorf("read list: %w", err)
	}
	if len(inv.Runnable) == 0 {
		return Inventory{}, errors.New("list has no runnable entries — refusing an empty inventory")
	}
	sort.Slice(inv.Runnable, func(i, j int) bool { return inv.Runnable[i].Name < inv.Runnable[j].Name })
	sort.Strings(inv.Benchmarks)
	return inv, nil
}

// validName rejects anything that cannot be a top-level Go test entry name.
// A '/' would make -test.run treat the name as a subtest path.
func validName(name string) error {
	if name == "" {
		return errors.New("empty line")
	}
	if strings.ContainsAny(name, "/ \t\r") {
		return fmt.Errorf("%q is not a top-level entry name", name)
	}
	return nil
}

// Timings maps top-level entry names to measured seconds from a previous
// unsharded run. Missing names are expected (new tests) and get the fallback.
type Timings struct {
	Source  string             `json:"source"`
	Package string             `json:"package"`
	Tests   map[string]float64 `json:"tests"`
}

// Plan is the partition: every runnable entry in exactly one chunk of exactly
// one shard.
type Plan struct {
	Schema          int         `json:"schema"`
	Package         string      `json:"package"`
	Shards          []ShardPlan `json:"shards"`
	Entries         int         `json:"entries"`
	Benchmarks      int         `json:"benchmarksExcluded"`
	MaxRegexBytes   int         `json:"maxRegexBytes"`
	TimingSource    string      `json:"timingSource"`
	FallbackSeconds float64     `json:"fallbackSeconds"`
	FallbackEntries int         `json:"fallbackEntries"`
}

// ShardPlan is one isolated process group. Chunks run sequentially in one job;
// each chunk is one process (one TestMain) with one -test.run argument.
type ShardPlan struct {
	Index            int      `json:"index"`
	EstimatedSeconds float64  `json:"estimatedSeconds"`
	FallbackEntries  int      `json:"fallbackEntries"`
	Chunks           []Chunk  `json:"chunks"`
	Names            []string `json:"names"`
}

// Chunk is one -test.run selection.
type Chunk struct {
	Index int      `json:"index"`
	Regex string   `json:"regex"`
	Names []string `json:"names"`
}

// minEstimateSeconds floors every estimate at the resolution of the timing
// source: `go test -v` prints durations to 10ms, so most root tests report
// 0.00s. A zero weight makes every such entry tie onto whichever shard is
// currently lightest — measured on the real inventory, one shard received
// 5,053 of 6,319 entries — although together they cost real seconds and each
// extra chunk repeats TestMain. With a floor they spread across shards.
const minEstimateSeconds = 0.005

// fallbackEstimate is the estimate for an entry with no historical timing: the
// MEAN of the measured entries (floored), i.e. the typical cost of one entry.
// Not the median: with most entries reporting 0.00s the median is zero, which
// would place every new test as if it cost nothing. 1s when nothing was
// measured at all. Deterministic for a given timing file.
func fallbackEstimate(t Timings) float64 {
	var sum float64
	n := 0
	for _, v := range t.Tests {
		if v >= 0 && !math.IsNaN(v) && !math.IsInf(v, 0) {
			sum += math.Max(v, minEstimateSeconds)
			n++
		}
	}
	if n == 0 {
		return 1
	}
	return math.Round(sum/float64(n)*1000) / 1000
}

// buildPlan partitions inv into n shards by longest-processing-time-first:
// entries sorted by estimate (desc, then name) are each placed on the currently
// lightest shard (ties to the lowest index). Every choice is a total order, so
// the same inventory + timings always yields the same plan, and a new test
// enters the partition automatically at the fallback estimate.
func buildPlan(pkg string, inv Inventory, t Timings, n, maxRegex int) (Plan, error) {
	if n < 1 {
		return Plan{}, fmt.Errorf("%w: shard count %d < 1", errUsage, n)
	}
	if len(inv.Runnable) < n {
		return Plan{}, fmt.Errorf("%d runnable entries cannot fill %d shards — a shard would run an empty selection", len(inv.Runnable), n)
	}
	fb := fallbackEstimate(t)
	p := Plan{Schema: planSchema, Package: pkg, Entries: len(inv.Runnable), Benchmarks: len(inv.Benchmarks),
		MaxRegexBytes: maxRegex, TimingSource: t.Source, FallbackSeconds: fb}
	p.Shards = make([]ShardPlan, n)
	for i := range p.Shards {
		p.Shards[i].Index = i
	}
	for _, e := range estimates(inv, t, fb) {
		s := &p.Shards[lightestShard(p.Shards)]
		s.EstimatedSeconds += e.sec
		s.Names = append(s.Names, e.name)
		if e.fallback {
			s.FallbackEntries++
			p.FallbackEntries++
		}
	}
	for i := range p.Shards {
		s := &p.Shards[i]
		sort.Strings(s.Names)
		s.EstimatedSeconds = math.Round(s.EstimatedSeconds*1000) / 1000
		chunks, err := chunkNames(s.Names, maxRegex)
		if err != nil {
			return Plan{}, fmt.Errorf("shard %d: %w", i, err)
		}
		s.Chunks = chunks
	}
	return p, nil
}

type estimate struct {
	name     string
	sec      float64
	fallback bool
}

// estimates returns every runnable entry's estimate, longest first (ties by
// name), with the fallback for entries the timing file does not know.
func estimates(inv Inventory, t Timings, fb float64) []estimate {
	ests := make([]estimate, len(inv.Runnable))
	for i, e := range inv.Runnable {
		sec, ok := t.Tests[e.Name]
		if !ok || sec < 0 || math.IsNaN(sec) || math.IsInf(sec, 0) {
			ests[i] = estimate{e.Name, fb, true}
			continue
		}
		ests[i] = estimate{e.Name, math.Max(sec, minEstimateSeconds), false}
	}
	sort.Slice(ests, func(i, j int) bool {
		if ests[i].sec != ests[j].sec {
			return ests[i].sec > ests[j].sec
		}
		return ests[i].name < ests[j].name
	})
	return ests
}

// lightestShard is the index of the least-loaded shard (ties: lowest index).
func lightestShard(shards []ShardPlan) int {
	lightest := 0
	for i := 1; i < len(shards); i++ {
		if shards[i].EstimatedSeconds < shards[lightest].EstimatedSeconds {
			lightest = i
		}
	}
	return lightest
}

// selectionRegex is the exact, anchored -test.run expression for names. Every
// name is QuoteMeta'd (a metacharacter must never widen the selection) and the
// alternation is wrapped in a group, so the anchors bind the WHOLE name and
// testing's splitter sees no top-level '|' or '/'.
func selectionRegex(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return "^(?:" + strings.Join(q, "|") + ")$"
}

// chunkNames packs sorted names into the fewest consecutive chunks whose regex
// fits maxRegex. Sorted order keeps each chunk's alternation prefix-factorable.
func chunkNames(names []string, maxRegex int) ([]Chunk, error) {
	if len(names) == 0 {
		return nil, errors.New("no names — refusing an empty selection")
	}
	var chunks []Chunk
	var cur []string
	size := len("^(?:)$")
	flush := func() {
		chunks = append(chunks, Chunk{Index: len(chunks), Regex: selectionRegex(cur), Names: cur})
		cur, size = nil, len("^(?:)$")
	}
	for _, n := range names {
		add := len(regexp.QuoteMeta(n))
		if len(cur) > 0 {
			add++ // the '|'
		}
		if size+add > maxRegex {
			if len(cur) == 0 {
				return nil, fmt.Errorf("entry %q alone exceeds the %d-byte selection limit", n, maxRegex)
			}
			flush()
			add = len(regexp.QuoteMeta(n))
		}
		cur = append(cur, n)
		size += add
	}
	flush()
	return chunks, nil
}

// verifyPlan re-derives the partition from the plan document itself, so a
// tampered, stale or hand-edited plan fails before any shard runs: every
// runnable entry is selected by exactly one chunk regex (evaluated with the
// same regexp engine `testing` uses), no chunk is empty or over the argument
// limit, no benchmark is selected, and each chunk's regex selects EXACTLY its
// listed names — which catches an escaping or anchoring bug that a name-list
// comparison alone would miss.
func verifyPlan(p Plan, inv Inventory) error {
	if p.Schema != planSchema {
		return fmt.Errorf("plan schema %d, want %d", p.Schema, planSchema)
	}
	all := make([]string, 0, len(inv.Runnable)+len(inv.Benchmarks))
	runnable := map[string]bool{}
	for _, e := range inv.Runnable {
		all = append(all, e.Name)
		runnable[e.Name] = true
	}
	all = append(all, inv.Benchmarks...)
	owner := map[string]string{}
	for _, s := range p.Shards {
		if len(s.Chunks) == 0 {
			return fmt.Errorf("shard %d has no chunks — an empty selection", s.Index)
		}
		for _, c := range s.Chunks {
			where := fmt.Sprintf("shard %d chunk %d", s.Index, c.Index)
			if err := verifyChunk(c, where, p.MaxRegexBytes, all, owner); err != nil {
				return err
			}
		}
	}
	for n := range owner {
		if !runnable[n] {
			return fmt.Errorf("%s selects %q, which is not a runnable entry", owner[n], n)
		}
	}
	for _, e := range inv.Runnable {
		if _, ok := owner[e.Name]; !ok {
			return fmt.Errorf("runnable entry %q is selected by no chunk", e.Name)
		}
	}
	return nil
}

func verifyChunk(c Chunk, where string, maxRegex int, all []string, owner map[string]string) error {
	if len(c.Names) == 0 || c.Regex == "" {
		return fmt.Errorf("%s is empty — `-test.run ''` would run EVERYTHING", where)
	}
	if maxRegex > 0 && len(c.Regex) > maxRegex {
		return fmt.Errorf("%s regex is %d bytes, over the %d-byte argument limit", where, len(c.Regex), maxRegex)
	}
	re, err := regexp.Compile(c.Regex)
	if err != nil {
		return fmt.Errorf("%s regex does not compile: %w", where, err)
	}
	want := map[string]bool{}
	for _, n := range c.Names {
		want[n] = true
	}
	if err := claimMatches(re, where, all, want, owner); err != nil {
		return err
	}
	for n := range want {
		if _, ok := owner[n]; !ok {
			return fmt.Errorf("%s lists %q, which is not in the binary's inventory", where, n)
		}
	}
	return nil
}

// claimMatches evaluates re against every name the binary knows: it must
// select exactly the chunk's own names, each not already claimed by another
// chunk.
func claimMatches(re *regexp.Regexp, where string, all []string, want map[string]bool, owner map[string]string) error {
	for _, n := range all {
		got := re.MatchString(n)
		switch {
		case got && !want[n]:
			return fmt.Errorf("%s regex also selects %q, which it does not list", where, n)
		case !got && want[n]:
			return fmt.Errorf("%s regex does not select its own entry %q", where, n)
		case !got:
			continue
		}
		if prev, dup := owner[n]; dup {
			return fmt.Errorf("%q is selected twice: %s and %s", n, prev, where)
		}
		owner[n] = where
	}
	return nil
}

func cmdPlan(args []string, stdout io.Writer) error {
	fs := newFlags("plan")
	list := fs.String("list", "", "`-test.list .*` output of the compiled binary")
	timings := fs.String("timings", "", "timing file (optional; every entry falls back when absent)")
	pkg := fs.String("pkg", "", "import path of the package under test")
	shards := fs.Int("shards", 4, "number of shards")
	maxRegex := fs.Int("max-regex-bytes", maxRegexBytesDefault, "maximum bytes in one -test.run argument")
	out := fs.String("out", "", "plan.json to write")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if err := required(fs, "list", "pkg", "out"); err != nil {
		return err
	}
	inv, err := readInventory(*list)
	if err != nil {
		return err
	}
	t := Timings{Source: "none", Tests: map[string]float64{}}
	if *timings != "" {
		if err := readJSON(*timings, &t); err != nil {
			return err
		}
	}
	p, err := buildPlan(*pkg, inv, t, *shards, *maxRegex)
	if err != nil {
		return err
	}
	if err := verifyPlan(p, inv); err != nil {
		return fmt.Errorf("generated plan failed verification: %w", err)
	}
	if err := writeJSON(*out, p); err != nil {
		return err
	}
	say(stdout, "plan: %d entries (%d benchmarks excluded) in %d shards, %d on the %.3fs fallback estimate\n",
		p.Entries, p.Benchmarks, len(p.Shards), p.FallbackEntries, p.FallbackSeconds)
	for _, s := range p.Shards {
		say(stdout, "  shard %d: %d entries, %d chunk(s), estimate %.1fs\n", s.Index, len(s.Names), len(s.Chunks), s.EstimatedSeconds)
	}
	return nil
}

func readInventory(path string) (Inventory, error) {
	f, err := os.Open(path)
	if err != nil {
		return Inventory{}, fmt.Errorf("open list: %w", err)
	}
	defer f.Close()
	return parseList(f)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
