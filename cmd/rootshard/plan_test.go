package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func mustList(t *testing.T, lines ...string) Inventory {
	t.Helper()
	inv, err := parseList(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatalf("parseList: %v", err)
	}
	return inv
}

func TestParseList_ClassifiesEntries(t *testing.T) {
	inv := mustList(t, "TestB", "BenchmarkX", "FuzzF", "ExampleE", "TestA")
	want := []Entry{{"ExampleE", kindExample}, {"FuzzF", kindFuzz}, {"TestA", kindTest}, {"TestB", kindTest}}
	if !reflect.DeepEqual(inv.Runnable, want) {
		t.Fatalf("runnable = %v, want %v", inv.Runnable, want)
	}
	if !reflect.DeepEqual(inv.Benchmarks, []string{"BenchmarkX"}) {
		t.Fatalf("benchmarks = %v", inv.Benchmarks)
	}
}

func TestParseList_FailsClosed(t *testing.T) {
	for name, in := range map[string]string{
		"unknown line":   "TestA\nwarning: GOCOVERDIR not set\n",
		"duplicate":      "TestA\nTestA\n",
		"blank line":     "TestA\n\nTestB\n",
		"subtest path":   "TestA/sub\n",
		"benchmark only": "BenchmarkX\n",
		"empty":          "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseList(strings.NewReader(in)); err == nil {
				t.Fatalf("parseList(%q) accepted invalid input", in)
			}
		})
	}
}

// synthInventory builds n test names with deterministic, uneven timings.
func synthInventory(n int) (Inventory, Timings) {
	t := Timings{Source: "synthetic", Tests: map[string]float64{}}
	var lines []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("TestSynth%04d", i)
		lines = append(lines, name)
		t.Tests[name] = float64((i*7919)%97) / 10
	}
	lines = append(lines, "FuzzSynth", "BenchmarkSynth")
	inv, err := parseList(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		panic(err)
	}
	return inv, t
}

func TestBuildPlan_EveryEntryExactlyOnce(t *testing.T) {
	inv, tm := synthInventory(1000)
	p, err := buildPlan("example.com/m", inv, tm, 4, maxRegexBytesDefault)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPlan(p, inv); err != nil {
		t.Fatalf("verifyPlan: %v", err)
	}
	seen := map[string]int{}
	for _, s := range p.Shards {
		var fromChunks []string
		for _, c := range s.Chunks {
			fromChunks = append(fromChunks, c.Names...)
		}
		if !reflect.DeepEqual(fromChunks, s.Names) {
			t.Fatalf("shard %d chunks do not cover its names exactly", s.Index)
		}
		for _, n := range s.Names {
			seen[n]++
		}
	}
	for _, e := range inv.Runnable {
		if seen[e.Name] != 1 {
			t.Fatalf("%s placed %d times", e.Name, seen[e.Name])
		}
	}
	if len(seen) != len(inv.Runnable) || p.Entries != len(inv.Runnable) || p.Benchmarks != 1 {
		t.Fatalf("plan has %d entries (%d recorded), inventory %d", len(seen), p.Entries, len(inv.Runnable))
	}
}

func TestBuildPlan_IsDeterministic(t *testing.T) {
	inv, tm := synthInventory(500)
	a, err := buildPlan("m", inv, tm, 4, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rev := inv
	rev.Runnable = append([]Entry(nil), inv.Runnable...)
	sort.Slice(rev.Runnable, func(i, j int) bool { return rev.Runnable[i].Name > rev.Runnable[j].Name })
	b, err := buildPlan("m", rev, tm, 4, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("the same inventory and timings produced two different plans")
	}
}

// LPT on known durations: {10,9,8,3,2,1} over 2 shards → {10,3,2}=15 / {9,8,1}=18?
// No: 10→s0, 9→s1, 8→s1(9<10), 3→s0(10<17), 2→s0(13<17), 1→s0(15<17) = 16/17.
func TestBuildPlan_BalancesByMeasuredDuration(t *testing.T) {
	inv := mustList(t, "TestA", "TestB", "TestC", "TestD", "TestE", "TestF")
	tm := Timings{Tests: map[string]float64{"TestA": 10, "TestB": 9, "TestC": 8, "TestD": 3, "TestE": 2, "TestF": 1}}
	p, err := buildPlan("m", inv, tm, 2, maxRegexBytesDefault)
	if err != nil {
		t.Fatal(err)
	}
	if got := []float64{p.Shards[0].EstimatedSeconds, p.Shards[1].EstimatedSeconds}; !reflect.DeepEqual(got, []float64{16, 17}) {
		t.Fatalf("loads = %v, want [16 17]", got)
	}
	if !reflect.DeepEqual(p.Shards[0].Names, []string{"TestA", "TestD", "TestE", "TestF"}) {
		t.Fatalf("shard 0 = %v", p.Shards[0].Names)
	}
}

func TestBuildPlan_NewEntriesGetTheMedianFallback(t *testing.T) {
	inv := mustList(t, "TestOld1", "TestOld2", "TestOld3", "TestNew", "FuzzNew")
	tm := Timings{Tests: map[string]float64{"TestOld1": 1, "TestOld2": 5, "TestOld3": 100, "TestGone": 7}}
	p, err := buildPlan("m", inv, tm, 2, maxRegexBytesDefault)
	if err != nil {
		t.Fatal(err)
	}
	if p.FallbackSeconds != 6 || p.FallbackEntries != 2 {
		t.Fatalf("fallback = %.1fs for %d entries, want the median 6s for 2", p.FallbackSeconds, p.FallbackEntries)
	}
	if err := verifyPlan(p, inv); err != nil {
		t.Fatalf("a new entry did not enter the partition: %v", err)
	}
	none, err := buildPlan("m", inv, Timings{}, 2, maxRegexBytesDefault)
	if err != nil || none.FallbackSeconds != 1 || none.FallbackEntries != 5 {
		t.Fatalf("no timings: %v, fallback %.1f for %d", err, none.FallbackSeconds, none.FallbackEntries)
	}
}

func TestBuildPlan_RefusesEmptySelections(t *testing.T) {
	inv := mustList(t, "TestA", "TestB")
	if _, err := buildPlan("m", inv, Timings{}, 3, maxRegexBytesDefault); err == nil {
		t.Fatal("3 shards over 2 entries must be refused — one shard would select nothing")
	}
	if _, err := buildPlan("m", inv, Timings{}, 0, maxRegexBytesDefault); err == nil {
		t.Fatal("0 shards must be refused")
	}
}

func TestChunkNames_HonoursTheArgumentLimit(t *testing.T) {
	inv, tm := synthInventory(300)
	p, err := buildPlan("m", inv, tm, 1, 512)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Shards[0].Chunks) < 2 {
		t.Fatalf("a 512-byte limit over 300 names produced %d chunk(s)", len(p.Shards[0].Chunks))
	}
	for _, c := range p.Shards[0].Chunks {
		if len(c.Regex) > 512 {
			t.Fatalf("chunk %d regex is %d bytes", c.Index, len(c.Regex))
		}
	}
	if err := verifyPlan(p, inv); err != nil {
		t.Fatal(err)
	}
	if _, err := chunkNames([]string{strings.Repeat("TestLong", 20)}, 64); err == nil {
		t.Fatal("a single name over the limit must be refused, not truncated")
	}
}

func TestSelectionRegex_IsEscapedAndAnchored(t *testing.T) {
	re := selectionRegex([]string{"TestA", "Test.X"})
	inv := Inventory{Runnable: []Entry{{"TestA", kindTest}, {"TestAB", kindTest}, {"XTestA", kindTest}, {"Test.X", kindTest}, {"TestYX", kindTest}}}
	owner := map[string]string{}
	err := verifyChunk(Chunk{Regex: re, Names: []string{"TestA", "Test.X"}}, "c", 0, []string{"TestA", "TestAB", "XTestA", "Test.X", "TestYX"}, owner)
	if err != nil {
		t.Fatalf("escaped, anchored regex over-selected: %v", err)
	}
	_ = inv
	// Controls: the same names unanchored or unescaped DO over-select, so the
	// check above is not vacuous.
	for _, bad := range []string{"^(?:TestA|Test.X)$", "(?:TestA|Test\\.X)"} {
		err := verifyChunk(Chunk{Regex: bad, Names: []string{"TestA", "Test.X"}}, "c", 0, []string{"TestA", "TestAB", "XTestA", "Test.X", "TestYX"}, map[string]string{})
		if err == nil {
			t.Fatalf("%q must be caught selecting a neighbour", bad)
		}
	}
}

func TestVerifyPlan_RejectsTamperedPlans(t *testing.T) {
	inv := mustList(t, "TestA", "TestAB", "TestB", "TestC", "BenchmarkZ")
	good, err := buildPlan("m", inv, Timings{}, 2, maxRegexBytesDefault)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPlan(good, inv); err != nil {
		t.Fatal(err)
	}
	clone := func() Plan {
		var p Plan
		b, _ := json.Marshal(good)
		_ = json.Unmarshal(b, &p)
		return p
	}
	set := func(p *Plan, s, c int, names ...string) {
		p.Shards[s].Chunks[c].Names = names
		p.Shards[s].Chunks[c].Regex = selectionRegex(names)
	}
	cases := map[string]func(p *Plan){
		"omission": func(p *Plan) { set(p, 0, 0, p.Shards[0].Chunks[0].Names[1:]...) },
		"duplicate": func(p *Plan) {
			set(p, 1, 0, append(append([]string{}, p.Shards[1].Chunks[0].Names...), p.Shards[0].Chunks[0].Names[0])...)
		},
		"unanchored regex": func(p *Plan) { p.Shards[0].Chunks[0].Regex = strings.TrimSuffix(p.Shards[0].Chunks[0].Regex, "$") },
		"empty chunk":      func(p *Plan) { p.Shards[1].Chunks[0] = Chunk{} },
		"no chunks":        func(p *Plan) { p.Shards[1].Chunks = nil },
		"regex over limit": func(p *Plan) { p.MaxRegexBytes = 5 },
		"unknown name": func(p *Plan) {
			set(p, 0, 0, append(append([]string{}, p.Shards[0].Chunks[0].Names...), "TestGhost")...)
		},
		"selects benchmark": func(p *Plan) {
			set(p, 0, 0, append(append([]string{}, p.Shards[0].Chunks[0].Names...), "BenchmarkZ")...)
		},
		"bad regex":    func(p *Plan) { p.Shards[0].Chunks[0].Regex = "^(?:TestA$" },
		"wrong schema": func(p *Plan) { p.Schema = 99 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := clone()
			mutate(&p)
			if err := verifyPlan(p, inv); err == nil {
				t.Fatal("tampered plan passed verification")
			}
		})
	}
}
