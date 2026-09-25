package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

func mustProfile(t *testing.T, s string) *Profile {
	t.Helper()
	p, err := parseProfile(strings.NewReader(s))
	if err != nil {
		t.Fatalf("parseProfile: %v", err)
	}
	return p
}

func TestParseProfile_FailsClosed(t *testing.T) {
	for name, in := range map[string]string{
		"empty":             "",
		"no mode":           "m/a.go:1.1,2.2 1 0\n",
		"unknown mode":      "mode: weird\n",
		"short line":        "mode: atomic\nm/a.go:1.1,2.2 1\n",
		"bad coordinates":   "mode: atomic\nm/a.go:1.1-2.2 1 0\n",
		"negative count":    "mode: atomic\nm/a.go:1.1,2.2 1 -1\n",
		"statement clash":   "mode: atomic\nm/a.go:1.1,2.2 1 0\nm/a.go:1.1,2.2 2 0\n",
		"non-numeric count": "mode: atomic\nm/a.go:1.1,2.2 1 x\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProfile(strings.NewReader(in)); err == nil {
				t.Fatalf("accepted %q", in)
			}
		})
	}
}

// The merge is by block, never by line concatenation or percentage: the same
// root block from two shards is ONE block in the denominator, covered when any
// shard covered it, with counters summed; zero-covered blocks survive once.
func TestMergeProfile_CombinesBlocksNotLines(t *testing.T) {
	a := mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 3\nm/a.go:3.1,4.2 5 0\nm/a.go:5.1,6.2 1 0\n")
	b := mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 4\nm/a.go:3.1,4.2 5 7\nm/a.go:5.1,6.2 1 0\n")
	lane := mustProfile(t, "mode: atomic\nm/sub/b.go:1.1,2.2 4 1\n")
	merged := &Profile{Mode: "atomic", Blocks: map[blockKey]*blockVal{}}
	for _, p := range []*Profile{a, b, lane} {
		if err := mergeProfile(merged, p); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := merged.write(&buf); err != nil {
		t.Fatal(err)
	}
	want := "mode: atomic\nm/a.go:1.1,2.2 2 7\nm/a.go:3.1,4.2 5 7\nm/a.go:5.1,6.2 1 0\nm/sub/b.go:1.1,2.2 4 1\n"
	if buf.String() != want {
		t.Fatalf("merged profile:\n%s\nwant:\n%s", buf.String(), want)
	}
	s := merged.stats(nil)
	if s.Blocks != 4 || s.Statements != 12 || s.CoveredStatements != 11 || s.Percent != 91.7 {
		t.Fatalf("stats = %+v, want 4 blocks, 11/12 statements", s)
	}
	// Control: the naive alternatives give different numbers, so the exact
	// values above pin the block merge. Concatenation double-counts the root
	// denominator (5+5+... ) and averaging per-shard percentages is 81.25/100.
	concat := a.stats(nil).Statements + b.stats(nil).Statements + lane.stats(nil).Statements
	if concat == s.Statements {
		t.Fatal("control: concatenation would have produced the same denominator — the fixture proves nothing")
	}
	if again, err := parseProfile(strings.NewReader(buf.String())); err != nil || len(again.Blocks) != 4 {
		t.Fatalf("merged profile does not re-parse: %v", err)
	}
}

func TestMergeProfile_SetModeIsOR(t *testing.T) {
	a := mustProfile(t, "mode: set\nm/a.go:1.1,2.2 1 1\nm/a.go:3.1,4.2 1 0\n")
	b := mustProfile(t, "mode: set\nm/a.go:1.1,2.2 1 1\nm/a.go:3.1,4.2 1 1\n")
	if err := mergeProfile(a, b); err != nil {
		t.Fatal(err)
	}
	for k, v := range a.Blocks {
		if v.Count != 1 {
			t.Fatalf("%s count %d in set mode", k, v.Count)
		}
	}
}

func TestMergeProfile_RefusesIncompatibleProfiles(t *testing.T) {
	atomic := mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 3\n")
	if err := mergeProfile(atomic, mustProfile(t, "mode: set\nm/a.go:1.1,2.2 2 1\n")); err == nil {
		t.Fatal("mode mismatch merged")
	}
	if err := mergeProfile(atomic, mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 3 1\n")); err == nil {
		t.Fatal("statement-count mismatch (a different build) merged")
	}
}

func TestSameUniverse(t *testing.T) {
	a := mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 3\nm/a.go:3.1,4.2 1 0\n")
	b := mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 0\nm/a.go:3.1,4.2 1 9\n")
	if d := sameUniverse(a, b); d != "" {
		t.Fatalf("same blocks, different counts must be the same universe: %s", d)
	}
	for _, other := range []string{
		"mode: atomic\nm/a.go:1.1,2.2 2 3\n",
		"mode: atomic\nm/a.go:1.1,2.2 2 3\nm/a.go:3.1,4.2 1 0\nm/a.go:9.1,9.2 1 0\n",
		"mode: atomic\nm/a.go:1.1,2.2 2 3\nm/a.go:3.1,4.2 4 0\n",
	} {
		if d := sameUniverse(a, mustProfile(t, other)); d == "" {
			t.Fatalf("universe difference not reported for\n%s", other)
		}
	}
}

func TestRootFile(t *testing.T) {
	for f, want := range map[string]bool{
		"example.com/m/a.go":          true,
		"example.com/m/sub/a.go":      false,
		"example.com/mm/a.go":         false,
		"example.com/m/internal/x.go": false,
	} {
		if rootFile("example.com/m", f) != want {
			t.Fatalf("rootFile(%q) != %v", f, want)
		}
	}
}
