package main

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

// checkCleanCompleteness pins what the standalone verdict proves about the
// fixture on its own: the source enumerator reproduces the root binary's
// -test.list, every lane entry the source declares was reported, and the two
// legitimate edge packages are LISTED rather than silently counted as zero.
func checkCleanCompleteness(t *testing.T, c Completeness) {
	t.Helper()
	if !c.SourceAgreesWithBinary {
		t.Fatal("source enumerator did not agree with the root binary")
	}
	if c.RootUniverseBlocks == 0 || c.LaneUniverseBlocks == 0 {
		t.Fatalf("universes are empty: %+v", c)
	}
	// sub: TestTwice, FuzzTwice, ExampleTwice, TestExternal — not the silent
	// example, the benchmark or the Testify helper.
	if c.LaneExpectedEntries != 4 || c.LaneReportedEntries != 4 {
		t.Fatalf("lane entries expected/reported = %d/%d, want 4/4", c.LaneExpectedEntries, c.LaneReportedEntries)
	}
	if want := []string{"example.com/pilot/notest", "example.com/pilot/types"}; !slices.Equal(c.PackagesWithoutTests, want) {
		t.Fatalf("packages without tests = %v, want %v", c.PackagesWithoutTests, want)
	}
	if want := []string{"example.com/pilot/types"}; !slices.Equal(c.PackagesWithoutStatements, want) {
		t.Fatalf("packages without statements = %v, want %v", c.PackagesWithoutStatements, want)
	}
	if want := []string{"example.com/pilot/types"}; !slices.Equal(c.EmptyPackages, want) {
		t.Fatalf("empty packages = %v, want %v", c.EmptyPackages, want)
	}
}

// incompleteEvidence breaks the evidence in every way a sharded run can lose,
// truncate, mix up or forge it, and requires the standalone verdict — with no
// unsharded reference available — to refuse each one and name the cause.
func incompleteEvidence(t *testing.T, f *fixture) {
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, f *fixture)
		want   string
	}{
		{"lane profile with no blocks", func(t *testing.T, f *fixture) {
			replaceFile(t, f.path("lane", laneRun.profile), []byte("mode: atomic\n"))
		}, "lane: coverage profile has no blocks"},
		{"lane profile truncated at a line boundary", func(t *testing.T, f *fixture) {
			editFile(t, f.path("lane", laneRun.profile), dropLastLine)
		}, "lane coverage is incomplete against the universe"},
		{"lane events lost for one test", func(t *testing.T, f *fixture) {
			editFile(t, f.path("lane", laneRun.events), func(b []byte) []byte { return dropLinesContaining(b, `"Test":"TestExternal"`) })
		}, "TestExternal has no result"},
		{"lane event stream truncated mid-line", func(t *testing.T, f *fixture) {
			editFile(t, f.path("lane", laneRun.events), func(b []byte) []byte { return b[:len(b)-7] })
		}, "is not an event"},
		{"lane reports an entry the source does not declare", func(t *testing.T, f *fixture) {
			editFile(t, f.path("lane", laneRun.events), func(b []byte) []byte {
				return append(b, []byte(`{"Action":"pass","Package":"example.com/pilot/sub","Test":"TestGhost","Elapsed":0}`+"\n")...)
			})
		}, "TestGhost ran but is not in the package's source inventory"},
		{"universe missing", func(t *testing.T, f *fixture) {
			moveAway(t, f.path("universe"))
		}, "universe: no usable evidence"},
		{"lane evidence passed off as the universe", func(t *testing.T, f *fixture) {
			b, err := os.ReadFile(f.path("lane", "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			replaceFile(t, f.path("universe", "meta.json"), b)
		}, `universe: evidence is of kind "run-lane"`},
		{"universe from another commit", func(t *testing.T, f *fixture) {
			editFile(t, f.path("universe", "meta.json"), func(b []byte) []byte {
				return bytes.Replace(b, []byte(f.commit), []byte("fedcba9876543210"), 1)
			})
		}, "universe: identity"},
		{"every root profile truncated identically", func(t *testing.T, f *fixture) {
			// Consistent across shards, so the shard-vs-shard check cannot see
			// it: only the build's independent root universe can.
			// Profiles are written sorted, so every chunk's last line is the
			// same block.
			for _, p := range chunkProfiles(t, f) {
				editFile(t, p, dropLastLine)
			}
		}, "root coverage is incomplete against the build's expected block set"},
		{"source gained a test the binary lacks", func(t *testing.T, f *fixture) {
			addFile(t, "late_test.go", "package pilot\n\nimport \"testing\"\n\nfunc TestLate(t *testing.T) {}\n")
		}, "source enumerator disagrees with the root binary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.damage(t, f)
			wantRejected(t, f, tc.want)
		})
	}

	// A root universe that is not the one the build recorded is refused before
	// any judging: the expected block set itself would be untrustworthy.
	t.Run("root universe replaced", func(t *testing.T) {
		editFile(t, f.path("build", "root-universe.cover.out"), dropLastLine)
		code, _, out := f.verdict("verdict-bad")
		if code == 0 || !strings.Contains(out, "root universe") {
			t.Fatalf("verdict accepted a replaced root universe (exit %d):\n%s", code, out)
		}
	})
}

func chunkProfiles(t *testing.T, f *fixture) []string {
	t.Helper()
	var p Plan
	if err := readJSON(f.path("build", "plan.json"), &p); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range p.Shards {
		for _, c := range s.Chunks {
			out = append(out, f.path("shards", shardDirName(s.Index), sprintf("chunk-%d.cover.out", c.Index)))
		}
	}
	return out
}

// replaceFile overwrites path for the duration of the test.
func replaceFile(t *testing.T, path string, body []byte) {
	t.Helper()
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(path, orig, 0o600) }) // #nosec G703 -- restores the fixture's own t.TempDir()-derived file
	if err := os.WriteFile(path, body, 0o600); err != nil {   // #nosec G703 -- test rewrites its own t.TempDir()-derived evidence file
		t.Fatal(err)
	}
}

func editFile(t *testing.T, path string, edit func([]byte) []byte) {
	t.Helper()
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, path, edit(slices.Clone(orig)))
}

// addFile creates a source file in the fixture module for the test's duration.
func addFile(t *testing.T, name, body string) {
	t.Helper()
	t.Cleanup(func() { _ = os.Remove(name) })
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func moveAway(t *testing.T, dir string) {
	t.Helper()
	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Rename(dir+".away", dir) })
}

func dropLastLine(b []byte) []byte {
	b = bytes.TrimRight(b, "\n")
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		return b[:i+1]
	}
	return nil
}

func dropLinesContaining(b []byte, needle string) []byte {
	var out []byte
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if !bytes.Contains(line, []byte(needle)) {
			out = append(out, line...)
		}
	}
	return out
}
