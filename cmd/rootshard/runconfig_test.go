package main

import (
	"slices"
	"testing"
)

// The sharded run is only worth anything if it measures the SAME thing as the
// unsharded `go test -race -count=1 -timeout=40m -coverprofile=… ./...` it
// replaces. The workflow wall (qa_race_shards_test.go) pins the flags written
// in YAML; these pin the flags this tool adds on its own, which no YAML shows.

func TestRunConfig_RootBinaryIsRaceAndCover(t *testing.T) {
	got := buildArgs("bin/root.test")
	want := []string{"test", "-c", "-race", "-cover", "-o", "bin/root.test", "."}
	if !slices.Equal(got, want) {
		t.Fatalf("buildArgs = %q, want %q", got, want)
	}
}

func TestRunConfig_LaneMatchesTheReference(t *testing.T) {
	got := packageArgs(laneRun, "40m", "lane.cover.out", []string{"a", "b"})
	want := []string{"test", "-race", "-count=1", "-timeout=40m", "-coverprofile=lane.cover.out", "-json", "a", "b"}
	if !slices.Equal(got, want) {
		t.Fatalf("lane args = %q, want %q", got, want)
	}
}

// The universe is the lane's exact command with every test deselected, so its
// block set is the lane's expected block set and nothing else.
func TestRunConfig_UniverseIsTheLaneWithNoTests(t *testing.T) {
	got := packageArgs(universeRun, "40m", "universe.cover.out", []string{"a"})
	want := []string{"test", "-race", "-count=1", "-timeout=40m", "-run=^$", "-coverprofile=universe.cover.out", "-json", "a"}
	if !slices.Equal(got, want) {
		t.Fatalf("universe args = %q, want %q", got, want)
	}
	if !slices.Equal(laneBuildFlags, []string{"-race"}) {
		t.Fatalf("laneBuildFlags = %q: the source inventory must list packages under the lane's build configuration", laneBuildFlags)
	}
}
