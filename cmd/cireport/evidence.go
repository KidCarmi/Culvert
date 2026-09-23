package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// The subset of cmd/rootshard's published documents this reporter reads. They
// are declared here rather than imported because a command's package main
// cannot be imported; evidence_test.go decodes the real documents rootshard
// writes, so a renamed field fails a test instead of silently reading zero.

type evVerdict struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems"`
	Package  string   `json:"package"`
	Commit   string   `json:"commit"`
	Shards   []struct {
		Index       int     `json:"index"`
		Entries     int     `json:"entries"`
		Skipped     int     `json:"skipped"`
		TestSeconds float64 `json:"testSeconds"`
		Estimated   float64 `json:"estimatedSeconds"`
	} `json:"shards"`
	Lane struct {
		Packages int                `json:"packages"`
		Seconds  float64            `json:"seconds"`
		Elapsed  map[string]float64 `json:"packageElapsed"`
	} `json:"lane"`
	Merged struct {
		Blocks  int     `json:"blocks"`
		Covered int     `json:"coveredBlocks"`
		Percent float64 `json:"percent"`
	} `json:"mergedCoverage"`
	Completeness struct {
		RootUniverseBlocks  int `json:"rootUniverseBlocks"`
		LaneUniverseBlocks  int `json:"laneUniverseBlocks"`
		LaneReportedEntries int `json:"laneReportedEntries"`
	} `json:"completeness"`
}

type evTestResult struct {
	Status  string  `json:"status"`
	Seconds float64 `json:"seconds"`
}

type evPkgResult struct {
	Status string                   `json:"status"`
	Tests  map[string]*evTestResult `json:"tests"`
}

type evShardMeta struct {
	Shard     int    `json:"shard"`
	Commit    string `json:"commit"`
	GoVersion string `json:"goVersion"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	// RunnerImage is the hosted image the shard ran on (ImageOS); empty in
	// artifacts from before it was recorded.
	RunnerImage        string `json:"runnerImage"`
	RunnerImageVersion string `json:"runnerImageVersion"`
}

type evComparison struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems"`
	Lost     []string `json:"blocksCoveredOnlyInReference"`
	Gained   []string `json:"blocksCoveredOnlyInPilot"`
	Excepted []string `json:"blocksLostUnderException"`
}

type evTimings struct {
	Source  string             `json:"source"`
	Package string             `json:"package"`
	Tests   map[string]float64 `json:"tests"`
}

// runEvidence is everything read from the run's artifacts. A nil field was not
// available; why is recorded in notes.
type runEvidence struct {
	Verdict    *evVerdict
	Results    map[string]*evPkgResult
	ShardMetas map[int]*evShardMeta
	Comparison *evComparison
	// Candidate is the audit's refreshed timing file, verbatim.
	Candidate    *evTimings
	CandidateRaw []byte
	// TimingFileSource is the committed timing file's `source` at the tested
	// SHA, read through the contents API.
	TimingFileSource string
	// Present are the artifact names the run published (expired included).
	Present []string
	// Read are the "artifact/member" documents actually downloaded and
	// decoded. Empty means the report rests on run metadata alone.
	Read  []string
	Notes []string
}

func decodeStrict(name string, b []byte, v any) error {
	if len(b) == 0 {
		return fmt.Errorf("%s is empty", name)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	return nil
}

// Artifact names this reporter may read, and the members it may read from each.
// qa-race-build is deliberately absent: it carries the prebuilt test binary and
// the tool binary, and a reporter never needs either.
var readableArtifacts = map[string]map[string]bool{
	"qa-race-verdict":    {"verdict.json": true, "results.json": true},
	"qa-audit-compare":   {"comparison.json": true, "qa-root-shard-timings.json": true},
	"fast-audit-compare": {"comparison.json": true},
}

var shardArtifactRE = regexp.MustCompile(`^qa-race-shard-(\d+)$`)

// readableMembers returns the allowlisted members for an artifact name, or nil.
func readableMembers(name string) map[string]bool {
	if m, ok := readableArtifacts[name]; ok {
		return m
	}
	if shardArtifactRE.MatchString(name) {
		return map[string]bool{"meta.json": true}
	}
	return nil
}

// ingest decodes one artifact's members into the evidence.
func (ev *runEvidence) ingest(name string, members map[string][]byte) {
	note := func(err error) { ev.Notes = append(ev.Notes, fmt.Sprintf("artifact %s: %v", name, err)) }
	if m := shardArtifactRE.FindStringSubmatch(name); m != nil {
		var meta evShardMeta
		if err := decodeStrict("meta.json", members["meta.json"], &meta); err != nil {
			note(err)
			return
		}
		idx, _ := strconv.Atoi(m[1])
		if ev.ShardMetas == nil {
			ev.ShardMetas = map[int]*evShardMeta{}
		}
		ev.ShardMetas[idx] = &meta
		ev.Read = append(ev.Read, name+"/meta.json")
		return
	}
	switch name {
	case "qa-race-verdict":
		var v evVerdict
		if err := decodeStrict("verdict.json", members["verdict.json"], &v); err != nil {
			note(err)
		} else {
			ev.Verdict = &v
			ev.Read = append(ev.Read, name+"/verdict.json")
		}
		if b, ok := members["results.json"]; ok {
			var r map[string]*evPkgResult
			if err := decodeStrict("results.json", b, &r); err != nil {
				note(err)
			} else {
				ev.Results = r
				ev.Read = append(ev.Read, name+"/results.json")
			}
		}
	case "qa-audit-compare", "fast-audit-compare":
		var c evComparison
		if err := decodeStrict("comparison.json", members["comparison.json"], &c); err != nil {
			note(err)
		} else {
			ev.Comparison = &c
			ev.Read = append(ev.Read, name+"/comparison.json")
		}
		if b, ok := members["qa-root-shard-timings.json"]; ok {
			var t evTimings
			if err := decodeStrict("qa-root-shard-timings.json", b, &t); err != nil {
				note(err)
			} else {
				ev.Candidate, ev.CandidateRaw = &t, b
				ev.Read = append(ev.Read, name+"/qa-root-shard-timings.json")
			}
		}
	}
}
