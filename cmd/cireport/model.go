package main

// Report schemas. Each document carries its schema string; a consumer that
// sees a schema it does not know refuses it rather than guessing.
const (
	runReportSchema   = "culvert.ci-run-report/v2"
	trendReportSchema = "culvert.ci-trend-report/v2"
	baselineSchema    = "culvert.ci-perf-baseline/v1"
)

// runnerMinutesNote travels with every runner-minute figure. The number is the
// SUM of job durations — every parallel job counted in full — which is neither
// wall time nor a bill: GitHub rounds each job up to a whole minute and prices
// runner types differently, and neither is modelled here.
const runnerMinutesNote = "sum of this attempt's job durations (parallel jobs counted in full); not wall time and not billing"

// RunReport is one execution of one workflow, measured from GitHub's own run
// and job metadata plus the race engine's published evidence, read as data.
type RunReport struct {
	Schema    string        `json:"schema"`
	Collector Collector     `json:"collector"`
	Run       RunIdentity   `json:"run"`
	Class     string        `json:"class"`
	Reasons   []string      `json:"classReasons"`
	JobSet    JobSet        `json:"jobSet"`
	Toolchain *Toolchain    `json:"toolchain"` // nil: not observable for this run
	Cohort    Cohort        `json:"cohort"`
	Config    RunConfig     `json:"config"`
	Timing    Timing        `json:"timing"`
	Race      *RaceStats    `json:"race"` // nil: the race path did not run or left no evidence
	Evidence  EvidenceState `json:"evidence"`
	// Unknowns lists what could not be observed. A missing value is never
	// reported as zero or as healthy.
	Unknowns []string `json:"unknowns"`
	// Problems are contradictions in the evidence (identities that disagree).
	// They make the evidence untrusted, never the run green or red.
	Problems []string `json:"problems"`
	// cohortImage carries the shards' runner image from the evidence check
	// to the cohort; not serialised (the cohort and toolchain carry it).
	cohortImage string
}

// Collector identifies the reporting execution, so a report can be traced to
// the trusted code that produced it.
type Collector struct {
	RunID int64  `json:"runId,omitempty"`
	SHA   string `json:"sha,omitempty"`
}

// RunIdentity is the execution being measured.
type RunIdentity struct {
	Workflow     string `json:"workflow"`
	WorkflowPath string `json:"workflowPath"`
	Event        string `json:"event"`
	RunID        int64  `json:"runId"`
	Attempt      int    `json:"attempt"`
	Rerun        bool   `json:"rerun"`
	HeadSHA      string `json:"headSha"`
	HeadBranch   string `json:"headBranch"`
	// TestedSHA is the checkout the race engine actually built (the PR merge
	// commit on pull_request), from the verdict; empty when not observable.
	TestedSHA    string `json:"testedSha"`
	DisplayTitle string `json:"displayTitle"`
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion"`
	CreatedAt    string `json:"createdAt"`
	// AttemptCreatedAt is when THIS attempt was enqueued. The run's own
	// createdAt belongs to attempt 1; GitHub exposes a re-run's enqueue time
	// only on the attempt endpoint. Empty when not observed.
	AttemptCreatedAt string `json:"attemptCreatedAt,omitempty"`
	StartedAt        string `json:"startedAt"`
}

// JobSet records what actually executed, so executions that ran different jobs
// are never averaged together.
type JobSet struct {
	Key string `json:"key"`
	// Groups are the optional job families that executed (race, audit,
	// frontend, mcp, maint, qa-layers).
	Groups   []string    `json:"groups"`
	Executed []JobTiming `json:"executed"`
	Skipped  []string    `json:"skipped"`
	// CarriedOver are jobs a re-run attempt reused from an earlier attempt.
	// Their time was spent before this attempt started and is excluded from
	// this attempt's elapsed time and runner-minutes.
	CarriedOver []string `json:"carriedOver"`
	// Incomplete are jobs with no completed timing (cancelled before start,
	// still running when observed).
	Incomplete []string `json:"incomplete"`
}

// JobTiming is one job of this attempt, split by what the step names show.
type JobTiming struct {
	Name       string  `json:"name"`
	Conclusion string  `json:"conclusion"`
	Seconds    float64 `json:"seconds"`
	Queue      float64 `json:"queueSeconds"`
	Setup      float64 `json:"setupSeconds"`
	Work       float64 `json:"workSeconds"`
	Teardown   float64 `json:"teardownSeconds"`
}

// Toolchain is what the shards report they ran with.
type Toolchain struct {
	Go     string `json:"go"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	// RunnerImage / RunnerImageVersion as the shards reported them, when
	// they agree; the version changes weekly and is not a cohort component.
	RunnerImage        string `json:"runnerImage,omitempty"`
	RunnerImageVersion string `json:"runnerImageVersion,omitempty"`
}

// Cohort is the observed configuration an execution ran under. Executions are
// compared only within one cohort, so a different runner platform, shard count
// or Go toolchain never enters another configuration's baseline. A component
// that was not observed is "unknown" — its own cohort, never merged into a
// verified one and never given a reviewed baseline.
type Cohort struct {
	// Platform is the runner labels and runner group of the executed jobs,
	// from GitHub's job metadata. The hosted image version behind a moving
	// label (ubuntu-latest) is not exposed by the API and is not part of it.
	Platform string `json:"platform"`
	// Image is the hosted runner image OS the race shards reported
	// (ImageOS, e.g. ubuntu24): the label ubuntu-latest moves between
	// images under one name. "unknown" when no shard reported it; "mixed:…"
	// when shards of one run landed on different images (never verified).
	// The weekly image version is recorded per report, not keyed.
	Image string `json:"image"`
	// Shards is the sharded race engine's root shard count, from the shard
	// jobs GitHub scheduled; "none" when the engine did not run.
	Shards string `json:"shards"`
	// Toolchain is the Go release line (major.minor) and GOOS/GOARCH the
	// shards reported building with, from their meta.json. Patch releases
	// stay comparable; the exact version is in the report's toolchain field.
	// "unknown" when no shard evidence was read (metadata-only).
	Toolchain string `json:"toolchain"`
	Verified  bool   `json:"verified"`
	Key       string `json:"key"`
}

// RunConfig is the configuration that changes what an execution measures.
type RunConfig struct {
	Shards           int    `json:"shards,omitempty"`
	TimingFileSource string `json:"timingFileSource,omitempty"`
	AuditRequested   bool   `json:"auditRequested"`
	Fault            string `json:"fault,omitempty"`
}

// Timing separates elapsed (wall-clock) time from summed job time. Pointers are
// nil when the value is not observable for this attempt.
type Timing struct {
	ElapsedToAggregate   *float64 `json:"elapsedToAggregateSeconds"`
	ElapsedToRaceVerdict *float64 `json:"elapsedToRaceVerdictSeconds"`
	// WallSpan is attempt start to the last job's completion; Busy is the
	// union of this attempt's job intervals. Both are wall time: parallel
	// jobs overlap and are counted once.
	WallSpan          float64 `json:"wallSpanSeconds"`
	Busy              float64 `json:"busySeconds"`
	RunnerMinutes     float64 `json:"runnerMinutes"`
	RunnerMinutesNote string  `json:"runnerMinutesNote"`
	// AttemptQueue is this attempt's wait for its first runner: attempt
	// enqueue to the first job of this attempt starting. nil when the
	// attempt's enqueue time was not observed (a re-run seen through the
	// runs list, whose createdAt is attempt 1's) — never zero, and never the
	// interval between attempts.
	AttemptQueue *float64   `json:"attemptQueueSeconds"`
	Queue        PhaseStats `json:"jobQueue"`
	Setup        PhaseStats `json:"jobSetup"`
	Work         PhaseStats `json:"jobWork"`
}

// PhaseStats summarises one phase across the attempt's jobs.
type PhaseStats struct {
	Jobs   int     `json:"jobs"`
	Sum    float64 `json:"sumSeconds"`
	Median float64 `json:"medianSeconds"`
	Max    float64 `json:"maxSeconds"`
}

// RaceStats is the sharded race path, from the verdict and the job timings.
type RaceStats struct {
	BuildJobSeconds  *float64          `json:"buildJobSeconds"`
	VerdictSeconds   *float64          `json:"verdictJobSeconds"`
	Shards           []ShardStat       `json:"shards"`
	Imbalance        Imbalance         `json:"imbalance"`
	Lane             LaneStat          `json:"lane"`
	SlowestRootTests []NamedSeconds    `json:"slowestRootTests"`
	Inventory        Inventory         `json:"inventory"`
	Coverage         *CoverageFraction `json:"coverage"`
}

// ShardStat is one root shard: test time from the evidence, job time from GitHub.
type ShardStat struct {
	Index     int      `json:"index"`
	Entries   int      `json:"entries"`
	Skipped   int      `json:"skipped"`
	Test      float64  `json:"testSeconds"`
	Estimated float64  `json:"estimatedSeconds"`
	Job       *float64 `json:"jobSeconds"`
}

// Imbalance describes how evenly the shards' test time fell.
type Imbalance struct {
	MaxOverMean   float64 `json:"maxOverMean"`
	SpreadSeconds float64 `json:"spreadSeconds"`
	// EstimateError is max(|test-estimated|/estimated) over shards: how far
	// the timing file's prediction was from what happened.
	EstimateError float64 `json:"maxEstimateError"`
}

// LaneStat is the non-root package lane.
type LaneStat struct {
	Packages int            `json:"packages"`
	Seconds  float64        `json:"seconds"`
	Job      *float64       `json:"jobSeconds"`
	Slowest  []NamedSeconds `json:"slowestPackages"`
}

// NamedSeconds is a ranked duration.
type NamedSeconds struct {
	Name    string  `json:"name"`
	Seconds float64 `json:"seconds"`
}

// Inventory is the size of what ran.
type Inventory struct {
	RootEntries        int `json:"rootEntries"`
	RootSkipped        int `json:"rootSkipped"`
	LanePackages       int `json:"lanePackages"`
	LaneEntries        int `json:"laneEntries"`
	RootUniverseBlocks int `json:"rootUniverseBlocks"`
	LaneUniverseBlocks int `json:"laneUniverseBlocks"`
}

// CoverageFraction is the merged profile's block coverage.
type CoverageFraction struct {
	Blocks  int     `json:"blocks"`
	Covered int     `json:"coveredBlocks"`
	Percent float64 `json:"percent"`
}

// EvidenceState is the completeness and audit outcome.
type EvidenceState struct {
	// Source is "artifacts" when at least one evidence document was
	// downloaded and decoded, else "metadata-only": the report then rests
	// on GitHub's run and job metadata alone.
	Source string `json:"source"`
	// Read lists the "artifact/member" documents decoded, sorted.
	Read []string `json:"read"`
	// Verdict: ok | failed | missing | not-run.
	Verdict         string   `json:"verdict"`
	VerdictProblems []string `json:"verdictProblems"`
	Audit           Audit    `json:"audit"`
}

// Audit is the same-SHA sharded-vs-unsharded comparison, when requested.
type Audit struct {
	// State: not-requested | passed | failed | missing | unknown.
	// "missing" = requested and not executed: an audit that did not run.
	// "unknown" = executed, but its comparison evidence could not be read.
	State             string   `json:"state"`
	Requested         bool     `json:"requested"`
	ReferenceJob      string   `json:"referenceJob"`
	CompareJob        string   `json:"compareJob"`
	BlocksLost        int      `json:"blocksLost"`
	BlocksGained      int      `json:"blocksGained"`
	BlocksExcepted    int      `json:"blocksExcepted"`
	Problems          []string `json:"problems"`
	TimingCandidate   bool     `json:"timingCandidate"`
	CandidateArtifact string   `json:"candidateArtifact,omitempty"`
}
