// Command cireport measures CI executions from evidence that already exists —
// GitHub's run and job metadata and the race engine's published artifacts —
// and never reruns a test to collect a number (CI-REDESIGN stage 6B).
//
//	cireport run   -repo OWNER/NAME -run-id N [-attempt N] -out-dir DIR [-summary FILE]
//	cireport trend -repo OWNER/NAME -baseline FILE -out-dir DIR [-summary FILE]
//
// `run` writes a versioned per-execution report (report.json, summary.md and,
// for a passed same-SHA audit, a timing-refresh candidate for review). `trend`
// groups equivalent executions, keeps statistics provisional until a group has
// enough samples, compares with the REVIEWED baseline only as advice, and
// exits 1 when the recurring equivalence audit failed, went stale or never ran.
//
// Trust boundary: everything downloaded is decoded as data. Artifacts are read
// in memory for an allowlist of member names; the prebuilt test binary is never
// downloaded, and nothing downloaded is executed or cached.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	os.Exit(dispatch(os.Args[1], os.Args[2:]))
}

// dispatch runs one subcommand and returns the process exit code; main exits
// only after its deferred cancel has run.
func dispatch(cmd string, args []string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	var err error
	code := 0
	switch cmd {
	case "run":
		err = cmdRun(ctx, args)
	case "trend":
		code, err = cmdTrend(ctx, args)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cireport:", err)
		return 1
	}
	return code
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cireport run|trend [flags]")
	os.Exit(2)
}

type commonFlags struct {
	repo, api, outDir, summary, collectorSHA string
	collectorRun                             int64
}

func (c *commonFlags) register(fl *flag.FlagSet) {
	fl.StringVar(&c.repo, "repo", os.Getenv("GITHUB_REPOSITORY"), "OWNER/NAME")
	api := os.Getenv("GITHUB_API_URL")
	if api == "" {
		api = "https://api.github.com"
	}
	fl.StringVar(&c.api, "api", api, "GitHub REST API base URL")
	fl.StringVar(&c.outDir, "out-dir", "", "directory for the JSON report and summary")
	fl.StringVar(&c.summary, "summary", os.Getenv("GITHUB_STEP_SUMMARY"), "file the markdown summary is appended to")
	fl.Int64Var(&c.collectorRun, "collector-run-id", 0, "run id of the reporting execution (provenance)")
	fl.StringVar(&c.collectorSHA, "collector-sha", os.Getenv("GITHUB_SHA"), "commit of the reporting code (provenance)")
}

func (c *commonFlags) client() (*ghClient, error) {
	if !strings.Contains(c.repo, "/") {
		return nil, errors.New("-repo must be OWNER/NAME")
	}
	return newGHClient(c.api, os.Getenv("GH_TOKEN"))
}

func cmdRun(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("run", flag.ExitOnError)
	var cf commonFlags
	cf.register(fl)
	runID := fl.Int64("run-id", 0, "workflow run id")
	attempt := fl.Int("attempt", 0, "run attempt (0 = latest)")
	committed := fl.String("committed-timings", committedTimingsPath, "committed timing file, for the candidate diff")
	if err := fl.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	if *runID <= 0 {
		return errors.New("-run-id is required")
	}
	c, err := cf.client()
	if err != nil {
		return err
	}
	_, err = collectRun(ctx, c, runOpts{repo: cf.repo, runID: *runID, attempt: *attempt, committedTimings: *committed,
		outDir: cf.outDir, summary: cf.summary, collector: Collector{RunID: cf.collectorRun, SHA: cf.collectorSHA}})
	return err
}

func cmdTrend(ctx context.Context, args []string) (int, error) {
	fl := flag.NewFlagSet("trend", flag.ExitOnError)
	var cf commonFlags
	cf.register(fl)
	workflows := fl.String("workflows", "pr-fast-gate.yml,qa-gate.yml", "workflow files to summarise")
	per := fl.Int("per-event", 25, "most recent runs read per workflow and event (the sample window is 20)")
	baseline := fl.String("baseline", ".github/ci-perf-baseline.json", "reviewed baseline file")
	defaultBranch := fl.String("default-branch", "main", "the only branch a trusted reporter run (whose retained reports are read) may be on")
	if err := fl.Parse(args); err != nil {
		return 0, fmt.Errorf("flags: %w", err)
	}
	c, err := cf.client()
	if err != nil {
		return 0, err
	}
	tr, err := collectTrend(ctx, c, trendOpts{repo: cf.repo, workflows: strings.Split(*workflows, ","), perEvent: *per, defaultBranch: *defaultBranch,
		baselinePath: *baseline, outDir: cf.outDir, summary: cf.summary, now: time.Now(),
		collector: Collector{RunID: cf.collectorRun, SHA: cf.collectorSHA}})
	if err != nil {
		return 0, err
	}
	if tr.Audit.failing() {
		fmt.Fprintf(os.Stderr, "::error::weekly equivalence audit is %s: %s\n", tr.Audit.State, tr.Audit.Detail)
		return 1, nil
	}
	for _, in := range tr.Indicators {
		fmt.Fprintf(os.Stderr, "::warning::sustained regression (advisory) in %s %s\n", in.Group, in.Metric)
	}
	return 0, nil
}
