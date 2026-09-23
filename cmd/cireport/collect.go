package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const committedTimingsPath = ".github/qa-root-shard-timings.json"

type runOpts struct {
	repo             string
	runID            int64
	attempt          int
	committedTimings string
	outDir           string
	summary          string
	collector        Collector
}

// collectRun fetches one run's metadata and allowlisted evidence, analyses it,
// and writes report.json, summary.md and — for a passed audit — a
// timing-refresh candidate. It never fails because evidence is missing: that
// is recorded in the report as unknown.
func collectRun(ctx context.Context, c *ghClient, o runOpts) (RunReport, error) {
	run, err := c.run(ctx, o.repo, o.runID)
	if err != nil {
		return RunReport{}, fmt.Errorf("run %d: %w", o.runID, err)
	}
	// Always read through the attempt endpoint: it is the only place GitHub
	// exposes a re-run's own enqueue time. An older attempt cannot be
	// measured without it; for the latest attempt its absence only makes the
	// attempt queue unknown.
	want := run.RunAttempt
	if o.attempt > 0 {
		want = o.attempt
	}
	att, err := c.runAttempt(ctx, o.repo, run, want)
	switch {
	case err == nil:
		run = att
	case want != run.RunAttempt:
		return RunReport{}, fmt.Errorf("run %d attempt %d: %w", o.runID, want, err)
	}
	jobs, err := c.jobs(ctx, o.repo, run.ID, run.RunAttempt)
	if err != nil {
		return RunReport{}, fmt.Errorf("jobs of run %d: %w", run.ID, err)
	}
	ev := gatherEvidence(ctx, c, o.repo, run)
	ev.JobImages, ev.Notes = gatherJobImages(ctx, c, o.repo, run, jobs, ev.Notes)
	rep := Analyze(run, jobs, ev)
	rep.Collector = o.collector
	if err := writeRunOutputs(rep, ev, o); err != nil {
		return rep, err
	}
	return rep, nil
}

func gatherEvidence(ctx context.Context, c *ghClient, repo string, run apiRun) runEvidence {
	var ev runEvidence
	arts, err := c.runArtifacts(ctx, repo, run.ID)
	if err != nil {
		ev.Notes = append(ev.Notes, "artifact list unavailable: "+err.Error())
	}
	for _, a := range arts {
		ev.Present = append(ev.Present, a.Name)
		want := readableMembers(a.Name)
		if want == nil {
			continue
		}
		if a.WorkflowRun.ID != 0 && a.WorkflowRun.ID != run.ID {
			ev.Notes = append(ev.Notes, fmt.Sprintf("artifact %s belongs to run %d, not %d: ignored", a.Name, a.WorkflowRun.ID, run.ID))
			continue
		}
		members, err := c.artifactMembers(ctx, repo, a, want)
		if err != nil {
			ev.Notes = append(ev.Notes, fmt.Sprintf("artifact %s unreadable: %v", a.Name, err))
			continue
		}
		ev.ingest(a.Name, members)
	}
	if run.HeadSHA != "" {
		b, err := c.fileAt(ctx, repo, committedTimingsPath, run.HeadSHA)
		var t evTimings
		switch {
		case err != nil:
			ev.Notes = append(ev.Notes, "timing file at head_sha unreadable: "+err.Error())
		case json.Unmarshal(b, &t) != nil:
			ev.Notes = append(ev.Notes, "timing file at head_sha is not valid JSON")
		default:
			ev.TimingFileSource = t.Source
		}
	}
	return ev
}

// maxJobLogs bounds how many job logs one report reads.
const maxJobLogs = 100

// gatherJobImages reads the head of each job this attempt measured (executed,
// not carried over) and takes the runner image from it. Each read is a small
// byte range; a log that cannot be read or carries no image group leaves that
// job unobserved, and the report then says the image is unknown.
func gatherJobImages(ctx context.Context, c *ghClient, repo string, run apiRun, jobs []apiJob, notes []string) (images map[int64]runnerImage, outNotes []string) {
	start, _ := parseTime(run.RunStartedAt)
	views := viewJobs(jobs, start)
	out := map[int64]runnerImage{}
	var unreadable, noGroup, skipped int
	var firstErr error
	for vI := range views {
		v := &views[vI]
		if !v.inAttempt() || v.api.ID == 0 {
			continue
		}
		if len(out)+unreadable+noGroup >= maxJobLogs {
			skipped++
			continue
		}
		head, err := c.jobLogHead(ctx, repo, v.api.ID, jobLogHeadBytes)
		if err != nil {
			unreadable++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ri, ok := parseRunnerImage(head)
		if !ok {
			noGroup++
			continue
		}
		out[v.api.ID] = ri
	}
	if unreadable > 0 {
		notes = append(notes, fmt.Sprintf("%d job logs unreadable (first: %v)", unreadable, firstErr))
	}
	if noGroup > 0 {
		notes = append(notes, fmt.Sprintf("%d job logs carry no runner image group", noGroup))
	}
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("%d job logs not read (over the %d-log bound)", skipped, maxJobLogs))
	}
	return out, notes
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

func appendSummary(path, md string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open summary: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(md); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}

func writeRunOutputs(rep RunReport, ev runEvidence, o runOpts) error {
	if o.outDir == "" {
		return nil
	}
	if err := os.MkdirAll(o.outDir, 0o750); err != nil {
		return fmt.Errorf("out dir: %w", err)
	}
	md := renderRunSummary(rep)
	if rep.Evidence.Audit.TimingCandidate {
		diff, err := candidateDiff(o.committedTimings, ev.Candidate)
		if err != nil {
			return err
		}
		dir := filepath.Join(o.outDir, "timing-candidate")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("candidate dir: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "qa-root-shard-timings.json"), ev.CandidateRaw, 0o600); err != nil {
			return fmt.Errorf("write candidate: %w", err)
		}
		if err := writeJSON(filepath.Join(dir, "diff.json"), diff); err != nil {
			return err
		}
		md += renderCandidate(diff)
	}
	if err := writeJSON(filepath.Join(o.outDir, "report.json"), rep); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(o.outDir, "summary.md"), []byte(md), 0o600); err != nil {
		return fmt.Errorf("write summary.md: %w", err)
	}
	return appendSummary(o.summary, md)
}

// CandidateDiff compares an audit's refreshed timing file with the committed
// one. It is REVIEW material: nothing here changes the committed file.
type CandidateDiff struct {
	Source           string    `json:"source"`
	CommittedSource  string    `json:"committedSource"`
	CommittedEntries int       `json:"committedEntries"`
	CandidateEntries int       `json:"candidateEntries"`
	Added            int       `json:"added"`
	Removed          int       `json:"removed"`
	ChangedOver25Pct int       `json:"changedOver25Percent"`
	CommittedSum     float64   `json:"committedSumSeconds"`
	CandidateSum     float64   `json:"candidateSumSeconds"`
	LargestChanges   []Change  `json:"largestChanges"`
	Note             string    `json:"note"`
	RemovedNames     []string  `json:"removedNames"`
	AddedNames       []string  `json:"addedNames"`
	committed        evTimings `json:"-"`
}

// Change is one test's timing movement.
type Change struct {
	Name string  `json:"name"`
	From float64 `json:"from"`
	To   float64 `json:"to"`
}

func candidateDiff(committedPath string, cand *evTimings) (CandidateDiff, error) {
	d := CandidateDiff{Note: "review material only: the timing file balances shards and never selects tests; commit it by hand if the drift is worth taking"}
	if cand == nil {
		return d, fmt.Errorf("no candidate")
	}
	b, err := os.ReadFile(committedPath)
	if err != nil {
		return d, fmt.Errorf("read committed timings: %w", err)
	}
	if err := json.Unmarshal(b, &d.committed); err != nil {
		return d, fmt.Errorf("decode committed timings: %w", err)
	}
	old, cur := d.committed.Tests, cand.Tests
	d.Source, d.CommittedSource = cand.Source, d.committed.Source
	d.CommittedEntries, d.CandidateEntries = len(old), len(cur)
	var changes []Change
	for name, to := range cur {
		d.CandidateSum += to
		from, ok := old[name]
		if !ok {
			d.Added++
			d.AddedNames = append(d.AddedNames, name)
			continue
		}
		if math.Abs(to-from) > 0.25*math.Max(from, 1) {
			d.ChangedOver25Pct++
		}
		if to != from {
			changes = append(changes, Change{Name: name, From: from, To: to})
		}
	}
	for name, from := range old {
		d.CommittedSum += from
		if _, ok := cur[name]; !ok {
			d.Removed++
			d.RemovedNames = append(d.RemovedNames, name)
		}
	}
	sort.Strings(d.AddedNames)
	sort.Strings(d.RemovedNames)
	sort.Slice(changes, func(i, j int) bool {
		di, dj := math.Abs(changes[i].To-changes[i].From), math.Abs(changes[j].To-changes[j].From)
		if di != dj {
			return di > dj
		}
		return changes[i].Name < changes[j].Name
	})
	if len(changes) > 15 {
		changes = changes[:15]
	}
	d.LargestChanges = changes
	d.CommittedSum = math.Round(d.CommittedSum*10) / 10
	d.CandidateSum = math.Round(d.CandidateSum*10) / 10
	return d, nil
}

func renderCandidate(d CandidateDiff) string {
	var b strings.Builder
	b.WriteString("\n### Timing-refresh candidate (review only — never auto-committed)\n\n")
	fmt.Fprintf(&b, "| | committed | candidate |\n|---|---|---|\n| source | %s | %s |\n| entries | %d | %d |\n| summed seconds | %.1f | %.1f |\n\n",
		d.CommittedSource, d.Source, d.CommittedEntries, d.CandidateEntries, d.CommittedSum, d.CandidateSum)
	fmt.Fprintf(&b, "Added %d, removed %d, changed by more than 25%%: %d. %s\n", d.Added, d.Removed, d.ChangedOver25Pct, d.Note)
	return b.String()
}
