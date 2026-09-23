package main

import (
	"fmt"
	"strings"
)

func fmtSecs(p *float64) string {
	if p == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.0f s", *p)
}

func renderRunSummary(r RunReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## CI run report — %s run %d (attempt %d)\n\n", r.Run.Workflow, r.Run.RunID, r.Run.Attempt)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| class | `%s` (%s) |\n", r.Class, strings.Join(r.Reasons, "; "))
	fmt.Fprintf(&b, "| event / conclusion | %s / %s |\n", r.Run.Event, r.Run.Conclusion)
	fmt.Fprintf(&b, "| head / tested checkout | `%s` / `%s` |\n", short(r.Run.HeadSHA), short(r.Run.TestedSHA))
	fmt.Fprintf(&b, "| job set | `%s` |\n", r.JobSet.Key)
	if r.Toolchain != nil {
		fmt.Fprintf(&b, "| toolchain | %s %s/%s |\n", r.Toolchain.Go, r.Toolchain.GOOS, r.Toolchain.GOARCH)
	}
	if r.Config.TimingFileSource != "" {
		fmt.Fprintf(&b, "| timing file | %s |\n", r.Config.TimingFileSource)
	}
	t := r.Timing
	b.WriteString("\n**Time.** Elapsed values are wall clock from the attempt's start. Runner-minutes are summed job time — parallel jobs counted in full — and are not a bill.\n\n")
	fmt.Fprintf(&b, "| metric | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| elapsed to the required aggregate | %s |\n", fmtSecs(t.ElapsedToAggregate))
	fmt.Fprintf(&b, "| elapsed to the race verdict | %s |\n", fmtSecs(t.ElapsedToRaceVerdict))
	fmt.Fprintf(&b, "| wall span / busy (union of jobs) | %.0f s / %.0f s |\n", t.WallSpan, t.Busy)
	fmt.Fprintf(&b, "| runner-minutes (summed) | %.1f over %d jobs |\n", t.RunnerMinutes, t.Queue.Jobs)
	fmt.Fprintf(&b, "| job queue wait: median / max | %.0f s / %.0f s |\n", t.Queue.Median, t.Queue.Max)
	fmt.Fprintf(&b, "| job setup: median / max | %.0f s / %.0f s |\n", t.Setup.Median, t.Setup.Max)
	if rs := r.Race; rs != nil {
		b.WriteString("\n**Race path.**\n\n| shard | entries | test s | estimated s | job s |\n|---|---|---|---|---|\n")
		for _, s := range rs.Shards {
			fmt.Fprintf(&b, "| %d | %d | %.0f | %.0f | %s |\n", s.Index, s.Entries, s.Test, s.Estimated, fmtSecs(s.Job))
		}
		fmt.Fprintf(&b, "\nImbalance: max/mean %.2f, spread %.0f s, worst estimate error %.0f%%. Lane: %d packages, %.0f s test, job %s. Build job %s, verdict job %s.\n",
			rs.Imbalance.MaxOverMean, rs.Imbalance.SpreadSeconds, rs.Imbalance.EstimateError*100,
			rs.Lane.Packages, rs.Lane.Seconds, fmtSecs(rs.Lane.Job), fmtSecs(rs.BuildJobSeconds), fmtSecs(rs.VerdictSeconds))
		fmt.Fprintf(&b, "Inventory: %d root entries (%d skipped), %d lane entries.\n", rs.Inventory.RootEntries, rs.Inventory.RootSkipped, rs.Inventory.LaneEntries)
		writeRanked(&b, "Slowest packages", rs.Lane.Slowest)
		writeRanked(&b, "Slowest root tests", rs.SlowestRootTests)
	}
	a := r.Evidence.Audit
	fmt.Fprintf(&b, "\n**Evidence.** Verdict: `%s`. Audit: `%s`", r.Evidence.Verdict, a.State)
	if a.State == "passed" || a.State == "failed" {
		fmt.Fprintf(&b, " (lost %d, gained %d, excepted %d)", a.BlocksLost, a.BlocksGained, a.BlocksExcepted)
	}
	b.WriteString(".\n")
	writeList(&b, "Problems (contradictory evidence)", r.Problems)
	writeList(&b, "Unknown (not observable — never read as healthy)", r.Unknowns)
	return b.String()
}

func writeRanked(b *strings.Builder, title string, xs []NamedSeconds) {
	if len(xs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s: ", title)
	parts := make([]string, 0, len(xs))
	for _, x := range xs {
		parts = append(parts, fmt.Sprintf("`%s` %.1f s", x.Name, x.Seconds))
	}
	b.WriteString(strings.Join(parts, ", ") + ".\n")
}

func writeList(b *strings.Builder, title string, xs []string) {
	if len(xs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", title)
	for _, x := range xs {
		fmt.Fprintf(b, "- %s\n", x)
	}
}
