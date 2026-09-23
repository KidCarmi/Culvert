// Command rootshard is the CI-REDESIGN stage 5A root-suite sharding PILOT: it
// splits the root package's race+coverage test suite across isolated processes
// and proves, before anyone relies on it, that nothing was lost on the way —
// no test, no coverage block and no failure.
//
// Why a tool and not a shell pipeline: every step here is a place a sharded
// suite can SILENTLY lose evidence (a test no regex selected, an escaping bug
// that selects a neighbour, an empty selection that `-test.run` reads as "run
// everything", a shard that crashed and wrote no profile, a profile from a
// different binary). Each of those has to fail closed, and each failure path is
// pinned by a test in this package, which the ordinary `go test ./...` runs.
//
// Subcommands (all JSON artifacts are deterministic):
//
//	build     compile the root race+coverage test binary ONCE, list its entries
//	          from the binary itself, time an empty run, write manifest.json
//	plan      partition the binary's inventory into N shards by measured duration
//	run-shard run one shard's chunks against the prebuilt binary
//	run-lane  run every OTHER package of the module as whole packages
//	verdict   check every shard + the lane, merge all coverage profiles
//	compare   compare the pilot against the unsharded reference run
//	timings   derive a timing file from a reference `go test -v` log
//
// See roadmap/CI-REDESIGN.md §13 and .github/workflows/qa-root-shard-pilot.yml.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// errUsage marks an invocation error, reported with exit status 2.
var errUsage = errors.New("usage")

var commands = map[string]func(args []string, stdout io.Writer) error{
	"build":     cmdBuild,
	"plan":      cmdPlan,
	"run-shard": cmdRunShard,
	"run-lane":  cmdRunLane,
	"verdict":   cmdVerdict,
	"compare":   cmdCompare,
	"timings":   cmdTimings,
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		sayln(stderr, "usage: rootshard <build|plan|run-shard|run-lane|verdict|compare|timings> [flags]")
		return 2
	}
	cmd, ok := commands[args[0]]
	if !ok {
		say(stderr, "rootshard: unknown subcommand %q\n", args[0])
		return 2
	}
	if err := cmd(args[1:], stdout); err != nil {
		say(stderr, "rootshard %s: %v\n", args[0], err)
		if errors.Is(err, errUsage) || errors.Is(err, flag.ErrHelp) {
			return 2
		}
		return 1
	}
	return 0
}

// newFlags returns a FlagSet that reports parse errors instead of exiting, so
// run() owns the exit status.
func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// required fails with errUsage when any named string flag was left empty.
func required(fs *flag.FlagSet, names ...string) error {
	for _, n := range names {
		f := fs.Lookup(n)
		if f == nil || f.Value.String() == "" {
			return fmt.Errorf("%w: -%s is required", errUsage, n)
		}
	}
	return nil
}

// say writes human-readable progress to the job log. A failed log write cannot
// change a verdict — every decision is carried by the exit status and the JSON
// artifacts, which are written and checked separately — so it is deliberately
// discarded here, in one place, rather than at every call site.
func say(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func sayln(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}
