//go:build lifecycle_conformance

// Command lifecyclecheck is the deterministic property gate for the lifecycle model.
// No network, standard library only.
//
//	go run -tags lifecycle_conformance ./internal/lifecyclemodel/cmd/lifecyclecheck [flags]
//
// Exit: 0 every counted property passes | 1 a counted property fails |
// 2 incomplete exploration, a vacuous property or an unusable baseline (takes precedence
// over 1; never a pass) | 3 everything passed but the model drifted from the reviewed
// baseline.json (see baseline.go).
// With -summary it only renders an existing report directory as Markdown. With
// -write-baseline it records the current baseline instead of comparing against it.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"culvert-maint/internal/lifecyclemodel"
)

func main() {
	var o lifecyclemodel.GateOptions
	flag.BoolVar(&o.IncludeProposed, "include-proposed", false, "also evaluate properties whose status is `proposed`")
	flag.BoolVar(&o.FailOnlyApproved, "fail-only-approved", false,
		"a failing property that is not owner-approved is printed with its trace but does not cause exit 1 (exit 2 is never downgraded)")
	flag.IntVar(&o.MaxStates, "max-states", 200_000, "state budget; exceeding it is INCOMPLETE (exit 2)")
	maxSeconds := flag.Float64("max-seconds", 60, "time budget in seconds; exceeding it is INCOMPLETE (exit 2)")
	flag.StringVar(&o.ReportDir, "report", "", "write model_check.json into this directory")
	noBaseline := flag.Bool("no-baseline", false, "do not compare with the embedded reviewed baseline (stated in the output)")
	flag.StringVar(&o.WriteBaseline, "write-baseline", "", "write the current baseline to this file instead of comparing")
	summary := flag.String("summary", "", "print the Markdown step summary for this report directory and exit")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments:", flag.Args())
		os.Exit(lifecyclemodel.ExitIncomplete)
	}
	if *summary != "" {
		lifecyclemodel.WriteSummary(*summary, os.Stdout)
		return
	}
	o.MaxDuration = time.Duration(*maxSeconds * float64(time.Second))
	if *noBaseline {
		fmt.Println("NOTE: -no-baseline: drift from the reviewed baseline is NOT checked")
	} else if o.WriteBaseline == "" {
		o.Baseline = lifecyclemodel.EmbeddedBaselineJSON()
	}
	os.Exit(lifecyclemodel.RunGate(lifecyclemodel.EmbeddedPropertiesJSON(), o, os.Stdout))
}
