// Command mcp-observe-acceptance runs the artifact-bound MCP Gateway Observe
// Acceptance Harness (QUAL-6) against a BUILT culvert binary and writes a
// deterministic, tamper-evident, secret-free evidence bundle.
//
// It is an ACCEPTANCE TEST harness only. It never begins Observe, never starts a
// qualification-duration window (it never calls BeginWindow), never promotes a
// Catalog tool, never enables execution, and never changes rollout mode or unlocks
// Production. A PASS bundle is evidence for an Observe acceptance decision; it is
// NOT authorization to transition rollout.
//
// Usage:
//
//	mcp-observe-acceptance -spec acceptance.json
//
// The spec selects authoritative mode (a signed artifact, matched digest +
// provenance, operator environment) or dev mode (a locally built binary, evidence
// marked authoritative:false — never qualification evidence). See
// docs/operator/mcp-observe-acceptance-harness.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcpacceptance"
)

func main() { os.Exit(run()) }

// run performs the acceptance and returns a process exit code (0 PASS, 1 FAIL, 2
// usage/error). Keeping os.Exit out of any deferred scope lets the deferred
// context cleanups run normally on return.
func run() int {
	specPath := flag.String("spec", "", "path to the acceptance spec JSON (required)")
	sourceSHA := flag.String("source-sha", "", "harness source commit, recorded in the bundle")
	timeout := flag.Duration("timeout", 15*time.Minute, "overall bounded run timeout")
	flag.Parse()

	if *specPath == "" {
		fmt.Fprintln(os.Stderr, "mcp-observe-acceptance: -spec is required")
		return 2
	}
	spec, err := mcpacceptance.LoadSpec(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-observe-acceptance: %v\n", err)
		return 2
	}
	h, err := mcpacceptance.NewHarness(spec, mcpacceptance.Options{SourceSHA: *sourceSHA})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-observe-acceptance: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	summary, err := h.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-observe-acceptance: run error: %v\n", err)
		return 2
	}
	fmt.Printf("acceptance run %s: overall=%s authoritative=%v evidence=%s\n",
		summary.RunID, summary.Overall, summary.Authoritative, spec.EvidenceDir)
	for i := range summary.Criteria {
		c := &summary.Criteria[i]
		if c.Status != mcpacceptance.StatusPass {
			fmt.Printf("  %-28s %-6s %s\n", c.ID, c.Status, c.Reason)
		}
	}
	if summary.Overall != mcpacceptance.StatusPass {
		return 1
	}
	return 0
}
