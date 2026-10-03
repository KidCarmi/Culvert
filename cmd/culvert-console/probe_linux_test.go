//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeProcess(t *testing.T) {
	// The current test binary is also a hermetic child process for runProbe.
	switch os.Args[len(os.Args)-1] {
	case "probe-output":
		fmt.Print(strings.Repeat("x", maxOutput*2))
		os.Exit(0)
	case "probe-fail":
		fmt.Fprintln(os.Stderr, "NEVER_DISPLAY")
		fmt.Print("invalid success")
		os.Exit(1)
	case "probe-sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func TestProbeBoundsAndFailure(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if len(runProbe(context.Background(), []string{exe, "-test.run=^TestProbeProcess$", "--", "probe-output"})) != maxOutput {
		t.Fatal("stdout not capped")
	}
	if runProbe(context.Background(), []string{exe, "-test.run=^TestProbeProcess$", "--", "probe-fail"}) != "" {
		t.Fatal("failed probe exposed data")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if runProbe(ctx, []string{exe, "-test.run=^TestProbeProcess$", "--", "probe-sleep"}) != "" {
		t.Fatal("timed out probe succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("probe did not respect deadline")
	}
	if runProbe(context.Background(), []string{filepath.Join(t.TempDir(), "absent")}) != "" {
		t.Fatal("missing command succeeded")
	}
}
