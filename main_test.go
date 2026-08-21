package main

import (
	"log"
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// TestMain initializes globals that proxy code expects before any test runs.
func TestMain(m *testing.M) {
	logger = log.New(os.Stderr, "[test] ", 0)
	// Route internal/* package logs (obs facade) into the same package-level
	// logger, mirroring production wiring (initLogger, ADR-0003 seam). The
	// closure reads `logger` at call time, so helpers that swap the logger
	// (e.g. captureLogger) capture obs-emitted lines too — without this the
	// obs default sink writes straight to stderr and observability tests for
	// extracted leaves (internal/bandwidth, internal/nodegroup, ...) see "".
	obs.SetSink(func(line string) { logger.Print(line) })
	// Give the test binary a writable default dataDir so components that now persist
	// node-local state (e.g. the durable MCP rollout state, mcp_rollout_persist.go)
	// do not fail against the production "/data" default. Tests that need a specific
	// dataDir still override it via withTempDataDir (which saves/restores this value).
	if td, err := os.MkdirTemp("", "culvert-test-datadir-"); err == nil {
		dataDir = td
		code := m.Run()
		os.RemoveAll(td)
		os.Exit(code)
	}
	os.Exit(m.Run())
}
