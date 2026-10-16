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
		// Bind the /data-rooted package defaults that are NOT derived from dataDir
		// at their own startup (config-version store, registry settings, CDR certs
		// root and runtime marker, alert retry queue) to the same root, exactly as
		// production applyDataDirFromEnv does. Setting dataDir alone left them at
		// the literal "/data/...": a dev host with a writable /data got test state
		// written into it, and on a CI runner (no /data) every such write failed.
		// A failed webhook delivery leaked by an earlier test then saved its retry
		// queue inside an unrelated rollback's storage-write scope (time-based, see
		// storage_health.go) and turned that rollback into rolled_back_not_durable.
		// Pinned by TestTestMain_BindsPersistedStateDefaultsToTestDataDir.
		rebindDataDirPaths()
		code := m.Run()
		os.RemoveAll(td)
		os.Exit(code)
	}
	os.Exit(m.Run())
}
