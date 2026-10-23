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
		// Bind the /data-rooted package defaults that are NOT derived from
		// dataDir at their own startup (config-version store, registry
		// settings, CDR certs root and runtime marker, alert retry queue) to
		// the same root, exactly as production applyDataDirFromEnv does.
		// Setting dataDir alone left them at the literal "/data/...": a host
		// with a writable /data accumulated test state (v50.json…v106.json in
		// an agent container), and on a CI runner, where /data does not exist,
		// every such write failed. A failed write feeds any OPEN storage-write
		// scope, which is time-based (storage_health.go), so a webhook delivery
		// an earlier test left in flight saved its retry queue inside an
		// unrelated rollback's scope and turned it into rolled_back_not_durable
		// (TestDCFin5_HistoricalRollbackIdentitySurvivesRestart, seed
		// 1792171671618181963). Pinned by
		// TestTestMain_BindsPersistedStateDefaultsToTestDataDir.
		//
		// Then Init the rebound config-version store, as production startup
		// does (loadPersistentAdminState → initConfigVersioning, after
		// applyDataDirFromEnv). configver.New does not create its directory,
		// so without Init every unisolated saveConfigVersion still failed with
		// ENOENT and fed the same storage-failure observer (Codex review on
		// #1634).
		rebindDataDirPaths()
		initConfigVersioning()
		code := m.Run()
		os.RemoveAll(td)
		os.Exit(code)
	}
	os.Exit(m.Run())
}
