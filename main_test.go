package main

import (
	"log"
	"os"
	"path/filepath"
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
		// The config-version store is a package default bound to
		// "/data/config_versions" at init, not derived from dataDir, so every
		// admin-handler test that reaches saveConfigVersion without
		// snapshotConfigVersionsDir wrote into the HOST's /data whenever that
		// directory existed (a developer box or agent container accumulated
		// v50.json…v106.json across runs), while on the CI runner, where /data
		// does not exist, the same writes failed. Point the store under the
		// temp root but leave the directory UNCREATED: unisolated writes keep
		// failing with ENOENT exactly as they do in CI, and nothing reaches
		// the host. Tests that need a working store still isolate one with
		// snapshotConfigVersionsDir / SetDirForTest, which save and restore
		// this value.
		configVersions.SetDirForTest(filepath.Join(td, "config_versions"))
		code := m.Run()
		os.RemoveAll(td)
		os.Exit(code)
	}
	os.Exit(m.Run())
}
