package main

// testmain_datadir_paths_red_test.go — the test binary's persisted-state root
// must bind EVERY /data-rooted default, not only dataDir.
//
// TestMain gives the binary a writable temp dataDir, but the defaults that
// rebindDataDirPaths derives (config-version store, registry settings, CDR
// certs root and runtime marker, alert retry queue) stayed at the literal
// production "/data/...". On a CI runner there is no /data, so every write to
// them fails, and fileutil's write-failure observer feeds any OPEN
// storage-write scope — which is time-based, not goroutine-based. A webhook
// delivery that an earlier test left in flight (cdr_alert_bound_test.go, then
// undrained, to https://example.invalid) failed a few ms later, saved its retry
// queue to /data/alert_retry_queue.json inside the rollback scope of
// TestDCFin5_HistoricalRollbackIdentitySurvivesRestart, and turned that
// rollback into a 500 "rolled_back_not_durable" (Deep · determinism, seed
// -test.shuffle 1792171671618181963).
//
// RED without the rebind in TestMain. The config-version assertion is
// order-independent: TestDataDirOverride_RebindsHardcodedDefaults restores
// the pre-test configVersions OBJECT, so before the fix it stays at
// /data/config_versions whatever ran first.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

func TestTestMain_BindsPersistedStateDefaultsToTestDataDir(t *testing.T) {
	inside := dataDir + string(filepath.Separator)
	if dataDir == defaultDataDir {
		t.Fatalf("test binary runs against the production data root %q", dataDir)
	}
	for name, p := range map[string]string{
		"alert retry queue":          alerts.RetryQueuePath(),
		"config-version store":       configVersions.Dir(),
		"registry settings file":     registrySettingsFile,
		"CDR certs root":             cdrCertsRoot,
		"CDR runtime-enabled marker": cdrRuntimeEnabledPath,
	} {
		if !strings.HasPrefix(p, inside) {
			t.Errorf("%s persists at %q, outside the test binary's data root %q: "+
				"writes there fail on a runner without /data and pollute a host that has one",
				name, p, dataDir)
		}
	}
}
