package main

// geoip_startup_test.go — PR3 expansion Batch 1 coverage.

import (
	"log"
	"os"
	"sync"
	"testing"
)

var geoIPLoggerMu sync.Mutex

func ensureGeoIPTestLogger(t *testing.T) {
	t.Helper()
	geoIPLoggerMu.Lock()
	defer geoIPLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

func TestResolveGeoIPStartupConfig_CLIWinsOverFileConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.GeoIPDB = "/etc/from-config.mmdb"
	got := resolveGeoIPStartupConfig(fc, "/etc/from-cli.mmdb")
	if got.DBPath != "/etc/from-cli.mmdb" {
		t.Errorf("CLI should win; got %q", got.DBPath)
	}
}

func TestResolveGeoIPStartupConfig_FallbackToFileConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.GeoIPDB = "/etc/from-config.mmdb"
	got := resolveGeoIPStartupConfig(fc, "")
	if got.DBPath != "/etc/from-config.mmdb" {
		t.Errorf("expected FileConfig value; got %q", got.DBPath)
	}
}

func TestResolveGeoIPStartupConfig_Empty(t *testing.T) {
	got := resolveGeoIPStartupConfig(&FileConfig{}, "")
	if got.DBPath != "" {
		t.Errorf("expected empty DBPath; got %q", got.DBPath)
	}
}

// Empty path: the loader must log "disabled" without calling InitGeoDB.
// We can't observe the log directly here without more plumbing — the
// regression guard is that no panic occurs and the function returns cleanly.
func TestLoadGeoIP_EmptyPathIsNoop(t *testing.T) {
	ensureGeoIPTestLogger(t)
	loadGeoIP(geoIPStartupConfig{DBPath: ""}) // must not panic or error
}

// Non-existent path: InitGeoDB returns an error; loader logs a "disabled"
// warning and returns without panic.
func TestLoadGeoIP_MissingFileIsNonFatal(t *testing.T) {
	ensureGeoIPTestLogger(t)
	loadGeoIP(geoIPStartupConfig{DBPath: "/does/not/exist.mmdb"}) // must not panic
}
