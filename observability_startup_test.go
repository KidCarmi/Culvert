package main

// observability_startup_test.go — P4.3 / S1 coverage for the
// extracted observability startup slice.
//
// Resolver tests are pure (no globals touched). Loader tests
// snapshot/restore the eleven package-level observability globals
// via t.Cleanup so they are safe under -shuffle=on / -count=2.
// File handles opened during tests are closed in cleanup; OTLP
// exporters spawned by Configure() are Stop()'d before pointer
// restore so no pushLoop goroutines leak across tests.
//
// CLAUDE.md "Test-authoring pitfalls": no len(auditGet()) delta
// assertions — the few tests that exercise audit-log init verify
// post-conditions on auditCloser / auditLogFilePath instead.

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/otlp"
	"github.com/KidCarmi/Culvert/internal/reqlog"
)

var observabilityStartupLoggerMu sync.Mutex

func ensureObservabilityStartupTestLogger(t *testing.T) {
	t.Helper()
	observabilityStartupLoggerMu.Lock()
	defer observabilityStartupLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// freshOTLPExporter constructs a zero-state metrics exporter for tests
// (nil snapshot: the engine exports an empty metric set).
func freshOTLPExporter() *OTLPExporter {
	return otlp.NewMetrics(nil)
}

// freshOTLPSpanExporter constructs a zero-state span exporter for tests.
func freshOTLPSpanExporter() *OTLPSpanExporter {
	return otlp.NewSpans()
}

// snapshotObservabilityGlobals saves and zeroes every package-level
// global that loadObservability can touch, then restores them on
// t.Cleanup. Any file handle or goroutine spawned by the test-under-
// test is closed/stopped in cleanup BEFORE the restore so the
// suite stays clean under -shuffle=on / -count=2.
func snapshotObservabilityGlobals(t *testing.T) {
	t.Helper()

	// Syslog forwarding (syslog.go + ui_config.go:648).
	oldSyslogConfigured := syslogConfigured
	oldGlobalSyslog := globalSyslog

	// Configured-path readback for GET /api/stats (ui_config.go).
	oldAuditLogConfiguredPath := auditLogConfiguredPath
	oldRequestLogConfiguredPath := requestLogConfiguredPath

	// OTLP (otlp.go + otlp_traces.go).
	oldGlobalOTLP := globalOTLP
	oldGlobalOTLPTraces := globalOTLPTraces

	// Audit engine (internal/audit).
	restoreAudit := audit.ResetForTest()

	// Request-log persistence (internal/reqlog). The restore closes any
	// handle the test-under-test opened before reinstating the snapshot.
	restoreReqlog := reqlog.SwapPersistenceForTest()

	syslogConfigured = ""
	globalSyslog = nil
	globalOTLP = freshOTLPExporter()
	globalOTLPTraces = freshOTLPSpanExporter()
	auditLogConfiguredPath = ""
	requestLogConfiguredPath = ""

	t.Cleanup(func() {
		// Close handles + stop goroutines the test opened on the
		// fresh instances before restoring originals.
		if globalSyslog != nil {
			_ = globalSyslog.Close()
		}
		globalOTLP.Stop()
		globalOTLPTraces.Stop()
		_ = audit.Close() // close any handle the test-under-test opened
		syslogConfigured = oldSyslogConfigured
		globalSyslog = oldGlobalSyslog
		globalOTLP = oldGlobalOTLP
		globalOTLPTraces = oldGlobalOTLPTraces
		auditLogConfiguredPath = oldAuditLogConfiguredPath
		requestLogConfiguredPath = oldRequestLogConfiguredPath
		audit.ClearPersistForTest() // closed above; restore must not double-close
		restoreAudit()
		restoreReqlog()
	})
}

// ─── Resolver ────────────────────────────────────────────────────────

func TestResolveObservabilityStartupConfig_Defaults(t *testing.T) {
	got := resolveObservabilityStartupConfig(&FileConfig{}, "", "", "", "", "", 0)
	if got.SyslogAddr != "" || got.SyslogFormat != "" || got.OTLPEndpoint != "" ||
		got.AuditLogPath != "" || got.RequestLogPath != "" {
		t.Errorf("non-empty defaults in zero-value DTO: %+v", got)
	}
	if got.RequestLogMaxMB != 100 {
		t.Errorf("RequestLogMaxMB = %d; want 100 default", got.RequestLogMaxMB)
	}
}

func TestResolveObservabilityStartupConfig_CLIWinsOverFC(t *testing.T) {
	fc := &FileConfig{}
	fc.SyslogAddr = "fc-syslog"
	fc.SyslogFormat = "fc-fmt"
	fc.OTLPEndpoint = "fc-otlp"
	fc.AuditLogFile = "/fc/audit"
	fc.RequestLogFile = "/fc/req"
	fc.RequestLogMaxMB = 200

	got := resolveObservabilityStartupConfig(fc,
		"cli-syslog", "cli-fmt", "cli-otlp", "/cli/audit", "/cli/req", 50,
	)

	want := observabilityStartupConfig{
		SyslogAddr:      "cli-syslog",
		SyslogFormat:    "cli-fmt",
		OTLPEndpoint:    "cli-otlp",
		AuditLogPath:    "/cli/audit",
		RequestLogPath:  "/cli/req",
		RequestLogMaxMB: 50,
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestResolveObservabilityStartupConfig_FCFallback(t *testing.T) {
	fc := &FileConfig{}
	fc.SyslogAddr = "fc-syslog"
	fc.SyslogFormat = "fc-fmt"
	fc.OTLPEndpoint = "fc-otlp"
	fc.AuditLogFile = "/fc/audit"
	fc.RequestLogFile = "/fc/req"
	fc.RequestLogMaxMB = 200

	got := resolveObservabilityStartupConfig(fc, "", "", "", "", "", 0)
	want := observabilityStartupConfig{
		SyslogAddr:      "fc-syslog",
		SyslogFormat:    "fc-fmt",
		OTLPEndpoint:    "fc-otlp",
		AuditLogPath:    "/fc/audit",
		RequestLogPath:  "/fc/req",
		RequestLogMaxMB: 200,
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestResolveObservabilityStartupConfig_RequestLogMaxMB_DefaultWhenBothZero(t *testing.T) {
	got := resolveObservabilityStartupConfig(&FileConfig{}, "", "", "", "", "", 0)
	if got.RequestLogMaxMB != 100 {
		t.Errorf("RequestLogMaxMB = %d; want 100", got.RequestLogMaxMB)
	}
}

func TestResolveObservabilityStartupConfig_RequestLogMaxMB_FCWinsWhenCLIZero(t *testing.T) {
	fc := &FileConfig{}
	fc.RequestLogMaxMB = 25
	got := resolveObservabilityStartupConfig(fc, "", "", "", "", "", 0)
	if got.RequestLogMaxMB != 25 {
		t.Errorf("RequestLogMaxMB = %d; want 25 (FC > 0 beats default)", got.RequestLogMaxMB)
	}
}

// ─── Loader ──────────────────────────────────────────────────────────

func TestLoadObservability_EmptyConfigIsNoOp(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	loadObservability(observabilityStartupConfig{})

	if syslogConfigured != "" {
		t.Errorf("syslogConfigured = %q; want empty", syslogConfigured)
	}
	if globalSyslog != nil {
		t.Errorf("globalSyslog = %v; want nil", globalSyslog)
	}
	if globalOTLP.Enabled() {
		t.Errorf("globalOTLP.Enabled() = true; want false")
	}
	if globalOTLPTraces.Enabled() {
		t.Errorf("globalOTLPTraces.Enabled() = true; want false")
	}
	if audit.PersistActive() {
		t.Error("audit persistence active; want inactive (no AuditLogPath)")
	}
	if reqlog.PersistActive() {
		t.Error("request-log persistence active; want inactive (no RequestLogPath)")
	}
}

func TestLoadObservability_AuditLogOpens(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	loadObservability(observabilityStartupConfig{
		AuditLogPath:    path,
		RequestLogMaxMB: 100,
	})

	if !audit.PersistActive() {
		t.Fatal("audit persistence inactive after AuditLogPath set; want active")
	}
	if auditLogConfiguredPath != path {
		t.Errorf("auditLogConfiguredPath = %q; want %q", auditLogConfiguredPath, path)
	}
}

// TestLoadObservability_AuditLogFallbackIsDistinguishable proves the GET
// /api/stats blind spot is closed: a configured-but-unopenable audit path
// (here, a directory, which os.OpenFile rejects with EISDIR) leaves
// PersistActive false while auditLogConfiguredPath stays non-empty — the
// exact signal apiStats needs to tell "silently fell back to volatile
// in-memory storage" apart from "operator never configured a path".
func TestLoadObservability_AuditLogFallbackIsDistinguishable(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	dirAsPath := t.TempDir() // opening a directory for writing fails
	loadObservability(observabilityStartupConfig{
		AuditLogPath:    dirAsPath,
		RequestLogMaxMB: 100,
	})

	if audit.PersistActive() {
		t.Fatal("audit persistence active despite unopenable path; want inactive (fallback)")
	}
	if auditLogConfiguredPath != dirAsPath {
		t.Errorf("auditLogConfiguredPath = %q; want %q (configured path must survive Init failure)", auditLogConfiguredPath, dirAsPath)
	}
}

func TestLoadObservability_RequestLogOpens(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	path := filepath.Join(t.TempDir(), "request.jsonl")
	loadObservability(observabilityStartupConfig{
		RequestLogPath:  path,
		RequestLogMaxMB: 10,
	})

	if !reqlog.PersistActive() {
		t.Fatal("request-log persistence inactive after RequestLogPath set; want active")
	}
	if requestLogConfiguredPath != path {
		t.Errorf("requestLogConfiguredPath = %q; want %q", requestLogConfiguredPath, path)
	}
	if reqlog.FilePath() != path {
		t.Errorf("reqlog.FilePath() = %q; want %q", reqlog.FilePath(), path)
	}
}

// TestLoadObservability_RequestLogFallbackIsDistinguishable mirrors
// TestLoadObservability_AuditLogFallbackIsDistinguishable for the
// request-log engine.
func TestLoadObservability_RequestLogFallbackIsDistinguishable(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	dirAsPath := t.TempDir()
	loadObservability(observabilityStartupConfig{
		RequestLogPath:  dirAsPath,
		RequestLogMaxMB: 100,
	})

	if reqlog.PersistActive() {
		t.Fatal("request-log persistence active despite unopenable path; want inactive (fallback)")
	}
	if requestLogConfiguredPath != dirAsPath {
		t.Errorf("requestLogConfiguredPath = %q; want %q (configured path must survive Init failure)", requestLogConfiguredPath, dirAsPath)
	}
}

func TestLoadObservability_SyslogUnreachableLogged(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	// tcp://127.0.0.1:1 — no listener; InitSyslog returns an error.
	loadObservability(observabilityStartupConfig{
		SyslogAddr:      "tcp://127.0.0.1:1",
		RequestLogMaxMB: 100,
	})

	if syslogConfigured != "" {
		t.Errorf("syslogConfigured = %q; want empty after unreachable syslog", syslogConfigured)
	}
	if globalSyslog != nil {
		t.Errorf("globalSyslog = %v; want nil after failed dial", globalSyslog)
	}
}

func TestLoadObservability_SyslogSuccessSetsConfigured(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	// Bind an ephemeral UDP listener so InitSyslog succeeds.
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	addr := pc.LocalAddr().String()

	cfgAddr := "udp://" + addr
	loadObservability(observabilityStartupConfig{
		SyslogAddr:      cfgAddr,
		SyslogFormat:    "rfc3164",
		RequestLogMaxMB: 100,
	})

	if syslogConfigured != cfgAddr {
		t.Errorf("syslogConfigured = %q; want %q", syslogConfigured, cfgAddr)
	}
	if globalSyslog == nil {
		t.Error("globalSyslog == nil after successful InitSyslog")
	}
}

func TestLoadObservability_OTLPEndpointConfigured(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	// Endpoint string is just stored; pushLoop spawns but won't
	// reach a real collector. snapshotObservabilityGlobals.Cleanup
	// calls Stop() on both exporters.
	const endpoint = "http://otlp.invalid:4318"
	loadObservability(observabilityStartupConfig{
		OTLPEndpoint:    endpoint,
		RequestLogMaxMB: 100,
	})

	if !globalOTLP.Enabled() {
		t.Error("globalOTLP.Enabled() = false; want true after Configure")
	}
	if got := globalOTLP.Endpoint(); !strings.HasPrefix(got, "http://otlp.invalid") {
		t.Errorf("globalOTLP.Endpoint() = %q; want prefix %q", got, "http://otlp.invalid")
	}
	if !globalOTLPTraces.Enabled() {
		t.Error("globalOTLPTraces.Enabled() = false; want true after Configure")
	}
}

func TestLoadObservability_OTLPEmptyLeavesGlobalsDisabled(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	loadObservability(observabilityStartupConfig{
		// OTLPEndpoint left empty.
		RequestLogMaxMB: 100,
	})

	if globalOTLP.Enabled() {
		t.Error("globalOTLP.Enabled() = true; want false when OTLPEndpoint is empty")
	}
	if globalOTLPTraces.Enabled() {
		t.Error("globalOTLPTraces.Enabled() = true; want false when OTLPEndpoint is empty")
	}
}
