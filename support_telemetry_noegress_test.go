package main

// support_telemetry_noegress_test.go — the M7 Slice 1 no-egress wall
// (roadmap/M7-proactive-telemetry-plan.md §14/§15 TestSupportTelemetrySlice1HasNoEgress).
// Slice 1 is registry + preview ONLY: no consent switch, no sender, no
// config, no spool, no credential/endpoint persistence. This test extends
// the existing support-surface no-egress wall (support_noegress_test.go) to
// the telemetry files specifically, so a later slice that accidentally
// wires egress into a Slice-1 file — rather than its own dedicated Slice 3
// sender file — fails loudly here.
//
// Two layers, mirroring support_noegress_test.go's convention:
//  1. IMPORT WALL — internal/supportmetrics (the engine) may not import any
//     net-capable package at all.
//  2. SOURCE WALL — every support_telemetry_*.go file in package main may not
//     contain any outbound-call marker (http.Client, http.NewRequest,
//     net.Dial, timers/tickers, goroutines). Zero occurrences allowed — Slice
//     1 has no audited seam to pin, unlike the diagnose surface.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenTelemetryEngineImports mirrors support_noegress_test.go's
// forbiddenEngineImports: outbound network/process packages the offline-only
// supportmetrics engine must never link.
var forbiddenTelemetryEngineImports = map[string]bool{
	"net": true, "net/http": true, "net/smtp": true, "net/rpc": true,
	"net/url": true, "os/exec": true, "syscall": true,
}

func TestSupportTelemetryEngine_ImportWall(t *testing.T) {
	fset := token.NewFileSet()
	dir := filepath.Join(pkgSourceDir(), "internal", "supportmetrics")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read internal/supportmetrics: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if forbiddenTelemetryEngineImports[p] {
				t.Errorf("%s imports %q — the support-metric registry engine is offline-only (Slice 1: zero egress)", path, p)
			}
		}
	}
}

// telemetryOutboundIdents are call-site markers indicating outbound network,
// process execution, background workers, or delivery-retry machinery — none
// of which Slice 1 may contain (that's exclusively Slice 3's, per §14).
var telemetryOutboundIdents = []string{
	"http.Get(", "http.Post(", "http.PostForm(", "http.Head(",
	"http.DefaultClient", "http.Client{", "http.NewRequest",
	"net.Dial(", "net.DialTimeout(", "net.Dialer{", "tls.Dial",
	"exec.Command", "exec.CommandContext", "DefaultResolver",
	"time.NewTicker(", "time.NewTimer(", "time.AfterFunc(",
	"go func(",
}

// TestSupportTelemetrySlice1HasNoEgress scans every M7 Slice 1 telemetry
// file in package main for outbound-call/background-worker markers. Zero
// occurrences are allowed anywhere — unlike the diagnose surface's audited
// seams, Slice 1 has no legitimate reason to dial anything or start a
// goroutine.
func TestSupportTelemetrySlice1HasNoEgress(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(pkgSourceDir(), "support_telemetry_*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no support_telemetry_*.go files found — glob pattern or working directory wrong?")
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(b)
		for _, ident := range telemetryOutboundIdents {
			if strings.Contains(src, ident) {
				t.Errorf("%s contains outbound/background-worker marker %q — M7 Slice 1 is registry+preview only, zero egress", path, ident)
			}
		}
	}
}

// TestSupportTelemetrySlice1NoStartupWiring proves the preview route is not
// wired into any startup/init path (no sender to start, no config to load).
// Mirrors the design's Slice-3-only "TestNoAutoTelemetry: static scan: gate
// not in startup files" precedent, applied here to prove Slice 1 introduces
// no startup coupling at all.
func TestSupportTelemetrySlice1NoStartupWiring(t *testing.T) {
	startupFiles := []string{"main.go", "main_shutdown.go"}
	for _, name := range startupFiles {
		b, err := os.ReadFile(filepath.Join(pkgSourceDir(), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		for _, marker := range []string{"supportTelemetry", "SupportTelemetry", "supportMetricRegistry"} {
			if strings.Contains(src, marker) {
				t.Errorf("%s references %q — M7 Slice 1 must not be wired into startup (no sender/consent exists yet)", name, marker)
			}
		}
	}
}
