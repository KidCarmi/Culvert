package main

// support_telemetry_noegress_test.go — the M7 no-egress wall
// (roadmap/M7-proactive-telemetry-plan.md §14/§15
// TestSupportTelemetrySlice1HasNoEgress / TestNoTelemetryEgressSlice2).
// Slices 1 AND 2 are registry+preview and consent+config+GUI respectively:
// neither has a sender, spool, retry/backoff, or any delivery machinery —
// that is exclusively Slice 3's. This test extends the existing
// support-surface no-egress wall (support_noegress_test.go) to the telemetry
// files specifically, so a later slice that accidentally wires egress into a
// Slice-1/2 file — rather than its own dedicated Slice 3 sender file — fails
// loudly here.
//
// Two layers, mirroring support_noegress_test.go's convention:
//  1. IMPORT WALL — internal/supportmetrics (the engine) may not import any
//     net-capable package at all.
//  2. SOURCE WALL — every support_telemetry_*.go file in package main may not
//     contain any outbound-call marker (http.Client, http.NewRequest,
//     net.Dial, timers/tickers, goroutines). Zero occurrences allowed —
//     neither slice has an audited seam to pin, unlike the diagnose surface.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
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

// telemetryStartupFiles are the startup seams the wall inspects — including
// the ACTUAL seam the merged design names for the future sender (§14 Slice
// 3: "Sender started in loadPersistentAdminState next to the upload
// worker"), so an accidental sender wiring in the real seam fails here
// instead of passing silently.
var telemetryStartupFiles = []string{
	"main.go", "main_shutdown.go",
	"persistent_admin_state_startup.go", // the named Slice-3 sender seam (§14)
	"background_services_startup.go",
}

// telemetryForbiddenStartupIdents are the startup references that would mean
// a SENDER/WORKER exists. Slice 2 legitimately performs ONE synchronous
// config validation at boot (loadTelemetryConfigAtStartup — the §14
// persistence contract), so the wall can no longer forbid the mere mention
// of telemetry in a startup file; it forbids the things that would actually
// constitute egress or background work.
var telemetryForbiddenStartupIdents = []string{
	"startTelemetry", "TelemetrySender", "telemetrySender",
	"startSupportTelemetry", "telemetryWorker", "telemetryPushLoop",
	"telemetrySpool", "telemetryPending",
	"supportMetricRegistry", // the registry is a Slice 1 engine — never armed at boot
}

// TestSupportTelemetrySlice1NoStartupWiring proves no telemetry SENDER or
// background worker is wired into any startup/init path. Mirrors the
// design's Slice-3-only "TestNoAutoTelemetry: static scan: gate not in
// startup files" precedent.
//
// Slice 2 CHANGED the shape of this wall deliberately: the §14 persistence
// contract requires the telemetry config to be loaded/validated through the
// established persistent-admin-state startup path, so a blanket
// "no telemetry identifier may appear in a startup file" rule would forbid
// the very thing the design asks for. The wall therefore now targets
// sender/worker/spool identifiers, and
// TestTelemetryStartupValidationHasNoSideEffects proves the one permitted
// startup call is inert.
func TestSupportTelemetrySlice1NoStartupWiring(t *testing.T) {
	for _, name := range telemetryStartupFiles {
		b, err := os.ReadFile(filepath.Join(pkgSourceDir(), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		for _, marker := range telemetryForbiddenStartupIdents {
			if strings.Contains(src, marker) {
				t.Errorf("%s references %q — no telemetry sender/worker may be wired into startup (Slice 3 is blocked on §13)", name, marker)
			}
		}
		// The ONLY telemetry call permitted in a startup file is the
		// synchronous config validation. Any other telemetry* call there is
		// a new startup coupling that must be reviewed, not assumed benign.
		for _, m := range regexp.MustCompile(`\b(?:load|start|init|run)[A-Za-z]*[Tt]elemetry[A-Za-z]*\(`).FindAllString(src, -1) {
			if m != "loadTelemetryConfigAtStartup(" {
				t.Errorf("%s calls %q in a startup path — only the inert loadTelemetryConfigAtStartup() validation is permitted (no sender until Slice 3)", name, m)
			}
		}
	}
}

// TestTelemetryStartupValidationHasNoSideEffects proves the one permitted
// startup call is genuinely inert: it starts no goroutine, creates no file,
// and — critically — performs no network activity. Goroutine count is
// sampled before/after (with a settle window) so an accidental `go func()`
// inside the validation path fails here.
func TestTelemetryStartupValidationHasNoSideEffects(t *testing.T) {
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prevDir })

	// A fully-configured, VALID config — the case most likely to tempt an
	// implementation into "arming" something at boot.
	telemetryConfigMu.Lock()
	err := saveTelemetryConfigLocked(telemetryConfig{
		Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "startup-test-token",
	})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	before := listDirTree(t, dataDir)
	goroutinesBefore := runtime.NumGoroutine()

	loadTelemetryConfigAtStartup()

	// Let any (illegitimately) spawned goroutine actually get scheduled
	// before sampling, so this doesn't pass by racing ahead of it.
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > goroutinesBefore {
		t.Errorf("startup validation started %d goroutine(s) — it must be strictly synchronous and inert",
			after-goroutinesBefore)
	}
	if after := listDirTree(t, dataDir); !reflect.DeepEqual(after, before) {
		t.Errorf("startup validation changed filesystem state: before=%v after=%v", before, after)
	}
}

// TestTelemetryStartupValidationSourceIsInert is the static counterpart:
// the startup validation function's own source may not contain any
// outbound/background marker. Together with the behavioral test above this
// covers both "it doesn't dial today" and "it can't grow a dialer quietly".
func TestTelemetryStartupValidationSourceIsInert(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), "support_telemetry_config.go"))
	if err != nil {
		t.Fatalf("read support_telemetry_config.go: %v", err)
	}
	src := string(b)
	start := strings.Index(src, "func loadTelemetryConfigAtStartup()")
	if start < 0 {
		t.Fatal("loadTelemetryConfigAtStartup not found — the §14 startup validation step must exist")
	}
	// Bound the scan to this function (up to the next top-level func).
	body := src[start:]
	if next := strings.Index(body[1:], "\nfunc "); next >= 0 {
		body = body[:next+1]
	}
	for _, ident := range telemetrySlice2OutboundIdents {
		if strings.Contains(body, ident) {
			t.Errorf("loadTelemetryConfigAtStartup contains outbound/background marker %q — the startup step must be inert", ident)
		}
	}
}

// telemetrySlice2OutboundIdents extends telemetryOutboundIdents with the
// concrete Slice-3-only CODE markers named in the M7 Slice 2 mission brief
// (§5/§9/§14): sending, dialing, redirect-handling, and seal-and-send
// call-sites. None of these have any legitimate reason to appear in a
// Slice 2 file — the consent switch stores config and computes a gate; it
// never builds, seals, or sends anything. Deliberately punctuated/code-shaped
// (a trailing "(" or "{") rather than bare English words like "spool" or
// "backoff", which legitimately appear in Slice 1/2 comments explaining what
// is DEFERRED to Slice 3 (e.g. support_telemetry_registry.go's "belongs to
// Slice 3's sender/spool") — a prose word would false-positive on those.
var telemetrySlice2OutboundIdents = append(append([]string{}, telemetryOutboundIdents...),
	"http.NewRequestWithContext(", "http.Transport{",
	"DialContext(", "net.ResolveTCPAddr(", "net.ResolveIPAddr(",
	"ssrf.SafeDialContext(", "CheckRedirect:",
	"sealBundleToTAC(", "sealbox.Seal(", "SealAnonymous(",
	"time.Sleep(",
)

// TestNoTelemetryEgressSlice2 is the M7 Slice 2 no-egress wall the mission
// requires by name: every support_telemetry_*.go file (Slice 1 AND Slice 2 —
// the same glob TestSupportTelemetrySlice1HasNoEgress uses, since Slice 2's
// new files share the same prefix) must contain ZERO occurrences of any
// outbound/background-worker/delivery-machinery marker. Slice 2 ships a
// config store and an HTTP admin-API handler only — no sender exists yet,
// and this wall proves it mechanically rather than by code review alone.
func TestNoTelemetryEgressSlice2(t *testing.T) {
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
		for _, ident := range telemetrySlice2OutboundIdents {
			if strings.Contains(src, ident) {
				t.Errorf("%s contains outbound/background-worker/delivery marker %q — M7 Slice 2 is consent+config+GUI only, zero egress (no sender until Slice 3)", path, ident)
			}
		}
	}

	// Also prove the Slice 2 config surface is not wired into any startup
	// path — same seams as TestSupportTelemetrySlice1NoStartupWiring,
	// checked here for the new telemetryConfig identifiers specifically.
	startupFiles := []string{
		"main.go", "main_shutdown.go",
		"persistent_admin_state_startup.go",
		"background_services_startup.go",
	}
	for _, name := range startupFiles {
		b, err := os.ReadFile(filepath.Join(pkgSourceDir(), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		for _, marker := range []string{"telemetryConfig", "telemetryEnabled", "telemetryConfigGet", "apiSupportTelemetryConfig"} {
			if strings.Contains(src, marker) {
				t.Errorf("%s references %q — M7 Slice 2 must not be wired into startup (no sender exists yet)", name, marker)
			}
		}
	}
}
