package main

// QUAL-3 tests: durable telemetry composition. They exercise the real events
// manager + encrypted spool (via a model-B KEK file in a temp dir), the real archive
// exporter + durable cursors, and the real runtime denial path — no stubs.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

func telemetryConfigAt(t *testing.T) mcpTelemetryStartupConfig {
	t.Helper()
	dir := t.TempDir()
	return mcpTelemetryStartupConfig{
		Enabled:          true,
		NodeID:           "qual-node-1",
		DataDir:          filepath.Join(dir, "data"),
		KEKFile:          filepath.Join(dir, "kek", "telemetry.kek"),
		ExportType:       telemExportTypeArchive,
		ExportDirectory:  filepath.Join(dir, "archive"),
		ExportBatchSize:  16,
		ExportMaxRetries: 2,
		ExportMaxBytes:   1 << 20,
	}
}

func buildReadyTelemetry(t *testing.T) *telemetryRuntime {
	t.Helper()
	rt, state, err := buildMCPTelemetry(telemetryConfigAt(t))
	if err != nil || state != mcpTelemReady || rt == nil {
		t.Fatalf("buildMCPTelemetry = state %q err %v", state, err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()); publishMCPTelemetry(mcpTelemNotConfigured, "", nil) })
	return rt
}

// denialEvent crafts a safe P-DEN model event with a controlled digest (exporter
// unit tests need deterministic identities without a live pipeline).
func denialEvent(digest string) evmodel.Event {
	return evmodel.Event{
		SchemaVersion: evmodel.SchemaVersion,
		Capability:    evmodel.CapGateway,
		Partition:     evmodel.PartDen,
		EventID:       "ev-" + digest,
		EventDigest:   digest,
	}
}

// ── configuration & startup ──────────────────────────────────────────────────

func TestTelemetry_DisabledIsNoOp(t *testing.T) {
	rt, state, err := buildMCPTelemetry(mcpTelemetryStartupConfig{Enabled: false})
	if err != nil || rt != nil || state != mcpTelemNotConfigured {
		t.Fatalf("disabled telemetry = (%v,%q,%v), want (nil,not_configured,nil)", rt, state, err)
	}
}

func TestTelemetry_ValidComposes(t *testing.T) {
	rt := buildReadyTelemetry(t)
	if rt.Manager() == nil {
		t.Fatal("ready telemetry must expose a manager")
	}
	if h := rt.Manager().Health(); h.NodeID != "qual-node-1" {
		t.Fatalf("manager node id = %q", h.NodeID)
	}
}

func TestTelemetry_InvalidConfigsFailClosed(t *testing.T) {
	base := telemetryConfigAt(t)
	cases := []struct {
		name string
		mut  func(c *mcpTelemetryStartupConfig)
	}{
		{"missing_node_id", func(c *mcpTelemetryStartupConfig) { c.NodeID = "" }},
		{"missing_data_dir", func(c *mcpTelemetryStartupConfig) { c.DataDir = "" }},
		{"missing_kek", func(c *mcpTelemetryStartupConfig) { c.KEKFile = "" }},
		{"missing_export_dir", func(c *mcpTelemetryStartupConfig) { c.ExportDirectory = "" }},
		{"bad_export_type", func(c *mcpTelemetryStartupConfig) { c.ExportType = "network-siem" }},
		{"traversal_data_dir", func(c *mcpTelemetryStartupConfig) { c.DataDir = "../../etc/data" }},
		{"batch_overflow", func(c *mcpTelemetryStartupConfig) { c.ExportBatchSize = telemMaxBatchSize + 1 }},
		{"retries_overflow", func(c *mcpTelemetryStartupConfig) { c.ExportMaxRetries = telemMaxRetries + 1 }},
		{"bytes_overflow", func(c *mcpTelemetryStartupConfig) { c.ExportMaxBytes = telemMaxArchiveBytes + 1 }},
		{"negative_bytes", func(c *mcpTelemetryStartupConfig) { c.ExportMaxBytes = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			rt, state, err := buildMCPTelemetry(c)
			if err == nil || state != mcpTelemInvalid || rt != nil {
				t.Fatalf("%s: expected invalid+error, got (%v,%q,%v)", tc.name, rt, state, err)
			}
		})
	}
}

// TestTelemetry_DotDotSegmentCheck locks in the segment-based traversal check: a
// real ".." path segment is rejected, but an absolute path or a name that merely
// contains ".." as a substring (e.g. "..cache") is accepted.
func TestTelemetry_DotDotSegmentCheck(t *testing.T) {
	// filepath.Clean collapses interior ".." ("a/../b" -> "b", "/var/lib/../x" ->
	// "/var/x"), which cannot escape a root, so only an un-collapsible leading ".."
	// survives as real traversal.
	reject := []string{"../../etc/data", "..", "../secret", "../"}
	accept := []string{"/var/lib/culvert/mcp", "/data/..cache/x", "/srv/culvert.telemetry", "relative/ok", "a/../b", "/var/lib/../x"}
	for _, p := range reject {
		if !hasDotDotSegment(p) {
			t.Fatalf("expected %q to be rejected as traversal", p)
		}
	}
	for _, p := range accept {
		if hasDotDotSegment(p) {
			t.Fatalf("expected %q to be accepted (no real .. segment)", p)
		}
	}
}

// TestTelemetry_NoRawKeyField structurally proves the config never carries raw key
// material (only a KEK file path). A raw-key value can never enter via YAML/CLI/env.
func TestTelemetry_NoRawKeyField(t *testing.T) {
	blob, _ := json.Marshal(mcpTelemetryStartupConfig{})
	for _, banned := range []string{"\"kek\"", "\"key\"", "\"secret\"", "\"passphrase\"", "\"password\""} {
		if strings.Contains(strings.ToLower(string(blob)), banned) {
			t.Fatalf("telemetry config exposes a raw-key field %q: %s", banned, blob)
		}
	}
}

// ── manager / encryption ─────────────────────────────────────────────────────

// fakeClock is a controllable clock for advancing past the bounded denial-aggregation
// window deterministically.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// withFakeClock installs a controllable manager clock for the test and restores the
// wall clock on cleanup. Advancing by >1h closes any denial-aggregation window.
func withFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	fc := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	prev := mcpTelemetryClock
	mcpTelemetryClock = fc.now
	t.Cleanup(func() { mcpTelemetryClock = prev })
	return fc
}

const denialWindowAdvance = 2 * time.Hour // > the 1h aggregation-window ceiling

func TestTelemetry_SpoolIsEncrypted(t *testing.T) {
	fc := withFakeClock(t)
	cfg := telemetryConfigAt(t)
	rt, _, err := buildMCPTelemetry(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	const marker = "ZZUNIQUEDENIALMARKERZZ"
	rt.mgr.ObserveDenial(events.DenialInput{Capability: evmodel.CapGateway, Listener: "l", Source: "s", Reason: marker})
	fc.advance(denialWindowAdvance)
	if committed, _ := rt.mgr.FlushDenials(evmodel.CapGateway); committed == 0 {
		t.Fatal("expected a committed denial aggregate")
	}
	_ = rt.Close(context.Background())

	// Walk every spool segment/checkpoint file: the marker must never appear in
	// plaintext (the spool is AES-GCM encrypted under the model-B KEK).
	var found bool
	_ = filepath.Walk(filepath.Join(cfg.DataDir, "gateway"), func(p string, info os.FileInfo, _ error) error {
		if info == nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p) //nolint:errcheck,gosec // #nosec G304,G122 -- test scan of a self-created temp spool dir; no untrusted symlinks
		if strings.Contains(string(b), marker) {
			found = true
		}
		return nil
	})
	if found {
		t.Fatal("denial marker found in plaintext on disk — spool is not encrypted")
	}
}

func TestTelemetry_CorrectProviderRecoversWrongFailsClosed(t *testing.T) {
	cfg := telemetryConfigAt(t)
	rt, _, err := buildMCPTelemetry(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rt.mgr.ObserveDenial(events.DenialInput{Capability: evmodel.CapGateway, Reason: "x"})
	rt.mgr.FlushDenials(evmodel.CapGateway)
	_ = rt.Close(context.Background())

	// Correct provider (same kek file + data dir) reopens and recovers.
	rt2, state, err := buildMCPTelemetry(cfg)
	if err != nil || state != mcpTelemReady {
		t.Fatalf("recover with correct KEK: state %q err %v", state, err)
	}
	_ = rt2.Close(context.Background())

	// Wrong provider: point kek_file at a DIFFERENT 32-byte key ⇒ the sealed DEK
	// cannot be opened ⇒ fail closed (no plaintext fallback).
	wrong := cfg
	wrongKEK := filepath.Join(t.TempDir(), "wrong.kek")
	if err := os.WriteFile(wrongKEK, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write wrong kek: %v", err)
	}
	wrong.KEKFile = wrongKEK
	rt3, state, err := buildMCPTelemetry(wrong)
	if err == nil || state != mcpTelemInvalid || rt3 != nil {
		t.Fatalf("wrong KEK must fail closed, got (%v,%q,%v)", rt3, state, err)
	}
}

// ── archive exporter ─────────────────────────────────────────────────────────

func TestArchiveExporter_AtomicIdempotentConflict(t *testing.T) {
	dir := t.TempDir()
	exp, err := newQualArchiveExporter(dir, 1<<20)
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	batch := []evmodel.Event{denialEvent("d1"), denialEvent("d2"), denialEvent("d3")}

	n, err := exp.Export(context.Background(), batch)
	if err != nil || n != 3 {
		t.Fatalf("export = (%d,%v), want (3,nil)", n, err)
	}
	// Idempotent retry: same batch accepted again, still one file.
	n, err = exp.Export(context.Background(), batch)
	if err != nil || n != 3 {
		t.Fatalf("idempotent retry = (%d,%v)", n, err)
	}
	if got := countFiles(t, dir); got != 1 {
		t.Fatalf("archive files = %d, want 1 (idempotent)", got)
	}
	// Conflict: same batch identity (first/last/count) but different middle content.
	conflict := []evmodel.Event{denialEvent("d1"), denialEvent("dX"), denialEvent("d3")}
	if _, err := exp.Export(context.Background(), conflict); err == nil {
		t.Fatal("conflicting batch under the same identity must be rejected")
	}
}

func TestArchiveExporter_SaturationNoSilentDrop(t *testing.T) {
	dir := t.TempDir()
	exp, err := newQualArchiveExporter(dir, 8) // 8-byte cap: any real batch exceeds it
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	n, err := exp.Export(context.Background(), []evmodel.Event{denialEvent("d1")})
	if err == nil || n != 0 {
		t.Fatalf("saturated export must reject (0,err), got (%d,%v)", n, err)
	}
	if countFiles(t, dir) != 0 {
		t.Fatal("saturated export must not write (spool retained, no silent drop)")
	}
	if !exp.stats().Saturated {
		t.Fatal("exporter must report saturated state")
	}
}

func TestTelemetryCursor_DurableAndPerPartition(t *testing.T) {
	dir := t.TempDir()
	cs, err := newTelemetryCursorStore(dir)
	if err != nil {
		t.Fatalf("cursor store: %v", err)
	}
	if err := cs.advance(evmodel.PartDen, 42); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if err := cs.advance(evmodel.PartDen, 10); err != nil { // backward is a no-op
		t.Fatalf("backward advance: %v", err)
	}
	if got := cs.get(evmodel.PartDen); got != 42 {
		t.Fatalf("cursor = %d, want 42 (monotonic)", got)
	}
	if got := cs.get(evmodel.PartCrit); got != 0 {
		t.Fatalf("crit cursor = %d, want 0 (per-partition isolation)", got)
	}
	// Restart: a fresh store loads the durable cursor.
	cs2, err := newTelemetryCursorStore(dir)
	if err != nil {
		t.Fatalf("reopen cursor store: %v", err)
	}
	if got := cs2.get(evmodel.PartDen); got != 42 {
		t.Fatalf("restarted cursor = %d, want 42", got)
	}
}

// ── live runtime denial path (end-to-end, real listener + pipeline) ───────────

// TestTelemetry_LiveDenialCommitsAndExports drives the REAL mTLS listener + pipeline
// with a QUAL-2 seeded inventory and telemetry composed: a seeded request with no
// token routes an auth denial into the durable denial lane, which flushes to P-DEN
// and is archived — proving the end-to-end telemetry path, all Observe-only.
func TestTelemetry_LiveDenialCommitsAndExports(t *testing.T) {
	resetInventory(t)
	fc := withFakeClock(t)
	pki := newMCPTestPKI(t)
	sc := scWithInventory(t, pki, writeInv(t, validInventoryJSON()))
	sc.Telemetry = telemetryConfigAt(t)

	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("state=%q reason=%q", act.State, act.Reason)
	}
	t.Cleanup(func() {
		publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
		publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
	})

	// The composed Deps carry the durable manager but NO executor/policy/inspection.
	if cfg.Deps.Events == nil {
		t.Fatal("telemetry must wire Deps.Events")
	}
	if cfg.Deps.Executor != nil || cfg.Deps.Policy != nil || cfg.Deps.Inspection != nil {
		t.Fatal("QUAL-3 must not compose executor/policy/inspection (Observe-only)")
	}
	tel := sharedTelemetry()
	if tel == nil {
		t.Fatal("telemetry holder must be published ready")
	}

	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(ctxWithTimeout(t)); _ = tel.Close(context.Background()) })

	// A seeded server + initialize + no token → auth denial (routes into the lane).
	base := "https://" + rt.Addr(false)
	cli := pki.mtlsClient(t, true)
	req := mcpObserveReq(t, "POST", base+"/mcp/gateway/srv-1", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req.Host = "gw.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("seeded request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("seeded request status = %d, want 401 (reached auth, routed a denial)", resp.StatusCode)
	}

	// Advance past the aggregation window, then drive the flush + export
	// deterministically (rather than waiting on the loops).
	fc.advance(denialWindowAdvance)
	committed, lost := tel.mgr.FlushDenials(evmodel.CapGateway)
	if committed == 0 || lost != 0 {
		t.Fatalf("denial flush committed=%d lost=%d, want committed>0 lost=0", committed, lost)
	}
	tel.exportStep(context.Background(), evmodel.PartDen)

	// Health + exporter reflect a durable, archived denial aggregate.
	h := tel.mgr.Health().Domains[evmodel.CapGateway]
	if h.DenialAggregates == 0 {
		t.Fatal("expected a durably committed denial aggregate")
	}
	if es := tel.exporter.stats(); es.ExportedEvents == 0 || es.BatchesOK == 0 {
		t.Fatalf("expected an archived denial aggregate, exporter=%+v", es)
	}
	// No Management events were produced by Gateway traffic.
	if mh, ok := tel.mgr.Health().Domains[evmodel.CapManagement]; ok && (mh.CommitOK != 0 || mh.DenialAggregates != 0) {
		t.Fatal("gateway traffic must not produce management events")
	}
	// Decision telemetry stays pending-policy (no decision fabricated).
	if st := mcpTelemetryStatus(); st.DecisionTelemetry != "pending_policy" {
		t.Fatalf("decision telemetry = %q, want pending_policy", st.DecisionTelemetry)
	}
}

// ── health + metrics ─────────────────────────────────────────────────────────

func TestTelemetry_StatusAndMetricsTruthful(t *testing.T) {
	// Not configured: status not_configured, metric ready=0, no other series.
	publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	if st := mcpTelemetryStatus(); st.State != string(mcpTelemNotConfigured) || st.Gateway != nil {
		t.Fatalf("disabled status = %+v", st)
	}
	var b strings.Builder
	writeMCPTelemetryMetrics(&b)
	if !strings.Contains(b.String(), `culvert_mcp_telemetry_ready{capability="gateway"} 0`) {
		t.Fatalf("disabled metrics missing ready=0: %s", b.String())
	}
	for _, banned := range []string{"tenant=", "principal=", "server_id=", "tool=", "event_id=", "path="} {
		if strings.Contains(b.String(), banned) {
			t.Fatalf("metrics leaked high-cardinality label %q", banned)
		}
	}

	// Ready: status reports ready + gateway domain; metric ready=1.
	rt := buildReadyTelemetry(t)
	publishMCPTelemetry(mcpTelemReady, "", rt)
	if st := mcpTelemetryStatus(); st.State != string(mcpTelemReady) || st.Gateway == nil || st.ExecutionEnabled {
		t.Fatalf("ready status = %+v", st)
	}
	b.Reset()
	writeMCPTelemetryMetrics(&b)
	if !strings.Contains(b.String(), `culvert_mcp_telemetry_ready{capability="gateway"} 1`) {
		t.Fatalf("ready metrics missing ready=1: %s", b.String())
	}
}

func TestTelemetry_EventReaderIsRealPath(t *testing.T) {
	rt := buildReadyTelemetry(t)
	publishMCPTelemetry(mcpTelemReady, "", rt)
	er := mcpAdminEventReader()
	if er == nil {
		t.Fatal("event reader must be wired when telemetry is ready")
	}
	// With Policy absent, no decision event exists — the reader is truthfully empty,
	// never fabricating a row.
	ev, _, _, err := er.CommittedEvents("gateway", "P-CRIT", 0, 10)
	if err != nil || len(ev) != 0 {
		t.Fatalf("empty decision read = (%d,%v), want (0,nil)", len(ev), err)
	}
	// A cross-capability read returns nothing (Management is not composed).
	if ev, _, _, _ := er.CommittedEvents("management", "P-CRIT", 0, 10); len(ev) != 0 {
		t.Fatal("management read must be empty (not composed)")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func countFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, _ error) error {
		if info != nil && info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	return n
}

// TestValidateBatch_AcceptsV1AndV2RejectsUnknown pins the SHADOW-EVIDENCE-ROUTING-1
// qualification-archive fix: the export-pump batch validator must accept a SUPPORTED
// schema version — v1 AND the v2 durable-Shadow-evidence envelope — not just the default
// v1. A hardcoded `!= v1` check would reject the first v2 Shadow event, and because the
// pump retries an all-or-nothing batch without advancing its cursor, that would wedge the
// whole partition out of the durable archive (Codex P1, PR #1235). A genuinely unknown
// version is still rejected. Mutation: reverting to `!= evmodel.SchemaVersion` fails the
// v2 assertion below.
func TestValidateBatch_AcceptsV1AndV2RejectsUnknown(t *testing.T) {
	v2 := func(d string) evmodel.Event {
		return evmodel.Event{
			SchemaVersion: evmodel.SchemaVersionV2, Capability: evmodel.CapGateway,
			Partition: evmodel.PartCrit, EventID: "ev-" + d, EventDigest: d,
		}
	}
	if _, _, err := validateBatch([]evmodel.Event{denialEvent("d1"), denialEvent("d2")}); err != nil {
		t.Fatalf("a v1 batch must validate: %v", err)
	}
	if _, _, err := validateBatch([]evmodel.Event{v2("a"), v2("b")}); err != nil {
		t.Fatalf("a v2 shadow batch must validate (else its partition wedges out of the archive): %v", err)
	}
	bad := v2("c")
	bad.SchemaVersion = unknownSchemaVersion
	if _, _, err := validateBatch([]evmodel.Event{bad}); err == nil {
		t.Fatal("an unsupported schema version must be rejected")
	}
}
