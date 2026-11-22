package main

// QUAL-3 — durable Gateway Observe telemetry foundation. This file composes the
// EXISTING MCP durable-events machinery (internal/mcp/events) into the real Gateway
// Observe runtime, disabled-by-default:
//
//   - a KEK from a model-B secret.Provider file (secret.FileProvider — a random
//     0600 key file, never a raw key in YAML/CLI/env, never derived from config);
//   - one events.Manager whose encrypted, capability-isolated spool is opened and
//     recovered before telemetry is declared ready;
//   - the Manager injected as the Gateway runtime's Deps.Events (denials commit on
//     live requests; decision events stay pending-policy while Policy is absent);
//   - a node-local, bounded, fsync-before-ack, idempotent qualification ARCHIVE
//     exporter (internal/mcp/events/qualarchive; implements
//     internal/mcp/events/export.Exporter) — the first production-capable sink,
//     NOT a network SIEM;
//   - restart-safe per-partition export cursors (same package; advanced here only
//     after a durable archive acceptance);
//   - a bounded denial-flush loop + per-partition export loops (no goroutine per
//     event, no busy loop);
//   - truthful telemetry health + low-cardinality metrics (mcp_telemetry_metrics.go).
//
// Observe-only: NO executor, upstream client, broker, or Policy is composed here,
// so no tool executes and no qualification/evidence clock starts. An enabled but
// invalid block fails activation closed (nothing binds; no partial manager or
// exporter; no plaintext/memory-only fallback).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/qualarchive"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// ── bounds & cadence (constants; not operator-tunable — bounded by construction) ──

const (
	telemExportTypeArchive = "local-qualification-archive"

	telemDefaultBatchSize  = 256
	telemMaxBatchSize      = 4096
	telemDefaultMaxRetries = 3
	telemMaxRetries        = 16
	telemDefaultMaxBytes   = int64(1) << 30 // 1 GiB archive cap
	telemMaxArchiveBytes   = int64(64) << 30

	telemFlushInterval  = 3 * time.Second // denial-aggregate flush cadence
	telemExportInterval = 1 * time.Second // export poll cadence (no busy loop)
	telemRetryBackoff   = 50 * time.Millisecond

	telemDirPerm = 0o700
)

// mcpTelemetryClock is the events-manager clock. It defaults to the wall clock and is
// overridable in tests to advance deterministically past the bounded (up to 1h)
// denial-aggregation window — production always uses time.Now.
var mcpTelemetryClock = time.Now

// ── state / holder ────────────────────────────────────────────────────────────

// mcpTelemetryState classifies the node-local telemetry outcome for the truthful
// admin/health surface.
type mcpTelemetryState string

const (
	// mcpTelemNotConfigured — telemetry disabled/absent (QUAL-2 behavior). NOT ready.
	mcpTelemNotConfigured mcpTelemetryState = "telemetry_not_configured"
	// mcpTelemReady — manager opened + recovered; the durability plane is composed.
	mcpTelemReady mcpTelemetryState = "ready"
	// mcpTelemInvalid — enabled but a prerequisite failed; nothing bound (fail closed).
	mcpTelemInvalid mcpTelemetryState = "invalid"
)

// mcpTelemetryHolder publishes the composed telemetry runtime for the admin/health
// surface and shutdown. Exactly one telemetry runtime backs Deps.Events, the health
// projection, and the export readers (single source of truth).
type mcpTelemetryHolder struct {
	mu     sync.RWMutex
	state  mcpTelemetryState
	reason string // bounded, secret-free classification when invalid
	rt     *telemetryRuntime
}

var mcpTelem = &mcpTelemetryHolder{state: mcpTelemNotConfigured}

func publishMCPTelemetry(state mcpTelemetryState, reason string, rt *telemetryRuntime) {
	mcpTelem.mu.Lock()
	defer mcpTelem.mu.Unlock()
	mcpTelem.state, mcpTelem.reason = state, reason
	if state == mcpTelemReady {
		mcpTelem.rt = rt
	} else {
		mcpTelem.rt = nil
	}
}

func sharedTelemetry() *telemetryRuntime {
	mcpTelem.mu.RLock()
	defer mcpTelem.mu.RUnlock()
	return mcpTelem.rt
}

// errTelemetry builds a bounded, secret-free telemetry error (never a path, key, or
// tenant; the health surface reduces it to a fixed classification code).
func errTelemetry(msg string) error { return errors.New("mcp telemetry: " + msg) }

// ── composition ────────────────────────────────────────────────────────────────

// telemetryRuntime is the composed durable-telemetry handle: the events manager
// (Deps.Events + health source), the node-local archive exporter, the durable
// export cursors, and the bounded background loops. It is closeable and owns every
// resource it opens.
type telemetryRuntime struct {
	nodeID     string
	mgr        *events.Manager
	exporter   *qualarchive.Exporter
	cursors    *qualarchive.CursorStore
	batchSize  int
	maxRetries int

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// buildMCPTelemetry validates the resolved telemetry config and composes the KEK
// provider, events manager, archive exporter and durable cursor store — all or
// nothing. Disabled ⇒ (nil, not_configured, nil). Any failure closes whatever was
// opened and returns (nil, invalid, err); the caller fails activation closed.
func buildMCPTelemetry(cfg mcpTelemetryStartupConfig) (*telemetryRuntime, mcpTelemetryState, error) {
	if !cfg.Enabled {
		return nil, mcpTelemNotConfigured, nil
	}
	if err := validateTelemetryConfig(cfg); err != nil {
		return nil, mcpTelemInvalid, err
	}
	dataDir := filepath.Clean(cfg.DataDir)
	kekFile := filepath.Clean(cfg.KEKFile)
	exportDir := filepath.Clean(cfg.ExportDirectory)

	// Ensure the durable roots exist (0700) before opening key material / spool.
	for _, d := range []string{dataDir, filepath.Dir(kekFile), exportDir} {
		if err := os.MkdirAll(d, telemDirPerm); err != nil {
			return nil, mcpTelemInvalid, errTelemetry("data directory is not usable")
		}
	}

	// Model-B KEK: a random 0600 key file; a wrong/unreadable/unavailable KEK fails
	// closed (no plaintext fallback). ValidateProvider generates-or-loads it once.
	kek := secret.FileProvider(kekFile)
	if err := secret.ValidateProvider(kek); err != nil {
		return nil, mcpTelemInvalid, errTelemetry("kek provider unavailable")
	}

	mgr, err := events.NewManager(events.ManagerConfig{
		NodeID:           cfg.NodeID,
		DataDir:          dataDir,
		KEK:              kek,
		GatewayLimits:    limits.DefaultGatewayEvent(),
		ManagementLimits: limits.DefaultManagementEvent(),
		Clock:            mcpTelemetryClock,
	})
	if err != nil {
		return nil, mcpTelemInvalid, errTelemetry("event manager could not be opened")
	}

	exporter, err := qualarchive.NewExporter(exportDir, clampMaxBytes(cfg.ExportMaxBytes))
	if err != nil {
		_ = mgr.Close()
		return nil, mcpTelemInvalid, errTelemetry("archive exporter could not be opened")
	}
	cursors, err := qualarchive.NewCursorStore(filepath.Join(dataDir, "export_cursors", "gateway"), gatewayPartitions)
	if err != nil {
		_ = mgr.Close()
		return nil, mcpTelemInvalid, errTelemetry("export cursor store could not be opened")
	}

	rt := &telemetryRuntime{
		nodeID:     cfg.NodeID,
		mgr:        mgr,
		exporter:   exporter,
		cursors:    cursors,
		batchSize:  clampBatchSize(cfg.ExportBatchSize),
		maxRetries: clampMaxRetries(cfg.ExportMaxRetries),
	}
	return rt, mcpTelemReady, nil
}

// validateTelemetryConfig enforces the required fields, the fixed exporter type, and
// path safety (traversal). It reads nothing.
func validateTelemetryConfig(cfg mcpTelemetryStartupConfig) error {
	if strings.TrimSpace(cfg.NodeID) == "" || cfg.NodeID != strings.TrimSpace(cfg.NodeID) {
		return errTelemetry("node_id is required")
	}
	if len(cfg.NodeID) > 256 {
		return errTelemetry("node_id exceeds bound")
	}
	for _, p := range []struct{ name, val string }{
		{"data_dir", cfg.DataDir}, {"kek_file", cfg.KEKFile}, {"export.directory", cfg.ExportDirectory},
	} {
		if strings.TrimSpace(p.val) == "" {
			return errTelemetry(p.name + " is required")
		}
		if hasDotDotSegment(p.val) {
			return errTelemetry(p.name + " path traversal not allowed")
		}
	}
	if cfg.ExportType != telemExportTypeArchive {
		return errTelemetry("export.type must be " + telemExportTypeArchive)
	}
	if cfg.ExportBatchSize < 0 || cfg.ExportBatchSize > telemMaxBatchSize {
		return errTelemetry("export.batch_size out of range")
	}
	if cfg.ExportMaxRetries < 0 || cfg.ExportMaxRetries > telemMaxRetries {
		return errTelemetry("export.max_retries out of range")
	}
	if cfg.ExportMaxBytes < 0 || cfg.ExportMaxBytes > telemMaxArchiveBytes {
		return errTelemetry("export.max_bytes out of range")
	}
	return nil
}

// hasDotDotSegment reports whether a cleaned path contains a literal ".." path
// SEGMENT (real parent-directory traversal). Unlike a substring test it accepts
// absolute paths and legitimate names that merely contain ".." (e.g. "..cache"),
// while still rejecting "a/../b" and a leading "..".
func hasDotDotSegment(p string) bool {
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(cleaned, string(os.PathSeparator)) {
		if seg == ".." {
			return true
		}
	}
	return false
}

func clampBatchSize(v int) int {
	if v <= 0 {
		return telemDefaultBatchSize
	}
	if v > telemMaxBatchSize {
		return telemMaxBatchSize
	}
	return v
}

func clampMaxRetries(v int) int {
	if v <= 0 {
		return telemDefaultMaxRetries
	}
	if v > telemMaxRetries {
		return telemMaxRetries
	}
	return v
}

func clampMaxBytes(v int64) int64 {
	if v <= 0 {
		return telemDefaultMaxBytes
	}
	if v > telemMaxArchiveBytes {
		return telemMaxArchiveBytes
	}
	return v
}

// Manager returns the events manager (the runtime EventProvider + health source).
func (t *telemetryRuntime) Manager() *events.Manager {
	if t == nil {
		return nil
	}
	return t.mgr
}

// gatewayPartitions is the fixed set of Gateway partitions exported. Management is
// never activated here, so no Management pump runs.
var gatewayPartitions = []evmodel.Partition{evmodel.PartCrit, evmodel.PartOrd, evmodel.PartDen}

// Start launches the bounded background loops: one denial-flush loop (so denial
// aggregates become durable + exportable) and one export loop per Gateway
// partition. Idempotent-safe to call once after the runtime is up.
func (t *telemetryRuntime) Start(parent context.Context) {
	if t == nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	t.cancel = cancel

	t.wg.Add(1)
	go t.flushLoop(ctx)
	for _, part := range gatewayPartitions {
		part := part
		t.wg.Add(1)
		go t.exportLoop(ctx, part)
	}
}

// Close stops the loops, performs a final denial flush + FULL export drain, and
// closes the manager (which does its own final per-domain flush + spool close). The
// entire sequence is bounded by the caller's shutdown context: if that budget is
// exhausted (e.g. a stuck archive/cursor volume) Close returns promptly so the later
// shutdown hooks (admin, proxy, log) still run — the committed events stay durable in
// the encrypted spool and export on the next start. A nil ctx means "unbounded".
func (t *telemetryRuntime) Close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if t.cancel != nil {
		t.cancel()
	}
	done := make(chan error, 1)
	go func() {
		t.wg.Wait()
		// CHAOS-119: every stage below is guarded, and the guard is per STAGE
		// rather than around the whole sequence, for two reasons that are
		// specific to a shutdown drain.
		//
		// Why guarded at all: this goroutine is `go`-detached, so an
		// unrecovered panic in it terminated the PROCESS — from a hook at
		// order 66, with orders 67..140 still unrun. That is the tunnel
		// establish-fence, the H2 GOAWAY wave and the whole tunnel drain
		// (every in-flight client connection severed rather than drained),
		// plus every hook above shutdownFlushBoundary: syslog, the community
		// DB, the log store, the request log and the audit log. CHAOS-56
		// carved a reserve for exactly those because "abandoning one costs
		// durability or leaves a store the next boot has to quarantine" — and
		// a panic here did not abandon them, it skipped them. The fault is not
		// hypothetical: drainPartition calls the SAME exportStep that
		// exportLoop has guarded under crashComponentMCPTelemetryExport since
		// CHAOS-118, reading the encrypted spool and calling out to the
		// archive exporter, "both fed by data this process does not author".
		// The identical call was contained on the periodic path and fatal on
		// the shutdown path.
		//
		// Why per stage: mgr.Close() is the durability-critical step — it does
		// its own final per-domain flush and closes the spool — so a fault in
		// the force-flush or in one partition's drain must not skip it. One
		// guard around the whole sequence would have. The CHAOS-105
		// whole-worker-recover objection does not apply: this is a ONE-SHOT
		// terminating sequence, not a loop that must keep ticking, so there is
		// no stall to convert a crash into.
		//
		// Force-flush here (unlike the periodic loop) so the still-open current denial
		// window becomes durable BEFORE the export drain runs — otherwise it would
		// commit only inside mgr.Close(), after this drain, and stay unarchived until
		// the next start.
		drainPanicked := runGuarded(crashComponentMCPTelemetryDrain, func() {
			t.mgr.FlushDenialsForce(evmodel.CapGateway)
		})
		for _, part := range gatewayPartitions {
			// One partition's fault costs that partition's pending batches,
			// which stay committed in the encrypted spool and export on the
			// next start; it does not cost the other partitions' drains.
			if runGuarded(crashComponentMCPTelemetryDrain, func() { t.drainPartition(ctx, part) }) {
				drainPanicked = true
			}
		}
		var closeErr error
		if runGuarded(crashComponentMCPTelemetryDrain, func() { closeErr = t.mgr.Close() }) {
			closeErr = errTelemetry("manager close panicked (contained); committed events stay durable in the encrypted spool")
		} else if drainPanicked && closeErr == nil {
			// Never report a clean shutdown for a drain that died: the caller
			// logs this, and the crash record names the component. The events
			// themselves are not lost — the spool is durable and the cursor
			// advances only on a durable archive acknowledgement.
			closeErr = errTelemetry("shutdown drain panicked (contained); pending batches export on the next start")
		}
		// Always answer, on every path: Close selects on this channel, and a
		// stage that panicked without sending would leave the hook waiting out
		// the entire shutdown budget it exists to honour.
		done <- closeErr
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drainPartition exports EVERY currently-committed batch for one partition (unlike
// the periodic loop's single step), so a graceful shutdown archives all pending
// evidence rather than one batch. It stops on no cursor progress (queue empty, or a
// failure that leaves the cursor unadvanced) and on ctx cancellation, so it can never
// spin unboundedly — new events are not produced after the listener stops.
func (t *telemetryRuntime) drainPartition(ctx context.Context, part evmodel.Partition) {
	for {
		if ctx.Err() != nil {
			return
		}
		before := t.cursors.Get(part)
		t.exportStep(ctx, part)
		if t.cursors.Get(part) <= before {
			return
		}
	}
}

// crashComponentMCPTelemetryFlush / crashComponentMCPTelemetryExport name the two
// MCP telemetry background loops in the crash plane, separately, so an operator
// reading culvert_crash_records_total{component=...} can tell a denial-flush
// fault from an archive-export fault.
const (
	crashComponentMCPTelemetryFlush  = "mcp_telemetry_flush"
	crashComponentMCPTelemetryExport = "mcp_telemetry_export"
	// crashComponentMCPTelemetryDrain names the SHUTDOWN drain separately from
	// the two periodic loops (CHAOS-119). An operator reading
	// culvert_crash_records_total{component=...} needs to tell a fault that
	// cost one tick of a running node from one that landed inside a graceful
	// shutdown, because the second is the one that leaves pending evidence
	// unexported and a spool for the next boot to reopen.
	crashComponentMCPTelemetryDrain = "mcp_telemetry_drain"
)

// flushLoop periodically commits closed denial-aggregate windows into P-DEN so they
// become durable + exportable. FlushDenials never blocks or touches the critical
// track.
func (t *telemetryRuntime) flushLoop(ctx context.Context) {
	defer t.wg.Done()
	ticker := time.NewTicker(telemFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// CHAOS-118: per-ROUND guard. This loop is `go`-detached from
			// Start, so an unrecovered panic while committing a denial window
			// terminated the gateway — an evidence-pipeline fault taking down
			// the data plane it collects evidence for. Keep-going is safe: a
			// failed flush leaves the window uncommitted and the next tick
			// retries it, and the final force-flush in Close still runs.
			runGuarded(crashComponentMCPTelemetryFlush, func() {
				t.mgr.FlushDenials(evmodel.CapGateway)
			})
		}
	}
}

// exportLoop drives one partition's export on a bounded cadence (no busy loop). A
// failed step leaves the cursor unadvanced; the next tick retries.
func (t *telemetryRuntime) exportLoop(ctx context.Context, part evmodel.Partition) {
	defer t.wg.Done()
	ticker := time.NewTicker(telemExportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// CHAOS-118: per-ROUND guard, one per partition. `go`-detached, so
			// a panic in an export step (it reads the encrypted spool and
			// calls out to the archive exporter, both fed by data this process
			// does not author) killed the gateway. Keep-going is safe and is
			// the existing failure semantics: exportStep advances the durable
			// cursor ONLY after the archive accepts the whole batch, so a
			// contained panic leaves the cursor unadvanced and the spool
			// intact, and the next tick retries the same batch.
			runGuarded(crashComponentMCPTelemetryExport, func() {
				t.exportStep(ctx, part)
			})
		}
	}
}

// exportStep reads the next committed batch for one partition and hands it to the
// archive exporter with bounded retries. The durable cursor advances ONLY after the
// archive durably accepts the whole batch (all-or-nothing) — an archive failure
// leaves the encrypted source spool intact and the cursor unadvanced (retryable).
func (t *telemetryRuntime) exportStep(ctx context.Context, part evmodel.Partition) {
	sp := t.mgr.Spool(evmodel.CapGateway)
	if sp == nil {
		return
	}
	cur := t.cursors.Get(part)
	batch, seqs, _, err := sp.CommittedForExport(part, cur, t.batchSize)
	if err != nil || len(batch) == 0 {
		return
	}
	accepted, xerr := t.exportWithRetry(ctx, batch)
	if xerr != nil || accepted < len(batch) {
		t.exporter.NoteFailure(errClass(xerr))
		return
	}
	// Durable acceptance confirmed: advance the persistent cursor to the last seq.
	if err := t.cursors.Advance(part, seqs[len(seqs)-1]); err != nil {
		// Cursor persistence failed: do NOT treat the batch as fully exported. Leave
		// the in-memory cursor unadvanced so the next tick retries from the same
		// point. If new events commit before that retry, the re-read range is a
		// SUPERSET of this batch, so the archive over-retains (the earlier events are
		// re-archived under a new, wider batch identity) — it never loses an event and
		// never advances past an unacknowledged commit. Idempotent absorption is exact
		// only for a byte-identical retry; across a cursor-persist gap the guarantee is
		// "no loss, no false advance," not "no duplicate." Duplicates carry unique
		// EventDigests and are dedupable downstream.
		t.exporter.NoteFailure("cursor_persist")
		return
	}
	t.exporter.NoteExported(len(batch))
}

// exportWithRetry attempts the archive export up to maxRetries with a bounded
// backoff, returning the accepted count of the first success (all-or-nothing).
func (t *telemetryRuntime) exportWithRetry(ctx context.Context, batch []evmodel.Event) (int, error) {
	var lastErr error
	for attempt := 0; attempt < t.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		accepted, err := t.exporter.Export(ctx, batch)
		if err == nil && accepted == len(batch) {
			return accepted, nil
		}
		lastErr = err
		if attempt < t.maxRetries-1 {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(telemRetryBackoff):
			}
		}
	}
	if lastErr == nil {
		lastErr = errTelemetry("archive did not accept the full batch")
	}
	return 0, lastErr
}

// exportLag returns the per-partition export lag in sequence space (committed high
// water minus the durable cursor), clamped at zero — a bounded health signal.
func (t *telemetryRuntime) exportLag(part evmodel.Partition) uint64 {
	sp := t.mgr.Spool(evmodel.CapGateway)
	if sp == nil {
		return 0
	}
	st := sp.Stats()
	next := st.Partitions[part].NextSeq // next-to-assign; committed high ≈ next-1
	cur := t.cursors.Get(part)
	if next == 0 || next-1 <= cur {
		return 0
	}
	return (next - 1) - cur
}

// errClass reduces an export error to a bounded, secret-free reason class for
// metrics/health (never raw error text).
func errClass(err error) string {
	if err == nil {
		return "none"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "conflict"):
		return "conflict"
	case strings.Contains(s, "saturated") || strings.Contains(s, "capacity"):
		return "saturated"
	case strings.Contains(s, "context"):
		return "canceled"
	default:
		return "write_error"
	}
}
