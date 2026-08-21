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
//     exporter (implements internal/mcp/events/export.Exporter) — the first
//     production-capable sink, NOT a network SIEM;
//   - restart-safe per-partition export cursors (advanced only after a durable
//     archive acceptance);
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
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

	telemDirPerm  = 0o700
	telemFilePerm = 0o600
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
	exporter   *qualArchiveExporter
	cursors    *telemetryCursorStore
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

	exporter, err := newQualArchiveExporter(exportDir, clampMaxBytes(cfg.ExportMaxBytes))
	if err != nil {
		_ = mgr.Close()
		return nil, mcpTelemInvalid, errTelemetry("archive exporter could not be opened")
	}
	cursors, err := newTelemetryCursorStore(filepath.Join(dataDir, "export_cursors", "gateway"))
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
		// Force-flush here (unlike the periodic loop) so the still-open current denial
		// window becomes durable BEFORE the export drain runs — otherwise it would
		// commit only inside mgr.Close(), after this drain, and stay unarchived until
		// the next start.
		t.mgr.FlushDenialsForce(evmodel.CapGateway)
		for _, part := range gatewayPartitions {
			t.drainPartition(ctx, part)
		}
		done <- t.mgr.Close()
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
		before := t.cursors.get(part)
		t.exportStep(ctx, part)
		if t.cursors.get(part) <= before {
			return
		}
	}
}

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
			t.mgr.FlushDenials(evmodel.CapGateway)
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
			t.exportStep(ctx, part)
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
	cur := t.cursors.get(part)
	batch, seqs, _, err := sp.CommittedForExport(part, cur, t.batchSize)
	if err != nil || len(batch) == 0 {
		return
	}
	accepted, xerr := t.exportWithRetry(ctx, batch)
	if xerr != nil || accepted < len(batch) {
		t.exporter.noteFailure(errClass(xerr))
		return
	}
	// Durable acceptance confirmed: advance the persistent cursor to the last seq.
	if err := t.cursors.advance(part, seqs[len(seqs)-1]); err != nil {
		// Cursor persistence failed: do NOT treat the batch as fully exported. Leave
		// the in-memory cursor unadvanced so the next tick retries from the same
		// point. If new events commit before that retry, the re-read range is a
		// SUPERSET of this batch, so the archive over-retains (the earlier events are
		// re-archived under a new, wider batch identity) — it never loses an event and
		// never advances past an unacknowledged commit. Idempotent absorption is exact
		// only for a byte-identical retry; across a cursor-persist gap the guarantee is
		// "no loss, no false advance," not "no duplicate." Duplicates carry unique
		// EventDigests and are dedupable downstream.
		t.exporter.noteFailure("cursor_persist")
		return
	}
	t.exporter.noteExported(len(batch))
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
	cur := t.cursors.get(part)
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

// ── durable export cursor store ─────────────────────────────────────────────────

// telemetryCursorStore persists the per-partition export cursor durably (fsync via
// fileutil.AtomicWrite) so a restart resumes exactly where the last acknowledged
// batch left off. Cursors are monotonic and per-partition — one partition can never
// overwrite another (distinct files), and this store is Gateway-only (a distinct
// directory from any Management state).
type telemetryCursorStore struct {
	mu  sync.Mutex
	dir string
	cur map[evmodel.Partition]uint64
}

type cursorFile struct {
	Cursor uint64 `json:"cursor"`
}

func newTelemetryCursorStore(dir string) (*telemetryCursorStore, error) {
	if err := os.MkdirAll(dir, telemDirPerm); err != nil {
		return nil, err
	}
	s := &telemetryCursorStore{dir: dir, cur: map[evmodel.Partition]uint64{}}
	for _, part := range gatewayPartitions {
		raw, err := os.ReadFile(filepath.Clean(s.path(part))) // #nosec G304 -- fixed enum-derived path under a cleaned root
		if err != nil {
			continue // absent ⇒ start at 0
		}
		var cf cursorFile
		if json.Unmarshal(raw, &cf) == nil {
			s.cur[part] = cf.Cursor
		}
	}
	return s, nil
}

func (s *telemetryCursorStore) path(part evmodel.Partition) string {
	return filepath.Join(s.dir, telemPartitionName(part)+".cursor")
}

func (s *telemetryCursorStore) get(part evmodel.Partition) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur[part]
}

// advance persists a strictly-forward cursor (monotonic). A backward or equal value
// is a no-op success; a forward value is durably written before the in-memory value
// moves, so the persisted cursor never runs ahead of a durable acknowledgement.
func (s *telemetryCursorStore) advance(part evmodel.Partition, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.cur[part] {
		return nil
	}
	b, err := json.Marshal(cursorFile{Cursor: seq})
	if err != nil {
		return err
	}
	if err := fileutil.AtomicWrite(s.path(part), b, telemFilePerm); err != nil {
		return err
	}
	s.cur[part] = seq
	return nil
}

// telemPartitionName maps a partition to a fixed, path/label-safe token (never a raw
// or attacker-controlled string).
func telemPartitionName(p evmodel.Partition) string {
	switch p {
	case evmodel.PartCrit:
		return "crit"
	case evmodel.PartOrd:
		return "ord"
	case evmodel.PartDen:
		return "den"
	default:
		return "none"
	}
}

// ── node-local qualification archive exporter (implements export.Exporter) ───────

// qualArchiveExporter is the first production-capable sink: a node-local, bounded,
// append-of-atomic-batches, idempotent archive of SAFE event envelopes. It is
// ADDITIVE to the encrypted source spool (a failure here never erases spool
// durability), performs NO network activity, stores only the safe envelope (never
// raw spool frames, encrypted segment bytes, or request/response bodies), and
// acknowledges a batch ONLY after it is durably fsynced (via fileutil.AtomicWrite).
type qualArchiveExporter struct {
	root     string
	maxBytes int64

	mu        sync.Mutex
	bytesUsed int64
	made      map[string]bool // created (cap/partition) dirs

	// counters (read by health + metrics at scrape time)
	exported   uint64
	batchesOK  uint64
	failures   uint64
	saturated  bool
	lastReason string
	lastOKNano int64
}

// archiveBatch is the on-disk record: only safe fields. batch_id is a content-range
// identity (capability|partition|first+last digest|count); content_hash covers every
// event digest in order, so an identical retry is idempotent while a DIFFERENT batch
// re-using the same range identity is detected as a conflict.
type archiveBatch struct {
	BatchID     string          `json:"batch_id"`
	ContentHash string          `json:"content_hash"`
	Capability  string          `json:"capability"`
	Partition   string          `json:"partition"`
	Count       int             `json:"count"`
	FirstDigest string          `json:"first_digest"`
	LastDigest  string          `json:"last_digest"`
	Events      []evmodel.Event `json:"events"`
}

func newQualArchiveExporter(root string, maxBytes int64) (*qualArchiveExporter, error) {
	if err := os.MkdirAll(root, telemDirPerm); err != nil {
		return nil, err
	}
	e := &qualArchiveExporter{root: filepath.Clean(root), maxBytes: maxBytes, made: map[string]bool{}}
	e.bytesUsed = dirSize(e.root) // restart-safe capacity accounting
	return e, nil
}

// Export durably archives a bounded batch of safe events and returns the accepted
// count. It is all-or-nothing: either the whole batch is fsynced and len(batch) is
// returned, or nothing is written and (0, err) is returned (the spool + cursor stay
// intact and the batch is retried). An identical batch already on disk is accepted
// idempotently; a conflicting batch under the same identity is rejected.
func (e *qualArchiveExporter) Export(_ context.Context, batch []evmodel.Event) (int, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	capName, partName, err := validateBatch(batch)
	if err != nil {
		return 0, err
	}
	rec := buildArchiveBatch(batch, capName, partName)
	body, err := json.Marshal(rec)
	if err != nil {
		return 0, errTelemetry("batch could not be encoded")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	dir := filepath.Join(e.root, capName, partName)
	path := filepath.Join(dir, rec.BatchID+".json")

	if existing, ok := e.readExisting(path); ok {
		if existing.ContentHash == rec.ContentHash {
			return len(batch), nil // idempotent retry
		}
		e.lastReason = "conflict"
		return 0, errTelemetry("conflicting duplicate batch identity")
	}
	// If a file already occupies this path (an unreadable/corrupt prior write —
	// readExisting returned false above), its bytes were already counted at open by
	// dirSize (or by an earlier successful write). Discount the old on-disk size FIRST
	// so both the capacity check and the running total treat this as a replacement,
	// not an addition — otherwise repairing a corrupt batch near the cap would wrongly
	// saturate and could never advance the cursor.
	var priorSize int64
	if fi, statErr := os.Stat(path); statErr == nil {
		priorSize = fi.Size()
	}
	if e.maxBytes > 0 && e.bytesUsed-priorSize+int64(len(body)) > e.maxBytes {
		e.saturated = true
		e.lastReason = "saturated"
		return 0, errTelemetry("archive capacity saturated") // no silent drop; spool retained
	}
	if err := e.ensureDir(dir); err != nil {
		e.lastReason = "write_error"
		return 0, errTelemetry("archive directory is not usable")
	}
	if err := fileutil.AtomicWrite(path, body, telemFilePerm); err != nil {
		e.lastReason = "write_error"
		return 0, errTelemetry("archive batch write failed")
	}
	e.bytesUsed += int64(len(body)) - priorSize
	e.batchesOK++
	e.saturated = false
	return len(batch), nil
}

func (e *qualArchiveExporter) readExisting(path string) (archiveBatch, bool) {
	raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- fixed hex-id path under a cleaned root
	if err != nil {
		return archiveBatch{}, false
	}
	var b archiveBatch
	if json.Unmarshal(raw, &b) != nil {
		return archiveBatch{}, false
	}
	return b, true
}

func (e *qualArchiveExporter) ensureDir(dir string) error {
	if e.made[dir] {
		return nil
	}
	if err := os.MkdirAll(dir, telemDirPerm); err != nil {
		return err
	}
	e.made[dir] = true
	return nil
}

func (e *qualArchiveExporter) noteExported(n int) {
	e.mu.Lock()
	e.exported += uint64(n) // #nosec G115 -- n is a batch length (>=0)
	e.lastOKNano = time.Now().UnixNano()
	e.mu.Unlock()
}

func (e *qualArchiveExporter) noteFailure(reason string) {
	e.mu.Lock()
	e.failures++
	if reason != "" {
		e.lastReason = reason
	}
	e.mu.Unlock()
}

// archiveStats is the safe exporter snapshot for health/metrics.
type archiveStats struct {
	ExportedEvents uint64
	BatchesOK      uint64
	Failures       uint64
	Saturated      bool
	BytesUsed      int64
	MaxBytes       int64
	LastReason     string
	LastOKUnixNano int64
}

func (e *qualArchiveExporter) stats() archiveStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return archiveStats{
		ExportedEvents: e.exported, BatchesOK: e.batchesOK, Failures: e.failures,
		Saturated: e.saturated, BytesUsed: e.bytesUsed, MaxBytes: e.maxBytes,
		LastReason: e.lastReason, LastOKUnixNano: e.lastOKNano,
	}
}

// validateBatch verifies every event carries schema version 1, a non-empty digest,
// and the SAME capability+partition (a pump batch is single-partition). It rejects an
// unknown schema version and returns the safe cap/partition names.
func validateBatch(batch []evmodel.Event) (capName, partName string, err error) {
	c0, p0 := batch[0].Capability, batch[0].Partition
	for i := range batch {
		e := batch[i]
		if e.SchemaVersion != evmodel.SchemaVersion {
			return "", "", errTelemetry("unsupported event schema version")
		}
		if e.EventDigest == "" {
			return "", "", errTelemetry("event missing digest")
		}
		if e.Capability != c0 || e.Partition != p0 {
			return "", "", errTelemetry("mixed capability/partition in one batch")
		}
	}
	return telemCapabilityName(c0), telemPartitionName(p0), nil
}

// buildArchiveBatch computes the deterministic identity + content hash and assembles
// the safe on-disk record.
func buildArchiveBatch(batch []evmodel.Event, capName, partName string) archiveBatch {
	first, last := batch[0].EventDigest, batch[len(batch)-1].EventDigest
	idH := sha256.New()
	idH.Write([]byte(capName + "\x00" + partName + "\x00" + first + "\x00" + last + "\x00"))
	countBytes := []byte(itoaLen(len(batch)))
	idH.Write(countBytes)

	contentH := sha256.New()
	for i := range batch {
		contentH.Write([]byte(batch[i].EventDigest))
		contentH.Write([]byte{0})
	}
	return archiveBatch{
		BatchID:     hex.EncodeToString(idH.Sum(nil)),
		ContentHash: hex.EncodeToString(contentH.Sum(nil)),
		Capability:  capName,
		Partition:   partName,
		Count:       len(batch),
		FirstDigest: first,
		LastDigest:  last,
		Events:      batch,
	}
}

func telemCapabilityName(c evmodel.Capability) string {
	if c == evmodel.CapManagement {
		return "management"
	}
	return "gateway"
}

// itoaLen renders a non-negative int without importing strconv into the hash path.
func itoaLen(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// dirSize sums the sizes of regular files under root (restart-safe archive capacity
// accounting). Best-effort: an unreadable entry is skipped.
func dirSize(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}
