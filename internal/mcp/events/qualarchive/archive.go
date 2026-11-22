package qualarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// Directory and file modes of everything this package creates.
const (
	dirPerm  = 0o700
	filePerm = 0o600
)

// errArchive builds a bounded, secret-free error (never a path, an identity or
// file content). The "mcp telemetry: " prefix and the phrases are unchanged
// from package main: its export loop reduces them to a reason class by
// substring, and operators have seen them in health output.
func errArchive(msg string) error { return errors.New("mcp telemetry: " + msg) }

// ── durable export cursor store ─────────────────────────────────────────────────

// CursorStore persists the per-partition export cursor durably (fsync via
// fileutil.AtomicWrite) so a restart resumes exactly where the last acknowledged
// batch left off. Cursors are monotonic and per-partition — one partition can never
// overwrite another (distinct files), and this store is Gateway-only (a distinct
// directory from any Management state).
type CursorStore struct {
	mu  sync.Mutex
	dir string
	cur map[evmodel.Partition]uint64
}

type cursorFile struct {
	Cursor uint64 `json:"cursor"`
}

// NewCursorStore creates dir if needed and loads the persisted cursor of each
// partition in parts. An absent or undecodable cursor file starts at 0.
func NewCursorStore(dir string, parts []evmodel.Partition) (*CursorStore, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, err
	}
	s := &CursorStore{dir: dir, cur: map[evmodel.Partition]uint64{}}
	for _, part := range parts {
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

func (s *CursorStore) path(part evmodel.Partition) string {
	return filepath.Join(s.dir, PartitionName(part)+".cursor")
}

// Get returns the partition's last durably persisted cursor (0 if none).
func (s *CursorStore) Get(part evmodel.Partition) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur[part]
}

// Advance persists a strictly-forward cursor (monotonic). A backward or equal value
// is a no-op success; a forward value is durably written before the in-memory value
// moves, so the persisted cursor never runs ahead of a durable acknowledgement.
func (s *CursorStore) Advance(part evmodel.Partition, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.cur[part] {
		return nil
	}
	b, err := json.Marshal(cursorFile{Cursor: seq})
	if err != nil {
		return err
	}
	if err := fileutil.AtomicWrite(s.path(part), b, filePerm); err != nil {
		return err
	}
	s.cur[part] = seq
	return nil
}

// PartitionName maps a partition to a fixed, path/label-safe token (never a raw
// or attacker-controlled string).
func PartitionName(p evmodel.Partition) string {
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

// Exporter is the first production-capable sink: a node-local, bounded,
// append-of-atomic-batches, idempotent archive of SAFE event envelopes. It is
// ADDITIVE to the encrypted source spool (a failure here never erases spool
// durability), performs NO network activity, stores only the safe envelope (never
// raw spool frames, encrypted segment bytes, or request/response bodies), and
// acknowledges a batch ONLY after it is durably fsynced (via fileutil.AtomicWrite).
type Exporter struct {
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

// NewExporter creates root if needed and counts the bytes already under it, so
// the cap survives a restart. maxBytes <= 0 means no cap.
func NewExporter(root string, maxBytes int64) (*Exporter, error) {
	if err := os.MkdirAll(root, dirPerm); err != nil {
		return nil, err
	}
	e := &Exporter{root: filepath.Clean(root), maxBytes: maxBytes, made: map[string]bool{}}
	e.bytesUsed = dirSize(e.root) // restart-safe capacity accounting
	return e, nil
}

// Export durably archives a bounded batch of safe events and returns the accepted
// count. It is all-or-nothing: either the whole batch is fsynced and len(batch) is
// returned, or nothing is written and (0, err) is returned (the spool + cursor stay
// intact and the batch is retried). An identical batch already on disk is accepted
// idempotently; a conflicting batch under the same identity is rejected.
func (e *Exporter) Export(_ context.Context, batch []evmodel.Event) (int, error) {
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
		return 0, errArchive("batch could not be encoded")
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
		return 0, errArchive("conflicting duplicate batch identity")
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
		return 0, errArchive("archive capacity saturated") // no silent drop; spool retained
	}
	if err := e.ensureDir(dir); err != nil {
		e.lastReason = "write_error"
		return 0, errArchive("archive directory is not usable")
	}
	if err := fileutil.AtomicWrite(path, body, filePerm); err != nil {
		e.lastReason = "write_error"
		return 0, errArchive("archive batch write failed")
	}
	e.bytesUsed += int64(len(body)) - priorSize
	e.batchesOK++
	e.saturated = false
	return len(batch), nil
}

func (e *Exporter) readExisting(path string) (archiveBatch, bool) {
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

func (e *Exporter) ensureDir(dir string) error {
	if e.made[dir] {
		return nil
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return err
	}
	e.made[dir] = true
	return nil
}

// NoteExported records n events as exported. The caller calls it after the
// batch was accepted AND its cursor was persisted.
func (e *Exporter) NoteExported(n int) {
	e.mu.Lock()
	e.exported += uint64(n) // #nosec G115 -- n is a batch length (>=0)
	e.lastOKNano = time.Now().UnixNano()
	e.mu.Unlock()
}

// NoteFailure counts one failed export step; a non-empty reason becomes the
// last reported reason class.
func (e *Exporter) NoteFailure(reason string) {
	e.mu.Lock()
	e.failures++
	if reason != "" {
		e.lastReason = reason
	}
	e.mu.Unlock()
}

// Stats is the safe exporter snapshot for health/metrics.
type Stats struct {
	ExportedEvents uint64
	BatchesOK      uint64
	Failures       uint64
	Saturated      bool
	BytesUsed      int64
	MaxBytes       int64
	LastReason     string
	LastOKUnixNano int64
}

// Stats returns a consistent snapshot of the counters.
func (e *Exporter) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{
		ExportedEvents: e.exported, BatchesOK: e.batchesOK, Failures: e.failures,
		Saturated: e.saturated, BytesUsed: e.bytesUsed, MaxBytes: e.maxBytes,
		LastReason: e.lastReason, LastOKUnixNano: e.lastOKNano,
	}
}

// validateBatch verifies every event carries a SUPPORTED schema version (v1 or the v2
// durable-Shadow-evidence envelope), a non-empty digest, and the SAME capability+partition
// (a pump batch is single-partition). It rejects a genuinely unknown schema version and
// returns the safe cap/partition names.
//
// This MUST accept every supported version, not just the default (v1): a Shadow decision
// event is stamped SchemaVersionV2 (SHADOW-EVIDENCE-ROUTING-1), and because the export pump
// retries an all-or-nothing batch without advancing its cursor, a hardcoded `!= v1` check
// would let the first v2 Shadow event wedge its whole partition out of the durable archive —
// exactly the evidence the activation verification requires to be flowing there.
func validateBatch(batch []evmodel.Event) (capName, partName string, err error) {
	c0, p0 := batch[0].Capability, batch[0].Partition
	for i := range batch {
		e := batch[i]
		if !evmodel.SupportedSchemaVersion(e.SchemaVersion) {
			return "", "", errArchive("unsupported event schema version")
		}
		if e.EventDigest == "" {
			return "", "", errArchive("event missing digest")
		}
		if e.Capability != c0 || e.Partition != p0 {
			return "", "", errArchive("mixed capability/partition in one batch")
		}
	}
	return capabilityName(c0), PartitionName(p0), nil
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

func capabilityName(c evmodel.Capability) string {
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
