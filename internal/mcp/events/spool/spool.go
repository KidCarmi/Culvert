// Package spool implements the mandatory local encrypted, bounded, durable spool
// for the PR-8 decision-event pipeline. It is one capability's spool: three
// logically separate partitions (P-CRIT / P-ORD / P-DEN) over a versioned,
// append-only, authenticated-encryption segment format, with a durable commit
// (append + fsync + crash-consistent checkpoint, CONFIRMED — a queue admission or
// a bare Write is NOT a commit), crash-tail recovery, deterministic reclamation,
// per-partition monotonic sequences, a bounded per-partition tamper-evident hash
// chain, replay-id deduplication, and unforgeable commit receipts.
//
// The three load-bearing guarantees:
//
//   - P-CRIT reserved capacity is never consumed by P-ORD/P-DEN. The limits
//     guarantee OrdinaryQuota + DenialQuota <= SpoolMaxBytes - CriticalReserve, so
//     the reserve is always physically available; admission enforces it per
//     partition (spool.go), and reclamation never deletes an unexported P-CRIT
//     record while any lower-priority record remains (reclaim.go).
//   - A commit is confirmed, not enqueued. A record is committed IFF the
//     checkpoint's per-segment CommittedLen covers it; append/fsync/checkpoint
//     failure, ENOSPC, or an encryption-key failure returns a commit error and
//     no receipt (never a plaintext fallback).
//   - Corruption fails toward the narrow critical state. Interior record
//     corruption or a checkpoint-digest mismatch on recovery is surfaced as a
//     corruption error the caller maps to critical-durability-degraded — never
//     silently repaired to "normal", never inventing a committed critical receipt.
package spool

import (
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/secret"
)

const (
	dirPerm  = 0o700
	filePerm = 0o600
)

// Config constructs a Spool. Root is the per-capability spool directory; the
// manager guarantees Root is distinct per capability and does not alias another
// spool, the config-versions store, or the audit ring.
type Config struct {
	Root       string
	Capability model.Capability
	NodeID     string
	Limits     limits.EventLimits
	KEK        *secret.Provider
	// Backend is the filesystem seam; nil uses the real OS backend.
	Backend fsBackend
	// Clock supplies commit timestamps; nil uses time.Now.
	Clock func() time.Time
}

// Spool is one capability's durable event spool.
type Spool struct {
	mu     sync.Mutex
	root   string
	cap    model.Capability
	nodeID string
	lim    limits.EventLimits
	cr     *cryptor
	be     fsBackend
	clock  func() time.Time

	parts map[model.Partition]*partition

	// replay dedup, bounded FIFO within the retained window.
	replay     map[string]replayEntry
	replayFIFO []string
}

type replayEntry struct {
	digest  string
	receipt CommitReceipt
}

// partition is one logical partition's in-memory state, reconstructed from the
// durable checkpoint at open.
type partition struct {
	kind       model.Partition
	dir        string
	ckptPath   string
	quotaBytes int // own quota (P-DEN/P-ORD); for P-CRIT the reserve floor (dynamic cap computed in admit)
	segments   []*segState
	nextSeq    uint64
	nextSegID  uint32
	lastChain  [32]byte
	totalBytes int64
}

type segState struct {
	id           uint32
	path         string
	firstSeq     uint64
	lastSeq      uint64
	committedLen int64
	records      int
	sealed       bool
	exported     bool
	createdNano  int64
}

func spErr(r mcperr.Reason, detail string) error {
	return mcperr.New(r, "events.spool", detail)
}

func spWrap(r mcperr.Reason, detail string, cause error) error {
	return mcperr.Wrap(r, "events.spool", detail, cause)
}

// New opens (or creates) a capability spool. It creates the directory tree, loads
// or generates the sealed DEK, and recovers durable state. A nil KEK fails closed
// (encryption is mandatory; there is no plaintext fallback).
func New(cfg Config) (*Spool, error) {
	if !cfg.Capability.Valid() {
		return nil, spErr(mcperr.ReasonEventInvalid, "invalid capability")
	}
	if cfg.Root == "" {
		return nil, spErr(mcperr.ReasonEventInvalid, "empty spool root")
	}
	if cfg.NodeID == "" {
		return nil, spErr(mcperr.ReasonEventInvalid, "empty node id")
	}
	be := cfg.Backend
	if be == nil {
		be = osBackend{}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	if err := be.MkdirAll(cfg.Root, dirPerm); err != nil {
		return nil, spWrap(mcperr.ReasonEventCommitFailed, "mkdir root", err)
	}
	cr, err := openCryptor(be, filepath.Join(cfg.Root, dekFileName), cfg.KEK)
	if err != nil {
		return nil, spWrap(mcperr.ReasonEventEncryptionUnavailable, "open cryptor", err)
	}
	s := &Spool{
		root:   cfg.Root,
		cap:    cfg.Capability,
		nodeID: cfg.NodeID,
		lim:    cfg.Limits,
		cr:     cr,
		be:     be,
		clock:  clock,
		parts:  map[model.Partition]*partition{},
		replay: map[string]replayEntry{},
	}
	for _, pk := range []model.Partition{model.PartCrit, model.PartOrd, model.PartDen} {
		dir := filepath.Join(cfg.Root, pk.String())
		if err := be.MkdirAll(dir, dirPerm); err != nil {
			return nil, spWrap(mcperr.ReasonEventCommitFailed, "mkdir partition", err)
		}
		s.parts[pk] = &partition{
			kind:       pk,
			dir:        dir,
			ckptPath:   filepath.Join(dir, "checkpoint.json"),
			quotaBytes: s.quotaFor(pk),
			nextSeq:    1,
			nextSegID:  1,
		}
	}
	return s, nil
}

// quotaFor returns the byte quota for a partition. P-CRIT's static field is its
// reserve floor; its effective cap is computed dynamically in admit so it can use
// the free non-reserved remainder too, while never being starved below reserve.
func (s *Spool) quotaFor(p model.Partition) int {
	switch p {
	case model.PartCrit:
		return s.lim.CriticalReserveBytes()
	case model.PartOrd:
		return s.lim.OrdinaryQuotaBytes()
	case model.PartDen:
		return s.lim.DenialQuotaBytes()
	default:
		return 0
	}
}

// DomainID returns the durability-domain id for a partition (node × capability ×
// partition), the maximum automatic degraded-state scope.
func (s *Spool) DomainID(p model.Partition) string {
	return s.nodeID + "|" + s.cap.String() + "|" + p.String()
}

// Capability returns the spool's capability.
func (s *Spool) Capability() model.Capability { return s.cap }

// Commit durably commits a validated event and returns a bound receipt. The event
// MUST already carry a computed digest (ComputeDigest) and pass model.Validate;
// Commit re-validates defensively. Failure returns a classified mcperr the caller
// maps to the correct degraded state — the spool never decides state itself.
func (s *Spool) Commit(e *model.Event) (CommitReceipt, error) {
	if e == nil {
		return CommitReceipt{}, spErr(mcperr.ReasonEventInvalid, "nil event")
	}
	if err := e.Validate(); err != nil {
		return CommitReceipt{}, err
	}
	if e.Capability != s.cap {
		return CommitReceipt{}, spErr(mcperr.ReasonEventTenantConflict, "event capability does not match spool")
	}
	// Store the FULL event (including its digest); CanonicalBytes is only for the
	// digest computation itself.
	plaintext, err := e.Marshal()
	if err != nil {
		return CommitReceipt{}, spWrap(mcperr.ReasonEventInvalid, "marshal", err)
	}
	if len(plaintext) > s.lim.MaxEventBytes() {
		return CommitReceipt{}, spErr(mcperr.ReasonEventTooLarge, "encoded event exceeds MaxEventBytes")
	}
	if e.EventDigest == "" || !e.VerifyDigest() {
		return CommitReceipt{}, spErr(mcperr.ReasonEventInvalid, "event digest missing or invalid")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Replay dedup: an exact repeat of a replay identity is idempotent; a DIFFERING
	// event under the same replay identity is a conflict (never two differing
	// committed critical events under one replay id).
	if prev, ok := s.replay[e.ReplayID]; ok {
		if prev.digest == e.EventDigest {
			return prev.receipt, nil
		}
		return CommitReceipt{}, spErr(mcperr.ReasonEventReplayConflict, "replay id bound to a different event")
	}

	p := s.parts[e.Partition]
	if p == nil {
		return CommitReceipt{}, spErr(mcperr.ReasonEventPartitionMismatch, "unknown partition")
	}
	frameLen := int64(recFixedPrefixLen + len(plaintext) + gcmOverhead)

	// Global watermark: reclaim toward the low watermark before admitting.
	if s.totalBytesLocked()+frameLen >= int64(s.lim.HighWatermarkBytes()) {
		s.reclaimLocked(int64(s.lim.LowWatermarkBytes()))
	}
	if err := s.admitLocked(p, frameLen); err != nil {
		return CommitReceipt{}, err
	}

	rec, err := s.appendLocked(p, e, plaintext, frameLen)
	if err != nil {
		return CommitReceipt{}, err
	}
	s.rememberReplayLocked(e.ReplayID, e.EventDigest, rec)
	return rec, nil
}

// admitLocked enforces per-partition capacity. P-DEN and P-ORD are capped by
// their own quota; P-CRIT is capped by the whole spool minus what P-ORD and P-DEN
// currently hold, which — because their quotas sum to at most the non-reserved
// remainder — is always at least the reserve. Over-quota is a fail-closed
// admission failure classified by partition.
func (s *Spool) admitLocked(p *partition, frameLen int64) error {
	switch p.kind {
	case model.PartCrit:
		avail := int64(s.lim.SpoolMaxBytes()) - s.parts[model.PartOrd].totalBytes - s.parts[model.PartDen].totalBytes
		if p.totalBytes+frameLen > avail {
			return spErr(mcperr.ReasonEventQueueSaturated, "P-CRIT admission over available capacity")
		}
	default:
		if p.totalBytes+frameLen > int64(p.quotaBytes) {
			return spErr(mcperr.ReasonEventQueueSaturated, p.kind.String()+" admission over quota")
		}
	}
	return nil
}

func (s *Spool) totalBytesLocked() int64 {
	var t int64
	for _, p := range s.parts {
		t += p.totalBytes
	}
	return t
}

// appendLocked performs the durable commit for one record: rotate if needed,
// append+fsync the frame, read it back and integrity-verify, then advance the
// crash-consistent checkpoint. Any step's failure returns a classified error and
// leaves no acknowledged record (the record, if on disk, is beyond the durable
// CommittedLen and recovery truncates it).
func (s *Spool) appendLocked(p *partition, e *model.Event, plaintext []byte, frameLen int64) (CommitReceipt, error) {
	seg, err := s.activeSegmentLocked(p, frameLen)
	if err != nil {
		return CommitReceipt{}, err
	}
	seq := p.nextSeq
	prior := p.lastChain
	frame, next, err := encodeRecord(s.cr, p.kind, seq, prior, plaintext)
	if err != nil {
		return CommitReceipt{}, spWrap(mcperr.ReasonEventEncryptionFailed, "seal record", err)
	}
	offset := seg.committedLen
	if err := s.be.AppendSync(seg.path, frame, filePerm); err != nil {
		return CommitReceipt{}, s.classifyIOFailure("append record", err)
	}
	// Integrity readback: re-read the just-appended frame and verify it decrypts,
	// chains and matches. A torn or silently-mangled write is caught here BEFORE the
	// checkpoint acknowledges it.
	if err := s.readbackVerifyLocked(seg, offset, int64(len(frame)), p.kind, seq, prior, e.EventDigest); err != nil {
		return CommitReceipt{}, err
	}
	// Advance the durable checkpoint. Until this succeeds the record is an
	// uncommitted tail; if it fails we do not advance in-memory state.
	newLen := offset + int64(len(frame))
	if err := s.persistCheckpointLocked(p, seg, seq, next, newLen, int64(len(frame))); err != nil {
		return CommitReceipt{}, err
	}
	seg.committedLen = newLen
	seg.lastSeq = seq
	seg.records++
	p.nextSeq = seq + 1
	p.lastChain = next
	p.totalBytes += int64(len(frame))

	now := s.clock().UnixNano()
	return CommitReceipt{
		valid:           true,
		eventID:         e.EventID,
		tenant:          e.Identity.Tenant,
		capability:      s.cap,
		partition:       p.kind,
		domainID:        s.DomainID(p.kind),
		actionClass:     e.ActionClass,
		sequence:        seq,
		segmentID:       seg.id,
		committedOffset: offset,
		eventDigest:     e.EventDigest,
		commitUnixNano:  now,
		policyRevision:  e.Decision.PolicyRevision,
		catalogRevision: e.Decision.CatalogRevision,
	}, nil
}

// activeSegmentLocked returns the writable segment, sealing and rotating when the
// next frame would overflow the segment bound.
func (s *Spool) activeSegmentLocked(p *partition, frameLen int64) (*segState, error) {
	segMax := int64(s.lim.SegmentMaxBytes())
	var active *segState
	if n := len(p.segments); n > 0 && !p.segments[n-1].sealed {
		active = p.segments[n-1]
	}
	if active != nil && active.committedLen+frameLen <= segMax {
		return active, nil
	}
	if active != nil {
		active.sealed = true // sealing is recorded in the next checkpoint write
	}
	if len(p.segments) >= s.lim.MaxSegments() {
		return nil, spErr(mcperr.ReasonEventStorageFull, "segment count cap reached")
	}
	// Create a new segment: durably write its header first.
	id := p.nextSegID
	seg := &segState{
		id:          id,
		path:        filepath.Join(p.dir, "seg-"+pad8(id)+".dat"),
		firstSeq:    p.nextSeq,
		createdNano: s.clock().UnixNano(),
	}
	hdr := encodeSegHeader(segHeader{
		partition:   p.kind,
		capability:  s.cap,
		segID:       id,
		firstSeq:    p.nextSeq,
		createdNano: seg.createdNano,
		keyID:       s.cr.keyID,
	})
	if err := s.be.AppendSync(seg.path, hdr, filePerm); err != nil {
		return nil, s.classifyIOFailure("write segment header", err)
	}
	seg.committedLen = int64(len(hdr))
	p.segments = append(p.segments, seg)
	p.nextSegID = id + 1
	p.totalBytes += int64(len(hdr))
	return seg, nil
}

// readbackVerifyLocked re-reads a just-written frame and confirms it decrypts,
// chains from prior, and its plaintext matches the intended event digest.
func (s *Spool) readbackVerifyLocked(seg *segState, offset, frameLen int64, part model.Partition, seq uint64, prior [32]byte, wantDigest string) error {
	buf := make([]byte, frameLen)
	n, err := s.be.ReadAt(seg.path, offset, buf)
	if err != nil || int64(n) != frameLen {
		return spWrap(mcperr.ReasonEventCommitFailed, "readback short", err)
	}
	f, derr := decodeRecordAt(buf)
	if derr != nil {
		return spWrap(mcperr.ReasonEventSpoolCorrupt, "readback decode", derr)
	}
	if f.partition != part || f.seq != seq || f.priorChain != prior {
		return spErr(mcperr.ReasonEventSpoolCorrupt, "readback header mismatch")
	}
	pt, _, verr := verifyRecord(s.cr, f)
	if verr != nil {
		return spWrap(mcperr.ReasonEventSpoolCorrupt, "readback verify", verr)
	}
	var e model.Event
	if err := unmarshalEvent(pt, &e); err != nil || e.EventDigest != wantDigest || !e.VerifyDigest() {
		return spErr(mcperr.ReasonEventSpoolCorrupt, "readback digest mismatch")
	}
	return nil
}

// persistCheckpointLocked writes the partition's crash-consistent committed
// position after a record append. Its own failure is a commit failure (the record
// stays an uncommitted tail).
func (s *Spool) persistCheckpointLocked(p *partition, seg *segState, seq uint64, next [32]byte, segCommittedLen, _ int64) error {
	// Build a checkpoint reflecting the record as committed.
	prevLen := seg.committedLen
	prevSeq := seg.lastSeq
	prevRecords := seg.records
	seg.committedLen = segCommittedLen
	seg.lastSeq = seq
	seg.records++
	ck := s.buildCheckpointLocked(p, seq+1, next)
	// Restore the tentative fields; appendLocked commits them only on success.
	seg.committedLen = prevLen
	seg.lastSeq = prevSeq
	seg.records = prevRecords

	body, err := ck.encode()
	if err != nil {
		return spWrap(mcperr.ReasonEventCommitFailed, "encode checkpoint", err)
	}
	if len(body) > s.lim.MaxMetadataBytes() {
		return spErr(mcperr.ReasonEventCommitFailed, "checkpoint exceeds metadata bound")
	}
	if err := s.be.AtomicReplace(p.ckptPath, body, filePerm); err != nil {
		return s.classifyIOFailure("write checkpoint", err)
	}
	return nil
}

// buildCheckpointLocked renders the current durable partition state, with nextSeq
// and lastChain overridden by the pending advance.
func (s *Spool) buildCheckpointLocked(p *partition, nextSeq uint64, lastChain [32]byte) checkpoint {
	segs := make([]segMeta, 0, len(p.segments))
	for _, sg := range p.segments {
		segs = append(segs, segMeta{
			ID: sg.id, FirstSeq: sg.firstSeq, LastSeq: sg.lastSeq,
			CommittedLen: sg.committedLen, Records: sg.records,
			Sealed: sg.sealed, Exported: sg.exported, CreatedNano: sg.createdNano,
		})
	}
	return checkpoint{
		Version:      checkpointVersion,
		Partition:    byte(p.kind),
		NextSeq:      nextSeq,
		NextSegID:    p.nextSegID,
		LastChainHex: hexChain(lastChain),
		TotalBytes:   p.totalBytes,
		Segments:     segs,
	}
}

// classifyIOFailure maps a backend error to a commit-failure reason. ENOSPC is a
// distinct storage-full reason; everything else is a generic commit failure. All
// are fail-closed for a critical event; none is ever a plaintext fallback.
func (s *Spool) classifyIOFailure(op string, err error) error {
	if isENOSPC(err) {
		return spWrap(mcperr.ReasonEventStorageFull, op, err)
	}
	return spWrap(mcperr.ReasonEventCommitFailed, op, err)
}

func (s *Spool) rememberReplayLocked(replayID, digest string, rec CommitReceipt) {
	s.replay[replayID] = replayEntry{digest: digest, receipt: rec}
	s.replayFIFO = append(s.replayFIFO, replayID)
	for len(s.replayFIFO) > s.lim.ReplayWindowEntries() {
		old := s.replayFIFO[0]
		s.replayFIFO = s.replayFIFO[1:]
		delete(s.replay, old)
	}
}

// pad8 renders an id zero-padded to 8 digits for stable sort-by-name order.
func pad8(v uint32) string {
	s := strconv.FormatUint(uint64(v), 10)
	for len(s) < 8 {
		s = "0" + s
	}
	return s
}

// gcmOverhead is the GCM tag length added to each ciphertext (used for a
// conservative frame-size estimate before sealing).
const gcmOverhead = 16
