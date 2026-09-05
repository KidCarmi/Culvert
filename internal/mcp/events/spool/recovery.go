package spool

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// RecoverReport summarises what recovery reconstructed. Corrupt is true when
// interior corruption, a checkpoint-digest mismatch, or ambiguous metadata was
// found — the caller maps that to critical-durability-degraded for the affected
// domain, never to normal.
type RecoverReport struct {
	Corrupt          bool
	CorruptPartition model.Partition
	CorruptReason    string
	Records          map[model.Partition]int
}

// Recover reconstructs durable state from the on-disk checkpoints and segments.
// It replays only COMMITTED records (up to each segment's checkpointed
// CommittedLen), truncates any uncommitted tail, verifies the per-partition hash
// chain and every record's authenticated encryption, restores the replay-dedup
// window, and NEVER invents a committed critical receipt. Interior corruption or
// ambiguous metadata is reported (Corrupt) rather than silently repaired.
func (s *Spool) Recover() (RecoverReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Recover is a full rebuild from disk and is idempotent: reset in-memory
	// partition state and the replay window before reconstructing, so calling it
	// more than once (or after New) never double-counts segments.
	for _, p := range s.parts {
		p.segments = nil
		p.totalBytes = 0
		p.nextSeq = 1
		p.nextSegID = 1
		p.lastChain = [32]byte{}
	}
	s.replay = map[string]replayEntry{}
	s.replayFIFO = nil

	rep := RecoverReport{Records: map[model.Partition]int{}}
	var recovered []recoveredEvent

	for _, pk := range []model.Partition{model.PartCrit, model.PartOrd, model.PartDen} {
		p := s.parts[pk]
		evs, err := s.recoverPartitionLocked(p)
		if err != nil {
			rep.Corrupt = true
			rep.CorruptPartition = pk
			rep.CorruptReason = err.Error()
			// Continue recovering other partitions so their state is intact, but the
			// affected domain will be held degraded by the caller.
			continue
		}
		rep.Records[pk] = len(evs)
		recovered = append(recovered, evs...)
	}

	// Restore the replay-dedup window from the most recent committed events.
	sort.Slice(recovered, func(i, j int) bool { return recovered[i].time < recovered[j].time })
	for i := range recovered {
		rc := &recovered[i]
		s.rememberReplayLocked(rc.replayID, rc.digest, rc.receipt)
	}
	return rep, nil
}

type recoveredEvent struct {
	replayID string
	digest   string
	time     int64
	receipt  CommitReceipt
}

// recoverPartitionLocked rebuilds one partition. A missing checkpoint with no
// segment files is a fresh partition; a missing checkpoint with segment files, a
// corrupt checkpoint, a header/chain break, or a record that fails to decrypt is
// corruption (error).
func (s *Spool) recoverPartitionLocked(p *partition) ([]recoveredEvent, error) {
	names, err := s.be.List(p.dir)
	if err != nil {
		return nil, spWrap(mcperr.ReasonEventSpoolCorrupt, "list partition", err)
	}
	segFiles := filterSegments(names)
	ckBytes, ckErr := s.be.ReadFile(p.ckptPath)
	if ckErr != nil || len(ckBytes) == 0 {
		if len(segFiles) == 0 {
			return nil, nil // fresh partition
		}
		// Segments exist but no committed checkpoint: ambiguous — fail toward critical.
		return nil, spErr(mcperr.ReasonEventSpoolCorrupt, "segments present without a checkpoint")
	}
	ck, derr := decodeCheckpoint(ckBytes)
	if derr != nil {
		return nil, spWrap(mcperr.ReasonEventSpoolCorrupt, "checkpoint", derr)
	}
	if model.Partition(ck.Partition) != p.kind {
		return nil, spErr(mcperr.ReasonEventSpoolCorrupt, "checkpoint partition mismatch")
	}
	lastChain, ok := parseHexChain(ck.LastChainHex)
	if !ok {
		return nil, spErr(mcperr.ReasonEventSpoolCorrupt, "checkpoint chain unparsable")
	}

	// Replay committed records segment by segment in id order. Each segment starts
	// verification from ITS OWN stored chain anchor, so reclaiming an earlier segment
	// never breaks a surviving one; the LAST segment's end chain must reconcile with
	// the checkpoint's LastChainHex (intra-segment + committed-tail tamper evidence).
	sort.Slice(ck.Segments, func(i, j int) bool { return ck.Segments[i].ID < ck.Segments[j].ID })
	var (
		lastSegEnd [32]byte
		haveSeg    bool
		evs        []recoveredEvent
		scanBytes  int64
		scanRecs   int
	)
	for i := range ck.Segments {
		sm := ck.Segments[i]
		anchor, aok := parseHexChain(sm.FirstChainHex)
		if !aok {
			return nil, spErr(mcperr.ReasonEventSpoolCorrupt, "segment chain anchor unparsable")
		}
		seg, segEvs, endChain, serr := s.recoverSegmentLocked(p, sm, anchor, &scanBytes, &scanRecs)
		if serr != nil {
			return nil, serr
		}
		seg.firstChain = anchor
		p.segments = append(p.segments, seg)
		p.totalBytes += seg.committedLen
		evs = append(evs, segEvs...)
		lastSegEnd = endChain
		haveSeg = true
	}
	if haveSeg && lastSegEnd != lastChain {
		return nil, spErr(mcperr.ReasonEventSpoolCorrupt, "chain does not reconcile with checkpoint")
	}
	p.nextSeq = ck.NextSeq
	if p.nextSeq == 0 {
		p.nextSeq = 1
	}
	p.nextSegID = ck.NextSegID
	if p.nextSegID == 0 {
		p.nextSegID = 1
	}
	p.lastChain = lastChain
	return evs, nil
}

// recoverSegmentLocked replays one segment's committed records starting from the
// segment's own chain anchor, verifying the header and each record, and truncating
// any uncommitted tail beyond CommittedLen. It returns the segment's end chain.
func (s *Spool) recoverSegmentLocked(p *partition, sm segMeta, chain [32]byte, scanBytes *int64, scanRecs *int) (*segState, []recoveredEvent, [32]byte, error) {
	path := segmentPath(p.dir, sm.ID)
	size, err := s.be.Size(path)
	if err != nil {
		return nil, nil, chain, spWrap(mcperr.ReasonEventSpoolCorrupt, "stat segment", err)
	}
	if sm.CommittedLen > size {
		return nil, nil, chain, spErr(mcperr.ReasonEventSpoolCorrupt, "checkpoint claims more than the segment holds")
	}
	*scanBytes += sm.CommittedLen
	if *scanBytes > int64(s.lim.MaxRecoveryScanBytes()) {
		return nil, nil, chain, spErr(mcperr.ReasonEventSpoolCorrupt, "recovery scan bound exceeded")
	}
	buf := make([]byte, sm.CommittedLen)
	n, rerr := s.be.ReadAt(path, 0, buf)
	if rerr != nil || int64(n) != sm.CommittedLen {
		return nil, nil, chain, spWrap(mcperr.ReasonEventSpoolCorrupt, "read segment", rerr)
	}
	hdr, herr := decodeSegHeader(buf)
	if herr != nil {
		return nil, nil, chain, spWrap(mcperr.ReasonEventSpoolCorrupt, "segment header", herr)
	}
	// The header must agree with the checkpoint's identity for this segment.
	if hdr.partition != p.kind || hdr.segID != sm.ID || hdr.firstSeq != sm.FirstSeq {
		return nil, nil, chain, spErr(mcperr.ReasonEventSpoolCorrupt, "segment header identity mismatch")
	}
	seg := &segState{
		id: sm.ID, path: path, firstSeq: sm.FirstSeq, lastSeq: sm.LastSeq,
		committedLen: sm.CommittedLen, records: 0, sealed: sm.Sealed,
		exported: sm.Exported, createdNano: sm.CreatedNano,
	}
	evs, endChain, rverr := s.replaySegmentRecordsLocked(seg, buf, chain, scanRecs)
	if rverr != nil {
		return nil, nil, chain, rverr
	}
	// Truncate any uncommitted tail beyond the committed length.
	if size > sm.CommittedLen {
		_ = s.be.Truncate(path, sm.CommittedLen) //nolint:errcheck // best-effort tail truncation
	}
	return seg, evs, endChain, nil
}

// replaySegmentRecordsLocked replays the committed records in buf (after the
// header) from the given chain anchor, verifying each record's hash-chain link
// and authenticated encryption, and appending each to seg's recovered set. It
// returns the recovered events and the segment's end chain.
func (s *Spool) replaySegmentRecordsLocked(seg *segState, buf []byte, chain [32]byte, scanRecs *int) ([]recoveredEvent, [32]byte, error) {
	off := segHeaderLen
	var evs []recoveredEvent
	for off < len(buf) {
		*scanRecs++
		if *scanRecs > s.lim.MaxRecoveryRecords() {
			return nil, chain, spErr(mcperr.ReasonEventSpoolCorrupt, "recovery record bound exceeded")
		}
		f, derr := decodeRecordAt(buf[off:])
		if derr != nil {
			return nil, chain, spWrap(mcperr.ReasonEventSpoolCorrupt, "record decode", derr)
		}
		if f.priorChain != chain {
			return nil, chain, spErr(mcperr.ReasonEventSpoolCorrupt, "hash-chain break")
		}
		pt, next, verr := verifyRecord(s.cr, f)
		if verr != nil {
			return nil, chain, spWrap(mcperr.ReasonEventSpoolCorrupt, "record verify", verr)
		}
		// The schema version is read FIRST, leniently, from the authenticated
		// plaintext. Both checks below — the strict decode and the intrinsic digest —
		// structurally cannot pass on a record written by a newer build, so leaving
		// the version check after them made a version rollback report as spool
		// corruption and abort recovery, which is the alarm reserved for tampering and
		// disk damage. An unsupported version is now refused AS a schema fault, which
		// is what the paragraph below already claimed and could not deliver.
		if v, ok := peekSchemaVersion(pt); ok && !model.SupportedSchemaVersion(v) {
			return nil, chain, spErr(mcperr.ReasonEventSchemaVersion, "record unknown schema version")
		}
		var e model.Event
		if uerr := unmarshalEvent(pt, &e); uerr != nil || !e.VerifyDigest() {
			return nil, chain, spErr(mcperr.ReasonEventSpoolCorrupt, "record event invalid")
		}
		// v1/v2 reader contract (SHADOW-EVIDENCE-ROUTING-1 §4/§8). A digest-valid record
		// must still carry a SUPPORTED schema version — an unknown version is rejected as
		// such (fail closed), never partially interpreted — and its Shadow sub-facts, if
		// any, must be consistent (complete evidence on a v2 event, no shadow evidence on a
		// v1 event, valid enums, no impossible combination). Recovery never repairs
		// malformed evidence into valid evidence.
		// Retained as defence in depth behind the pre-decode peek above: the peek is
		// lenient, so this is the check that runs against the DECODED value.
		if !model.SupportedSchemaVersion(e.SchemaVersion) {
			return nil, chain, spErr(mcperr.ReasonEventSchemaVersion, "record unknown schema version")
		}
		if serr := e.ValidateShadowEvidence(); serr != nil {
			return nil, chain, spWrap(mcperr.ReasonEventSpoolCorrupt, "record shadow evidence invalid", serr)
		}
		// The attempt-evidence sibling of the shadow check: a record whose stamped
		// version disagrees with the evidence it carries is a schema fault, not a
		// record to be accepted into recovery.
		if verr := e.ValidateEvidenceSchema(); verr != nil {
			return nil, chain, spWrap(mcperr.ReasonEventSchemaVersion, "record evidence schema invalid", verr)
		}
		chain = next
		seg.records++
		evs = append(evs, recoveredEvent{
			replayID: e.ReplayID, digest: e.EventDigest, time: e.TimeUnixNano,
			receipt: s.reconstructReceipt(&e, seg, int64(off)),
		})
		off += f.total
	}
	return evs, chain, nil
}

// reconstructReceipt rebuilds a bound receipt for a recovered committed event so
// an idempotent replay after restart returns an equivalent receipt.
func (s *Spool) reconstructReceipt(e *model.Event, seg *segState, offset int64) CommitReceipt {
	return CommitReceipt{
		valid: true, eventID: e.EventID, tenant: e.Identity.Tenant, capability: s.cap,
		partition: e.Partition, domainID: s.DomainID(e.Partition), actionClass: e.ActionClass,
		sequence: 0, segmentID: seg.id, committedOffset: offset, eventDigest: e.EventDigest,
		commitUnixNano: e.TimeUnixNano, policyRevision: e.Decision.PolicyRevision,
		catalogRevision: e.Decision.CatalogRevision,
	}
}

func segmentPath(dir string, id uint32) string { return dir + "/seg-" + pad8(id) + ".dat" }

func filterSegments(names []string) []string {
	var out []string
	for _, n := range names {
		if len(n) > 4 && n[:4] == "seg-" {
			out = append(out, n)
		}
	}
	return out
}
