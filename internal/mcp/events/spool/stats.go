package spool

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Stats is a safe, typed snapshot of one spool's durability state. It carries no
// tenant, subject, token, session, argument or URL — only bounded counts, bytes
// and ids — so it is safe to surface on a health endpoint.
type Stats struct {
	Capability        model.Capability
	TotalBytes        int64
	SpoolMaxBytes     int
	CriticalReserve   int
	CriticalFreeBytes int64 // headroom P-CRIT still has (criterion-2 input)
	ReplayWindowUsed  int
	Partitions        map[model.Partition]PartitionStats
}

// PartitionStats is one partition's safe snapshot.
type PartitionStats struct {
	Bytes                int64
	Quota                int
	Segments             int
	Records              int
	NextSeq              uint64
	OldestUnexportedNano int64
}

// Stats returns a safe snapshot of the spool.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statsLocked()
}

func (s *Spool) statsLocked() Stats {
	st := Stats{
		Capability:       s.cap,
		TotalBytes:       s.totalBytesLocked(),
		SpoolMaxBytes:    s.lim.SpoolMaxBytes(),
		CriticalReserve:  s.lim.CriticalReserveBytes(),
		ReplayWindowUsed: len(s.replayFIFO),
		Partitions:       map[model.Partition]PartitionStats{},
	}
	for pk, p := range s.parts {
		var records int
		var oldest int64
		for _, sg := range p.segments {
			records += sg.records
			if !sg.exported && (oldest == 0 || sg.createdNano < oldest) {
				oldest = sg.createdNano
			}
		}
		st.Partitions[pk] = PartitionStats{
			Bytes: p.totalBytes, Quota: p.quotaBytes, Segments: len(p.segments),
			Records: records, NextSeq: p.nextSeq, OldestUnexportedNano: oldest,
		}
	}
	// P-CRIT headroom = whole spool minus what P-ORD/P-DEN hold minus what P-CRIT
	// already holds; always >= the reserve minus what P-CRIT holds.
	avail := int64(s.lim.SpoolMaxBytes()) - s.parts[model.PartOrd].totalBytes - s.parts[model.PartDen].totalBytes
	st.CriticalFreeBytes = avail - s.parts[model.PartCrit].totalBytes
	if st.CriticalFreeBytes < 0 {
		st.CriticalFreeBytes = 0
	}
	return st
}

// ProbeWritable reports whether a probe write to the P-CRIT partition would be
// admitted right now (criterion-1 input for the recovery-exit check). It is a
// pure capacity check and does not write.
func (s *Spool) ProbeWritable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A minimal frame must fit in P-CRIT's available capacity.
	minFrame := int64(recFixedPrefixLen + gcmOverhead + 1)
	return s.admitLocked(s.parts[model.PartCrit], minFrame) == nil
}

// CommittedForExport returns up to maxRecords committed events from a partition
// whose sequence is strictly greater than afterSeq, in ascending sequence order.
// The events are the full safe envelopes (no secrets by construction); the export
// layer applies tenant/capability authorization and bounds. This never returns an
// uncommitted tail record.
func (s *Spool) CommittedForExport(part model.Partition, afterSeq uint64, maxRecords int) ([]model.Event, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.parts[part]
	if p == nil {
		return nil, afterSeq, spErr(mcperr.ReasonEventInvalid, "unknown partition")
	}
	segs := make([]*segState, len(p.segments))
	copy(segs, p.segments)
	sort.Slice(segs, func(i, j int) bool { return segs[i].id < segs[j].id })

	var out []model.Event
	cursor := afterSeq
	for _, sg := range segs {
		if len(out) >= maxRecords {
			break
		}
		if sg.lastSeq <= afterSeq {
			continue
		}
		evs, err := s.readSegmentEventsLocked(sg)
		if err != nil {
			return nil, cursor, err
		}
		// Records within a segment are stored in ascending sequence starting at the
		// segment's firstSeq, so the i-th committed record has sequence firstSeq+i.
		for i, e := range evs {
			if len(out) >= maxRecords {
				break
			}
			seq := sg.firstSeq + uint64(i)
			if seq <= afterSeq {
				continue
			}
			out = append(out, e)
			cursor = seq
		}
	}
	return out, cursor, nil
}

// readSegmentEventsLocked decodes all committed events in a segment (used by
// export reads). It re-verifies each record's integrity.
func (s *Spool) readSegmentEventsLocked(sg *segState) ([]model.Event, error) {
	buf := make([]byte, sg.committedLen)
	n, err := s.be.ReadAt(sg.path, 0, buf)
	if err != nil || int64(n) != sg.committedLen {
		return nil, spWrap(mcperr.ReasonEventSpoolCorrupt, "read segment", err)
	}
	off := segHeaderLen
	var out []model.Event
	for off < len(buf) {
		f, derr := decodeRecordAt(buf[off:])
		if derr != nil {
			return nil, spWrap(mcperr.ReasonEventSpoolCorrupt, "record decode", derr)
		}
		pt, _, verr := verifyRecord(s.cr, f)
		if verr != nil {
			return nil, spWrap(mcperr.ReasonEventSpoolCorrupt, "record verify", verr)
		}
		var e model.Event
		if uerr := unmarshalEvent(pt, &e); uerr != nil {
			return nil, spWrap(mcperr.ReasonEventSpoolCorrupt, "event decode", uerr)
		}
		out = append(out, e)
		off += f.total
	}
	return out, nil
}
