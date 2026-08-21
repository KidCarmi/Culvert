package spool

import "github.com/KidCarmi/Culvert/internal/mcp/events/model"

// Reclaim runs a reclamation pass toward the low watermark and reports whether an
// unexported critical record would have to be discarded to free enough space
// (which is never done). A true "stuck" result is the caller's cue to enter
// critical-durability-degraded.
func (s *Spool) Reclaim() (stuck bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reclaimLocked(int64(s.lim.LowWatermarkBytes()))
}

// reclaimLocked deletes whole SEALED segments in the fixed deterministic priority
// order until the spool is at or below the target, or no safe reclamation remains.
// It returns true when it cannot reach the target without deleting an unexported
// P-CRIT record — the "reclamation could not free space without reclaiming
// unexported critical records" condition, which the caller maps to
// critical-durability-degraded (EVENT-MODEL.md §4b.4).
//
// Reclamation order (oldest-first within each tier):
//
//	1 exported P-DEN   2 exported P-ORD   3 unexported P-DEN
//	4 unexported P-ORD 5 exported P-CRIT  (6 unexported P-CRIT: NEVER)
func (s *Spool) reclaimLocked(target int64) bool {
	type tier struct {
		part     model.Partition
		exported bool
	}
	order := []tier{
		{model.PartDen, true},
		{model.PartOrd, true},
		{model.PartDen, false},
		{model.PartOrd, false},
		{model.PartCrit, true},
	}
	budget := s.lim.MaxReclaimPerPass()
	for _, t := range order {
		if s.totalBytesLocked() <= target {
			return false
		}
		p := s.parts[t.part]
		// Oldest-first: p.segments is maintained in ascending id order.
		for i := 0; i < len(p.segments); {
			if budget <= 0 || s.totalBytesLocked() <= target {
				break
			}
			sg := p.segments[i]
			// Only SEALED segments are reclaimable (the active tail holds live data),
			// and only those matching this tier's exported flag.
			if !sg.sealed || sg.exported != t.exported {
				i++
				continue
			}
			if s.removeSegmentLocked(p, i) {
				budget-- // slice shrank at idx i; do not advance
			} else {
				i++ // could not remove; skip past it this pass
			}
		}
		if s.totalBytesLocked() <= target {
			return false
		}
	}
	// Everything reclaimable is gone and we are still above the target: the only
	// remaining space is held by unexported P-CRIT (and the active tails), which is
	// never reclaimed.
	return s.totalBytesLocked() > int64(s.lim.HighWatermarkBytes())
}

// removeSegmentLocked deletes a sealed segment file and drops it from the
// partition, updating byte accounting. It reports whether the segment was
// removed; a failed unlink leaves the segment in place (accounting stays
// consistent) — reclamation is best-effort per segment and never risks losing an
// unexported critical record.
func (s *Spool) removeSegmentLocked(p *partition, idx int) bool {
	sg := p.segments[idx]
	if err := s.be.Remove(sg.path); err != nil {
		return false
	}
	p.totalBytes -= sg.committedLen
	if p.totalBytes < 0 {
		p.totalBytes = 0
	}
	p.segments = append(p.segments[:idx], p.segments[idx+1:]...)
	// Persist the reclamation in the checkpoint so a crash cannot resurrect the
	// segment's accounting. Best-effort: a failed checkpoint here does not
	// un-delete the file; recovery re-derives from the surviving segments.
	ck := s.buildCheckpointLocked(p, p.nextSeq, p.lastChain)
	if body, err := ck.encode(); err == nil {
		_ = s.be.AtomicReplace(p.ckptPath, body, filePerm) //nolint:errcheck // best-effort; recovery re-derives
	}
	return true
}

// MarkExported records that all records in a sealed segment have been
// acknowledged by an exporter, making the segment eligible for the earlier
// reclamation tiers. It targets a specific (partition, segmentID).
func (s *Spool) MarkExported(part model.Partition, segID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.parts[part]
	if p == nil {
		return
	}
	for _, sg := range p.segments {
		if sg.id == segID {
			sg.exported = true
			ck := s.buildCheckpointLocked(p, p.nextSeq, p.lastChain)
			if body, err := ck.encode(); err == nil {
				_ = s.be.AtomicReplace(p.ckptPath, body, filePerm) //nolint:errcheck // best-effort; recovery re-derives
			}
			return
		}
	}
}
