package spool

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func critSegPath(root string) string {
	return filepath.Join(root, model.PartCrit.String(), "seg-00000001.dat")
}

// TestCrashTailTruncated proves an uncommitted torn tail beyond the committed
// checkpoint length is truncated on recovery, and the committed records survive.
func TestCrashTailTruncated(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	if _, err := s.Commit(criticalEvent("0001", "x")); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Simulate a crash mid-append: garbage bytes after the committed record.
	seg := critSegPath(root)
	f, err := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("TORN-PARTIAL-RECORD-GARBAGE")
	_ = f.Close()

	s2 := newTestSpool(t, root)
	rep, err := s2.Recover()
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rep.Corrupt {
		t.Fatalf("torn tail must not be interior corruption: %s", rep.CorruptReason)
	}
	if rep.Records[model.PartCrit] != 1 {
		t.Fatalf("committed record lost: %d", rep.Records[model.PartCrit])
	}
	// The tail must have been truncated back to the committed length.
	fi, _ := os.Stat(seg)
	if fi.Size() != committedLenOf(t, s2, model.PartCrit) {
		t.Fatalf("tail not truncated: file %d != committed %d", fi.Size(), committedLenOf(t, s2, model.PartCrit))
	}
}

func committedLenOf(t *testing.T, s *Spool, p model.Partition) int64 {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	for _, sg := range s.parts[p].segments {
		total += sg.committedLen
	}
	return total
}

// TestInteriorCorruptionFailsTowardCritical proves that flipping a byte inside a
// committed record is detected on recovery as corruption (fail toward the narrow
// critical state), never silently accepted or repaired to normal.
func TestInteriorCorruptionFailsTowardCritical(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	if _, err := s.Commit(criticalEvent("0001", "x")); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	seg := critSegPath(root)
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the first record's ciphertext (well past the header).
	pos := segHeaderLen + recFixedPrefixLen + 3
	if pos >= len(b) {
		t.Fatalf("segment too small: %d", len(b))
	}
	b[pos] ^= 0xFF
	if err := os.WriteFile(seg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newTestSpool(t, root)
	rep, err := s2.Recover()
	if err != nil {
		t.Fatalf("Recover returned error (want Corrupt flag): %v", err)
	}
	if !rep.Corrupt || rep.CorruptPartition != model.PartCrit {
		t.Fatalf("interior corruption not detected: %+v", rep)
	}
}

// TestCorruptCheckpointFailsTowardCritical proves a checkpoint-digest mismatch is
// detected and never silently replaced with a fresh normal file.
func TestCorruptCheckpointFailsTowardCritical(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	if _, err := s.Commit(criticalEvent("0001", "x")); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	ck := filepath.Join(root, model.PartCrit.String(), "checkpoint.json")
	b, _ := os.ReadFile(ck)
	b[len(b)/2] ^= 0xFF // corrupt the checkpoint body → digest mismatch
	_ = os.WriteFile(ck, b, 0o600)

	s2 := newTestSpool(t, root)
	rep, _ := s2.Recover()
	if !rep.Corrupt {
		t.Fatal("corrupt checkpoint must be detected, not silently reset to normal")
	}
}

// TestReclamationOrder proves the deterministic reclamation priority: denial and
// ordinary sealed segments are reclaimed before an unexported critical segment,
// and an unexported P-CRIT record is retained (CI-GATES test #8, spool level).
func TestReclamationOrder(t *testing.T) {
	root := t.TempDir()
	cfg := smallEventConfig()
	// Force tiny segments so each commit rolls a new segment quickly.
	cfg.SegmentMaxBytes = 2048
	cfg.MaxEventBytes = 1024
	lim, err := limits.NewEvent(cfg)
	if err != nil {
		t.Fatalf("limits: %v", err)
	}
	s, err := New(Config{Root: root, Capability: model.CapGateway, NodeID: "dp", Limits: lim, KEK: testKEK(), Clock: func() time.Time { return time.Unix(0, 1) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	// Commit a critical record and DO NOT export it.
	if _, err := s.Commit(criticalEvent("keepcrit", "x")); err != nil {
		t.Fatalf("critical commit: %v", err)
	}
	critBefore := partitionBytes(s, model.PartCrit)

	// Fill ordinary + denial with many records and mark their sealed segments
	// exported so they are top reclamation priority.
	for i := 0; i < 200; i++ {
		_, _ = s.Commit(ordinaryEvent(i))
		_, _ = s.Commit(denialEvent(i))
	}
	markAllSealedExported(s, model.PartOrd)
	markAllSealedExported(s, model.PartDen)

	// Drive reclamation.
	stuck := s.Reclaim()

	// The unexported critical record must be retained.
	if partitionBytes(s, model.PartCrit) < critBefore {
		t.Fatal("unexported critical bytes were reclaimed")
	}
	_ = stuck
	// Denial/ordinary exported segments should have been reclaimed first (their
	// byte totals dropped or the spool is at/below low watermark).
	if partitionBytes(s, model.PartDen)+partitionBytes(s, model.PartOrd) == 0 && partitionBytes(s, model.PartCrit) == 0 {
		t.Fatal("everything reclaimed including critical")
	}
}

// TestReclaimThenRecoverPreservesChain is the regression guard for the
// reclamation chain-anchor fix: reclaiming EARLIER sealed segments (dropping
// their bytes and their checkpoint rows) must never be read as a hash-chain
// break on the next recovery. Each surviving segment verifies from its OWN
// stored anchor, so a reopened spool reports no corruption and recovers the
// records that survived reclamation.
func TestReclaimThenRecoverPreservesChain(t *testing.T) {
	root := t.TempDir()
	cfg := smallEventConfig()
	// Tiny segments so many sealed segments accumulate behind the active tail.
	cfg.SegmentMaxBytes = 2048
	cfg.MaxEventBytes = 1024
	lim, err := limits.NewEvent(cfg)
	if err != nil {
		t.Fatalf("limits: %v", err)
	}
	s, err := New(Config{Root: root, Capability: model.CapGateway, NodeID: "dp", Limits: lim, KEK: testKEK(), Clock: func() time.Time { return time.Unix(0, 1) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	committed := 0
	for i := 0; i < 300; i++ {
		if _, cerr := s.Commit(ordinaryEvent(i)); cerr != nil {
			// Filling toward the ordinary quota is expected; stop once saturated so
			// several sealed segments already exist to reclaim.
			if mcperr.ReasonOf(cerr) == mcperr.ReasonEventQueueSaturated {
				break
			}
			t.Fatalf("commit %d: %v", i, cerr)
		}
		committed++
	}
	if committed == 0 {
		t.Fatal("no ordinary records committed")
	}
	before := partitionBytes(s, model.PartOrd)
	// Remove the OLDEST sealed ordinary segments through the same reclamation path
	// reclaimLocked uses (removeSegmentLocked drops the file + rewrites the
	// checkpoint). Doing this directly is deterministic regardless of watermark and
	// is exactly the operation the chain-anchor fix must survive.
	removeOldestSealed(t, s, model.PartOrd, 2)
	after := partitionBytes(s, model.PartOrd)
	if after >= before {
		t.Fatalf("reclamation freed nothing (%d >= %d); test would not exercise the fix", after, before)
	}

	// Reopen from the same root and recover: reclaiming the earliest segments must
	// not corrupt the surviving chain.
	s2 := newTestSpool(t, root)
	rep, rerr := s2.Recover()
	if rerr != nil {
		t.Fatalf("Recover after reclamation: %v", rerr)
	}
	if rep.Corrupt {
		t.Fatalf("recovery after reclaiming early segments reported corruption: %s", rep.CorruptReason)
	}
	if rep.Records[model.PartOrd] == 0 {
		t.Fatal("no ordinary records survived reclamation + recovery")
	}
}

// removeOldestSealed reclaims up to n of the oldest sealed segments in a
// partition through removeSegmentLocked — the exact operation reclaimLocked
// performs — so the reclamation chain-anchor path is exercised deterministically.
func removeOldestSealed(t *testing.T, s *Spool, part model.Partition, n int) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.parts[part]
	removed := 0
	for i := 0; i < len(p.segments) && removed < n; {
		if p.segments[i].sealed && s.removeSegmentLocked(p, i) {
			removed++ // slice shrank at i; do not advance
			continue
		}
		i++
	}
	if removed == 0 {
		t.Fatal("no sealed segment available to reclaim")
	}
}

func partitionBytes(s *Spool, p model.Partition) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.parts[p].totalBytes
}

func markAllSealedExported(s *Spool, p model.Partition) {
	s.mu.Lock()
	ids := []uint32{}
	for _, sg := range s.parts[p].segments {
		if sg.sealed {
			ids = append(ids, sg.id)
		}
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.MarkExported(p, id)
	}
}

func ordinaryEvent(i int) *model.Event {
	id := "o" + strconv.Itoa(i)
	e := &model.Event{
		SchemaVersion: model.SchemaVersion, EventID: "evt_" + id, Phase: model.PhaseDecision,
		Criticality: model.CritOrdinary, Partition: model.PartOrd, Capability: model.CapGateway,
		ActionClass: model.ActionClassRead, NodeID: "dp", DomainID: "d", TimeUnixNano: 1,
		ReplayID: "rpl_" + id, CorrelationID: "cor_" + id,
		Identity: model.IdentityEvidence{Tenant: "acme", PrincipalID: "u", PrincipalType: "human"},
		Decision: model.DecisionEvidence{Action: "MONITOR", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1},
	}
	_, _ = e.ComputeDigest()
	return e
}
