package spool

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func spoolWithBackend(t *testing.T, root string, be Backend) *Spool {
	t.Helper()
	s, err := New(Config{
		Root: root, Capability: model.CapGateway, NodeID: "dp-test",
		Limits: testLimits(t), KEK: testKEK(), Backend: be,
		Clock: func() time.Time { return time.Unix(0, 1000) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Recover(); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	return s
}

// TestCommitFailsClosedOnAppendError proves an append-time failure (short
// write / storage I/O) is a commit FAILURE — no receipt, and the record is not
// durable (recovery finds nothing).
func TestCommitFailsClosedOnAppendError(t *testing.T) {
	root := t.TempDir()
	be := newHookBackend()
	// Fail appends only to record data files (not the segment header / dek).
	be.onAppend = func(path string) error {
		if strings.Contains(path, "seg-") {
			return errors.New("injected append error")
		}
		return nil
	}
	s := spoolWithBackend(t, root, be)
	// Header write happens first (seg- path) — allow it, fail the record append.
	// To make the header succeed but the record fail, only fail after the header:
	var seenHeader bool
	be.onAppend = func(path string) error {
		if strings.Contains(path, "seg-") {
			if !seenHeader {
				seenHeader = true
				return nil // let the header through
			}
			return errors.New("injected append error")
		}
		return nil
	}
	_, err := s.Commit(criticalEvent("0001", "x"))
	if err == nil {
		t.Fatal("append failure must fail closed")
	}
	if r := mcperr.ReasonOf(err); r != mcperr.ReasonEventCommitFailed {
		t.Fatalf("reason = %v, want commit_failed", r)
	}
	// The record must not be durable: reopen with a clean backend and recover.
	s2 := newTestSpool(t, root)
	rep, _ := s2.Recover()
	if rep.Records[model.PartCrit] != 0 {
		t.Fatalf("append-failed record was durable: %d", rep.Records[model.PartCrit])
	}
}

// TestCommitFailsClosedOnENOSPC proves ENOSPC is a distinct storage-full commit
// failure.
func TestCommitFailsClosedOnENOSPC(t *testing.T) {
	root := t.TempDir()
	be := newHookBackend()
	s := spoolWithBackend(t, root, be)
	var seenHeader bool
	be.onAppend = func(path string) error {
		if strings.Contains(path, "seg-") && seenHeader {
			return enospc
		}
		if strings.Contains(path, "seg-") {
			seenHeader = true
		}
		return nil
	}
	_, err := s.Commit(criticalEvent("0001", "x"))
	if mcperr.ReasonOf(err) != mcperr.ReasonEventStorageFull {
		t.Fatalf("reason = %v, want storage_full", mcperr.ReasonOf(err))
	}
}

// TestCheckpointFailureLeavesUncommittedTail proves a checkpoint (AtomicReplace)
// failure after the record is on disk is still a commit failure, and the record
// is treated as an uncommitted tail on recovery (never acknowledged).
func TestCheckpointFailureLeavesUncommittedTail(t *testing.T) {
	root := t.TempDir()
	be := newHookBackend()
	s := spoolWithBackend(t, root, be)
	be.onReplace = func(path string) error {
		if strings.Contains(path, "checkpoint") {
			return errors.New("injected checkpoint failure")
		}
		return nil
	}
	_, err := s.Commit(criticalEvent("0001", "x"))
	if mcperr.ReasonOf(err) != mcperr.ReasonEventCommitFailed {
		t.Fatalf("reason = %v, want commit_failed", mcperr.ReasonOf(err))
	}
	// The record bytes may be on disk, but there is no committed checkpoint → the
	// record is an uncommitted tail. Recovery must not count it.
	s2 := newTestSpool(t, root)
	rep, rerr := s2.Recover()
	if rerr != nil {
		t.Fatalf("Recover: %v", rerr)
	}
	if rep.Records[model.PartCrit] != 0 {
		t.Fatalf("uncommitted tail was counted as committed: %d", rep.Records[model.PartCrit])
	}
}

// TestReservedPartition proves a P-CRIT commit still succeeds when P-DEN is
// saturated — the reserve is never consumed by denial traffic (CI-GATES test #3,
// spool level).
func TestReservedPartition(t *testing.T) {
	root := t.TempDir()
	// Tiny spool so P-DEN saturates quickly, but the reserve stays available.
	cfg := smallEventConfig()
	lim, err := limits.NewEvent(cfg)
	if err != nil {
		t.Fatalf("limits: %v", err)
	}
	s, err := New(Config{Root: root, Capability: model.CapGateway, NodeID: "dp", Limits: lim, KEK: testKEK(), Clock: func() time.Time { return time.Unix(0, 1) }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	// Saturate P-DEN.
	denialFull := false
	for i := 0; i < 100000 && !denialFull; i++ {
		d := denialEvent(i)
		if _, err := s.Commit(d); err != nil {
			if mcperr.ReasonOf(err) == mcperr.ReasonEventQueueSaturated {
				denialFull = true
				break
			}
			t.Fatalf("unexpected denial commit error: %v", err)
		}
	}
	if !denialFull {
		t.Fatal("could not saturate P-DEN")
	}
	// A critical commit MUST still succeed from the reserved capacity.
	if _, err := s.Commit(criticalEvent("crit1", "x")); err != nil {
		t.Fatalf("critical commit failed while P-DEN saturated: %v", err)
	}
}

func smallEventConfig() limits.EventConfig {
	c := limits.EventConfig{
		SpoolMaxBytes: 512 << 10, CriticalReserveBytes: 256 << 10,
		OrdinaryQuotaBytes: 128 << 10, DenialQuotaBytes: 64 << 10,
		SegmentMaxBytes: 32 << 10, MaxEventBytes: 16 << 10, MaxMetadataBytes: 64 << 10,
		MaxSafeResultBytes: 64 << 10, MaxSegments: 1024, MaxQueuePerPartition: 4096,
		MaxInFlightCommits: 64, CommitBatchSize: 64, MaxSyncOps: 16, MaxDenialBuckets: 4096,
		MaxBucketsPerSource: 128, MaxCoalescePerAggregate: 1 << 20, MaxRecoveryScanBytes: 8 << 20,
		MaxRecoverySegments: 1024, MaxRecoveryRecords: 65536, MaxReclaimPerPass: 256,
		ExporterWorkers: 2, ExportBatchRecords: 256, ExportBatchBytes: 1 << 20, ExportMaxRetries: 4,
		ReplayWindowEntries: 65536, TenantExportMaxRecords: 4096, TenantExportMaxBytes: 4 << 20,
		HighWatermarkPct: 85, LowWatermarkPct: 60, ReserveRecoveryPct: 50,
		AggregationWindow: time.Second, RetentionWindow: time.Hour, ProbeInterval: time.Second,
		CommitBatchDelay: time.Millisecond, ShutdownDrain: time.Second,
	}
	return c
}

func denialEvent(i int) *model.Event {
	id := "d" + pad8(uint32(i))
	e := &model.Event{
		SchemaVersion: model.SchemaVersion, EventID: "evt_" + id, Phase: model.PhaseDenialAggregate,
		Criticality: model.CritDenial, Partition: model.PartDen, Capability: model.CapGateway,
		NodeID: "dp", DomainID: "d", TimeUnixNano: 1, ReplayID: "rpl_" + id, CorrelationID: "cor_" + id,
		Denial: &model.DenialEvidence{DenialReason: "auth_failed", SourceBucket: "ip:203.0.113." + pad8(uint32(i%250)), Count: 1, FirstSeenUnixNano: 1, LastSeenUnixNano: 2},
	}
	_, _ = e.ComputeDigest()
	return e
}
