package export

import (
	"context"
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// fakeReader is a deterministic in-memory committed-event source.
type fakeReader struct {
	cap    model.Capability
	events []model.Event // ascending sequence == index+1
}

func (f *fakeReader) Capability() model.Capability { return f.cap }

func (f *fakeReader) CommittedForExport(_ model.Partition, afterSeq uint64, maxRecords int) (events []model.Event, seqs []uint64, cursor uint64, err error) {
	cursor = afterSeq
	for i := uint64(0); i < uint64(len(f.events)); i++ {
		seq := i + 1
		if seq <= afterSeq {
			continue
		}
		if len(events) >= maxRecords {
			break
		}
		events = append(events, f.events[i])
		seqs = append(seqs, seq)
		cursor = seq
	}
	return events, seqs, cursor, nil
}

func ev(tenant string) model.Event {
	e := model.Event{
		SchemaVersion: model.SchemaVersion, EventID: "evt_x", Phase: model.PhaseDecision,
		Criticality: model.CritOrdinary, Partition: model.PartOrd, Capability: model.CapGateway,
		ActionClass: model.ActionClassRead, NodeID: "dp", DomainID: "d", TimeUnixNano: 1,
		ReplayID: "rpl_x", CorrelationID: "cor_x",
		Identity: model.IdentityEvidence{Tenant: tenant, PrincipalID: "u", PrincipalType: "human"},
		Decision: model.DecisionEvidence{Action: "MONITOR", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1},
	}
	_, _ = e.ComputeDigest()
	return e
}

func gwAuth(tenant string) Authorization {
	return Authorization{
		Tenant: tenant, Capability: model.CapGateway,
		Partitions: map[model.Partition]bool{model.PartOrd: true},
		MaxRecords: 100, MaxBytes: 1 << 20,
	}
}

func TestTenantIsolationRead(t *testing.T) {
	lim := limits.DefaultGatewayEvent()
	r := &fakeReader{cap: model.CapGateway, events: []model.Event{ev("acme"), ev("globex"), ev("acme"), ev("globex")}}
	res, err := Read(r, lim, gwAuth("acme"), model.PartOrd, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("tenant read returned %d events, want 2 (only acme)", len(res.Events))
	}
	for _, e := range res.Events {
		if e.Identity.Tenant != "acme" {
			t.Fatal("cross-tenant event leaked into a tenant read")
		}
	}
}

func TestCrossTenantReturnsNothing(t *testing.T) {
	lim := limits.DefaultGatewayEvent()
	r := &fakeReader{cap: model.CapGateway, events: []model.Event{ev("acme"), ev("acme")}}
	res, err := Read(r, lim, gwAuth("globex"), model.PartOrd, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(res.Events) != 0 {
		t.Fatal("a tenant read another tenant's events")
	}
}

func TestCapabilityMismatchRejected(t *testing.T) {
	lim := limits.DefaultGatewayEvent()
	r := &fakeReader{cap: model.CapGateway, events: []model.Event{ev("acme")}}
	auth := gwAuth("acme")
	auth.Capability = model.CapManagement // mismatch vs the gateway reader
	_, err := Read(r, lim, auth, model.PartOrd, 0)
	if mcperr.ReasonOf(err) != mcperr.ReasonEventExportUnauthorized {
		t.Fatalf("want export_unauthorized, got %v", err)
	}
}

func TestPartitionNotAuthorized(t *testing.T) {
	lim := limits.DefaultGatewayEvent()
	r := &fakeReader{cap: model.CapGateway, events: []model.Event{ev("acme")}}
	_, err := Read(r, lim, gwAuth("acme"), model.PartCrit, 0) // auth only allows P-ORD
	if mcperr.ReasonOf(err) != mcperr.ReasonEventExportUnauthorized {
		t.Fatalf("want export_unauthorized, got %v", err)
	}
}

func TestRangeBoundsRejected(t *testing.T) {
	lim := limits.DefaultGatewayEvent()
	r := &fakeReader{cap: model.CapGateway}
	auth := gwAuth("acme")
	auth.MaxRecords = lim.TenantExportMaxRecords() + 1
	if mcperr.ReasonOf(mustErr(Read(r, lim, auth, model.PartOrd, 0))) != mcperr.ReasonEventExportRangeExceeded {
		t.Fatal("over-range MaxRecords not rejected")
	}
}

func mustErr(_ ReadResult, err error) error { return err }

// countingExporter accepts everything and records batches; failFirst makes the
// first Export call fail so the durability-preservation path is exercised.
type countingExporter struct {
	batches   int
	total     int
	failFirst bool
	failed    bool
}

func (c *countingExporter) Export(_ context.Context, batch []model.Event) (int, error) {
	if c.failFirst && !c.failed {
		c.failed = true
		return 0, errors.New("injected exporter outage")
	}
	c.batches++
	c.total += len(batch)
	return len(batch), nil
}

func TestExporterFailurePreservesDurability(t *testing.T) {
	lim := limits.DefaultGatewayEvent()
	r := &fakeReader{cap: model.CapGateway, events: []model.Event{ev("acme"), ev("acme")}}
	exp := &countingExporter{failFirst: true}
	acked := []uint64{}
	p := NewPump(PumpConfig{
		Reader: r, Exporter: exp, Limits: lim, Auth: gwAuth("acme"), Partition: model.PartOrd,
		BatchSize: 10, MaxRetries: 1, OnAck: func(_ model.Partition, seq uint64) { acked = append(acked, seq) },
	}, 0)
	// First step: exporter fails → no ack, cursor unadvanced (durability preserved).
	if _, err := p.Step(context.Background()); err == nil {
		t.Fatal("expected the injected exporter failure to surface")
	}
	if p.Cursor() != 0 {
		t.Fatal("cursor advanced despite export failure (durability not preserved)")
	}
	if len(acked) != 0 {
		t.Fatal("ack fired despite export failure")
	}
	// Second step: exporter recovers → events exported, cursor advances.
	if n, err := p.Step(context.Background()); err != nil || n == 0 {
		t.Fatalf("recovery step: n=%d err=%v", n, err)
	}
	if p.Cursor() == 0 {
		t.Fatal("cursor did not advance after successful export")
	}
	if len(acked) == 0 {
		t.Fatal("ack did not fire after successful export")
	}
}
