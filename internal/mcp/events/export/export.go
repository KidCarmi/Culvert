// Package export is the additive, tenant-separated export foundation for the
// PR-8 event pipeline (MCP-EVENT-006 / MCP-PRIVACY-002). It provides an authorized
// tenant-scoped read over committed spool events, a pluggable Exporter interface
// (with deterministic test exporters — NO network SIEM client), a bounded worker
// Pump that drives export batches and advances an acknowledgment cursor, and the
// privacy guarantees:
//
//   - external export failure NEVER erases local durability (the spool retains the
//     record; the cursor only advances on a confirmed ack);
//   - a read is authorized and tenant-separated: a tenant read returns ONLY that
//     tenant's events, never another tenant's existence, count, range or content;
//   - unattributed denial aggregates (no tenant) stay in an unattributed scope and
//     are never returned to a tenant read;
//   - everything is bounded (workers, batch records/bytes, retries, range).
//
// This package adds no public HTTP API and reads no secret-bearing event form —
// every event it handles is already a safe envelope by construction.
package export

import (
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Reader is the spool-side committed-event source (implemented by *spool.Spool).
type Reader interface {
	CommittedForExport(part model.Partition, afterSeq uint64, maxRecords int) ([]model.Event, uint64, error)
	Capability() model.Capability
}

// Authorization is the trusted authorization context a read/export carries. It is
// supplied by an authenticated caller (a future Management API in PR-9), never by
// the requester's own claims. A read is refused unless the capability matches the
// reader, the partition is permitted, and the tenant scope is honored.
type Authorization struct {
	Tenant     string // "" denotes the unattributed security scope (denial aggregates)
	Capability model.Capability
	Partitions map[model.Partition]bool
	MaxRecords int
	MaxBytes   int
}

func expErr(r mcperr.Reason, detail string) error {
	return mcperr.New(r, "events.export", detail)
}

// validate bounds the authorization against the event limits.
func (a Authorization) validate(lim limits.EventLimits) error {
	if !a.Capability.Valid() {
		return expErr(mcperr.ReasonEventExportUnauthorized, "invalid capability")
	}
	if a.MaxRecords <= 0 || a.MaxRecords > lim.TenantExportMaxRecords() {
		return expErr(mcperr.ReasonEventExportRangeExceeded, "MaxRecords out of range")
	}
	if a.MaxBytes <= 0 || a.MaxBytes > lim.TenantExportMaxBytes() {
		return expErr(mcperr.ReasonEventExportRangeExceeded, "MaxBytes out of range")
	}
	return nil
}

// ReadResult is a bounded, tenant-scoped read.
type ReadResult struct {
	Events     []model.Event
	NextCursor uint64
	More       bool
}

// Read returns up to the authorized bound of a tenant's committed events from one
// partition, strictly after afterSeq. It enforces capability + partition scope and
// filters to the authorized tenant. Cross-tenant content is never returned: an
// event whose tenant differs from the authorization is dropped, and the
// unattributed (empty-tenant) denial aggregates are returned ONLY to the
// unattributed scope (Authorization.Tenant == "").
func Read(r Reader, lim limits.EventLimits, auth Authorization, part model.Partition, afterSeq uint64) (ReadResult, error) {
	if err := auth.validate(lim); err != nil {
		return ReadResult{}, err
	}
	if auth.Capability != r.Capability() {
		return ReadResult{}, expErr(mcperr.ReasonEventExportUnauthorized, "capability mismatch")
	}
	if !auth.Partitions[part] {
		return ReadResult{}, expErr(mcperr.ReasonEventExportUnauthorized, "partition not authorized")
	}
	// Read a bounded window and filter to the tenant scope. We over-read the raw
	// window (bounded by MaxRecords) and then filter, so a tenant only ever sees its
	// own events; the returned cursor advances past what was scanned so pagination
	// terminates, but the events themselves are tenant-isolated.
	raw, next, err := r.CommittedForExport(part, afterSeq, auth.MaxRecords)
	if err != nil {
		return ReadResult{}, err
	}
	res := ReadResult{NextCursor: next, More: len(raw) == auth.MaxRecords}
	var bytesUsed int
	for i := range raw {
		e := raw[i]
		if e.Capability != auth.Capability {
			continue
		}
		// Tenant isolation: an authorized tenant sees only its own events; the
		// unattributed scope (empty tenant) sees only unattributed events.
		if e.Identity.Tenant != auth.Tenant {
			continue
		}
		enc, merr := e.Marshal()
		if merr != nil {
			continue
		}
		if bytesUsed+len(enc) > auth.MaxBytes {
			res.More = true
			break
		}
		bytesUsed += len(enc)
		res.Events = append(res.Events, e)
	}
	return res, nil
}
