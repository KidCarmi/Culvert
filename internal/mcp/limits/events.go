package limits

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// EventLimits is the immutable, validated bound set for the PR-8 durable
// decision-event pipeline (bounded queues, the local encrypted spool with its
// three partitions P-CRIT/P-ORD/P-DEN, recovery/reclamation work, denial
// coalescing, the degraded-state recovery watermarks, and the tenant-scoped
// export foundation). It mirrors the Limits / InspectionLimits pattern exactly
// (unexported Config read through accessors, a single Validate gate, hard-cap
// ceilings, no mutable singleton).
//
// Gateway and Management carry INDEPENDENT event limit sets: one capability's
// bound never affects the other (capability isolation, asserted by tests). The
// spool is attacker-adjacent — a peer can drive request rate, denial rate,
// output size and reconnect churn — so every quantity is bounded here, and
// construction fails closed on any zero, negative, inconsistent, or over-ceiling
// value. There is NO per-event goroutine and NO unbounded queue: these bounds
// cap concurrent and per-pass work.
//
// The three load-bearing capacity invariants (checked in Validate) are:
//   - CriticalReserveBytes > 0 and < SpoolMaxBytes (an unreachable-exit-free
//     reserve; a zero reserve would make critical durability unprotectable);
//   - DenialQuotaBytes <= SpoolMaxBytes - CriticalReserveBytes and
//     OrdinaryQuotaBytes <= SpoolMaxBytes - CriticalReserveBytes, so neither the
//     denial lane nor ordinary traffic can PROVABLY overlap the critical reserve;
//   - the recovery watermark (ReserveRecoveryPct) is a fraction OF THE RESERVE,
//     never of the spool, with 0 < ReserveRecoveryPct <= 100, so every accepted
//     configuration has a reachable critical-durability-degraded exit.

// Hard-cap ceilings for the event surface. An EventConfig value above its
// ceiling fails validation regardless of how a caller configures the defaults.
const (
	capEvtSpoolMaxBytes     = 4 << 30 // 4 GiB — one capability's whole spool
	capEvtCriticalReserve   = 2 << 30 // 2 GiB — reserved critical capacity
	capEvtOrdinaryQuota     = 4 << 30
	capEvtDenialQuota       = 2 << 30
	capEvtSegmentBytes      = 256 << 20 // 256 MiB — one segment file
	capEvtEventBytes        = 1 << 20   // 1 MiB — one encoded event
	capEvtMetadataBytes     = 1 << 20   // 1 MiB — one integrity-protected state file
	capEvtSafeResultBytes   = 4 << 20   // 4 MiB — one sanitized export/read result
	capEvtSegments          = 1 << 16   // segments per partition
	capEvtQueuePerPartition = 1 << 20   // queued events per partition
	capEvtInFlightCommits   = 4096      // concurrent in-flight commits
	capEvtCommitBatch       = 4096      // events per commit batch
	capEvtSyncOps           = 1024      // concurrent sync operations
	capEvtDenialBuckets     = 1 << 20   // active denial-aggregation buckets
	capEvtBucketsPerSource  = 4096      // buckets attributable to one source
	capEvtCoalescePerAgg    = 1 << 30   // coalesced count an aggregate may track
	capEvtRecoveryScanBytes = 8 << 30   // bytes a bounded recovery scan may read
	capEvtRecoverySegments  = 1 << 16   // segments a bounded recovery may scan
	capEvtRecoveryRecords   = 1 << 24   // records a bounded recovery may replay
	capEvtReclaimPerPass    = 1 << 16   // records reclaimed in one pass
	capEvtExporterWorkers   = 256       // bounded exporter workers
	capEvtExportBatchRecs   = 1 << 16   // records per export batch
	capEvtExportBatchBytes  = 256 << 20 // bytes per export batch
	capEvtExportRetries     = 64        // bounded export retries
	capEvtReplayWindow      = 1 << 20   // replay-dedup window entries
	capEvtTenantExportRecs  = 1 << 20   // records one tenant export may return
	capEvtTenantExportBytes = 512 << 20 // bytes one tenant export may return

	capEvtAggregationWindow = time.Hour // denial-aggregation window
	capEvtRetentionWindow   = 365 * 24 * time.Hour
	capEvtProbeInterval     = time.Hour        // durability-recovery probe interval
	capEvtCommitBatchDelay  = 10 * time.Second // commit-batch coalescing delay
	capEvtShutdownDrain     = time.Minute      // bounded shutdown drain
)

// EventConfig is the mutable input to NewEvent. A zero EventConfig is invalid;
// every field must be set. Percentages are whole-number percents. The loss
// policy, rotation policy, spool path, export target and redaction-profile
// reference are NOT numeric bounds and live on the events package runtime
// config, not here.
type EventConfig struct {
	// Spool capacity (bytes).
	SpoolMaxBytes        int // total bounded spool size for one capability
	CriticalReserveBytes int // P-CRIT reserved capacity (never consumed by P-ORD/P-DEN)
	OrdinaryQuotaBytes   int // P-ORD quota (shares the non-reserved remainder)
	DenialQuotaBytes     int // P-DEN quota (own, cannot overlap the reserve)
	SegmentMaxBytes      int // max bytes of one segment file
	MaxEventBytes        int // max bytes of one encoded event
	MaxMetadataBytes     int // max bytes of one integrity-protected state file
	MaxSafeResultBytes   int // max bytes of one sanitized export/read result

	// Counts and concurrency.
	MaxSegments             int // max segments per partition
	MaxQueuePerPartition    int // max queued events per partition (bounded queue)
	MaxInFlightCommits      int // max concurrent in-flight commits
	CommitBatchSize         int // max events grouped into one commit batch
	MaxSyncOps              int // max concurrent sync operations
	MaxDenialBuckets        int // max active denial-aggregation buckets
	MaxBucketsPerSource     int // max buckets attributable to one source
	MaxCoalescePerAggregate int // max coalesced count one aggregate may track
	MaxRecoveryScanBytes    int // max bytes a bounded recovery scan may read
	MaxRecoverySegments     int // max segments a bounded recovery may scan
	MaxRecoveryRecords      int // max records a bounded recovery may replay
	MaxReclaimPerPass       int // max records reclaimed in one reclamation pass
	ExporterWorkers         int // bounded exporter worker count
	ExportBatchRecords      int // max records per export batch
	ExportBatchBytes        int // max bytes per export batch
	ExportMaxRetries        int // bounded export retries
	ReplayWindowEntries     int // replay-dedup window entries retained
	TenantExportMaxRecords  int // max records one tenant export may return
	TenantExportMaxBytes    int // max bytes one tenant export may return

	// Watermarks (whole-number percents).
	HighWatermarkPct   int // reclamation trigger, percent of SpoolMaxBytes (1..99)
	LowWatermarkPct    int // reclamation target, percent of SpoolMaxBytes (< high)
	ReserveRecoveryPct int // recovery watermark, percent OF CriticalReserveBytes (1..100)

	// Durations.
	AggregationWindow time.Duration // bounded denial-aggregation window
	RetentionWindow   time.Duration // bounded retention window
	ProbeInterval     time.Duration // durability-recovery probe interval
	CommitBatchDelay  time.Duration // commit-batch coalescing delay
	ShutdownDrain     time.Duration // bounded shutdown drain
}

// EventLimits is an immutable, validated event bound set.
type EventLimits struct{ c EventConfig }

// SpoolMaxBytes returns the total bounded spool size.
func (l EventLimits) SpoolMaxBytes() int { return l.c.SpoolMaxBytes }

// CriticalReserveBytes returns the P-CRIT reserved capacity.
func (l EventLimits) CriticalReserveBytes() int { return l.c.CriticalReserveBytes }

// OrdinaryQuotaBytes returns the P-ORD quota.
func (l EventLimits) OrdinaryQuotaBytes() int { return l.c.OrdinaryQuotaBytes }

// DenialQuotaBytes returns the P-DEN quota.
func (l EventLimits) DenialQuotaBytes() int { return l.c.DenialQuotaBytes }

// SegmentMaxBytes returns the max bytes of one segment file.
func (l EventLimits) SegmentMaxBytes() int { return l.c.SegmentMaxBytes }

// MaxEventBytes returns the max bytes of one encoded event.
func (l EventLimits) MaxEventBytes() int { return l.c.MaxEventBytes }

// MaxMetadataBytes returns the max bytes of one integrity-protected state file.
func (l EventLimits) MaxMetadataBytes() int { return l.c.MaxMetadataBytes }

// MaxSafeResultBytes returns the max bytes of one sanitized export/read result.
func (l EventLimits) MaxSafeResultBytes() int { return l.c.MaxSafeResultBytes }

// MaxSegments returns the max segments per partition.
func (l EventLimits) MaxSegments() int { return l.c.MaxSegments }

// MaxQueuePerPartition returns the max queued events per partition.
func (l EventLimits) MaxQueuePerPartition() int { return l.c.MaxQueuePerPartition }

// MaxInFlightCommits returns the max concurrent in-flight commits.
func (l EventLimits) MaxInFlightCommits() int { return l.c.MaxInFlightCommits }

// CommitBatchSize returns the max events grouped into one commit batch.
func (l EventLimits) CommitBatchSize() int { return l.c.CommitBatchSize }

// MaxSyncOps returns the max concurrent sync operations.
func (l EventLimits) MaxSyncOps() int { return l.c.MaxSyncOps }

// MaxDenialBuckets returns the max active denial-aggregation buckets.
func (l EventLimits) MaxDenialBuckets() int { return l.c.MaxDenialBuckets }

// MaxBucketsPerSource returns the max buckets attributable to one source.
func (l EventLimits) MaxBucketsPerSource() int { return l.c.MaxBucketsPerSource }

// MaxCoalescePerAggregate returns the max coalesced count one aggregate may track.
func (l EventLimits) MaxCoalescePerAggregate() int { return l.c.MaxCoalescePerAggregate }

// MaxRecoveryScanBytes returns the max bytes a bounded recovery scan may read.
func (l EventLimits) MaxRecoveryScanBytes() int { return l.c.MaxRecoveryScanBytes }

// MaxRecoverySegments returns the max segments a bounded recovery may scan.
func (l EventLimits) MaxRecoverySegments() int { return l.c.MaxRecoverySegments }

// MaxRecoveryRecords returns the max records a bounded recovery may replay.
func (l EventLimits) MaxRecoveryRecords() int { return l.c.MaxRecoveryRecords }

// MaxReclaimPerPass returns the max records reclaimed in one reclamation pass.
func (l EventLimits) MaxReclaimPerPass() int { return l.c.MaxReclaimPerPass }

// ExporterWorkers returns the bounded exporter worker count.
func (l EventLimits) ExporterWorkers() int { return l.c.ExporterWorkers }

// ExportBatchRecords returns the max records per export batch.
func (l EventLimits) ExportBatchRecords() int { return l.c.ExportBatchRecords }

// ExportBatchBytes returns the max bytes per export batch.
func (l EventLimits) ExportBatchBytes() int { return l.c.ExportBatchBytes }

// ExportMaxRetries returns the bounded export retries.
func (l EventLimits) ExportMaxRetries() int { return l.c.ExportMaxRetries }

// ReplayWindowEntries returns the replay-dedup window entries retained.
func (l EventLimits) ReplayWindowEntries() int { return l.c.ReplayWindowEntries }

// TenantExportMaxRecords returns the max records one tenant export may return.
func (l EventLimits) TenantExportMaxRecords() int { return l.c.TenantExportMaxRecords }

// TenantExportMaxBytes returns the max bytes one tenant export may return.
func (l EventLimits) TenantExportMaxBytes() int { return l.c.TenantExportMaxBytes }

// HighWatermarkPct returns the reclamation-trigger watermark (percent of spool).
func (l EventLimits) HighWatermarkPct() int { return l.c.HighWatermarkPct }

// LowWatermarkPct returns the reclamation-target watermark (percent of spool).
func (l EventLimits) LowWatermarkPct() int { return l.c.LowWatermarkPct }

// ReserveRecoveryPct returns the recovery watermark (percent OF the reserve).
func (l EventLimits) ReserveRecoveryPct() int { return l.c.ReserveRecoveryPct }

// AggregationWindow returns the bounded denial-aggregation window.
func (l EventLimits) AggregationWindow() time.Duration { return l.c.AggregationWindow }

// RetentionWindow returns the bounded retention window.
func (l EventLimits) RetentionWindow() time.Duration { return l.c.RetentionWindow }

// ProbeInterval returns the durability-recovery probe interval.
func (l EventLimits) ProbeInterval() time.Duration { return l.c.ProbeInterval }

// CommitBatchDelay returns the commit-batch coalescing delay.
func (l EventLimits) CommitBatchDelay() time.Duration { return l.c.CommitBatchDelay }

// ShutdownDrain returns the bounded shutdown drain.
func (l EventLimits) ShutdownDrain() time.Duration { return l.c.ShutdownDrain }

// HighWatermarkBytes returns the reclamation-trigger threshold in bytes.
func (l EventLimits) HighWatermarkBytes() int { return l.c.SpoolMaxBytes / 100 * l.c.HighWatermarkPct }

// LowWatermarkBytes returns the reclamation-target threshold in bytes.
func (l EventLimits) LowWatermarkBytes() int { return l.c.SpoolMaxBytes / 100 * l.c.LowWatermarkPct }

// ReserveRecoveryBytes returns criterion (2)'s free-byte threshold: a fraction
// of the CRITICAL RESERVE (never of the spool), so every accepted config has a
// reachable critical-durability-degraded exit.
func (l EventLimits) ReserveRecoveryBytes() int {
	return l.c.CriticalReserveBytes / 100 * l.c.ReserveRecoveryPct
}

// PendingBacklogBytes returns criterion (4)'s derived in-process backlog bound:
// (100 - reserve_recovery) percent of the reserve. It is DERIVED, never
// separately configured, so (2) and (4) can never be set to contradict.
func (l EventLimits) PendingBacklogBytes() int {
	return l.c.CriticalReserveBytes / 100 * (100 - l.c.ReserveRecoveryPct)
}

func evtLimitErr(detail string) error {
	return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", detail)
}

// Validate reports whether the EventConfig is safe and internally consistent.
// Zero, negative, over-cap, or inconsistent limits are rejected.
func (c EventConfig) Validate() error { //nolint:gocyclo,cyclop,funlen // a flat table of independent bound checks + consistency invariants
	posCaps := []struct {
		name string
		v    int
		cap  int
	}{
		{"SpoolMaxBytes", c.SpoolMaxBytes, capEvtSpoolMaxBytes},
		{"CriticalReserveBytes", c.CriticalReserveBytes, capEvtCriticalReserve},
		{"OrdinaryQuotaBytes", c.OrdinaryQuotaBytes, capEvtOrdinaryQuota},
		{"DenialQuotaBytes", c.DenialQuotaBytes, capEvtDenialQuota},
		{"SegmentMaxBytes", c.SegmentMaxBytes, capEvtSegmentBytes},
		{"MaxEventBytes", c.MaxEventBytes, capEvtEventBytes},
		{"MaxMetadataBytes", c.MaxMetadataBytes, capEvtMetadataBytes},
		{"MaxSafeResultBytes", c.MaxSafeResultBytes, capEvtSafeResultBytes},
		{"MaxSegments", c.MaxSegments, capEvtSegments},
		{"MaxQueuePerPartition", c.MaxQueuePerPartition, capEvtQueuePerPartition},
		{"MaxInFlightCommits", c.MaxInFlightCommits, capEvtInFlightCommits},
		{"CommitBatchSize", c.CommitBatchSize, capEvtCommitBatch},
		{"MaxSyncOps", c.MaxSyncOps, capEvtSyncOps},
		{"MaxDenialBuckets", c.MaxDenialBuckets, capEvtDenialBuckets},
		{"MaxBucketsPerSource", c.MaxBucketsPerSource, capEvtBucketsPerSource},
		{"MaxCoalescePerAggregate", c.MaxCoalescePerAggregate, capEvtCoalescePerAgg},
		{"MaxRecoveryScanBytes", c.MaxRecoveryScanBytes, capEvtRecoveryScanBytes},
		{"MaxRecoverySegments", c.MaxRecoverySegments, capEvtRecoverySegments},
		{"MaxRecoveryRecords", c.MaxRecoveryRecords, capEvtRecoveryRecords},
		{"MaxReclaimPerPass", c.MaxReclaimPerPass, capEvtReclaimPerPass},
		{"ExporterWorkers", c.ExporterWorkers, capEvtExporterWorkers},
		{"ExportBatchRecords", c.ExportBatchRecords, capEvtExportBatchRecs},
		{"ExportBatchBytes", c.ExportBatchBytes, capEvtExportBatchBytes},
		{"ExportMaxRetries", c.ExportMaxRetries, capEvtExportRetries},
		{"ReplayWindowEntries", c.ReplayWindowEntries, capEvtReplayWindow},
		{"TenantExportMaxRecords", c.TenantExportMaxRecords, capEvtTenantExportRecs},
		{"TenantExportMaxBytes", c.TenantExportMaxBytes, capEvtTenantExportBytes},
	}
	for _, p := range posCaps {
		if p.v <= 0 {
			return evtLimitErr(p.name + " must be positive")
		}
		if p.v > p.cap {
			return evtLimitErr(p.name + " exceeds its hard-cap ceiling")
		}
	}
	durCaps := []struct {
		name string
		v    time.Duration
		cap  time.Duration
	}{
		{"AggregationWindow", c.AggregationWindow, capEvtAggregationWindow},
		{"RetentionWindow", c.RetentionWindow, capEvtRetentionWindow},
		{"ProbeInterval", c.ProbeInterval, capEvtProbeInterval},
		{"CommitBatchDelay", c.CommitBatchDelay, capEvtCommitBatchDelay},
		{"ShutdownDrain", c.ShutdownDrain, capEvtShutdownDrain},
	}
	for _, p := range durCaps {
		if p.v <= 0 {
			return evtLimitErr(p.name + " must be positive")
		}
		if p.v > p.cap {
			return evtLimitErr(p.name + " exceeds its hard-cap ceiling")
		}
	}
	// Watermark percents.
	if c.HighWatermarkPct <= 0 || c.HighWatermarkPct >= 100 {
		return evtLimitErr("HighWatermarkPct must satisfy 0 < high < 100")
	}
	if c.LowWatermarkPct <= 0 || c.LowWatermarkPct >= c.HighWatermarkPct {
		return evtLimitErr("LowWatermarkPct must satisfy 0 < low < high")
	}
	if c.ReserveRecoveryPct <= 0 || c.ReserveRecoveryPct > 100 {
		return evtLimitErr("ReserveRecoveryPct must satisfy 0 < reserve_recovery <= 100 (fraction OF THE RESERVE)")
	}
	// Load-bearing capacity invariants.
	if c.CriticalReserveBytes >= c.SpoolMaxBytes {
		return evtLimitErr("CriticalReserveBytes must be < SpoolMaxBytes")
	}
	nonReserved := c.SpoolMaxBytes - c.CriticalReserveBytes
	if c.DenialQuotaBytes > nonReserved {
		return evtLimitErr("DenialQuotaBytes cannot overlap the critical reserve (must be <= SpoolMaxBytes - CriticalReserveBytes)")
	}
	if c.OrdinaryQuotaBytes > nonReserved {
		return evtLimitErr("OrdinaryQuotaBytes cannot overlap the critical reserve (must be <= SpoolMaxBytes - CriticalReserveBytes)")
	}
	// The SUM of the non-critical quotas must fit in the non-reserved remainder,
	// so P-ORD and P-DEN together can NEVER hold more than SpoolMaxBytes - reserve
	// — the reserve is then always physically available to P-CRIT.
	if c.OrdinaryQuotaBytes+c.DenialQuotaBytes > nonReserved {
		return evtLimitErr("OrdinaryQuotaBytes + DenialQuotaBytes cannot exceed SpoolMaxBytes - CriticalReserveBytes (the reserve must stay available to P-CRIT)")
	}
	// A segment must fit inside every partition's applicable quota, else that
	// partition could never seal even one segment.
	if c.SegmentMaxBytes > c.CriticalReserveBytes {
		return evtLimitErr("SegmentMaxBytes cannot exceed CriticalReserveBytes")
	}
	if c.SegmentMaxBytes > c.DenialQuotaBytes {
		return evtLimitErr("SegmentMaxBytes cannot exceed DenialQuotaBytes")
	}
	if c.SegmentMaxBytes > c.OrdinaryQuotaBytes {
		return evtLimitErr("SegmentMaxBytes cannot exceed OrdinaryQuotaBytes")
	}
	// One maximum event (plus room for record framing) must fit inside a segment.
	if c.MaxEventBytes >= c.SegmentMaxBytes {
		return evtLimitErr("MaxEventBytes must be < SegmentMaxBytes (one event must fit in a segment)")
	}
	// A safe export result can never exceed a whole tenant export budget.
	if c.MaxSafeResultBytes > c.TenantExportMaxBytes {
		return evtLimitErr("MaxSafeResultBytes cannot exceed TenantExportMaxBytes")
	}
	// A commit batch can never exceed the queue it drains.
	if c.CommitBatchSize > c.MaxQueuePerPartition {
		return evtLimitErr("CommitBatchSize cannot exceed MaxQueuePerPartition")
	}
	// An export batch can never exceed a tenant export budget.
	if c.ExportBatchRecords > c.TenantExportMaxRecords {
		return evtLimitErr("ExportBatchRecords cannot exceed TenantExportMaxRecords")
	}
	if c.ExportBatchBytes > c.TenantExportMaxBytes {
		return evtLimitErr("ExportBatchBytes cannot exceed TenantExportMaxBytes")
	}
	return nil
}

// NewEvent validates c and returns an immutable EventLimits, or an error.
func NewEvent(c EventConfig) (EventLimits, error) {
	if err := c.Validate(); err != nil {
		return EventLimits{}, err
	}
	return EventLimits{c: c}, nil
}

// gatewayEventConfig is the conservative safe-default for the Gateway event
// surface (business tool traffic — the higher-throughput surface).
var gatewayEventConfig = EventConfig{
	SpoolMaxBytes:           512 << 20,
	CriticalReserveBytes:    128 << 20,
	OrdinaryQuotaBytes:      256 << 20,
	DenialQuotaBytes:        64 << 20,
	SegmentMaxBytes:         16 << 20,
	MaxEventBytes:           64 << 10,
	MaxMetadataBytes:        64 << 10,
	MaxSafeResultBytes:      1 << 20,
	MaxSegments:             4096,
	MaxQueuePerPartition:    8192,
	MaxInFlightCommits:      256,
	CommitBatchSize:         256,
	MaxSyncOps:              64,
	MaxDenialBuckets:        65536,
	MaxBucketsPerSource:     256,
	MaxCoalescePerAggregate: 1 << 24,
	MaxRecoveryScanBytes:    512 << 20,
	MaxRecoverySegments:     4096,
	MaxRecoveryRecords:      1 << 20,
	MaxReclaimPerPass:       1024,
	ExporterWorkers:         4,
	ExportBatchRecords:      1024,
	ExportBatchBytes:        4 << 20,
	ExportMaxRetries:        8,
	ReplayWindowEntries:     65536,
	TenantExportMaxRecords:  65536,
	TenantExportMaxBytes:    64 << 20,
	HighWatermarkPct:        85,
	LowWatermarkPct:         70,
	ReserveRecoveryPct:      50,
	AggregationWindow:       10 * time.Second,
	RetentionWindow:         90 * 24 * time.Hour,
	ProbeInterval:           5 * time.Second,
	CommitBatchDelay:        50 * time.Millisecond,
	ShutdownDrain:           10 * time.Second,
}

// managementEventConfig is the conservative safe-default for the Management event
// surface — deliberately tighter and INDEPENDENT of the Gateway set. Management
// carries configuration payloads (the higher-privilege stream) at far lower
// volume, so its spool and queues are smaller while its reserve share is larger.
//
//nolint:dupl // Gateway and Management default sets are intentionally parallel literals (independent tunables)
var managementEventConfig = EventConfig{
	SpoolMaxBytes:           128 << 20,
	CriticalReserveBytes:    48 << 20,
	OrdinaryQuotaBytes:      48 << 20,
	DenialQuotaBytes:        16 << 20,
	SegmentMaxBytes:         8 << 20,
	MaxEventBytes:           64 << 10,
	MaxMetadataBytes:        64 << 10,
	MaxSafeResultBytes:      512 << 10,
	MaxSegments:             2048,
	MaxQueuePerPartition:    4096,
	MaxInFlightCommits:      128,
	CommitBatchSize:         128,
	MaxSyncOps:              32,
	MaxDenialBuckets:        16384,
	MaxBucketsPerSource:     128,
	MaxCoalescePerAggregate: 1 << 24,
	MaxRecoveryScanBytes:    128 << 20,
	MaxRecoverySegments:     2048,
	MaxRecoveryRecords:      1 << 19,
	MaxReclaimPerPass:       512,
	ExporterWorkers:         2,
	ExportBatchRecords:      512,
	ExportBatchBytes:        2 << 20,
	ExportMaxRetries:        8,
	ReplayWindowEntries:     32768,
	TenantExportMaxRecords:  32768,
	TenantExportMaxBytes:    32 << 20,
	HighWatermarkPct:        85,
	LowWatermarkPct:         70,
	ReserveRecoveryPct:      50,
	AggregationWindow:       10 * time.Second,
	RetentionWindow:         180 * 24 * time.Hour,
	ProbeInterval:           5 * time.Second,
	CommitBatchDelay:        50 * time.Millisecond,
	ShutdownDrain:           10 * time.Second,
}

// DefaultGatewayEvent returns the validated Gateway event default bounds.
func DefaultGatewayEvent() EventLimits {
	l, err := NewEvent(gatewayEventConfig)
	if err != nil {
		panic("mcp/limits: gateway event default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}

// DefaultManagementEvent returns the validated Management event default bounds.
func DefaultManagementEvent() EventLimits {
	l, err := NewEvent(managementEventConfig)
	if err != nil {
		panic("mcp/limits: management event default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}
