package main

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/supportmetrics"
)

// supportMetricRegistry is the M7 scoped support-metric registry
// (roadmap/M7-proactive-telemetry-plan.md §6/§7). It governs ONLY the
// support-health scalar set shared by support-bundle evidence, the telemetry
// preview (this slice), and the future telemetry sender (Slice 3) — it is
// NOT a canonical mirror of every culvert_* Prometheus/OTLP metric, and it
// must never grow to include exact traffic/scale/policy/detection/security-
// posture values. Every entry below is exactly one row of the merged
// design's §7 initial eligibility table; there is no ineligible entry in
// this slice because the table's rejected metrics (culvert_requests_total,
// culvert_blocklist_size, etc.) are existing Prometheus/OTLP metrics
// entirely OUT OF this registry's scope, not descriptors that belong here
// with TelemetryEligible=false.
//
// Immutable after package init: nothing in this file, or anywhere else,
// mutates supportMetricRegistry or its descriptors at runtime. Each Read
// closure below reads ONLY the appliance's own subsystem-health state — never
// request logs, top-host stores, policy-rule content, usernames, URLs, IPs,
// hostnames, or tenant identifiers.
var supportMetricRegistry = supportmetrics.Registry{
	{
		ID:                "support_health_ca_ready",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "appliance's own health; the point of proactive support; no customer data",
		Read:              readSupportHealthCAReady,
	},
	{
		ID:                "support_health_clamav_ready",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "own health; not detection activity",
		Read:              readSupportHealthClamAVReady,
	},
	{
		ID:                "support_health_yara_ready",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "own health",
		Read:              readSupportHealthYARAReady,
	},
	{
		ID:                "support_health_policy_loaded",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "own health; not policy content/size",
		Read:              readSupportHealthPolicyLoaded,
	},
	{
		ID:                "support_health_session_ready",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "own health; no secret material",
		Read:              readSupportHealthSessionReady,
	},
	{
		ID:                "support_health_config_snapshot_valid",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "own health; not config content",
		Read:              readSupportHealthConfigSnapshotValid,
	},
	{
		ID:                "support_health_ca_expiry_bucket",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "proactive renewal signal; bucketed to avoid a precise cert-timeline fingerprint",
		Buckets:           supportmetrics.CAExpiryBucketLabels,
		Read:              readSupportHealthCAExpiryBucket,
	},
	{
		ID:                "support_uptime_bucket",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "coarse stability signal; exact uptime rejected (fingerprint/correlation)",
		Buckets:           supportmetrics.UptimeBucketLabels,
		Read:              readSupportUptimeBucket,
	},
}

// readSupportHealthCAReady mirrors computeReadiness's "ca" check
// (healthcheck.go): a CA that was configured but failed to load/persist
// (sslInspectionLoadFailure) is NOT ready, even though certMgr.Ready() can
// still report true in that window (CHAOS-06) — the SSL-inspect path is
// effectively degraded (tunnel-only bypass), and this telemetry bit must
// reflect that instead of a stale "usable" signal.
func readSupportHealthCAReady() float64 {
	if sslInspectionLoadFailure() != "" {
		return 0
	}
	if certMgr.Ready() {
		return 1
	}
	return 0
}

func readSupportHealthClamAVReady() float64 {
	if globalSecScanner != nil && globalSecScanner.ClamAVStatus() == "connected" {
		return 1
	}
	return 0
}

func readSupportHealthYARAReady() float64 {
	if globalYARA.Enabled() {
		return 1
	}
	return 0
}

func readSupportHealthPolicyLoaded() float64 {
	if ver, _ := policyStore.policyVersion(); ver > 0 {
		return 1
	}
	return 0
}

func readSupportHealthSessionReady() float64 {
	if sessionSecretSet() {
		return 1
	}
	return 0
}

func readSupportHealthConfigSnapshotValid() float64 {
	if configSnapshotValidatorOK() {
		return 1
	}
	return 0
}

// readSupportHealthCAExpiryBucket keeps the same posture as
// readSupportHealthCAReady: a recorded SSL-inspect load failure is at least
// as urgent as an imminently-expiring cert, so it reports the most urgent
// bucket rather than a possibly-stale expiry computed from a CA that never
// actually persisted.
func readSupportHealthCAExpiryBucket() float64 {
	if sslInspectionLoadFailure() != "" {
		return supportmetrics.CAExpiryBucket(-1)
	}
	return supportmetrics.CAExpiryBucket(caExpiryDaysRemaining())
}

func readSupportUptimeBucket() float64 {
	return supportmetrics.UptimeBucket(time.Since(startTime))
}

// supportTelemetryNow is the injectable clock BuildSupportTelemetrySample
// uses. Tests swap it for a fixed clock so the preview handler and a
// directly-built sample can be proven to render identically (§8
// TestSupportTelemetryPreviewMatchesBuiltSample) without depending on
// wall-clock timing.
var supportTelemetryNow = time.Now

// buildSupportTelemetrySample constructs ONE immutable current support
// telemetry sample (roadmap/M7-proactive-telemetry-plan.md §3.3/§8) from the
// live registry. Side-effect-free: reads eligible descriptors' Read()
// closures only; no I/O, no goroutines, no persistence, no audit event.
//
// Slice 1 scope: unlike the merged design's illustrative
// buildSupportTelemetrySample(now, epoch, sequence) signature, this builder
// takes no epoch/sequence — those are Slice 3 delivery-retry state (§5) with
// no sender to consume them yet; adding placeholder values here would be
// invented behavior, not implemented behavior. Slice 3 extends the sample
// shape when it adds the sender/spool, without changing this function's
// existing contract.
func buildSupportTelemetrySample(now time.Time) (supportmetrics.Sample, error) {
	return supportMetricRegistry.BuildSample(now)
}
