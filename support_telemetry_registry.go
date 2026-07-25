package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
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
		Buckets:           supportmetrics.CAExpiryBucketLadder,
		Read:              readSupportHealthCAExpiryBucket,
	},
	{
		ID:                "support_uptime_bucket",
		Type:              supportmetrics.Gauge,
		PrivacyClass:      supportmetrics.Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		TelemetryReason:   "coarse stability signal; exact uptime rejected (fingerprint/correlation)",
		Buckets:           supportmetrics.UptimeBucketLadder,
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

// readSupportHealthConfigSnapshotValid reports "last config snapshot
// validated" (§7) as TWO conditions, both required: the pure validator
// itself accepts the empty baseline (configSnapshotValidatorOK — the same
// self-test computeReadiness's "config_snapshot_validator" row uses), AND
// the last REAL snapshot/delta apply this node actually attempted did not
// get rejected (lastConfigSnapshotApplyOK, configsnapshot_apply_health.go —
// set at the exact validate/apply call sites in controlplane_client.go).
// Without the second condition this bit could report healthy while a
// reachable CP kept pushing a snapshot this node rejects on every poll.
func readSupportHealthConfigSnapshotValid() float64 {
	if configSnapshotValidatorOK() && lastConfigSnapshotApplyOK() {
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

// supportTelemetryNow is the injectable clock buildSupportTelemetrySample
// uses. Tests swap it for a fixed clock so the preview handler and a
// directly-built sample can be proven to render identically (§8
// TestSupportTelemetryPreviewMatchesBuiltSample) without depending on
// wall-clock timing.
var supportTelemetryNow = time.Now

// supportTelemetryProcessEpoch is a 128-bit random hex token generated once,
// lazily, on first use per process lifetime — matching the merged design's
// sample_epoch semantics (§5: "128-bit random per process start/counter-
// reset epoch; lets TAC detect resets without an appliance id"). It is
// NEVER persisted and never derived from any appliance identity, so it
// carries no stable identity across restarts; it is deliberately STABLE
// within one process run so repeated preview calls (and, unchanged, a
// future sender within the same process) share the same epoch, exactly as
// the wire contract intends. Slice 1 has no delivery sequence counter yet
// (that belongs to Slice 3's sender/spool), so every sample built in this
// slice uses sequence 0 — honest, since there is no counter to advance.
var supportTelemetryProcessEpoch = sync.OnceValue(func() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read on a supported platform does not fail; a non-nil
		// err here indicates a broken entropy source, which the process
		// cannot recover from safely. Panicking (rather than silently
		// falling back to a zero/predictable epoch) matches the "fail
		// closed, never invent a fake identity token" posture.
		panic("supportmetrics: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
})

// buildSupportTelemetrySample constructs ONE immutable current support
// telemetry sample (roadmap/M7-proactive-telemetry-plan.md §3.3/§8) from the
// live registry. Side-effect-free: reads eligible descriptors' Read()
// closures only; no I/O, no goroutines, no persistence, no audit event.
func buildSupportTelemetrySample(now time.Time) (supportmetrics.Sample, error) {
	return supportMetricRegistry.BuildSample(now, supportTelemetryProcessEpoch(), 0)
}
