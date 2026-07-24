package supportmetrics

import "time"

// CAExpiryBucketLabels are the canonical, ordered bucket names for
// support_health_ca_expiry_bucket (§7): index == the value CAExpiryBucket
// returns. They participate in Registry.Hash via Descriptor.Buckets, so a
// change to the boundaries themselves is a governed schema change.
var CAExpiryBucketLabels = []string{"gt90d", "le90d", "le30d", "le7d"}

// CAExpiryBucket maps days-until-CA-expiry to the coarse bucket (§7:
// ">90d/<=90/<=30/<=7") that avoids exposing a precise cert-timeline
// fingerprint. A negative daysUntilExpiry (no usable CA / already expired)
// maps to the most urgent bucket (le7d) — the CA is not merely "nearing"
// expiry, it is unusable, which is at least as urgent as the closest named
// boundary.
func CAExpiryBucket(daysUntilExpiry int) float64 {
	switch {
	case daysUntilExpiry > 90:
		return 0 // gt90d
	case daysUntilExpiry > 30:
		return 1 // le90d
	case daysUntilExpiry > 7:
		return 2 // le30d
	default:
		return 3 // le7d (includes negative/expired/no-cert)
	}
}

// UptimeBucketLabels are the canonical, ordered bucket names for
// support_uptime_bucket (§7): index == the value UptimeBucket returns.
var UptimeBucketLabels = []string{"lt1d", "lt7d", "lt30d", "ge30d"}

// UptimeBucket maps a process uptime duration to the coarse restart-cadence
// bucket (§7: "<1d/<7/<30/>=30") — a coarse stability signal; exact uptime is
// deliberately rejected (fingerprint/correlation risk).
func UptimeBucket(d time.Duration) float64 {
	switch {
	case d < 24*time.Hour:
		return 0 // lt1d
	case d < 7*24*time.Hour:
		return 1 // lt7d
	case d < 30*24*time.Hour:
		return 2 // lt30d
	default:
		return 3 // ge30d
	}
}
