package supportmetrics

import "time"

// BucketLadder is a canonical, single-source-of-truth definition of a coarse
// bucket function: an ordered set of Labels (len N) and the ascending
// Thresholds (len N-1) that separate them. The SAME BucketLadder value is
// used both to EVALUATE a raw value (Index) and to CONTRIBUTE to
// registry_hash (via its canonical encoding in hash.go) — so changing a
// threshold or label is structurally impossible without also changing the
// hash; there is no second, separately-maintained copy of the boundaries to
// drift out of sync.
//
// Descending controls direction: false means higher raw values map to
// HIGHER bucket indices (e.g. uptime: longer uptime = a later/healthier
// bucket); true means higher raw values map to LOWER bucket indices (e.g.
// days-until-expiry: more days remaining = an earlier/healthier bucket).
type BucketLadder struct {
	Labels     []string  // len N; Labels[i] names bucket i
	Thresholds []float64 // len N-1, ascending
	Descending bool
}

// Index evaluates x against the ladder and returns its bucket index (as a
// float64, matching the Descriptor.Read signature). For a non-Descending
// ladder, Index is the count of thresholds x is >= to (an ascending step
// function). For a Descending ladder, Index is (N-1) minus the count of
// thresholds x is > (so a larger x — further from any threshold — lands in
// the lowest, "healthiest" bucket).
func (b *BucketLadder) Index(x float64) float64 {
	rank := 0
	for _, t := range b.Thresholds {
		if b.Descending {
			if x > t {
				rank++
			}
		} else if x >= t {
			rank++
		}
	}
	if b.Descending {
		return float64(len(b.Labels) - 1 - rank)
	}
	return float64(rank)
}

// CAExpiryBucketLadder is the canonical, hash-participating definition for
// support_health_ca_expiry_bucket (§7: ">90d/<=90/<=30/<=7"). Descending:
// MORE days remaining is healthier (bucket 0), FEWER (or negative — no
// usable cert) is more urgent (bucket 3).
var CAExpiryBucketLadder = &BucketLadder{
	Labels:     []string{"gt90d", "le90d", "le30d", "le7d"},
	Thresholds: []float64{7, 30, 90},
	Descending: true,
}

// CAExpiryBucket maps days-until-CA-expiry to the coarse bucket that avoids
// exposing a precise cert-timeline fingerprint. A negative daysUntilExpiry
// (no usable CA / already expired) maps to the most urgent bucket (le7d) —
// the CA is not merely "nearing" expiry, it is unusable, at least as urgent
// as the closest named boundary.
func CAExpiryBucket(daysUntilExpiry int) float64 {
	return CAExpiryBucketLadder.Index(float64(daysUntilExpiry))
}

// UptimeBucketLadder is the canonical, hash-participating definition for
// support_uptime_bucket (§7: "<1d/<7/<30/>=30"), expressed in days.
// Non-descending: longer uptime is a later (more stable) bucket.
var UptimeBucketLadder = &BucketLadder{
	Labels:     []string{"lt1d", "lt7d", "lt30d", "ge30d"},
	Thresholds: []float64{1, 7, 30},
	Descending: false,
}

// UptimeBucket maps a process uptime duration to the coarse restart-cadence
// bucket — a coarse stability signal; exact uptime is deliberately rejected
// (fingerprint/correlation risk).
func UptimeBucket(d time.Duration) float64 {
	return UptimeBucketLadder.Index(d.Hours() / 24)
}
