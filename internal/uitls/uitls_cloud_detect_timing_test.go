package uitls

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDetectCloudPublicIPs_NonAWSProbesRunConcurrently guards against a
// startup-latency regression: SelfSigned (called synchronously from
// startUI on every process start whenever no explicit -tls-cert/-tls-key is
// configured — the shipped docker-compose.yml default) calls
// detectCloudPublicIPs before it can bind the admin-UI listener. On a host
// where the cloud metadata address (169.254.169.254) is unreachable in a way
// that HANGS rather than fails fast — a common enterprise/air-gapped
// hardening posture that DROPs rather than REJECTs metadata traffic to deter
// SSRF — every candidate provider used to be tried one after another, each
// paying its own multi-second timeout, so the total delay grew with the
// number of providers instead of being capped by the slowest single one.
//
// This test simulates that "hangs, does not refuse" case for the GCP/Azure
// probes (the AWS probe always targets the real 169.254.169.254 address and,
// in this sandbox, fails fast — see queryAWSMetadata — so it does not
// interfere with the timing assertion below) and requires the total time to
// stay close to a SINGLE provider's timeout rather than the sum of both.
func TestDetectCloudPublicIPs_NonAWSProbesRunConcurrently(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Longer than queryMetadataEndpoint's own 2s per-request context
		// timeout, so the client — not this handler — decides when the
		// request gives up.
		time.Sleep(4 * time.Second)
	}))
	defer hang.Close()

	origEndpoints := cloudMetadataEndpoints
	cloudMetadataEndpoints = []cloudMetadataEndpoint{
		{name: "AWS"}, // index 0 is never dereferenced directly; queryAWSMetadata hardcodes its own URLs
		{name: "GCP", url: hang.URL},
		{name: "Azure", url: hang.URL},
	}
	defer func() { cloudMetadataEndpoints = origEndpoints }()

	start := time.Now()
	detectCloudPublicIPs()
	elapsed := time.Since(start)

	// Two probes run sequentially would sum to ~4s (2s timeout each); run
	// concurrently they cost at most ~2s regardless of how many providers
	// are unreachable. 3s leaves comfortable margin above the concurrent
	// case while still catching a regression back to sequential probing.
	if elapsed > 3*time.Second {
		t.Errorf("detectCloudPublicIPs took %s with 2 unreachable (hanging) non-AWS providers; "+
			"want the GCP/Azure probes to run concurrently (~2s total), not sum sequentially (~4s+) — "+
			"this blocks admin-UI startup on every restart when cloud metadata traffic is dropped rather than refused",
			elapsed)
	}
}
