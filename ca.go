package main

// ca.go — CA shim: aliases + singleton + auto-rotation loop over internal/ca
// (ADR-0002). The MITM trust engine — Root CA lifecycle, the FROZEN encrypted
// bundle codec (caMagic/PBKDF2-600k/AES-GCM), leaf signing + LRU/TTL cache,
// dual-CA rotation, KeyProvider — lives in the package. main keeps the process
// singleton (certMgr), the runtime bundle path/passphrase (caRuntime), the
// auto-rotation LOOP (which also drives the separate cluster CA), and wires
// the package's observability hooks to the Prometheus histogram + alert store
// + rotation counter.

import (
	"context"
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

type (
	// CertManager is the SSL-inspection Root CA manager.
	CertManager = ca.Manager
	// KeyProvider abstracts CA private-key signing (local / HSM / KMS).
	KeyProvider = ca.KeyProvider
)

// certMgr is the process-wide inspection CA.
var certMgr = ca.New()

// caRuntime holds the CA bundle path and passphrase for runtime operations
// (rotation, re-persist) after startup initialisation.
var caRuntime struct {
	path       string
	passphrase string
}

// init wires the engine's publish-once observability hooks to main's metrics
// and alerting. Runs in tests too, so a direct certMgr.RotateIfNeeded still
// bumps culvert_ca_rotations_total (the pre-extraction contract) and a leaf
// sign still records its latency histogram sample.
func init() {
	ca.SignLatencyObserver = func(seconds float64) {
		certSignHist.Observe(seconds)
	}
	ca.RotationObserver = func(oldExpiry, newExpiry time.Time) {
		fireAlert("cert_expiry", AlertPayload{
			Host: "culvert-ca",
			Detail: fmt.Sprintf("Root CA rotated — old CA valid until %s, new CA expires %s (dual-CA overlap active)",
				oldExpiry.Format("2006-01-02"), newExpiry.Format("2006-01-02")),
			Source: "ca",
		})
		statCARotations.Add(1)
	}
	// End the client-facing TLS resumption epoch whenever the Root CA changes,
	// so no client can resume a session authenticated under the previous CA.
	ca.CAChangedObserver = rotateMITMTicketKeys
}

// StartCAAutoRotation runs a background goroutine that periodically checks CA
// certificate expiry and triggers rotation when needed — for BOTH the
// inspection CA (internal/ca) and the cluster CA (enrollment.go). The loop
// lives here, not in the package, because it spans both CAs.
func StartCAAutoRotation(ctx context.Context, caPath, passphrase string) {
	go func() {
		t := time.NewTicker(ca.RotationCheckInterval)
		defer t.Stop()
		// CHAOS-28 / CA-4: check IMMEDIATELY, before the first tick. The loop
		// used to wait a full RotationCheckInterval (24h) after boot, which put
		// a 24-hour blind spot in front of the one recovery path this failure
		// has. It is reached exactly when it matters most — an appliance that
		// was powered off through its rotation window, or restarted to recover
		// from the expiry outage itself, would sit there for another day doing
		// nothing while every inspected HTTPS request failed. RotateIfNeeded is
		// a no-op outside the 30-day window, so on a healthy node this costs one
		// expiry comparison at startup.
		checkRound := func() {
			// Each CA is guarded separately so a fault in one still lets the
			// other rotate.
			runGuarded("ca_rotation", func() {
				certMgr.RotateIfNeeded(caPath, passphrase)
				certMgr.CleanupSecondaryCA()
			})
			runGuarded("cluster_ca_rotation", func() {
				globalClusterCA.RotateIfNeeded()
				globalClusterCA.CleanupSecondary()
			})
		}
		checkRound()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// CHAOS-24: contain the ROUND. A panic here would otherwise
				// kill the gateway; a guard that let the goroutine exit would
				// be worse still — the CA would silently never rotate again
				// and the failure would only surface at expiry, as a
				// fleet-wide inspected-HTTPS outage. Each CA is guarded
				// separately so a fault in one still lets the other rotate.
				checkRound()
			}
		}
	}()
}
