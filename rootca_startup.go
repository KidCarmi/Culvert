package main

// rootca_startup.go — loader for the Root-CA slice. Owns the side effects:
// loading/initialising the inspection CA on certMgr, publishing the caRuntime
// rotation config, and starting the auto-rotation background check. The
// resolver + DTO live in rootca_startup_config.go; the initRootCA shim in
// main.go wires them.

import (
	"context"
	"fmt"
	"sync/atomic"
)

// sslInspectionLoadError records a Root-CA load/init failure at startup
// (empty = no failure). For a Zero-Trust SWG this failure is fail-open on
// the primary control — the gateway keeps serving TLS as tunnel-only bypass
// with no MITM scanning/DLP/CDR — so it must be VISIBLE beyond one startup
// log line (CHAOS-06): /healthz + /readyz surface it and a ca_load_failed
// alert fires once webhooks are loaded.
var sslInspectionLoadError atomic.Value // string

// sslInspectionLoadFailure returns the recorded startup CA failure, or "".
func sslInspectionLoadFailure() string {
	s, _ := sslInspectionLoadError.Load().(string)
	return s
}

// noteSSLInspectionUnavailable records the failure and queues the alert
// (delivered after the webhook store loads — see deferStartupAlert).
func noteSSLInspectionUnavailable(path string, err error) {
	detail := fmt.Sprintf("Root CA load/init failed: %v — SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)", err)
	if path != "" {
		detail = fmt.Sprintf("Root CA load/init failed for %s: %v — SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)", path, err)
	}
	sslInspectionLoadError.Store(detail)
	deferStartupAlert("ca_load_failed", AlertPayload{Detail: detail, Source: "ca"})
}

// loadRootCA loads (or initialises) the Root CA for SSL inspection. A CA
// failure is non-fatal by design — the proxy serves with SSL inspection
// disabled rather than refusing to start. caRuntime is published for the
// API-driven rotation handlers regardless of load success (rotation needs the
// path+passphrase to write the new bundle). NOTE: caRuntime remains the
// pre-existing unsynchronised global flagged by ARCH_DISCOVERY — moved
// verbatim; hardening it is a separate, out-of-scope change.
func loadRootCA(cfg rootCAStartupConfig, ctx context.Context) {
	initInspectionCA(cfg)
	// Store CA runtime config for API-driven rotation.
	caRuntime.path = cfg.Path
	caRuntime.passphrase = cfg.Passphrase

	// CHAOS-50 / register row CA-3: start the auto-rotation loop
	// UNCONDITIONALLY. It used to be gated on certMgr.Ready(), which coupled two
	// CAs that share nothing but this goroutine: the round it runs drives the
	// INSPECTION CA *and* the CLUSTER CA (enrollment / CP↔DP mTLS), plus both
	// secondary-CA overlap cleanups. So an inspection-CA load failure — a wrong
	// passphrase, a corrupt bundle, a volume that was not mounted yet — silently
	// disabled cluster-CA rotation and both cleanups for the entire life of the
	// process, in a subsystem the operator has no reason to connect to the CA
	// bundle they are debugging. The gate bought nothing: both RotateIfNeeded
	// implementations already return immediately when their own CA is absent
	// (internal/ca CAExpiry().IsZero(), enrollment.go cert == nil), so on a
	// CA-less node the round is two nil checks a day.
	//
	// It also made every RUNTIME recovery permanent-but-useless: an operator who
	// fixed inspection via force-rotate or a custom-CA upload got a working CA
	// that would never auto-rotate again, because the loop that would have
	// rotated it was skipped at boot and there is no other place that starts it.
	StartCAAutoRotation(ctx, cfg.Path, cfg.Passphrase)

	// A recorded load failure gets a bounded retry campaign (rootca_recovery.go).
	// No-op on a healthy boot.
	startInspectionCARecoveryLoop(ctx, cfg)
}

// initInspectionCA performs the load-or-init half of loadRootCA: persisted
// bundle when a path is configured, ephemeral in-memory CA otherwise.
func initInspectionCA(cfg rootCAStartupConfig) {
	if cfg.Path == "" {
		if err := certMgr.InitCA(); err != nil {
			logger.Printf("Warning: Root CA init failed (%v) — SSL inspection disabled", err)
			noteSSLInspectionUnavailable("", err)
			return
		}
		logger.Printf("SSLCA: Root CA ready in-memory (set -ca-path + %s for persistence)", caPassphraseEnv)
		return
	}
	if err := certMgr.LoadOrInitCA(cfg.Path, cfg.Passphrase); err != nil {
		logger.Printf("Warning: Root CA load/init failed (%v) — SSL inspection disabled", err)
		noteSSLInspectionUnavailable(cfg.Path, err)
		return
	}
	logger.Printf("SSLCA: Root CA ready (persisted at %s, encrypted=%v)", cfg.Path, cfg.Passphrase != "")
}
