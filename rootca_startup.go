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
	// Start CA auto-rotation background check.
	//
	// CHAOS-50: this used to be gated on certMgr.Ready(). The loop drives TWO
	// unrelated CAs — the inspection CA AND the cluster CA that signs Data-Plane
	// node certificates — so gating it on the inspection CA's health made a
	// wrong CULVERT_CA_PASSPHRASE, a corrupt bundle, or an unwritable bundle
	// path silently disable cluster-CA rotation as well, permanently and with no
	// signal. The two failures then compound on a schedule: the appliance loses
	// SSL inspection today (loudly, via ca_load_failed) and loses the ability to
	// enroll or renew ANY node in ten years' time (silently), and nothing
	// connects the two events.
	//
	// The gate bought nothing: RotateIfNeeded returns immediately when its CA
	// has no expiry (internal/ca/ca.go — CAExpiry().IsZero()), and
	// CleanupSecondaryCA is nil-safe, so on a node with no inspection CA the
	// loop costs one zero-check per 24h tick. StartCAAutoRotation is idempotent,
	// so calling it unconditionally here is also what makes a later runtime
	// Control-Plane promotion safe to cover.
	StartCAAutoRotation(ctx, cfg.Path, cfg.Passphrase)
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
