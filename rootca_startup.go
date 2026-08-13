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
	// CHAOS-50 / CA-13: started UNCONDITIONALLY. The loop drives BOTH CAs —
	// the inspection CA and the cluster CA (see StartCAAutoRotation) — so the
	// old `if certMgr.Ready()` guard coupled two subsystems that share nothing
	// but a ticker. A corrupt bundle, a wrong CULVERT_CA_PASSPHRASE or an
	// unwritable CA directory leaves certMgr not-ready, which is already an
	// accepted degradation for inspection (register row CA-3, fail-open to
	// tunnel-only) — but it ALSO silently switched off cluster-CA auto-rotation
	// on a control plane, whose only consequence appears years later as a
	// fleet-wide CP↔DP mTLS outage with no rotation ever having been attempted.
	//
	// Running the loop with no inspection CA costs one zero-expiry comparison
	// per 24h: certMgr.RotateIfNeeded returns immediately when CAExpiry() is
	// zero, and each CA is guarded separately inside the round.
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
