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
	// CHAOS-50 / CA-13: started UNCONDITIONALLY. This used to be gated on
	// certMgr.Ready(), which reads as a harmless optimisation — why run a
	// rotation loop for a CA that failed to load? — but the loop drives BOTH
	// CAs (see StartCAAutoRotation), and the cluster CA is the only thing
	// rotating it. So a corrupt inspection bundle, a wrong
	// CULVERT_CA_PASSPHRASE, or an unreadable -ca-path silently took the
	// CLUSTER CA's entire lifecycle manager down with it: no auto-rotation, and
	// no secondary-CA overlap cleanup, on a node whose cluster CA was perfectly
	// healthy. Two independent trust roots, one shared failure — and because a
	// cluster CA is a 10-year certificate, the consequence would surface years
	// after the inspection-CA fault that caused it, with nothing left to
	// connect them.
	//
	// The gate is not needed for the inspection half either: RotateIfNeeded and
	// CleanupSecondaryCA both return immediately when no CA is loaded, so on a
	// node with no inspection CA this costs one zero-time comparison per day.
	// The loop's done channel is published so a caller that cancels ctx can join
	// the worker. Production never waits on it (shutdown does not block on a
	// rotation check); it exists so a test driving this loader leaves no
	// background goroutine running past its own completion.
	caRotationLoopDone = StartCAAutoRotation(ctx, cfg.Path, cfg.Passphrase)
}

// caRotationLoopDone is closed when the auto-rotation loop started by the most
// recent loadRootCA has exited. Written once per loadRootCA (startup, or a test),
// read only after cancelling that loop's context.
var caRotationLoopDone <-chan struct{}

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
