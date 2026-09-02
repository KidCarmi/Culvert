package main

// cdr_startup.go — loader for the CDR (Sluice) slice. Owns the side effects:
// the runtime enable-sentinel read, the unconditional persistent-store loads,
// the (non-fatal) gRPC client dial, and the health-poller goroutine. The
// resolver + DTO live in cdr_startup_config.go; the initCDR shim in main.go
// wires them.

import "context"

// loadCDR applies the resolved CDR config. Sequence (verbatim from the
// pre-slice init):
//
//  1. Runtime sentinel takes priority: /data/cdr_enabled (written by the
//     admin-GUI toggle or the first enrollment auto-enable) turns CDR on
//     regardless of YAML/CLI, so operators can enable it without editing
//     config files.
//  2. Persistent state loads UNCONDITIONALLY — registry/policy stores must
//     know their paths even while CDR is disabled, or GUI enrolls/toggles
//     live only in RAM until the next restart wipes them. Missing files are
//     tolerated (fresh install); malformed files log loudly.
//  3. When enabled: dial the client (NON-fatal — CDR is opt-in; the proxy
//     pipeline fails open/closed per policy) and start the health poller
//     (15s cached snapshot so /api/cdr/health is cheap).
func loadCDR(cfg cdrStartupConfig, ctx context.Context) {
	cdrCfg := cfg.CDR
	if cdrRuntimeEnabled() {
		cdrCfg.Enabled = true
	}

	if err := cdrInstances.Load(cfg.InstancesPath); err != nil {
		logger.Printf("CDR: instance registry load failed: %v", err)
	}
	if err := cdrPolicyStore.Load(cfg.PoliciesPath); err != nil {
		logger.Printf("CDR: policy store load failed: %v", err)
	}
	if issues := cdrPolicyStore.Integrity(); !issues.OK {
		logger.Printf("CDR: policy store is DEGRADED (%d identity issue(s)) — resolve them via the admin API before adding rules", len(issues.Issues))
	}
	if err := cdrEnrollReceipts.Load(cfg.EnrollReceiptsPath); err != nil {
		logger.Printf("CDR: enrollment receipts load failed: %v", err)
	}
	// 2E-C R7: finish or abandon any renewal interrupted by a crash, from
	// the durable lineage + on-disk PEMs, BEFORE the pool dials.
	reconcileCredentialLineage()

	if !cdrCfg.Enabled {
		return
	}

	// Display defaults for the status line only — initCDRClient receives the
	// config as-is (its own defaulting is authoritative).
	mode := cdrCfg.DefaultMode
	if mode == "" {
		mode = "ENFORCE"
	}
	profile := cdrCfg.DefaultProfile
	if profile == "" {
		profile = "default"
	}
	failSafe := "fail-open"
	if !cdrCfg.CDRFailOpen() {
		failSafe = "fail-closed"
	}

	if err := initCDRClient(cdrCfg); err != nil {
		logger.Printf("CDR: initial client dial failed, CDR effectively disabled: %v", sanitizeLog(err.Error()))
	}

	startCDRHealthPoller(ctx)

	logger.Printf("CDR: enabled — endpoint=%q profile=%q mode=%q %s (Phase 2c: client + policy engine + proxy wiring + admin API live)",
		sanitizeLog(cdrCfg.Endpoint), sanitizeLog(profile), sanitizeLog(mode), failSafe)
}
