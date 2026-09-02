package main

import (
	"context"
	"sync"

	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcpRuntime is the dedicated MCP listener runtime (Gateway + Management,
// physically and logically isolated). It is DISABLED BY DEFAULT: with no MCP
// configuration it is constructed disabled, binds no socket, starts no
// goroutine/timer, allocates nothing on the SWG request path, and leaves the
// existing Secure Web Gateway byte-identical.
//
// QUAL-1 adds ONE authoritative enablement path (mcp.gateway.* — Gateway capability
// only, Observe posture). When explicitly and validly configured, the Gateway
// listener binds with real TLS, client authentication and OAuth resource validation
// and processes only the accepted remote Streamable HTTP surface; it composes NO
// executor/upstream/broker/event manager, so it can never execute an upstream tool
// call. Management activation remains impossible here.
var (
	mcpRuntime *mcpruntime.Runtime

	// mcpObserveStatusMu guards mcpObserveStatus, which the admin health surface
	// reads. It records the truthful activation outcome (disabled / invalid /
	// configured) independently of the live listener Phase the runtime reports.
	mcpObserveStatusMu sync.RWMutex
	mcpObserveStatus   = mcpObserveActivation{State: mcpObserveDisabled}
)

// initMCPRuntime resolves the authoritative startup config, composes the runtime
// (disabled unless mcp.gateway.enabled is explicitly set and every security
// prerequisite validates), and starts it. Every failure on the enable path is
// fail-closed: nothing binds, a bounded secret-free classification is recorded for
// health, and SWG startup is never blocked.
func initMCPRuntime(s *startupState) {
	cfg, act := loadMCPObserveRuntime(resolveMCPObserveStartupConfig(s.fc))
	setMCPObserveStatus(act)

	// RISK-027: evaluate capability health on a timer, so a fault alerts even on a
	// deployment that never reads /healthz. DEFERRED, not called at the end of the
	// function: both startup-failure branches below mark the capability invalid and
	// return early, and those are precisely the faults most worth paging on — an MCP
	// port already in use produces a node that is "configured but not serving" and
	// would otherwise stay silent until something scraped /healthz. A deferred call
	// runs on every return path, including ones a later edit adds.
	//
	// It reads the status published above rather than `act`, so an invalid marking
	// made inside those branches is what it sees. No-ops when MCP was never
	// requested, so the disabled default still spawns nothing.
	//
	// Bound to the PROCESS LIFECYCLE, never context.Background(). Two reasons, and
	// the first is a correctness bug rather than tidiness: mcpCapStopped is a
	// FAULTED state (mcp_health_plane.go), and graceful shutdown deliberately stops
	// the listener via the mcp-runtime-stop hook. A poller that outlives
	// appLifecycleCancel therefore ticks after that hook runs, observes the
	// intentional stop, and pages mcp_gateway_down for a healthy orderly shutdown --
	// the alert plane crying wolf on exactly the event operators trigger on purpose.
	// (Draining is already exempt; Stopped, the state the listener actually ends in,
	// is not -- and must not be, because a listener that stopped on its own IS a
	// fault.) Second, it gives the goroutine a termination signal short of process
	// exit. resolveLifecycleCtx falls back to Background before the context is
	// wired, so early callers still work.
	defer func() { _ = startMCPHealthAlertPoller(resolveLifecycleCtx()) }()

	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		// A disabled config never fails validation; an enabled-but-invalid config was
		// already reduced to an empty (disabled) config by the loader, so this only
		// fires on an unexpected internal error. Fail closed: record it, never block SWG.
		logger.Printf("MCP runtime init skipped: %v", sanitizeLog(err.Error()))
		markMCPObserveInvalid("runtime_init_failed")
		invalidateMCPActivationOnStartupFailure()
		return
	}
	if err := rt.Start(); err != nil {
		logger.Printf("MCP runtime start skipped: %v", sanitizeLog(err.Error()))
		markMCPObserveInvalid("runtime_start_failed")
		invalidateMCPActivationOnStartupFailure()
		return
	}
	mcpRuntime = rt
	if act.State == mcpObserveConfigured {
		logger.Printf("MCP gateway observe listener active on %s:%d (client_cert=%s, sender=%s, protocol=%s)",
			sanitizeLog(act.BindAddress), act.Port, act.ClientCertMode, act.SenderProfile, act.ProtocolVersion)
	}
	// QUAL-3: start the durable-telemetry background loops (denial flush + per-partition
	// export) only AFTER the listener is up. Disabled ⇒ nil telemetry, nothing starts.
	if tel := sharedTelemetry(); tel != nil {
		tel.Start(context.Background())
		logger.Printf("MCP gateway telemetry active (node=%s, local qualification archive export)", sanitizeLog(tel.nodeID))
	}
	// QUAL-2 single-source ordering guard: the loader has now published the shared
	// inventory holder. When a qualification inventory is loaded, eagerly bind the
	// admin singleton HERE — after publication — so the read-only Servers/Tools Admin
	// API is guaranteed to snapshot the SAME populated registry/catalog the pipeline
	// resolves against, regardless of when the first admin request arrives. Without a
	// loaded inventory this stays lazy (byte-identical to QUAL-1), so the disabled
	// default is unchanged.
	// QUAL-3 extends the same ordering guard to telemetry: when either a qualification
	// inventory OR the durable telemetry manager is published, eagerly bind the admin
	// singleton HERE so the read-only inventory sources AND the committed-event read
	// seam (DecisionService) snapshot the SAME instances the runtime uses.
	if reg, _ := mcpInventory.sharedInventory(); reg != nil || sharedTelemetry() != nil {
		_ = getMCPAdmin()
	}
}

// setMCPObserveStatus publishes the activation summary for the health surface.
func setMCPObserveStatus(act mcpObserveActivation) {
	mcpObserveStatusMu.Lock()
	mcpObserveStatus = act
	mcpObserveStatusMu.Unlock()
}

// markMCPObserveInvalid downgrades the recorded status to invalid with a bounded
// reason (used when construction/start fails after a valid resolve).
func markMCPObserveInvalid(reason string) {
	mcpObserveStatusMu.Lock()
	mcpObserveStatus.State = mcpObserveInvalid
	mcpObserveStatus.EnableRequested = true
	mcpObserveStatus.Reason = reason
	mcpObserveStatusMu.Unlock()
}

// getMCPObserveStatus returns a copy of the current activation summary.
func getMCPObserveStatus() mcpObserveActivation {
	mcpObserveStatusMu.RLock()
	defer mcpObserveStatusMu.RUnlock()
	return mcpObserveStatus
}

// shutdownMCPRuntime stops the MCP runtime (a no-op while disabled). Bounded by the
// supplied shutdown context so a drain can never exceed the budget.
func shutdownMCPRuntime(ctx context.Context) error {
	if mcpRuntime == nil {
		return nil
	}
	return mcpRuntime.Shutdown(ctx)
}

// shutdownMCPTelemetry stops the telemetry loops, drains a final denial flush +
// export, and closes the encrypted spool (QUAL-3). A no-op while disabled. It runs
// AFTER the MCP listener stops (so no new events are produced) and clears the holder
// so a post-shutdown health read reports not-configured rather than a closed spool.
func shutdownMCPTelemetry(ctx context.Context) error {
	tel := sharedTelemetry()
	if tel == nil {
		return nil
	}
	publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	return tel.Close(ctx) // honor the shutdown budget so later hooks are never starved
}

// closeMCPTelemetryOnStartupFailure closes a telemetry runtime that the loader
// published as ready when the listener then failed to construct/start, so a
// fail-closed startup never leaks the opened encrypted spool.
func closeMCPTelemetryOnStartupFailure() {
	if tel := sharedTelemetry(); tel != nil {
		publishMCPTelemetry(mcpTelemInvalid, "runtime_start_failed", nil)
		_ = tel.Close(context.Background())
	}
}

// invalidateMCPActivationOnStartupFailure clears every node-local holder the loader
// published as active — the policy snapshot, the seeded inventory, and the telemetry
// runtime — when the listener then fails to construct or start. Without it, a bind
// failure (e.g. an occupied address) would leave the admin surface advertising an
// active, evaluation-enabled policy and a loaded inventory for a listener that is not
// running. The Secure Web Gateway path is never affected.
func invalidateMCPActivationOnStartupFailure() {
	invalidateMCPPolicyOnStartupFailure()
	if reg, cat := mcpInventory.sharedInventory(); reg != nil || cat != nil {
		publishMCPInventory(mcpInvInvalid, "runtime_start_failed", nil, nil)
	}
	closeMCPTelemetryOnStartupFailure()
	// Reset the live-tier holders composed during loadMCPObserveRuntime (the lifecycle object
	// + production-deps status), so a listener that never started stops reporting a composed
	// executor / events_ready (the event manager was just closed above) and an in-process retry
	// starts clean. No-op on a node that never composed the live tier.
	invalidateMCPLiveOnStartupFailure()
}
