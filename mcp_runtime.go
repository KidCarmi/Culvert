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

	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		// A disabled config never fails validation; an enabled-but-invalid config was
		// already reduced to an empty (disabled) config by the loader, so this only
		// fires on an unexpected internal error. Fail closed: record it, never block SWG.
		logger.Printf("MCP runtime init skipped: %v", sanitizeLog(err.Error()))
		markMCPObserveInvalid("runtime_init_failed")
		return
	}
	if err := rt.Start(); err != nil {
		logger.Printf("MCP runtime start skipped: %v", sanitizeLog(err.Error()))
		markMCPObserveInvalid("runtime_start_failed")
		return
	}
	mcpRuntime = rt
	if act.State == mcpObserveConfigured {
		logger.Printf("MCP gateway observe listener active on %s:%d (client_cert=%s, sender=%s, protocol=%s)",
			sanitizeLog(act.BindAddress), act.Port, act.ClientCertMode, act.SenderProfile, act.ProtocolVersion)
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
