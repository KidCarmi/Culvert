package main

import (
	"context"

	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcpRuntime is the PR-5 dedicated MCP listener runtime (Gateway + Management,
// physically and logically isolated). It is DISABLED BY DEFAULT and, in this slice,
// is always constructed disabled: PR-5 deliberately ships NO config/CLI/env surface
// that enables it and NO admin/UI management workflow — production enablement and
// the admin surface are later slices (the scope lock forbids them here). A disabled
// runtime binds no socket, starts no goroutine/timer, allocates nothing on the SWG
// request path, and leaves the existing Secure Web Gateway byte-identical.
var mcpRuntime *mcpruntime.Runtime

// initMCPRuntime constructs the disabled-by-default MCP runtime and starts it (a
// no-op while disabled). It is the single integration point for the later-slice
// enablement path; today it proves the SWG path is untouched when MCP is off and
// that startup succeeds with NO MCP certificates, registry or auth configured.
func initMCPRuntime(_ *startupState) {
	rt, err := mcpruntime.NewRuntime(mcpruntime.Config{})
	if err != nil {
		// A disabled runtime never fails validation; log defensively and continue —
		// MCP wiring must never block SWG startup.
		logger.Printf("MCP runtime init skipped: %v", err)
		return
	}
	if err := rt.Start(); err != nil {
		logger.Printf("MCP runtime start skipped: %v", err)
		return
	}
	mcpRuntime = rt
}

// shutdownMCPRuntime stops the MCP runtime (a no-op while disabled). Bounded by the
// supplied shutdown context so a drain can never exceed the budget.
func shutdownMCPRuntime(ctx context.Context) error {
	if mcpRuntime == nil {
		return nil
	}
	return mcpRuntime.Shutdown(ctx)
}
