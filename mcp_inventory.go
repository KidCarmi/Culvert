package main

// QUAL-2 — static qualification-inventory composition for the Gateway Observe
// listener. This file loads a bounded, node-local JSON inventory document ONCE at
// startup and seeds it through the EXISTING Registry and Catalog contracts, so a
// correctly authenticated Model-A request for a seeded server/tool can pass
// registry resolution (pipeline step 8) and reach the QUAL-1 Observe-only decision
// boundary — while composing NO policy, events, executor, upstream client, or
// broker (QUAL-2 does not widen QUAL-1 beyond inventory resolution).
//
// It NEVER writes internal Registry/Catalog maps or fields directly: every server
// is seeded via registry.Register + registry.VerifyIdentity (identity confirmed to
// the exact accepted VerifyVerified state), and every tool via catalog.Ingest
// (which recomputes the existing fingerprint from the tool's own bounded schema —
// no second fingerprint format is invented — and lands the tool Quarantined, the
// correct record-only-Observe disposition; a seeded tool is KNOWN inventory, never
// automatically trusted for execution).
//
// Loading is ALL-OR-NOTHING: the candidate is parsed and every server + tool is
// validated and seeded into a FRESH private Registry/Catalog pair, and that pair is
// published to the runtime + Admin API only after every item succeeds. Any failure
// leaves the active composition empty and the activation invalid (fail closed) —
// never a partially loaded fleet. The same instances back the runtime pipeline AND
// the read-only MCP Servers/Tools Admin API (single source of truth).
//
// The document itself (bounded read, strict decode, validation, seeding) is owned
// by internal/mcp/qualinventory (IM-023, ADR-0055). This file keeps the state, the
// published holder, the Admin API adapters, the status view and the loader that
// classifies the outcome for the activation.

import (
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/adminapi"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/qualinventory"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// ── inventory state (holder) ─────────────────────────────────────────────────

// mcpInventoryState classifies the node-local qualification-inventory outcome for
// the read-only admin/health surface. It distinguishes a genuinely empty fleet
// from a failed load so an invalid inventory is NEVER rendered as an empty healthy
// fleet.
type mcpInventoryState string

const (
	// mcpInvNotConfigured — the Gateway listener is disabled, or enabled with no
	// qualification_inventory_file set (QUAL-1 posture). No fleet is expected.
	mcpInvNotConfigured mcpInventoryState = "not_configured"
	// mcpInvLoaded — a present, valid inventory file was seeded atomically.
	mcpInvLoaded mcpInventoryState = "loaded"
	// mcpInvInvalid — a present inventory file failed to load/seed; the listener did
	// not bind (fail closed). The lists are empty but the state is NOT "loaded".
	mcpInvInvalid mcpInventoryState = "invalid"
)

// mcpInventoryHolder is the node-local shared inventory published once at startup.
// The SAME reg/cat pointers are handed to the runtime Deps and the Admin API, so
// there is exactly one source of truth. Guarded because startup publishes it and
// the lazily-built admin singleton + health reads consume it.
type mcpInventoryHolder struct {
	mu     sync.RWMutex
	state  mcpInventoryState
	reason string // bounded, secret-free classification when state == invalid
	reg    *registry.Registry
	cat    *catalog.Catalog
}

var mcpInventory = &mcpInventoryHolder{state: mcpInvNotConfigured}

// publishMCPInventory records the node-local inventory outcome. A loaded state MUST
// carry both a registry and a catalog; every other state clears them so the Admin
// API never wires a stale source.
func publishMCPInventory(state mcpInventoryState, reason string, reg *registry.Registry, cat *catalog.Catalog) {
	mcpInventory.mu.Lock()
	defer mcpInventory.mu.Unlock()
	mcpInventory.state = state
	mcpInventory.reason = reason
	if state == mcpInvLoaded {
		mcpInventory.reg, mcpInventory.cat = reg, cat
	} else {
		mcpInventory.reg, mcpInventory.cat = nil, nil
	}
}

// sharedInventory returns the published registry/catalog pair (both nil unless a
// valid inventory is loaded). The runtime and the Admin API both call this so they
// observe the identical instances.
func (h *mcpInventoryHolder) sharedInventory() (*registry.Registry, *catalog.Catalog) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.reg, h.cat
}

// ── Admin API source adapters (single source of truth) ───────────────────────
// These adapt the SAME *registry.Registry / *catalog.Catalog the runtime pipeline
// reads into the narrow adminapi read seams, so the Admin API and the listener can
// never diverge. They are read-only (snapshot loads); they never mutate.

// mcpRegistrySource adapts the shared registry to adminapi.RegistrySource.
type mcpRegistrySource struct{ reg *registry.Registry }

func (s mcpRegistrySource) Servers() []registry.ServerRecord { return s.reg.Current().Servers() }
func (s mcpRegistrySource) RegistryRevision() uint64         { return s.reg.Current().Revision() }

// mcpCatalogSource adapts the shared catalog to adminapi.CatalogSource.
type mcpCatalogSource struct{ cat *catalog.Catalog }

func (s mcpCatalogSource) Tools() []catalog.ToolRecord { return s.cat.Current().Records() }
func (s mcpCatalogSource) CatalogRevision() uint64     { return s.cat.Current().Revision() }

// mcpInventoryCounts adapts the shared pair to adminapi.InventoryCounts for the
// per-capability health surface. Only Gateway carries inventory in QUAL-2.
type mcpInventoryCounts struct {
	reg *registry.Registry
	cat *catalog.Catalog
}

func (c mcpInventoryCounts) Counts(capability string) (servers, quarantined, drifted int) {
	if capability != protocol.Gateway.String() {
		return 0, 0, 0
	}
	servers = c.reg.Current().Len()
	// Index-based range: ToolRecord is a wide struct (gocritic rangeValCopy).
	tools := c.cat.Current().Records()
	for i := range tools {
		switch tools[i].Eligibility {
		case catalog.Quarantined:
			quarantined++
		case catalog.ReviewRequired:
			drifted++
		}
	}
	return servers, quarantined, drifted
}

// mcpAdminInventorySources returns the adminapi read seams over the SHARED
// inventory, or (nil, nil, nil) when no inventory is loaded. getMCPAdmin consumes
// this so the read-only Servers/Tools Admin API reads the identical
// registry/catalog the runtime pipeline resolves against — the single source of
// truth. Both-nil ⇒ the adminapi Inventory service stays disabled (empty views),
// byte-identical to the QUAL-1 default. Isolating the wiring here makes the
// single-source contract directly testable (see mcp_inventory_test.go), instead of
// only through the lazily-built admin singleton.
func mcpAdminInventorySources() (adminapi.RegistrySource, adminapi.CatalogSource, adminapi.InventoryCounts) {
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		return nil, nil, nil
	}
	return mcpRegistrySource{reg: reg}, mcpCatalogSource{cat: cat}, mcpInventoryCounts{reg: reg, cat: cat}
}

// InventoryStatus is the safe, read-only inventory readiness surfaced on the admin
// overview. It distinguishes not_configured / loaded / invalid and reports counts,
// but never labels the subsystem Observe-/qualification-/production-ready (inventory
// is only ONE dependency).
type InventoryStatus struct {
	State               string `json:"state"` // not_configured | loaded | invalid
	Reason              string `json:"reason,omitempty"`
	Servers             int    `json:"servers"`
	VerifiedServers     int    `json:"verified_servers"`
	Tools               int    `json:"tools"`
	QuarantinedTools    int    `json:"quarantined_tools"`
	ReviewRequiredTools int    `json:"review_required_tools"`
	// ExecutionEnabled is always false: QUAL-2 composes no executor. Surfaced so the
	// UI can keep stating that upstream execution is disabled.
	ExecutionEnabled bool `json:"execution_enabled"`
}

// inventoryStatus builds the safe status view from the published holder.
func inventoryStatus() InventoryStatus {
	mcpInventory.mu.RLock()
	state, reason, reg, cat := mcpInventory.state, mcpInventory.reason, mcpInventory.reg, mcpInventory.cat
	mcpInventory.mu.RUnlock()

	st := InventoryStatus{State: string(state), Reason: reason, ExecutionEnabled: false}
	if reg != nil {
		// Index-based range: ServerRecord is a wide struct; avoid the per-iteration
		// value copy (gocritic rangeValCopy).
		servers := reg.Current().Servers()
		st.Servers = len(servers)
		for i := range servers {
			if servers[i].Usable() {
				st.VerifiedServers++
			}
		}
	}
	if cat != nil {
		tools := cat.Current().Records()
		st.Tools = len(tools)
		for i := range tools {
			switch tools[i].Eligibility {
			case catalog.Quarantined:
				st.QuarantinedTools++
			case catalog.ReviewRequired:
				st.ReviewRequiredTools++
			}
		}
	}
	return st
}

// ── inventory engine bindings (internal/mcp/qualinventory, ADR-0055) ────────
// The bounded read, the strict decode, the validation and the Register →
// VerifyIdentity → Ingest seeding live in internal/mcp/qualinventory. Main keeps
// these names so the loader below, the activation that calls it and the root
// tests that build fixtures through them read as before.

// qualInventoryDoc is the decoded qualification inventory document.
type qualInventoryDoc = qualinventory.Doc

// readInventoryFile reads the operator-supplied inventory path, bounded and with
// a directory-traversal path rejected.
func readInventoryFile(path string) ([]byte, error) { return qualinventory.ReadFile(path) }

// decodeInventory strictly decodes inventory bytes; it performs no seeding.
func decodeInventory(raw []byte) (*qualInventoryDoc, error) { return qualinventory.Decode(raw) }

// seedInventory seeds a FRESH registry/catalog pair, all-or-nothing.
func seedInventory(doc *qualInventoryDoc, lim limits.CatalogLimits) (*registry.Registry, *catalog.Catalog, error) {
	return qualinventory.Seed(doc, lim)
}

// ── loader ───────────────────────────────────────────────────────────────────

// loadQualificationInventory resolves the qualification inventory for the resolved
// startup config. It returns the fresh registry/catalog pair the caller wires into
// BOTH the runtime Deps and the Admin API, plus the node-local state. Contracts:
//
//   - listener disabled ⇒ (empty reg, empty cat, not_configured, nil): QUAL-1
//     byte-identical empty-registry behavior;
//   - enabled, no file ⇒ (empty reg, empty cat, not_configured, nil);
//   - enabled, file present + valid ⇒ (populated reg, populated cat, loaded, nil);
//   - enabled, file present + invalid ⇒ (nil, nil, invalid, err): the caller fails
//     activation closed (nothing binds) and surfaces the bounded reason.
//
// The empty pair is always constructed with limits.DefaultCatalog() so the disabled
// / no-file path is identical to QUAL-1's assembleGatewayConfig.
func loadQualificationInventory(sc mcpObserveStartupConfig) (*registry.Registry, *catalog.Catalog, mcpInventoryState, error) {
	lim := limits.DefaultCatalog()
	if !sc.Enabled || sc.QualificationInventoryFile == "" {
		return registry.New(lim), catalog.New(lim), mcpInvNotConfigured, nil
	}
	raw, err := readInventoryFile(sc.QualificationInventoryFile)
	if err != nil {
		return nil, nil, mcpInvInvalid, err
	}
	doc, err := decodeInventory(raw)
	if err != nil {
		return nil, nil, mcpInvInvalid, err
	}
	reg, cat, err := seedInventory(doc, lim)
	if err != nil {
		return nil, nil, mcpInvInvalid, err
	}
	return reg, cat, mcpInvLoaded, nil
}
