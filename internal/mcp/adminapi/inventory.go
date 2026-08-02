package adminapi

import (
	"encoding/hex"
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// RegistrySource and CatalogSource are the narrow read seams the inventory
// service consumes. package main adapts *registry.Registry / *catalog.Catalog;
// tests supply fakes. They return the concrete upstream records; the inventory
// service maps them to SAFE, redacted view DTOs.
type RegistrySource interface {
	Servers() []registry.ServerRecord
	RegistryRevision() uint64
}

// CatalogSource exposes the current tool records and catalog revision.
type CatalogSource interface {
	Tools() []catalog.ToolRecord
	CatalogRevision() uint64
}

// ServerView is a safe, redacted inventory view of one registered server. It
// never exposes the raw endpoint, pinned identity material, or credential
// material — only opaque IDs, safe references and lifecycle state.
type ServerView struct {
	ServerID             string `json:"server_id"`
	Tenant               string `json:"tenant"`
	Capability           string `json:"capability"`
	Enabled              bool   `json:"enabled"`
	Verification         string `json:"verification"` // "verified" | "identity_mismatch"
	IdentityChanged      bool   `json:"identity_changed"`
	Revision             uint64 `json:"revision"`
	CredentialProfileRef string `json:"credential_profile_ref,omitempty"`
	EndpointConfigured   bool   `json:"endpoint_configured"`
}

// ToolView is a safe, redacted inventory view of one catalog tool. It never
// exposes complete schemas, arguments or output — only the fingerprint digest,
// disposition and destination class.
type ToolView struct {
	ServerID         string `json:"server_id"`
	Name             string `json:"name"`
	Fingerprint      string `json:"fingerprint"`
	Disposition      string `json:"disposition"` // usable | quarantined | review_required | ...
	Quarantined      bool   `json:"quarantined"`
	ReviewRequired   bool   `json:"review_required"`
	DestinationClass string `json:"destination_class"`
	Revision         uint64 `json:"revision"`
}

// InventoryService produces tenant-scoped, redacted, bounded inventory views.
type InventoryService struct {
	reg RegistrySource
	cat CatalogSource
	lim Limits
}

// NewInventoryService builds an inventory service.
func NewInventoryService(reg RegistrySource, cat CatalogSource, lim Limits) *InventoryService {
	return &InventoryService{reg: reg, cat: cat, lim: lim}
}

// verificationString maps a registry.Verification to a stable safe label.
func verificationString(v registry.Verification) string {
	if v == registry.VerifyIdentityMismatch {
		return "identity_mismatch"
	}
	return "verified"
}

// serverView maps a concrete record to its safe redacted view.
func serverView(r registry.ServerRecord) ServerView {
	return ServerView{
		ServerID:             string(r.ID),
		Tenant:               string(r.OwnerScope),
		Capability:           r.Capability.String(),
		Enabled:              r.Enabled,
		Verification:         verificationString(r.Verification),
		IdentityChanged:      r.Verification == registry.VerifyIdentityMismatch,
		Revision:             r.Revision,
		CredentialProfileRef: string(r.CredentialProfile),
		EndpointConfigured:   r.Endpoint != "",
	}
}

// ListServers returns a bounded, tenant-scoped, redacted server list ordered by
// ServerID. A caller only ever sees servers within its own tenant (OwnerScope).
func (s *InventoryService) ListServers(tenant string, limit int) ([]ServerView, error) {
	if tenant == "" {
		return nil, mcperr.New(mcperr.ReasonAdminTenantScope, "adminapi.inventory", "tenant required")
	}
	limit = s.clampLimit(limit)
	out := make([]ServerView, 0, limit)
	recs := s.reg.Servers()
	for i := range recs {
		if string(recs[i].OwnerScope) != tenant {
			continue
		}
		out = append(out, serverView(recs[i]))
		if len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerID < out[j].ServerID })
	return out, nil
}

// GetServer returns a single server within the caller's tenant, or a uniform
// not-found (no cross-tenant existence leak).
func (s *InventoryService) GetServer(tenant, serverID string) (ServerView, error) {
	if tenant == "" {
		return ServerView{}, mcperr.New(mcperr.ReasonAdminTenantScope, "adminapi.inventory", "tenant required")
	}
	for _, r := range s.reg.Servers() {
		if string(r.ID) == serverID && string(r.OwnerScope) == tenant {
			return serverView(r), nil
		}
	}
	return ServerView{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.inventory", "not found")
}

// ListTools returns a bounded, tenant-scoped, redacted tool list. Tools are
// joined to their server's tenant; an unknown/quarantined tool remains visibly
// quarantined (never presented as usable).
func (s *InventoryService) ListTools(tenant, serverID string, limit int) ([]ToolView, error) {
	if tenant == "" {
		return nil, mcperr.New(mcperr.ReasonAdminTenantScope, "adminapi.inventory", "tenant required")
	}
	limit = s.clampLimit(limit)
	tenantByServer := s.serverTenants()
	out := make([]ToolView, 0, limit)
	tools := s.cat.Tools()
	for i := range tools {
		sid := string(tools[i].Key.Server)
		if tenantByServer[sid] != tenant {
			continue
		}
		if serverID != "" && sid != serverID {
			continue
		}
		out = append(out, toolView(tools[i]))
		if len(out) >= limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerID != out[j].ServerID {
			return out[i].ServerID < out[j].ServerID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// GetTool returns one tool within the caller's tenant, or uniform not-found.
func (s *InventoryService) GetTool(tenant, serverID, name string) (ToolView, error) {
	if tenant == "" {
		return ToolView{}, mcperr.New(mcperr.ReasonAdminTenantScope, "adminapi.inventory", "tenant required")
	}
	if s.serverTenants()[serverID] != tenant {
		return ToolView{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.inventory", "not found")
	}
	for _, tr := range s.cat.Tools() {
		if string(tr.Key.Server) == serverID && tr.Key.Name == name {
			return toolView(tr), nil
		}
	}
	return ToolView{}, mcperr.New(mcperr.ReasonAdminNotFound, "adminapi.inventory", "not found")
}

func (s *InventoryService) serverTenants() map[string]string {
	m := make(map[string]string)
	for _, r := range s.reg.Servers() {
		m[string(r.ID)] = string(r.OwnerScope)
	}
	return m
}

func (s *InventoryService) clampLimit(limit int) int {
	if limit <= 0 || limit > s.lim.MaxInventoryResults() {
		return s.lim.MaxInventoryResults()
	}
	return limit
}

func toolView(tr catalog.ToolRecord) ToolView {
	sum := tr.Fingerprint.Sum()
	return ToolView{
		ServerID:         string(tr.Key.Server),
		Name:             tr.Key.Name,
		Fingerprint:      hex.EncodeToString(sum[:]),
		Disposition:      tr.Eligibility.String(),
		Quarantined:      tr.Eligibility == catalog.Quarantined,
		ReviewRequired:   tr.Eligibility == catalog.ReviewRequired,
		DestinationClass: destClassString(tr.Fingerprint.Destination),
		Revision:         tr.Revision,
	}
}

func destClassString(d catalog.DestinationClass) string {
	switch d {
	case catalog.DestNone:
		return "none"
	case catalog.DestApproved:
		return "approved"
	case catalog.DestInternal:
		return "internal"
	case catalog.DestArbitrary:
		return "arbitrary"
	default:
		return "unknown"
	}
}
