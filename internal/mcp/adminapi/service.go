package adminapi

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/approval"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// Service is the adminapi composition root: it ties the individual domain
// services together behind one struct that both the admin HTTP handlers
// (package main) and the Management MCP backend consume. It holds no HTTP,
// session or RBAC concern — callers authorize before invoking it.
type Service struct {
	Inventory   *InventoryService
	Decisions   *DecisionService
	Policy      *PolicyService
	Publication *PublicationService
	Health      *HealthService
	Config      *ConfigStore
	Approvals   *approval.Store
	Limits      Limits
}

// Params bundles the dependencies needed to build a Service.
type Params struct {
	Registry     RegistrySource
	Catalog      CatalogSource
	Events       EventReader
	PolicyStores PolicyStores
	PolicyLimits policy.Limits
	Approvals    *approval.Store
	PubCommitter PublicationCommitter
	IDGen        func() approval.ID
	Health       HealthSources
	ConfigStore  *ConfigStore
	Limits       Limits
	Clock        func() time.Time
}

// NewService builds the composition root from its dependencies. Any source may
// be nil for a capability that is not wired; the corresponding service then
// returns empty/disabled results rather than panicking.
func NewService(p Params) *Service {
	ps := NewPolicyService(p.PolicyStores, p.PolicyLimits, p.Limits, p.Clock)
	svc := &Service{
		Policy:    ps,
		Config:    p.ConfigStore,
		Approvals: p.Approvals,
		Limits:    p.Limits,
	}
	if p.Registry != nil && p.Catalog != nil {
		svc.Inventory = NewInventoryService(p.Registry, p.Catalog, p.Limits)
	}
	if p.Events != nil {
		svc.Decisions = NewDecisionService(p.Events, p.Limits)
	}
	if p.Approvals != nil && p.PolicyStores != nil {
		svc.Publication = NewPublicationService(ps, p.PolicyStores, p.Approvals, p.PubCommitter, p.IDGen, p.Clock)
	}
	svc.Health = NewHealthService(p.Health, p.Limits)
	return svc
}
