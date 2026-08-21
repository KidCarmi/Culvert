package adminapi

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

type fakeReg struct{ recs []registry.ServerRecord }

func (f *fakeReg) Servers() []registry.ServerRecord { return f.recs }
func (f *fakeReg) RegistryRevision() uint64         { return 7 }

type fakeCat struct{ recs []catalog.ToolRecord }

func (f *fakeCat) Tools() []catalog.ToolRecord { return f.recs }
func (f *fakeCat) CatalogRevision() uint64     { return 9 }

func invSvc() *InventoryService {
	reg := &fakeReg{recs: []registry.ServerRecord{
		{ID: "s-acme-1", Endpoint: "https://a.example", OwnerScope: "acme", Enabled: true, Verification: registry.VerifyVerified, Revision: 1, CredentialProfile: "cp-1"},
		{ID: "s-globex-1", Endpoint: "https://g.example", OwnerScope: "globex", Enabled: true, Verification: registry.VerifyIdentityMismatch, Revision: 2},
	}}
	cat := &fakeCat{recs: []catalog.ToolRecord{
		{Key: catalog.ToolKey{Server: "s-acme-1", Name: "read_file"}, Eligibility: catalog.Usable, Revision: 1},
		{Key: catalog.ToolKey{Server: "s-globex-1", Name: "danger"}, Eligibility: catalog.Quarantined, Revision: 1},
	}}
	return NewInventoryService(reg, cat, DefaultLimits())
}

func TestInventory_ServerTenantIsolation(t *testing.T) {
	s := invSvc()
	acme, err := s.ListServers("acme", 100)
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(acme) != 1 || acme[0].ServerID != "s-acme-1" {
		t.Fatalf("acme should see exactly its own server: %+v", acme)
	}
	// Cross-tenant get is uniform not-found.
	if _, err := s.GetServer("acme", "s-globex-1"); mcperr.ReasonOf(err) != mcperr.ReasonAdminNotFound {
		t.Fatalf("cross-tenant server get must be not_found, got %v", err)
	}
}

func TestInventory_Redaction(t *testing.T) {
	s := invSvc()
	acme, _ := s.ListServers("acme", 100)
	v := acme[0]
	// Redacted view carries a credential-profile REFERENCE and endpoint presence,
	// never the raw endpoint or credential material.
	if v.CredentialProfileRef != "cp-1" {
		t.Fatalf("want profile ref, got %q", v.CredentialProfileRef)
	}
	if !v.EndpointConfigured {
		t.Fatal("endpoint presence should be true")
	}
}

func TestInventory_QuarantineVisibleNotUsable(t *testing.T) {
	s := invSvc()
	tools, err := s.ListTools("globex", "", 100)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 1 || !tools[0].Quarantined || tools[0].Disposition == "usable" {
		t.Fatalf("quarantined tool must be visible and not usable: %+v", tools)
	}
}

func TestInventory_ToolTenantIsolation(t *testing.T) {
	s := invSvc()
	acme, _ := s.ListTools("acme", "", 100)
	if len(acme) != 1 || acme[0].Name != "read_file" {
		t.Fatalf("acme should see only its tool: %+v", acme)
	}
	if _, err := s.GetTool("acme", "s-globex-1", "danger"); mcperr.ReasonOf(err) != mcperr.ReasonAdminNotFound {
		t.Fatalf("cross-tenant tool get must be not_found, got %v", err)
	}
}

func TestInventory_TenantRequired(t *testing.T) {
	s := invSvc()
	if _, err := s.ListServers("", 10); mcperr.ReasonOf(err) != mcperr.ReasonAdminTenantScope {
		t.Fatalf("empty tenant must be rejected, got %v", err)
	}
}
