package canary

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// approvalFor builds a valid live_execution approval bound to an exact tool identity.
func approvalFor(server, tool string, digest tooltrust.FingerprintDigest, now time.Time) *tooltrust.ToolApproval {
	exp := now.Add(time.Hour)
	return &tooltrust.ToolApproval{
		Tenant: "t1", ServerID: server, ToolName: tool,
		Fingerprint: digest, FingerprintFormatVersion: 1,
		Purpose:     tooltrust.PurposeLiveExecution,
		Status:      tooltrust.StatusActive,
		RequestedBy: "alice", ApprovedBy: "bob",
		ApprovedAt: now, ExpiresAt: &exp,
	}
}

func bindingFor(server, tool string, digest tooltrust.FingerprintDigest, now time.Time) ToolApprovalBinding {
	return ToolApprovalBinding{
		Target:   LiveTarget{Tenant: "t1", ServerID: server, ToolName: tool, Fingerprint: digest, FingerprintFormat: 1},
		Approval: approvalFor(server, tool, digest, now),
	}
}

// fpHex is the hex encoding of an all-b digest — the scope tool's declared fingerprint string,
// which must equal hex of the binding target's digest.
func fpHex(b byte) string {
	d := fp(b)
	return hex.EncodeToString(d[:])
}

// twoToolScope + its matching bindings: two exact fingerprinted tools on one server.
func twoToolScope() rollout.ScopeSpec {
	return rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Tenants:    []string{"t1"},
		Servers:    []string{"srv"},
		Tools: []rollout.ToolSel{
			{Server: "srv", Name: "echo", Fingerprint: fpHex(0x11)},
			{Server: "srv", Name: "list", Fingerprint: fpHex(0x22)},
		},
		Principals: []string{"synthetic"},
		Operations: []rollout.RiskClass{rollout.RiskRead},
	}
}

func twoToolBindings(now time.Time) []ToolApprovalBinding {
	return []ToolApprovalBinding{
		bindingFor("srv", "echo", fp(0x11), now),
		bindingFor("srv", "list", fp(0x22), now),
	}
}

func TestValidateScopeApprovals_EveryToolCovered(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if r := ValidateScopeApprovals(twoToolScope(), twoToolBindings(now), now); r != ScopeApprovalOK {
		t.Fatalf("fully-covered scope rejected: %s", r)
	}
}

// TestValidateScopeApprovals_MissingToolIsUnapproved is the core P1-C invariant: a single
// approval can NOT authorize a multi-tool scope — every scoped tool needs its own.
func TestValidateScopeApprovals_MissingToolIsUnapproved(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	only := twoToolBindings(now)[:1] // only the "echo" approval; "list" uncovered
	if r := ValidateScopeApprovals(twoToolScope(), only, now); r != ScopeApprovalToolUnapproved {
		t.Fatalf("SECURITY: a scope tool with no approval must be unapproved, got %q", r)
	}
}

func TestValidateScopeApprovals_Rejections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name     string
		bindings func() []ToolApprovalBinding
		want     ScopeApprovalReason
	}{
		{"outside_scope", func() []ToolApprovalBinding {
			b := twoToolBindings(now)
			return append(b, bindingFor("srv", "danger", fp(0x33), now)) // a tool the scope never named
		}, ScopeApprovalOutsideScope},
		{"duplicate_tool", func() []ToolApprovalBinding {
			b := twoToolBindings(now)
			return append(b, bindingFor("srv", "echo", fp(0x11), now)) // second binding for echo
		}, ScopeApprovalDuplicate},
		{"wrong_fingerprint", func() []ToolApprovalBinding {
			b := twoToolBindings(now)
			b[0] = bindingFor("srv", "echo", fp(0x99), now) // target fp != scope's declared fp for echo
			return b
		}, ScopeApprovalFingerprint},
		{"shadow_purpose", func() []ToolApprovalBinding {
			b := twoToolBindings(now)
			b[0].Approval.Purpose = tooltrust.PurposeShadowEvaluation
			return b
		}, ScopeApprovalToolUnapproved},
		{"nil_approval", func() []ToolApprovalBinding {
			b := twoToolBindings(now)
			b[1].Approval = nil
			return b
		}, ScopeApprovalToolUnapproved},
		{"wrong_tenant", func() []ToolApprovalBinding {
			// A binding for tenant t2 must NOT count as coverage for a scope admitting t1: the
			// t1/echo combination is then uncovered (Codex P1). Approvals are keyed by tenant too.
			b := twoToolBindings(now)
			b[0].Target.Tenant = "t2"
			b[0].Approval.Tenant = "t2"
			return b
		}, ScopeApprovalToolUnapproved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r := ValidateScopeApprovals(twoToolScope(), tc.bindings(), now); r != tc.want {
				t.Fatalf("ValidateScopeApprovals(%s) = %q, want %q", tc.name, r, tc.want)
			}
		})
	}
}

func TestValidateScopeApprovals_NoTools(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := twoToolScope()
	s.Tools = nil
	if r := ValidateScopeApprovals(s, nil, now); r != ScopeApprovalNoTools {
		t.Fatalf("a scope naming no tools must be scope_has_no_tools, got %q", r)
	}
}

func TestValidateScopeApprovals_NoTenant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := twoToolScope()
	s.Tenants = nil
	if r := ValidateScopeApprovals(s, twoToolBindings(now), now); r != ScopeApprovalNoTenant {
		t.Fatalf("a scope naming no tenant must be scope_has_no_tenant, got %q", r)
	}
}
