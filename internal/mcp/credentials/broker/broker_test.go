package broker

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestMaterializeReadHappyPath(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	plan := h.readPlan(t)
	var got string
	res, err := h.broker.Materialize(context.Background(), plan, permitGate(), func(kind profile.CredentialKind, m *provider.Material) error {
		if kind != profile.KindBearerToken {
			t.Fatalf("kind = %v", kind)
		}
		b, ok := m.Field(provider.FieldToken)
		if !ok {
			t.Fatal("token field missing")
		}
		got = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if got != "UPSTREAM-v1" {
		t.Fatalf("materialized token = %q", got)
	}
	if !res.Materialized || res.Reason != mcperr.ReasonNone || res.Version != "v1" {
		t.Fatalf("safe result wrong: %+v", res)
	}
	if f, _, _ := h.prov.Calls(); f != 1 {
		t.Fatalf("provider fetch calls = %d, want 1", f)
	}
}

func TestMaterializeWriteRequiresDurableConfirmation(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerWrite)
	plan := h.writePlan(t)
	// High-risk without durable confirmation → denied, provider untouched.
	res, err := h.broker.Materialize(context.Background(), plan, &fakeGate{permit: true, durable: false}, noopCB)
	if mcperr.ReasonOf(err) != mcperr.ReasonMaterializationGateDenied {
		t.Fatalf("want gate denied, got %v", mcperr.ReasonOf(err))
	}
	if res.Materialized {
		t.Fatal("must not materialize")
	}
	if f, _, _ := h.prov.Calls(); f != 0 {
		t.Fatalf("provider must be untouched on gate denial, calls=%d", f)
	}
	// With durable confirmation → succeeds.
	if _, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB); err != nil {
		t.Fatalf("write with durable confirmation should succeed: %v", err)
	}
}

func TestGateFailuresLeaveProviderAndCacheUntouched(t *testing.T) {
	cases := []struct {
		name string
		gate *fakeGate
		want mcperr.Reason
	}{
		{"denied", &fakeGate{permit: false}, mcperr.ReasonMaterializationGateDenied},
		{"unavailable", &fakeGate{err: context.DeadlineExceeded}, mcperr.ReasonMaterializationGateUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
			plan := h.readPlan(t)
			res, err := h.broker.Materialize(context.Background(), plan, tc.gate, noopCB)
			if mcperr.ReasonOf(err) != tc.want {
				t.Fatalf("reason = %v, want %v", mcperr.ReasonOf(err), tc.want)
			}
			if res.Materialized {
				t.Fatal("must not materialize")
			}
			if f, _, _ := h.prov.Calls(); f != 0 {
				t.Fatalf("provider called on gate failure: %d", f)
			}
			if h.broker.cache.size() != 0 {
				t.Fatal("cache touched on gate failure")
			}
		})
	}
}

func TestPlanMatrix(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	base := PlanInput{Identity: h.id, Profile: profID, Environment: "prod", Operation: profile.OpRead}
	cases := []struct {
		name  string
		patch func(*PlanInput)
		want  mcperr.Reason
	}{
		{"wrong-env", func(in *PlanInput) { in.Environment = "staging" }, mcperr.ReasonCredentialScopeMismatch},
		{"unknown-profile", func(in *PlanInput) { in.Profile = "nope" }, mcperr.ReasonCredentialProfileMissing},
		{"stale-revision", func(in *PlanInput) { in.BaseRevision = 99 }, mcperr.ReasonCredentialVersionStale},
		{"bad-operation", func(in *PlanInput) { in.Operation = profile.OpUnset }, mcperr.ReasonCredentialScopeMismatch},
		{"resource-outside", func(in *PlanInput) { in.Resources = []string{"repo:evil"} }, mcperr.ReasonCredentialScopeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.patch(&in)
			if _, err := h.broker.Plan(in); mcperr.ReasonOf(err) != tc.want {
				t.Fatalf("reason = %v, want %v", mcperr.ReasonOf(err), tc.want)
			}
		})
	}
}

func TestPlanRejectsManagementIdentity(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	// A Management identity context presented to the Gateway broker is rejected.
	mgmt := managementIdentity(t)
	if _, err := h.broker.Plan(PlanInput{Identity: mgmt, Profile: profID, Environment: "prod", Operation: profile.OpRead}); mcperr.ReasonOf(err) != mcperr.ReasonCapabilityMismatch {
		t.Fatalf("management identity must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

func TestPlanWrongTenantIdentity(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	// A tenant-b Gateway identity planning against the tenant-a profile must be
	// rejected by the broker's tenant check (a profile for one tenant never resolves
	// for another).
	other := gwIdentityTenant(t, h.reg, h.cat, tenantB)
	if _, err := h.broker.Plan(PlanInput{Identity: other, Profile: profID, Environment: "prod", Operation: profile.OpRead}); mcperr.ReasonOf(err) != mcperr.ReasonTenantMismatch {
		t.Fatalf("cross-tenant identity must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

func TestProviderErrorCanaryNotLeaked(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	const canary = "TOPSECRET-CANARY-9f3a"
	h.prov.SetFetchError(errorsNew(canary))
	plan := h.readPlan(t)
	res, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB)
	if err == nil {
		t.Fatal("expected failure")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("provider canary leaked in error: %q", err.Error())
	}
	if strings.Contains(safeString(res), canary) {
		t.Fatal("provider canary leaked in safe result")
	}
	if mcperr.ReasonOf(err) != mcperr.ReasonProviderUnavailable {
		t.Fatalf("unclassified provider error should map to provider_unavailable, got %v", mcperr.ReasonOf(err))
	}
}

func TestCallbackZeroizesOnSuccessAndPanic(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	plan := h.readPlan(t)
	var captured []byte
	_, err := h.broker.Materialize(context.Background(), plan, permitGate(), func(_ profile.CredentialKind, m *provider.Material) error {
		b, _ := m.Field(provider.FieldToken)
		captured = b // alias into the scoped plaintext buffer
		if !bytes.Contains(captured, []byte("UPSTREAM")) {
			t.Fatal("token not visible during callback")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allZero(captured) {
		t.Fatal("plaintext not zeroized after successful callback")
	}

	// Panic path: the deferred Destroy must still zeroize.
	plan2 := h.readPlan(t)
	var captured2 []byte
	func() {
		defer func() { _ = recover() }()
		_, _ = h.broker.Materialize(context.Background(), plan2, permitGate(), func(_ profile.CredentialKind, m *provider.Material) error {
			b, _ := m.Field(provider.FieldToken)
			captured2 = b
			panic("boom")
		})
	}()
	if captured2 != nil && !allZero(captured2) {
		t.Fatal("plaintext not zeroized during panic unwinding")
	}
}

func TestNoRawTokenInProviderRequest(t *testing.T) {
	// The provider request carries only the PR-3 correlation digest, never a token.
	rp := &recordingProvider{InMemoryProvider: memProvider(t, fixedClock(), profile.PowerReadOnly, "v1", provider.Capabilities{})}
	h := newHarnessWithProvider(t, rp, profile.PowerReadOnly)
	plan := h.readPlan(t)
	if _, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	if rp.lastReq.TokenDigest != "digest-abc123" {
		t.Fatalf("provider request digest = %q", rp.lastReq.TokenDigest)
	}
	// Structurally, provider.Request has no raw-token field; assert the digest is not
	// a usable upstream token by construction (it equals the PR-3 digest only).
	if strings.Contains(rp.lastReq.TokenDigest, "UPSTREAM") {
		t.Fatal("provider request must not carry upstream material")
	}
}

func TestScopePowerMatrix(t *testing.T) {
	cases := []struct {
		name  string
		op    profile.OperationClass
		power profile.CredentialPower
		scope func(testing.TB) profile.EffectiveScope
		want  mcperr.Reason
	}{
		{"read-cred-for-write", profile.OpWrite, profile.PowerReadOnly, func(tb testing.TB) profile.EffectiveScope { return leaseScope(tb, profile.PowerReadOnly) }, mcperr.ReasonCredentialScopeMismatch},
		{"write-cred-for-read", profile.OpRead, profile.PowerWrite, func(tb testing.TB) profile.EffectiveScope { return leaseScope(tb, profile.PowerWrite) }, mcperr.ReasonCredentialPowerExceeded},
		{"cross-tenant-cred", profile.OpRead, profile.PowerReadOnly, func(tb testing.TB) profile.EffectiveScope {
			s := leaseScope(tb, profile.PowerReadOnly)
			s.Tenant = tenantB
			return s
		}, mcperr.ReasonCredentialScopeMismatch},
		{"cross-server-cred", profile.OpRead, profile.PowerReadOnly, func(tb testing.TB) profile.EffectiveScope {
			s := leaseScope(tb, profile.PowerReadOnly)
			s.Server = "srv-2"
			return s
		}, mcperr.ReasonCredentialScopeMismatch},
		{"broader-resource-cred", profile.OpRead, profile.PowerReadOnly, func(tb testing.TB) profile.EffectiveScope {
			s := leaseScope(tb, profile.PowerReadOnly)
			rs, _ := profile.NewResourceScope([]string{"repo:foo", "repo:secret"})
			s.Resources = rs
			return s
		}, mcperr.ReasonCredentialScopeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, provider.Capabilities{}, tc.power)
			h.prov.SetMaterial(profile.KindBearerToken, map[provider.FieldName][]byte{provider.FieldToken: []byte("x")},
				provider.Lease{Version: "v1", IssuedAt: h.clk(), Expiry: h.clk().Add(10 * timeMinute), Scope: tc.scope(t)})
			var plan CredentialPlan
			if tc.op == profile.OpWrite {
				plan = h.writePlan(t)
			} else {
				plan = h.readPlan(t)
			}
			if _, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB); mcperr.ReasonOf(err) != tc.want {
				t.Fatalf("reason = %v, want %v", mcperr.ReasonOf(err), tc.want)
			}
		})
	}
}

func TestQuarantinedToolCarriedNotApproved(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	ingestTool(t, h.cat, h.reg, "tool-a")
	plan, err := h.broker.Plan(PlanInput{Identity: h.id, Profile: profID, Environment: "prod", Operation: profile.OpRead, Tool: &profile.ToolBinding{Server: srv1, Name: "tool-a"}})
	if err != nil {
		t.Fatalf("plan with tool: %v", err)
	}
	elig, ok := plan.ToolEligibility()
	if !ok || elig.String() != "quarantined" {
		t.Fatalf("quarantined eligibility not carried: %v ok=%v", elig, ok)
	}
	// A gate that denies (representing policy blocking a quarantined tool) fails
	// closed; PR-4 never auto-approves.
	if _, err := h.broker.Materialize(context.Background(), plan, &fakeGate{permit: false}, noopCB); mcperr.ReasonOf(err) != mcperr.ReasonMaterializationGateDenied {
		t.Fatalf("quarantined tool must not be auto-usable, got %v", mcperr.ReasonOf(err))
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

const timeMinute = 60_000_000_000

func noopCB(_ profile.CredentialKind, _ *provider.Material) error { return nil }

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func mcperrIs(err error, code string) bool { return mcperr.ReasonOf(err).Code() == code }
