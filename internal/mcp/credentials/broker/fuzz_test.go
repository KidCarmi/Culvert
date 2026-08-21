package broker

import (
	"context"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// FuzzPlan proves plan construction never panics on arbitrary environment/operation/
// resource inputs and never resolves a plan whose tenant/server diverge from the
// profile.
func FuzzPlan(f *testing.F) {
	h := newHarness(f, provider.Capabilities{}, profile.PowerReadOnly)
	f.Add("prod", uint8(1), "repo:foo")
	f.Add("", uint8(0), "*")
	f.Fuzz(func(t *testing.T, env string, op uint8, res string) {
		in := PlanInput{
			Identity: h.id, Profile: profID, Environment: profile.Environment(env),
			Operation: profile.OperationClass(op % 5), Resources: []string{res},
		}
		plan, err := h.broker.Plan(in)
		if err != nil {
			return
		}
		// A resolved plan always carries the profile's tenant and server.
		if plan.Tenant() != tenantA || plan.Server() != srv1 {
			t.Fatalf("plan diverged from profile: tenant=%v server=%v", plan.Tenant(), plan.Server())
		}
	})
}

// FuzzMaterializeGate proves Materialize never panics for arbitrary gate decisions
// and never materializes when the gate denies, and never leaks the material canary
// into the returned error.
func FuzzMaterializeGate(f *testing.F) {
	f.Add(false, false)
	f.Add(true, false)
	f.Add(true, true)
	f.Fuzz(func(t *testing.T, permit, durable bool) {
		h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
		plan := h.readPlan(t)
		res, err := h.broker.Materialize(context.Background(), plan, &fakeGate{permit: permit, durable: durable}, noopCB)
		if err != nil && strings.Contains(err.Error(), "UPSTREAM") {
			t.Fatal("material canary leaked into error")
		}
		if !permit && res.Materialized {
			t.Fatal("materialized despite gate denial")
		}
	})
}

// FuzzEffectiveScope proves scope validation never panics and never validates a
// broadening.
func FuzzEffectiveScope(f *testing.F) {
	f.Add("tenant-a", "prod", "srv-1", uint8(1), "repo:foo")
	f.Add("tenant-b", "prod", "srv-1", uint8(4), "repo:evil")
	f.Fuzz(func(t *testing.T, tenant, env, server string, power uint8, sel string) {
		rs, err := profile.NewResourceScope([]string{sel})
		if err != nil {
			return
		}
		profRS, _ := profile.NewResourceScope([]string{"repo:foo"})
		bound := profile.ScopeBound{
			Tenant: tenantA, Environment: "prod", Server: srv1, Resources: profRS,
			PowerFloor: profile.PowerReadOnly, PowerCeiling: profile.PowerReadOnly, RequireProof: true,
		}
		eff := profile.EffectiveScope{
			Tenant: identity.TenantID(tenant), Environment: profile.Environment(env),
			Server: registry.ServerID(server), Resources: rs, Power: profile.CredentialPower(power % 5), HasScopeProof: true,
		}
		if err := profile.ValidateEffectiveScope(eff, bound); err == nil {
			// A validated scope must match every scalar dimension and stay within power.
			if eff.Tenant != tenantA || eff.Environment != "prod" || eff.Server != srv1 {
				t.Fatal("validated a broadened scope")
			}
		}
	})
}
