package identity

import (
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

func humanSubject(sub, tenant string) Subject {
	return Subject{Kind: SubjectHuman, Human: &Human{Subject: sub, Tenant: TenantID(tenant), Issuer: "iss", Assurance: AssuranceHigh}}
}

func gwReg(t testing.TB) *registry.Registry {
	t.Helper()
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: "srv-1", Endpoint: "mcp://srv-1", PinnedIdentity: "spiffe://srv-1",
		Capability: protocol.Gateway, CredentialProfile: "cred-a",
	}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func baseGatewayInput() ResolveInput {
	sid := registry.ServerID("srv-1")
	return ResolveInput{
		Capability: protocol.Gateway, Tenant: Tenant{ID: "tenant-a"},
		Subject: humanSubject("user-1", "tenant-a"),
		Client:  Client{ClientID: "client-g", Tenant: "tenant-a", Capability: protocol.Gateway},
		Server:  &sid, CanonicalResource: "/mcp/gateway/srv-1", Issuer: "iss",
	}
}

func TestResolveValidGateway(t *testing.T) {
	ctx, err := Resolve(baseGatewayInput(), gwReg(t), nil)
	if err != nil {
		t.Fatalf("valid gateway resolve: %v", err)
	}
	if s, ok := ctx.Server(); !ok || s != "srv-1" {
		t.Fatal("server not resolved")
	}
	if ctx.Fingerprint() == "" {
		t.Fatal("fingerprint empty")
	}
}

func TestResolveRejections(t *testing.T) {
	reg := gwReg(t)
	cases := []struct {
		name string
		mut  func(in *ResolveInput)
		want mcperr.Reason
	}{
		{"both-subjects", func(in *ResolveInput) {
			in.Subject = Subject{Kind: SubjectHuman, Human: &Human{Subject: "u", Tenant: "tenant-a"}, Workload: &Workload{Service: "w", Tenant: "tenant-a"}}
		}, mcperr.ReasonDelegationChainInvalid},
		{"no-subject", func(in *ResolveInput) { in.Subject = Subject{} }, mcperr.ReasonDelegationChainInvalid},
		{"tenant-conflict", func(in *ResolveInput) { in.Client.Tenant = "tenant-b" }, mcperr.ReasonTenantMismatch},
		{"client-capability-mismatch", func(in *ResolveInput) { in.Client.Capability = protocol.Management }, mcperr.ReasonCapabilityMismatch},
		{"agent-owner-mismatch", func(in *ResolveInput) {
			in.Agent = &Agent{AgentID: "a1", Owner: PrincipalRef{Kind: KindHuman, ID: "someone-else"}}
		}, mcperr.ReasonDelegationChainInvalid},
		{"gateway-without-server", func(in *ResolveInput) { in.Server = nil }, mcperr.ReasonDelegationChainInvalid},
		{"unregistered-server", func(in *ResolveInput) { s := registry.ServerID("nope"); in.Server = &s }, mcperr.ReasonRegistryServerUnavailable},
		{"tool-wrong-server", func(in *ResolveInput) { in.Tool = &ToolRef{Server: "other", Name: "t"} }, mcperr.ReasonDelegationChainInvalid},
		{"cross-tenant-resource", func(in *ResolveInput) { in.Resource = &ResourceRef{Type: "db", ID: "x", Tenant: "tenant-b"} }, mcperr.ReasonTenantMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseGatewayInput()
			tc.mut(&in)
			if _, err := Resolve(in, reg, nil); mcperr.ReasonOf(err) != tc.want {
				t.Fatalf("reason = %v, want %v (err=%v)", mcperr.ReasonOf(err), tc.want, err)
			}
		})
	}
}

// Management must not carry Gateway server/tool authority.
func TestManagementRejectsGatewayAuthority(t *testing.T) {
	sid := registry.ServerID("srv-1")
	in := ResolveInput{
		Capability: protocol.Management, Tenant: Tenant{ID: "tenant-a"},
		Subject: humanSubject("admin-1", "tenant-a"),
		Client:  Client{ClientID: "client-m", Tenant: "tenant-a", Capability: protocol.Management},
		Server:  &sid, CanonicalResource: "/mcp/management",
	}
	if _, err := Resolve(in, gwReg(t), nil); mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
		t.Fatalf("management with a server must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

// --- binding state machine -------------------------------------------------

func mustResolve(t *testing.T, in ResolveInput, reg *registry.Registry) *ResolvedContext {
	t.Helper()
	ctx, err := Resolve(in, reg, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return ctx
}

func TestBindingStateMachine(t *testing.T) {
	reg := gwReg(t)
	store := NewBindingStore()
	ctx := mustResolve(t, baseGatewayInput(), reg)

	// First bind.
	if _, err := store.Bind("sess-1", ctx); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	// Idempotent equivalent re-bind (a freshly resolved equal identity).
	equiv := mustResolve(t, baseGatewayInput(), reg)
	if _, err := store.Bind("sess-1", equiv); err != nil {
		t.Fatalf("idempotent rebind must succeed: %v", err)
	}
	// A DIFFERENT identity (subject change) is rejected; the existing binding is kept.
	diffIn := baseGatewayInput()
	diffIn.Subject = humanSubject("user-2", "tenant-a")
	diff := mustResolve(t, diffIn, reg)
	if _, err := store.Bind("sess-1", diff); mcperr.ReasonOf(err) != mcperr.ReasonSessionIdentityRebind {
		t.Fatalf("subject rebind must be rejected, got %v", err)
	}
	got, _ := store.Get("sess-1")
	if got.Subject().Human.Subject != "user-1" {
		t.Fatal("rejected rebind altered the binding")
	}
	// Session isolation: another session sees nothing.
	if _, ok := store.Get("sess-2"); ok {
		t.Fatal("session sess-2 must have no binding")
	}
	// Unbind removes it (session close).
	store.Unbind("sess-1")
	if _, ok := store.Get("sess-1"); ok {
		t.Fatal("unbind did not remove the binding")
	}
}

func TestBindingRejectsEachChangeDimension(t *testing.T) {
	reg := gwReg(t)
	store := NewBindingStore()
	base := mustResolve(t, baseGatewayInput(), reg)
	_, _ = store.Bind("s", base)
	mutations := map[string]func(in *ResolveInput){
		"tenant": func(in *ResolveInput) { in.Tenant.ID = "tenant-a" }, // same → still equal (control)
		"client": func(in *ResolveInput) { in.Client.ClientID = "client-other" },
		"agent":  func(in *ResolveInput) { in.Agent = &Agent{AgentID: "a9", Owner: in.Subject.ref()} },
		"resource": func(in *ResolveInput) {
			s := registry.ServerID("srv-1")
			in.Server = &s
			in.CanonicalResource = "/mcp/gateway/other"
		},
	}
	for name, mut := range mutations {
		in := baseGatewayInput()
		mut(&in)
		ctx, err := Resolve(in, reg, nil)
		if err != nil {
			continue // some mutations may be invalid to resolve; skip
		}
		_, bindErr := store.Bind("s", ctx)
		if name == "tenant" {
			if bindErr != nil {
				t.Fatalf("equal-identity control must be idempotent, got %v", bindErr)
			}
			continue
		}
		if mcperr.ReasonOf(bindErr) != mcperr.ReasonSessionIdentityRebind {
			t.Fatalf("%s change must be a rebind rejection, got %v", name, bindErr)
		}
	}
}

func TestBindingConcurrent(t *testing.T) {
	reg := gwReg(t)
	store := NewBindingStore()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := baseGatewayInput()
			in.Subject = humanSubject("user-1", "tenant-a") // same identity per session id
			ctx, err := Resolve(in, reg, nil)
			if err != nil {
				return
			}
			sid := "sess"
			if i%2 == 0 {
				sid = "sess-even"
			}
			_, _ = store.Bind(sid, ctx)
			_, _ = store.Get(sid)
		}(i)
	}
	// Concurrent readers.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = store.Len()
			}
		}()
	}
	wg.Wait()
}

// FuzzResolveIdentity proves principal-chain resolution never panics on arbitrary
// subject/tenant/client strings and never resolves a cross-tenant chain (a client
// or subject tenant differing from the context tenant must always reject).
func FuzzResolveIdentity(f *testing.F) {
	seeds := []struct{ ctxT, subT, cliT string }{
		{"tenant-a", "tenant-a", "tenant-a"},
		{"tenant-a", "tenant-b", "tenant-a"},
		{"tenant-a", "tenant-a", "tenant-b"},
		{"", "", ""},
	}
	for _, s := range seeds {
		f.Add(s.ctxT, s.subT, s.cliT)
	}
	reg := gwReg(f)
	f.Fuzz(func(t *testing.T, ctxT, subT, cliT string) {
		sid := registry.ServerID("srv-1")
		in := ResolveInput{
			Capability: protocol.Gateway, Tenant: Tenant{ID: TenantID(ctxT)},
			Subject: Subject{Kind: SubjectHuman, Human: &Human{Subject: "user-1", Tenant: TenantID(subT), Issuer: "iss", Assurance: AssuranceHigh}},
			Client:  Client{ClientID: "client-g", Tenant: TenantID(cliT), Capability: protocol.Gateway},
			Server:  &sid, CanonicalResource: "/mcp/gateway/srv-1", Issuer: "iss",
		}
		ctx, err := Resolve(in, reg, nil)
		if err == nil {
			// A successful resolution must have a single consistent tenant across
			// context, subject and client — a cross-tenant chain can never resolve.
			if ctxT != subT || ctxT != cliT {
				t.Fatalf("cross-tenant chain resolved: ctx=%q subj=%q cli=%q", ctxT, subT, cliT)
			}
			if string(ctx.TenantID()) != ctxT {
				t.Fatalf("resolved tenant %q != %q", ctx.TenantID(), ctxT)
			}
		}
	})
}

// FuzzBindingStateMachine drives a sequence of bind/unbind operations from
// arbitrary bytes and asserts the core invariants hold for every interleaving:
// a bound identity is immutable, a rejected rebind never mutates the binding, and
// unbind is the only thing that clears it.
func FuzzBindingStateMachine(f *testing.F) {
	reg := gwReg(f)
	a := mustResolveF(f, baseGatewayInput(), reg)
	inB := baseGatewayInput()
	inB.Subject = humanSubject("user-2", "tenant-a")
	b := mustResolveF(f, inB, reg)

	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, ops []byte) {
		store := NewBindingStore()
		var boundFP string
		var isBound bool
		for _, op := range ops {
			switch op % 4 {
			case 0: // bind a
				got, err := store.Bind("s", a)
				assertBindOutcome(t, store, "s", a, got, err, &boundFP, &isBound)
			case 1: // bind b
				got, err := store.Bind("s", b)
				assertBindOutcome(t, store, "s", b, got, err, &boundFP, &isBound)
			case 2: // read
				cur, ok := store.Get("s")
				if ok != isBound {
					t.Fatalf("Get presence %v != tracked %v", ok, isBound)
				}
				if ok && cur.fingerprint != boundFP {
					t.Fatal("bound identity mutated without unbind")
				}
			case 3: // unbind
				store.Unbind("s")
				isBound = false
				boundFP = ""
			}
		}
	})
}

func assertBindOutcome(t *testing.T, store *BindingStore, sid string, want, got *ResolvedContext, err error, boundFP *string, isBound *bool) {
	t.Helper()
	if !*isBound {
		if err != nil {
			t.Fatalf("first bind failed: %v", err)
		}
		*isBound = true
		*boundFP = want.fingerprint
		return
	}
	// Already bound: same fingerprint is idempotent, different is rejected — either
	// way the stored fingerprint must be unchanged.
	if want.fingerprint == *boundFP {
		if err != nil {
			t.Fatalf("equivalent rebind rejected: %v", err)
		}
	} else if mcperr.ReasonOf(err) != mcperr.ReasonSessionIdentityRebind {
		t.Fatalf("different-identity rebind must be rejected, got %v", err)
	}
	cur, _ := store.Get(sid)
	if cur.fingerprint != *boundFP {
		t.Fatal("rebind mutated the bound identity")
	}
	_ = got
}

func mustResolveF(f *testing.F, in ResolveInput, reg *registry.Registry) *ResolvedContext {
	f.Helper()
	ctx, err := Resolve(in, reg, nil)
	if err != nil {
		f.Fatalf("resolve: %v", err)
	}
	return ctx
}
