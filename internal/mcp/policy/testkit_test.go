package policy

import (
	"testing"
	"time"
)

func testTime() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

// gwInput returns a well-formed Gateway tools/call decision tuple (usable, no drift).
func gwInput() DecisionInput {
	return DecisionInput{
		Capability: CapGateway, PolicyRevision: 1, CatalogRevision: 7,
		RegistryRevision: 3, RuntimeRevision: 1, EvalTime: testTime(),
		Principal: Principal{Kind: SubjectHuman, SubjectID: "user-1", Tenant: "tenant-a",
			Groups: []string{"developers"}, Assurance: AssuranceHigh, Issuer: "https://idp"},
		Client: Client{ClientID: "client-g", Tenant: "tenant-a", Capability: CapGateway, Trust: TrustHigh},
		// Owner MUST equal Principal.Tenant so the default fixture is a valid same-tenant
		// request (QUAL-5 Gateway tenant isolation denies a cross-tenant tuple as a hard
		// override before any user rule).
		Server: &Server{ServerID: "srv-1", Owner: "tenant-a", Environment: "prod",
			Enabled: true, Verification: ServerVerified},
		Tool: &Tool{Name: "read_file", ServerID: "srv-1", FingerprintHash: "abc123",
			Disposition: DispUsable, Drift: DriftNoMaterialChange, Destination: DestinationApproved,
			CredentialPower: PowerReadOnly, Reversibility: Reversible},
		Operation: Operation{Method: "tools/call", Class: OpRead, Namespace: NamespaceGatewayTool,
			Operand: "read_file", DecisionPoint: "policy_engine"},
	}
}

// mgmtInput returns a well-formed Management read operation tuple.
func mgmtInput() DecisionInput {
	return DecisionInput{
		Capability: CapManagement, PolicyRevision: 1, CatalogRevision: 7,
		RuntimeRevision: 1, EvalTime: testTime(),
		Principal: Principal{Kind: SubjectHuman, SubjectID: "admin-1", Tenant: "tenant-a",
			Assurance: AssuranceHigh},
		Client:    Client{ClientID: "client-m", Tenant: "tenant-a", Capability: CapManagement},
		Operation: Operation{Method: "tools/list", Class: OpDiscovery, Namespace: NamespaceManagementOperation, Operand: "list"},
	}
}

// mustCompile compiles a document and fails the test on error.
func mustCompile(t testing.TB, doc string) *Snapshot {
	t.Helper()
	snap, err := Compile([]byte(doc), CreatedMeta{Author: "test"}, DefaultLimits())
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, doc)
	}
	return snap
}

// gwSnap builds a Gateway snapshot with the given rules JSON array body.
func gwSnap(rules string) string {
	return `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[` + rules + `]}`
}

func mgmtSnap(rules string) string {
	return `{"schema_version":1,"capability":"management","policy_revision":1,"default_action":"DENY","rules":[` + rules + `]}`
}

func eval(t testing.TB, snap *Snapshot, in DecisionInput) (Decision, ExplainTrace) {
	t.Helper()
	e := NewEngine(DefaultLimits())
	d, tr, _ := e.Evaluate(snap, &in)
	return d, tr
}
