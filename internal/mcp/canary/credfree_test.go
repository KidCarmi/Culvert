package canary

import (
	"reflect"
	"testing"
)

// credFreeAll returns the ONLY input shape that yields CredFreeOK: resolved, with every
// authoritative credential layer empty. Tests set exactly one layer non-empty to prove each is
// independently load-bearing.
func credFreeAll() CredentialFreeInput { return CredentialFreeInput{Resolved: true} }

// TestCredFree_CanonicalCredentialFreePathIsOK is the POSITIVE CONTROL for every negative below.
// Without it a resolver returning a constant refusal would satisfy the whole negative matrix
// while making the First Canary permanently impossible — the §13 anti-vacuity requirement.
func TestCredFree_CanonicalCredentialFreePathIsOK(t *testing.T) {
	if got := EvaluateCredentialFree(credFreeAll()); got != CredFreeOK {
		t.Fatalf("the canonical credential-free path must be OK, got %q", got)
	}
}

// TestCredFree_EachLayerIsIndependentlyLoadBearing sets one layer non-empty at a time. A
// constant-true resolver fails every row here; a resolver that checks only the policy layer
// fails the two inventory rows — which is precisely the defect blocker #9 names.
func TestCredFree_EachLayerIsIndependentlyLoadBearing(t *testing.T) {
	cases := []struct {
		field string
		want  CredentialFreeReason
	}{
		{"PolicyCredentialProfile", CredFreePolicyObligation},
		{"ServerCredentialProfile", CredFreeServerRequires},
		{"CatalogCredentialProfile", CredFreeCatalogRequires},
	}
	// Parity guard: every string layer on the input must have a case, so a new authoritative
	// credential source cannot arrive unchecked.
	if got := len(CredentialFreeLayers()); got != len(cases) {
		t.Fatalf("CredentialFreeLayers names %d layers but only %d are exercised", got, len(cases))
	}
	for _, tc := range cases {
		in := credFreeAll()
		setStringField(t, &in, tc.field, "profile-x")
		if got := EvaluateCredentialFree(in); got != tc.want {
			t.Fatalf("%s set must yield %q, got %q", tc.field, tc.want, got)
		}
	}
}

// TestCredFree_LayerInventoryIsComplete derives the layer list by reflection over the input
// struct, so adding an authoritative credential field without classifying it fails the build.
// This is the credential twin of TestPermit_EveryObligationFieldIsClassified.
func TestCredFree_LayerInventoryIsComplete(t *testing.T) {
	named := map[string]bool{}
	for _, n := range CredentialFreeLayers() {
		named[n] = true
	}
	ty := reflect.TypeOf(CredentialFreeInput{})
	for i := range ty.NumField() {
		f := ty.Field(i)
		if f.Type.Kind() != reflect.String {
			continue // Resolved is the capture status, not a credential statement
		}
		if !named[f.Name] {
			t.Errorf("CredentialFreeInput.%s is an unclassified credential layer: add it to "+
				"CredentialFreeLayers AND check it in EvaluateCredentialFree", f.Name)
		}
		delete(named, f.Name)
	}
	for n := range named {
		t.Errorf("CredentialFreeLayers names %q but CredentialFreeInput has no such string field", n)
	}
}

// TestCredFree_UnresolvedIsUnavailableNotCredentialFree pins the fail-closed direction: an
// input that could not be captured must NOT read as "no credential required". All-empty strings
// with Resolved=false is exactly the shape a naive resolver would produce on a failed capture.
func TestCredFree_UnresolvedIsUnavailableNotCredentialFree(t *testing.T) {
	if got := EvaluateCredentialFree(CredentialFreeInput{}); got != CredFreeUnavailable {
		t.Fatalf("an unresolved capture must be %q, got %q", CredFreeUnavailable, got)
	}
	// And it must stay unavailable even when the layers happen to be empty AND the caller
	// filled some of them: Resolved is the only thing that makes the statement meaningful.
	in := CredentialFreeInput{PolicyCredentialProfile: "", ServerCredentialProfile: ""}
	if got := EvaluateCredentialFree(in); got != CredFreeUnavailable {
		t.Fatalf("unresolved must outrank empty layers, got %q", got)
	}
}

// TestCredFree_BothMismatchDirectionsAreRefused is the §5 mandatory differential.
//
// Direction A is the dangerous one and the reason this fact exists: policy says no credential
// while the authoritative server record requires one. Execution reads ONLY the policy
// obligation, so it takes the no-broker branch and reaches a credential-required upstream with
// NO Authorization header. Direction B (policy requires, server does not) is also refused —
// "the server happens to allow anonymous access" is never a First-Canary path.
func TestCredFree_BothMismatchDirectionsAreRefused(t *testing.T) {
	a := credFreeAll()
	a.ServerCredentialProfile, a.CatalogCredentialProfile = "profile-x", "profile-x"
	if got := EvaluateCredentialFree(a); got != CredFreeServerRequires {
		t.Fatalf("policy-none/server-requires must be refused as %q, got %q", CredFreeServerRequires, got)
	}
	b := credFreeAll()
	b.PolicyCredentialProfile = "profile-x"
	if got := EvaluateCredentialFree(b); got != CredFreePolicyObligation {
		t.Fatalf("policy-requires/server-none must be refused as %q, got %q", CredFreePolicyObligation, got)
	}
}

// TestCredFree_TwoPublicationWindowIsRefusedInBothDirections covers the registry/catalog pair
// disagreeing. The catalog value is a COPY taken at ingest and the registry publishes
// independently, so the pair can genuinely disagree in published state — the same shape the
// blocker-#13 row answers for Identity. Neither direction may pass.
func TestCredFree_TwoPublicationWindowIsRefusedInBothDirections(t *testing.T) {
	// Credential ADDED to the server, catalog not yet re-ingested.
	added := credFreeAll()
	added.ServerCredentialProfile = "profile-x"
	if got := EvaluateCredentialFree(added); got == CredFreeOK {
		t.Fatal("a credential added to the server but absent from the fingerprint must not be credential-free")
	}
	// Credential REMOVED from the server, fingerprint still carries it.
	removed := credFreeAll()
	removed.CatalogCredentialProfile = "profile-x"
	if got := EvaluateCredentialFree(removed); got == CredFreeOK {
		t.Fatal("a credential still in the fingerprint must not be credential-free even if the server record dropped it")
	}
}

// TestCredFree_DisagreementIsSubsumedByTheEmptyChecks pins that the trailing disagreement check
// is defense-in-depth, not the thing standing between a mismatched inventory and a permit.
//
// This matters because a reader could otherwise conclude the empty-checks are redundant with it
// and delete one. They are not interchangeable: the empty checks are what refuse a
// CONSISTENT inventory that agrees a credential is required, which the disagreement check alone
// would happily pass.
func TestCredFree_DisagreementIsSubsumedByTheEmptyChecks(t *testing.T) {
	// A fully CONSISTENT credential-required inventory: the disagreement check cannot see it.
	consistent := credFreeAll()
	consistent.ServerCredentialProfile, consistent.CatalogCredentialProfile = "profile-x", "profile-x"
	if consistent.ServerCredentialProfile != consistent.CatalogCredentialProfile {
		t.Fatal("fixture error: this case must be a CONSISTENT inventory")
	}
	if got := EvaluateCredentialFree(consistent); got != CredFreeServerRequires {
		t.Fatalf("a consistent credential-required inventory must be refused by the empty check, got %q", got)
	}
	// And every input that reaches the disagreement check has both sides empty, so it is
	// unreachable — asserted by construction over the reachable input space.
	for _, pol := range []string{"", "p"} {
		for _, srv := range []string{"", "s"} {
			for _, cat := range []string{"", "c"} {
				in := CredentialFreeInput{Resolved: true, PolicyCredentialProfile: pol,
					ServerCredentialProfile: srv, CatalogCredentialProfile: cat}
				if EvaluateCredentialFree(in) == CredFreeInventoryDisagrees {
					t.Fatalf("CredFreeInventoryDisagrees became reachable for %+v — the empty "+
						"checks no longer subsume it, so its placement must be re-reasoned", in)
				}
			}
		}
	}
}

// TestCredFree_ReasonsAreBoundedAndDistinct pins that the vocabulary carries no operator-chosen
// value. A profile reference is a name somebody picked; leaking it onto the read-only readiness
// surface is the WK-12/RS-5 defect one subsystem over.
func TestCredFree_ReasonsAreBoundedAndDistinct(t *testing.T) {
	all := []CredentialFreeReason{
		CredFreeOK, CredFreeUnavailable, CredFreePolicyObligation,
		CredFreeServerRequires, CredFreeCatalogRequires, CredFreeInventoryDisagrees,
	}
	seen := map[CredentialFreeReason]bool{}
	for _, r := range all {
		if seen[r] {
			t.Fatalf("duplicate reason %q", r)
		}
		seen[r] = true
	}
	// Drive every reachable input and require the emitted reason to be in the bounded set and
	// to never contain the profile value the input carried.
	const secretish = "profile-super-secret"
	for _, pol := range []string{"", secretish} {
		for _, srv := range []string{"", secretish} {
			for _, cat := range []string{"", secretish} {
				for _, res := range []bool{false, true} {
					got := EvaluateCredentialFree(CredentialFreeInput{Resolved: res,
						PolicyCredentialProfile: pol, ServerCredentialProfile: srv, CatalogCredentialProfile: cat})
					if !seen[got] {
						t.Fatalf("unadvertised reason %q", got)
					}
					if len(got) > 0 && containsSub(string(got), secretish) {
						t.Fatalf("reason %q leaked the profile reference", got)
					}
				}
			}
		}
	}
}

// TestCredFree_IsPureAndDeterministic pins that the verdict is a function of its input alone.
func TestCredFree_IsPureAndDeterministic(t *testing.T) {
	in := credFreeAll()
	in.ServerCredentialProfile = "profile-x"
	first := EvaluateCredentialFree(in)
	for range 64 {
		if got := EvaluateCredentialFree(in); got != first {
			t.Fatalf("verdict is not deterministic: %q then %q", first, got)
		}
	}
	if in != (CredentialFreeInput{Resolved: true, ServerCredentialProfile: "profile-x"}) {
		t.Fatal("EvaluateCredentialFree mutated its input")
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// setStringField sets a named string field on a CredentialFreeInput by reflection, so the
// table above names fields rather than duplicating literal construction.
func setStringField(t *testing.T, in *CredentialFreeInput, field, val string) {
	t.Helper()
	f := reflect.ValueOf(in).Elem().FieldByName(field)
	if !f.IsValid() || f.Kind() != reflect.String {
		t.Fatalf("CredentialFreeInput has no string field %q", field)
	}
	f.SetString(val)
}
