package canary

// FIRST-CANARY CREDENTIAL-FREE PATH (blocker #9).
//
// Blocker #9 asks for one of two proofs before a First Canary: either the exact executable
// policy path requires NO credential, or a real production credential provider/materialization
// path exists and is safe. This file is the pure half of the FIRST disjunct. Nothing here
// claims a production provider exists — the production broker is composed with ZERO providers
// and that is the truthful posture.
//
// WHY THE POLICY PERMIT IS NOT ENOUGH, AND THIS IS THE WHOLE POINT. EvaluateExactPermit already
// refuses a matched rule carrying a CredentialProfile obligation, and by its invariance argument
// that refusal holds for every request the scope admits. But the policy obligation is only ONE
// of three authoritative statements about whether this tool needs a credential, and it is the
// only one any enforcement path reads:
//
//	policy      Decision.Obligations.CredentialProfile — read by execution (run.go profileRef)
//	registry    registry.ServerRecord.CredentialProfile — read by NO enforcement path at all
//	catalog     catalog.Fingerprint.CredentialProfile   — a COPY of the registry value taken at
//	                                                      ingest; reaches enforcement only
//	                                                      through fingerprint equality/drift
//
// So a snapshot in which policy says "no credential" while the authoritative server record says
// the upstream requires one is not a contradiction the engine can see: execution reads the
// policy obligation, finds it empty, takes the no-broker branch, and calls the upstream with NO
// Authorization header. The upstream then either refuses (an activation that cannot execute) or
// — the case that matters — accepts ambient/unauthenticated access, performing a
// credential-REQUIRED operation with no credential planning, no broker gate, and no
// CREDENTIAL_SELECT event. Proving only the policy half would license exactly that.
//
// THE REVIEWED HALF IS STRUCTURAL, NOT A FOURTH FIELD. A reviewed target pins the tool's
// fingerprint DIGEST, and CredentialProfile is one of the hashed fingerprint fields
// (catalog.Fingerprint.Sum). So "the reviewed target requires no credential" is exactly
// "the record whose digest the four-eyes approval bound carries an empty CredentialProfile" —
// which is CatalogCredentialProfile below, given the digest match the reviewed-target binding
// already enforces. There is deliberately no separate reviewed-credential authority to drift
// against the fingerprint.
//
// THE TWO-PUBLICATION WINDOW. The catalog value is a copy taken at ingest and the registry
// publishes independently, so the pair can genuinely disagree in published state — the same
// shape as the repin window the blocker-#13 row answers for Identity. Requiring BOTH to be
// empty answers it in the only direction that is safe: a credential added to the server but not
// yet re-ingested, and a credential removed from the server but still in the fingerprint, are
// both refusals.
//
// This file decides only. It reads no state, holds no engine, and can never permit anything:
// its output is one bounded reason consumed by the readiness table.

// CredentialFreeReason is the bounded classification of WHY the exact First-Canary path is not
// provably credential-free. It is a fixed vocabulary — no profile id, tenant, host or error text
// ever appears, so it is safe on the read-only operator surface. An opaque credential profile
// reference is still a name an operator chose; naming WHICH LAYER objected is what the remedy
// needs, and it is all this says. CredFreeOK is the empty value.
type CredentialFreeReason string

const (
	// CredFreeOK — every authoritative layer agrees the exact First-Canary request needs no
	// credential, so no broker planning, materialization, provider access or Authorization
	// header can arise from it.
	CredFreeOK CredentialFreeReason = ""
	// CredFreeUnavailable — the authoritative facts could not be resolved (no policy snapshot,
	// no coherent inventory capture, no exact tuple). Nothing was established, so the fact is
	// unmet. Distinct from a resolved answer that a credential IS required.
	CredFreeUnavailable CredentialFreeReason = "credential_facts_unavailable"
	// CredFreePolicyObligation — the matched policy decision carries a CredentialProfile
	// obligation, so execution would plan and materialize a credential (run.go: profileRef !=
	// "" ⇒ Broker.Plan → Broker.Materialize → Authorization).
	CredFreePolicyObligation CredentialFreeReason = "policy_requires_credential"
	// CredFreeServerRequires — the authoritative registry server record declares a credential
	// profile. NO enforcement path reads this field, so policy agreeing to "no credential" would
	// send the request to a credential-required upstream with no Authorization at all. This is
	// the layer the policy permit alone cannot see.
	CredFreeServerRequires CredentialFreeReason = "server_requires_credential"
	// CredFreeCatalogRequires — the catalog record whose fingerprint the reviewed approval bound
	// carries a credential profile. Because CredentialProfile is a hashed fingerprint field, this
	// is also the statement "the REVIEWED target requires a credential".
	CredFreeCatalogRequires CredentialFreeReason = "reviewed_target_requires_credential"
	// CredFreeInventoryDisagrees — the registry record and the catalog fingerprint disagree about
	// the credential profile. The fingerprint is a copy taken at ingest and the registry publishes
	// independently, so this is published-state inconsistency, not a stale read: one of the two
	// is describing a credential requirement the other has not caught up with, and which of them
	// is right is not decidable here. Refused rather than guessed.
	CredFreeInventoryDisagrees CredentialFreeReason = "credential_inventory_disagrees"
)

// CredentialFreeInput carries the three authoritative credential statements for the exact
// First-Canary request, captured from ONE coherent inventory read alongside the decision the
// real policy engine returned for that same tuple.
//
// Every field is an OPAQUE profile reference compared only against empty; nothing here
// interprets a profile's meaning. The zero value with Resolved=false is the fail-closed input.
type CredentialFreeInput struct {
	// Resolved reports that all three statements below were captured from authoritative state.
	// False means the resolver could not establish them and the fact is unmet — never that no
	// credential is required.
	Resolved bool
	// PolicyCredentialProfile is Decision.Obligations.CredentialProfile from the SAME decision
	// EvaluateExactPermit judged. It is the only one of the three any enforcement path reads.
	PolicyCredentialProfile string
	// ServerCredentialProfile is registry.ServerRecord.CredentialProfile — what the authoritative
	// server inventory says the upstream requires.
	ServerCredentialProfile string
	// CatalogCredentialProfile is catalog.Fingerprint.CredentialProfile for the exact tool — a
	// hashed fingerprint field, hence also the reviewed target's credential statement.
	CatalogCredentialProfile string
}

// EvaluateCredentialFree returns CredFreeOK when the exact First-Canary request is provably
// credential-free at every authoritative layer, and otherwise the bounded reason naming the
// layer that objected.
//
// The check order runs cheapest-and-most-specific first so the reason an operator reads names
// the layer they can act on: the policy obligation is an operator rule they wrote, the server
// record and catalog fingerprint are inventory. The disagreement check is LAST because it is
// only meaningful once neither side has been rejected on its own terms — by then the pair can
// only disagree if exactly one is empty, which the two preceding checks already cover, so it is
// unreachable on these inputs and is kept as a defense-in-depth statement of the invariant this
// function establishes. TestCredFree_DisagreementIsSubsumedByTheEmptyChecks pins that it is
// subsumed rather than load-bearing, so nobody later reads it as the only thing standing between
// a mismatched inventory and a permit.
func EvaluateCredentialFree(in CredentialFreeInput) CredentialFreeReason {
	if !in.Resolved {
		return CredFreeUnavailable
	}
	if in.PolicyCredentialProfile != "" {
		return CredFreePolicyObligation
	}
	if in.ServerCredentialProfile != "" {
		return CredFreeServerRequires
	}
	if in.CatalogCredentialProfile != "" {
		return CredFreeCatalogRequires
	}
	if in.ServerCredentialProfile != in.CatalogCredentialProfile {
		return CredFreeInventoryDisagrees
	}
	return CredFreeOK
}

// CredentialFreeLayers names every authoritative credential statement EvaluateCredentialFree
// requires to be empty. It exists so a structural wall can assert that the input struct carries
// no unclassified credential field: a new authoritative layer must be added here and checked
// above before it can ride a First-Canary permit, exactly as a new obligation field must be
// classified by PermitSatisfiableObligationFields / PermitRefusedObligationFields.
//
// The order is the check order in EvaluateCredentialFree.
func CredentialFreeLayers() []string {
	return []string{"PolicyCredentialProfile", "ServerCredentialProfile", "CatalogCredentialProfile"}
}
