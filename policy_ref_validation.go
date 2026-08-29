package main

// policy_ref_validation.go — reference-target validation under the shared
// side of objectReferenceMutationGate (transactional-integrity correction,
// Blocker B §§6–11).
//
// The gate alone closed only the writer-first serial order (a committed
// reference always blocks the delete's scan). In the DELETE-FIRST order the
// queued reference writer woke after the deletion and committed a reference
// to the just-deleted object — both requests 2xx, and a Deny rule scoped to
// the deleted category silently stopped matching. A reference-creating or
// -changing writer therefore validates its targets AFTER acquiring the
// shared gate and BEFORE committing the reference, so
//
//	target validation → reference mutation → durable/staged success
//
// is one ordered operation against object deletion: a delete cannot land
// between the validation and the commit (it needs the exclusive side), and a
// delete that already won makes the validation fail with a structured 400.
//
// REFERENCE-VALIDITY PREDICATES (§9 — matched to the real runtime
// resolution semantics, never bare store membership):
//
//   - URL category names participate in MULTIPLE authority layers. A rule's
//     DestCategory (and a group's member) matches at eval through the
//     two-tier fusion: the signed effective view / catStore (admin tier) and
//     the UT1 community DB. A name is therefore resolvable if ANY current
//     authority carries it — a catStore object (BuiltIn or admin-created),
//     a class served by the live signed effective view, or a UT1-mapped
//     community category. Deleting a catStore object whose name keeps NO
//     other authority leaves the name unresolvable, and a NEW reference to
//     it must fail; a legitimate feed category is never rejected merely for
//     not being a writable catStore object.
//   - Category groups and decryption profiles are ID-bearing objects whose
//     references resolve ID-first with a documented name fallback
//     (categoryGroupMatchesHostScratch / the profile resolvers): the
//     reference is valid iff the ID or the name resolves in the live store.
//   - File profiles resolve by name through globalProfileStore and then the
//     legacy built-in fileProfileExts map (PolicyRule.FileProfileBlocked);
//     the reference is valid iff either resolves.
//
// Engine-level mutators and the bulk installers stay unvalidated here: bulk
// installs (config import / rollback / CP→DP snapshot apply) hold the gate
// EXCLUSIVELY and apply their whole candidate leaf-first (categories →
// groups → rules), so every reference resolves against the candidate being
// installed — their whole-candidate dependency-ordered application is the
// validation for that path, and re-judging a historical candidate against
// the current node's transient authorities would reject legitimate
// restores. Rule delete/reorder/move remain reference-removing/order-only
// and validate nothing.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// referencedCategoryResolvable is the authoritative predicate for a URL
// category NAME: does a CURRENT category authority resolve it? It mirrors the
// REAL hot-path source model (hostCatScratch.resolveFusion/matchesCategory,
// policy_hostcat.go) exactly — never status.state, never bare store
// membership:
//
//   - effective view INSTALLED: the admin tier is catStore's BuiltIn=false
//     categories ONLY (MatchesHostAdmin), the SaaS tier is the CURRENT view's
//     classes, then UT1. A BuiltIn=true catStore-only name the view does not
//     serve is NOT a live authority — a signed generation may simply not
//     contain that old local category, and a rule keyed on it would never
//     match (fail-open for a Deny intent).
//   - NO view: the full catStore taxonomy (BuiltIn included), then UT1.
//
// The view pointer is read ONCE so the verdict is against one authority
// state.
func referencedCategoryResolvable(name string) bool {
	if name == "" {
		return true // "" = no reference
	}
	if v := saasEffectiveView.Current(); v != nil {
		if builtIn, found := catStore.BuiltInFlag(name); found && !builtIn {
			return true
		}
		if v.HasCategoryName(name) {
			return true
		}
	} else if _, found := catStore.BuiltInFlag(name); found {
		return true
	}
	if communityDB != nil {
		for _, c := range feedsync.MappedCategories() {
			if strings.EqualFold(c, name) {
				return true
			}
		}
	}
	return false
}

// danglingRefError describes one unresolvable reference target.
type danglingRefError struct {
	Type string // "category" | "category-group" | "decryption-profile" | "file-profile"
	Name string
}

func (e *danglingRefError) Error() string {
	return fmt.Sprintf("referenced %s %q does not exist in any current authority", e.Type, e.Name)
}

// validateRuleObjectRefs checks every shared-object reference the FINAL
// SERVER-CANONICAL rule carries. Callers MUST (a) hold the shared side of
// objectReferenceMutationGate and (b) run this AFTER
// stampRuleMetadataForWrite/stampObjectRefIDs, so the rule being validated is
// exactly the rule that persists and no restamp can change what was
// validated.
//
// TRUST BOUNDARY (ID-trust correction): on the interactive write path the
// NAME is the client's intent and object IDs are SERVER-DERIVED ONLY —
// stampObjectRefIDs discards any client-supplied destCategoryGroupId /
// decryptionProfileId and re-derives from the name. Validation therefore
// keys on the NAMES and never consults an ID: a client-supplied ID for an
// unrelated live object must not be able to satisfy validation of a name
// the server cannot resolve (post-stamp, a non-empty ID exists exactly when
// its name resolved). A mismatched name/ID pair binds to the NAME's object,
// per the standing name-intent doctrine.
func validateRuleObjectRefs(r *PolicyRule) *danglingRefError {
	if r.DestCategory != CategoryAny && r.DestCategory != "" &&
		!referencedCategoryResolvable(string(r.DestCategory)) {
		return &danglingRefError{Type: "category", Name: string(r.DestCategory)}
	}
	if r.DestCategoryGroup != "" && globalCategoryGroups.GetByName(r.DestCategoryGroup) == nil {
		return &danglingRefError{Type: "category-group", Name: r.DestCategoryGroup}
	}
	if r.DecryptionProfile != "" && globalDecryptionProfiles.GetByName(r.DecryptionProfile) == nil {
		return &danglingRefError{Type: "decryption-profile", Name: r.DecryptionProfile}
	}
	if r.FileProfile != "" && r.FileProfile != FileProfileNone {
		if globalProfileStore.GetByName(string(r.FileProfile)) == nil {
			if _, legacy := fileProfileExts[r.FileProfile]; !legacy {
				return &danglingRefError{Type: "file-profile", Name: string(r.FileProfile)}
			}
		}
	}
	return nil
}

// writeDanglingRefError renders the structured integrity 400 for a write that
// would commit a dangling reference.
func writeDanglingRefError(w http.ResponseWriter, e *danglingRefError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":         e.Error(),
		"referenceType": e.Type,
		"name":          e.Name,
	})
}

// refuseDanglingRuleRefs is the write-door check for rule create/edit
// handlers: caller must already hold the shared gate. Returns true when the
// response has been written.
func refuseDanglingRuleRefs(w http.ResponseWriter, r *PolicyRule) bool {
	if e := validateRuleObjectRefs(r); e != nil {
		writeDanglingRefError(w, e)
		return true
	}
	return false
}

// refuseDanglingGroupMembers is the write-door check for category-group
// create/membership-edit handlers: every member name must currently resolve
// in some category authority. Caller must already hold the shared gate.
func refuseDanglingGroupMembers(w http.ResponseWriter, categories []string) bool {
	for _, c := range categories {
		if strings.TrimSpace(c) == "" {
			continue
		}
		if !referencedCategoryResolvable(c) {
			writeDanglingRefError(w, &danglingRefError{Type: "category", Name: c})
			return true
		}
	}
	return false
}
