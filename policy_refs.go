package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// policy_refs.go — generic object dependency walk + the read-only
// GET /api/objects/references endpoint (P0 policy-refs; authority
// roadmap/POLICY-REFS-PLAN.md). Deliberately NOT rule-shaped: the entry
// envelope is the product-wide "Where Used" seam the M3 whereUsed UI
// contract (DESIGN-SYSTEM.md §3) anticipates. The same walk backs the
// block-on-referenced deletes, so a block reason and the endpoint can never
// disagree.

// objectRef is one generic consumer of a shared object. consumerType is an
// open enum (today only access-rule/auth-rule; future: pac, node-group,
// alert-route, cdr-policy, …). id is the consumer's stable identity (the
// rule ULID); detail names the referencing field; view is the SPA view that
// edits the consumer.
type objectRef struct {
	ConsumerType string `json:"consumerType"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Detail       string `json:"detail"`
	View         string `json:"view"`
}

// objectRefType enumerates the shared-object kinds the walk understands.
// Unknown kinds are a caller error (400 at the endpoint).
//
// idp is deliberately NOT here: auth rules reference IdPs by ID
// (Auth.ProviderRefs hold IdP IDs, not names), so a name-keyed walk cannot
// answer it, and IdP deletion is fail-CLOSED already (a dangling providerRef
// fails SSO 403, not open). It joins this walk with the object-ID work that
// makes ID-vs-name references first-class (see roadmap/POLICY-REFS-PLAN.md).
var objectRefTypes = map[string]bool{
	"category":           true,
	"category-group":     true,
	"file-profile":       true,
	"decryption-profile": true,
}

// consumerTypeForRule maps a rule's stage to its whereUsed consumerType/view.
func consumerTypeForRule(r *PolicyRule) (consumerType, view string) {
	if ruleTypeOf(r) == ruleTypeAuth {
		return "auth-rule", "authpolicy"
	}
	return "access-rule", "policy"
}

// objectReferences returns every consumer that references the named object,
// via (found, refs). `found` is FALSE only for an unknown object type — it is
// deliberately distinct from `found==true, len(refs)==0` ("known type, not
// referenced, safe to delete"). Delete callers MUST treat !found as "do not
// proceed": an unknown type silently reported as empty would read as
// safe-to-delete and re-open the fail-open hole the walk exists to close.
//
// Case-insensitive throughout to match the engine's matching (objects are
// referenced by name today; the ULID promotion slice makes id load-bearing).
func objectReferences(objType, name string) (found bool, refs []objectRef) {
	if !objectRefTypes[objType] {
		return false, nil
	}
	if name == "" {
		return true, nil
	}
	// Resolve the object's stable ID ONCE (references-by-id delete-block): a rule
	// may link by ID with a momentarily-stale denormalized name, so the walk must
	// match the ID too, not just the name (else a still-referenced object could be
	// deleted → dangling ref). "" for name-referenced types / not-found.
	objID := resolveObjectID(objType, name)
	rules := policyStore.List()
	for i := range rules {
		r := &rules[i]
		if detail := ruleReferencesObject(r, objType, name, objID); detail != "" {
			consumerType, view := consumerTypeForRule(r)
			refs = append(refs, objectRef{
				ConsumerType: consumerType, ID: r.ID, Name: r.Name,
				Detail: detail, View: view,
			})
		}
	}
	// A category is referenced by TWO kinds of consumer: policy rules
	// (DestCategory, above) AND category groups (membership). Emitting both
	// keeps the walk the single source of truth — the Where-Used endpoint
	// and the URLCat delete block off the same list and can never disagree.
	if objType == "category" {
		refs = append(refs, categoryGroupMembers(name)...)
	}
	sortObjectRefs(refs)
	return true, refs
}

// ruleReferencesObject returns the referencing field name if the rule points
// at the named object of the given type, else "". Case-insensitive to match
// the engine.
// resolveObjectID returns the stable ULID of the named object for the ID-bearing
// object types (references-by-id delete-block), or "" when the type is
// name-referenced or the object is not found. Called ONCE per walk, not per rule.
func resolveObjectID(objType, name string) string {
	if objType == "decryption-profile" {
		if p := globalDecryptionProfiles.GetByName(name); p != nil {
			return p.ID
		}
	}
	// category-group joins here in S2.
	return ""
}

func ruleReferencesObject(r *PolicyRule, objType, name, objID string) string {
	switch objType {
	case "category":
		// CategoryAny ("Any") is the wildcard "any destination", NOT a
		// reference to a concrete category object — the engine only
		// category-matches when DestCategory != CategoryAny (policy.go). A
		// rule set to Any must not appear as a consumer of a category, and an
		// admin-created category literally named "Any" must stay deletable.
		if r.DestCategory != CategoryAny && strings.EqualFold(string(r.DestCategory), name) {
			return "destCategory"
		}
	case "category-group":
		if strings.EqualFold(r.DestCategoryGroup, name) {
			return "destCategoryGroup"
		}
	case "file-profile":
		if strings.EqualFold(string(r.FileProfile), name) {
			return "fileProfile"
		}
	case "decryption-profile":
		if strings.EqualFold(r.DecryptionProfile, name) {
			return "decryptionProfile"
		}
		// ID-first (references-by-id): match a rule that links by the profile's
		// stable ID even if its denormalized name is momentarily stale.
		if objID != "" && r.DecryptionProfileID == objID {
			return "decryptionProfile"
		}
	}
	return ""
}

// categoryGroupMembers returns the category groups whose membership includes
// the named category, as generic consumer entries.
func categoryGroupMembers(name string) []objectRef {
	var refs []objectRef
	for _, g := range globalCategoryGroups.List() {
		for _, c := range g.Categories {
			if strings.EqualFold(c, name) {
				refs = append(refs, objectRef{
					ConsumerType: "category-group", ID: g.ID, Name: g.Name,
					Detail: "categories", View: "catgroups",
				})
				break
			}
		}
	}
	return refs
}

// sortObjectRefs orders by consumerType, then name, then id — deterministic
// across calls so the 409 message, the audit detail, and the endpoint list
// never reorder.
func sortObjectRefs(refs []objectRef) {
	sort.Slice(refs, func(a, b int) bool {
		if refs[a].ConsumerType != refs[b].ConsumerType {
			return refs[a].ConsumerType < refs[b].ConsumerType
		}
		if refs[a].Name != refs[b].Name {
			return refs[a].Name < refs[b].Name
		}
		return refs[a].ID < refs[b].ID
	})
}

// deleteBlockedByReferences enforces referential integrity for a
// shared-object delete: it writes a 409 (and audits the attempt) when the
// object is referenced, AND fails CLOSED when the object type is unknown —
// an unrecognized type means the walk cannot verify safety, so refusing
// beats silently deleting (honoring objectReferences' found contract, which
// a bare `len(refs) > 0` check would discard). Returns true when the caller
// must stop because a response was written.
func deleteBlockedByReferences(w http.ResponseWriter, r *http.Request, objType, name, auditAction string) bool {
	found, refs := objectReferences(objType, name)
	if !found {
		auditEvent(r, auditAction, name, "reference check unavailable for object type "+objType)
		http.Error(w, "cannot verify references for object type "+objType, http.StatusConflict)
		return true
	}
	if len(refs) == 0 {
		return false
	}
	auditEvent(r, auditAction, name, referenceBlockMessage(objType, name, refs))
	writeReferenceBlock(w, objType, name, refs)
	return true
}

// referenceBlockMessage renders the human-readable 409 summary: names the
// first referent and, when there is more than one, the remaining count. The
// referent is described by its consumerType so "used by group X" reads
// correctly alongside "used by policy rule Y".
func referenceBlockMessage(objType, objName string, refs []objectRef) string {
	first := refs[0]
	label := first.Name
	if label == "" {
		label = "(unnamed)"
	}
	kind := map[string]string{
		"access-rule":    "policy rule",
		"auth-rule":      "authentication rule",
		"category-group": "category group",
	}[first.ConsumerType]
	if kind == "" {
		kind = first.ConsumerType
	}
	if len(refs) == 1 {
		return fmt.Sprintf("cannot delete %s %q: referenced by %s %q", objType, objName, kind, label)
	}
	return fmt.Sprintf("cannot delete %s %q: referenced by %s %q and %d other object(s)",
		objType, objName, kind, label, len(refs)-1)
}

// writeReferenceBlock writes the structured 409 for a block-on-referenced
// delete: the same referencedBy shape the endpoint returns, so the P1
// delete-impact dialog (and any future force-delete flow) needs no second
// round-trip. The plain "error" string keeps non-JSON clients informative.
func writeReferenceBlock(w http.ResponseWriter, objType, objName string, refs []objectRef) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":        referenceBlockMessage(objType, objName, refs),
		"object":       map[string]string{"type": objType, "name": objName},
		"referencedBy": refs,
	})
}

// GET /api/objects/references?type=<>&name=<> — read-only dependency walk.
// The generic "Where Used" contract (roadmap/POLICY-REFS-PLAN.md).
func apiObjectReferences(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	objType := strings.TrimSpace(r.URL.Query().Get("type"))
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !objectRefTypes[objType] {
		http.Error(w, "unknown or missing object type", http.StatusBadRequest)
		return
	}
	if name == "" {
		http.Error(w, "name query param required", http.StatusBadRequest)
		return
	}
	_, refs := objectReferences(objType, name)
	if refs == nil {
		refs = []objectRef{} // never null in the JSON — the UI iterates it
	}
	jsonOK(w, map[string]any{
		"object":       map[string]string{"type": objType, "name": name},
		"referencedBy": refs,
	})
}
