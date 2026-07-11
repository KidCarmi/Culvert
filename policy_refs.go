package main

import (
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
var objectRefTypes = map[string]bool{
	"category":       true,
	"category-group": true,
	"file-profile":   true,
	"idp":            true,
}

// consumerTypeForRule maps a rule's stage to its whereUsed consumerType/view.
func consumerTypeForRule(r *PolicyRule) (consumerType, view string) {
	if ruleTypeOf(r) == ruleTypeAuth {
		return "auth-rule", "authpolicy"
	}
	return "access-rule", "policy"
}

// objectReferences walks every policy rule and returns the consumers that
// reference the named object of the given type. Case-insensitive to match
// the engine's matching (categories/profiles are referenced by name).
// Returns nil for an unknown type — callers that need to distinguish
// "unknown type" from "no referents" check objectRefTypes first.
func objectReferences(objType, name string) []objectRef {
	if name == "" || !objectRefTypes[objType] {
		return nil
	}
	var refs []objectRef
	rules := policyStore.List()
	for i := range rules {
		r := &rules[i]
		consumerType, view := consumerTypeForRule(r)
		add := func(detail string) {
			refs = append(refs, objectRef{
				ConsumerType: consumerType, ID: r.ID, Name: r.Name,
				Detail: detail, View: view,
			})
		}
		switch objType {
		case "category":
			if strings.EqualFold(string(r.DestCategory), name) {
				add("destCategory")
			}
		case "category-group":
			if strings.EqualFold(r.DestCategoryGroup, name) {
				add("destCategoryGroup")
			}
		case "file-profile":
			if strings.EqualFold(string(r.FileProfile), name) {
				add("fileProfile")
			}
		case "idp":
			if r.Auth != nil {
				for _, ref := range r.Auth.ProviderRefs {
					if strings.EqualFold(ref, name) {
						add("providerRefs")
						break
					}
				}
			}
		}
	}
	// Stable order: by rule name then id, so the block reason and the
	// endpoint list are deterministic across calls.
	sort.Slice(refs, func(a, b int) bool {
		if refs[a].Name != refs[b].Name {
			return refs[a].Name < refs[b].Name
		}
		return refs[a].ID < refs[b].ID
	})
	return refs
}

// referenceBlockReason renders the 409 body for a block-on-referenced delete:
// names the first referent and, when there is more than one, the remaining
// count. Empty string means "not referenced — safe to delete".
func referenceBlockReason(objType, objName string, refs []objectRef) string {
	if len(refs) == 0 {
		return ""
	}
	first := refs[0].Name
	if first == "" {
		first = "(unnamed rule)"
	}
	if len(refs) == 1 {
		return fmt.Sprintf("cannot delete %s %q: referenced by policy rule %q", objType, objName, first)
	}
	return fmt.Sprintf("cannot delete %s %q: referenced by policy rule %q and %d other rule(s)",
		objType, objName, first, len(refs)-1)
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
	refs := objectReferences(objType, name)
	if refs == nil {
		refs = []objectRef{} // never null in the JSON — the UI iterates it
	}
	jsonOK(w, map[string]any{
		"object":       map[string]string{"type": objType, "name": name},
		"referencedBy": refs,
	})
}
