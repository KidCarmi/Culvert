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
	// A category is referenced by TWO kinds of consumer: policy rules
	// (DestCategory, above) AND category groups (membership). The Where-Used
	// endpoint and the delete guard must see both, or the endpoint
	// under-reports and the URLCat delete needs a second, separate check
	// that could disagree with it. Emit group membership as a generic
	// consumer entry (consumerType "category-group") so the walk stays the
	// single source of truth.
	if objType == "category" {
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
	}
	// Stable order: by consumerType, then name, then id — deterministic
	// across calls so the block reason and the endpoint list never reorder.
	sort.Slice(refs, func(a, b int) bool {
		if refs[a].ConsumerType != refs[b].ConsumerType {
			return refs[a].ConsumerType < refs[b].ConsumerType
		}
		if refs[a].Name != refs[b].Name {
			return refs[a].Name < refs[b].Name
		}
		return refs[a].ID < refs[b].ID
	})
	return true, refs
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
