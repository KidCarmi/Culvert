package main

// object_mutation.go — 2D-A shared-object mutation glue: the handler-side
// error mapping for the engines' MutateDurable primitive (internal/catgroup,
// internal/decryptprofile) and the boot-time denormalized-name reconciliation
// that makes an interrupted rename deterministically recoverable.
//
// Contract (2D-A.0):
//   - a confirmed 2xx on a category-group / decryption-profile mutation means
//     the object mutation is restart-durable (MutateDurable persisted it);
//   - a pre-replacement persist failure rolled the in-memory store back to the
//     previous truth and maps to a 500 here;
//   - an ifVersion mismatch maps to the SAME structured 409 JSON contract as
//     the policy rulebase fence ({error, currentVersion, yourVersion}) so the
//     client sees one optimistic-concurrency shape product-wide;
//   - a name collision maps to 409 (server-authoritative refusal).

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// writeObjectVersionConflict writes the structured optimistic-concurrency 409
// with the SAME JSON keys as writePolicyVersionConflictError, so the frontend's
// conflict decoder handles rulebase and object-store fences identically.
func writeObjectVersionConflict(w http.ResponseWriter, msg string, current, asserted int64) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":          msg,
		"currentVersion": current,
		"yourVersion":    asserted,
	})
}

// writeObjectMutationError maps a MutateDurable failure to its response and
// reports whether a response was written (true = the handler must stop).
//   - *VersionConflictError → structured 409 (fence contract above)
//   - ErrNameTaken → 409 (server-authoritative name-collision refusal)
//   - ErrPersist → 500 (mutation rolled back; nothing durable changed)
//   - anything else → 400 (validation / not-found from the store)
func writeObjectMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var cgConflict *catgroup.VersionConflictError
	var dpConflict *decryptprofile.VersionConflictError
	switch {
	case errors.As(err, &cgConflict):
		writeObjectVersionConflict(w, cgConflict.Error(), cgConflict.Current, cgConflict.Asserted)
	case errors.As(err, &dpConflict):
		writeObjectVersionConflict(w, dpConflict.Error(), dpConflict.Current, dpConflict.Asserted)
	case errors.Is(err, catgroup.ErrNameTaken), errors.Is(err, decryptprofile.ErrNameTaken):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, catgroup.ErrPersist), errors.Is(err, decryptprofile.ErrPersist):
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	return true
}

// writeRenameCascadePersistFailure is the truthful non-2xx for a rename whose
// OBJECT mutation is already durable but whose policy display-name cascade
// could not be persisted (§6: never 2xx while a required durable domain is
// known-failed). Enforcement is unchanged either way — rules link by stable
// object ID — and the divergence is display/export-only: the in-memory names
// are already refreshed, and reconcileObjectRefNames converges the durable
// copy at the next restart (or a later successful policy write does).
func writeRenameCascadePersistFailure(w http.ResponseWriter, objKind string, cause error) {
	http.Error(w,
		"the "+objKind+" rename is durable and rule links (by stable ID) keep enforcement unchanged, "+
			"but a policy display-name refresh could not be persisted: "+cause.Error()+
			" — the names reconcile automatically at the next restart; storage may be degraded",
		http.StatusInternalServerError)
}

// reconcileObjectRefNames re-derives every rule's denormalized object display
// names (running policy AND the open draft candidate) from the ID-authoritative
// object stores, persisting only when something actually changed. Called once
// at startup, AFTER the policy store, draft, category groups, and decryption
// profiles have loaded.
//
// This is the deterministic recovery half of the 2D-A rename model (§7): a
// rename is object-store persist → running cascade persist → draft cascade
// persist, and a crash or write failure between any two phases leaves stale
// DISPLAY names on a later domain while every rule still references the same
// stable object ID (enforcement provably unchanged). The object store is the
// single authority for an object's name, so this pass converges every crash
// point — and any pre-existing drift — to consistent display/export truth.
//
// A refresh that touches running rules advances the running generation (it is
// a real content change that must reach export/DP-sync); if a persisted draft
// is active, its base generation then reads stale — truthful: after a crashed
// rename the operator should re-review the candidate before committing.
func reconcileObjectRefNames() {
	groupNames := make(map[string]string)
	for _, g := range globalCategoryGroups.List() {
		groupNames[g.ID] = g.Name
	}
	profileNames := make(map[string]string)
	for _, p := range globalDecryptionProfiles.List() {
		profileNames[p.ID] = p.Name
	}
	fileProfileNames := make(map[string]string)
	for _, p := range globalProfileStore.List() {
		fileProfileNames[p.ID] = p.Name
	}
	if n := policyStore.RefreshObjectRefNames(groupNames, profileNames, fileProfileNames); n > 0 {
		logger.Printf("Policy: reconciled %d stale denormalized object name(s) on running rules (ID-authoritative)", n)
		if err := policyStore.SaveErr(); err != nil {
			logger.Printf("Policy: reconciled names not persisted (%v) — in-memory truth is correct; will reconcile again next restart", err)
		}
	}
	if n, err := policyDraft.refreshObjectRefNames(groupNames, profileNames, fileProfileNames); n > 0 {
		logger.Printf("PolicyDraft: reconciled %d stale denormalized object name(s) on the candidate", n)
		if err != nil {
			logger.Printf("PolicyDraft: reconciled candidate names not persisted (%v) — in-memory truth is correct; will reconcile again next restart", err)
		}
	}
}
