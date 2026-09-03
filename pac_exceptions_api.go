package main

// pac_exceptions_api.go — PAC Exception Intelligence P2: governance API for
// PAC DIRECT bypasses. Attaches owner / reason / business-app / ticket /
// expiry / review cadence to each DIRECT-capable profile so every
// full-security-path bypass is owned, justified, and time-bounded.
//
// The store is NODE-LOCAL operator metadata (not cluster-synced; it does not
// affect the served PAC). Mutations are admin-only, audited, and config-
// versioned. Status (ungoverned/expired/review_due/governed) is computed
// against the DIRECT inventory — only profiles that can actually emit DIRECT
// carry a governance status.
//
// Routes (registerPACRoutes, metadata in ui_routes_meta.go):
//   GET    /api/pac/posture/exceptions        — viewer: governance list + status
//   GET    /api/pac/posture/exceptions/{id}   — viewer: one record
//   PUT    /api/pac/posture/exceptions/{id}   — admin: set governance
//   DELETE /api/pac/posture/exceptions/{id}   — admin: clear governance

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// pacExceptions is the process-wide DIRECT-exception governance store
// (node-local), loaded by the startup slice from <dataDir>/pac_exceptions.json.
var pacExceptions = &pac.ExceptionStore{}

// pacExceptionsMu serializes the read-modify-write of a governance record
// (preserve CreatedAt/CreatedBy across an update).
var pacExceptionsMu sync.Mutex

// pacExceptionFieldMax bounds a free-text governance field (owner/reason/
// businessApp/ticket) — defense-in-depth beyond the middleware body cap.
const pacExceptionFieldMax = 512

// pacDirectCapableMap builds profileID → (directCapable, serving, name) over
// the synthesized legacy default + all custom profiles, reusing the P0
// inventory so governance status can only apply to genuinely DIRECT-capable
// profiles.
func pacDirectCapableMap() map[string]pac.ProfileDirectInventory {
	inv := pacDirectInventory()
	m := make(map[string]pac.ProfileDirectInventory, len(inv.Profiles))
	for i := range inv.Profiles {
		m[inv.Profiles[i].ProfileID] = inv.Profiles[i]
	}
	return m
}

// pacExceptionView is one row of the governance listing.
type pacExceptionView struct {
	ProfileID     string              `json:"profileId"`
	Name          string              `json:"name"`
	Serving       bool                `json:"serving"`
	DirectCapable bool                `json:"directCapable"`
	Status        string              `json:"status"`
	Record        pac.ExceptionRecord `json:"record"`
}

// apiPACExceptions handles GET /api/pac/posture/exceptions — the governance
// list for every DIRECT-capable profile, joined with its record + status.
func apiPACExceptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := pacGovernanceViews(pacDirectCapableMap(), pacExceptions.All(), time.Now().UTC())
	jsonOK(w, map[string]any{"exceptions": out})
}

// pacGovernanceViews joins the DIRECT-capable profiles with their governance
// records into a sorted view list. Non-DIRECT-capable profiles are skipped —
// governance only applies to profiles that can actually emit DIRECT. Pure
// (clock injected) so it is unit-testable without the HTTP layer.
func pacGovernanceViews(capable map[string]pac.ProfileDirectInventory, records map[string]pac.ExceptionRecord, now time.Time) []pacExceptionView {
	out := make([]pacExceptionView, 0, len(capable))
	for id, pinv := range capable {
		if !pinv.DirectCapable {
			continue
		}
		rec := records[id] // zero value when absent
		out = append(out, pacExceptionView{
			ProfileID:     id,
			Name:          pinv.Name,
			Serving:       pinv.Serving,
			DirectCapable: true,
			Status:        rec.Status(now, true),
			Record:        rec,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out
}

// apiPACExceptionItem handles GET/PUT/DELETE /api/pac/posture/exceptions/{id}.
func apiPACExceptionItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/pac/posture/exceptions/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rec, _ := pacExceptions.Get(id)
		rec.ProfileID = id
		capable := pacDirectCapableMap()
		pinv, known := capable[id]
		jsonOK(w, pacExceptionView{
			ProfileID:     id,
			Name:          pinv.Name,
			Serving:       pinv.Serving,
			DirectCapable: known && pinv.DirectCapable,
			Status:        rec.Status(time.Now().UTC(), known && pinv.DirectCapable),
			Record:        rec,
		})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		pacExceptionPut(w, r, id)
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		pacExceptionDelete(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func pacExceptionPut(w http.ResponseWriter, r *http.Request, id string) {
	var in pac.ExceptionRecord
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Governance is only meaningful for a known profile (a custom profile or
	// the legacy default) — reject orphan records.
	capable := pacDirectCapableMap()
	if _, known := capable[id]; !known {
		http.Error(w, "unknown profile: "+sanitizeLog(id), http.StatusNotFound)
		return
	}
	// Normalize free-text fields up front: trim surrounding whitespace so the
	// stored record is clean and the empty check below is authoritative.
	in.Owner = strings.TrimSpace(in.Owner)
	in.Reason = strings.TrimSpace(in.Reason)
	in.BusinessApp = strings.TrimSpace(in.BusinessApp)
	in.Ticket = strings.TrimSpace(in.Ticket)
	// Required governance fields (this is the whole point of the feature).
	if in.Owner == "" || in.Reason == "" {
		writePACIssues(w, "validation failed", []pac.ValidationIssue{
			{Field: "owner", Message: "owner and reason are required to govern a DIRECT exception"},
		})
		return
	}
	// Bound field lengths (defense-in-depth beyond the 1 MiB body cap): this is
	// admin-only node-local metadata, not free-form storage.
	for _, f := range []struct {
		name, val string
	}{{"owner", in.Owner}, {"reason", in.Reason}, {"businessApp", in.BusinessApp}, {"ticket", in.Ticket}} {
		if len(f.val) > pacExceptionFieldMax {
			http.Error(w, fmt.Sprintf("%s too long (max %d chars)", f.name, pacExceptionFieldMax), http.StatusBadRequest)
			return
		}
	}
	if in.ReviewCadenceDays < 0 || in.ReviewCadenceDays > 3650 {
		http.Error(w, "reviewCadenceDays must be between 0 and 3650", http.StatusBadRequest)
		return
	}
	if in.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, in.ExpiresAt); err != nil {
			http.Error(w, "expiresAt must be RFC3339 (e.g. 2026-12-31T00:00:00Z)", http.StatusBadRequest)
			return
		}
	}
	if in.LastReviewedAt != "" {
		if _, err := time.Parse(time.RFC3339, in.LastReviewedAt); err != nil {
			http.Error(w, "lastReviewedAt must be RFC3339", http.StatusBadRequest)
			return
		}
	}

	token := pacFenceInt(r, "revision", in.Revision)
	pacExceptionsMu.Lock()
	defer pacExceptionsMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	actor := sessionAdmin(r)
	prev, existed := pacExceptions.Get(id)
	// 2F-A fence: an existing record must be echoed by the revision it was
	// loaded at (428 absent, 409 stale); the first PUT creates the record and
	// takes no token; a non-zero token for a record that no longer exists
	// means the governance record vanished (404). The store stays OFF
	// config-version rollback and cluster sync — a different property.
	switch {
	case existed:
		if !pacCheckRevision(w, "revision", token, prev.Revision) {
			return
		}
	case token != 0:
		http.NotFound(w, r)
		return
	}

	rec := in
	rec.ProfileID = id
	rec.UpdatedAt = now
	if existed {
		rec.CreatedAt = prev.CreatedAt
		rec.CreatedBy = prev.CreatedBy
		rec.Revision = prev.Revision + 1
	} else {
		rec.CreatedAt = now
		rec.CreatedBy = actor
		rec.Revision = 1
	}
	if err := pacExceptions.Put(rec); err != nil {
		http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	auditEvent(r, "pac.exception_set", id,
		fmt.Sprintf("owner=%q app=%q expires=%q cadence=%d",
			sanitizeLog(rec.Owner), sanitizeLog(rec.BusinessApp), sanitizeLog(rec.ExpiresAt), rec.ReviewCadenceDays))
	// Intentionally NOT saveConfigVersion: this store is node-local and is not
	// on the config-version capture/apply surface, so a version snapshot could
	// neither record nor restore this change — it would be a misleading no-op
	// rollback point. The change is audited above instead.
	jsonOK(w, rec)
}

func pacExceptionDelete(w http.ResponseWriter, r *http.Request, id string) {
	token := pacFenceInt(r, "revision", 0)
	pacExceptionsMu.Lock()
	defer pacExceptionsMu.Unlock()
	prev, ok := pacExceptions.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// 2F-A fence: a DELETE must echo the revision it loaded.
	if !pacCheckRevision(w, "revision", token, prev.Revision) {
		return
	}
	if err := pacExceptions.Delete(id); err != nil {
		http.Error(w, "delete error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	auditEvent(r, "pac.exception_clear", id, "governance cleared")
	// Not versioned — node-local store, see pacExceptionPut.
	w.WriteHeader(http.StatusNoContent)
}
