package main

// ha_write_gate.go — ADR-0064: a node that cannot show it leads, or a leader
// that is not publish-authorized, accepts no change to DISTRIBUTED
// configuration from the admin API. Independent services stay available: the
// proxy keeps enforcing its last configuration, every read works, and
// authentication, diagnostics, support and the HA endpoints themselves (the
// recovery actions live there) are never refused by this gate.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// haGatedWriteDomains are the uiRoutes domains whose mutations change state a
// leader distributes to the fleet (ConfigSnapshot content, cluster trust).
var haGatedWriteDomains = map[string]bool{
	"policy": true, "security": true, "settings": true, "pac": true,
	"cdr": true, "mcp": true, "cluster": true, "release": true,
}

// haWriteHold reports why distributed-configuration writes are refused right
// now, or held=false. One predicate, consulted by the admin write gate: the
// legacy restart revalidation (part C) and the publication gate (part D).
func haWriteHold() (reason string, held bool) {
	if globalHA.legacyRevalidationPending() {
		r, _ := globalHA.intentGate()
		return r, true
	}
	if ok, why := haPublishAuthorized(); !ok {
		return why, true
	}
	return "", false
}

// haWriteGated reports whether r is a mutation this gate covers.
func haWriteGated(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/cluster/ha") {
		return false // enable / promote / release: the recovery actions
	}
	meta, ok := getC2Index().Lookup(r.URL.Path)
	if !ok || !haGatedWriteDomains[meta.Domain] {
		return false
	}
	pol, ok := meta.PolicyForMethod(r.Method)
	return ok && pol.Mutating
}

// haWriteGateMiddleware refuses gated mutations with 503 and the reason.
func haWriteGateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reason, held := haWriteHold(); held && haWriteGated(r) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  "configuration changes are refused: this node is not authorized to distribute configuration",
				"reason": reason,
				"code":   "ha_write_hold",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// addAuthorityStatus adds the leadership-authority and publication-gate view
// to an HA status response.
func addAuthorityStatus(resp map[string]any) {
	if state, reason := haAuthorityStatus(); state != "" {
		resp["authority"] = state
		resp["authority_reason"] = reason
		resp["authority_action"] = "Wait for the standby to poll this node (automatic), or restore it. " +
			"If the standby is permanently gone, promote this node: POST /api/cluster/ha/promote."
	}
	resp["leadership_held"] = haLeadershipHeld()
	ok, why := haPublishAuthorized()
	resp["publish_authorized"] = ok
	if !ok {
		resp["publish_hold_reason"] = why
	}
	addPublishGateStatus(resp)
}

// apiAssertLegacyLeadership is the promote endpoint's behaviour on a node that
// is revalidating: the operator asserts that the standby is gone and this node
// leads. Admin role was checked by the caller.
func apiAssertLegacyLeadership(w http.ResponseWriter, r *http.Request) {
	if !assertLegacyLeadership() {
		http.Error(w, "promote failed: leadership could not be resumed (see logs)", http.StatusConflict)
		return
	}
	st := globalHA.Status()
	warning := "leadership was asserted by an operator without evidence from the standby: if the standby " +
		"promoted while this node was down, two leaders now exist"
	jsonOK(w, map[string]any{"ok": true, "role": st.Role, "term": st.Term, "warning": warning})
	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: "cluster.ha-promote",
		Object: "self",
		Detail: "operator asserted leadership on a restarted legacy leader (term=" + strconv.FormatUint(st.Term, 10) + "); WARNING: " + warning,
	})
}
