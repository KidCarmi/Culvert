package main

// pac_fence.go — the 2F-A PAC concurrency-fencing contract shared by every
// PAC mutation handler (profiles, pools, collection creates, the legacy PAC
// config, the lifecycle draft/publish/rollback and the posture exceptions).
//
// One rule, one shape, everywhere:
//   - absent or zero token → 428 {error, code:"precondition_required", current:{<key>: …}}
//   - stale token          → 409 {error, code:"stale",                 current:{<key>: …}}
//   - vanished identity    → 404 (decided by the handler before the fence)
// and a refusal is decided INSIDE the handler's mutation mutex against the
// authoritative store, so it never reflects state the caller read earlier.
// A refusal mutates nothing, audits nothing and advances no config version.
//
// Tokens travel in the JSON body (revision / etag / collectionEtag /
// draftRevision / expectedActiveRevision) or, for bodiless DELETEs and any
// caller that prefers it, as a query parameter of the same name; the query
// parameter wins when both are present.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

const (
	pacFenceCodePreconditionRequired = "precondition_required"
	pacFenceCodeStale                = "stale"
)

// writePACFenceRefusal writes the structured refusal body.
func writePACFenceRefusal(w http.ResponseWriter, status int, code, msg string, current map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort refusal body
		"error":   msg,
		"code":    code,
		"current": current,
	})
}

// pacFenceInt returns the caller's integer precondition token: the query
// parameter wins when present (a malformed one reads as 0 → 428), else the
// decoded body value.
func pacFenceInt(r *http.Request, name string, body int64) int64 {
	if q := r.URL.Query().Get(name); q != "" {
		v, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return body
}

// pacFenceStr returns the caller's string precondition token (query wins).
func pacFenceStr(r *http.Request, name, body string) string {
	if q := r.URL.Query().Get(name); q != "" {
		return q
	}
	return body
}

// pacCheckRevision applies the integer-token contract for key (e.g.
// "revision", "draftRevision"). It returns false after writing the refusal.
func pacCheckRevision(w http.ResponseWriter, key string, token, current int64) bool {
	if token == 0 {
		writePACFenceRefusal(w, http.StatusPreconditionRequired, pacFenceCodePreconditionRequired,
			fmt.Sprintf("precondition required: echo the current %s you loaded (%d)", key, current),
			map[string]any{key: current})
		return false
	}
	if token != current {
		writePACFenceRefusal(w, http.StatusConflict, pacFenceCodeStale,
			fmt.Sprintf("stale %s %d (current %d): the object changed since you loaded it — reload and retry", key, token, current),
			map[string]any{key: current})
		return false
	}
	return true
}

// pacCheckEtag applies the string-token contract for key (e.g. "etag",
// "collectionEtag"). It returns false after writing the refusal.
func pacCheckEtag(w http.ResponseWriter, key, token, current string) bool {
	if token == "" {
		writePACFenceRefusal(w, http.StatusPreconditionRequired, pacFenceCodePreconditionRequired,
			fmt.Sprintf("precondition required: echo the current %s you loaded", key),
			map[string]any{key: current})
		return false
	}
	if token != current {
		writePACFenceRefusal(w, http.StatusConflict, pacFenceCodeStale,
			fmt.Sprintf("stale %s: the collection changed since you loaded it — reload and retry", key),
			map[string]any{key: current})
		return false
	}
	return true
}
