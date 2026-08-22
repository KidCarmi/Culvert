// ui_logs_cursor.go — the ADR-FE-002 Monitor keyset-cursor contract for
// GET /api/logs?source=store. Activated ONLY when the request carries a
// `cursor` parameter (present-but-empty = first page), so every existing
// offset/limit client keeps its exact current behavior and `total` field.
//
// The cursor is OPAQUE and STATELESS: base64url(JSON{v, ts, seq, fp}).
//   - ts/seq name the last-returned history entry (the store's own
//     time-ordered key pair) — no Badger key bytes, file paths, or other
//     datastore internals are exposed, and the decoded pair is VALIDATED
//     against the request's time window before use, so a forged cursor can
//     only reposition pagination inside the same window it already reads.
//   - fp is a bounded fingerprint of the query the cursor belongs to
//     (from/to + every filter param). A cursor presented with different
//     query parameters is refused with 400 — a cursor from query A can
//     never silently page query B.
//   - Decoding is bounded (length cap before base64), malformed input is a
//     controlled 400, and no server-side session state is involved.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// apiLogsCursorDefaultLimit is the Monitor page size (ADR-FE-002: 100).
	apiLogsCursorDefaultLimit = 100
	// apiLogsCursorMaxLimit is deliberately conservative — the legacy 5000
	// offset ceiling is NOT the normal UI behavior.
	apiLogsCursorMaxLimit = 500
	// apiLogsCursorMaxLen bounds cursor decoding (CWE-770).
	apiLogsCursorMaxLen = 256
)

type logsCursor struct {
	V   int    `json:"v"`
	TS  int64  `json:"ts"`
	Seq uint32 `json:"seq"`
	FP  string `json:"fp"`
}

// logsCursorFingerprintParams: every parameter that defines the logical
// query a cursor belongs to. limit/cursor are deliberately excluded (page
// size may vary between pages; the cursor never fingerprints itself).
var logsCursorFingerprintParams = []string{
	"from", "to", "filter", "status", "level", "method", "identity",
	"dec_outcome", "dec_decision_source", "dec_fail_category", "dec_profile_id",
}

// logsQueryFingerprint is a bounded, order-independent fingerprint of the
// logical query (16 hex chars of SHA-256 over the length-framed canonical
// parameter list).
func logsQueryFingerprint(q url.Values) string {
	h := sha256.New()
	for _, p := range logsCursorFingerprintParams {
		v := q.Get(p)
		h.Write([]byte(strconv.Itoa(len(v))))
		h.Write([]byte{0})
		h.Write([]byte(v))
		h.Write([]byte{0xff})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func encodeLogsCursor(c logsCursor) string {
	b, err := json.Marshal(c)
	if err != nil {
		return "" // unreachable for this struct; fail closed to "no cursor"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var (
	errLogsCursorMalformed = errors.New("invalid cursor")
	errLogsCursorMismatch  = errors.New("cursor does not match query")
)

// decodeLogsCursor validates an opaque cursor against the CURRENT query:
// bounded decode, version check, query-fingerprint match, and the ts must
// sit inside the request's effective time window — a cursor can never
// escape the window/filter semantics it was issued under.
func decodeLogsCursor(raw, wantFP string, fromMs, toMsEffective int64) (logsCursor, error) {
	var c logsCursor
	if len(raw) > apiLogsCursorMaxLen {
		return c, errLogsCursorMalformed
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, errLogsCursorMalformed
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, errLogsCursorMalformed
	}
	if c.V != 1 || c.TS <= 0 {
		return c, errLogsCursorMalformed
	}
	if c.FP != wantFP {
		return c, errLogsCursorMismatch
	}
	if fromMs > 0 && c.TS < fromMs {
		return c, errLogsCursorMismatch
	}
	if toMsEffective > 0 && c.TS > toMsEffective {
		return c, errLogsCursorMismatch
	}
	return c, nil
}

// apiLogsServeStoreCursor serves the cursor-mode history page (ADR-FE-002).
// Response: {logs, next_cursor, has_more, history, snapshot_at, limit} —
// deliberately NO total: rendering pagination must never require scanning
// matching history past the page (the old offset path's exact-count cost).
func apiLogsServeStoreCursor(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fromMs, toMs, _, _, errMsg := parseLogQueryWindow(q)
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	limit := apiLogsCursorDefaultLimit
	if lq := q.Get("limit"); lq != "" {
		if v, err := strconv.Atoi(lq); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > apiLogsCursorMaxLimit {
		limit = apiLogsCursorMaxLimit
	}
	snapshotAt := time.Now().UTC().Format(time.RFC3339)

	ls := globalLogStore.Load()
	if ls == nil {
		jsonOK(w, map[string]any{
			"logs": []LogEntry{}, "next_cursor": "", "has_more": false,
			"history": false, "snapshot_at": snapshotAt, "limit": limit,
		})
		return
	}

	fp := logsQueryFingerprint(q)
	var afterTS int64
	var afterSeq uint32
	if raw := strings.TrimSpace(q.Get("cursor")); raw != "" {
		c, err := decodeLogsCursor(raw, fp, fromMs, toMs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		afterTS, afterSeq = c.TS, c.Seq
	}

	page, err := ls.QueryPage(fromMs, toMs, afterTS, afterSeq, limit, buildLogFilterPredicate(q))
	if err != nil {
		logger.Printf("WARN apiLogs: history cursor query: %v", err)
		http.Error(w, "history query error", http.StatusInternalServerError)
		return
	}
	next := ""
	if page.HasMore && len(page.Entries) > 0 {
		next = encodeLogsCursor(logsCursor{V: 1, TS: page.NextTS, Seq: page.NextSeq, FP: fp})
	}
	jsonOK(w, map[string]any{
		"logs": page.Entries, "next_cursor": next, "has_more": page.HasMore,
		"history": true, "snapshot_at": snapshotAt, "limit": limit,
	})
}
