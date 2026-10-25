package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// historyExportBusy single-flights exports: each one walks the whole store,
// and two at once would only double the read load for the same bytes.
var historyExportBusy atomic.Bool

// apiLogsHistoryExport streams the stored request history sealed under an
// operator-supplied archive passphrase (history_archive.go). POST so the
// passphrase travels in the body, never in a URL or an access log; JSON for
// API clients, a form field for the admin UI (a form post lets the browser
// stream a multi-gigabyte download to disk instead of buffering it). Admin
// only: the archive contains every recorded request.
//
// Once streaming starts the status is committed. A failure after that point
// is audited and then ABORTS the response (http.ErrAbortHandler), so a client
// sees a broken transfer rather than a clean, truncated download — and the
// truncated bytes never authenticate as a complete archive anyway.
func apiLogsHistoryExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	phrase, ok := historyExportPhrase(w, r)
	if !ok {
		return
	}
	s := globalLogStore.Load()
	if s == nil {
		http.Error(w, "request-history saving is not enabled on this node", http.StatusConflict)
		return
	}
	if !historyExportBusy.CompareAndSwap(false, true) {
		http.Error(w, "an export is already running", http.StatusConflict)
		return
	}
	defer historyExportBusy.Store(false)

	now := time.Now()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="culvert-request-history-%s.cvst"`, now.UTC().Format("20060102T150405Z")))
	w.Header().Set("Cache-Control", "no-store")
	res, err := writeHistoryArchive(w, s, phrase, now)
	if err != nil {
		logger.Printf("WARN history export failed after %d records: %s", res.Records, strings.ReplaceAll(err.Error(), "\n", " "))
		auditEvent(r, "logstore.export.failed", "history", fmt.Sprintf("failed after %d records; the partial archive does not authenticate", res.Records))
		panic(http.ErrAbortHandler)
	}
	auditEvent(r, "logstore.export", "history", fmt.Sprintf("%d records exported (encrypted archive), %d oversize records skipped", res.Records, res.Skipped))
}

// historyExportPhrase reads the archive passphrase from a JSON body or a form
// field and enforces its minimum length.
func historyExportPhrase(w http.ResponseWriter, r *http.Request) (string, bool) {
	var phrase string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return "", false
		}
		phrase = r.PostForm.Get("archivePhrase")
	} else {
		var body struct {
			ArchivePhrase string `json:"archivePhrase"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return "", false
		}
		phrase = body.ArchivePhrase
	}
	if len(phrase) < historyArchivePhraseMinLen {
		http.Error(w, fmt.Sprintf("archivePhrase must be at least %d characters", historyArchivePhraseMinLen), http.StatusBadRequest)
		return "", false
	}
	return phrase, true
}
