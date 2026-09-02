package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsync"
	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/KidCarmi/Culvert/internal/rewrite"
)

// blocklistCleanupUnattributed handles DELETE /api/blocklist?scope=unattributed:
// removes entries of UNKNOWN origin — no admin attribution and no per-feed
// attribution. In feed-driven deployments these are legacy imports from
// before the .sources sidecar existed; in deployments that load a static
// blocklist file or restored an old config snapshot they may be operator
// data (Codex P1, PR #447), so this is refused unless at least one feed is
// configured, and the UI warns accordingly. Admin-asserted destructive op.
func blocklistCleanupUnattributed(w http.ResponseWriter, r *http.Request) {
	if len(blFeedSyncer.Feeds()) == 0 {
		http.Error(w, "no blocklist feeds configured — refusing to purge unattributed entries (they may be static-file or imported operator data)", http.StatusConflict)
		return
	}
	removed := bl.RemoveUnattributedFeedEntries()
	logger.Printf("UI: removed %d unattributed blocklist entries", removed)
	auditEvent(r, "blocklist.cleanup.unattributed", fmt.Sprintf("%d host(s)", removed), "")
	saveConfigVersion(sessionAdmin(r), "blocklist.cleanup.unattributed")
	jsonOK(w, map[string]any{"removed": removed})
}

func apiBlocklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		blocklistList(w, r)

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		blocklistAdd(w, r)

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		blocklistDelete(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func blocklistList(w http.ResponseWriter, r *http.Request) {
	entries := bl.ListWithSource()
	// Sort by host for stable output.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Host < entries[j].Host })

	// Optional filters: ?q=keyword&source=manual|feed&limit=N&offset=N
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	sourceFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	// Apply filters.
	filtered := entries
	if q != "" || sourceFilter != "" {
		filtered = make([]BlocklistEntry, 0, 64)
		for _, e := range entries {
			if q != "" && !strings.Contains(e.Host, q) {
				continue
			}
			if sourceFilter != "" && e.Source != sourceFilter {
				continue
			}
			filtered = append(filtered, e)
		}
	}
	total := len(filtered)
	offset, limit := parseListWindow(offsetStr, limitStr, total)
	filtered = filtered[offset:]

	jsonOK(w, map[string]any{
		"entries": filtered[:limit],
		"count":   total,
		"offset":  offset,
		"limit":   limit,
	})
}

// parseListWindow parses pagination query values against total entries:
// offset is clamped to [0, total]; limit defaults to all remaining rows
// (backward-compat with export/import callers that read the full list).
// The limit ceiling MUST be the post-offset remainder — capping at `total`
// would let filtered[:limit] read past the offset reslice (garbage
// zero-value entries, or a slice-bounds panic when the backing array cap
// is tight): a viewer-role GET ?offset=N could crash the proxy (fixed
// independently on main in afb41f1; merged with this refactor). An
// explicit limit=0 is honored and yields an empty page.
func parseListWindow(offsetStr, limitStr string, total int) (offset, limit int) {
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v > 0 {
			offset = v
		}
	}
	if offset > total {
		offset = total
	}
	limit = total - offset
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v >= 0 && v < limit {
			limit = v
		}
	}
	return offset, limit
}

func blocklistAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hosts []string `json:"hosts"` // support bulk add
		Host  string   `json:"host"`  // single add
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	added := 0
	if body.Host != "" {
		body.Hosts = append(body.Hosts, body.Host)
	}
	// Validate-first: collect normalized valid hosts; bail with 400
	// on the first invalid wildcard so a bad entry mid-list never
	// causes a partial mutation. Once all hosts validate, AddManualBulk
	// does ONE save+sidecar write for the whole batch instead of N
	// (Codex P2 on PR #283: per-host Save() turned bulk into
	// O(hosts × blocklist-size) disk work on feed-backed blocklists).
	valid := make([]string, 0, len(body.Hosts))
	for _, h := range body.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if len(h) > 253 {
			logger.Printf("UI: blocklist entry too long, skipped: %q…", sanitizeLog(h[:50]))
			continue
		}
		// Validate wildcard patterns (Finding 1.3).
		if strings.Contains(h, "*") {
			if !isValidBlocklistWildcard(h) {
				http.Error(w, fmt.Sprintf("invalid wildcard pattern %q: only *.example.com format is allowed", sanitizeLog(h)), http.StatusBadRequest)
				return
			}
		}
		valid = append(valid, h)
	}
	added = bl.AddManualBulk(valid)
	for _, h := range valid {
		logger.Printf("UI: blocked %q", sanitizeLog(h))
	}
	auditEvent(r, "blocklist.add", fmt.Sprintf("%d host(s)", added), strings.Join(body.Hosts, ", "))
	saveConfigVersion(sessionAdmin(r), "blocklist.add")
	jsonOK(w, map[string]any{"added": added})
}

func blocklistDelete(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("scope") == "unattributed" {
		blocklistCleanupUnattributed(w, r)
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	// F19: support bulk delete via JSON body with hosts array.
	if host == "" {
		var body struct {
			Hosts []string `json:"hosts"`
		}
		if err := decodeJSON(r, &body); err == nil && len(body.Hosts) > 0 {
			removed := 0
			for _, h := range body.Hosts {
				h = strings.TrimSpace(h)
				if h == "" {
					continue
				}
				bl.Remove(h)
				removed++
			}
			bl.Save()
			logger.Printf("UI: bulk unblocked %d host(s)", removed)
			auditEvent(r, "blocklist.bulk_remove", fmt.Sprintf("%d host(s)", removed), "")
			saveConfigVersion(sessionAdmin(r), "blocklist.bulk_remove")
			jsonOK(w, map[string]any{"removed": removed})
			return
		}
		http.Error(w, "missing host param or hosts body", http.StatusBadRequest)
		return
	}
	bl.Remove(host)
	bl.Save()
	logger.Printf("UI: unblocked %q", sanitizeLog(host))
	auditEvent(r, "blocklist.remove", host, "")
	saveConfigVersion(sessionAdmin(r), "blocklist.remove")
	w.WriteHeader(http.StatusNoContent)
}

// GET/POST /api/blocklist/mode — switch between "block" and "allow" modes.
func apiBlocklistMode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]string{"mode": bl.Mode()})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Mode string `json:"mode"` // "block" or "allow"
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Mode != "block" && body.Mode != "allow" {
			http.Error(w, `mode must be "block" or "allow"`, http.StatusBadRequest)
			return
		}
		bl.SetMode(body.Mode)
		auditEvent(r, "blocklist.mode", body.Mode, "")
		// Snapshot for rollback: BlocklistMode is in the rollback
		// surface (captureConfigBackup at configversion.go:64 +
		// applyConfigBackup at :336-338). Sibling apiBlocklist add /
		// remove handlers in this file already call saveConfigVersion;
		// this omission was flagged as Category B (genuine gap) in
		// roadmap/CONFIG-VERSIONING-TRIAGE.md.
		saveConfigVersion(sessionAdmin(r), "blocklist.mode")
		jsonOK(w, map[string]string{"mode": bl.Mode()})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Blocklist Feed ─────────────────────────────────────────────────────────

// GET    /api/blocklist/feed         → list all configured feeds + status
// POST   /api/blocklist/feed         → add or update a feed (URL + interval)
// DELETE /api/blocklist/feed?url=X   → remove a feed
func apiBlocklistFeed(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		blocklistFeedList(w)

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		blocklistFeedUpsert(w, r)

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		blocklistFeedDelete(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func blocklistFeedList(w http.ResponseWriter) {
	feeds := blFeedSyncer.Feeds()
	out := make([]map[string]any, 0, len(feeds))
	for i := range feeds {
		lastSyncStr := ""
		if !feeds[i].LastSync.IsZero() {
			lastSyncStr = feeds[i].LastSync.UTC().Format(time.RFC3339)
		}
		out = append(out, map[string]any{
			"url":              feeds[i].URL,
			"interval":         feeds[i].Interval.String(),
			"last_sync":        lastSyncStr,
			"last_error":       feeds[i].LastError,
			"imported_count":   feeds[i].ImportedCount,
			"attributed_count": bl.CountByFeedSource(feeds[i].URL),
		})
	}
	jsonOK(w, map[string]any{"feeds": out})
}

func blocklistFeedUpsert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL      string `json:"url"`
		Interval string `json:"interval"` // e.g. "24h", "off"
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.URL == "" {
		http.Error(w, "feed URL is required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(body.URL, "http://") && !strings.HasPrefix(body.URL, "https://") {
		http.Error(w, "feed URL must use http:// or https://", http.StatusBadRequest)
		return
	}
	// SSRF guard: reject URLs pointing at private/loopback addresses.
	u, err := url.Parse(body.URL)
	if err != nil {
		http.Error(w, "invalid feed URL", http.StatusBadRequest)
		return
	}
	host := u.Hostname()
	if err := isPrivateHost(host); err != nil {
		http.Error(w, "feed URL must not point to private/loopback addresses", http.StatusBadRequest)
		return
	}
	var interval time.Duration
	if body.Interval == "" || body.Interval == "off" {
		interval = 0 // disabled
	} else if d, perr := time.ParseDuration(body.Interval); perr == nil && d > 0 {
		interval = d
	} else {
		interval = blFeedDefaultInterval
	}
	blFeedSyncer.SetFeed(body.URL, interval)
	auditEvent(r, "blocklist.feed.set", body.URL, "")
	adminSettingsSave()
	jsonOK(w, map[string]any{"ok": true, "url": body.URL, "interval": interval.String()})
}

// DELETE /api/blocklist/feed?url=X                 → remove feed config only
// DELETE /api/blocklist/feed?url=X&purge=entries   → also remove the entries it imported
func blocklistFeedDelete(w http.ResponseWriter, r *http.Request) {
	feedURL := r.URL.Query().Get("url")
	if feedURL == "" {
		http.Error(w, "url query parameter is required", http.StatusBadRequest)
		return
	}
	if !blFeedSyncer.RemoveFeed(feedURL) {
		http.Error(w, "feed not found", http.StatusNotFound)
		return
	}
	purged := 0
	if r.URL.Query().Get("purge") == "entries" {
		purged = bl.RemoveByFeedSource(feedURL)
		logger.Printf("UI: feed %q deleted, purged %d attributed entries", sanitizeLog(feedURL), purged)
	}
	auditEvent(r, "blocklist.feed.delete", feedURL, fmt.Sprintf("purged %d attributed entries", purged))
	adminSettingsSave()
	jsonOK(w, map[string]any{"ok": true, "purged": purged})
}

// POST /api/blocklist/feed/sync        → sync all feeds now (synchronous)
// POST /api/blocklist/feed/sync?url=X  → sync one feed now
func apiBlocklistFeedSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	feedURL := r.URL.Query().Get("url")
	var count int
	var err error
	if feedURL != "" {
		count, err = blFeedSyncer.SyncFeed(feedURL)
	} else {
		count, err = blFeedSyncer.SyncAll()
	}
	auditEvent(r, "blocklist.feed.sync", feedURL, "")
	if err != nil {
		http.Error(w, "sync failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "domains_synced": count})
}

// GET /api/blocklist/exceptions        → list all exception hosts
// POST /api/blocklist/exceptions       → add exception(s)  body: {host} or {hosts:[]}
// DELETE /api/blocklist/exceptions?host=X → remove one exception
func apiBlocklistExceptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		hosts := bl.ListExceptions()
		jsonOK(w, map[string]any{"hosts": hosts, "count": len(hosts)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Host  string   `json:"host"`
			Hosts []string `json:"hosts"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Host != "" {
			body.Hosts = append(body.Hosts, body.Host)
		}
		added := 0
		for _, h := range body.Hosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if len(h) > 253 {
				logger.Printf("UI: exception entry too long, skipped: %q…", sanitizeLog(h[:50]))
				continue
			}
			bl.AddException(h)
			logger.Printf("UI: blocklist exception added %q", sanitizeLog(h))
			added++
		}
		auditEvent(r, "blocklist.exception.add", fmt.Sprintf("%d host(s)", added), strings.Join(body.Hosts, ", "))
		jsonOK(w, map[string]any{"ok": true, "added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "host required", http.StatusBadRequest)
			return
		}
		bl.RemoveException(host)
		logger.Printf("UI: blocklist exception removed %q", sanitizeLog(host))
		auditEvent(r, "blocklist.exception.remove", host, "")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── URL Categories ─────────────────────────────────────────────────────────

// GET/POST/PUT/DELETE /api/urlcat
// GET/POST/PUT/DELETE /api/category-groups - manage named category groups.
func apiCategoryGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		// One coherent snapshot: groups, names, and the fence version must
		// describe the SAME store state — List()/Names()/Version() are three
		// independent reads a writer can land between, handing the client rows
		// from one state paired with the successor's fence value (POST-2D-A
		// COHERENT-READ CORRECTION DISCOVERED DURING 2D-B REVIEW).
		snap := globalCategoryGroups.SnapshotView()
		jsonOK(w, map[string]any{
			"groups":  snap.Groups,
			"names":   snap.Names,
			"version": snap.Version,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// Blocker B (shared side): group membership REFERENCES categories —
		// creating one must not interleave with a category delete's
		// scan-and-delete decision.
		refWriteLock()
		defer refWriteUnlock()
		var body struct {
			Name       string   `json:"name"`
			Categories []string `json:"categories"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Blocker B delete-first order: every member category must currently
		// resolve in some category authority — validated under the shared
		// gate, before the commit.
		if refuseDanglingGroupMembers(w, body.Categories) {
			return
		}
		// Durable-or-nothing (2D-A.0): the fence check (optional ?ifVersion=),
		// the mutation, and the persist run in one serialized critical section;
		// a persist failure rolls the store back and maps to 500 — a confirmed
		// 2xx means the group is restart-durable.
		var g *CategoryGroup
		err := globalCategoryGroups.MutateDurable(parseIfVersion(r), func() error {
			created, aerr := globalCategoryGroups.Add(body.Name, body.Categories)
			if aerr != nil {
				return aerr
			}
			g = created
			return nil
		})
		if writeObjectMutationError(w, err) {
			return
		}
		auditEvent(r, "category-group.create", g.Name, fmt.Sprintf("%d categories", len(g.Categories)))
		saveConfigVersion(sessionAdmin(r), "category-group.create")
		jsonOK(w, map[string]any{"ok": true, "group": g, "version": globalCategoryGroups.Version()})

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// Blocker B (shared side): membership edits CHANGE which categories a
		// group references (and the rename cascade rewrites rule references).
		refWriteLock()
		defer refWriteUnlock()
		var body struct {
			Name       string   `json:"name"`
			Categories []string `json:"categories"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Blocker B delete-first order: membership edits must reference
		// currently-resolvable categories (validated under the shared gate).
		if refuseDanglingGroupMembers(w, body.Categories) {
			return
		}
		// Prefer stable-ID addressing (rename-safe) when ?id= is supplied; fall
		// back to name for legacy clients. Mirrors the policy ?id= path (#695).
		if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
			before := globalCategoryGroups.GetByID(id)
			if before == nil {
				http.Error(w, "group not found", http.StatusNotFound)
				return
			}
			// Rename (references-by-id S2): UpdateByID keeps the current name, so a
			// name change must be applied explicitly via Rename (re-keys the store)
			// and cascaded onto referencing rules. Rules link by the group ID, so
			// matching survives regardless; the cascade keeps the denormalized name
			// honest for display/export/DP-sync.
			newName := strings.TrimSpace(body.Name)
			renamed := newName != "" && !strings.EqualFold(newName, before.Name)
			// Phase 1 — the OBJECT domain, durable-or-nothing (2D-A.0): content
			// update + rename apply and persist in one serialized critical section
			// under the optional ?ifVersion= fence. Validation rejects before any
			// state changes; a persist failure rolls everything back (500); a name
			// collision is refused under the store lock (409, no TOCTOU).
			err := globalCategoryGroups.MutateDurable(parseIfVersion(r), func() error {
				if uerr := globalCategoryGroups.UpdateByID(id, body.Categories); uerr != nil {
					return uerr
				}
				if renamed {
					if _, rerr := globalCategoryGroups.Rename(id, newName); rerr != nil {
						return rerr
					}
				}
				return nil
			})
			if writeObjectMutationError(w, err) {
				return
			}
			detail := fmt.Sprintf("%d categories", len(body.Categories))
			// Phase 2/3 — the rename cascade onto RUNNING policy and the open
			// draft candidate (composed cross-store operation, §6/§7): each is a
			// real policy mutation that must survive a restart, so both persists
			// are error-aware. A failure after the durable object rename keeps the
			// (correct) in-memory cascade, is surfaced as a truthful 500 — never a
			// 2xx with a known-failed durable domain — and converges at the next
			// restart via reconcileObjectRefNames (the object store owns name truth).
			var cascadeErr error
			if renamed {
				if n := policyStore.CascadeDestCategoryGroupRename(id, before.Name, newName); n > 0 {
					if perr := policyStore.SaveErr(); perr != nil && !errors.Is(perr, fileutil.ErrReplacedNotSynced) {
						cascadeErr = fmt.Errorf("running policy: %w", perr)
					}
				}
				if derr := policyDraft.cascadeDestCategoryGroupRename(id, before.Name, newName); derr != nil {
					if cascadeErr != nil {
						cascadeErr = fmt.Errorf("%w; draft candidate: %w", cascadeErr, derr)
					} else {
						cascadeErr = fmt.Errorf("draft candidate: %w", derr)
					}
				}
				detail += ", renamed from " + sanitizeLog(before.Name)
			}
			auditName := before.Name
			if renamed {
				auditName = newName
			}
			if cascadeErr != nil {
				auditEventDiffID(r, "category-group.update", auditName, id,
					detail+" — rename durable but display-name cascade not persisted: "+cascadeErr.Error(), nil, nil)
				writeRenameCascadePersistFailure(w, "category group", cascadeErr)
				return
			}
			auditEventDiffID(r, "category-group.update", auditName, id, detail, nil, nil)
			saveConfigVersion(sessionAdmin(r), "category-group.update")
			jsonOK(w, map[string]any{"ok": true, "version": globalCategoryGroups.Version()})
			return
		}
		if err := globalCategoryGroups.MutateDurable(nil, func() error {
			return globalCategoryGroups.Update(body.Name, body.Categories)
		}); writeObjectMutationError(w, err) {
			return
		}
		auditEvent(r, "category-group.update", body.Name, fmt.Sprintf("%d categories", len(body.Categories)))
		saveConfigVersion(sessionAdmin(r), "category-group.update")
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// Blocker B: reference scan + durable delete as one atomic decision
		// under the exclusive side of the reference-integrity gate.
		refScanDeleteLock()
		defer refScanDeleteUnlock()
		// Stable-ID addressing (rename-safe); resolve to the current name for the
		// reference-integrity check + audit, then delete by id.
		if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
			before := globalCategoryGroups.GetByID(id)
			if before == nil {
				http.Error(w, "group not found", http.StatusNotFound)
				return
			}
			if deleteBlockedByReferences(w, r, "category-group", before.Name, "category-group.remove.blocked") {
				return
			}
			var name string
			err := globalCategoryGroups.MutateDurable(parseIfVersion(r), func() error {
				n, derr := globalCategoryGroups.DeleteByID(id)
				name = n
				return derr
			})
			if writeObjectMutationError(w, err) {
				return
			}
			auditEventDiffID(r, "category-group.delete", name, id, "", nil, nil)
			saveConfigVersion(sessionAdmin(r), "category-group.delete")
			jsonOK(w, map[string]any{"ok": true, "version": globalCategoryGroups.Version()})
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		// Referential integrity (policy-refs P0): block via the shared
		// objectReferences walk so this 409 and GET /api/objects/references
		// stay a single source of truth.
		if deleteBlockedByReferences(w, r, "category-group", name, "category-group.remove.blocked") {
			return
		}
		if err := globalCategoryGroups.MutateDurable(nil, func() error {
			return globalCategoryGroups.Delete(name)
		}); writeObjectMutationError(w, err) {
			return
		}
		auditEvent(r, "category-group.delete", name, "")
		saveConfigVersion(sessionAdmin(r), "category-group.delete")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiDecryptionProfiles is the CRUD handler for named SSL-decryption profiles
// (the PAN-OS-style "how to decrypt" object rules reference). Mirrors
// apiCategoryGroups: GET viewer / POST·PUT·DELETE operator, engine-side
// validation surfaced as 400, saveConfigVersion after each mutating auditEvent,
// and delete blocked while a rule references it (shared objectReferences walk).
func apiDecryptionProfiles(w http.ResponseWriter, r *http.Request) { //nolint:cyclop,funlen // CRUD handler: one branch per HTTP method is intentional
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		// One coherent snapshot — same coherent-read contract as the category-
		// group list (POST-2D-A COHERENT-READ CORRECTION DISCOVERED DURING
		// 2D-B REVIEW): rows, names, and the fence version from one lock hold.
		snap := globalDecryptionProfiles.SnapshotView()
		jsonOK(w, map[string]any{
			"profiles": snap.Profiles,
			"names":    snap.Names,
			"version":  snap.Version,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var p DecryptionProfile
		if err := decodeJSON(r, &p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Durable-or-nothing (2D-A.0): fence + mutation + persist in one
		// serialized critical section; persist failure rolls back (500), name
		// collision refuses under the store lock (409).
		var created *DecryptionProfile
		err := globalDecryptionProfiles.MutateDurable(parseIfVersion(r), func() error {
			c, aerr := globalDecryptionProfiles.Add(p)
			if aerr != nil {
				return aerr
			}
			created = c
			return nil
		})
		if writeObjectMutationError(w, err) {
			return
		}
		auditEvent(r, "decryption-profile.create", created.Name, "")
		saveConfigVersion(sessionAdmin(r), "decryption-profile.create")
		jsonOK(w, map[string]any{"ok": true, "profile": created, "version": globalDecryptionProfiles.Version()})

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// Blocker B (shared side): the rename cascade REWRITES rule
		// references, so a profile update must not interleave with a
		// concurrent object delete's scan-and-delete decision.
		refWriteLock()
		defer refWriteUnlock()
		var p DecryptionProfile
		if err := decodeJSON(r, &p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Prefer stable-ID addressing (rename-safe) when ?id= is supplied; fall
		// back to name for legacy clients. Mirrors the policy/category-group path.
		if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
			before := globalDecryptionProfiles.GetByID(id)
			if before == nil {
				http.Error(w, "profile not found", http.StatusNotFound)
				return
			}
			// Rename (references-by-id): UpdateByID keeps the current name, so a
			// name change must be applied explicitly via Rename (re-keys the store)
			// and cascaded onto referencing rules. Rules link by the profile ID, so
			// matching survives regardless; the cascade keeps the denormalized name
			// honest for display/export/DP-sync.
			newName := strings.TrimSpace(p.Name)
			renamed := newName != "" && !strings.EqualFold(newName, before.Name)
			// Phase 1 — the OBJECT domain, durable-or-nothing (2D-A.0): content
			// update (validates first — no partial state where the name changed but
			// the content bounced) + rename apply and persist in one serialized
			// critical section under the optional ?ifVersion= fence. Persist
			// failure rolls back (500); a name collision is refused under the
			// store lock (409, no TOCTOU).
			err := globalDecryptionProfiles.MutateDurable(parseIfVersion(r), func() error {
				if uerr := globalDecryptionProfiles.UpdateByID(id, p); uerr != nil {
					return uerr
				}
				if renamed {
					if _, rerr := globalDecryptionProfiles.Rename(id, newName); rerr != nil {
						return rerr
					}
				}
				return nil
			})
			if writeObjectMutationError(w, err) {
				return
			}
			detail := ""
			// Phase 2/3 — the rename cascade onto RUNNING policy and the open
			// draft candidate (§6/§7): error-aware persists; a failure after the
			// durable object rename keeps the correct in-memory cascade, surfaces
			// a truthful 500 (never 2xx with a known-failed durable domain), and
			// converges at the next restart via reconcileObjectRefNames.
			var cascadeErr error
			if renamed {
				if n := policyStore.CascadeDecryptionProfileRename(id, before.Name, newName); n > 0 {
					if perr := policyStore.SaveErr(); perr != nil && !errors.Is(perr, fileutil.ErrReplacedNotSynced) {
						cascadeErr = fmt.Errorf("running policy: %w", perr)
					}
				}
				if derr := policyDraft.cascadeDecryptionProfileRename(id, before.Name, newName); derr != nil {
					if cascadeErr != nil {
						cascadeErr = fmt.Errorf("%w; draft candidate: %w", cascadeErr, derr)
					} else {
						cascadeErr = fmt.Errorf("draft candidate: %w", derr)
					}
				}
				detail = "renamed from " + sanitizeLog(before.Name)
			}
			auditName := before.Name
			if renamed {
				auditName = newName
			}
			if cascadeErr != nil {
				auditEventDiffID(r, "decryption-profile.update", auditName, id,
					detail+" — rename durable but display-name cascade not persisted: "+cascadeErr.Error(), nil, nil)
				writeRenameCascadePersistFailure(w, "decryption profile", cascadeErr)
				return
			}
			auditEventDiffID(r, "decryption-profile.update", auditName, id, detail, nil, nil)
			saveConfigVersion(sessionAdmin(r), "decryption-profile.update")
			jsonOK(w, map[string]any{"ok": true, "version": globalDecryptionProfiles.Version()})
			return
		}
		if err := globalDecryptionProfiles.MutateDurable(nil, func() error {
			return globalDecryptionProfiles.Update(p)
		}); writeObjectMutationError(w, err) {
			return
		}
		auditEvent(r, "decryption-profile.update", p.Name, "")
		saveConfigVersion(sessionAdmin(r), "decryption-profile.update")
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// Blocker B: reference scan + durable delete as one atomic decision
		// under the exclusive side of the reference-integrity gate.
		refScanDeleteLock()
		defer refScanDeleteUnlock()
		// Stable-ID addressing (rename-safe); resolve to the current name for the
		// reference-integrity check + audit, then delete by id.
		if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
			before := globalDecryptionProfiles.GetByID(id)
			if before == nil {
				http.Error(w, "profile not found", http.StatusNotFound)
				return
			}
			if deleteBlockedByReferences(w, r, "decryption-profile", before.Name, "decryption-profile.remove.blocked") {
				return
			}
			var name string
			err := globalDecryptionProfiles.MutateDurable(parseIfVersion(r), func() error {
				n, derr := globalDecryptionProfiles.DeleteByID(id)
				name = n
				return derr
			})
			if writeObjectMutationError(w, err) {
				return
			}
			auditEventDiffID(r, "decryption-profile.delete", name, id, "", nil, nil)
			saveConfigVersion(sessionAdmin(r), "decryption-profile.delete")
			jsonOK(w, map[string]any{"ok": true, "version": globalDecryptionProfiles.Version()})
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		// Referential integrity: block while any rule references it, via the shared
		// objectReferences walk so this 409 and GET /api/objects/references stay a
		// single source of truth.
		if deleteBlockedByReferences(w, r, "decryption-profile", name, "decryption-profile.remove.blocked") {
			return
		}
		if err := globalDecryptionProfiles.MutateDurable(nil, func() error {
			return globalDecryptionProfiles.Delete(name)
		}); writeObjectMutationError(w, err) {
			return
		}
		auditEvent(r, "decryption-profile.delete", name, "")
		saveConfigVersion(sessionAdmin(r), "decryption-profile.delete")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiDecryptionExclusions is the read-mostly surface over the adaptive
// decryption-exclusion cache (internal/autoexclude): learned hosts that a
// fail-open rule currently bypasses inspection for. GET (viewer) lists the active
// entries with their blast-radius (reason, hit count, learned/expires) plus the
// cache posture (Stats) so an operator can prove the configuration. DELETE
// (operator) evicts one host (?host=) or clears all — both audit, so C2c does not
// flag audit_missing. The cache is VOLATILE runtime state (not persisted, not
// synced, off every config surface), so there is intentionally no create/update
// path and no saveConfigVersion.
func apiDecryptionExclusions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		// Affirmative provable-OFF / over-adoption evidence: how many profiles opt
		// into fail-open and how many rules reference them. 0/0 ⇒ nothing can ever
		// auto-disable inspection (an empty cache alone does not prove this).
		foProfiles, foRules := failOpenFootprint()
		// ONE Stats snapshot: the stats block AND the tunables revision derive
		// from it, so the served {current values, revision} pair is coherent
		// (2E-B §D — the revision must fingerprint exactly the returned state).
		stats := autoExclude().Stats()
		exclusions := autoExclude().List()
		// Bounded management read (2E-B §E): ?limit= caps the entry corpus a
		// browser is handed (the cache itself is bounded by max_entries, which an
		// admin may raise to 262144 — far past a sane management payload). Absent
		// ⇒ the legacy full listing. stats.active keeps the full population.
		truncated := false
		if limStr := strings.TrimSpace(r.URL.Query().Get("limit")); limStr != "" {
			lim, err := strconv.Atoi(limStr)
			if err != nil || lim < 1 {
				http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
				return
			}
			if len(exclusions) > lim {
				exclusions = exclusions[:lim]
				truncated = true
			}
		}
		// Resolve each scope's CURRENT profile name + rule-count blast radius by ID
		// (a rename keeps the profile ID; the entry's cached ScopeName may be stale).
		// Both maps are keyed by scope ID; the UI prefers the current name.
		idToName := make(map[string]string)
		profs := globalDecryptionProfiles.List()
		for i := range profs {
			idToName[profs[i].ID] = profs[i].Name
		}
		scopeRules := make(map[string]int)
		scopeNames := make(map[string]string)
		for i := range exclusions {
			sid := exclusions[i].ScopeID
			if _, done := scopeRules[sid]; done || sid == "" {
				continue
			}
			name := idToName[sid]
			if name == "" {
				// Profile was deleted: DO NOT populate scope_names[sid] — its absence
				// is the signal the UI uses to badge the row "deleted" (it falls back
				// to the entry's cached ScopeName for display). Blast radius is 0.
				scopeRules[sid] = 0
				continue
			}
			scopeNames[sid] = name
			_, refs := objectReferences("decryption-profile", name)
			scopeRules[sid] = len(refs)
		}
		jsonOK(w, map[string]any{
			"exclusions":         exclusions,
			"truncated":          truncated,
			"stats":              stats,
			"tunables_revision":  autoExcludeTunablesRevisionOf(autoExcludeTunablesFromStats(stats)),
			"fail_open_profiles": foProfiles,
			"fail_open_rules":    foRules,
			"scope_rule_counts":  scopeRules, // keyed by scope_id
			"scope_names":        scopeNames, // scope_id -> current display name
		})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		scope := strings.TrimSpace(r.URL.Query().Get("scope"))
		if host != "" {
			// Evict one (scope, host). scope is the owning decryption-profile ID.
			removed := autoExclude().Remove(scope, host)
			// Audit truth (2E-B §I): the record reflects what actually happened —
			// a request for an absent entry is not an eviction.
			detail := "manual eviction of a learned exclusion"
			if !removed {
				detail = "eviction requested; entry was not present"
			}
			auditEvent(r, "decryption.autoexclude.evict", scope+"/"+host, detail)
			jsonOK(w, map[string]any{"ok": true, "removed": removed})
			return
		}
		n := autoExclude().Clear()
		auditEvent(r, "decryption.autoexclude.clear", "*", fmt.Sprintf("cleared %d learned exclusion(s)", n))
		jsonOK(w, map[string]any{"ok": true, "cleared": n})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiDecryptionExclusionTunables is the F10 admin surface for the auto-exclusion
// cache PARAMETERS (confirmN / TTL / pinnedTTL / window / maxEntries). It is the
// FIRST reachable-by-product entry point of the F10 feature.
//
//   - GET (viewer): returns DEFAULTS + BOUNDS + a small schema only. The CURRENT
//     effective values are NOT duplicated here — they remain the single source of
//     truth on /api/decryption-exclusions (the Stats block). This avoids two
//     surfaces disagreeing about the live values.
//   - PUT (admin): a full effective-set replacement. Each omitted/zero field resets
//     to its default (so "Reset to Defaults" is a PUT of all-zeros); a NEGATIVE is
//     rejected. The RESOLVED set is validated against the bounds contract
//     (confirm_n>=2, max_entries<=262144, pinned_ttl<=ttl, …) — 400 on any violation.
//
// Consistency model (the transaction order): VALIDATE → PERSIST target → APPLY
// runtime. The durable write is the only fallible step, so it goes FIRST: on a
// persist failure the live cache is never touched, a 500 is returned, and runtime +
// disk still agree on the OLD value. Only after a successful persist is the target
// applied via Reconfigure, which is infallible (always yields a valid state) — so a
// committed durable value is always reflected in the runtime. There is no rollback
// branch and, critically, no eviction-then-strand window: an operator who lowers
// max_entries below the current active count keeps every learned exclusion if the
// write fails (persist-before-apply — see Codex review on PR #752). NO
// saveConfigVersion (the tunables are OFF the rollback surface); auditEventDiff
// records old→new so the change is attributable.
func apiDecryptionExclusionTunables(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"defaults": defaultAutoExcludeTunables(),
			"bounds": map[string]map[string]int{
				"confirm_n":       {"min": autoExcludeConfirmNMin, "max": autoExcludeConfirmNMax},
				"ttl_secs":        {"min": autoExcludeTTLSecsMin, "max": autoExcludeTTLSecsMax},
				"pinned_ttl_secs": {"min": autoExcludePinnedSecsMin, "max": autoExcludeTTLSecsMax}, // upper bound is ttl_secs (cross-field)
				"window_secs":     {"min": autoExcludeWindowSecsMin, "max": autoExcludeWindowSecsMax},
				"max_entries":     {"min": autoExcludeMaxEntriesMin, "max": autoExcludeMaxEntriesMax},
			},
			// Where to read the CURRENT effective values (single source of truth).
			"current_values_source": "/api/decryption-exclusions (stats)",
			"note":                  "PUT is a full replacement; an omitted/zero field resets to its default. pinned_ttl_secs must not exceed ttl_secs.",
		})

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var patch autoExcludeTunables
		if err := decodeJSON(r, &patch); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		resolved := resolveAutoExcludeTunables(patch)
		if err := validateAutoExcludeTunables(resolved); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// VALIDATE (done) → FENCE → PERSIST target → APPLY runtime. Persist first: a
		// write failure must not have already evicted learned entries
		// (persist-before-apply). The OPTIONAL ?ifRevision= stale-writer fence
		// (2E-B §D) is compared inside the save's precondition — the comparison and
		// the durable target write share ONE serialized AdminSettings save domain,
		// so two racing fenced admins cannot both pass; absent keeps the legacy
		// replacement contract (the v2 client always asserts). The apply runs via
		// applyOnSuccess INSIDE the save's lock so a concurrent omnibus save can't
		// revert the just-persisted tunables on disk.
		ifRev := parseIfRevision(r)
		var old autoExcludeTunables
		err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			autoExclude: &resolved,
			precondition: func() error {
				old = currentAutoExcludeTunables()
				if ifRev != nil {
					if cur := autoExcludeTunablesRevisionOf(old); cur != *ifRev {
						return errContentSecRevisionConflict{current: cur, asserted: *ifRev}
					}
				}
				return nil
			},
			applyOnSuccess: func() { autoExclude().Reconfigure(resolved.engineConfig()) },
		})
		var conflict errContentSecRevisionConflict
		if errors.As(err, &conflict) {
			writeContentSecRevisionConflict(w, "auto-exclusion tunables", conflict.current, conflict.asserted)
			return
		}
		if err != nil {
			logger.Printf("decryption tunables: persist failed, runtime unchanged: %v", err)
			http.Error(w, "failed to persist tunables", http.StatusInternalServerError)
			return
		}
		auditEventDiff(r, "decryption.autoexclude.tunables", "tunables",
			"updated adaptive decryption-exclusion tunables", old, resolved)
		// The response is the set THIS PUT installed plus its revision (coherent
		// by construction — never a re-read).
		jsonOK(w, map[string]any{
			"confirm_n":       resolved.ConfirmN,
			"ttl_secs":        resolved.TTLSecs,
			"pinned_ttl_secs": resolved.PinnedTTLSecs,
			"window_secs":     resolved.WindowSecs,
			"max_entries":     resolved.MaxEntries,
			"revision":        autoExcludeTunablesRevisionOf(resolved),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiURLCat(w http.ResponseWriter, r *http.Request) { //nolint:cyclop,funlen,gocognit // CRUD handler: one branch per HTTP method is intentional
	switch r.Method {
	case http.MethodGet:
		// LEGACY raw-array contract — never reshaped (2D-B §8; the v2 read
		// is GET /api/urlcat/state). Same enrichment helper as /state so the
		// two reads cannot disagree.
		jsonOK(w, enrichedURLCategories())

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Name  string   `json:"name"`
			Hosts []string `json:"hosts"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if len(body.Name) > 256 {
			http.Error(w, "name must be 256 characters or fewer", http.StatusBadRequest)
			return
		}
		if len(body.Hosts) > 10000 {
			http.Error(w, "category cannot contain more than 10000 hosts", http.StatusBadRequest)
			return
		}
		if ifRev := parseIfRevision(r); ifRev != nil {
			// v2 fenced STRICT create (2D-B §9/§10): fence + mutation +
			// durable publish in one serialization domain; an existing name
			// is a 409, never a silent upsert. Recompose ONLY after durable
			// success (§13) — a failed mutation never reaches the effective
			// policy view.
			if err := catStore.CreateDurable(ifRev, body.Name, body.Hosts); err != nil {
				writeTaxonomyMutationError(w, err)
				return
			}
			recomposeSignedFeedTaxonomy()
			auditEvent(r, "urlcat.create", body.Name, fmt.Sprintf("%d host(s)", len(body.Hosts)))
			saveConfigVersion(sessionAdmin(r), "urlcat.create")
			jsonOK(w, map[string]any{"name": body.Name, "revision": catStore.ContentFingerprint()})
			return
		}
		if err := catStore.Set(body.Name, body.Hosts, false); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Set() on an EXISTING name preserves that entry's BuiltIn flag, so this POST can
		// land on a built-in category — which the policy path serves from the effective
		// view, not catStore. Recompose so the edit is actually enforced.
		recomposeSignedFeedTaxonomy()
		auditEvent(r, "urlcat.create", body.Name, fmt.Sprintf("%d host(s)", len(body.Hosts)))
		saveConfigVersion(sessionAdmin(r), "urlcat.create")
		jsonOK(w, map[string]string{"name": body.Name})

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name query param required", http.StatusBadRequest)
			return
		}
		var body struct {
			Hosts []string `json:"hosts"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if ifRev := parseIfRevision(r); ifRev != nil {
			// Blocker D + C: a BuiltIn category owned by an active signed
			// generation is read-only on the v2 surface (structured 409 →
			// SaaS Overrides), and the ownership decision is linearized with
			// the durable mutation against signed cutover (§14) — released
			// before the recompose.
			release, refused := beginV2CategoryMutation(w, name)
			if refused {
				return
			}
			// v2 fenced host replacement: the store preserves BuiltIn INSIDE
			// the transaction (no read-then-write window) and enforces the
			// MaxHostsPerCategory bound; recompose only after durable success.
			err := catStore.ReplaceHostsDurable(ifRev, name, body.Hosts)
			release()
			if err != nil {
				writeTaxonomyMutationError(w, err)
				return
			}
			recomposeSignedFeedTaxonomy()
			auditEvent(r, "urlcat.update", name, fmt.Sprintf("%d host(s)", len(body.Hosts)))
			saveConfigVersion(sessionAdmin(r), "urlcat.update")
			jsonOK(w, map[string]any{"name": name, "revision": catStore.ContentFingerprint()})
			return
		}
		// Preserve builtIn flag when updating.
		all := catStore.All()
		builtIn := false
		for _, e := range all {
			if strings.EqualFold(e.Name, name) {
				builtIn = e.BuiltIn
				break
			}
		}
		if err := catStore.Set(name, body.Hosts, builtIn); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// A built-in category's hosts are served from the effective view, not catStore.
		recomposeSignedFeedTaxonomy()
		auditEvent(r, "urlcat.update", name, fmt.Sprintf("%d host(s)", len(body.Hosts)))
		saveConfigVersion(sessionAdmin(r), "urlcat.update")
		jsonOK(w, map[string]string{"name": name})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name query param required", http.StatusBadRequest)
			return
		}
		// Referential integrity (policy-refs P0): block deletion if ANY
		// consumer references the category — policy rules (DestCategory) OR
		// category-group membership. Both come from the single objectReferences
		// walk (via deleteBlockedByReferences), so the 409 and
		// GET /api/objects/references can never disagree. Deleting a referenced
		// category was fail-open: a Deny rule scoped to it silently stopped
		// blocking.
		//
		// Blocker B: the scan and the deletion hold the reference-integrity
		// gate EXCLUSIVELY as one atomic decision — a reference writer can no
		// longer land between "unreferenced" and the delete (the recorded
		// POLICY-REFS-PLAN.md TOCTOU).
		refScanDeleteLock()
		defer refScanDeleteUnlock()
		if deleteBlockedByReferences(w, r, "category", name, "urlcat.delete.blocked") {
			return
		}
		if ifRev := parseIfRevision(r); ifRev != nil {
			// Blocker D + C: deleting a feed-owned BuiltIn category cannot
			// remove it from enforcement — refuse (409 → SaaS Overrides
			// tombstones); ownership decision linearized with the durable
			// delete (§14), released before the recompose.
			release, refused := beginV2CategoryMutation(w, name)
			if refused {
				return
			}
			// v2 fenced durable delete; recompose only after durable success.
			err := catStore.DeleteDurable(ifRev, name)
			release()
			if err != nil {
				writeTaxonomyMutationError(w, err)
				return
			}
			recomposeSignedFeedTaxonomy()
			auditEvent(r, "urlcat.delete", name, "")
			saveConfigVersion(sessionAdmin(r), "urlcat.delete")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := catStore.Delete(name); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		// Deleting a built-in category must also retire it from the served view —
		// otherwise policy keeps matching a category the operator just removed.
		recomposeSignedFeedTaxonomy()
		auditEvent(r, "urlcat.delete", name, "")
		saveConfigVersion(sessionAdmin(r), "urlcat.delete")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST/DELETE /api/urlcat/host — add or remove a single host from a category.
func apiURLCatHost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Category string `json:"category"`
			Host     string `json:"host"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Category == "" || body.Host == "" {
			http.Error(w, "category and host are required", http.StatusBadRequest)
			return
		}
		if ifRev := parseIfRevision(r); ifRev != nil {
			// Blocker D + C: no v2 host mutation on a feed-owned BuiltIn
			// category; ownership decision linearized with the mutation.
			release, refused := beginV2CategoryMutation(w, body.Category)
			if refused {
				return
			}
			// v2 fenced durable single-host add (post-mutation cap enforced
			// at the store boundary); recompose only after durable success.
			err := catStore.AddHostDurable(ifRev, body.Category, body.Host)
			release()
			if err != nil {
				writeTaxonomyMutationError(w, err)
				return
			}
			recomposeSignedFeedTaxonomy()
			auditEvent(r, "urlcat.host.add", body.Category, body.Host)
			saveConfigVersion(sessionAdmin(r), "urlcat.host.add")
			jsonOK(w, map[string]any{"category": body.Category, "host": body.Host, "revision": catStore.ContentFingerprint()})
			return
		}
		if err := catStore.AddHost(body.Category, body.Host); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		// The canonical "block this host via its category" action. On a built-in
		// category the host only reaches policy through the effective view.
		recomposeSignedFeedTaxonomy()
		auditEvent(r, "urlcat.host.add", body.Category, body.Host)
		saveConfigVersion(sessionAdmin(r), "urlcat.host.add")
		jsonOK(w, map[string]string{"category": body.Category, "host": body.Host})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		category := r.URL.Query().Get("category")
		host := r.URL.Query().Get("host")
		if category == "" || host == "" {
			http.Error(w, "category and host query params required", http.StatusBadRequest)
			return
		}
		if ifRev := parseIfRevision(r); ifRev != nil {
			// Blocker D + C: no v2 host mutation on a feed-owned BuiltIn
			// category; ownership decision linearized with the mutation.
			release, refused := beginV2CategoryMutation(w, category)
			if refused {
				return
			}
			// v2 fenced durable single-host remove.
			err := catStore.RemoveHostDurable(ifRev, category, host)
			release()
			if err != nil {
				writeTaxonomyMutationError(w, err)
				return
			}
			recomposeSignedFeedTaxonomy()
			auditEvent(r, "urlcat.host.remove", category, host)
			saveConfigVersion(sessionAdmin(r), "urlcat.host.remove")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := catStore.RemoveHost(category, host); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		recomposeSignedFeedTaxonomy()
		auditEvent(r, "urlcat.host.remove", category, host)
		saveConfigVersion(sessionAdmin(r), "urlcat.host.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/urlcat/lookup?host=example.com
// Resolves a hostname to its URL category AND checks the blocklist.
// Response: {"host":"…","category":"…","tier":"admin"|"community"|"none","matchedBy":"…","blocked":true|false,"blockSource":"manual"|"feed"|""}
func apiURLCatLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host query param required", http.StatusBadRequest)
		return
	}
	category, tier, matchedBy := lookupHostCategory(host)
	// Also check the blocklist so the lookup tool gives a complete picture.
	blocked := bl.IsBlocked(host)
	blockSource := ""
	if blocked {
		blockSource = "blocklist"
	}
	jsonOK(w, map[string]any{
		"host":        host,
		"category":    category,
		"tier":        tier,
		"matchedBy":   matchedBy,
		"blocked":     blocked,
		"blockSource": blockSource,
	})
}

// GET /api/urlcat/feed-status — freshness and failure counts for the two
// background feeds that back URL Categories (UT1 community blacklist + SaaS
// curated JSON). Both feeds already track this state via Stats()/SyncFailures()
// for the /metrics Prometheus writer (urlcat_metrics.go); this surfaces the
// same read-only state to the admin GUI so a stalled or failing feed is
// visible without scraping /metrics or reading logs. Read-only, no config-version.
//
// NOTE: the two feeds' counts mean different things and are NOT
// interchangeable. UT1's Stats() reports the full corpus size parsed on the
// last sync (feedsync.Syncer.totalDomains). SaaS's Stats() reports only the
// merge callback's "added" return (mergeSaaSCategories, saas_feed.go) — the
// number of NEW hosts folded in that sync, which is legitimately 0 on a
// healthy, routine, unchanged sync. Rendering that as "entries" would read
// as an empty/broken feed, so it gets its own field name.
func apiURLCatFeedStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ut1 := map[string]any{"configured": globalUT1FeedSyncer != nil}
	if globalUT1FeedSyncer != nil {
		entries, lastSync, interval := globalUT1FeedSyncer.Stats()
		ut1["entries"] = entries
		ut1["lastSync"] = rfc3339OrEmpty(lastSync)
		ut1["intervalSeconds"] = int64(interval.Seconds())
		ut1["syncFailures"] = feedsync.SyncFailures()
	}

	// SaaS block now reflects the SIGNED feed (F3b-4). The legacy raw syncer is retired
	// from runtime authority, so its sync-failure counters no longer contaminate this
	// status — this is a compact summary of the signed-feed runtime state (the full
	// snapshot lives on GET /api/saas-feed/status). UT1 stays a separate, unchanged feed.
	sf := globalSaaSFeedStatus.Snapshot()
	saas := map[string]any{
		"configured":        sf.Configured,
		"enabled":           sf.Enabled,
		"state":             sf.State.String(),
		"activeFeedVersion": nullableInt64(sf.ActiveFeedVersion),
		"provenance":        sf.Provenance,
		"lastSuccess":       rfc3339OrEmpty(sf.LastSuccessfulActivation),
		"syncFailures":      sf.FailuresSinceStart,
		"stale":             sf.Stale,
	}

	jsonOK(w, map[string]any{"ut1": ut1, "saas": saas})
}

// rfc3339OrEmpty renders t as RFC3339 UTC, or "" for the zero value (never
// synced) — mirrors the blocklist-feed and threat-feed status handlers.
func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// configBackup is the portable JSON snapshot of all non-secret configuration.
type configBackup struct {
	Version             int           `json:"version"`
	ExportedAt          string        `json:"exportedAt"`
	BlocklistMode       string        `json:"blocklistMode"`
	Blocklist           []string      `json:"blocklist"`
	PolicyRules         []PolicyRule  `json:"policyRules"`
	DefaultAction       string        `json:"defaultAction"`
	RewriteRules        []RewriteRule `json:"rewriteRules"`
	SSLBypass           []string      `json:"sslBypass"`
	ContentScanPatterns []string      `json:"contentScanPatterns"`
	FileBlockExtensions []string      `json:"fileBlockExtensions"`
	IPFilterMode        string        `json:"ipFilterMode"`
	IPList              []string      `json:"ipList"`
	RateLimitRPM        int           `json:"rateLimitRPM"`
	RateLimitExempt     []string      `json:"rateLimitExempt"`
	PACProxyHost        string        `json:"pacProxyHost,omitempty"`
	PACProxyPort        int           `json:"pacProxyPort,omitempty"`
	PACExclusions       []string      `json:"pacExclusions,omitempty"`

	// ── Export/import-only fields — intentionally NOT on the rollback surface ──
	//
	// The five fields below are serialized by apiConfigExport / apiConfigImport
	// (ui_config.go) for configuration portability, but are deliberately NOT
	// captured by captureConfigBackup, NOT applied by applyConfigBackup, and
	// NOT reported by diffConfigs (configversion.go). Rolling back to a config
	// version leaves these live values untouched by design. They keep
	// `omitempty` precisely because they are export-only; do NOT wire them into
	// the rollback capture/apply/diff path without first reading
	// roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md.
	//
	// Why each is off the rollback surface:
	//   - AlertWebhooks: AlertStore.List() strips the HMAC Secret (alerts.go)
	//     and Add() reassigns the ID, so the capture surface cannot round-trip
	//     a webhook faithfully — a "restore" would silently drop signing
	//     secrets and renumber IDs. Faithful capture would persist the secret
	//     in plaintext in config-version files (gosec G117 concern).
	//   - UpstreamProxies: a proxy URL may embed inline credentials
	//     (user:pass@host); putting it on the rollback surface would persist
	//     those credentials in plaintext across up to 50 config-version files.
	//   - BlockPageHTML, ConnLimitEnabled, ConnLimitMaxPerIP: already restart-
	//     durable via /data/admin_settings.json, and their handlers
	//     (apiBlockPage, apiConnLimit) intentionally do NOT call
	//     saveConfigVersion — operational settings, not versioned policy.
	//
	// NOTE: RateLimitExempt (above) is ON the rollback surface as of PR-2:
	// captured by captureConfigBackup, applied by applyConfigBackup
	// (nil→skip / []→wipe / populated→replace, via rl.ReplaceExemptions), and
	// reported by diffConfigs. Its tag therefore omits `omitempty` (like
	// CategoryGroups/URLCategories) so a zero-exemption snapshot serializes as
	// [] and round-trips as a wipe. The handler (apiSettingsSecurity) already
	// calls saveConfigVersion; sibling RateLimitRPM was already covered. It is
	// NOT one of the five export/import-only fields below. See
	// roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md.
	AlertWebhooks     []AlertWebhook  `json:"alertWebhooks,omitempty"`
	BlockPageHTML     string          `json:"blockPageHTML,omitempty"`
	UpstreamProxies   []UpstreamEntry `json:"upstreamProxies,omitempty"`
	ConnLimitEnabled  bool            `json:"connLimitEnabled,omitempty"`
	ConnLimitMaxPerIP int             `json:"connLimitMaxPerIP,omitempty"`

	// CategoryGroups extends the rollback surface to cover the
	// PolicyRules → CategoryGroup reference. Per
	// roadmap/CATEGORYGROUPS-ROLLBACK-EXTENSION-SPEC.md §3.3:
	// json:"categoryGroups" WITHOUT omitempty so a snapshot recorded
	// at zero groups serializes as `[]` and distinguishes itself from
	// an old pre-extension snapshot (which simply lacks the field and
	// decodes to nil). nil → apply skips; [] → apply wipes; populated
	// → apply replaces.
	CategoryGroups []CategoryGroup `json:"categoryGroups"`

	// DecryptionProfiles extends the rollback surface to cover the
	// PolicyRules → DecryptionProfile reference. json:"decryptionProfiles"
	// WITHOUT omitempty (same posture as CategoryGroups): nil → apply skips;
	// [] → apply wipes; populated → apply replaces. The paired ConfigSnapshot
	// field keeps omitempty (SnapshotWireWipe requires it for a
	// non-WireWipeCapable field).
	DecryptionProfiles []DecryptionProfile `json:"decryptionProfiles"`

	// PACProfiles/PACPools put the PAC steering profiles feature (PAC
	// initiative PR 2) on the export/import + rollback surfaces. Same
	// posture as CategoryGroups: NO omitempty — nil → apply skips (old
	// snapshot, no opinion); [] → apply wipes; populated → apply replaces.
	// Both are cluster-synced WireWipeCapable (see config_surfaces.go).
	PACProfiles []pac.Profile `json:"pacProfiles"`
	PACPools    []pac.Pool    `json:"pacPools"`

	// URLCategories extends the rollback surface to cover catStore
	// (admin-managed Layer 1; communityDB Layer 2 is intentionally
	// out-of-band). Per roadmap/URL-CATEGORIES-ROLLBACK-EXTENSION-SPEC.md
	// §4.1: json:"urlCategories" WITHOUT omitempty so a snapshot
	// recorded at zero categories serializes as `[]` and distinguishes
	// itself from an old pre-extension snapshot (which simply lacks
	// the field and decodes to nil). Same shape as CategoryGroups
	// (PR #267) for consistency.
	URLCategories []CategoryEntry `json:"urlCategories"`

	// ContentScanBypassHosts extends the rollback surface to cover
	// dpiScanner's per-host DPI bypass list (the second half of the
	// content_scan.json envelope; patterns are already covered by
	// ContentScanPatterns above). Per
	// roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md: json:"contentScanBypassHosts"
	// WITHOUT omitempty so a snapshot recorded at zero bypass hosts
	// serializes as `[]` (wipe on apply) and distinguishes itself from
	// an old pre-extension snapshot (absent field → nil → skip).
	ContentScanBypassHosts []string `json:"contentScanBypassHosts"`

	// SaaS signed category-feed configuration (F3a-2). CP-authoritative fleet
	// policy on the export/import/rollback surface. Exported as CONFIGURATION only —
	// never the node-local runtime/activation/floor state (design §A.6). On import,
	// the block is applied only when SaaSFeedProtocol is set (never-wipe); on
	// rollback it is applied unconditionally (like DefaultAction). URL/protocol are
	// strict-validated at import through the F3a-1 boundary (legacy/unsupported
	// values rejected). The values round-trip through the durable holder, NOT the
	// legacy syncer.
	SaaSFeedManaged        bool   `json:"saasFeedManaged,omitempty"`
	SaaSFeedEnabled        bool   `json:"saasFeedEnabled,omitempty"`
	SaaSFeedURL            string `json:"saasFeedURL,omitempty"`
	SaaSFeedProtocol       string `json:"saasFeedProtocol,omitempty"`
	SaaSFeedRefreshSeconds int64  `json:"saasFeedRefreshSeconds,omitempty"`

	// CategoryOverrides is the admin category-override set (F3a-2). Pointer for
	// presence — nil ⇒ absent (import skips = never-wipe; rollback keep-local) —
	// mirroring the ConfigSnapshot posture. NO omitempty so an explicit empty set
	// (a deliberate clear) round-trips as `{}` rather than being dropped.
	CategoryOverrides *CategoryOverrides `json:"categoryOverrides"`
}

// GET /api/config/export — download a full configuration backup as JSON.
func apiRewrite(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Management-surface closure: RewriteRule serializes stableId, so the
		// LEGACY list is a management-identity read too — while identity is
		// not durable it answers the SAME structured 503 as the v2 state
		// surface (one dialect; ephemeral StableIDs are never exposed as a
		// healthy management list). Healthy behavior is unchanged.
		if d := rewriteIdentityDegraded(); d != nil {
			writeRewriteIdentityDegraded(w, d)
			return
		}
		rules := rewriter.List()
		jsonOK(w, map[string]any{"rules": rules, "count": len(rules)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// AFTER the RBAC boundary (authorization precedes degradation
		// disclosure): while management identity is not durable a v2
		// mutation could create/address identity that re-mints on restart
		// (and a save could clobber a refused/corrupt settings file) — refuse
		// with the structured 503, visible to authorized Operators only.
		if d := rewriteIdentityDegraded(); d != nil {
			writeRewriteIdentityDegraded(w, d)
			return
		}
		var rule RewriteRule
		if err := decodeJSON(r, &rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := validateIncomingRewriteRule(rule); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Server-owned identity (§22): a client-supplied stableId is ignored.
		rule.StableID = rewrite.NewStableID()
		ifRev := strings.TrimSpace(r.URL.Query().Get("ifRevision"))
		// Durable-or-nothing (§24): fence + target build + settings persist +
		// runtime publication in ONE adminSettingsMu critical section. A hard
		// persist failure means the rule was never active anywhere.
		err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			rewriteMutate: func(current []RewriteRule) ([]RewriteRule, error) {
				if ferr := rewriteFence(ifRev, current); ferr != nil {
					return nil, ferr
				}
				return append(append([]RewriteRule(nil), current...), rule), nil
			},
		})
		if err != nil {
			var conflict *errRewriteRevisionConflict
			if errors.As(err, &conflict) {
				writeRewriteRevisionConflict(w, conflict.current, ifRev)
				return
			}
			http.Error(w, "rewrite rule not persisted: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// The published copy carries the process-local integer id assigned at
		// publication — return it for legacy-client compatibility.
		added := rule
		for _, lr := range rewriter.List() {
			if lr.StableID == rule.StableID {
				added = lr
				break
			}
		}
		logger.Printf("UI: rewrite rule added stableId=%s host=%q", sanitizeLog(added.StableID), sanitizeLog(added.Host))
		auditEvent(r, "rewrite.add", fmt.Sprintf("stableId=%s host=%s", added.StableID, added.Host), "")
		saveConfigVersion(sessionAdmin(r), "rewrite.add")
		jsonOK(w, added)

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		// AFTER the RBAC boundary — same ordering contract as POST.
		if d := rewriteIdentityDegraded(); d != nil {
			writeRewriteIdentityDegraded(w, d)
			return
		}
		// v2 addressing: ?stableId= (durable identity). Legacy ?id= (process-
		// local integer) stays supported for existing clients; it is resolved
		// to the durable identity INSIDE the critical section so a concurrent
		// reload cannot retarget it.
		stableID := strings.TrimSpace(r.URL.Query().Get("stableId"))
		idStr := strings.TrimSpace(r.URL.Query().Get("id"))
		var legacyID int
		hasLegacy := false
		if stableID == "" {
			if _, err := fmt.Sscanf(idStr, "%d", &legacyID); err != nil {
				http.Error(w, "missing or invalid id/stableId param", http.StatusBadRequest)
				return
			}
			hasLegacy = true
		}
		ifRev := strings.TrimSpace(r.URL.Query().Get("ifRevision"))
		removedStable := stableID
		err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			rewriteMutate: func(current []RewriteRule) ([]RewriteRule, error) {
				if ferr := rewriteFence(ifRev, current); ferr != nil {
					return nil, ferr
				}
				target := make([]RewriteRule, 0, len(current))
				found := false
				for _, cr := range current {
					match := (stableID != "" && cr.StableID == stableID) ||
						(hasLegacy && cr.ID == legacyID)
					if match && !found {
						found = true
						removedStable = cr.StableID
						continue
					}
					target = append(target, cr)
				}
				if !found {
					return nil, errRewriteRuleNotFound
				}
				return target, nil
			},
		})
		if err != nil {
			var conflict *errRewriteRevisionConflict
			if errors.As(err, &conflict) {
				writeRewriteRevisionConflict(w, conflict.current, ifRev)
				return
			}
			if errors.Is(err, errRewriteRuleNotFound) {
				http.Error(w, "rule not found", http.StatusNotFound)
				return
			}
			http.Error(w, "rewrite rule removal not persisted: "+err.Error(), http.StatusInternalServerError)
			return
		}
		logger.Printf("UI: rewrite rule removed stableId=%s", sanitizeLog(removedStable))
		auditEvent(r, "rewrite.remove", "stableId="+removedStable, "")
		saveConfigVersion(sessionAdmin(r), "rewrite.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─── Policy API ───────────────────────────────────────────────────────────────

// GET/POST/PUT/DELETE /api/policy — manage PBAC policy rules
// stampRuleMetadataForWrite sets the server-authoritative Tier-A metadata on a
// rule about to be written (policy-metadata P1). CreatedAt/ModifiedAt/ModifiedBy
// are ALWAYS server-set here — client-supplied values are ignored, or the
// provenance fields become theater (POLICY-ARCHITECTURE-FUTURE.md §2). On an
// edit (before != nil) CreatedAt is carried from the stored rule so an edit
// never rewrites when the rule was born; a pre-feature rule (empty CreatedAt)
// stays empty rather than being back-dated to now, which would be a lie.
// Comment is deliberately NOT touched — it is the one admin-authored field.
func stampRuleMetadataForWrite(rule *PolicyRule, before *PolicyRule, actor string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if before == nil {
		rule.CreatedAt = now
	} else {
		rule.CreatedAt = before.CreatedAt
	}
	rule.ModifiedAt = now
	rule.ModifiedBy = actor
	stampObjectRefIDs(rule)
}

// stampObjectRefIDs derives the authoritative, rename-safe object-link IDs from
// the object NAMES the client submitted (references-by-id write path,
// OBJECT-REFERENCES-BY-ID.md). Resolved SERVER-SIDE ONLY — any client-supplied
// ID is discarded and re-derived, so a rule can never point at an object the
// operator did not pick. An unknown or empty name leaves the ID empty
// (fail-safe: the match path falls back to the name).
func stampObjectRefIDs(rule *PolicyRule) {
	rule.DecryptionProfileID = ""
	if rule.DecryptionProfile != "" {
		if p := globalDecryptionProfiles.GetByName(rule.DecryptionProfile); p != nil {
			rule.DecryptionProfileID = p.ID
		}
	}
	rule.DestCategoryGroupID = ""
	if rule.DestCategoryGroup != "" {
		if g := globalCategoryGroups.GetByName(rule.DestCategoryGroup); g != nil {
			rule.DestCategoryGroupID = g.ID
		}
	}
	// File profile (2D-C promotion): same trust boundary — the NAME is client
	// intent, the ID is server-derived. A legacy built-in name with no store
	// object (compiled fileProfileExts fallback) legitimately stamps no ID and
	// keeps resolving by name.
	rule.FileProfileID = ""
	if rule.FileProfile != "" && rule.FileProfile != FileProfileNone {
		if p := globalProfileStore.GetByName(string(rule.FileProfile)); p != nil {
			rule.FileProfileID = p.ID
		}
	}
}

// policyVersionConflict enforces the OPTIONAL optimistic-concurrency
// precondition on a policy mutation (P2 rule-set generation counter). When the
// client sends ?ifVersion=N (the rule-set version it loaded), a mismatch with
// the current version means another admin mutated the rulebase in between — so
// this writes a structured 409 and returns true (caller must stop), preventing
// a silent last-write-wins overwrite. Absent/blank param = no check, so
// non-version-aware clients (curl, tests, older UIs) keep working unchanged.
//
// This is handler-level (HTTP If-Match semantics): it catches the real
// multi-admin case — two admins load v5, one commits (→v6), the other's v5
// write is rejected. It does NOT close the microsecond window where two writes
// both read v5 before either commits; the store still serializes those two
// mutations (no corruption), same as today. Truly-atomic check-and-write would
// thread the expected version into the store mutators — a recorded follow-up.
func policyVersionConflict(w http.ResponseWriter, r *http.Request) bool {
	// Effective version: the candidate's while a draft is ENGAGED (so two admins
	// editing the shared draft collide), else running's (policy-draft G2).
	cur, _ := effectivePolicyVersion()
	return policyVersionConflictAgainst(w, r, cur)
}

// policyVersionConflictAgainst is the shared optimistic-concurrency precondition
// against an EXPLICIT current generation. The draft-commit path uses it with the
// candidate's version directly: a commit always operates on the candidate, so it
// must compare against candidateVersion() even when RequireCommit is off (the
// stranded-draft recovery state) — otherwise effectivePolicyVersion() would fall
// back to running and 409 a legitimate recovery commit whose ?ifVersion= is the
// candidate generation GET /api/policy/draft advertised.
func policyVersionConflictAgainst(w http.ResponseWriter, r *http.Request, cur int64) bool {
	raw := strings.TrimSpace(r.URL.Query().Get("ifVersion"))
	if raw == "" {
		return false
	}
	want, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		http.Error(w, "invalid ifVersion", http.StatusBadRequest)
		return true
	}
	if want == cur {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":          fmt.Sprintf("the rulebase changed since you loaded it (your version %d, current %d) — reload and reapply your change", want, cur),
		"currentVersion": cur,
		"yourVersion":    want,
	})
	return true
}

// parseIfVersion extracts the optional ?ifVersion=N asserted generation for
// callers that re-verify the fence inside a locked critical section (the
// draft-commit path). nil = no assertion. Invalid input also returns nil —
// callers run policyVersionConflictAgainst first, which 400s malformed input
// before this is consulted.
func parseIfVersion(r *http.Request) *int64 {
	raw := strings.TrimSpace(r.URL.Query().Get("ifVersion"))
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// apiPolicy dispatches the access-rule CRUD endpoint. The per-method branches
// live in apiPolicyCreate/Update/Delete so this stays a thin router (gocognit).
func apiPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Effective view: the candidate while the draft is engaged (so the editor
		// shows what will be committed), else running (policy-draft G2). ONE
		// coordinator-locked capture supplies the store choice, the rules, the
		// version fence, AND the draft fact (§§6–8 fenced-read correction):
		// independent effectivePolicyList/effectivePolicyVersion calls let a
		// staged edit land in between, tearing rules from version — a client
		// holding generation-P rules with a generation-P+1 token would pass the
		// optimistic fence with a stale edit. The draft flag comes from the same
		// selected state so the SPA banner never claims draft editing while the
		// rules shown (and written) are the live ones.
		snap, draft := effectiveManagementSnapshot()
		jsonOK(w, map[string]any{
			"rules":     snap.Rules,
			"count":     len(snap.Rules),
			"version":   snap.Version,
			"updatedAt": snap.UpdatedAt,
			"draft":     draft,
		})
	case http.MethodPost:
		apiPolicyCreate(w, r)
	case http.MethodPut:
		apiPolicyUpdate(w, r)
	case http.MethodDelete:
		apiPolicyDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// findRuleByPriorityCopy returns a copy of the stored rule at the given
// priority (nil if none) — the before-state snapshot for diff/audit.
func findRuleByPriorityCopy(priority int) *PolicyRule {
	// Index-based range: PolicyRule is a large struct (CLAUDE.md rangeValCopy
	// convention) — copy only the matched rule, not every iteration.
	// Effective list: candidate while drafting, else running (policy-draft G2) —
	// the before-state for a diff/audit must come from what is being edited.
	rules := effectivePolicyList()
	for i := range rules {
		if rules[i].Priority == priority {
			r2 := rules[i]
			return &r2
		}
	}
	return nil
}

// effectiveRuleByID returns a copy of the rule with the given ID from the
// effective rulebase (candidate while drafting, else running), or nil. The
// before-state lookup for the id-addressed update/delete paths (policy-draft G2).
func effectiveRuleByID(id string) *PolicyRule {
	rules := effectivePolicyList()
	for i := range rules {
		if rules[i].ID == id {
			r2 := rules[i]
			return &r2
		}
	}
	return nil
}

func apiPolicyCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleOperator) {
		return
	}
	// Blocker B (shared side): a new rule CREATES references (destCategory /
	// destCategoryGroup / fileProfile / decryptionProfile) — it must not land
	// between a concurrent object delete's reference scan and its deletion.
	refWriteLock()
	defer refWriteUnlock()
	if policyVersionConflict(w, r) {
		return
	}
	var rule PolicyRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if rule.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	// Auth (Stage-1) rules are admin-managed via /api/authpolicy only —
	// this operator-level endpoint must not create authentication waivers.
	if ruleTypeOf(&rule) == ruleTypeAuth {
		http.Error(w, `auth rules are managed via /api/authpolicy (admin only)`, http.StatusBadRequest)
		return
	}
	policyWriteStateDecision(r, "resolved")
	if err := validatePolicyRule(rule, effectivePolicyList(), -1); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// SERVER CANONICALIZATION FIRST (ID-trust correction): stamp metadata and
	// re-derive object IDs from NAMES (client-supplied IDs are discarded),
	// then validate the FINAL canonical rule — reference validation must
	// never trust a client ID, and no restamp may follow it.
	stampRuleMetadataForWrite(&rule, nil, sessionAdmin(r))
	// Blocker B delete-first order: validate every referenced object UNDER the
	// shared gate, before the commit — a delete that already won makes this
	// fail 400 instead of committing a dangling reference.
	if refuseDanglingRuleRefs(w, &rule) {
		return
	}
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a): when ?ifVersion= is asserted, the
	// version comparison and the Add run in one coordinator critical section —
	// the early policyVersionConflict above stays as fast-path/400 only.
	var added PolicyRule
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		added = target.Add(rule)
		return true
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	logName := strings.ReplaceAll(strings.ReplaceAll(added.Name, "\n", "_"), "\r", "_")
	logAction := strings.ReplaceAll(strings.ReplaceAll(string(added.Action), "\n", "_"), "\r", "_")
	logPriority := strings.ReplaceAll(fmt.Sprintf("%d", added.Priority), "\n", "_")
	logger.Printf("UI: policy rule added priority=%s name=%q action=%q", logPriority, logName, logAction)
	auditEventDiffID(r, "policy.add", added.Name, added.ID,
		fmt.Sprintf("priority=%d action=%s", added.Priority, added.Action), nil, added)
	finalizeFencedPolicyWrite(r, "policy.add", res)
	jsonOK(w, added)
}

func apiPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleOperator) {
		return
	}
	// Blocker B (shared side): an edited rule can CHANGE which objects it
	// references — covers the ?id= delegate below too (acquire once here;
	// shared holds must never nest).
	refWriteLock()
	defer refWriteUnlock()
	if policyVersionConflict(w, r) {
		return
	}
	// Prefer stable-ID addressing when the client supplies ?id= — it is safe
	// against a concurrent reorder shifting priorities between load and save
	// (§1 identity seam). ?priority= stays supported for the deprecation window.
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		apiPolicyUpdateByID(w, r, id)
		return
	}
	priorityStr := strings.TrimSpace(r.URL.Query().Get("priority"))
	var priority int
	if _, err := fmt.Sscanf(priorityStr, "%d", &priority); err != nil {
		http.Error(w, "missing or invalid priority param", http.StatusBadRequest)
		return
	}
	beforeRule := findRuleByPriorityCopy(priority)
	// Auth (Stage-1) rules are admin-managed via /api/authpolicy only.
	if beforeRule != nil && ruleTypeOf(beforeRule) == ruleTypeAuth {
		http.Error(w, `auth rules are managed via /api/authpolicy (admin only)`, http.StatusBadRequest)
		return
	}
	var rule PolicyRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if ruleTypeOf(&rule) == ruleTypeAuth {
		http.Error(w, `auth rules are managed via /api/authpolicy (admin only)`, http.StatusBadRequest)
		return
	}
	policyWriteStateDecision(r, "resolved")
	if err := validatePolicyRule(rule, effectivePolicyList(), priority); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// SERVER CANONICALIZATION FIRST (ID-trust correction): stamp metadata and
	// re-derive object IDs from NAMES (client-supplied IDs are discarded),
	// then validate the FINAL canonical rule — reference validation must
	// never trust a client ID, and no restamp may follow it.
	stampRuleMetadataForWrite(&rule, beforeRule, sessionAdmin(r))
	// Blocker B delete-first order: validate referenced objects under the
	// shared gate before committing the edit.
	if refuseDanglingRuleRefs(w, &rule) {
		return
	}
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a); a failed mutation that opened the draft
	// fork is discarded inside the same critical section.
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		return target.Update(priority, rule)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	logPriority := strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", "_")
	logger.Printf("UI: policy rule updated priority=%s name=%q", logPriority, sanitizeLog(rule.Name))
	auditEventDiffID(r, "policy.update", rule.Name, ruleAuditID(beforeRule),
		fmt.Sprintf("priority=%d action=%s", priority, rule.Action), beforeRule, rule)
	finalizeFencedPolicyWrite(r, "policy.update", res)
	jsonOK(w, map[string]any{"ok": true})
}

func apiPolicyDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleOperator) {
		return
	}
	if policyVersionConflict(w, r) { // guards both single- and bulk-delete (dispatched below)
		return
	}
	// Stable-ID addressing (?id=) — reorder-safe, preferred over ?priority=.
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		apiPolicyDeleteByID(w, r, id)
		return
	}
	priorityStr := strings.TrimSpace(r.URL.Query().Get("priority"))
	// F19: support bulk delete via JSON body with priorities array.
	if priorityStr == "" {
		apiPolicyBulkDelete(w, r)
		return
	}
	var priority int
	if _, err := fmt.Sscanf(priorityStr, "%d", &priority); err != nil {
		http.Error(w, "missing or invalid priority param", http.StatusBadRequest)
		return
	}
	beforeRule := findRuleByPriorityCopy(priority)
	// Auth (Stage-1) rules are admin-managed via /api/authpolicy only.
	if beforeRule != nil && ruleTypeOf(beforeRule) == ruleTypeAuth {
		http.Error(w, `auth rules are managed via /api/authpolicy (admin only)`, http.StatusBadRequest)
		return
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a).
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		return target.Delete(priority)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	name := fmt.Sprintf("priority=%d", priority)
	if beforeRule != nil {
		name = beforeRule.Name
	}
	logPriority := strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", "_")
	logger.Printf("UI: policy rule deleted priority=%s", logPriority)
	auditEventDiffID(r, "policy.remove", name, ruleAuditID(beforeRule), "", beforeRule, nil)
	finalizeFencedPolicyWrite(r, "policy.remove", res)
	w.WriteHeader(http.StatusNoContent)
}

// ruleAuditID returns a rule's stable ULID for the audit ObjectID field, or ""
// when the before-state copy is nil (a rare capture/mutate race) — keeps the
// audit trail rename-correlatable without risking a nil deref.
func ruleAuditID(r *PolicyRule) string {
	if r == nil {
		return ""
	}
	return r.ID
}

// apiPolicyUpdateByID handles PUT /api/policy?id=<ulid> — the reorder-safe
// addressing path. Mirrors the priority path's validation, auth-rule guard, and
// metadata stamping but resolves the target by stable ULID (§1 identity seam).
func apiPolicyUpdateByID(w http.ResponseWriter, r *http.Request, id string) {
	beforeRule := effectiveRuleByID(id)
	if beforeRule == nil {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	// Auth (Stage-1) rules are admin-managed via /api/authpolicy only.
	if ruleTypeOf(beforeRule) == ruleTypeAuth {
		http.Error(w, `auth rules are managed via /api/authpolicy (admin only)`, http.StatusBadRequest)
		return
	}
	var rule PolicyRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if ruleTypeOf(&rule) == ruleTypeAuth {
		http.Error(w, `auth rules are managed via /api/authpolicy (admin only)`, http.StatusBadRequest)
		return
	}
	// Exclude the rule's CURRENT slot from duplicate checks (same as the
	// priority path passes the URL priority).
	policyWriteStateDecision(r, "resolved")
	if err := validatePolicyRule(rule, effectivePolicyList(), beforeRule.Priority); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// SERVER CANONICALIZATION FIRST (ID-trust correction): stamp metadata and
	// re-derive object IDs from NAMES (client-supplied IDs are discarded),
	// then validate the FINAL canonical rule — reference validation must
	// never trust a client ID, and no restamp may follow it.
	stampRuleMetadataForWrite(&rule, beforeRule, sessionAdmin(r))
	// Blocker B delete-first order: validate referenced objects under the
	// shared gate (held by the apiPolicyUpdate caller) before committing.
	if refuseDanglingRuleRefs(w, &rule) {
		return
	}
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a).
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		return target.UpdateByID(id, rule)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	logger.Printf("UI: policy rule updated id=%s name=%q", sanitizeLog(id), sanitizeLog(rule.Name))
	auditEventDiffID(r, "policy.update", rule.Name, id,
		fmt.Sprintf("priority=%d action=%s", rule.Priority, rule.Action), beforeRule, rule)
	finalizeFencedPolicyWrite(r, "policy.update", res)
	jsonOK(w, map[string]any{"ok": true})
}

// apiPolicyDeleteByID handles DELETE /api/policy?id=<ulid> — reorder-safe delete.
func apiPolicyDeleteByID(w http.ResponseWriter, r *http.Request, id string) {
	beforeRule := effectiveRuleByID(id)
	if beforeRule == nil {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	if ruleTypeOf(beforeRule) == ruleTypeAuth {
		http.Error(w, `auth rules are managed via /api/authpolicy (admin only)`, http.StatusBadRequest)
		return
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a).
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		return target.DeleteByID(id)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	logger.Printf("UI: policy rule deleted id=%s", sanitizeLog(id))
	auditEventDiffID(r, "policy.remove", beforeRule.Name, id, "", beforeRule, nil)
	finalizeFencedPolicyWrite(r, "policy.remove", res)
	w.WriteHeader(http.StatusNoContent)
}

// validateMoveBody checks the /api/policy/move position/targetName combination.
func validateMoveBody(position, targetName string) error {
	if position != "first" && position != "last" && position != "before" && position != "after" {
		return fmt.Errorf("position must be first, last, before, or after")
	}
	if (position == "before" || position == "after") && targetName == "" {
		return fmt.Errorf("targetName is required for before/after")
	}
	return nil
}

// apiPolicyBulkDelete handles DELETE /api/policy with a {"priorities":[...]}
// body (F19 bulk delete). RBAC was already checked by the caller.
func apiPolicyBulkDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Priorities []int `json:"priorities"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Priorities) == 0 {
		http.Error(w, "missing priority param or priorities body", http.StatusBadRequest)
		return
	}
	// Auth rules are admin-managed via /api/authpolicy only — reject the
	// whole batch rather than silently skipping (explicit > silent).
	for _, p := range body.Priorities {
		if isAuthRulePriority(p) {
			http.Error(w, fmt.Sprintf("priority %d is an auth rule — managed via /api/authpolicy (admin only)", p), http.StatusBadRequest)
			return
		}
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a): the whole batch runs in one critical
	// section, so a fenced bulk delete is all-checked-then-deleted against the
	// generation the client asserted. NOTE (recorded for the v2 client): this
	// endpoint addresses rules by PRIORITY, which is not stable across a
	// reorder — the v2 frontend does not use it (see the 2B parity record).
	deleted := 0
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		for _, p := range body.Priorities {
			if target.Delete(p) {
				deleted++
			}
		}
		return deleted > 0
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		// Rolled back — nothing durable changed; the count must not be reported.
		writePolicyPersistFailure(w, res.err)
		return
	}
	logger.Printf("UI: bulk policy delete %d rule(s)", deleted)
	auditEvent(r, "policy.bulk_remove", fmt.Sprintf("%d rule(s)", deleted), "")
	finalizeFencedPolicyWrite(r, "policy.bulk_remove", res)
	jsonOK(w, map[string]any{"deleted": deleted})
}

// listPolicyRules returns the Stage-2 policy rules (the GUI/API "Policy Rule"
// concept) from the policy store, in priority order. Stage-1 auth rules are
// excluded — they are managed via /api/authpolicy and keep their priorities
// through every policy-side reorder.
func listPolicyRules() []PolicyRule {
	// Effective list: candidate while a draft is open, else running. The
	// reorder/move write handlers permute the effective store, so they must
	// validate against it (policy-draft G2).
	rules := effectivePolicyList()
	out := make([]PolicyRule, 0, len(rules))
	for i := range rules {
		if ruleTypeOf(&rules[i]) == ruleTypeAccess {
			out = append(out, rules[i])
		}
	}
	return out
}

// POST /api/policy/reorder — drag-and-drop priority reordering
// Body: {"priorities": [3,1,2]} — ordered list of old priorities (new order)
func apiPolicyReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	if policyVersionConflict(w, r) {
		return
	}
	var body struct {
		Priorities []int `json:"priorities"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Access-only contract: the list must be exactly the current Stage-2 access-
	// rule priority set. Stage-1 auth rules are reordered exclusively via
	// /api/authpolicy (admin-only) and keep their priorities, so this endpoint
	// permutes access rules among their own slots and never touches an auth rule
	// (no operator/admin escalation). Rejecting any auth priority — and any
	// partial/stale list — keeps the permutation well-defined.
	access := listPolicyRules()
	accessPris := make(map[int]bool, len(access))
	for i := range access {
		accessPris[access[i].Priority] = true
	}
	if len(body.Priorities) != len(accessPris) {
		http.Error(w, "priorities must list every access rule exactly once", http.StatusBadRequest)
		return
	}
	for _, p := range body.Priorities {
		if !accessPris[p] {
			http.Error(w, fmt.Sprintf("priority %d is not an access rule", p), http.StatusBadRequest)
			return
		}
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a).
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		return target.PermutePriorities(body.Priorities)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		http.Error(w, "priority list length mismatch or unknown priority", http.StatusBadRequest)
		return
	}
	logger.Printf("UI: policy rules reordered (%d rules)", len(body.Priorities))
	auditEvent(r, "policy.reorder", fmt.Sprintf("%d rules", len(body.Priorities)), "")
	finalizeFencedPolicyWrite(r, "policy.reorder", res)
	jsonOK(w, map[string]any{"ok": true})
}

// POST /api/policy/move — move a rule to first/last/before/after a target rule.
// Builds a new ordered priority list and delegates to policyStore.Reorder().
// Body: {"priority": 5, "position": "first|last|before|after", "targetName": "rule-name"}
// findRuleIdxByName returns the index within priorities that corresponds to the
// rule named targetName. Returns -1 if not found. Extracted to keep
// buildMovedPriorities under the cyclop complexity threshold.
func findRuleIdxByName(rules []PolicyRule, priorities []int, targetName string) int {
	for i, pri := range priorities {
		for j := range rules {
			if rules[j].Priority == pri && strings.EqualFold(rules[j].Name, targetName) {
				return i
			}
		}
	}
	return -1
}

// buildMovedPriorities computes a new priority ordering after moving a rule
// identified by movePriority to the given position (first/last/before/after).
// Returns the reordered priority slice or an error for unknown rule/target.
func buildMovedPriorities(rules []PolicyRule, movePriority int, position, targetName string) ([]int, error) {
	moveIdx := -1
	for i := range rules {
		if rules[i].Priority == movePriority {
			moveIdx = i
			break
		}
	}
	if moveIdx < 0 {
		return nil, fmt.Errorf("rule not found")
	}

	// Build priority list without the moved rule.
	priorities := make([]int, 0, len(rules))
	for i := range rules {
		if i != moveIdx {
			priorities = append(priorities, rules[i].Priority)
		}
	}
	movePri := rules[moveIdx].Priority

	switch position {
	case "first":
		return append([]int{movePri}, priorities...), nil
	case "last":
		return append(priorities, movePri), nil
	case "before", "after":
		targetIdx := findRuleIdxByName(rules, priorities, targetName)
		if targetIdx < 0 {
			return nil, fmt.Errorf("target rule not found: %s", strings.ReplaceAll(targetName, "\n", ""))
		}
		insertAt := targetIdx
		if position == "after" {
			insertAt++
		}
		newPri := make([]int, 0, len(rules))
		newPri = append(newPri, priorities[:insertAt]...)
		newPri = append(newPri, movePri)
		newPri = append(newPri, priorities[insertAt:]...)
		return newPri, nil
	}
	return nil, fmt.Errorf("invalid position")
}

func apiPolicyMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	if policyVersionConflict(w, r) {
		return
	}
	var body struct {
		Priority   int    `json:"priority"`
		Position   string `json:"position"`
		TargetName string `json:"targetName"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := validateMoveBody(body.Position, body.TargetName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Access-only: build the moved order over Stage-2 access rules and permute
	// just those priorities. Stage-1 auth rules are reordered via /api/authpolicy
	// and keep their priorities, so an access move never crosses or renumbers one
	// (no operator/admin escalation). Moving an auth rule via this endpoint is
	// rejected because buildMovedPriorities won't find it among the access rules.
	access := listPolicyRules()
	if len(access) == 0 {
		http.Error(w, "no rules to reorder", http.StatusBadRequest)
		return
	}
	priorities, err := buildMovedPriorities(access, body.Priority, body.Position, body.TargetName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert (Codex round 16; see beginPolicyWrite).
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic fence + mutation (2B.0a).
	res := policyDraft.fencedMutate(sessionAdmin(r), parseIfVersion(r), func(target *PolicyStore) bool {
		return target.PermutePriorities(priorities)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		http.Error(w, "reorder failed (concurrent modification?)", http.StatusConflict)
		return
	}
	safePri := strings.ReplaceAll(fmt.Sprintf("%d", body.Priority), "\n", "")
	safePos := sanitizeLog(body.Position)
	logger.Printf("UI: policy rule pri=%s moved to %s", safePri, safePos)
	auditEvent(r, "policy.move", fmt.Sprintf("pri=%s to %s", safePri, safePos), "")
	finalizeFencedPolicyWrite(r, "policy.move", res)
	jsonOK(w, map[string]any{"ok": true})
}

// policyTestTrace is one row of the simulator's rule-evaluation trace.
type policyTestTrace struct {
	Priority   int    `json:"priority"`
	Name       string `json:"name"`
	SkipReason string `json:"skipReason,omitempty"` // why this rule was skipped
}

// walkPolicyTestRules dry-runs Stage-2 access evaluation for the simulator (no
// hit counts, no mutation), returning the per-rule trace and the first match
// (nil = none). It routes through the canonical evaluator core (evalAccessRules,
// ADR-0026), so a simulation matches exactly what the proxy enforcement path
// would decide: same priority/first-match, the same matchers, the
// one-instant-per-evaluation schedule clock, and — unlike the pre-ADR-0026
// tester — it skips disabled rules (a disabled rule can never match at runtime,
// so it now appears in the trace as skipped "disabled" rather than as a match).
// Stage-1 auth rules stay inert for access decisions and appear as skipped.
func walkPolicyTestRules(rules []PolicyRule, sourceIP, identity, authSource, host string, groups []string) ([]policyTestTrace, *PolicyRule) {
	// The core walks []*PolicyRule; take addresses of the caller-owned copies.
	ptrs := make([]*PolicyRule, len(rules))
	for i := range rules {
		ptrs[i] = &rules[i]
	}
	trace := make([]policyTestTrace, 0, len(rules))
	in := accessEvalInput{
		clientIP:   sourceIP,
		identity:   identity,
		authSource: authSource,
		host:       host,
		normHost:   normalizeHost(host),
		groups:     groups,
	}
	matched := evalAccessRules(ptrs, &in, time.Now, func(rule *PolicyRule, skip string) {
		trace = append(trace, policyTestTrace{Priority: rule.Priority, Name: rule.Name, SkipReason: skip})
	})
	return trace, matched
}

// POST /api/policy/test — evaluate policy rules against hypothetical inputs.
// Useful for debugging: returns the first matching rule (or no-match) without
// side-effects (hit counts are NOT incremented).
// Body: {"sourceIP":"…","identity":"…","authSource":"…","groups":["…"],"host":"…",
// "protocol":"http|connect","method":"GET"} — protocol/method feed the Stage-1
// auth simulation only.
func apiPolicyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	var body struct {
		SourceIP   string   `json:"sourceIP"`
		Identity   string   `json:"identity"`
		AuthSource string   `json:"authSource"`
		Groups     []string `json:"groups"`
		Host       string   `json:"host"`
		Protocol   string   `json:"protocol"` // "http" (default) | "connect" — Stage-1 simulation only
		Method     string   `json:"method"`   // optional HTTP method — Stage-1 simulation only
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}

	// Evaluate the EFFECTIVE rulebase: the draft candidate when Draft Mode is
	// engaged, else the running store (GAP-POL-03, ADR-0026). rulebase tells the
	// admin which set was simulated so a draft-mode test is never mistaken for a
	// test of live policy. Rules and label come from ONE coordinator-locked
	// snapshot (Codex round 15) — separate reads could interleave with a
	// commit/revert and evaluate an empty candidate or mislabel the set.
	rules, rulebase := effectivePolicySnapshot()

	// Stage-1 simulation (Slice 8): resolve the auth outcome for this request
	// and mirror Slice 7's runtime wiring — a no-credentials Exempt match makes
	// Stage-2 see authSource="exempt". Dry-run: no counters, no hit counts.
	stage2AuthSource, authBlock := simulateAuthOutcome(rules,
		body.SourceIP, body.Host, body.Protocol, body.Method, body.Identity, body.AuthSource)
	body.AuthSource = stage2AuthSource

	// Walk rules manually without incrementing hit counts.
	trace, matched := walkPolicyTestRules(rules, body.SourceIP, body.Identity, body.AuthSource, body.Host, body.Groups)

	// Enrich with category lookup so the admin can see how the host was categorised.
	catName, catTier, catMatchedBy := lookupHostCategory(body.Host)
	hostCategory := map[string]string{
		"category":  catName,
		"tier":      catTier,
		"matchedBy": catMatchedBy,
	}

	if matched == nil {
		defAction := defaultPolicyAction()
		jsonOK(w, map[string]any{
			"matched":       false,
			"defaultAction": defAction,
			"trace":         trace,
			"hostCategory":  hostCategory,
			"auth":          authBlock,
			"rulebase":      rulebase,
		})
		return
	}
	jsonOK(w, map[string]any{
		"matched":      true,
		"rule":         matched,
		"action":       matched.Action,
		"trace":        trace,
		"hostCategory": hostCategory,
		"auth":         authBlock,
		"rulebase":     rulebase,
	})
}

// GET /api/ca-cert — download the Root CA certificate (PEM) for browser/OS import.
// Also returns metadata: subject, expiry, SHA256 fingerprint.
func apiDefaultAction(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]string{"defaultAction": defaultPolicyAction()})
	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Action string `json:"action"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Action != "allow" && body.Action != "deny" {
			http.Error(w, `action must be "allow" or "deny"`, http.StatusBadRequest)
			return
		}
		setDefaultPolicyAction(body.Action)
		auditEvent(r, "policy.default_action", body.Action, "")
		adminSettingsSave()
		saveConfigVersion(sessionAdmin(r), "policy.default_action")
		logger.Printf("UI: default policy action set to %q", body.Action)
		jsonOK(w, map[string]string{"defaultAction": defaultPolicyAction()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/export?format=json|csv — download all logs
func apiExport(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	entries := logGet()
	format := r.URL.Query().Get("format")
	ts := time.Now().Format("20060102-150405")

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="culvert-%s.csv"`, ts))
		cw := csv.NewWriter(w)
		cw.Write([]string{"timestamp", "time", "ip", "identity", "method", "host", "status", "level", "rule_matched", "action_taken", "bytes_sent", "bytes_recv", "ssl_action"}) //nolint:errcheck // CSV write
		for i := range entries {
			e := &entries[i]
			cw.Write([]string{ //nolint:errcheck // CSV write
				fmt.Sprintf("%d", e.TS),
				e.Time, e.IP, e.Identity, e.Method, e.Host, e.Status, e.Level,
				e.RuleMatched, e.ActionTaken,
				fmt.Sprintf("%d", e.BytesSent), fmt.Sprintf("%d", e.BytesRecv),
				e.SSLAction,
			})
		}
		cw.Flush()

	default: // json
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="culvert-%s.json"`, ts))
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // HTTP response write
			"exported": ts,
			"count":    len(entries),
			"logs":     entries,
		})
	}
}

// GET/POST/DELETE /api/ssl-bypass — manage the dynamic SSL bypass pattern list.
//
// Patterns are persisted to the file configured via ssl_bypass_file in
// config.yaml (or -ssl-bypass-file flag). Changes take effect immediately
// without a proxy restart.
//
//	GET    → {"patterns": [...], "count": N}
//	POST   → {"pattern": "*.co.il"} or {"patterns": ["*.co.il","~^.*\.gov\.il$"]}
//	DELETE → ?pattern=*.co.il
func apiSSLBypass(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		patterns := sslBypass.List()
		jsonOK(w, map[string]any{"patterns": patterns, "count": len(patterns)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Pattern  string   `json:"pattern"`
			Patterns []string `json:"patterns"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Pattern != "" {
			body.Patterns = append(body.Patterns, body.Pattern)
		}
		added := 0
		for _, p := range body.Patterns {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if err := sslBypass.Add(p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			logger.Printf("UI: ssl bypass added %q", p)
			added++
		}
		sslBypass.Save()
		auditEvent(r, "ssl_bypass.add", fmt.Sprintf("%d pattern(s)", added),
			strings.Join(body.Patterns, ", "))
		saveConfigVersion(sessionAdmin(r), "ssl_bypass.add")
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		pattern := strings.TrimSpace(r.URL.Query().Get("pattern"))
		if pattern == "" {
			http.Error(w, "missing pattern param", http.StatusBadRequest)
			return
		}
		sslBypass.Remove(pattern)
		sslBypass.Save()
		logger.Printf("UI: ssl bypass removed %q", pattern)
		auditEvent(r, "ssl_bypass.remove", pattern, "")
		saveConfigVersion(sessionAdmin(r), "ssl_bypass.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST/DELETE /api/content-scan — manage DPI signature patterns
//
// These regex patterns are matched against decrypted HTTP response bodies
// flowing through SSL Inspect tunnels.  Only text/* and application/json
// responses are scanned; binary content is passed through unscanned.
//
//	GET    → {"patterns": [...], "count": N, "blocked_total": N}
//	POST   → {"pattern": "evil-keyword"} or {"patterns": ["p1","p2"]}
//	DELETE → ?pattern=evil-keyword

// registerPolicyRoutes wires the policy engine, blocklist, file-block,
// rewrite, URL category, and block-page admin endpoints. All routes are
// gated by uiAuthMiddleware; per-handler RBAC is the handler's
// responsibility.
func registerPolicyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/blocklist", apiBlocklist)
	mux.HandleFunc("/api/fileblock", apiFileblock)
	mux.HandleFunc("/api/fileblock/profiles", apiFileblockProfiles)
	mux.HandleFunc("/api/fileblock/profiles/state", apiFileblockProfilesState)
	mux.HandleFunc("/api/rewrite", apiRewrite)
	mux.HandleFunc("/api/rewrite/state", apiRewriteState)
	mux.HandleFunc("/api/policy", apiPolicy)
	mux.HandleFunc("/api/policy/reorder", apiPolicyReorder)
	mux.HandleFunc("/api/policy/move", apiPolicyMove)
	mux.HandleFunc("/api/policy/test", apiPolicyTest)
	// policy-draft (G2): candidate/commit for the rulebase.
	mux.HandleFunc("/api/policy/draft", apiPolicyDraft)              // GET state+diff / PUT require-commit mode (admin)
	mux.HandleFunc("/api/policy/draft/commit", apiPolicyDraftCommit) // POST commit the candidate (operator)
	mux.HandleFunc("/api/policy/draft/revert", apiPolicyDraftRevert) // POST discard the candidate (operator)
	mux.HandleFunc("/api/objects/references", apiObjectReferences)

	// Stage-1 authentication-policy (auth/exempt) rules — admin-only writes.
	mux.HandleFunc("/api/authpolicy", apiAuthPolicy)                // GET list / POST add / PUT update / DELETE remove
	mux.HandleFunc("/api/authpolicy/reorder", apiAuthPolicyReorder) // POST reorder auth rules among themselves
	mux.HandleFunc("/api/default-action", apiDefaultAction)

	// Blocklist mode + feed sync.
	mux.HandleFunc("/api/blocklist/mode", apiBlocklistMode)             // GET/POST blocklist mode
	mux.HandleFunc("/api/blocklist/feed", apiBlocklistFeed)             // GET list / POST upsert / DELETE remove feed
	mux.HandleFunc("/api/blocklist/feed/sync", apiBlocklistFeedSync)    // POST force-sync (all or ?url=)
	mux.HandleFunc("/api/blocklist/exceptions", apiBlocklistExceptions) // GET/POST/DELETE

	// URL Categories (dynamic host-list management).
	mux.HandleFunc("/api/category-groups", apiCategoryGroups)                             // GET/POST/PUT/DELETE category groups
	mux.HandleFunc("/api/decryption-profiles", apiDecryptionProfiles)                     // GET/POST/PUT/DELETE decryption profiles
	mux.HandleFunc("/api/decryption/health", apiDecryptionHealth)                         // GET ADR-0011 coverage + failure aggregate (viewer, read-only)
	mux.HandleFunc("/api/decryption/redaction", apiDecryptionRedaction)                   // GET viewer / PUT admin — ADR-0011 §4 traffic-log destination-privacy posture (host/URI/dec.*/top_hosts)
	mux.HandleFunc("/api/decryption-exclusions", apiDecryptionExclusions)                 // GET list learned exclusions / DELETE evict one (?host=) or clear all
	mux.HandleFunc("/api/decryption-exclusions/tunables", apiDecryptionExclusionTunables) // GET defaults+bounds / PUT admin runtime tunables (F10)
	mux.HandleFunc("/api/urlcat", apiURLCat)                                              // GET/POST/PUT/DELETE categories
	mux.HandleFunc("/api/urlcat/state", apiURLCatState)                                   // GET — v2 read: categories + server-owned semantic revision (2D-B)
	mux.HandleFunc("/api/urlcat/host", apiURLCatHost)                                     // POST/DELETE individual hosts
	mux.HandleFunc("/api/urlcat/lookup", apiURLCatLookup)                                 // GET — resolve a domain to its category
	mux.HandleFunc("/api/urlcat/feed-status", apiURLCatFeedStatus)                        // GET — UT1 + SaaS feed freshness/failure counts (viewer, read-only)
	mux.HandleFunc("/api/saas-feed/settings", apiSaaSFeedSettings)                        // GET viewer / PUT admin (F3a-2 signed-feed config)
	mux.HandleFunc("/api/saas-feed/overrides", apiSaaSFeedOverrides)                      // GET viewer / PUT admin (F3a-2 category overrides)
	mux.HandleFunc("/api/saas-feed/status", apiSaaSFeedStatus)                            // GET viewer (F3b-4 signed-feed runtime status)
	mux.HandleFunc("/api/saas-feed/refresh", apiSaaSFeedRefresh)                          // POST admin (F3b-4 manual refresh, singleflight)

	// Block page template (shown to users blocked by a policy rule).
	mux.HandleFunc("/api/blockpage", apiBlockPage) // GET template / PUT update
}
