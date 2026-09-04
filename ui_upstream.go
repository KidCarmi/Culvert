package main

// ui_upstream.go — the Upstream admin API (2F-C, contract C4/C6/C9/C10/C11).
//
//   GET  /api/upstream                          effective pool truth (viewer)
//   POST /api/upstream                          v1 compatibility adapter: credential-FREE full
//                                              replacement of the managed set (admin)
//   GET  /api/upstream/settings                 same read model (legacy alias)
//   POST /api/upstream/health                   probe now with the shared classifier (admin)
//   POST /api/upstream/entries                  create a managed entry (admin)
//   PUT|DELETE /api/upstream/entries/{id}       edit / delete a managed entry (admin)
//   POST /api/upstream/entries/{id}/credential  {action:replace,password,revision} (T2)
//                                              {action:clear,revision,confirm:<id>} (T3)
//
// Every managed-entry mutation is revision-fenced (428 missing / 409 stale
// with the current token / 404 vanished), runs INSIDE the admin-settings
// save lock against the current document, and is durable BEFORE it answers:
// a failed write is a non-2xx with zero visible mutation. YAML-owned
// entries answer 409 yaml_owned to every mutation. A credential is bound to
// its entry's immutable id AND canonical authority: an authority change
// while material exists is 409 credential_bound, a delete while material
// exists is 409 credential_present. Derived state (credentialState) is never
// accepted from a client (the strict decoder answers 400). Audit carries the
// entry id, the credential-free authority and the action — never a password.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

const upstreamMaxPasswordLen = 1024

// upstreamRefusal is a structured, bounded refusal produced inside the
// locked mutation and rendered by the handler.
type upstreamRefusal struct {
	Status  int
	Code    string
	Msg     string
	Current map[string]any
	// Extra carries bounded top-level fields beside error/code/current
	// (the duplicate-authority count for the legacy surface).
	Extra map[string]any
}

func (e *upstreamRefusal) Error() string { return e.Code + ": " + e.Msg }

func writeUpstreamRefusal(w http.ResponseWriter, ref *upstreamRefusal) {
	cur := ref.Current
	if cur == nil {
		cur = map[string]any{}
	}
	body := map[string]any{"error": ref.Msg, "code": ref.Code, "current": cur}
	for k, v := range ref.Extra {
		if k != "error" && k != "code" && k != "current" {
			body[k] = v
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ref.Status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.Printf("ERROR: upstream refusal encode failed: %v", err)
	}
}

// upstreamDecode strict-decodes a mutation body into v and renders a bounded
// structured 400 on failure: a body that tries to assert the DERIVED
// credential state (credentialState / credential_configured) is refused as
// credential_state_not_accepted (C4); anything else is invalid_json. The
// decoder error text is bounded and never echoes a value.
func upstreamDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	err := decodeJSON(r, v)
	if err == nil {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, `"credentialState"`) || strings.Contains(msg, `"credential_configured"`) {
		writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusBadRequest, Code: "credential_state_not_accepted",
			Msg: "credentialState is derived by the server and is never accepted from a client"})
		return false
	}
	if len(msg) > 160 {
		msg = msg[:160]
	}
	writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusBadRequest, Code: "invalid_json", Msg: "invalid JSON: " + msg})
	return false
}

// upstreamView is the read model shared by every upstream GET/POST answer.
func upstreamView() map[string]any {
	list := upstreamPool.List()
	eff := upstreamPool.Effective()
	doc := upstreamPool.Document()
	st := getUpstreamState()
	ineligible := 0
	for i := range list {
		if cs := list[i].CredentialState; cs == upstream.CredentialUnusable || cs == upstream.CredentialMismatch {
			ineligible++
		}
	}
	probeConfigured, probeInterval := upstreamPool.ProbeConfig()
	v := map[string]any{
		"enabled":   upstreamPool.Enabled(),
		"mode":      eff.Mode,
		"effective": eff,
		// Coverage is backend-derived truth per client path: only the
		// plain-HTTP forward path is chained (PX-1: CONNECT, WebSocket and
		// SOCKS5 client traffic always egress direct).
		"coverage": map[string]any{
			"plainHttp": "chained", "connect": "direct", "websocket": "direct", "socks5": "direct",
			"summary": "plain_http_only",
		},
		"probe":                 map[string]any{"configured": probeConfigured, "interval": probeInterval.String()},
		"revision":              doc.Revision,
		"entries":               list,
		"proxies":               list, // legacy field: same credential-free rows
		"direct_fallback":       upstreamDirectFallbackStatus(),
		"migration":             st.Migration,
		"key":                   st.Key,
		"credentialsIneligible": ineligible,
		"scope":                 "node-local",
	}
	if st.Degraded != nil {
		v["degraded"] = st.Degraded
	}
	if st.YAMLDegraded != nil {
		v["yamlDegraded"] = st.YAMLDegraded
	}
	return v
}

func apiUpstream(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, upstreamView())
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiUpstreamV1Replace(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiUpstreamSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, upstreamView())
}

// apiUpstreamHealth runs the shared probe classifier now (admin). The
// response carries bounded reasons only.
func apiUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	upstreamPool.HealthCheck(upstream.ProbeManual)
	v := upstreamView()
	v["ok"] = true
	jsonOK(w, v)
}

// upstreamMutate runs fn INSIDE the admin-settings lock against the current
// managed document and answers only after the durable write landed. fn
// returns the target document and an outcome (audit + response) or a typed
// refusal. On success the pool is already re-published.
func upstreamMutate(w http.ResponseWriter, r *http.Request, fn func(cur upstream.Document) (upstream.Document, *upstreamOutcome, error)) {
	// Review blocker 3: a rejected stored document freezes every managed
	// mutation (the save core re-checks under its own lock as well).
	if upstreamRejectedActive() {
		writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusConflict, Code: "document_rejected",
			Msg: errUpstreamDocumentRejected.Error(), Current: map[string]any{"degraded": getUpstreamState().Degraded}})
		return
	}
	var out *upstreamOutcome
	err := saveAdminSettingsWithOverrides(adminSaveOverrides{upstreamMutate: func(cur upstream.Document) (upstream.Document, error) {
		next, o, err := fn(cur)
		if err != nil {
			return cur, err
		}
		out = o
		return next, nil
	}})
	if err != nil {
		if errors.Is(err, errUpstreamDocumentRejected) {
			writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusConflict, Code: "document_rejected", Msg: err.Error()})
			return
		}
		var ref *upstreamRefusal
		if errors.As(err, &ref) {
			writeUpstreamRefusal(w, ref)
			return
		}
		var dup *upstream.DuplicateAuthorityError
		if errors.As(err, &dup) {
			writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusConflict, Code: "duplicate_authority",
				Msg:     "the effective pool (YAML-owned + managed) would carry duplicate canonical authorities; nothing was changed",
				Current: map[string]any{"count": dup.Count}, Extra: map[string]any{"count": dup.Count}})
			return
		}
		var inv *upstream.InvalidEntryError
		if errors.As(err, &inv) {
			writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusBadRequest, Code: "invalid_entry",
				Msg: "an entry is invalid; nothing was changed: " + inv.Reason, Current: map[string]any{"index": inv.Index, "id": inv.ID}})
			return
		}
		logger.Printf("Upstream: mutation not persisted (%s); nothing was changed", sanitizeLog(upstreamPersistReason(err)))
		writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusInternalServerError, Code: "persist_failed",
			Msg: "the change could not be made durable; nothing was changed"})
		return
	}
	if out != nil {
		auditEvent(r, out.action, out.object, out.detail)
		v := upstreamView()
		for k, val := range out.result {
			v[k] = val
		}
		w.WriteHeader(out.status)
		jsonWrite(w, v)
	}
}

// upstreamPersistReason renders a save error as a bounded class (a
// filesystem error can embed a path but never a credential; keep it short).
func upstreamPersistReason(err error) string {
	if err == nil {
		return "unknown"
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

type upstreamOutcome struct {
	status int
	action string
	object string
	detail string
	result map[string]any
}

// jsonWrite is jsonOK without the status (the caller set it).
func jsonWrite(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Printf("ERROR: upstream response encode failed: %v", err)
	}
}

// ── v1 adapter ────────────────────────────────────────────────────────────

type upstreamV1Request struct {
	Proxies  []UpstreamEntry `json:"proxies"`
	Revision int64           `json:"revision"`
}

// apiUpstreamV1Replace is the credential-free compatibility adapter (C6):
// 400 on any userinfo or invalid entry (nothing dropped), 409
// credentialed_entries_present while any managed entry holds material (it
// never mutates or omits a credentialed entry), revision-fenced on the
// document revision, YAML-owned authorities skipped (YAML owns them).
func apiUpstreamV1Replace(w http.ResponseWriter, r *http.Request) {
	var body upstreamV1Request
	if !upstreamDecode(w, r, &body) {
		return
	}
	body.Revision = pacFenceInt(r, "revision", body.Revision)
	upstreamMutate(w, r, func(cur upstream.Document) (upstream.Document, *upstreamOutcome, error) {
		if ref := upstreamFenceDoc(body.Revision, cur.Revision); ref != nil {
			return cur, nil, ref
		}
		// The state gate comes first: while any managed entry holds a
		// credential the credential-free replacement is refused whatever
		// the body says (a re-POST of the listed authorities included).
		for i := range cur.Entries {
			if cur.Entries[i].Credential != nil {
				return cur, nil, &upstreamRefusal{Status: http.StatusConflict, Code: "credentialed_entries_present",
					Msg:     "the managed pool holds credentialed entries; the credential-free v1 replacement is refused — manage entries individually through /api/upstream/entries",
					Current: map[string]any{"revision": cur.Revision, "credentialed": upstreamCredentialedIDs(cur)}}
			}
		}
		specs := make([]upstream.Spec, 0, len(body.Proxies))
		for i, e := range body.Proxies {
			spec, _, hasPW, err := upstream.SpecFromURL(e.URL)
			if err != nil {
				return cur, nil, &upstreamRefusal{Status: http.StatusBadRequest, Code: "invalid_entry",
					Msg: fmt.Sprintf("entry %d is invalid (%s); nothing was changed", i, err.Error()), Current: map[string]any{"index": i}}
			}
			if hasPW || spec.Username != "" {
				return cur, nil, &upstreamRefusal{Status: http.StatusBadRequest, Code: "userinfo_not_allowed",
					Msg:     fmt.Sprintf("entry %d carries userinfo; the v1 list is credential-free — set credentials through /api/upstream/entries/{id}/credential", i),
					Current: map[string]any{"index": i}}
			}
			specs = append(specs, spec)
		}
		next, yamlOwned := upstreamRebuildFromSpecs(cur, specs)
		return next, &upstreamOutcome{status: http.StatusOK, action: "upstream.update",
			object: fmt.Sprintf("%d proxies", len(next.Entries)),
			detail: fmt.Sprintf("v1 replace managed=%d yamlOwnedSkipped=%d", len(next.Entries), yamlOwned),
			result: map[string]any{"ok": true, "yamlOwned": yamlOwned}}, nil
	})
}

func upstreamCredentialedIDs(doc upstream.Document) []string {
	var ids []string
	for i := range doc.Entries {
		if doc.Entries[i].Credential != nil {
			ids = append(ids, doc.Entries[i].ID)
		}
	}
	return ids
}

// upstreamRebuildFromSpecs builds the next managed document from
// credential-free specs, preserving the identity of an existing managed
// entry with the same canonical authority and skipping YAML-owned ones.
func upstreamRebuildFromSpecs(cur upstream.Document, specs []upstream.Spec) (next upstream.Document, yamlOwned int) {
	byAuth := map[string]upstream.ManagedEntry{}
	for i := range cur.Entries {
		byAuth[cur.Entries[i].AuthorityHash()] = cur.Entries[i]
	}
	yamlAuth := map[string]struct{}{}
	yaml := upstreamPool.YAMLEntries()
	for i := range yaml {
		yamlAuth[yaml[i].AuthorityHash()] = struct{}{}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	next = upstream.Document{Schema: upstream.DocumentSchema, Revision: cur.Revision + 1}
	for i := range specs {
		spec := specs[i]
		h := spec.AuthorityHash()
		if _, owned := yamlAuth[h]; owned {
			yamlOwned++
			continue
		}
		if prev, ok := byAuth[h]; ok {
			next.Entries = append(next.Entries, prev)
			continue
		}
		next.Entries = append(next.Entries, upstream.ManagedEntry{
			ID: upstreamNewID(cur), Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username,
			Revision: 1, Source: upstream.SourceManaged, CreatedAt: now, UpdatedAt: now,
		})
	}
	return next, yamlOwned
}

// upstreamNewID mints a ULID that collides with no managed or YAML id.
func upstreamNewID(cur upstream.Document) string {
	taken := map[string]struct{}{}
	for i := range cur.Entries {
		taken[cur.Entries[i].ID] = struct{}{}
	}
	yaml := upstreamPool.YAMLEntries()
	for i := range yaml {
		taken[yaml[i].ID] = struct{}{}
	}
	for {
		id := upstream.NewManagedID()
		if _, dup := taken[id]; !dup {
			return id
		}
	}
}

// ── Fences ────────────────────────────────────────────────────────────────

func upstreamFenceDoc(token, current int64) *upstreamRefusal {
	if token == 0 {
		return &upstreamRefusal{Status: http.StatusPreconditionRequired, Code: pacFenceCodePreconditionRequired,
			Msg: fmt.Sprintf("precondition required: echo the current revision you loaded (%d)", current), Current: map[string]any{"revision": current}}
	}
	if token != current {
		return &upstreamRefusal{Status: http.StatusConflict, Code: pacFenceCodeStale,
			Msg: fmt.Sprintf("stale revision %d (current %d): the pool changed since you loaded it — reload and retry", token, current), Current: map[string]any{"revision": current}}
	}
	return nil
}

func upstreamFenceEntry(token int64, e *upstream.ManagedEntry) *upstreamRefusal {
	if token == 0 {
		return &upstreamRefusal{Status: http.StatusPreconditionRequired, Code: pacFenceCodePreconditionRequired,
			Msg: fmt.Sprintf("precondition required: echo the entry revision you loaded (%d)", e.Revision), Current: map[string]any{"revision": e.Revision, "id": e.ID}}
	}
	if token != e.Revision {
		return &upstreamRefusal{Status: http.StatusConflict, Code: pacFenceCodeStale,
			Msg: fmt.Sprintf("stale revision %d (current %d): the entry changed since you loaded it — reload and retry", token, e.Revision), Current: map[string]any{"revision": e.Revision, "id": e.ID}}
	}
	return nil
}

// upstreamLocateEntry resolves id inside the locked document: a YAML-owned
// id is 409 yaml_owned, an unknown id is 404 vanished.
func upstreamLocateEntry(cur *upstream.Document, id string) (int, *upstreamRefusal) {
	yaml := upstreamPool.YAMLEntries()
	for i := range yaml {
		if yaml[i].ID == id {
			return -1, &upstreamRefusal{Status: http.StatusConflict, Code: "yaml_owned",
				Msg: "this entry is owned by config.yaml and is read-only through the API; edit the YAML and reload", Current: map[string]any{"id": id, "source": "yaml"}}
		}
	}
	for i := range cur.Entries {
		if cur.Entries[i].ID == id {
			return i, nil
		}
	}
	return -1, &upstreamRefusal{Status: http.StatusNotFound, Code: "vanished", Msg: "the entry no longer exists", Current: map[string]any{"id": id}}
}

// ── v2 entries ────────────────────────────────────────────────────────────

type upstreamEntryRequest struct {
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Revision int64  `json:"revision"`
}

// POST /api/upstream/entries
func apiUpstreamEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body upstreamEntryRequest
	if !upstreamDecode(w, r, &body) {
		return
	}
	body.Revision = pacFenceInt(r, "revision", body.Revision)
	spec, err := upstream.Normalize(upstream.Spec{Scheme: body.Scheme, Host: body.Host, Port: body.Port, Username: body.Username})
	if err != nil {
		writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusBadRequest, Code: "invalid_entry", Msg: err.Error()})
		return
	}
	upstreamMutate(w, r, func(cur upstream.Document) (upstream.Document, *upstreamOutcome, error) {
		if ref := upstreamFenceDoc(body.Revision, cur.Revision); ref != nil {
			return cur, nil, ref
		}
		now := time.Now().UTC().Format(time.RFC3339)
		e := upstream.ManagedEntry{
			ID: upstreamNewID(cur), Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username,
			Revision: 1, Source: upstream.SourceManaged, CreatedAt: now, UpdatedAt: now,
		}
		next := cur.Clone()
		next.Schema = upstream.DocumentSchema
		next.Revision++
		next.Entries = append(next.Entries, e)
		return next, &upstreamOutcome{status: http.StatusCreated, action: "upstream.entry.create", object: e.ID,
			detail: "authority=" + e.Authority(), result: map[string]any{"entry": upstreamEntryDTO(e)}}, nil
	})
}

func upstreamEntryDTO(e upstream.ManagedEntry) map[string]any {
	state := upstream.CredentialNone
	list := upstreamPool.List()
	for i := range list {
		if list[i].ID == e.ID {
			state = list[i].CredentialState
		}
	}
	return map[string]any{
		"id": e.ID, "scheme": e.Scheme, "host": e.Host, "port": e.Port, "username": e.Username,
		"authority": e.Authority(), "source": e.Source, "revision": e.Revision, "credentialState": state,
	}
}

// /api/upstream/entries/{id}[/credential]
func apiUpstreamEntryRouter(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/upstream/entries/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" || strings.Contains(sub, "/") {
		http.NotFound(w, r)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	switch {
	case sub == "" && r.Method == http.MethodPut:
		apiUpstreamEntryUpdate(w, r, id)
	case sub == "" && r.Method == http.MethodDelete:
		apiUpstreamEntryDelete(w, r, id)
	case sub == "credential" && r.Method == http.MethodPost:
		apiUpstreamEntryCredential(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiUpstreamEntryUpdate(w http.ResponseWriter, r *http.Request, id string) {
	var body upstreamEntryRequest
	if !upstreamDecode(w, r, &body) {
		return
	}
	body.Revision = pacFenceInt(r, "revision", body.Revision)
	spec, err := upstream.Normalize(upstream.Spec{Scheme: body.Scheme, Host: body.Host, Port: body.Port, Username: body.Username})
	if err != nil {
		writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusBadRequest, Code: "invalid_entry", Msg: err.Error()})
		return
	}
	upstreamMutate(w, r, func(cur upstream.Document) (upstream.Document, *upstreamOutcome, error) {
		i, ref := upstreamLocateEntry(&cur, id)
		if ref != nil {
			return cur, nil, ref
		}
		if ref := upstreamFenceEntry(body.Revision, &cur.Entries[i]); ref != nil {
			return cur, nil, ref
		}
		next := cur.Clone()
		e := &next.Entries[i]
		if e.Credential != nil && spec.AuthorityHash() != e.AuthorityHash() {
			return cur, nil, &upstreamRefusal{Status: http.StatusConflict, Code: "credential_bound",
				Msg:     "a credential is bound to this entry's authority; clear it (T3), edit the authority, then set a new credential — there is no combined rebind",
				Current: map[string]any{"id": e.ID, "revision": e.Revision, "authority": e.Authority(), "credentialState": upstreamEntryDTO(*e)["credentialState"]}}
		}
		before := e.Authority()
		e.Scheme, e.Host, e.Port, e.Username = spec.Scheme, spec.Host, spec.Port, spec.Username
		e.Revision++
		e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		next.Revision++
		return next, &upstreamOutcome{status: http.StatusOK, action: "upstream.entry.update", object: e.ID,
			detail: "authority=" + e.Authority() + " previous=" + before, result: map[string]any{"entry": upstreamEntryDTO(*e)}}, nil
	})
}

func apiUpstreamEntryDelete(w http.ResponseWriter, r *http.Request, id string) {
	token := pacFenceInt(r, "revision", 0)
	upstreamMutate(w, r, func(cur upstream.Document) (upstream.Document, *upstreamOutcome, error) {
		i, ref := upstreamLocateEntry(&cur, id)
		if ref != nil {
			return cur, nil, ref
		}
		if ref := upstreamFenceEntry(token, &cur.Entries[i]); ref != nil {
			return cur, nil, ref
		}
		e := cur.Entries[i]
		if e.Credential != nil {
			return cur, nil, &upstreamRefusal{Status: http.StatusConflict, Code: "credential_present",
				Msg:     "this entry holds credential material (configured, unusable or mismatch); clear the credential (T3) before deleting it",
				Current: map[string]any{"id": e.ID, "revision": e.Revision, "credentialState": upstreamEntryDTO(e)["credentialState"]}}
		}
		next := cur.Clone()
		next.Entries = append(next.Entries[:i], next.Entries[i+1:]...)
		next.Revision++
		return next, &upstreamOutcome{status: http.StatusOK, action: "upstream.entry.delete", object: e.ID,
			detail: "authority=" + e.Authority(), result: map[string]any{"deleted": e.ID}}, nil
	})
}

type upstreamCredentialRequest struct {
	Action   string `json:"action"` // replace | clear
	Password string `json:"password"`
	Revision int64  `json:"revision"`
	Confirm  string `json:"confirm"`
}

func apiUpstreamEntryCredential(w http.ResponseWriter, r *http.Request, id string) {
	var body upstreamCredentialRequest
	if !upstreamDecode(w, r, &body) {
		return
	}
	body.Revision = pacFenceInt(r, "revision", body.Revision)
	switch body.Action {
	case "replace":
		if body.Password == "" || len(body.Password) > upstreamMaxPasswordLen {
			writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusBadRequest, Code: "invalid_password", Msg: "password is required (1..1024 bytes)"})
			return
		}
	case "clear":
	default:
		writeUpstreamRefusal(w, &upstreamRefusal{Status: http.StatusBadRequest, Code: "invalid_action", Msg: `action must be "replace" or "clear"`})
		return
	}
	actor := sessionAdmin(r)
	upstreamMutate(w, r, func(cur upstream.Document) (upstream.Document, *upstreamOutcome, error) {
		i, ref := upstreamLocateEntry(&cur, id)
		if ref != nil {
			return cur, nil, ref
		}
		if ref := upstreamFenceEntry(body.Revision, &cur.Entries[i]); ref != nil {
			return cur, nil, ref
		}
		next := cur.Clone()
		e := &next.Entries[i]
		now := time.Now().UTC().Format(time.RFC3339)
		switch body.Action {
		case "replace":
			key, err := upstreamEnsureKey()
			if err != nil {
				return cur, nil, &upstreamRefusal{Status: http.StatusConflict, Code: "key_unusable",
					Msg: "the node-local credential key is unavailable; restore .upstream_cred_key (or clear every sealed credential) before setting a credential", Current: map[string]any{"id": e.ID, "revision": e.Revision}}
			}
			sealed, err := key.Seal(body.Password, e.ID, e.AuthorityHash(), now, actor)
			if err != nil {
				return cur, nil, &upstreamRefusal{Status: http.StatusInternalServerError, Code: "seal_failed", Msg: "the credential could not be sealed; nothing was changed"}
			}
			e.Credential = sealed
			e.Revision++
			e.UpdatedAt = now
			next.Revision++
			return next, &upstreamOutcome{status: http.StatusOK, action: "upstream.credential.replace", object: e.ID,
				detail: "authority=" + e.Authority(), result: map[string]any{"entry": upstreamEntryDTOFrom(*e, upstream.CredentialConfigured)}}, nil
		default: // clear (T3): the exact entry id must be typed
			if e.Credential == nil {
				return cur, nil, &upstreamRefusal{Status: http.StatusConflict, Code: "no_credential", Msg: "this entry holds no credential material", Current: map[string]any{"id": e.ID, "revision": e.Revision}}
			}
			if body.Confirm != e.ID {
				return cur, nil, &upstreamRefusal{Status: http.StatusConflict, Code: "confirm_required",
					Msg: "clearing a credential is a Tier-3 action: retype the exact entry id into confirm", Current: map[string]any{"id": e.ID, "revision": e.Revision, "confirmField": "confirm", "confirmValue": e.ID}}
			}
			e.Credential = nil
			e.Revision++
			e.UpdatedAt = now
			next.Revision++
			return next, &upstreamOutcome{status: http.StatusOK, action: "upstream.credential.clear", object: e.ID,
				detail: "authority=" + e.Authority(), result: map[string]any{"entry": upstreamEntryDTOFrom(*e, upstream.CredentialNone)}}, nil
		}
	})
}

// upstreamEntryDTOFrom renders an entry with the state the mutation just
// established (the pool has been re-published, but derive from the fact).
func upstreamEntryDTOFrom(e upstream.ManagedEntry, state string) map[string]any {
	d := upstreamEntryDTO(e)
	d["credentialState"] = state
	return d
}
