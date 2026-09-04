package main

// upstream_portability.go — the 2F-D Upstream v2 portability contract
// (approved 2F contract C5/C9/C12, docs/design/FRONTEND-MIGRATION-PLAN.md):
//
//   - EXPORT emits the versioned `upstream_proxies_v2` representation
//     ({id, scheme, host, port, username, credentialState} per MANAGED entry)
//     plus `upstream_credentials: "omitted"`. It never carries a password,
//     a sealed record, ciphertext, a key id, the `xxxxx` redaction marker or
//     the legacy URL list (the legacy key is import-only compatibility).
//   - IMPORT is planned over the WHOLE file before any store is touched:
//     every incoming entry is classified preserve | create | update |
//     requiresReplacement, every existing managed entry retain | remove, and
//     any removal / replacement / authority change of a CREDENTIALED entry
//     sets credentialClearRequired and refuses the import with 409
//     credential_clear_required carrying the complete plan. A dry-run
//     (?dryRun=1) returns the plan + a deterministic importDigest and applies
//     nothing; the commit re-plans under the authoritative admin-settings
//     lock and refuses a stale digest before anything mutates.
//   - Credential material NEVER travels: an incoming entry inherits a
//     credential only when its ID resolves to exactly one existing entry and
//     the canonical authority hash is unchanged (preserve). A changed or
//     unknown identity/authority that DECLARED a credential lands in the
//     distinct durable requiresReplacement state instead.
//   - The legacy `upstreamProxies` list stays importable under the versioned
//     compatibility rule: `xxxxx` preserves only an exact, unique
//     canonical-authority match; a real password is 400
//     credentials_not_importable; a legacy list carries no identity, so an
//     omission is NEVER a removal (the 2F-C rule): unnamed credentialed
//     entries are retained in every mode.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// configBackupVersion is the export schema version: 2 since 2F-D (the
// upstream_proxies_v2 representation replaced the legacy upstreamProxies
// list). Import accepts 1 (legacy exports) and 2.
const configBackupVersion = 2

// upstreamCredentialsOmitted is the constant value of the export's
// `upstream_credentials` field: no export ever carries material.
const upstreamCredentialsOmitted = "omitted"

// upstreamExportEntry is one exported managed entry — the C5 shape and
// NOTHING else (pinned by the RED matrix: any extra field fails).
type upstreamExportEntry struct {
	ID              string `json:"id"`
	Scheme          string `json:"scheme"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	CredentialState string `json:"credentialState"`
}

// upstreamExportDocument is the `upstream_proxies_v2` export section.
type upstreamExportDocument struct {
	Entries []upstreamExportEntry `json:"entries"`
}

// upstreamExportNow renders the managed document for export (YAML-owned
// entries live in config.yaml and are never exported as managed state).
func upstreamExportNow() *upstreamExportDocument {
	doc := upstreamPool.Document()
	states := map[string]string{}
	list := upstreamPool.List()
	for i := range list {
		states[list[i].ID] = list[i].CredentialState
	}
	out := &upstreamExportDocument{Entries: make([]upstreamExportEntry, 0, len(doc.Entries))}
	for i := range doc.Entries {
		e := &doc.Entries[i]
		state, ok := states[e.ID]
		if !ok {
			state = upstream.CredentialNone
			if e.Credential != nil {
				state = upstream.CredentialConfigured
			} else if e.RequiresReplacement {
				state = upstream.CredentialRequiresReplacement
			}
		}
		out.Entries = append(out.Entries, upstreamExportEntry{
			ID: e.ID, Scheme: e.Scheme, Host: e.Host, Port: e.Port, Username: e.Username, CredentialState: state,
		})
	}
	return out
}

// ── Import plan ────────────────────────────────────────────────────────────

// Plan actions (bounded vocabulary, C9).
const (
	planPreserve            = "preserve"
	planCreate              = "create"
	planUpdate              = "update"
	planRequiresReplacement = "requiresReplacement"
	planRetain              = "retain"
	planRemove              = "remove"
)

type upstreamPlanItem struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

// upstreamImportPlan is the complete, counts-and-identities-only plan of
// what an import would do to the managed document. It carries entry IDs
// and actions — never an authority, username or credential.
type upstreamImportPlan struct {
	Mode                    string             `json:"mode"`
	Incoming                []upstreamPlanItem `json:"incoming"`
	Existing                []upstreamPlanItem `json:"existing"`
	CredentialClearRequired []string           `json:"credentialClearRequired"`
	Counts                  map[string]int     `json:"counts"`
	// YAMLOwnedSkipped counts incoming entries whose canonical authority is
	// owned by config.yaml on this node (read-only; never adopted).
	YAMLOwnedSkipped int `json:"yamlOwnedSkipped"`
	// Legacy is true when the payload carried only the pre-2F-D
	// upstreamProxies list (authority-keyed compatibility rule).
	Legacy bool `json:"legacy,omitempty"`
}

// upstreamImportResult is the counts-only commit summary (C5).
type upstreamImportResult struct {
	Preserved           int `json:"preserved"`
	Omitted             int `json:"omitted"`
	Cleared             int `json:"cleared"`
	RequiresReplacement int `json:"requiresReplacement"`
}

// upstreamImportPlanned is the outcome of planning: the plan, the target
// document (nil when the payload carries no upstream section), the digest
// and the commit summary.
type upstreamImportPlanned struct {
	Plan   *upstreamImportPlan
	Next   *upstream.Document
	Digest string
	Result upstreamImportResult
}

// errUpstreamCredentialClearRequired is the typed 409 (C9): the plan is
// attached so the refusal can carry it whole.
type upstreamClearRequiredError struct{ Plan *upstreamImportPlan }

func (e *upstreamClearRequiredError) Error() string {
	return "credential_clear_required: the import would remove, replace or change the authority of " +
		fmt.Sprintf("%d entr(y/ies) that hold or require a credential; set (Tier-2) or clear (Tier-3) each credential first", len(e.Plan.CredentialClearRequired))
}

// errUpstreamImportStale is the commit-time refusal when the document moved
// between the dry-run digest and the commit.
var errUpstreamImportStale = errors.New("import_stale: the upstream document changed since the plan was computed; re-run the dry-run")

// upstreamPlanImport plans the upstream section of an import against the
// CURRENT managed document (`cur`, read by the caller — under the
// authoritative lock at commit time). It never touches a store.
func upstreamPlanImport(b *configBackup, replace bool, cur upstream.Document) (*upstreamImportPlanned, error) {
	hasV2 := b.UpstreamProxiesV2 != nil
	hasLegacy := len(b.UpstreamProxies) > 0
	if hasV2 && hasLegacy {
		return nil, &upstreamImportError{Code: "ambiguous_upstream_sections", Index: 0,
			Msg: "a backup must carry either upstream_proxies_v2 or the legacy upstreamProxies list, not both"}
	}
	if err := upstreamValidateImportEnvelope(b, hasV2, hasLegacy); err != nil {
		return nil, err
	}
	if !hasV2 && !hasLegacy {
		return &upstreamImportPlanned{}, nil
	}
	if upstreamRejectedActive() {
		return nil, errUpstreamDocumentRejected
	}
	if hasV2 {
		return upstreamPlanV2(b.UpstreamProxiesV2.Entries, replace, cur)
	}
	return upstreamPlanLegacy(b.UpstreamProxies, replace, cur)
}

func newUpstreamPlan(replace bool) *upstreamImportPlan {
	mode := "merge"
	if replace {
		mode = "replace"
	}
	return &upstreamImportPlan{Mode: mode, Incoming: []upstreamPlanItem{}, Existing: []upstreamPlanItem{},
		CredentialClearRequired: []string{}, Counts: map[string]int{
			planPreserve: 0, planCreate: 0, planUpdate: 0, planRequiresReplacement: 0, planRetain: 0, planRemove: 0,
		}}
}

func (p *upstreamImportPlan) incoming(id, action string) {
	p.Incoming = append(p.Incoming, upstreamPlanItem{ID: id, Action: action})
	p.Counts[action]++
}

func (p *upstreamImportPlan) existing(id, action string) {
	p.Existing = append(p.Existing, upstreamPlanItem{ID: id, Action: action})
	p.Counts[action]++
}

// upstreamEntryHasMaterial reports whether an entry holds credential
// material (configured, unusable or mismatch all count).
func upstreamEntryHasMaterial(e *upstream.ManagedEntry) bool { return e.Credential != nil }

// upstreamEntryProtected is the C9/C12 refusal predicate: an import may
// never silently discard credential MATERIAL, and it may never clear or
// discard the durable requiresReplacement TRUST STATE either — that state
// is resolved only by an explicit T2 replace or T3 clear on the credential
// endpoint (2F-D correction, CR1/CR2). Both shapes therefore refuse an
// authority change and a replace-mode omission with the complete plan.
func upstreamEntryProtected(e *upstream.ManagedEntry) bool {
	return e.Credential != nil || e.RequiresReplacement
}

// upstreamRecognizedCredentialState is the closed vocabulary a versioned
// export may declare per entry (C4 derived states + the C12 marker state).
// Anything else — including an absent value — is a schema error, never
// credential evidence (2F-D correction, CR5/CR6).
func upstreamRecognizedCredentialState(s string) bool {
	switch s {
	case upstream.CredentialNone, upstream.CredentialConfigured, upstream.CredentialUnusable,
		upstream.CredentialMismatch, upstream.CredentialRequiresReplacement:
		return true
	}
	return false
}

// upstreamEnvelopeError is the structured 400 for a versioned-schema
// violation of the import envelope (no entry index applies).
type upstreamEnvelopeError struct{ Code, Msg string }

func (e *upstreamEnvelopeError) Error() string { return e.Code + ": " + e.Msg }

// upstreamValidateImportEnvelope pins the versioned credential-omission
// schema BEFORE planning or any mutation (2F-D correction, CR7/CR8): a
// `upstream_proxies_v2` section is coherent only under version
// configBackupVersion with the exact `upstream_credentials:"omitted"`
// marker; the legacy `upstreamProxies` list belongs to version 1 and never
// carries the marker; a marker without the section is a mismatch. The
// offending value is never echoed.
func upstreamValidateImportEnvelope(b *configBackup, hasV2, hasLegacy bool) error {
	hasMarker := b.UpstreamCredentials != ""
	switch {
	case hasV2:
		if b.Version != configBackupVersion {
			return &upstreamEnvelopeError{Code: "schema_mismatch",
				Msg: fmt.Sprintf("upstream_proxies_v2 requires backup version %d (got %d)", configBackupVersion, b.Version)}
		}
		if !hasMarker {
			return &upstreamEnvelopeError{Code: "invalid_upstream_credentials_marker",
				Msg: "the versioned export must declare upstream_credentials: \"omitted\""}
		}
		if b.UpstreamCredentials != upstreamCredentialsOmitted {
			return &upstreamEnvelopeError{Code: "invalid_upstream_credentials_marker",
				Msg: "unrecognized upstream_credentials marker; the versioned export declares \"omitted\" only"}
		}
	case hasLegacy:
		if b.Version != 1 || hasMarker {
			return &upstreamEnvelopeError{Code: "schema_mismatch",
				Msg: "the legacy upstreamProxies list belongs to backup version 1 and carries no upstream_credentials marker"}
		}
	case hasMarker:
		return &upstreamEnvelopeError{Code: "schema_mismatch",
			Msg: "upstream_credentials marker without an upstream_proxies_v2 section"}
	}
	return nil
}

// upstreamPlanV2 is the identity-keyed plan (C9).
func upstreamPlanV2(in []upstreamExportEntry, replace bool, cur upstream.Document) (*upstreamImportPlanned, error) {
	plan := newUpstreamPlan(replace)
	yaml := upstreamPool.YAMLEntries()
	yamlAuth := map[string]struct{}{}
	for i := range yaml {
		yamlAuth[yaml[i].AuthorityHash()] = struct{}{}
	}
	byID := map[string]int{}
	for i := range cur.Entries {
		byID[cur.Entries[i].ID] = i
	}
	now := time.Now().UTC().Format(time.RFC3339)
	next := upstream.Document{Schema: upstream.DocumentSchema, Revision: cur.Revision + 1}
	named := map[string]struct{}{}
	var res upstreamImportResult
	ctx := &planV2Ctx{plan: plan, cur: cur, byID: byID, yamlAuth: yamlAuth, named: named, next: &next, res: &res, now: now}
	seenID := map[string]struct{}{}
	for i := range in {
		ie := &in[i]
		id := strings.TrimSpace(ie.ID)
		if id == "" || !upstream.IsULID(id) {
			return nil, &upstreamImportError{Code: "invalid_entry", Index: i, Msg: "entry id must be a ULID"}
		}
		if _, dup := seenID[id]; dup {
			return nil, &upstreamImportError{Code: "duplicate_id", Index: i, Msg: "the same entry id appears twice in the import"}
		}
		seenID[id] = struct{}{}
		if !upstreamRecognizedCredentialState(ie.CredentialState) {
			return nil, &upstreamImportError{Code: "invalid_credential_state", Index: i,
				Msg: "credentialState must be one of none, configured, unusable, mismatch, requiresReplacement"}
		}
		spec, err := upstream.Normalize(upstream.Spec{Scheme: ie.Scheme, Host: ie.Host, Port: ie.Port, Username: ie.Username})
		if err != nil {
			return nil, &upstreamImportError{Code: "invalid_entry", Index: i, Msg: err.Error()}
		}
		declared := ie.CredentialState != upstream.CredentialNone
		ctx.classify(id, spec, declared)
	}
	// Existing entries the import did not name.
	for i := range cur.Entries {
		e := cur.Entries[i]
		if _, ok := named[e.ID]; ok {
			continue
		}
		if !replace {
			plan.existing(e.ID, planRetain)
			next.Entries = append(next.Entries, e)
			continue
		}
		plan.existing(e.ID, planRemove)
		if upstreamEntryProtected(&e) {
			plan.CredentialClearRequired = append(plan.CredentialClearRequired, e.ID)
		}
	}
	sort.Strings(plan.CredentialClearRequired)
	if len(plan.CredentialClearRequired) > 0 {
		return nil, &upstreamClearRequiredError{Plan: plan}
	}
	if err := upstream.ValidateEffective(yaml, next.Entries); err != nil {
		return nil, err
	}
	return &upstreamImportPlanned{Plan: plan, Next: &next, Digest: upstreamImportDigest(plan, cur), Result: res}, nil
}

// planV2Ctx carries the identity-keyed plan under construction.
type planV2Ctx struct {
	plan     *upstreamImportPlan
	cur      upstream.Document
	byID     map[string]int
	yamlAuth map[string]struct{}
	named    map[string]struct{}
	next     *upstream.Document
	res      *upstreamImportResult
	now      string
}

// classify plans ONE incoming v2 entry (C9): preserve on same id + same
// authority; a changed authority on a credentialed entry is a refusal
// (requiresReplacement + remove + clear required); a changed authority on a
// credential-free entry is update (or requiresReplacement when a credential
// was declared); an unknown id is create with its STABLE id (or
// requiresReplacement when a credential was declared).
func (c *planV2Ctx) classify(id string, spec upstream.Spec, declared bool) {
	if declared {
		c.res.Omitted++ // the export omitted this entry's material by construction
	}
	h := spec.AuthorityHash()
	if _, owned := c.yamlAuth[h]; owned {
		c.plan.YAMLOwnedSkipped++
		return
	}
	idx, exists := c.byID[id]
	switch {
	case exists && c.cur.Entries[idx].AuthorityHash() == h:
		c.plan.incoming(id, planPreserve)
		c.named[id] = struct{}{}
		e := c.cur.Entries[idx]
		if e.Credential != nil {
			c.res.Preserved++
		}
		c.next.Entries = append(c.next.Entries, e)
	case exists:
		old := c.cur.Entries[idx]
		c.named[id] = struct{}{}
		if upstreamEntryProtected(&old) {
			c.plan.incoming(id, planRequiresReplacement)
			c.plan.existing(id, planRemove)
			c.plan.CredentialClearRequired = append(c.plan.CredentialClearRequired, id)
			return
		}
		e := old
		e.Scheme, e.Host, e.Port, e.Username = spec.Scheme, spec.Host, spec.Port, spec.Username
		e.RequiresReplacement = declared
		e.Revision++
		e.UpdatedAt = c.now
		c.plan.incoming(id, planUpdateOrReplacement(declared, c.res))
		c.next.Entries = append(c.next.Entries, e)
	default:
		e := upstream.ManagedEntry{
			ID: id, Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username,
			Revision: 1, Source: upstream.SourceManaged, CreatedAt: c.now, UpdatedAt: c.now, RequiresReplacement: declared,
		}
		if declared {
			c.plan.incoming(id, planRequiresReplacement)
			c.res.RequiresReplacement++
		} else {
			c.plan.incoming(id, planCreate)
		}
		c.next.Entries = append(c.next.Entries, e)
	}
}

func planUpdateOrReplacement(declared bool, res *upstreamImportResult) string {
	if declared {
		res.RequiresReplacement++
		return planRequiresReplacement
	}
	return planUpdate
}

// upstreamPlanLegacy is the authority-keyed compatibility plan for a pre-2F-D
// `upstreamProxies` list (versioned rule, C5): `xxxxx` preserves only an
// exact, unique canonical-authority match; a real password is refused; the
// list carries no identity, so omission never removes a credentialed entry.
func upstreamPlanLegacy(in []UpstreamEntry, replace bool, cur upstream.Document) (*upstreamImportPlanned, error) {
	plan := newUpstreamPlan(replace)
	plan.Legacy = true
	yaml := upstreamPool.YAMLEntries()
	yamlAuth := map[string]struct{}{}
	for i := range yaml {
		yamlAuth[yaml[i].AuthorityHash()] = struct{}{}
	}
	byAuth := map[string][]int{}
	for i := range cur.Entries {
		h := cur.Entries[i].AuthorityHash()
		byAuth[h] = append(byAuth[h], i)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	next := upstream.Document{Schema: upstream.DocumentSchema, Revision: cur.Revision + 1}
	named := map[string]struct{}{}
	seen := map[string]struct{}{}
	var res upstreamImportResult
	for i := range in {
		spec, err := upstreamImportSpec(i, in[i].URL)
		if err != nil {
			return nil, err
		}
		h := spec.AuthorityHash()
		if _, owned := yamlAuth[h]; owned {
			plan.YAMLOwnedSkipped++
			continue
		}
		if _, dup := seen[h]; dup {
			return nil, &upstreamImportError{Code: "duplicate_authority", Index: i, Msg: "the same authority appears twice in the import"}
		}
		seen[h] = struct{}{}
		if idxs := byAuth[h]; len(idxs) == 1 {
			e := cur.Entries[idxs[0]]
			plan.incoming(e.ID, planPreserve)
			named[e.ID] = struct{}{}
			if e.Credential != nil {
				res.Preserved++
			}
			next.Entries = append(next.Entries, e)
			continue
		}
		id := upstreamNewIDFor(cur, next)
		plan.incoming(id, planCreate)
		next.Entries = append(next.Entries, upstream.ManagedEntry{
			ID: id, Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username,
			Revision: 1, Source: upstream.SourceManaged, CreatedAt: now, UpdatedAt: now,
		})
	}
	for i := range cur.Entries {
		e := cur.Entries[i]
		if _, ok := named[e.ID]; ok {
			continue
		}
		if !replace || upstreamEntryHasMaterial(&e) || e.RequiresReplacement {
			// Merge keeps everything; replace keeps every entry that holds
			// (or is known to need) a credential — a legacy list cannot name
			// identities, so omission is never a removal (2F-C R16/R31).
			plan.existing(e.ID, planRetain)
			next.Entries = append(next.Entries, e)
			continue
		}
		plan.existing(e.ID, planRemove)
	}
	if err := upstream.ValidateEffective(yaml, next.Entries); err != nil {
		return nil, err
	}
	return &upstreamImportPlanned{Plan: plan, Next: &next, Digest: upstreamImportDigest(plan, cur), Result: res}, nil
}

// upstreamNewIDFor mints a ULID unused by the current document, the target
// under construction and the YAML seed.
func upstreamNewIDFor(cur, next upstream.Document) string {
	taken := map[string]struct{}{}
	for i := range cur.Entries {
		taken[cur.Entries[i].ID] = struct{}{}
	}
	for i := range next.Entries {
		taken[next.Entries[i].ID] = struct{}{}
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

// upstreamImportDigest is the deterministic identity of a plan against a
// document state: SHA-256 over the canonical plan (mode, incoming/existing
// id+action pairs, clear-required ids) and the current document's revision
// plus per-entry (id, authority hash, material presence). Same payload
// against the same document ⇒ the same digest; any mutation in between
// changes it. It carries no authority, username or credential.
func upstreamImportDigest(plan *upstreamImportPlan, cur upstream.Document) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	_ = enc.Encode(plan)
	type row struct {
		ID, Hash string
		Material bool
		Flag     bool
	}
	rows := make([]row, 0, len(cur.Entries))
	for i := range cur.Entries {
		e := &cur.Entries[i]
		rows = append(rows, row{ID: e.ID, Hash: e.AuthorityHash(), Material: e.Credential != nil, Flag: e.RequiresReplacement})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	_ = enc.Encode(struct {
		Revision int64
		Rows     []row
	}{cur.Revision, rows})
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// upstreamImportApply installs a planned import under the authoritative
// admin-settings lock: the plan is recomputed against the CURRENT document
// inside the lock and, when the caller supplied the dry-run digest, refused
// as stale if it differs. Returns the applied result (counts only).
func upstreamImportApply(b *configBackup, replace bool, expectDigest string) (*upstreamImportPlanned, error) {
	var planned *upstreamImportPlanned
	err := saveAdminSettingsWithOverrides(adminSaveOverrides{upstreamMutate: func(cur upstream.Document) (upstream.Document, error) {
		p, err := upstreamPlanImport(b, replace, cur)
		if err != nil {
			return cur, err
		}
		if expectDigest != "" && p.Digest != expectDigest {
			return cur, errUpstreamImportStale
		}
		planned = p
		if p.Next == nil {
			return cur, nil
		}
		return *p.Next, nil
	}})
	if err != nil {
		return nil, err
	}
	return planned, nil
}

// writeUpstreamPlanRefusal renders the C9 409 with the complete plan (or
// the stale-digest 409); any other error falls through to the bounded
// legacy refusal writer.
func writeUpstreamPlanRefusal(w http.ResponseWriter, err error) {
	var cr *upstreamClearRequiredError
	if errors.As(err, &cr) {
		jsonWriteStatus(w, http.StatusConflict, map[string]any{
			"error": err.Error(), "code": "credential_clear_required", "plan": cr.Plan,
		})
		return
	}
	if errors.Is(err, errUpstreamImportStale) {
		jsonWriteStatus(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "import_stale"})
		return
	}
	var env *upstreamEnvelopeError
	if errors.As(err, &env) {
		jsonWriteStatus(w, http.StatusBadRequest, map[string]any{"error": "invalid upstream proxies: " + env.Error(), "code": env.Code})
		return
	}
	writeUpstreamImportRefusal(w, err)
}

func jsonWriteStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck // response already committed; a write error cannot be reported
}

// importDryRunRequested accepts both the legacy `dryRun=true` and the 2F-D
// `dryRun=1` spellings.
func importDryRunRequested(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("dryRun"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}
