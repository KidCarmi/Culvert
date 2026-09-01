package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/sslbypass"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// PolicyAction defines what happens when a rule matches.
type PolicyAction string

const (
	ActionAllow     PolicyAction = "Allow"
	ActionDrop      PolicyAction = "Drop"
	ActionBlockPage PolicyAction = "Block_Page"
	ActionRedirect  PolicyAction = "Redirect"
)

// SSLAction defines SSL inspection behavior for CONNECT tunnels.
type SSLAction string

const (
	SSLInspect SSLAction = "Inspect"
	SSLBypass  SSLAction = "Bypass"
)

// URLCategory defines known content categories for destination matching.
// The URL-category engine (CategoryStore + host index + defaults embed)
// moved to internal/urlcat (ADR-0002, policy.go decomposition Phase A).
// main keeps the two-tier category resolution below (matchCategory /
// lookupHostCategory compose the admin store with the community BadgerDB
// feed), the API handlers, cluster sync, and rollback — via these aliases.

// URLCategory names a URL category referenced by policy rules.
type URLCategory = urlcat.Category

// Built-in category names, re-exposed under their original identifiers.
const (
	CategorySocial    = urlcat.Social
	CategoryMalicious = urlcat.Malicious
	CategoryNews      = urlcat.News
	CategoryStreaming = urlcat.Streaming
	CategoryGambling  = urlcat.Gambling
	CategoryAdult     = urlcat.Adult
	CategoryAny       = urlcat.Any
)

// CategoryEntry is one named URL category with its list of host patterns.
type CategoryEntry = urlcat.Entry

// CategoryStore manages URL categories (engine type is urlcat.Store).
type CategoryStore = urlcat.Store

var catStore = urlcat.New(urlcat.DefaultEntries())

// Engine constructor re-exposed under its original name (tests).
var newCategoryStore = urlcat.New

// FileProfileName identifies a named file-extension block profile.
type FileProfileName string

const (
	FileProfileNone        FileProfileName = ""
	FileProfileExecutables FileProfileName = "Executables" // .exe .dll .bat .cmd .ps1 .scr .msi .pif .com .vbs
	FileProfileArchives    FileProfileName = "Archives"    // .zip .rar .7z .tar .gz .bz2 .xz .cab
	FileProfileDocuments   FileProfileName = "Documents"   // .doc .docm .xls .xlsm .ppt .pptm (macro-enabled)
	FileProfileMedia       FileProfileName = "Media"       // .mp3 .mp4 .avi .mkv .mov .flv .wmv
	FileProfileStrict      FileProfileName = "Strict"      // all of the above combined
)

// fileProfileExts maps profile names to their blocked extensions.
var fileProfileExts = map[FileProfileName][]string{
	FileProfileExecutables: {".exe", ".dll", ".bat", ".cmd", ".ps1", ".scr", ".msi", ".pif", ".com", ".vbs"},
	FileProfileArchives:    {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso"},
	FileProfileDocuments:   {".docm", ".xlsm", ".pptm", ".xlam", ".dotm"},
	FileProfileMedia:       {".mp3", ".mp4", ".avi", ".mkv", ".mov", ".flv", ".wmv", ".webm"},
	FileProfileStrict:      {".exe", ".dll", ".bat", ".cmd", ".ps1", ".scr", ".msi", ".pif", ".com", ".vbs", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".docm", ".xlsm", ".pptm"},
}

// PolicyRule is a single PBAC rule evaluated in priority order.
type PolicyRule struct {
	Priority          int         `json:"priority"`
	Name              string      `json:"name"`
	SourceIP          string      `json:"sourceIP"`          // single IP or CIDR; empty = any
	SourceIdentity    string      `json:"sourceIdentity"`    // authenticated username; empty = any
	SourceGroup       string      `json:"sourceGroup"`       // IdP group/role membership; empty = any
	AuthSource        string      `json:"authSource"`        // IdP name ("okta","adfs","ldap","local") or "unauth"; empty = any
	DestFQDN          string      `json:"destFQDN"`          // exact or wildcard FQDN; empty = any
	DestCategory      URLCategory `json:"destCategory"`      // URL category; empty = any
	DestCategoryGroup string      `json:"destCategoryGroup"` // category group name; empty = any (denormalized display cache; DestCategoryGroupID is authoritative)
	// DestCategoryGroupID is the AUTHORITATIVE, rename-safe link to the category
	// group (references-by-id S2, OBJECT-REFERENCES-BY-ID.md). Resolution prefers
	// the ID and falls back to the name for un-migrated/dangling rules; the name
	// above is a denormalized display cache kept honest by the rename cascade.
	// Stamped name→id on write; omitempty so pre-migration rules are byte-unchanged.
	DestCategoryGroupID string          `json:"destCategoryGroupId,omitempty"`
	DestCountry         []string        `json:"destCountry"`                 // ISO 3166-1 alpha-2 country codes; empty = any
	Schedule            *PolicySchedule `json:"schedule,omitempty"`          // nil = always active
	SSLAction           SSLAction       `json:"sslAction"`                   // Inspect | Bypass
	FileFiltering       bool            `json:"fileFiltering"`               // enable file-type scanning
	FileProfile         FileProfileName `json:"fileProfile"`                 // named file-extension block profile
	LogFullURI          bool            `json:"logFullUri"`                  // log the full request URL (path, no query) for traffic matching this rule; HTTPS requires SSLAction=Inspect
	LogTraffic          *bool           `json:"logTraffic,omitempty"`        // log allowed traffic matching this rule (nil/true = log; false = count stats only, no feed entry). Blocks/threats are always logged.
	TLSSkipVerify       bool            `json:"tlsSkipVerify"`               // skip upstream cert verification (use with caution)
	StripALPN           *bool           `json:"stripAlpn,omitempty"`         // SSL-inspect only: nil (absent, pre-feature) or true => downgrade the inspected tunnel to HTTP/1.1 (today's behavior); false => native HTTP/2 inspection. Ignored when SSLAction==Bypass. Presence-aware so an upgrade never silently switches existing rules to H2 (resolveStripALPN). Superseded by DecryptionProfile.InspectHTTP2 when a profile is bound.
	DecryptionProfile   string          `json:"decryptionProfile,omitempty"` // SSL-inspect only: name of a DecryptionProfile that governs HOW this tunnel is decrypted (InspectHTTP2, cert-verification, TLS floor/cap, stall). Empty = none. A dangling ref falls back to the inline StripALPN/TLSSkipVerify (fail-safe at eval).
	// DecryptionProfileID is the AUTHORITATIVE, rename-safe link to the profile
	// (references-by-id, OBJECT-REFERENCES-BY-ID.md). Resolution prefers the ID
	// and falls back to the name for un-migrated/dangling rules; the name above is
	// a denormalized display cache kept honest by the rename cascade. Backfilled
	// name→id on load; omitempty so pre-migration rules are byte-unchanged.
	DecryptionProfileID string        `json:"decryptionProfileId,omitempty"`
	Action              PolicyAction  `json:"action"`
	RedirectURL         string        `json:"redirectURL"`            // used when Action == Redirect
	Enabled             *bool         `json:"enabled,omitempty"`      // nil or true = active; false = skipped during evaluation
	ID                  string        `json:"id,omitempty"`           // stable ULID; backfilled on load (Phase 0 seam)
	RuleType            string        `json:"ruleType,omitempty"`     // "" or "access" = Stage-2 access rule; "auth" = Stage-1 (reserved)
	SubjectMatch        *SubjectMatch `json:"subjectMatch,omitempty"` // typed subject selector (reserved; nil = unused)
	Auth                *AuthRuleSpec `json:"auth,omitempty"`         // Stage-1 auth-rule spec; non-nil only for ruleType="auth" (Phase 1 seam)
	HitCount            int64         `json:"hitCount"`               // match counter; persisted by rule NAME via ruleMet (metrics.go)
	lastHitUnix         int64         // unix-seconds of the last match (0 = never); persisted by name via ruleMet
	LastHit             string        `json:"lastHit,omitempty"` // computed in List() from the counters cell (RFC3339 UTC); never stored on the live rule
	// counters is the only mutable cell shared by immutable published revisions
	// of the same rule. Definition edits, reorders, and rename cascades preserve
	// this pointer, so an Evaluate on the prior revision cannot lose its hit when
	// a writer publishes the next revision.
	counters *policyRuleCounters

	// Tier-A rule metadata (policy-metadata P1; authority
	// docs/design/POLICY-ARCHITECTURE-FUTURE.md §2). CreatedAt/ModifiedAt/
	// ModifiedBy are stamped SERVER-SIDE ONLY in the write handlers
	// (stampRuleMetadataForWrite) — never trusted from the client, or they
	// become theater. ModifiedAt/By are a denormalized cache of audit truth
	// for list rendering; the audit log stays authoritative. Comment is the one
	// admin-authored field (free text, "why this rule exists"), included in the
	// audit diff. All omitempty so pre-feature rules and the many tests that
	// construct PolicyRule directly are byte-unchanged.
	CreatedAt  string `json:"createdAt,omitempty"`  // RFC3339 UTC; set once at create, preserved across edits
	ModifiedAt string `json:"modifiedAt,omitempty"` // RFC3339 UTC; restamped on every CONTENT edit (create/update)
	ModifiedBy string `json:"modifiedBy,omitempty"` // actor identity of the last content edit
	Comment    string `json:"comment,omitempty"`    // admin free-text note (client-authoritative, like Name/Action)

	// Metadata scope (policy-metadata P1): ModifiedAt/ModifiedBy track the last
	// edit to a rule's DEFINITION (its fields), stamped by
	// stampRuleMetadataForWrite in the create/update handlers. Position-only
	// changes — reorder (Reorder/PermutePriorities) and move (apiPolicyMove) —
	// are rulebase-level operations, NOT content edits: they deliberately do
	// NOT restamp, so a drag that repositions many rules never overwrites every
	// rule's "who last edited it" with the reorderer. Those operations are
	// tracked authoritatively by the config-version history and the
	// policy.reorder / policy.move audit events, which is where "who moved this"
	// belongs.

	// normFQDN is the IDNA-normalized form of DestFQDN, precomputed by
	// sortLocked() whenever rules are mutated. The proxy hot path (Evaluate)
	// reads it instead of re-normalizing DestFQDN on every request — normalizing
	// a host allocates (~1 alloc via idna.ToASCII), so doing it per-rule
	// per-request was the dominant policy-eval allocation. Unexported ⇒ never
	// serialized; a rule that reaches the store outside the mutators (empty
	// normFQDN) falls back to the allocating path, so correctness never depends
	// on it being populated.
	normFQDN string

	// srcIPNet is the parsed form of a CIDR SourceIP, precomputed by
	// sortLocked() under the same contract as normFQDN: the hot path uses it
	// (a single Contains on the once-parsed client IP) instead of re-running
	// net.ParseCIDR + net.ParseIP per rule per request (~4 allocs/rule). nil
	// for non-CIDR/empty/invalid SourceIP or for rules that bypassed the
	// mutators — those fall back to the allocating matchIPOrCIDR path.
	srcIPNet *net.IPNet

	// srcPrefix is srcIPNet expressed as a netip.Prefix, precomputed by
	// sortLocked() from the SAME *net.IPNet via prefixFromIPNet (security.go) —
	// the helper the IP filter already uses, so both matchers inherit one
	// pinned conversion (including the 4-in-6 subtlety its differential test
	// covers) instead of two hand-rolled ones.
	//
	// It exists purely to make the per-rule source check cheaper. net.IPNet
	// stores its address and mask as byte SLICES of unspecified length, so
	// Contains re-derives their shape on EVERY call: networkNumberAndMask runs
	// To4 on both, and To4 runs isZeros over the 16-byte form. That work is
	// identical for every request and every rule, yet it was paid per rule per
	// request — and it dominated. Profiling BenchmarkPolicyEvaluate_CIDRRules
	// (1000 source-scoped rules) attributed 34.4% of the ENTIRE evaluation to
	// net.(*IPNet).Contains: 13.8% Contains itself, 10.1% net.isZeros, 5.3%
	// net.IP.To4, 5.3% net.networkNumberAndMask.
	//
	// netip.Prefix is a fixed-size value with the family already decided, so
	// Contains is a masked comparison and nothing is re-derived. Both fields
	// are kept: an IPNet whose mask is non-contiguous has no Prefix form, and
	// prefixFromIPNet reports that rather than guessing, so srcIPNet remains
	// the authority whenever srcPrefix is invalid. Same fallback discipline as
	// normFQDN/srcIPNet — a rule that bypassed the mutators simply takes the
	// slower path, so correctness never depends on this being populated.
	srcPrefix netip.Prefix

	// matchedConds is the buildMatchedConditions summary, precomputed by
	// sortLocked(): it depends only on the rule's configured fields, never on
	// the request, so rebuilding it on every match was pure per-request
	// allocation. Never empty after precompute (empty ⇒ "any"), so "" doubles
	// as the fallback signal for rules that bypassed the mutators.
	matchedConds string
}

type policyRuleCounters struct {
	hitCount         int64
	restoredHitCount int64
	lastHitUnix      int64
}

// ruleIsEnabled returns whether a rule is active. A nil Enabled pointer
// (the zero value for existing rules loaded from JSON without the field)
// is treated as true so that all pre-existing rules remain active.
func ruleIsEnabled(r *PolicyRule) bool {
	return r.Enabled == nil || *r.Enabled
}

// ruleLogsTraffic reports whether allowed traffic matching this rule should
// produce a request-log entry. A nil LogTraffic pointer (the zero value for
// rules loaded from JSON without the field) means "log" so existing rules are
// unchanged. Only the allow path consults this — blocks and threats are always
// logged as security events.
func ruleLogsTraffic(r *PolicyRule) bool {
	return r.LogTraffic == nil || *r.LogTraffic
}

// PolicySchedule restricts a rule to specific days/times.
// Empty/nil fields mean "any" (match all).
type PolicySchedule struct {
	Days      []string `json:"days"`      // e.g. ["Mon","Tue","Wed","Thu","Fri"]; empty = any
	TimeStart string   `json:"timeStart"` // "09:00" 24-h; empty = any
	TimeEnd   string   `json:"timeEnd"`   // "17:00" 24-h; empty = any
	Timezone  string   `json:"timezone"`  // IANA tz name; empty = UTC
}

// PolicyStore holds an ordered list of policy rules with thread-safe access.
// Every successful mutation publishes a fresh slice containing fresh rule
// definitions. Published revisions are immutable except for each rule's shared
// atomic hit-accounting cell.
type PolicyStore struct {
	mu        sync.RWMutex
	saveMu    sync.Mutex // serializes snapshot-through-policy-and-meta publication
	rules     []*PolicyRule
	path      string
	version   int64  // incremented on every mutation
	updatedAt string // RFC3339 timestamp of last mutation
}

// policyVersion returns the current version number and last-updated time.
func (ps *PolicyStore) policyVersion() (int64, string) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.version, ps.updatedAt
}

// bumpVersion must be called under ps.mu.Lock().
func (ps *PolicyStore) bumpVersion() {
	ps.version++
	ps.updatedAt = time.Now().UTC().Format(time.RFC3339)
}

var policyStore = &PolicyStore{}

// Load reads rules from a JSON file. Missing file is treated as empty ruleset.
func (ps *PolicyStore) Load(path string) error {
	ps.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var rules []*PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	// Auth-aware fail-closed load gate (Phase 1 Slice 3, shared with ReplaceAll via
	// policyRulePersistable): VALID auth rules are kept (inert at runtime until the
	// matcher slice); invalid auth rules and access rules carrying a non-nil
	// SubjectMatch are dropped. Dropping the latter prevents a hand-edited or
	// newer-version policy.json from failing OPEN (a source-scoped access rule
	// matching every client, since Evaluate does not consult SubjectMatch). This
	// closes the startup load path in addition to the bulk-replace path. In-memory
	// only; the file is not rewritten here, so an offending line is inert and
	// re-warned each load until removed.
	kept := rules[:0]
	for _, r := range rules {
		if ok, reason := policyRulePersistable(r); !ok {
			name := ""
			if r != nil {
				name = r.Name
			}
			logWarnf("Policy: dropping rule %q on load — %s", sanitizeLog(name), sanitizeLog(reason))
			continue
		}
		kept = append(kept, r)
	}
	rules = kept
	ps.mu.Lock()
	previousCounters := make(map[string]*policyRuleCounters, len(ps.rules))
	for _, current := range ps.rules {
		if validRuleID(current.ID) && current.counters != nil {
			previousCounters[current.ID] = current.counters
		}
	}
	ps.rules = rules
	migrated := ps.backfillIDsLocked()
	for _, loaded := range ps.rules {
		if counters := previousCounters[loaded.ID]; counters != nil {
			loaded.counters = counters
		}
	}
	ps.sortLocked()
	ps.mu.Unlock()
	// Restore persisted version from sidecar .meta file.
	ps.loadMeta()
	// One-time idempotent ID migration: persist newly-assigned stable IDs so
	// they survive restarts. This is a data migration, NOT a semantic policy
	// change — it deliberately does not bump the policy version. A second load
	// finds all IDs present and writes nothing.
	if migrated > 0 {
		ps.Save()
		logger.Printf("Policy: assigned stable ULID IDs to %d rule(s) with missing, malformed, or duplicate identity", migrated)
	}
	return nil
}

// backfillIDsLocked replaces every missing, malformed, or duplicate ID with a
// fresh stable ULID and returns the number assigned. Must be called with ps.mu held.
func (ps *PolicyStore) backfillIDsLocked() int {
	next := append([]*PolicyRule(nil), ps.rules...)
	seen := make(map[string]struct{}, len(ps.rules))
	n := 0
	for i, r := range ps.rules {
		_, duplicate := seen[r.ID]
		if !validRuleID(r.ID) || duplicate {
			nr := clonePolicyRuleForPublication(r)
			nr.ID = freshRuleID(seen)
			next[i] = nr
			n++
		}
		seen[next[i].ID] = struct{}{}
	}
	if n > 0 {
		ps.rules = next
	}
	return n
}

func freshRuleID(seen map[string]struct{}) string {
	for {
		id := newRuleID()
		if _, exists := seen[id]; !exists {
			return id
		}
	}
}

// policyMeta is persisted alongside the policy file so version survives restart.
type policyMeta struct {
	Version   int64  `json:"version"`
	UpdatedAt string `json:"updated_at"`
}

func (ps *PolicyStore) loadMeta() {
	if ps.path == "" {
		return
	}
	metaPath := ps.path + ".meta"
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return
	}
	var m policyMeta
	if json.Unmarshal(data, &m) == nil {
		ps.mu.Lock()
		ps.version = m.Version
		if m.UpdatedAt != "" {
			ps.updatedAt = m.UpdatedAt
		}
		ps.mu.Unlock()
	}
}

func (ps *PolicyStore) saveMeta() {
	if ps.path == "" {
		return
	}
	ps.saveMu.Lock()
	defer ps.saveMu.Unlock()
	ps.mu.RLock()
	m := policyMeta{Version: ps.version, UpdatedAt: ps.updatedAt}
	ps.mu.RUnlock()
	ps.saveMetaSnapshot(m)
}

func (ps *PolicyStore) saveMetaSnapshot(m policyMeta) {
	data, _ := json.Marshal(m)
	_ = atomicWriteFile(ps.path+".meta", data, 0o600)
}

// Per-rule hit counters + lastHit are persisted by the metrics-layer system
// (metrics.go). policyRuleCounters holds the live atomic values shared across
// immutable revisions; saveHitCounters snapshots them under each current rule
// name, and RestoreHitCounts restores them at startup. The store deliberately
// does not carry a second persistence path.

// Save persists the current rules to disk (skips HitCount — runtime only).
// Best-effort legacy wrapper; callers that must know whether the durable
// write landed (the draft-commit path) use SaveErr.
func (ps *PolicyStore) Save() { _ = ps.SaveErr() }

// SaveErr is the error-returning persistence core (Codex fix: the commit path
// must not clear the draft when the running-policy write failed — a swallowed
// error left the NEW policy in memory, the OLD policy on disk, and no draft,
// so a restart silently reverted the commit and stranded a learning
// acceptance with no durable target).
func (ps *PolicyStore) SaveErr() error {
	if ps.path == "" {
		return nil
	}
	// Mutations may proceed while persistence runs, but saves themselves must be
	// ordered end-to-end. Otherwise an older snapshot can rename after a newer
	// save and regress durable policy state.
	ps.saveMu.Lock()
	defer ps.saveMu.Unlock()
	ps.mu.RLock()
	// Snapshot without hit counts for persistence.
	snapshot := make([]PolicyRule, len(ps.rules))
	for i, r := range ps.rules {
		snapshot[i] = *r
		snapshot[i].HitCount = 0
		snapshot[i].LastHit = "" // computed display field — never persist it into the rules file
	}
	meta := policyMeta{Version: ps.version, UpdatedAt: ps.updatedAt}
	ps.mu.RUnlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy rules: %w", err)
	}
	// Atomic + durable write — temp file, fsync, rename, parent-dir fsync.
	// Skip saveMeta on failure so the .meta sidecar can't record a newer
	// version/timestamp than the rules actually on disk.
	if err := atomicWriteFile(ps.path, data, 0o600); err != nil {
		return fmt.Errorf("write policy rules: %w", err)
	}
	ps.saveMetaSnapshot(meta)
	return nil
}

// List returns a copy of all rules (including live HitCount).
func (ps *PolicyStore) List() []PolicyRule {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]PolicyRule, len(ps.rules))
	for i, r := range ps.rules {
		out[i] = *clonePolicyRuleForPublication(r)
		if r.counters != nil {
			out[i].HitCount = atomic.LoadInt64(&r.counters.hitCount)
		} else {
			out[i].HitCount = atomic.LoadInt64(&r.HitCount)
		}
		// LastHit is a COMPUTED display field — always derive it from the atomic
		// timestamp, never from a copied string.
		u := atomic.LoadInt64(&r.lastHitUnix)
		if r.counters != nil {
			u = atomic.LoadInt64(&r.counters.lastHitUnix)
		}
		out[i].lastHitUnix = u
		if u > 0 {
			out[i].LastHit = time.Unix(u, 0).UTC().Format(time.RFC3339)
		} else {
			out[i].LastHit = ""
		}
		out[i].counters = nil
	}
	return out
}

// ReplaceAll atomically replaces all rules (used by cluster config sync,
// config import in replace mode, and config-version rollback).
//
// Auth-aware fail-closed gate (Phase 1 Slice 3, shared with Load via
// policyRulePersistable): VALID auth (Stage-1) rules are KEPT — they round-trip
// through cluster sync / import-replace / rollback but stay inert at runtime
// (Evaluate skips non-access rules; resolveAuthOutcome returns Default). Invalid
// auth rules are DROPPED fail-closed, as are access rules carrying a non-nil
// SubjectMatch (Evaluate does not consult it, so persisting one would let a
// scoped rule match every request — fail-open). validatePolicyRule guards the
// per-rule API/import-merge paths; this store-level gate closes the bulk paths
// that bypass that validator (cluster sync, import-replace, and any other direct
// ReplaceAll caller). The phase that wires the matcher activates these rules.
func (ps *PolicyStore) ReplaceAll(rules []PolicyRule) {
	ps.mu.Lock()
	out := make([]*PolicyRule, 0, len(rules))
	seenIDs := make(map[string]struct{}, len(rules))
	for i := range rules {
		r := rules[i]
		// Fail-closed: drop invalid auth rules and SubjectMatch-bearing access rules.
		if ok, reason := policyRulePersistable(&r); !ok {
			logWarnf("Policy: dropping rule %q on bulk replace — %s", sanitizeLog(r.Name), sanitizeLog(reason))
			continue
		}
		r.HitCount = 0
		r.lastHitUnix = 0
		r.counters = nil
		r.LastHit = "" // strip any computed display string that rode in via a List-derived snapshot
		// Auto-enable FileFiltering when a profile is selected.
		if r.FileProfile != "" && r.FileProfile != FileProfileNone {
			r.FileFiltering = true
		}
		// Preserve only canonical, unique imported IDs. Invalid or duplicate IDs
		// cannot safely address a rule or correlate its audit history.
		_, duplicate := seenIDs[r.ID]
		if !validRuleID(r.ID) || duplicate {
			r.ID = freshRuleID(seenIDs)
		}
		seenIDs[r.ID] = struct{}{}
		out = append(out, &r)
	}
	ps.rules = out
	ps.sortLocked()
	ps.bumpVersion()
	ps.mu.Unlock()
}

// Add inserts a new rule and re-sorts by priority.
func (ps *PolicyStore) Add(r PolicyRule) PolicyRule {
	ps.mu.Lock()
	nr := r
	nr.HitCount = 0
	nr.lastHitUnix = 0 // a new rule has never matched
	nr.counters = nil
	nr.LastHit = "" // computed display field is never stored on the live rule
	// Auto-enable FileFiltering when a profile is selected (defense-in-depth).
	if nr.FileProfile != "" && nr.FileProfile != FileProfileNone {
		nr.FileFiltering = true
	}
	if nr.Enabled == nil {
		t := true
		nr.Enabled = &t
	}
	seenIDs := make(map[string]struct{}, len(ps.rules))
	for _, existing := range ps.rules {
		seenIDs[existing.ID] = struct{}{}
	}
	if !validRuleID(nr.ID) {
		nr.ID = freshRuleID(seenIDs)
	} else if _, duplicate := seenIDs[nr.ID]; duplicate {
		nr.ID = freshRuleID(seenIDs)
	}
	nr.Priority = ps.availablePriorityLocked(nr.Priority)
	next := make([]*PolicyRule, len(ps.rules), len(ps.rules)+1)
	copy(next, ps.rules)
	next = append(next, &nr)
	ps.rules = next
	ps.sortLocked()
	ps.bumpVersion()
	ps.mu.Unlock()

	// Detect policy conflicts after adding the new rule.
	for _, w := range ps.DetectConflicts() {
		logWarnf("Policy: %s", sanitizeLog(w))
	}
	return nr
}

// availablePriorityLocked preserves a unique requested priority and otherwise
// selects one above the current maximum. The caller holds ps.mu.
func (ps *PolicyStore) availablePriorityLocked(requested int) int {
	maxPriority := 0
	collision := requested <= 0
	for _, existing := range ps.rules {
		if existing.Priority > maxPriority {
			maxPriority = existing.Priority
		}
		if existing.Priority == requested {
			collision = true
		}
	}
	if !collision {
		return requested
	}
	if requested > 0 {
		logWarnf("Policy: Add: priority %d collision (concurrent request?) — reassigning to %d",
			requested, maxPriority+1)
	}
	return maxPriority + 1
}

// Update replaces the rule with the given priority. Returns false if not found.
func (ps *PolicyStore) Update(priority int, r PolicyRule) bool {
	// Auto-enable FileFiltering when a profile is selected (defense-in-depth).
	if r.FileProfile != "" && r.FileProfile != FileProfileNone {
		r.FileFiltering = true
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, rule := range ps.rules {
		if rule.Priority != priority {
			continue
		}
		// Identity belongs to the stored rule, never to an update body. Older
		// clients omit it and newer/malicious callers must not rewrite it.
		r.ID = rule.ID
		r.counters = rule.counters
		next := append([]*PolicyRule(nil), ps.rules...)
		next[i] = &r
		ps.rules = next
		ps.sortLocked()
		ps.bumpVersion()
		return true
	}
	return false
}

// Delete removes the rule with the given priority. Returns false if not found.
func (ps *PolicyStore) Delete(priority int) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, rule := range ps.rules {
		if rule.Priority == priority {
			ps.rules = append(append(make([]*PolicyRule, 0, len(ps.rules)-1), ps.rules[:i]...), ps.rules[i+1:]...)
			ps.bumpVersion()
			return true
		}
	}
	return false
}

// UpdateByID replaces the rule with the given stable ULID. Unlike Update
// (which keys on mutable priority), addressing by ID is safe against a
// concurrent reorder shifting priorities between a client's load and save —
// the edit always lands on the rule the client loaded (§1 identity seam).
// Returns false if no rule carries the id.
func (ps *PolicyStore) UpdateByID(id string, r PolicyRule) bool {
	if !validRuleID(id) {
		return false
	}
	// Auto-enable FileFiltering when a profile is selected (parity with Update).
	if r.FileProfile != "" && r.FileProfile != FileProfileNone {
		r.FileFiltering = true
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, rule := range ps.rules {
		if rule.ID != id {
			continue
		}
		r.ID = id // identity is immutable across an edit
		// Position is managed by reorder/move, NOT by content edits. Preserve
		// the matched rule's CURRENT priority so an id-addressed edit made against
		// a stale-priority body (a concurrent reorder moved the rule after the
		// client loaded it) can never write a duplicate priority slot.
		r.Priority = rule.Priority
		r.counters = rule.counters
		next := append([]*PolicyRule(nil), ps.rules...)
		next[i] = &r
		ps.rules = next
		ps.sortLocked()
		ps.bumpVersion()
		return true
	}
	return false
}

// CascadeDecryptionProfileRename refreshes the denormalized DecryptionProfile
// name on every rule that references the renamed profile — by its stable ID
// (migrated rules) or, for un-migrated name-only rules, by its OLD name (which
// also stamps the ID, migrating them so the reference is ID-stable henceforth).
// References-by-id: the match path already resolves by ID, so matching survives
// the rename regardless; this keeps the human-readable denormalized copy honest
// for display/export/DP-sync. Returns the number of rules touched; the caller
// persists via Save(). Race-safe by pointer swap (like UpdateByID) — never
// in-place field mutation, which would race Evaluate's lock-free field reads.
func (ps *PolicyStore) CascadeDecryptionProfileRename(id, oldName, newName string) int {
	if id == "" {
		return 0
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	next := append([]*PolicyRule(nil), ps.rules...)
	n := 0
	for i, rule := range next {
		byID := rule.DecryptionProfileID == id && rule.DecryptionProfile != newName
		byName := rule.DecryptionProfileID == "" && strings.EqualFold(rule.DecryptionProfile, oldName)
		if !byID && !byName {
			continue
		}
		nr := *rule
		nr.DecryptionProfile = newName
		nr.DecryptionProfileID = id // stamp/keep the authoritative link
		next[i] = &nr
		n++
	}
	if n > 0 {
		ps.rules = next
		ps.sortLocked()
		ps.bumpVersion()
	}
	return n
}

// CascadeDestCategoryGroupRename refreshes the denormalized DestCategoryGroup
// name on every rule that references the renamed group — by its stable ID
// (migrated rules) or, for un-migrated name-only rules, by its OLD name (which
// also stamps the ID, migrating them). References-by-id S2: the match path
// resolves by ID, so matching survives the rename regardless; this keeps the
// human-readable denormalized copy honest for display/export/DP-sync. Returns
// the number of rules touched; the caller persists via Save(). Race-safe by
// pointer swap (like CascadeDecryptionProfileRename) — never in-place field
// mutation, which would race Evaluate's lock-free field reads.
func (ps *PolicyStore) CascadeDestCategoryGroupRename(id, oldName, newName string) int {
	if id == "" {
		return 0
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	next := append([]*PolicyRule(nil), ps.rules...)
	n := 0
	for i, rule := range next {
		byID := rule.DestCategoryGroupID == id && rule.DestCategoryGroup != newName
		byName := rule.DestCategoryGroupID == "" && strings.EqualFold(rule.DestCategoryGroup, oldName)
		if !byID && !byName {
			continue
		}
		nr := *rule
		nr.DestCategoryGroup = newName
		nr.DestCategoryGroupID = id // stamp/keep the authoritative link
		next[i] = &nr
		n++
	}
	if n > 0 {
		ps.rules = next
		ps.sortLocked()
		ps.bumpVersion()
	}
	return n
}

// DeleteByID removes the rule with the given stable ULID. Rename/reorder-safe
// counterpart to Delete. Returns false if not found.
func (ps *PolicyStore) DeleteByID(id string) bool {
	if !validRuleID(id) {
		return false
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, rule := range ps.rules {
		if rule.ID == id {
			ps.rules = append(append(make([]*PolicyRule, 0, len(ps.rules)-1), ps.rules[:i]...), ps.rules[i+1:]...)
			ps.bumpVersion()
			return true
		}
	}
	return false
}

// findByIDCopy returns a copy of the rule with the given ULID, or nil. Used by
// the ID-addressed API handlers to resolve the before-state for audit/validation
// without holding the store lock across the handler. Goes through List() for a
// detached definition and an atomic snapshot of the shared accounting cell.
func (ps *PolicyStore) findByIDCopy(id string) *PolicyRule {
	if id == "" {
		return nil
	}
	rules := ps.List()
	for i := range rules {
		if rules[i].ID == id {
			r2 := rules[i]
			return &r2
		}
	}
	return nil
}

// matchForImport resolves an incoming (imported) rule to an existing rule for
// upsert-on-import (POLICY-ARCHITECTURE-FUTURE §1). Match order: (1) stable
// ULID when the incoming rule carries one — idempotent re-import, the true
// migration case; (2) a one-time name-match fallback for pre-ID or
// hand-authored backups that never carried an id. Returns nil when the rule is
// new (the caller Adds it, preserving its carried id or minting a fresh one).
// Returns a COPY; callers address the live rule via UpdateByID(match.ID, …).
// Names are unique across the whole store (validatePolicyRule enforces it over
// both rule types), so the name fallback can never be ambiguous.
func (ps *PolicyStore) matchForImport(r PolicyRule) *PolicyRule {
	if m := ps.findByIDCopy(r.ID); m != nil {
		return m
	}
	if r.Name == "" {
		return nil
	}
	rules := ps.List()
	for i := range rules {
		if strings.EqualFold(rules[i].Name, r.Name) {
			r2 := rules[i]
			return &r2
		}
	}
	return nil
}

// countImportUpserts reports how many of the incoming rules would UPDATE an
// existing rule (matched by matchForImport) versus be ADDED fresh, under
// merge-import upsert semantics. Read-only — used by the import preview to
// report the real split instead of a misleading "add N" when some incoming
// rules are re-imports. Computed against current store state: for a well-formed
// export (unique ids and names — a store invariant at export time) this equals
// the progressive apply exactly; only a hand-crafted backup with intra-file
// duplicates could diverge, and then only in the displayed split.
func (ps *PolicyStore) countImportUpserts(incoming []PolicyRule) (updates, adds int) {
	for i := range incoming {
		if ps.matchForImport(incoming[i]) != nil {
			updates++
		} else {
			adds++
		}
	}
	return updates, adds
}

// Reorder reassigns priorities according to the provided ordered list of old
// priorities. The caller provides priorities in the desired new order (index 0
// becomes priority 1, etc.). Returns false if lengths mismatch.
func (ps *PolicyStore) Reorder(orderedPriorities []int) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if len(orderedPriorities) != len(ps.rules) {
		return false
	}
	next := make([]*PolicyRule, len(ps.rules))
	byOldPri := make(map[int]*PolicyRule, len(ps.rules))
	for i, rule := range ps.rules {
		nr := *rule
		next[i] = &nr
		byOldPri[nr.Priority] = &nr
	}
	for newIdx, oldPri := range orderedPriorities {
		r, ok := byOldPri[oldPri]
		if !ok {
			return false
		}
		r.Priority = newIdx + 1
	}
	ps.rules = next
	ps.sortLocked()
	ps.bumpVersion()
	return true
}

// PermutePriorities reassigns the priorities of a SUBSET of rules among
// themselves. orderedPriorities lists existing priorities in the desired new
// order; the same priority VALUES are redistributed across those rules (the
// sorted slot values are assigned in the requested order), so the priority
// multiset — and therefore the ordering of every rule OUTSIDE the subset — is
// unchanged. Used by the auth-policy reorder endpoint (Slice 8), which must
// never disturb access-rule ordering. Returns false on an empty list, a
// duplicate, or a priority that matches no rule.
func (ps *PolicyStore) PermutePriorities(orderedPriorities []int) bool {
	if len(orderedPriorities) == 0 {
		return false
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	seen := make(map[int]bool, len(orderedPriorities))
	for _, p := range orderedPriorities {
		if seen[p] {
			return false
		}
		seen[p] = true
	}
	next := make([]*PolicyRule, len(ps.rules))
	byOldPri := make(map[int]*PolicyRule, len(orderedPriorities))
	for i, rule := range ps.rules {
		nr := *rule
		next[i] = &nr
		r := &nr
		if seen[r.Priority] {
			if _, already := byOldPri[r.Priority]; already {
				return false // ambiguous: two store rules share a listed priority
			}
			byOldPri[r.Priority] = r
		}
	}
	if len(byOldPri) != len(orderedPriorities) {
		return false // a listed priority matches no rule
	}
	slots := make([]int, len(orderedPriorities))
	copy(slots, orderedPriorities)
	sort.Ints(slots)
	for i, oldPri := range orderedPriorities {
		byOldPri[oldPri].Priority = slots[i]
	}
	ps.rules = next
	ps.sortLocked()
	ps.bumpVersion()
	return true
}

// DetectConflicts checks for rules at the same priority with overlapping
// conditions but different actions. Returns human-readable warnings.
func (ps *PolicyStore) DetectConflicts() []string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var warnings []string
	for i := 0; i < len(ps.rules); i++ {
		for j := i + 1; j < len(ps.rules); j++ {
			a, b := ps.rules[i], ps.rules[j]
			if a.Priority != b.Priority {
				continue
			}
			if a.Action == b.Action {
				continue // same action = not a conflict
			}
			// Same priority, different actions — check for overlap.
			if rulesOverlap(a, b) {
				warnings = append(warnings, fmt.Sprintf(
					"conflict: rules %q (pri %d, action %s) and %q (pri %d, action %s) overlap",
					a.Name, a.Priority, a.Action, b.Name, b.Priority, b.Action,
				))
			}
		}
	}
	return warnings
}

// rulesOverlap returns true if two rules could match the same request.
func rulesOverlap(a, b *PolicyRule) bool {
	// If either field is empty (wildcard), it overlaps with anything.
	// If both are set, they must match for overlap.
	if a.SourceIP != "" && b.SourceIP != "" && a.SourceIP != b.SourceIP {
		return false
	}
	if a.SourceIdentity != "" && b.SourceIdentity != "" && !strings.EqualFold(a.SourceIdentity, b.SourceIdentity) {
		return false
	}
	if a.DestFQDN != "" && b.DestFQDN != "" && a.DestFQDN != b.DestFQDN {
		return false
	}
	if a.DestCategory != "" && b.DestCategory != "" && a.DestCategory != b.DestCategory {
		return false
	}
	return true
}

func (ps *PolicyStore) sortLocked() {
	// Clone the slice and every definition before sorting/precomputing. A reader
	// that captured the prior slice can finish against exactly that revision while
	// this writer prepares and publishes the next one.
	next := make([]*PolicyRule, len(ps.rules))
	for i, rule := range ps.rules {
		next[i] = clonePolicyRuleForPublication(rule)
	}
	sort.Slice(next, func(i, j int) bool {
		return next[i].Priority < next[j].Priority
	})
	// Precompute the request-independent per-rule state once per mutation so
	// Evaluate never re-derives it on the per-request hot path.
	for i := range next {
		r := next[i]
		if r.DestFQDN != "" {
			r.normFQDN = normalizeHost(r.DestFQDN)
		} else {
			r.normFQDN = ""
		}
		r.srcIPNet, r.srcPrefix = nil, netip.Prefix{}
		if strings.Contains(r.SourceIP, "/") {
			if _, ipNet, err := net.ParseCIDR(r.SourceIP); err == nil {
				r.srcIPNet = ipNet
				// Derived from the SAME IPNet, so the two forms can never
				// describe different networks. An unconvertible mask leaves
				// srcPrefix invalid and the hot path falls back to srcIPNet.
				if p, ok := prefixFromIPNet(ipNet); ok {
					r.srcPrefix = p
				}
			}
		}
		r.matchedConds = buildMatchedConditions(r)
		// Stage-1 (auth-rule) subject CIDRs, same contract: parse once here so
		// the per-request resolver never runs net.ParseCIDR.
		precomputeSubjectNets(r.SubjectMatch)
	}
	ps.rules = next
}

// copyPolicyRuleForPublication detaches every mutable nested value that the
// evaluator can read. The counters cell is deliberately shared so accounting
// follows the stable rule across immutable definition revisions.
func copyPolicyRuleForPublication(nr, rule *PolicyRule) {
	*nr = *rule
	if rule.counters == nil {
		hits := atomic.LoadInt64(&rule.HitCount)
		nr.counters = &policyRuleCounters{
			hitCount:         hits,
			restoredHitCount: hits,
			lastHitUnix:      atomic.LoadInt64(&rule.lastHitUnix),
		}
	}
	nr.DestCountry = append([]string(nil), rule.DestCountry...)
	if rule.Schedule != nil {
		schedule := *rule.Schedule
		schedule.Days = append([]string(nil), rule.Schedule.Days...)
		nr.Schedule = &schedule
	}
	if rule.LogTraffic != nil {
		v := *rule.LogTraffic
		nr.LogTraffic = &v
	}
	if rule.StripALPN != nil {
		v := *rule.StripALPN
		nr.StripALPN = &v
	}
	if rule.Enabled != nil {
		v := *rule.Enabled
		nr.Enabled = &v
	}
	if rule.SubjectMatch != nil {
		sm := *rule.SubjectMatch
		sm.All = append([]SubjectPredicate(nil), rule.SubjectMatch.All...)
		for i := range sm.All {
			sm.All[i].Values = append([]string(nil), sm.All[i].Values...)
			// Drop the precompute with the same discipline as srcIPNet below: a
			// copy must never carry a net parsed from a since-edited Values.
			// sortLocked repopulates it on the published definition.
			sm.All[i].nets = nil
		}
		nr.SubjectMatch = &sm
	}
	if rule.Auth != nil {
		auth := *rule.Auth
		auth.ProviderRefs = append([]string(nil), rule.Auth.ProviderRefs...)
		nr.Auth = &auth
	}
	nr.srcIPNet = nil
	nr.srcPrefix = netip.Prefix{}
	nr.normFQDN = ""
	nr.matchedConds = ""
}

func clonePolicyRuleForPublication(rule *PolicyRule) *PolicyRule {
	if rule == nil {
		return nil
	}
	nr := new(PolicyRule)
	copyPolicyRuleForPublication(nr, rule)
	return nr
}

// copyPolicyRuleForMatch writes a detached decision snapshot. PolicyMatch is
// consumed outside the store lock, so it must not expose a published definition
// that a caller could mutate. Accounting is materialized after the current hit
// and the private shared cell is not exposed through the result.
func copyPolicyRuleForMatch(nr, rule *PolicyRule) {
	copyPolicyRuleForPublication(nr, rule)
	hits := atomic.LoadInt64(&rule.HitCount)
	lastHit := atomic.LoadInt64(&rule.lastHitUnix)
	if rule.counters != nil {
		hits = atomic.LoadInt64(&rule.counters.hitCount)
		lastHit = atomic.LoadInt64(&rule.counters.lastHitUnix)
	}
	nr.HitCount = hits
	nr.lastHitUnix = lastHit
	nr.counters = nil
	// LastHit remains the computed List-only display field. The private atomic
	// timestamp is materialized for compatibility without formatting on the hot
	// path.
	nr.LastHit = ""
}

// PolicyMatch is returned when a rule is matched against a request.
type PolicyMatch struct {
	Rule          *PolicyRule
	Action        PolicyAction
	SSLAction     SSLAction
	TLSSkipVerify bool
	// MatchedConditions is a human-readable summary of which rule conditions
	// were satisfied (e.g. "srcIP=10.0.0.0/8 destFQDN=*.example.com").
	// Populated by Evaluate for policy audit trail logging.
	MatchedConditions string
	ruleSnapshot      PolicyRule
}

func (ps *PolicyStore) evaluationSnapshot() []*PolicyRule {
	ps.mu.RLock()
	rules := ps.rules
	needsPublication := false
	for _, rule := range rules {
		if rule.counters == nil {
			needsPublication = true
			break
		}
	}
	ps.mu.RUnlock()
	if !needsPublication {
		return rules
	}

	// Production mutators publish initialized cells. This compatibility path is
	// for internal callers/tests that install ps.rules directly: normalize them
	// under the writer lock before any evaluator can mutate accounting fields on
	// a published definition.
	ps.mu.Lock()
	for _, rule := range ps.rules {
		if rule.counters == nil {
			ps.sortLocked()
			break
		}
	}
	rules = ps.rules
	ps.mu.Unlock()
	return rules
}

// accessEvalInput carries the per-request Stage-2 evaluation inputs. It is
// passed to evalAccessRules by POINTER so the non-inlinable core takes a narrow
// register-friendly argument list (the F4 Policy Tester and future replay/shadow
// callers pass the same struct). The client IP is carried as a STRING, not a
// pre-parsed net.IP: the core parses it once into a local, so the net.ParseIP
// result never escapes through the struct to the heap. Measured note: extracting
// the hot loop into this shared non-inlinable core costs ~10% on the policy
// evaluation micro-benchmark versus the pre-extraction inlined scan, independent
// of the argument-passing form (explicit params / this struct / forwarded
// params all measured a comparable regression); allocations are unchanged. This
// is the accepted cost of the single-evaluator mandate (ADR-0026) — see the F3
// evidence package.
type accessEvalInput struct {
	clientIP   string
	identity   string
	authSource string
	host       string // raw destination host
	normHost   string // normalizeHost(host)
	groups     []string
}

// Stage-2 per-rule skip reasons. Shared by the evaluator core's trace callback
// and the Policy Tester so both speak one vocabulary (ADR-0026).
const (
	accessSkipDisabled  = "disabled"
	accessSkipNonAccess = "non-access rule (auth)"
	accessSkipSource    = "source mismatch"
	accessSkipSchedule  = "schedule inactive"
	accessSkipDest      = "destination mismatch"
)

// evalAccessRules is the single canonical Stage-2 access-rule scan: priority
// order, first match wins, empty rule field = "any". It is the one definition
// of access-decision semantics (ADR-0026), shared by the enforcement path
// (PolicyStore.Evaluate, which wraps it with hit accounting + PolicyMatch
// construction), the Policy Tester, and future replay/shadow.
//
// It is PURE: no counter mutation, no logging, no store locks. Callers needing a
// pinned category/geo environment pin generations around it rather than forking
// the evaluator — the live singletons the destination matchers consult ARE the
// evaluation semantics.
//
// The inputs arrive via a pointer to accessEvalInput (see that type's doc).
// in.normHost MUST be normalizeHost(in.host); each rule reuses its precomputed
// srcIPNet / normFQDN.
//
// now is read at most once, lazily, on the first scheduled rule reached (a scan
// with no scheduled rules never calls it) — the one-instant-per-evaluation
// decision point. trace, when non-nil, is called once per rule with the skip
// reason ("" = this rule matched, scan stops). trace MUST be nil on the
// enforcement hot path: the nil branch allocates nothing (the skip strings are
// static literals), preserving the zero-per-rule-allocation contract.
func evalAccessRules(rules []*PolicyRule, in *accessEvalInput, now func() time.Time, trace func(rule *PolicyRule, skip string)) *PolicyRule { //nolint:gocognit // one explicit skip-reason branch per rule condition; the zero-alloc contract forbids extraction on this hot path
	// The client address is parsed at most ONCE for the whole scan, lazily on
	// the first rule that actually carries a SourceIP, and reused across every
	// rule's precomputed srcPrefix/srcIPNet. A scan with no source-scoped rule
	// never parses at all. The local stays on the stack — matchSourceAddr reads
	// and memoises through the pointer but never retains it.
	clientSrc := newClientSource(in.clientIP)
	// Resolve the destination's CATEGORY at most ONCE for the whole scan, lazily
	// on the first category-scoped rule reached (see policy_hostcat.go): the
	// host→category fusion depends only on the host, so running it per rule
	// multiplied an O(all host patterns) taxonomy scan — plus a BadgerDB read
	// per domain label on a feed-backed deployment — by the rule count.
	catScratch := newHostCatScratch(in.host)
	// The control flow is deliberately the parent enforcement loop's exact
	// continue-based structure: on the nil-trace path (enforcement) it is
	// branch-for-branch identical to the pre-extraction scan, and the skip-reason
	// string literals are referenced only inside the `if trace != nil` guards, so
	// they are never materialized on the hot path (no per-rule string work). The
	// guards themselves are predicted-not-taken when trace is nil.
	var scanNow time.Time
	var scanNowSet bool
	for i := range rules {
		rule := rules[i]
		if !ruleIsEnabled(rule) {
			if trace != nil {
				trace(rule, accessSkipDisabled)
			}
			continue
		}
		// Stage-2 evaluates access rules only. Authentication rules (Stage-1)
		// are inert here; an empty RuleType defaults to access for backward
		// compatibility, so pre-existing rules match exactly as before.
		if ruleTypeOf(rule) != ruleTypeAccess {
			if trace != nil {
				trace(rule, accessSkipNonAccess)
			}
			continue
		}
		if !matchSourceAddr(rule, &clientSrc, in.identity, in.authSource, in.groups) {
			if trace != nil {
				trace(rule, accessSkipSource)
			}
			continue
		}
		if rule.Schedule != nil {
			if !scanNowSet {
				scanNow = now()
				scanNowSet = true
			}
			if !matchScheduleAt(rule.Schedule, scanNow) {
				if trace != nil {
					trace(rule, accessSkipSchedule)
				}
				continue
			}
		}
		if !matchDestNorm(rule, in.host, in.normHost, &catScratch) {
			if trace != nil {
				trace(rule, accessSkipDest)
			}
			continue
		}
		if trace != nil {
			trace(rule, "")
		}
		return rule
	}
	return nil
}

// Evaluate iterates rules in priority order and returns the first match.
// authSource is the IdP name that authenticated the user (e.g. "okta", "ldap",
// "local") or "unauth" when no credentials were presented.
// groups is the list of IdP group/role memberships for the authenticated user.
// Returns nil when no rule matches (caller should default to Deny — Zero Trust).
func (ps *PolicyStore) Evaluate(clientIP, identity, authSource, host string, groups []string) *PolicyMatch {
	// Snapshot the slice header under RLock, then release BEFORE the scan: the
	// scan can block (matchDestNorm → geo.LookupCached → DNS on an uncached
	// DestCountry host; category lookups hit the community DB), so the lock must
	// NOT be held across it — otherwise a config-plane List()/Save() (exclusive
	// Lock) waiting on a DNS-blocked scan would stall all policy evaluation.
	rules := ps.evaluationSnapshot()

	// Enforcement path: the canonical core with the wall clock and no trace (the
	// nil-trace branch is allocation-free). Normalize the destination host ONCE
	// for the whole scan (each rule reuses its precomputed normFQDN; the core
	// parses the client IP once for the precomputed srcIPNet), keeping the ~2
	// host + ~4 CIDR per-rule allocations the hot path previously incurred
	// eliminated. in stays on this frame — evalAccessRules never retains it.
	in := accessEvalInput{
		clientIP:   clientIP,
		identity:   identity,
		authSource: authSource,
		host:       host,
		normHost:   normalizeHost(host),
		groups:     groups,
	}
	rule := evalAccessRules(rules, &in, time.Now, nil)
	if rule == nil {
		return nil
	}

	// Every published definition has a stable accounting cell. Revisions of the
	// same rule share it, so a reader finishing on an older definition cannot
	// lose its hit when a writer publishes the next revision.
	atomic.AddInt64(&rule.counters.hitCount, 1)
	atomicStoreMax(&rule.counters.lastHitUnix, time.Now().Unix())
	// Precomputed by sortLocked (never "" there — empty conditions render as
	// "any"); fall back for rules that bypassed the mutators.
	conds := rule.matchedConds
	if conds == "" {
		conds = buildMatchedConditions(rule)
	}
	match := &PolicyMatch{
		Action:            rule.Action,
		SSLAction:         rule.SSLAction,
		TLSSkipVerify:     rule.TLSSkipVerify,
		MatchedConditions: conds,
	}
	copyPolicyRuleForMatch(&match.ruleSnapshot, rule)
	match.Rule = &match.ruleSnapshot
	return match
}

// buildMatchedConditions produces a compact summary of which rule conditions
// contributed to the match. Only non-wildcard (configured) fields are listed.
func buildMatchedConditions(rule *PolicyRule) string {
	var parts []string
	if rule.SourceIP != "" {
		parts = append(parts, "srcIP="+rule.SourceIP)
	}
	if rule.SourceIdentity != "" {
		parts = append(parts, "identity="+rule.SourceIdentity)
	}
	if rule.SourceGroup != "" {
		parts = append(parts, "group="+rule.SourceGroup)
	}
	if rule.AuthSource != "" {
		parts = append(parts, "authSrc="+rule.AuthSource)
	}
	if rule.DestFQDN != "" {
		parts = append(parts, "destFQDN="+rule.DestFQDN)
	}
	if rule.DestCategory != "" && rule.DestCategory != CategoryAny {
		parts = append(parts, "destCat="+string(rule.DestCategory))
	}
	if rule.DestCategoryGroup != "" {
		parts = append(parts, "destCatGroup="+rule.DestCategoryGroup)
	}
	if len(rule.DestCountry) > 0 {
		parts = append(parts, "destCountry="+strings.Join(rule.DestCountry, ","))
	}
	if rule.Schedule != nil {
		parts = append(parts, "schedule=active")
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, " ")
}

// ─── Schedule matching ────────────────────────────────────────────────────────

// scheduleLocCache memoises time.LoadLocation results for schedule timezones.
// LoadLocation reads and parses the tzdata file from disk on EVERY call (the
// stdlib does not cache it), so calling it per scheduled rule per request put
// a disk read on the proxy hot path (~12 µs and ~8.6 KB per rule per request
// measured). Keyed by the admin-configured timezone string — bounded, low
// cardinality (never client-controlled). An invalid timezone caches time.UTC
// (and warns once instead of once per request); a tzdata fix therefore needs a
// restart to be picked up, matching the read-once posture of other config.
// time.Location values are immutable and safe for concurrent use.
var scheduleLocCache sync.Map // timezone string → scheduleLoc

// scheduleLoc is one memoised timezone resolution. It carries the parse OUTCOME
// alongside the location so callers that need to distinguish "resolved to UTC"
// from "failed, fell back to UTC" — the Stage-1 auth gate, which must fail
// closed on a timezone it cannot evaluate — can share this cache instead of
// calling time.LoadLocation themselves.
type scheduleLoc struct {
	loc *time.Location
	ok  bool
}

// scheduleLocationResolved resolves an IANA timezone name through the
// process-wide cache, returning the location and whether the name actually
// parsed. On failure it returns (time.UTC, false).
func scheduleLocationResolved(name string) (*time.Location, bool) {
	if cached, ok := scheduleLocCache.Load(name); ok {
		e := cached.(scheduleLoc)
		return e.loc, e.ok
	}
	e := scheduleLoc{ok: true}
	loc, err := time.LoadLocation(name)
	if err != nil {
		logWarnf("Policy: invalid schedule timezone %q, falling back to UTC", sanitizeLog(name))
		e.loc, e.ok = time.UTC, false
	} else {
		e.loc = loc
	}
	scheduleLocCache.Store(name, e)
	return e.loc, e.ok
}

// scheduleLocation resolves an IANA timezone name to a *time.Location through
// the process-wide cache, falling back to UTC on failure. Shared by every
// matchSchedule caller (Stage-2 access rules, Stage-1 auth rules, CDR policy,
// and the policy simulator).
func scheduleLocation(name string) *time.Location {
	loc, _ := scheduleLocationResolved(name)
	return loc
}

func matchSchedule(s *PolicySchedule) bool {
	if s == nil {
		return true
	}
	return matchScheduleAt(s, time.Now())
}

// matchScheduleAt is matchSchedule against a caller-supplied instant. The
// Stage-2 Evaluate scan reads the clock once per request and passes the same
// instant to every scheduled rule — previously each rule paid its own
// time.Now() inside the scan (and one decision could straddle a minute
// boundary mid-scan).
func matchScheduleAt(s *PolicySchedule, now time.Time) bool {
	loc := time.UTC
	if s.Timezone != "" {
		loc = scheduleLocation(s.Timezone)
	}
	now = now.In(loc)
	if !scheduleDayMatch(s.Days, now) {
		return false
	}
	if s.TimeStart == "" || s.TimeEnd == "" {
		return true
	}
	return scheduleTimeMatch(s.TimeStart, s.TimeEnd, now)
}

// scheduleDayMatch is the day-of-week check ("Mon", "Tue" …, case-insensitive).
// An empty Days list means every day.
func scheduleDayMatch(days []string, now time.Time) bool {
	if len(days) == 0 {
		return true
	}
	day := now.Weekday().String()[:3] // "Mon", "Tue" …
	for _, d := range days {
		if strings.EqualFold(d, day) {
			return true
		}
	}
	return false
}

// scheduleTimeMatch is the time-of-day window check (start inclusive, end
// exclusive; start > end is an overnight range). Well-formed zero-padded
// "HH:MM" bounds compare on a minutes-of-day scale — the same total order as
// the previous lexicographic string comparison, minus the per-rule fmt.Sprintf
// allocation that put O(rules) heap garbage on the policy hot path. Malformed
// bounds fall back to the legacy string comparison unchanged.
func scheduleTimeMatch(startStr, endStr string, now time.Time) bool {
	start, okStart := parseClockMinutes(startStr)
	end, okEnd := parseClockMinutes(endStr)
	if !okStart || !okEnd {
		return scheduleTimeMatchLegacy(startStr, endStr, now)
	}
	cur := now.Hour()*60 + now.Minute()
	if start <= end {
		// Normal range e.g. 09:00–17:00.
		return cur >= start && cur < end
	}
	// Overnight range e.g. 22:00–06:00.
	return cur >= start || cur < end
}

// scheduleTimeMatchLegacy preserves the pre-optimization lexicographic
// comparison for bounds parseClockMinutes rejects (e.g. unpadded "9:00"):
// whatever such a schedule matched before, it matches now.
func scheduleTimeMatchLegacy(startStr, endStr string, now time.Time) bool {
	cur := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
	if startStr <= endStr {
		return cur >= startStr && cur < endStr
	}
	return cur >= startStr || cur < endStr
}

// parseClockMinutes converts a strict zero-padded 24-h "HH:MM" clock string to
// minutes since midnight. "24:00" is accepted (1440) as the exclusive
// end-of-day bound existing schedules use to close a full-day window. On the
// strict format the minute scale is order-isomorphic to string comparison, so
// swapping the comparison cannot flip any schedule decision; anything else
// returns ok=false and stays on the legacy comparison.
func parseClockMinutes(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h1, h2 := s[0]-'0', s[1]-'0'
	m1, m2 := s[3]-'0', s[4]-'0'
	if h1 > 9 || h2 > 9 || m1 > 9 || m2 > 9 {
		return 0, false
	}
	hh := int(h1)*10 + int(h2)
	mm := int(m1)*10 + int(m2)
	if hh == 24 && mm == 0 {
		return 1440, true
	}
	if hh > 23 || mm > 59 {
		return 0, false
	}
	return hh*60 + mm, true
}

// ─── Source matching ──────────────────────────────────────────────────────────

func matchSource(rule *PolicyRule, clientIP, identity, authSource string, groups []string) bool {
	src := newClientSource(clientIP)
	return matchSourceAddr(rule, &src, identity, authSource, groups)
}

// clientSource carries the request's client address for the per-rule source
// check. One is built per EVALUATION and shared by every rule, replacing work
// that used to be redone per RULE.
//
// It is passed by POINTER and its parse is LAZY, and both of those are load
// bearing:
//
//   - Lazy, because the address is needed only by a rule that actually carries
//     a SourceIP. Parsing eagerly at the top of the scan — which is what the
//     pre-change code did, with net.ParseIP — charges every deployment for a
//     feature only some use. Measured on a 500-rule rulebase with NO source
//     CIDRs, an eager parse cost 2-8% depending on where the match landed; a
//     cost change should not be a trade.
//   - By pointer, so the memoised parse is visible to the NEXT rule rather
//     than being thrown away with a by-value copy. The pointer is read and
//     written only by matchSourceAddr, never retained, so it stays on
//     evalAccessRules' stack and the scan keeps its zero-allocation contract
//     (pinned by TestBenchGate_PolicySourceCIDRAllocFree).
//
// A clientSource belongs to ONE evaluation and must not be shared across
// goroutines; evalAccessRules keeps it as a local for exactly that reason.
type clientSource struct {
	// raw is the address verbatim, for a rule whose SourceIP is a literal
	// rather than a CIDR (a plain string compare).
	raw string
	// addr is raw parsed and Unmapped; invalid exactly when raw is not a valid
	// IP address — the condition the pre-change code spelled as
	// net.ParseIP(clientIP) != nil. Valid only once parsed is true.
	//
	// The Unmap mirrors net.IPNet.Contains, which folds a 4-in-6 address to
	// IPv4 via To4 before comparing — the same pairing prefixFromIPNet applies
	// to the network side.
	addr   netip.Addr
	parsed bool
}

func newClientSource(clientIP string) clientSource {
	return clientSource{raw: clientIP}
}

// address parses raw on first use and memoises the result — including the
// failure, so an unparseable address is not re-parsed once per rule.
//
// It uses netip.ParseAddr rather than the net.ParseIP this path used before:
// net.ParseIP builds a 16-byte slice (53 ns, 1 alloc on this machine) where
// netip.ParseAddr fills a value (26 ns, 0 allocs), and a slice field would
// also make the struct's contents escape.
//
// The one place the two parsers disagree is a ZONED address: net.ParseIP
// rejects "fe80::1%eth0" outright, netip.ParseAddr accepts it. Rejecting the
// zone here restores net.ParseIP's verdict exactly, so a zoned address still
// matches no source-scoped rule rather than newly matching one. This is the
// same parser swap, with the same explicit zone rejection, that the IP filter
// already makes (ipFilterView.contains, security.go); the equivalence is
// pinned here by TestSrcPrefix_DifferentialAgainstLegacyMatcher, whose oracle
// is still net.ParseIP.
//
// The parse itself is OUTLINED into parseAddr so that address() — which runs
// once per source-scoped rule — stays inside the inliner's budget. Inlined,
// the warm case is a load and a predicted-not-taken branch; with the parse
// spliced in it costs 147 against a budget of 80 and every rule pays a call.
func (s *clientSource) address() netip.Addr {
	if !s.parsed {
		s.parseAddr()
	}
	return s.addr
}

func (s *clientSource) parseAddr() {
	s.parsed = true
	if addr, err := netip.ParseAddr(s.raw); err == nil && addr.Zone() == "" {
		s.addr = addr.Unmap()
	}
}

// matchSourceAddr is matchSource's core, taking the client address pre-parsed:
// the hot path (Evaluate) builds it ONCE per request and reuses it across every
// rule's precomputed srcPrefix/srcIPNet, eliminating the per-rule
// ParseCIDR+ParseIP allocations.
//
// The three source-IP arms are ordered cheapest-first and are equivalent, not
// alternative, policies — each is a strictly narrower encoding of the same
// network. srcPrefix is preferred because netip.Prefix.Contains re-derives
// nothing (see the srcPrefix field doc); srcIPNet covers the masks that have no
// Prefix form; matchIPOrCIDR covers rules that never reached the mutators.
func matchSourceAddr(rule *PolicyRule, src *clientSource, identity, authSource string, groups []string) bool {
	ipOK := true
	if rule.SourceIP != "" {
		switch {
		case rule.srcPrefix.IsValid():
			addr := src.address()
			ipOK = addr.IsValid() && rule.srcPrefix.Contains(addr)
		case rule.srcIPNet != nil:
			// Reached only for a mask prefixFromIPNet cannot express, which
			// net.ParseCIDR cannot produce — so this arm is a guard against a
			// future srcIPNet source, not a live path, and the AsSlice
			// allocation it costs is never paid in practice. AsSlice returns
			// the 4-byte form for an unmapped IPv4 address; Contains folds its
			// argument through To4 anyway, so the verdict is unchanged.
			addr := src.address()
			ipOK = addr.IsValid() && rule.srcIPNet.Contains(net.IP(addr.AsSlice()))
		default:
			ipOK = matchIPOrCIDR(rule.SourceIP, src.raw)
		}
	}
	idOK := rule.SourceIdentity == "" || strings.EqualFold(rule.SourceIdentity, identity)
	grpOK := rule.SourceGroup == "" || containsGroupCI(groups, rule.SourceGroup)
	srcOK := rule.AuthSource == "" || matchAuthSource(rule.AuthSource, authSource)
	return ipOK && idOK && grpOK && srcOK
}

func matchAuthSource(ruleAuthSource, actualAuthSource string) bool {
	if strings.EqualFold(ruleAuthSource, actualAuthSource) {
		return true
	}
	// Legacy/canonical alias: a bare profile ID ("okta") and its prefixed form
	// ("oidc:okta") refer to the same provider, so they match. BUT two DIFFERENT
	// explicit schemes MUST NOT alias — a rule scoped to "oidc:okta" must not
	// authorize a "saml:okta" source (cross-IdP/cross-scheme confusion). Match
	// iff the bare names are equal AND the schemes are compatible (either side
	// bare, or the same scheme).
	ruleScheme, ruleName := splitIdPSource(ruleAuthSource)
	actScheme, actName := splitIdPSource(actualAuthSource)
	if !strings.EqualFold(ruleName, actName) {
		return false
	}
	return ruleScheme == "" || actScheme == "" || strings.EqualFold(ruleScheme, actScheme)
}

// splitIdPSource separates an auth-source string into its IdP scheme
// ("oidc"/"saml", or "" when bare/non-IdP) and the profile name.
func splitIdPSource(source string) (scheme, name string) {
	for _, p := range []string{"oidc:", "saml:", "ldap:"} {
		if rest, ok := strings.CutPrefix(source, p); ok && rest != "" {
			return strings.TrimSuffix(p, ":"), rest
		}
	}
	return "", source
}

func stripIdPPrefix(source string) string {
	for _, prefix := range []string{"oidc:", "saml:", "ldap:"} {
		if rest, ok := strings.CutPrefix(source, prefix); ok && rest != "" {
			return rest
		}
	}
	return source
}

// containsGroupCI reports whether groups contains name (case-insensitive).
func containsGroupCI(groups []string, name string) bool {
	name = strings.TrimSpace(name)
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g), name) {
			return true
		}
	}
	return false
}

func matchIPOrCIDR(cidrOrIP, clientIP string) bool {
	if strings.Contains(cidrOrIP, "/") {
		_, ipNet, err := net.ParseCIDR(cidrOrIP)
		if err != nil {
			return false
		}
		ip := net.ParseIP(clientIP)
		return ip != nil && ipNet.Contains(ip)
	}
	return cidrOrIP == clientIP
}

// matchIPOrCIDRAddr is matchIPOrCIDR with the client IP pre-parsed. clientAddr
// MUST be net.ParseIP(clientIP) (nil = unparseable, fails closed on the CIDR
// branch); the Stage-1 auth resolver parses once per request instead of per
// predicate value.
func matchIPOrCIDRAddr(cidrOrIP, clientIP string, clientAddr net.IP) bool {
	if strings.Contains(cidrOrIP, "/") {
		_, ipNet, err := net.ParseCIDR(cidrOrIP)
		if err != nil {
			return false
		}
		return clientAddr != nil && ipNet.Contains(clientAddr)
	}
	return cidrOrIP == clientIP
}

// ─── Destination matching ─────────────────────────────────────────────────────

func matchDest(rule *PolicyRule, host string) bool {
	sc := newHostCatScratch(host)
	return matchDestNorm(rule, host, normalizeHost(host), &sc)
}

// matchDestNorm is matchDest's core. normHost MUST be normalizeHost(host) and
// sc MUST be a scratch built for the same host; the hot path (Evaluate) builds
// both ONCE per request and reuses them across every rule, and uses each rule's
// precomputed normFQDN — eliminating the two per-rule host+pattern
// normalization allocations and the per-rule host→category resolution.
// Country checks keep using the raw host (they normalize internally and are far
// less common).
func matchDestNorm(rule *PolicyRule, host, normHost string, sc *hostCatScratch) bool {
	// Empty fields mean "match any" — all configured fields must satisfy.
	fqdnSet := rule.DestFQDN != ""
	catSet := rule.DestCategory != "" && rule.DestCategory != CategoryAny
	catGroupSet := rule.DestCategoryGroup != ""
	countrySet := len(rule.DestCountry) > 0

	// FQDN check — use the precomputed normalized pattern when available;
	// otherwise fall back to the allocating matchFQDN so correctness never
	// depends on normFQDN having been precomputed.
	if fqdnSet {
		if rule.normFQDN != "" {
			if !matchFQDNNorm(rule.normFQDN, normHost) {
				return false
			}
		} else if !matchFQDN(rule.DestFQDN, host) {
			return false
		}
	}
	// URL category check (single category).
	if catSet && !sc.matchesCategory(rule.DestCategory) {
		return false
	}
	// Category group check — host must be in ANY category within the group.
	// Amortized O(1) per rule: the host→category fusion is resolved ONCE per
	// scan (hostCatScratch) and each of its halves is itself indexed — the
	// urlcat reverse index answers host→category in O(labels) map probes
	// (urlcat.Store.LookupHost) and the group membership check is a set probe.
	if catGroupSet && !categoryGroupMatchesHostScratch(rule, sc) {
		return false
	}
	// Geo-IP country check — cache-only to avoid blocking the request goroutine.
	// Fail-closed: on a cache miss the country is unknown and the rule does NOT
	// match, preventing unclassified traffic from matching geo-restricted rules.
	if countrySet {
		code, cached := geo.LookupCached(host)
		if !cached || !matchCountry(rule.DestCountry, code) {
			return false
		}
	}
	return true
}

func matchCountry(countries []string, code string) bool {
	if code == "" {
		return false
	}
	code = strings.ToUpper(code)
	for _, c := range countries {
		if strings.ToUpper(c) == code {
			return true
		}
	}
	return false
}

// FileProfileBlocked returns true if the file extension of urlPath is blocked
// by the rule's FileProfile, and FileFiltering is enabled.
// Dynamic profiles from globalProfileStore take precedence over the legacy
// hardcoded fileProfileExts map (backward-compatible fallback).
func (r *PolicyRule) FileProfileBlocked(urlPath string) bool {
	if !r.FileFiltering || r.FileProfile == FileProfileNone {
		return false
	}
	// Resolve extension list: check dynamic store first, then legacy map.
	var exts []string
	if p := globalProfileStore.GetByName(string(r.FileProfile)); p != nil {
		exts = p.Extensions
	} else if legacyExts, ok := fileProfileExts[r.FileProfile]; ok {
		exts = legacyExts
	} else {
		return false
	}
	return matchFileExt(urlPath, exts)
}

// matchFileExt returns true if urlPath ends with one of the given extensions.
func matchFileExt(urlPath string, exts []string) bool {
	ext := ""
	for i := len(urlPath) - 1; i >= 0 && urlPath[i] != '/'; i-- {
		if urlPath[i] == '.' {
			ext = strings.ToLower(urlPath[i:])
			break
		}
	}
	if ext == "" {
		return false
	}
	for _, e := range exts {
		if e == ext {
			return true
		}
	}
	return false
}

// The canonical FQDN-glob matcher moved to internal/hostutil (ADR-0002,
// policy.go decomposition Phase B) — it is shared by rule matching here and
// the SSL-bypass matcher (internal/sslbypass); their agreement is pinned by
// policy_bypass_security_test.go. Wrapper FUNCTIONS (not func vars) so the
// per-rule call in Evaluate's hot path stays direct and inlinable.

func matchFQDN(pattern, host string) bool { return hostutil.MatchFQDN(pattern, host) }

func matchFQDNNorm(pattern, host string) bool { return hostutil.MatchFQDNNorm(pattern, host) }

// matchCategory reports whether host belongs to the named URL category.
//
// F3b-4 source-aware resolution. When the signed-feed effective view is installed
// (offline at startup, atomically replaced on a committed activation / override
// recompose), the SaaS taxonomy is served EXCLUSIVELY from that view and catStore
// contributes ADMIN-created categories only — so a signed activation cannot be
// double-served or served stale from catStore, and policy readers observe a single
// complete view via one atomic pointer load. When the view is absent (lifecycle
// unarmed / disabled build / unit tests) the full catStore taxonomy serves, byte-for-
// byte as before.
//
// The resolution itself lives on hostCatScratch so a policy scan can share one
// host→category resolution across every rule (policy_hostcat.go); this is the
// single-shot entry point for callers outside a scan.
func matchCategory(cat URLCategory, host string) bool {
	sc := newHostCatScratch(host)
	return sc.matchesCategory(cat)
}

// lookupHostCategory resolves a hostname to its URL category across both tiers.
// Returns (category, tier, matchedBy) where tier is "admin", "saas",
// "community", or "none". Used by the admin URL-lookup API endpoint and policy
// test response enrichment.
//
// F3b-4 source-aware resolution — see matchCategory. With the signed-feed
// effective view installed: admin-created categories (catStore, BuiltIn=false)
// first, then the SaaS taxonomy from the atomic view (tier "saas"), then UT1.
// Without it, the full catStore taxonomy serves as before (tier "admin").
//
// The resolution lives on hostCatScratch (policy_hostcat.go) so a policy scan
// resolves it once and shares it across every rule; this is the single-shot
// entry point for callers outside a scan.
func lookupHostCategory(host string) (category, tier, matchedBy string) {
	sc := newHostCatScratch(host)
	return sc.fusion()
}

// ── SSL Bypass Matcher ────────────────────────────────────────────────────────
// The SSL-bypass engine (pattern compilation, glob/regex matching, JSON
// persistence) moved to internal/sslbypass (ADR-0002, policy.go
// decomposition Phase B). main keeps the /api/ssl-bypass handlers, the
// inspection-rules startup slice, cluster sync, and rollback — via this
// alias + singleton. Matches sits on the per-CONNECT hot path
// (resolveSSLAction).

// SSLBypassMatcher is re-exposed unqualified (engine type is sslbypass.Matcher).
type SSLBypassMatcher = sslbypass.Matcher

var sslBypass = &SSLBypassMatcher{}
