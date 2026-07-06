package main

import (
	"encoding/json"
	"fmt"
	"net"
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
	Priority          int             `json:"priority"`
	Name              string          `json:"name"`
	SourceIP          string          `json:"sourceIP"`             // single IP or CIDR; empty = any
	SourceIdentity    string          `json:"sourceIdentity"`       // authenticated username; empty = any
	SourceGroup       string          `json:"sourceGroup"`          // IdP group/role membership; empty = any
	AuthSource        string          `json:"authSource"`           // IdP name ("okta","adfs","ldap","local") or "unauth"; empty = any
	DestFQDN          string          `json:"destFQDN"`             // exact or wildcard FQDN; empty = any
	DestCategory      URLCategory     `json:"destCategory"`         // URL category; empty = any
	DestCategoryGroup string          `json:"destCategoryGroup"`    // category group name; empty = any
	DestCountry       []string        `json:"destCountry"`          // ISO 3166-1 alpha-2 country codes; empty = any
	Schedule          *PolicySchedule `json:"schedule,omitempty"`   // nil = always active
	SSLAction         SSLAction       `json:"sslAction"`            // Inspect | Bypass
	FileFiltering     bool            `json:"fileFiltering"`        // enable file-type scanning
	FileProfile       FileProfileName `json:"fileProfile"`          // named file-extension block profile
	LogFullURI        bool            `json:"logFullUri"`           // log the full request URL (path, no query) for traffic matching this rule; HTTPS requires SSLAction=Inspect
	LogTraffic        *bool           `json:"logTraffic,omitempty"` // log allowed traffic matching this rule (nil/true = log; false = count stats only, no feed entry). Blocks/threats are always logged.
	TLSSkipVerify     bool            `json:"tlsSkipVerify"`        // skip upstream cert verification (use with caution)
	Action            PolicyAction    `json:"action"`
	RedirectURL       string          `json:"redirectURL"`            // used when Action == Redirect
	Enabled           *bool           `json:"enabled,omitempty"`      // nil or true = active; false = skipped during evaluation
	ID                string          `json:"id,omitempty"`           // stable ULID; backfilled on load (Phase 0 seam)
	RuleType          string          `json:"ruleType,omitempty"`     // "" or "access" = Stage-2 access rule; "auth" = Stage-1 (reserved)
	SubjectMatch      *SubjectMatch   `json:"subjectMatch,omitempty"` // typed subject selector (reserved; nil = unused)
	Auth              *AuthRuleSpec   `json:"auth,omitempty"`         // Stage-1 auth-rule spec; non-nil only for ruleType="auth" (Phase 1 seam)
	HitCount          int64           `json:"hitCount"`               // runtime counter, not persisted

	// normFQDN is the IDNA-normalized form of DestFQDN, precomputed by
	// sortLocked() whenever rules are mutated. The proxy hot path (Evaluate)
	// reads it instead of re-normalizing DestFQDN on every request — normalizing
	// a host allocates (~1 alloc via idna.ToASCII), so doing it per-rule
	// per-request was the dominant policy-eval allocation. Unexported ⇒ never
	// serialized; a rule that reaches the store outside the mutators (empty
	// normFQDN) falls back to the allocating path, so correctness never depends
	// on it being populated.
	normFQDN string

	// srcIPNet is the parsed network when SourceIP is CIDR notation, precomputed
	// by sortLocked() whenever rules are mutated — the same contract as normFQDN.
	// The hot path (Evaluate) reads it instead of re-running net.ParseCIDR on
	// every request: parsing a CIDR allocates (~4 allocs with the client-IP
	// parse), so doing it per-rule per-request made source-scoped rules ~8×
	// costlier than FQDN rules. nil (plain-IP SourceIP, invalid CIDR, or a rule
	// built outside the mutators) falls back to matchIPOrCIDR, so correctness
	// never depends on it being populated.
	srcIPNet *net.IPNet
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
type PolicyStore struct {
	mu        sync.RWMutex
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
	ps.rules = rules
	migrated := ps.backfillIDsLocked()
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
		logger.Printf("Policy: assigned stable ULID IDs to %d rule(s) missing them (one-time migration)", migrated)
	}
	return nil
}

// backfillIDsLocked assigns a stable ULID to every rule missing an ID and
// returns the number assigned. Must be called with ps.mu held.
func (ps *PolicyStore) backfillIDsLocked() int {
	n := 0
	for _, r := range ps.rules {
		if r.ID == "" {
			r.ID = newRuleID()
			n++
		}
	}
	return n
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
	ps.mu.RLock()
	m := policyMeta{Version: ps.version, UpdatedAt: ps.updatedAt}
	ps.mu.RUnlock()
	data, _ := json.Marshal(m)
	_ = atomicWriteFile(ps.path+".meta", data, 0o600)
}

// Save persists the current rules to disk (skips HitCount — runtime only).
func (ps *PolicyStore) Save() {
	if ps.path == "" {
		return
	}
	ps.mu.RLock()
	// Snapshot without hit counts for persistence.
	snapshot := make([]PolicyRule, len(ps.rules))
	for i, r := range ps.rules {
		snapshot[i] = *r
		snapshot[i].HitCount = 0
	}
	ps.mu.RUnlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	// Atomic + durable write — temp file, fsync, rename, parent-dir fsync.
	// Skip saveMeta on failure so the .meta sidecar can't record a newer
	// version/timestamp than the rules actually on disk.
	if err := atomicWriteFile(ps.path, data, 0o600); err != nil {
		return
	}
	ps.saveMeta()
}

// List returns a copy of all rules (including live HitCount).
func (ps *PolicyStore) List() []PolicyRule {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]PolicyRule, len(ps.rules))
	for i, r := range ps.rules {
		out[i] = *r
		out[i].HitCount = atomic.LoadInt64(&r.HitCount) // B7: atomic read of concurrently-written counter
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
	for i := range rules {
		r := rules[i]
		// Fail-closed: drop invalid auth rules and SubjectMatch-bearing access rules.
		if ok, reason := policyRulePersistable(&r); !ok {
			logWarnf("Policy: dropping rule %q on bulk replace — %s", sanitizeLog(r.Name), sanitizeLog(reason))
			continue
		}
		r.HitCount = 0
		// Auto-enable FileFiltering when a profile is selected.
		if r.FileProfile != "" && r.FileProfile != FileProfileNone {
			r.FileFiltering = true
		}
		// Backfill a stable ID if missing. Cross-node ID consistency (CP/DP
		// agreeing on the same ID) is deferred to Phase 3, when ConfigSnapshot
		// carries rule IDs; until then nodes assign IDs independently.
		if r.ID == "" {
			r.ID = newRuleID()
		}
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
	// Auto-enable FileFiltering when a profile is selected (defense-in-depth).
	if nr.FileProfile != "" && nr.FileProfile != FileProfileNone {
		nr.FileFiltering = true
	}
	if nr.Enabled == nil {
		t := true
		nr.Enabled = &t
	}
	if nr.ID == "" {
		nr.ID = newRuleID()
	}
	if nr.Priority <= 0 {
		// Auto-assign priority: one higher than the current max.
		maxPri := 0
		for _, existing := range ps.rules {
			if existing.Priority > maxPri {
				maxPri = existing.Priority
			}
		}
		nr.Priority = maxPri + 1
	}
	ps.rules = append(ps.rules, &nr)
	ps.sortLocked()
	ps.bumpVersion()
	ps.mu.Unlock()

	// Detect policy conflicts after adding the new rule.
	for _, w := range ps.DetectConflicts() {
		logWarnf("Policy: %s", sanitizeLog(w))
	}
	return nr
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
		if rule.Priority == priority {
			r.HitCount = atomic.LoadInt64(&rule.HitCount) // B7: atomic read of concurrently-written counter
			// Preserve the existing stable ID when the incoming body omits it
			// (PUT bodies from older clients carry no "id"). Never let an edit
			// wipe a rule's durable identifier.
			if r.ID == "" {
				r.ID = rule.ID
			}
			ps.rules[i] = &r
			ps.sortLocked()
			ps.bumpVersion()
			return true
		}
	}
	return false
}

// Delete removes the rule with the given priority. Returns false if not found.
func (ps *PolicyStore) Delete(priority int) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, rule := range ps.rules {
		if rule.Priority == priority {
			ps.rules = append(ps.rules[:i], ps.rules[i+1:]...)
			ps.bumpVersion()
			return true
		}
	}
	return false
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
	byOldPri := make(map[int]*PolicyRule, len(ps.rules))
	for _, r := range ps.rules {
		byOldPri[r.Priority] = r
	}
	for newIdx, oldPri := range orderedPriorities {
		r, ok := byOldPri[oldPri]
		if !ok {
			return false
		}
		r.Priority = newIdx + 1
	}
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
	byOldPri := make(map[int]*PolicyRule, len(orderedPriorities))
	for _, r := range ps.rules {
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
	sort.Slice(ps.rules, func(i, j int) bool {
		return ps.rules[i].Priority < ps.rules[j].Priority
	})
	// Precompute the normalized FQDN and parsed source CIDR once per mutation so
	// Evaluate never has to normalize a pattern or parse a CIDR on the
	// per-request hot path. Index-based range avoids copying the rule pointer's
	// target.
	for i := range ps.rules {
		r := ps.rules[i]
		if r.DestFQDN != "" {
			r.normFQDN = normalizeHost(r.DestFQDN)
		} else {
			r.normFQDN = ""
		}
		// An invalid CIDR leaves srcIPNet nil; the fallback path re-parses and
		// returns false — identical to the pre-precompute behavior.
		r.srcIPNet = nil
		if strings.Contains(r.SourceIP, "/") {
			if _, ipNet, err := net.ParseCIDR(r.SourceIP); err == nil {
				r.srcIPNet = ipNet
			}
		}
	}
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
}

// Evaluate iterates rules in priority order and returns the first match.
// authSource is the IdP name that authenticated the user (e.g. "okta", "ldap",
// "local") or "unauth" when no credentials were presented.
// groups is the list of IdP group/role memberships for the authenticated user.
// Returns nil when no rule matches (caller should default to Deny — Zero Trust).
func (ps *PolicyStore) Evaluate(clientIP, identity, authSource, host string, groups []string) *PolicyMatch {
	ps.mu.RLock()
	rules := ps.rules
	ps.mu.RUnlock()

	// Normalize the destination host ONCE for the whole scan; every rule's FQDN
	// check reuses it (the host is identical across rules). This, plus each
	// rule's precomputed normFQDN, removes the ~2 allocs/rule the policy hot path
	// previously incurred re-normalizing host+pattern on every rule.
	normHost := normalizeHost(host)

	// Parse the client IP lazily and at most ONCE per request: only a scan that
	// reaches a CIDR-scoped rule pays the parse, and every subsequent CIDR rule
	// reuses it. Paired with each rule's precomputed srcIPNet this removes the
	// ~4 allocs/rule that net.ParseCIDR+net.ParseIP previously cost source-scoped
	// rules on every request.
	var clientNetIP net.IP
	clientIPParsed := false

	for i := range rules {
		rule := rules[i]
		if !ruleIsEnabled(rule) {
			continue
		}
		// Stage-2 evaluates access rules only. Authentication rules (Stage-1)
		// are inert here; an empty RuleType defaults to access for backward
		// compatibility, so all pre-existing rules are matched exactly as before.
		if ruleTypeOf(rule) != ruleTypeAccess {
			continue
		}
		if rule.srcIPNet != nil && !clientIPParsed {
			clientNetIP = net.ParseIP(clientIP)
			clientIPParsed = true
		}
		if !matchSourceNorm(rule, clientIP, clientNetIP, identity, authSource, groups) {
			continue
		}
		if !matchSchedule(rule.Schedule) {
			continue
		}
		if !matchDestNorm(rule, host, normHost) {
			continue
		}
		atomic.AddInt64(&rule.HitCount, 1)
		conds := buildMatchedConditions(rule)
		return &PolicyMatch{
			Rule:              rule,
			Action:            rule.Action,
			SSLAction:         rule.SSLAction,
			TLSSkipVerify:     rule.TLSSkipVerify,
			MatchedConditions: conds,
		}
	}
	return nil
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

func matchSchedule(s *PolicySchedule) bool {
	if s == nil {
		return true
	}
	loc := time.UTC
	if s.Timezone != "" {
		if l, err := time.LoadLocation(s.Timezone); err != nil {
			logWarnf("Policy: invalid schedule timezone %q, falling back to UTC", sanitizeLog(s.Timezone))
		} else {
			loc = l
		}
	}
	now := time.Now().In(loc)

	// Day-of-week check.
	if len(s.Days) > 0 {
		day := now.Weekday().String()[:3] // "Mon", "Tue" …
		found := false
		for _, d := range s.Days {
			if strings.EqualFold(d, day) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Time-of-day check.
	if s.TimeStart != "" && s.TimeEnd != "" {
		cur := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())
		if s.TimeStart <= s.TimeEnd {
			// Normal range e.g. 09:00–17:00.
			if cur < s.TimeStart || cur >= s.TimeEnd {
				return false
			}
		} else {
			// Overnight range e.g. 22:00–06:00.
			if cur < s.TimeStart && cur >= s.TimeEnd {
				return false
			}
		}
	}
	return true
}

// ─── Source matching ──────────────────────────────────────────────────────────

func matchSource(rule *PolicyRule, clientIP, identity, authSource string, groups []string) bool {
	return matchSourceNorm(rule, clientIP, nil, identity, authSource, groups)
}

// matchSourceNorm is matchSource's core. clientNetIP, when non-nil, MUST be
// net.ParseIP(clientIP); the hot path (Evaluate) parses it at most once per
// request and reuses it across every CIDR-scoped rule. nil means "parse on
// demand" (simulator / CDR / test callers off the hot path).
func matchSourceNorm(rule *PolicyRule, clientIP string, clientNetIP net.IP, identity, authSource string, groups []string) bool {
	ipOK := rule.SourceIP == "" || matchRuleSourceIP(rule, clientIP, clientNetIP)
	idOK := rule.SourceIdentity == "" || strings.EqualFold(rule.SourceIdentity, identity)
	grpOK := rule.SourceGroup == "" || containsGroupCI(groups, rule.SourceGroup)
	srcOK := rule.AuthSource == "" || matchAuthSource(rule.AuthSource, authSource)
	return ipOK && idOK && grpOK && srcOK
}

// matchRuleSourceIP checks a rule's SourceIP condition using the precomputed
// srcIPNet when available; otherwise it falls back to the parsing matchIPOrCIDR
// so correctness never depends on the precompute (mirrors normFQDN's contract).
func matchRuleSourceIP(rule *PolicyRule, clientIP string, clientNetIP net.IP) bool {
	if rule.srcIPNet != nil {
		if clientNetIP == nil {
			clientNetIP = net.ParseIP(clientIP)
		}
		return clientNetIP != nil && rule.srcIPNet.Contains(clientNetIP)
	}
	return matchIPOrCIDR(rule.SourceIP, clientIP)
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
	for _, p := range []string{"oidc:", "saml:"} {
		if rest, ok := strings.CutPrefix(source, p); ok && rest != "" {
			return strings.TrimSuffix(p, ":"), rest
		}
	}
	return "", source
}

func stripIdPPrefix(source string) string {
	for _, prefix := range []string{"oidc:", "saml:"} {
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

// ─── Destination matching ─────────────────────────────────────────────────────

func matchDest(rule *PolicyRule, host string) bool {
	return matchDestNorm(rule, host, normalizeHost(host))
}

// matchDestNorm is matchDest's core. normHost MUST be normalizeHost(host); the
// hot path (Evaluate) computes it ONCE per request and reuses it across every
// rule, and uses each rule's precomputed normFQDN — eliminating the two
// per-rule host+pattern normalization allocations. Category/country checks keep
// using the raw host (they normalize internally and are far less common).
func matchDestNorm(rule *PolicyRule, host, normHost string) bool {
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
	if catSet && !matchCategory(rule.DestCategory, host) {
		return false
	}
	// Category group check — host must be in ANY category within the group.
	// O(1): lookupHostCategory(host) → group.catSet[result].
	if catGroupSet && !categoryGroupMatchesHost(rule.DestCategoryGroup, host) {
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

func matchCategory(cat URLCategory, host string) bool {
	// Layer 1: admin-managed catStore — exact + suffix match (fast, in-memory).
	if catStore.MatchesHost(cat, host) {
		return true
	}
	// Layer 2: community BadgerDB feed — domain-walking point lookups.
	if communityDB != nil {
		if foundCat, ok := communityDB.Lookup(host); ok {
			return strings.EqualFold(foundCat, string(cat))
		}
	}
	return false
}

// lookupHostCategory resolves a hostname to its URL category across both tiers.
// Returns (category, tier, matchedBy) where tier is "admin", "community", or "none".
// Used by the admin URL-lookup API endpoint and policy test response enrichment.
func lookupHostCategory(host string) (category, tier, matchedBy string) {
	// Layer 1: admin-managed catStore — exact + suffix match.
	if name, pattern, ok := catStore.LookupHost(host); ok {
		return name, "admin", pattern
	}

	// Layer 2: community BadgerDB feed.
	h := normalizeHost(host)
	if communityDB != nil {
		if foundCat, ok := communityDB.Lookup(h); ok {
			return foundCat, "community", h
		}
	}
	return "", "none", ""
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
