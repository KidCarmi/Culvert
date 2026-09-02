package main

// Sluice CDR policy engine.
//
// This file implements the Zero-Trust matcher that decides, per request,
// WHICH sanitization profile Culvert should ask Sluice to apply and in
// WHICH mode (ENFORCE / REPORT_ONLY / BYPASS_WITH_REPORT).
//
// The matching primitives intentionally mirror `PolicyRule` (see policy.go)
// so operators get a consistent mental model between "allow/deny" policy
// and "how to sanitize this file" policy.  Rules are first-match by
// priority.  When no rule matches, the default profile + mode from
// CDRConfig are used.
//
// Phase 2a (this file): in-memory engine + JSON persistence.
// Phase 2b (next):      wired from handleTunnelInspect.
// Phase 2c:             admin API CRUD + ConfigSnapshot sync.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// ─── Rule shape ─────────────────────────────────────────────────────────────

// CDRPolicyRule is a single Content Disarm & Reconstruction rule.
// Matching fields intentionally parallel PolicyRule so admins can reuse
// their mental model.  A zero-value/empty field means "any".
type CDRPolicyRule struct {
	Priority int    `json:"priority"`
	Name     string `json:"name"`
	Enabled  *bool  `json:"enabled,omitempty"` // nil/true = active

	// Source matchers — identity-level scoping.
	SourceIP       string `json:"sourceIP"`       // single IP or CIDR; "" = any
	SourceIdentity string `json:"sourceIdentity"` // authenticated username; "" = any
	SourceGroup    string `json:"sourceGroup"`    // IdP group/role; "" = any
	AuthSource     string `json:"authSource"`     // IdP name; "" = any

	// Destination matchers — what the user is downloading from.
	DestFQDN          string      `json:"destFQDN"`          // exact or wildcard; "" = any
	DestCategory      URLCategory `json:"destCategory"`      // URL category; "" = any
	DestCategoryGroup string      `json:"destCategoryGroup"` // "" = any
	DestCountry       []string    `json:"destCountry"`       // ISO-3166 α2; nil = any

	// Temporal scoping — reuses policy.go's PolicySchedule for symmetry.
	Schedule *PolicySchedule `json:"schedule,omitempty"`

	// Action — what Sluice should do when this rule fires.
	ProfileName string `json:"profileName"` // must match a name in Health.profiles (default "default")
	Mode        string `json:"mode"`        // ENFORCE | REPORT_ONLY | BYPASS_WITH_REPORT

	HitCount int64 `json:"hitCount"` // runtime counter, not persisted
}

// cdrRuleIsEnabled mirrors policy.go's ruleIsEnabled — nil pointer = active.
func cdrRuleIsEnabled(r *CDRPolicyRule) bool {
	return r.Enabled == nil || *r.Enabled
}

// ─── Decision ───────────────────────────────────────────────────────────────

// CDRPolicyDecision is the matcher's output.  Carries enough context for
// auditing plus the exact {profile, mode} pair Culvert sends to Sluice.
type CDRPolicyDecision struct {
	// MatchedRule is nil when no rule matched and defaults were applied.
	MatchedRule *CDRPolicyRule

	ProfileName string
	Mode        pb.Mode

	// MatchedConditions is a compact, human-readable summary of the rule
	// fields that contributed to the match ("srcGroup=finance dstCat=cloud-storage").
	MatchedConditions string

	// Source: "rule" | "default".
	Source string
}

// normalizeMode returns the pb.Mode for a string, defaulting to ENFORCE.
// Unknown strings default to ENFORCE (safer than REPORT_ONLY which lets
// active content through).
func normalizeMode(s string) pb.Mode {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "REPORT_ONLY":
		return pb.Mode_REPORT_ONLY
	case "BYPASS_WITH_REPORT":
		return pb.Mode_BYPASS_WITH_REPORT
	case "", "ENFORCE":
		return pb.Mode_ENFORCE
	default:
		return pb.Mode_ENFORCE
	}
}

// validateMode reports whether s is one of the three allowed mode strings.
// Empty is treated as valid (means ENFORCE).
func validateMode(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "ENFORCE", "REPORT_ONLY", "BYPASS_WITH_REPORT":
		return true
	}
	return false
}

// ─── Store ──────────────────────────────────────────────────────────────────

// CDRPolicyStore is the ordered, thread-safe list of CDRPolicyRule entries.
// Persisted as JSON at `path`; missing file = empty ruleset.
//
// The store exposes a monotonic `epoch` counter bumped on every mutation.
// Downstream caches (cdrHashCache in cdr_proxy.go) tag entries with the
// epoch-at-write so cached decisions under an old policy are invalidated
// automatically without a mass Clear() — addresses the "stale cached
// verdict after policy change" class of bug.
type CDRPolicyStore struct {
	mu        sync.RWMutex
	rules     []*CDRPolicyRule
	path      string
	version   int64  // monotonic, bumped on every mutation
	updatedAt string // RFC3339
	epoch     int64  // monotonic, bumped on every mutation (lock-free read via atomic)

	// integrity is the identity truth computed at Load / Replace / RemoveAt
	// (2E-C R10). A nil Issues slice means "never evaluated" (in-memory
	// store built by Add alone), which is OK by construction.
	integrity CDRPolicyIntegrity
}

// cdrPolicyStore is the process-wide store, loaded from disk at init.
var cdrPolicyStore = &CDRPolicyStore{}

// Version returns the current monotonic version + last-updated timestamp.
func (s *CDRPolicyStore) Version() (int64, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version, s.updatedAt
}

// bumpVersion MUST be called under s.mu.Lock().
func (s *CDRPolicyStore) bumpVersion() {
	s.version++
	s.updatedAt = time.Now().UTC().Format(time.RFC3339)
	// Advance the lock-free epoch atomic so cache readers see the change
	// without acquiring our RWMutex.
	atomic.AddInt64(&s.epoch, 1)
}

// Epoch returns the current lock-free monotonic epoch.  Safe to call from
// hot paths (cache lookups) without holding s.mu.  Guaranteed to advance
// strictly monotonically across mutations.
func (s *CDRPolicyStore) Epoch() int64 {
	return atomic.LoadInt64(&s.epoch)
}

// Load reads rules from a JSON file.  A missing file is treated as an
// empty ruleset (no error) so first-boot works without manual setup.
func (s *CDRPolicyStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cdr policies: read %q: %w", sanitizeLog(path), err)
	}
	var rules []*CDRPolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("cdr policies: parse %q: %w", sanitizeLog(path), err)
	}
	// 2E-C R10: the name is the rule's identity. A durable file written
	// before identity was enforced (or edited by hand) may carry duplicate
	// or empty names; it is loaded VERBATIM (nothing is silently chosen or
	// dropped) and the store is marked DEGRADED — the read surface says so
	// and the operator repairs it by position (RemoveAt). Add is refused
	// while degraded; DELETE by an ambiguous name is refused.
	s.rules = rules
	s.integrity = computeCDRPolicyIntegrity(rules)
	s.bumpVersion()
	return nil
}

// cdrPolicyIdentity is the normalised identity key: names that differ
// only by surrounding whitespace are the SAME rule.
func cdrPolicyIdentity(name string) string { return strings.TrimSpace(name) }

// CDRPolicyIntegrityIssue names one identity defect in the loaded store.
type CDRPolicyIntegrityIssue struct {
	Kind      string `json:"kind"` // duplicate_name | empty_name
	Name      string `json:"name"`
	Positions []int  `json:"positions"`
}

// CDRPolicyIntegrity is the read-surface truth about the store's identity
// invariants. OK=false ⇒ degraded (see Load).
type CDRPolicyIntegrity struct {
	OK     bool                      `json:"ok"`
	Issues []CDRPolicyIntegrityIssue `json:"issues"`
}

func computeCDRPolicyIntegrity(rules []*CDRPolicyRule) CDRPolicyIntegrity {
	out := CDRPolicyIntegrity{OK: true, Issues: []CDRPolicyIntegrityIssue{}}
	byName := map[string][]int{}
	var empty []int
	for i, r := range rules {
		if r == nil {
			empty = append(empty, i)
			continue
		}
		id := cdrPolicyIdentity(r.Name)
		if id == "" {
			empty = append(empty, i)
			continue
		}
		byName[id] = append(byName[id], i)
	}
	if len(empty) > 0 {
		out.OK = false
		out.Issues = append(out.Issues, CDRPolicyIntegrityIssue{Kind: "empty_name", Positions: empty})
	}
	names := make([]string, 0, len(byName))
	for n, pos := range byName {
		if len(pos) > 1 {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		out.OK = false
		out.Issues = append(out.Issues, CDRPolicyIntegrityIssue{Kind: "duplicate_name", Name: n, Positions: byName[n]})
	}
	return out
}

// Integrity returns the current identity truth (always well-formed).
func (s *CDRPolicyStore) Integrity() CDRPolicyIntegrity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.integrity.Issues == nil {
		return CDRPolicyIntegrity{OK: true, Issues: []CDRPolicyIntegrityIssue{}}
	}
	return s.integrity
}

var (
	errCDRPolicyStoreDegraded = fmt.Errorf("the CDR policy store is degraded (duplicate or empty rule names on disk); repair it before adding rules")
	errCDRPolicyAmbiguousName = fmt.Errorf("more than one CDR policy rule carries that name; delete by position")
	errCDRPolicyEmptyName     = fmt.Errorf("cdr policies: rule name is required")
)

// validateIdentities enforces unique, non-empty normalised names.
func validateCDRPolicyIdentities(rules []*CDRPolicyRule) error {
	seen := map[string]int{}
	for i, r := range rules {
		id := cdrPolicyIdentity(r.Name)
		if id == "" {
			return fmt.Errorf("%w (rule %d)", errCDRPolicyEmptyName, i)
		}
		if j, dup := seen[id]; dup {
			return fmt.Errorf("%w: %q (rules %d and %d)", errCDRPolicyDuplicateName,
				strings.ReplaceAll(strings.ReplaceAll(id, "\n", "_"), "\r", "_"), j, i)
		}
		seen[id] = i
	}
	return nil
}

// RemoveAt deletes the rule at `position` (0-based, current order) ONLY
// when the store is degraded and the rule there carries `expectedName`
// (verbatim) — the operator's fenced repair path for duplicate/empty
// identities. Durable-or-nothing.
func (s *CDRPolicyStore) RemoveAt(position int, expectedName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.integrity.OK || s.integrity.Issues == nil {
		return fmt.Errorf("cdr policies: positional delete is only available while the store is degraded")
	}
	if position < 0 || position >= len(s.rules) || s.rules[position] == nil {
		return fmt.Errorf("cdr policies: no rule at position %d", position)
	}
	if s.rules[position].Name != expectedName {
		return fmt.Errorf("cdr policies: rule at position %d is not named as expected", position)
	}
	prev := s.rules
	prevIntegrity := s.integrity
	next := make([]*CDRPolicyRule, 0, len(prev)-1)
	next = append(next, prev[:position]...)
	next = append(next, prev[position+1:]...)
	s.rules = next
	s.integrity = computeCDRPolicyIntegrity(next)
	if err := s.saveLocked(); err != nil {
		s.rules = prev
		s.integrity = prevIntegrity
		return err
	}
	s.bumpVersion()
	return nil
}

// Save atomically writes the current ruleset to s.path (if set).  Returns
// nil without writing when path is empty (in-memory-only mode).
//
// 2E-C commit boundary: Save takes the WRITE lock and persists while
// holding it, and Add/RemoveByName persist inside their own critical
// sections (saveLocked) — the pre-2E-C snapshot-under-RLock/write-unlocked
// shape let two concurrent mutations land their file writes out of order,
// so the durable file could lose the later mutation (same class as the
// instance registry; see cdrstore.go Save).
func (s *CDRPolicyStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// saveLocked persists the current ruleset.  MUST be called with s.mu
// held (write mode).  No-op when path is empty.
func (s *CDRPolicyStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.rules, "", "  ")
	if err != nil {
		return fmt.Errorf("cdr policies: marshal: %w", err)
	}
	if err := fileutil.AtomicWrite(s.path, data, 0o600); err != nil {
		return fmt.Errorf("cdr policies: %w", err)
	}
	return nil
}

// List returns a shallow snapshot of the rules in priority order.
func (s *CDRPolicyStore) List() []*CDRPolicyRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*CDRPolicyRule, len(s.rules))
	copy(out, s.rules)
	return out
}

// Replace swaps the entire ruleset with `rules`, sorted by priority.
// Used by Load() and by the admin API's bulk-update path.
func (s *CDRPolicyStore) Replace(rules []*CDRPolicyRule) error {
	for i, r := range rules {
		if r == nil {
			return fmt.Errorf("cdr policies: rule %d is nil", i)
		}
		if !validateMode(r.Mode) {
			// sanitizeLog is belt-and-braces for log injection; the value is
			// already reflected in an error string so inlining the
			// strings.ReplaceAll keeps CodeQL's taint-tracking happy.
			safe := strings.ReplaceAll(strings.ReplaceAll(r.Mode, "\n", "_"), "\r", "_")
			return fmt.Errorf("cdr policies: rule %d has invalid mode %q", i, safe)
		}
	}
	if err := validateCDRPolicyIdentities(rules); err != nil {
		return err
	}
	sortCDRRulesByPriority(rules)
	s.mu.Lock()
	s.rules = rules
	s.integrity = computeCDRPolicyIntegrity(rules)
	s.bumpVersion()
	s.mu.Unlock()
	return nil
}

// errCDRPolicyDuplicateName rejects a second rule under an existing
// name (2E-C): the name is the only key RemoveByName / the admin DELETE
// accepts, so duplicates would make the deletion target ambiguous.
var errCDRPolicyDuplicateName = fmt.Errorf("a CDR policy rule with that name already exists")

// Add appends a rule, keeps the list priority-sorted, and persists.
// The name must be unique (it is the rule's identity — see
// errCDRPolicyDuplicateName). Durable-or-nothing: a failed persist
// reverts the in-memory append.
func (s *CDRPolicyStore) Add(r CDRPolicyRule) (CDRPolicyRule, error) {
	if !validateMode(r.Mode) {
		safe := strings.ReplaceAll(strings.ReplaceAll(r.Mode, "\n", "_"), "\r", "_")
		return CDRPolicyRule{}, fmt.Errorf("invalid mode %q", safe)
	}
	id := cdrPolicyIdentity(r.Name)
	if id == "" {
		return CDRPolicyRule{}, errCDRPolicyEmptyName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.integrity.Issues != nil && !s.integrity.OK {
		return CDRPolicyRule{}, errCDRPolicyStoreDegraded
	}
	for i := range s.rules {
		if cdrPolicyIdentity(s.rules[i].Name) == id {
			return CDRPolicyRule{}, fmt.Errorf("%w: %q", errCDRPolicyDuplicateName,
				strings.ReplaceAll(strings.ReplaceAll(id, "\n", "_"), "\r", "_"))
		}
	}
	prev := s.rules
	rule := r
	next := append(append([]*CDRPolicyRule(nil), prev...), &rule)
	sortCDRRulesByPriority(next)
	s.rules = next
	if err := s.saveLocked(); err != nil {
		s.rules = prev
		return CDRPolicyRule{}, err
	}
	s.bumpVersion()
	return rule, nil
}

// RemoveByName removes the rule with the matching name; returns false
// if no such rule exists. Durable-or-nothing: a failed persist restores
// the rule and reports (false, err).
func (s *CDRPolicyStore) RemoveByName(name string) (bool, error) {
	id := cdrPolicyIdentity(name)
	if id == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := -1
	for i := range s.rules {
		if s.rules[i] != nil && cdrPolicyIdentity(s.rules[i].Name) == id {
			if found >= 0 {
				// 2E-C R10: never silently choose which duplicate dies.
				return false, errCDRPolicyAmbiguousName
			}
			found = i
		}
	}
	if found < 0 {
		return false, nil
	}
	prev := s.rules
	prevIntegrity := s.integrity
	next := make([]*CDRPolicyRule, 0, len(prev)-1)
	next = append(next, prev[:found]...)
	next = append(next, prev[found+1:]...)
	s.rules = next
	if s.integrity.Issues != nil {
		s.integrity = computeCDRPolicyIntegrity(next)
	}
	if err := s.saveLocked(); err != nil {
		s.rules = prev
		s.integrity = prevIntegrity
		return false, err
	}
	s.bumpVersion()
	return true, nil
}

// sortCDRRulesByPriority orders rules descending by Priority so the
// highest-priority rule matches first (matches policy.go conventions).
func sortCDRRulesByPriority(rules []*CDRPolicyRule) {
	// Simple stable insertion sort — ruleset is typically small (<100).
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && rules[j-1].Priority < rules[j].Priority; j-- {
			rules[j-1], rules[j] = rules[j], rules[j-1]
		}
	}
}

// ─── Evaluator ──────────────────────────────────────────────────────────────

// Evaluate picks the first enabled rule whose source + schedule + dest
// matchers all fire.  When no rule matches, returns a default decision
// built from the config's default profile/mode.  Callers MUST always get
// a non-nil decision — the matcher never returns nil.
func (s *CDRPolicyStore) Evaluate(clientIP, identity, authSource, host string, groups []string, defaults CDRConfig) *CDRPolicyDecision {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	// Same per-scan hoist as policyStore.Evaluate: the destination's category
	// depends on the host, not the rule, so resolving it inside the loop would
	// pay an O(taxonomy) lookup — and a BadgerDB read transaction per domain
	// label on a feed-backed deployment — once per CDR rule. See
	// policy_hostcat.go.
	normHost := normalizeHost(host)
	catScratch := newHostCatScratch(host)

	for i := range rules {
		rule := rules[i]
		if !cdrRuleIsEnabled(rule) {
			continue
		}
		// Reuse policy.go's battle-tested matchers by constructing a
		// synthetic PolicyRule with just the fields they consult.  Cheap
		// (stack allocation) and keeps the matching semantics identical.
		syn := &PolicyRule{
			SourceIP:          rule.SourceIP,
			SourceIdentity:    rule.SourceIdentity,
			SourceGroup:       rule.SourceGroup,
			AuthSource:        rule.AuthSource,
			DestFQDN:          rule.DestFQDN,
			DestCategory:      rule.DestCategory,
			DestCategoryGroup: rule.DestCategoryGroup,
			DestCountry:       rule.DestCountry,
			Schedule:          rule.Schedule,
		}
		if !matchSource(syn, clientIP, identity, authSource, groups) {
			continue
		}
		if !matchSchedule(rule.Schedule) {
			continue
		}
		if !matchDestNorm(syn, host, normHost, &catScratch) {
			continue
		}
		atomic.AddInt64(&rule.HitCount, 1)
		return &CDRPolicyDecision{
			MatchedRule:       rule,
			ProfileName:       cdrProfileOrDefault(rule.ProfileName, defaults.DefaultProfile),
			Mode:              normalizeMode(rule.Mode),
			MatchedConditions: buildCDRMatchedConditions(rule),
			Source:            "rule",
		}
	}

	return &CDRPolicyDecision{
		ProfileName: cdrProfileOrDefault("", defaults.DefaultProfile),
		Mode:        normalizeMode(defaults.DefaultMode),
		Source:      "default",
	}
}

// cdrProfileOrDefault returns `configured`, falling back to `defaultName`,
// falling back to the reserved "default" profile.
func cdrProfileOrDefault(configured, defaultName string) string {
	if s := strings.TrimSpace(configured); s != "" {
		return s
	}
	if s := strings.TrimSpace(defaultName); s != "" {
		return s
	}
	return "default"
}

// buildCDRMatchedConditions produces a short audit-friendly summary of the
// rule fields that contributed to the match.  Only non-wildcard fields
// are listed.
func buildCDRMatchedConditions(rule *CDRPolicyRule) string {
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
		parts = append(parts, "destCatGrp="+rule.DestCategoryGroup)
	}
	if len(rule.DestCountry) > 0 {
		parts = append(parts, "destCountry="+strings.Join(rule.DestCountry, ","))
	}
	return strings.Join(parts, " ")
}
