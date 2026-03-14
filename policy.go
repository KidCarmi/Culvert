package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
type URLCategory string

const (
	CategorySocial    URLCategory = "Social"
	CategoryMalicious URLCategory = "Malicious"
	CategoryNews      URLCategory = "News"
	CategoryStreaming  URLCategory = "Streaming"
	CategoryGambling  URLCategory = "Gambling"
	CategoryAdult     URLCategory = "Adult"
	CategoryAny       URLCategory = "Any"
)

// CategoryEntry is one named URL category with its list of host patterns.
type CategoryEntry struct {
	Name    string   `json:"name"`
	Hosts   []string `json:"hosts"`
	BuiltIn bool     `json:"builtIn"` // seeded from built-in defaults; editable by admin
}

// CategoryStore manages URL categories with thread-safe, file-backed persistence.
type CategoryStore struct {
	mu      sync.RWMutex
	entries []*CategoryEntry
	path    string
}

var catStore = &CategoryStore{entries: defaultCategoryEntries()}

// defaultCategoryEntries returns the built-in category seed list.
func defaultCategoryEntries() []*CategoryEntry {
	return []*CategoryEntry{
		{Name: "Social", BuiltIn: true, Hosts: []string{
			"facebook.com", "twitter.com", "x.com", "instagram.com",
			"tiktok.com", "linkedin.com", "reddit.com", "snapchat.com", "pinterest.com",
		}},
		{Name: "Malicious", BuiltIn: true, Hosts: []string{
			"malware.com", "phishing.com", "eicar.org",
		}},
		{Name: "News", BuiltIn: true, Hosts: []string{
			"cnn.com", "bbc.com", "bbc.co.uk", "reuters.com", "nytimes.com",
			"theguardian.com", "foxnews.com", "nbcnews.com", "apnews.com",
		}},
		{Name: "Streaming", BuiltIn: true, Hosts: []string{
			"netflix.com", "youtube.com", "twitch.tv", "hulu.com",
			"disneyplus.com", "spotify.com", "primevideo.com",
		}},
		{Name: "Gambling", BuiltIn: true, Hosts: []string{
			"bet365.com", "pokerstars.com", "draftkings.com", "fanduel.com",
		}},
		{Name: "Adult", BuiltIn: true, Hosts: []string{}},
	}
}

// Load reads categories from a JSON file. If the file does not exist the
// built-in defaults are seeded and written to disk.
func (cs *CategoryStore) Load(path string) error {
	cs.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cs.mu.Lock()
			cs.entries = defaultCategoryEntries()
			cs.mu.Unlock()
			cs.Save()
			return nil
		}
		return err
	}
	var entries []*CategoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	cs.mu.Lock()
	cs.entries = entries
	cs.mu.Unlock()
	return nil
}

// Save atomically persists categories to disk.
func (cs *CategoryStore) Save() {
	if cs.path == "" {
		return
	}
	cs.mu.RLock()
	data, err := json.MarshalIndent(cs.entries, "", "  ")
	cs.mu.RUnlock()
	if err != nil {
		return
	}
	tmp := cs.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, cs.path)
}

// All returns a copy of all category entries.
func (cs *CategoryStore) All() []CategoryEntry {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	out := make([]CategoryEntry, len(cs.entries))
	for i, e := range cs.entries {
		cp := *e
		cp.Hosts = append([]string(nil), e.Hosts...)
		out[i] = cp
	}
	return out
}

// Set creates or replaces the host list for a named category.
func (cs *CategoryStore) Set(name string, hosts []string, builtIn bool) error {
	if name == "" {
		return fmt.Errorf("category name must not be empty")
	}
	if hosts == nil {
		hosts = []string{}
	}
	cs.mu.Lock()
	for _, e := range cs.entries {
		if strings.EqualFold(e.Name, name) {
			e.Hosts = hosts
			cs.mu.Unlock()
			cs.Save()
			return nil
		}
	}
	cs.entries = append(cs.entries, &CategoryEntry{Name: name, Hosts: hosts, BuiltIn: builtIn})
	cs.mu.Unlock()
	cs.Save()
	return nil
}

// Delete removes a category by name. Returns an error if not found.
func (cs *CategoryStore) Delete(name string) error {
	cs.mu.Lock()
	for i, e := range cs.entries {
		if strings.EqualFold(e.Name, name) {
			cs.entries = append(cs.entries[:i], cs.entries[i+1:]...)
			cs.mu.Unlock()
			cs.Save()
			return nil
		}
	}
	cs.mu.Unlock()
	return fmt.Errorf("category %q not found", name)
}

// AddHost appends a host to the named category (no-op if already present).
func (cs *CategoryStore) AddHost(category, host string) error {
	cs.mu.Lock()
	for _, e := range cs.entries {
		if strings.EqualFold(e.Name, category) {
			host = strings.ToLower(strings.TrimSpace(host))
			for _, h := range e.Hosts {
				if strings.ToLower(h) == host {
					cs.mu.Unlock()
					return nil // already present
				}
			}
			e.Hosts = append(e.Hosts, host)
			cs.mu.Unlock()
			cs.Save()
			return nil
		}
	}
	cs.mu.Unlock()
	return fmt.Errorf("category %q not found", category)
}

// RemoveHost deletes a host from the named category.
func (cs *CategoryStore) RemoveHost(category, host string) error {
	cs.mu.Lock()
	for _, e := range cs.entries {
		if strings.EqualFold(e.Name, category) {
			host = strings.ToLower(strings.TrimSpace(host))
			for i, h := range e.Hosts {
				if strings.ToLower(h) == host {
					e.Hosts = append(e.Hosts[:i], e.Hosts[i+1:]...)
					cs.mu.Unlock()
					cs.Save()
					return nil
				}
			}
			cs.mu.Unlock()
			return fmt.Errorf("host %q not in category %q", host, category)
		}
	}
	cs.mu.Unlock()
	return fmt.Errorf("category %q not found", category)
}

// FileProfileName identifies a named file-extension block profile.
type FileProfileName string

const (
	FileProfileNone        FileProfileName = ""
	FileProfileExecutables FileProfileName = "Executables"    // .exe .dll .bat .cmd .ps1 .scr .msi .pif .com .vbs
	FileProfileArchives    FileProfileName = "Archives"       // .zip .rar .7z .tar .gz .bz2 .xz .cab
	FileProfileDocuments   FileProfileName = "Documents"      // .doc .docm .xls .xlsm .ppt .pptm (macro-enabled)
	FileProfileMedia       FileProfileName = "Media"          // .mp3 .mp4 .avi .mkv .mov .flv .wmv
	FileProfileStrict      FileProfileName = "Strict"         // all of the above combined
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
	Priority       int             `json:"priority"`
	Name           string          `json:"name"`
	SourceIP       string          `json:"sourceIP"`       // single IP or CIDR; empty = any
	SourceIdentity string          `json:"sourceIdentity"` // authenticated username; empty = any
	SourceGroup    string          `json:"sourceGroup"`    // IdP group/role membership; empty = any
	AuthSource     string          `json:"authSource"`     // IdP name ("okta","adfs","ldap","local") or "unauth"; empty = any
	DestFQDN       string          `json:"destFQDN"`       // exact or wildcard FQDN; empty = any
	DestCategory   URLCategory     `json:"destCategory"`   // URL category; empty = any
	DestCountry    []string        `json:"destCountry"`    // ISO 3166-1 alpha-2 country codes; empty = any
	Schedule       *PolicySchedule `json:"schedule,omitempty"` // nil = always active
	SSLAction      SSLAction       `json:"sslAction"`      // Inspect | Bypass
	FileFiltering  bool            `json:"fileFiltering"`  // enable file-type scanning
	FileProfile    FileProfileName `json:"fileProfile"`    // named file-extension block profile
	TLSSkipVerify  bool            `json:"tlsSkipVerify"`  // skip upstream cert verification (use with caution)
	Action         PolicyAction    `json:"action"`
	RedirectURL    string          `json:"redirectURL"` // used when Action == Redirect
	HitCount       int64           `json:"hitCount"`    // runtime counter, not persisted
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
	ps.mu.Lock()
	ps.rules = rules
	ps.sortLocked()
	ps.mu.Unlock()
	return nil
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
	// Write to a temp file then rename for an atomic replace — a crash
	// mid-write must not corrupt the persisted rule file.
	tmp := ps.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, ps.path)
}

// List returns a copy of all rules (including live HitCount).
func (ps *PolicyStore) List() []PolicyRule {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]PolicyRule, len(ps.rules))
	for i, r := range ps.rules {
		out[i] = *r
	}
	return out
}

// Add inserts a new rule and re-sorts by priority.
func (ps *PolicyStore) Add(r PolicyRule) PolicyRule {
	ps.mu.Lock()
	nr := r
	nr.HitCount = 0
	ps.rules = append(ps.rules, &nr)
	ps.sortLocked()
	ps.bumpVersion()
	ps.mu.Unlock()
	return nr
}

// Update replaces the rule with the given priority. Returns false if not found.
func (ps *PolicyStore) Update(priority int, r PolicyRule) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for i, rule := range ps.rules {
		if rule.Priority == priority {
			r.HitCount = rule.HitCount // preserve live hit count
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

func (ps *PolicyStore) sortLocked() {
	sort.Slice(ps.rules, func(i, j int) bool {
		return ps.rules[i].Priority < ps.rules[j].Priority
	})
}

// PolicyMatch is returned when a rule is matched against a request.
type PolicyMatch struct {
	Rule          *PolicyRule
	Action        PolicyAction
	SSLAction     SSLAction
	TLSSkipVerify bool
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

	for _, rule := range rules {
		if !matchSource(rule, clientIP, identity, authSource, groups) {
			continue
		}
		if !matchSchedule(rule.Schedule) {
			continue
		}
		if !matchDest(rule, host) {
			continue
		}
		atomic.AddInt64(&rule.HitCount, 1)
		return &PolicyMatch{
			Rule:          rule,
			Action:        rule.Action,
			SSLAction:     rule.SSLAction,
			TLSSkipVerify: rule.TLSSkipVerify,
		}
	}
	return nil
}

// ─── Schedule matching ────────────────────────────────────────────────────────

func matchSchedule(s *PolicySchedule) bool {
	if s == nil {
		return true
	}
	loc := time.UTC
	if s.Timezone != "" {
		if l, err := time.LoadLocation(s.Timezone); err == nil {
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
	ipOK := rule.SourceIP == "" || matchIPOrCIDR(rule.SourceIP, clientIP)
	idOK := rule.SourceIdentity == "" || strings.EqualFold(rule.SourceIdentity, identity)
	grpOK := rule.SourceGroup == "" || containsGroupCI(groups, rule.SourceGroup)
	srcOK := rule.AuthSource == "" || strings.EqualFold(rule.AuthSource, authSource)
	return ipOK && idOK && grpOK && srcOK
}

// containsGroupCI reports whether groups contains name (case-insensitive).
func containsGroupCI(groups []string, name string) bool {
	for _, g := range groups {
		if strings.EqualFold(g, name) {
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
	// Empty fields mean "match any" — all configured fields must satisfy.
	fqdnSet := rule.DestFQDN != ""
	catSet := rule.DestCategory != "" && rule.DestCategory != CategoryAny
	countrySet := len(rule.DestCountry) > 0

	// FQDN check.
	if fqdnSet && !matchFQDN(rule.DestFQDN, host) {
		return false
	}
	// URL category check.
	if catSet && !matchCategory(rule.DestCategory, host) {
		return false
	}
	// Geo-IP country check — cache-only to avoid blocking the request goroutine.
	// On a cache miss the country is unknown; skip the country filter so we do
	// not inadvertently block traffic while the background poller catches up.
	if countrySet {
		code, cached := geo.LookupCached(host)
		if cached && !matchCountry(rule.DestCountry, code) {
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
func (r *PolicyRule) FileProfileBlocked(urlPath string) bool {
	if !r.FileFiltering || r.FileProfile == FileProfileNone {
		return false
	}
	exts, ok := fileProfileExts[r.FileProfile]
	if !ok {
		return false
	}
	// Extract extension (path.Ext semantics).
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

func matchFQDN(pattern, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	// Palo Alto-style: a bare domain implicitly includes all its subdomains.
	// "example.com" matches "example.com" AND "www.example.com".
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

func matchCategory(cat URLCategory, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	catStore.mu.RLock()
	defer catStore.mu.RUnlock()
	for _, e := range catStore.entries {
		if !strings.EqualFold(e.Name, string(cat)) {
			continue
		}
		for _, h := range e.Hosts {
			h = strings.ToLower(h)
			if host == h || strings.HasSuffix(host, "."+h) {
				return true
			}
		}
		return false
	}
	return false
}

// ── SSL Bypass Matcher ────────────────────────────────────────────────────────

// bypassPattern holds one compiled bypass entry.
// Glob patterns (e.g. "*.co.il") use matchFQDN semantics.
// Regex patterns are prefixed with "~" (e.g. "~^.*\.gov\.il$").
type bypassPattern struct {
	raw  string
	isRE bool
	re   *regexp.Regexp
}

// SSLBypassMatcher holds a list of host patterns that must always bypass
// SSL inspection, regardless of what the PBAC policy says.
// Patterns are managed at runtime via /api/ssl-bypass and persisted to a
// JSON file so they survive restarts without modifying config.yaml.
type SSLBypassMatcher struct {
	mu       sync.RWMutex
	raw      []string       // raw strings for persistence and API listing
	compiled []bypassPattern // pre-compiled for fast matching
	path     string         // optional JSON file path for persistence
}

var sslBypass = &SSLBypassMatcher{}

func compileBypassPattern(p string) (bypassPattern, error) {
	bp := bypassPattern{raw: p}
	if strings.HasPrefix(p, "~") {
		re, err := regexp.Compile(p[1:])
		if err != nil {
			return bypassPattern{}, fmt.Errorf("ssl bypass pattern %q: %w", p, err)
		}
		bp.isRE = true
		bp.re = re
	}
	return bp, nil
}

// Set atomically replaces all bypass patterns.
func (m *SSLBypassMatcher) Set(patterns []string) error {
	compiled := make([]bypassPattern, 0, len(patterns))
	for _, p := range patterns {
		bp, err := compileBypassPattern(p)
		if err != nil {
			return err
		}
		compiled = append(compiled, bp)
	}
	m.mu.Lock()
	m.raw = append([]string(nil), patterns...)
	m.compiled = compiled
	m.mu.Unlock()
	return nil
}

// Load reads bypass patterns from a JSON file (array of strings).
// A missing file is treated as an empty list (not an error).
// Sets the persistence path so subsequent Save() calls write to this file.
func (m *SSLBypassMatcher) Load(path string) error {
	m.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err != nil {
		return err
	}
	return m.Set(patterns)
}

// Save atomically persists the current patterns to the configured JSON file.
// A temporary file + rename ensures a crash mid-write never corrupts the list.
func (m *SSLBypassMatcher) Save() {
	if m.path == "" {
		return
	}
	m.mu.RLock()
	raw := make([]string, len(m.raw))
	copy(raw, m.raw)
	m.mu.RUnlock()

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, m.path)
}

// Add appends a single pattern. No-ops if the pattern is already present.
func (m *SSLBypassMatcher) Add(pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.raw {
		if p == pattern {
			return nil // already present
		}
	}
	bp, err := compileBypassPattern(pattern)
	if err != nil {
		return err
	}
	m.raw = append(m.raw, pattern)
	m.compiled = append(m.compiled, bp)
	return nil
}

// Remove deletes a pattern by exact string match. Returns true if removed.
func (m *SSLBypassMatcher) Remove(pattern string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.raw {
		if p == pattern {
			m.raw = append(m.raw[:i], m.raw[i+1:]...)
			m.compiled = append(m.compiled[:i], m.compiled[i+1:]...)
			return true
		}
	}
	return false
}

// List returns a snapshot of all raw patterns.
func (m *SSLBypassMatcher) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.raw))
	copy(out, m.raw)
	return out
}

// Matches reports whether host matches any configured bypass pattern.
// Glob patterns follow matchFQDN semantics ("*.co.il" matches "www.co.il").
// Regex patterns (prefix "~") are matched against the lower-cased bare host.
func (m *SSLBypassMatcher) Matches(host string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range m.compiled {
		if p.isRE {
			if p.re.MatchString(h) {
				return true
			}
		} else {
			if matchFQDN(p.raw, h) {
				return true
			}
		}
	}
	return false
}
