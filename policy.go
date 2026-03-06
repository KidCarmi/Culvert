package main

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

// categoryHosts maps URL categories to known host patterns (suffix-matched).
var categoryHosts = map[URLCategory][]string{
	CategorySocial: {
		"facebook.com", "twitter.com", "x.com", "instagram.com",
		"tiktok.com", "linkedin.com", "reddit.com", "snapchat.com", "pinterest.com",
	},
	CategoryMalicious: {
		"malware.com", "phishing.com", "eicar.org",
	},
	CategoryNews: {
		"cnn.com", "bbc.com", "bbc.co.uk", "reuters.com", "nytimes.com",
		"theguardian.com", "foxnews.com", "nbcnews.com", "apnews.com",
	},
	CategoryStreaming: {
		"netflix.com", "youtube.com", "twitch.tv", "hulu.com",
		"disneyplus.com", "spotify.com", "primevideo.com",
	},
	CategoryGambling: {
		"bet365.com", "pokerstars.com", "draftkings.com", "fanduel.com",
	},
	CategoryAdult: {},
}

// PolicyRule is a single PBAC rule evaluated in priority order.
type PolicyRule struct {
	Priority       int          `json:"priority"`
	Name           string       `json:"name"`
	SourceIP       string       `json:"sourceIP"`       // single IP or CIDR; empty = any
	SourceIdentity string       `json:"sourceIdentity"` // user/group mock; empty = any
	DestFQDN       string       `json:"destFQDN"`       // exact or wildcard FQDN; empty = any
	DestCategory   URLCategory  `json:"destCategory"`   // URL category; empty = any
	SSLAction      SSLAction    `json:"sslAction"`      // Inspect | Bypass
	FileFiltering  bool         `json:"fileFiltering"`  // enable file-type scanning (future)
	Action         PolicyAction `json:"action"`
	RedirectURL    string       `json:"redirectURL"` // used when Action == Redirect
	HitCount       int64        `json:"hitCount"`    // runtime counter, not persisted
}

// PolicyStore holds an ordered list of policy rules with thread-safe access.
type PolicyStore struct {
	mu    sync.RWMutex
	rules []*PolicyRule
	path  string
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
	_ = os.WriteFile(ps.path, data, 0600)
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
	return true
}

func (ps *PolicyStore) sortLocked() {
	sort.Slice(ps.rules, func(i, j int) bool {
		return ps.rules[i].Priority < ps.rules[j].Priority
	})
}

// PolicyMatch is returned when a rule is matched against a request.
type PolicyMatch struct {
	Rule      *PolicyRule
	Action    PolicyAction
	SSLAction SSLAction
}

// Evaluate iterates rules in priority order and returns the first match.
// Returns nil when no rule matches (caller should default to Allow).
func (ps *PolicyStore) Evaluate(clientIP, identity, host string) *PolicyMatch {
	ps.mu.RLock()
	rules := ps.rules
	ps.mu.RUnlock()

	for _, rule := range rules {
		if !matchSource(rule, clientIP, identity) {
			continue
		}
		if !matchDest(rule, host) {
			continue
		}
		atomic.AddInt64(&rule.HitCount, 1)
		return &PolicyMatch{
			Rule:      rule,
			Action:    rule.Action,
			SSLAction: rule.SSLAction,
		}
	}
	return nil
}

// ─── Source matching ──────────────────────────────────────────────────────────

func matchSource(rule *PolicyRule, clientIP, identity string) bool {
	ipOK := rule.SourceIP == "" || matchIPOrCIDR(rule.SourceIP, clientIP)
	idOK := rule.SourceIdentity == "" || strings.EqualFold(rule.SourceIdentity, identity)
	return ipOK && idOK
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
	// Empty fields mean "match any" — both must satisfy independently.
	fqdnSet := rule.DestFQDN != ""
	catSet := rule.DestCategory != "" && rule.DestCategory != CategoryAny

	switch {
	case !fqdnSet && !catSet:
		return true // wildcard rule
	case fqdnSet && !catSet:
		return matchFQDN(rule.DestFQDN, host)
	case !fqdnSet && catSet:
		return matchCategory(rule.DestCategory, host)
	default: // both set → AND logic
		return matchFQDN(rule.DestFQDN, host) && matchCategory(rule.DestCategory, host)
	}
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
	return host == pattern
}

func matchCategory(cat URLCategory, host string) bool {
	known, ok := categoryHosts[cat]
	if !ok {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range known {
		h = strings.ToLower(h)
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}
