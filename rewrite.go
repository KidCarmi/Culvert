package main

import (
	"net/http"
	"strings"
	"sync"
)

// RewriteRule defines header mutations applied to requests and/or responses
// whose destination host matches the given pattern.
//
// Example (config.yaml):
//
//	rewrite:
//	  - host: "*.internal.corp"
//	    req_set:
//	      X-Forwarded-By: "Culvert"
//	    resp_remove:
//	      - Server
//	  - host: ""           # empty = match all hosts
//	    resp_set:
//	      Strict-Transport-Security: "max-age=31536000"
type RewriteRule struct {
	// ID is assigned automatically when the rule is added at runtime.
	ID int `json:"id"`

	// Host is an exact hostname or wildcard pattern (*.example.com).
	// Empty string matches every request.
	Host string `yaml:"host" json:"host"`

	// Request header operations — applied before forwarding to upstream.
	ReqSet    map[string]string `yaml:"req_set"    json:"req_set,omitempty"`    // set / overwrite
	ReqAdd    map[string]string `yaml:"req_add"    json:"req_add,omitempty"`    // append
	ReqRemove []string          `yaml:"req_remove" json:"req_remove,omitempty"` // delete

	// Response header operations — applied before returning to client.
	RespSet    map[string]string `yaml:"resp_set"    json:"resp_set,omitempty"`
	RespAdd    map[string]string `yaml:"resp_add"    json:"resp_add,omitempty"`
	RespRemove []string          `yaml:"resp_remove" json:"resp_remove,omitempty"`
}

// matchesHost reports whether the rule applies to host.
func (r *RewriteRule) matchesHost(host string) bool {
	if r.Host == "" {
		return true // wildcard — matches everything
	}
	host = strings.ToLower(host)
	pattern := strings.ToLower(r.Host)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return host == pattern
}

// Rewriter holds the ordered list of active rewrite rules and applies them.
type Rewriter struct {
	mu     sync.RWMutex
	rules  []RewriteRule
	nextID int
}

var rewriter = &Rewriter{nextID: 1}

// SetRules replaces the full rule set (used during startup from config).
func (rw *Rewriter) SetRules(rules []RewriteRule) {
	rw.mu.Lock()
	rw.rules = make([]RewriteRule, len(rules))
	for i, r := range rules {
		r.ID = rw.nextID
		rw.nextID++
		rw.rules[i] = r
	}
	rw.mu.Unlock()
}

// List returns a snapshot of the current rules.
func (rw *Rewriter) List() []RewriteRule {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	out := make([]RewriteRule, len(rw.rules))
	copy(out, rw.rules)
	return out
}

// Add appends a rule and returns it with the assigned ID.
func (rw *Rewriter) Add(rule RewriteRule) RewriteRule {
	rw.mu.Lock()
	rule.ID = rw.nextID
	rw.nextID++
	rw.rules = append(rw.rules, rule)
	rw.mu.Unlock()
	return rule
}

// RemoveByID deletes the rule with the given ID. Returns false if not found.
func (rw *Rewriter) RemoveByID(id int) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	for i, r := range rw.rules {
		if r.ID == id {
			rw.rules = append(rw.rules[:i], rw.rules[i+1:]...)
			return true
		}
	}
	return false
}

// ApplyRequest mutates h in-place for every matching rule.
func (rw *Rewriter) ApplyRequest(host string, h http.Header) {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	for _, rule := range rw.rules {
		if !rule.matchesHost(host) {
			continue
		}
		for k, v := range rule.ReqSet {
			h.Set(k, v)
		}
		for k, v := range rule.ReqAdd {
			h.Add(k, v)
		}
		for _, k := range rule.ReqRemove {
			h.Del(k)
		}
	}
}

// ApplyResponse mutates resp.Header in-place for every matching rule.
func (rw *Rewriter) ApplyResponse(host string, resp *http.Response) {
	if resp == nil {
		return
	}
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	for _, rule := range rw.rules {
		if !rule.matchesHost(host) {
			continue
		}
		for k, v := range rule.RespSet {
			resp.Header.Set(k, v)
		}
		for k, v := range rule.RespAdd {
			resp.Header.Add(k, v)
		}
		for _, k := range rule.RespRemove {
			resp.Header.Del(k)
		}
	}
}
