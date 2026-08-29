// Package rewrite owns per-host HTTP header rewrite rules: the rule DTO, the
// ordered active rule set, and the request/response header mutators. It is a
// self-contained leaf (stdlib + the uuid generator, no Culvert coupling)
// extracted from the flat package main per ADR-0002.
package rewrite

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// Rule defines header mutations applied to requests and/or responses
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
type Rule struct {
	// ID is assigned automatically when the rule is added at runtime.
	//
	// COMPATIBILITY/PROCESS-LOCAL ONLY (2D-C §19): SetRules reassigns
	// sequential IDs on every load, so this integer is NOT durable object
	// identity — it exists for legacy clients that address rules by it within
	// one process lifetime. Management identity is StableID.
	ID int `json:"id"`

	// StableID is the server-owned DURABLE rule identity (2D-C §20): a UUID
	// assigned once — at interactive Add, or backfilled exactly once when a
	// legacy persisted/imported rule without one first passes through
	// SetRules — and preserved verbatim across restart, export/import,
	// config-version rollback, and CP→DP snapshot sync (the persistence owner
	// is AdminSettings, which snapshots rules WITH their StableIDs). The v2
	// management surface addresses rules ONLY by this. Never derived from
	// array position or rule contents: two identical rules are two different
	// objects. yaml:"-" — YAML-authored config rules receive their identity at
	// first load and it becomes durable through the settings owner.
	StableID string `yaml:"-" json:"stableId,omitempty"`

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
func (r *Rule) matchesHost(host string) bool {
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
	rules  []Rule
	nextID int
}

// NewRewriter returns a Rewriter with ID assignment starting at 1.
func NewRewriter() *Rewriter {
	return &Rewriter{nextID: 1}
}

// SetRules replaces the full rule set, PRESERVING LIST ORDER (order is
// evaluation semantics, §23) and every non-empty StableID verbatim (§21 —
// restart/rollback/snapshot must never re-identify a known rule). Legacy
// rules without a StableID are backfilled exactly once here; the returned
// count tells the caller whether a one-time migration happened so it can make
// the backfilled identities durable through the real persistence owner.
// Process-local integer IDs are reassigned as before (compatibility only).
//
// DEFENSIVE dedupe: the validated doors (import / rollback / snapshot
// candidate checks) reject duplicate StableIDs before any apply reaches here;
// if a duplicate still arrives (hand-edited file that bypassed a door), the
// FIRST occurrence keeps the identity and later duplicates are regenerated —
// counted in the return so the caller persists and logs, never silently.
func (rw *Rewriter) SetRules(rules []Rule) (backfilled int) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	seen := make(map[string]bool, len(rules))
	rw.rules = make([]Rule, len(rules))
	for i, r := range rules {
		r.ID = rw.nextID
		rw.nextID++
		if r.StableID == "" || seen[r.StableID] {
			r.StableID = uuid.NewString()
			backfilled++
		}
		seen[r.StableID] = true
		rw.rules[i] = r
	}
	return backfilled
}

// List returns a snapshot of the current rules.
func (rw *Rewriter) List() []Rule {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	out := make([]Rule, len(rw.rules))
	copy(out, rw.rules)
	return out
}

// Add appends a rule and returns it with the assigned identities. The
// interactive trust boundary (§22): any CALLER-supplied StableID is ignored —
// the server owns identity generation on create.
func (rw *Rewriter) Add(rule Rule) Rule {
	rw.mu.Lock()
	rule.ID = rw.nextID
	rw.nextID++
	rule.StableID = uuid.NewString()
	rw.rules = append(rw.rules, rule)
	rw.mu.Unlock()
	return rule
}

// RemoveByID deletes the rule with the given process-local integer ID
// (legacy-compat addressing). Returns false if not found.
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

// RemoveByStableID deletes the rule with the given durable identity (the v2
// management addressing). Returns false if not found.
func (rw *Rewriter) RemoveByStableID(stableID string) bool {
	if stableID == "" {
		return false
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	for i, r := range rw.rules {
		if r.StableID == stableID {
			rw.rules = append(rw.rules[:i], rw.rules[i+1:]...)
			return true
		}
	}
	return false
}

// StateSnapshot returns the ordered rules AND the content-derived revision
// that describes exactly them, from ONE lock hold (v2 coherent-read
// contract): rows from one state must never pair with another state's fence.
func (rw *Rewriter) StateSnapshot() ([]Rule, string) {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	out := make([]Rule, len(rw.rules))
	copy(out, rw.rules)
	return out, FingerprintRules(rw.rules)
}

// FingerprintRules is the canonical content fingerprint of an ORDERED rewrite
// rule set (§26): it covers stable identity, position, host, and every
// request/response header operation, with map keys sorted deterministically so
// map iteration order can never make the revision nondeterministic. The
// process-local integer ID is deliberately excluded — it changes across
// restarts without any semantic change.
func FingerprintRules(rules []Rule) string {
	h := sha256.New()
	h.Write([]byte("rwv1\x00"))
	writeMap := func(tag string, m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(h, "%s:%d\x00", tag, len(keys))
		for _, k := range keys {
			fmt.Fprintf(h, "%d\x00%s\x00%d\x00%s\x00", len(k), k, len(m[k]), m[k])
		}
	}
	writeList := func(tag string, l []string) {
		fmt.Fprintf(h, "%s:%d\x00", tag, len(l))
		for _, v := range l {
			fmt.Fprintf(h, "%d\x00%s\x00", len(v), v)
		}
	}
	for i, r := range rules {
		fmt.Fprintf(h, "rule:%d\x00%d\x00%s\x00%d\x00%s\x00", i, len(r.StableID), r.StableID, len(r.Host), r.Host)
		writeMap("qs", r.ReqSet)
		writeMap("qa", r.ReqAdd)
		writeList("qr", r.ReqRemove)
		writeMap("ps", r.RespSet)
		writeMap("pa", r.RespAdd)
		writeList("pr", r.RespRemove)
	}
	return hex.EncodeToString(h.Sum(nil))
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

// Snapshot captures the current rules and ID counter and returns a closure that
// restores them, under the mutex on both ends. Production code never calls this;
// it exists so package main's startup-slice test isolation helper can save and
// restore the package-global rewriter without reaching across the package
// boundary into the unexported fields (ADR-0002 extraction).
func (rw *Rewriter) Snapshot() func() {
	rw.mu.RLock()
	savedRules := append([]Rule(nil), rw.rules...)
	savedNext := rw.nextID
	rw.mu.RUnlock()
	return func() {
		rw.mu.Lock()
		rw.rules = savedRules
		rw.nextID = savedNext
		rw.mu.Unlock()
	}
}

// NewStableID mints a durable rewrite-rule identity (server-owned; the
// interactive create path calls this so a client-supplied value is never
// trusted).
func NewStableID() string { return uuid.NewString() }
