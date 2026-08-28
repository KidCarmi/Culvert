package rollout

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// selectorSchema is the rollout-scope selector-schema version this build
// understands. A scope declaring a HIGHER schema carries selector kinds this
// binary cannot interpret, so it is rejected WHOLE (fail closed) rather than
// silently under-matched — an older DP that does not understand a selector never
// executes a broader set than intended.
const selectorSchema = 1

// RiskClass classifies an operation by reversibility/blast radius. The zero value
// fails closed (never admitted to any scope).
type RiskClass uint8

const (
	// RiskUnknown is the zero value; fails closed.
	RiskUnknown RiskClass = iota
	// RiskRead — read-only/reversible.
	RiskRead
	// RiskWrite — mutating but recoverable.
	RiskWrite
	// RiskDestructive — irreversible/high blast radius.
	RiskDestructive
)

var riskToken = map[RiskClass]string{RiskRead: "read", RiskWrite: "write", RiskDestructive: "destructive"}

// Valid reports whether r is a defined risk class.
func (r RiskClass) Valid() bool { _, ok := riskToken[r]; return ok }

// String returns the stable token.
func (r RiskClass) String() string {
	if s, ok := riskToken[r]; ok {
		return s
	}
	return "unknown"
}

// HighRisk reports whether the class is write or destructive (requires an explicit
// high-risk scope to enter Shadow/Canary).
func (r RiskClass) HighRisk() bool { return r == RiskWrite || r == RiskDestructive }

// BucketKeyKind selects which stable subject attribute keys a percentage bucket.
// The keyed attribute MUST be stable for a subject across restarts (so the same
// subject stays in or out); it is never a clock, random value, or map order.
type BucketKeyKind uint8

const (
	// BucketByPrincipal keys the bucket by the authenticated principal id (default).
	BucketByPrincipal BucketKeyKind = iota
	// BucketByTenant keys the bucket by tenant id.
	BucketByTenant
	// BucketByAgent keys the bucket by agent id.
	BucketByAgent
	// BucketByClient keys the bucket by client/application id.
	BucketByClient
)

// Subject is the per-request attribute tuple matched against a scope. It is
// derived from already-resolved request state (identity, registry, catalog,
// policy operation class); matching reads only these fields and never performs
// I/O or reads a clock.
type Subject struct {
	Capability      Capability
	Tenant          string
	ServerID        string
	ToolFingerprint string // exact fingerprint hash
	ToolName        string
	PrincipalID     string
	AgentID         string
	ClientID        string
	Groups          []string
	Environment     string
	Operation       RiskClass
}

// ToolSel is an exact tool selector: a tool name is only meaningful when bound to
// its server and fingerprint (a bare name is never a selector).
type ToolSel struct {
	Server      string `json:"server"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

// ScopeSpec is the mutable input used to build (Compile) an immutable Scope. All
// slices are inclusion selectors unless prefixed Exclude*. An empty spec (no
// inclusion selectors and Percent==0) compiles to a scope that matches NOTHING —
// there is no wildcard "all" default.
type ScopeSpec struct {
	Capability        Capability    `json:"capability"`
	Tenants           []string      `json:"tenants,omitempty"`
	Servers           []string      `json:"servers,omitempty"`
	ToolFingerprints  []string      `json:"tool_fingerprints,omitempty"`
	Tools             []ToolSel     `json:"tools,omitempty"`
	Principals        []string      `json:"principals,omitempty"`
	Agents            []string      `json:"agents,omitempty"`
	Clients           []string      `json:"clients,omitempty"`
	Groups            []string      `json:"groups,omitempty"`
	Environments      []string      `json:"environments,omitempty"`
	Operations        []RiskClass   `json:"operations,omitempty"`  // admitted risk classes; empty ⇒ read-only only
	Percent           int           `json:"percent,omitempty"`     // 0 ⇒ no percentage gate; 1..99 sub-samples; 100 ⇒ all-in-dims
	BucketSalt        string        `json:"bucket_salt,omitempty"` // REQUIRED when 0 < Percent < 100 (binds the stable hash)
	BucketKey         BucketKeyKind `json:"bucket_key,omitempty"`
	ExcludeTenants    []string      `json:"exclude_tenants,omitempty"`
	ExcludeServers    []string      `json:"exclude_servers,omitempty"`
	ExcludeTools      []ToolSel     `json:"exclude_tools,omitempty"`
	ExcludePrincipals []string      `json:"exclude_principals,omitempty"`
	// HighRisk must be true for a scope whose Operations include write/destructive.
	// A plain scope is read-only/reversible; write/destructive never enter a rollout
	// through a percentage or a non-high-risk scope.
	HighRisk bool `json:"high_risk,omitempty"`
}

// Scope is the immutable, revisioned, content-hashed rollout scope. It is
// capability-scoped (tenant isolation and capability isolation are structural: a
// Gateway scope never matches a Management subject and vice versa). Construct via
// Compile; the zero Scope matches nothing.
type Scope struct {
	schema       int
	capability   Capability
	revision     uint64
	tenants      stringSet
	servers      stringSet
	fingerprints stringSet
	tools        toolSet
	principals   stringSet
	agents       stringSet
	clients      stringSet
	groups       stringSet
	environments stringSet
	operations   map[RiskClass]struct{}
	percent      int
	bucketSalt   string
	bucketKey    BucketKeyKind
	exTenants    stringSet
	exServers    stringSet
	exTools      toolSet
	exPrincipals stringSet
	highRisk     bool
	hash         string
	built        bool
}

type stringSet map[string]struct{}

func (s stringSet) has(v string) bool { _, ok := s[v]; return ok }
func (s stringSet) empty() bool       { return len(s) == 0 }

type toolSet map[ToolSel]struct{}

func (t toolSet) has(v ToolSel) bool { _, ok := t[v]; return ok }
func (t toolSet) empty() bool        { return len(t) == 0 }

// EmptyScope returns a compiled scope for a capability that matches nothing (the
// safe default at every mode's entry). Revision 0.
func EmptyScope(capb Capability) Scope {
	sc, _ := Compile(ScopeSpec{Capability: capb}, 0, DefaultLimits())
	return sc
}

// Compile validates spec and returns an immutable Scope at the given revision. It
// enforces bounds, value sizes, the no-wildcard rule, the high-risk gate for
// write/destructive operations, and percentage-bucket well-formedness. It is pure
// (no I/O, no clock). On any violation it returns a classified fail-closed error.
func Compile(spec ScopeSpec, revision uint64, lim Limits) (Scope, error) {
	if !lim.Valid() {
		return Scope{}, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "invalid limits")
	}
	if !spec.Capability.Valid() {
		return Scope{}, mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "rollout.scope", "scope capability invalid")
	}
	total := 0
	mkSet := func(vals []string) (stringSet, error) {
		set := make(stringSet, len(vals))
		for _, v := range vals {
			if v == "" {
				return nil, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "empty selector value")
			}
			if len(v) > lim.MaxValueBytes() {
				return nil, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "selector value too long")
			}
			set[v] = struct{}{}
		}
		if len(set) > lim.MaxSelectorValues() {
			return nil, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "selector value count over limit")
		}
		total += len(set)
		return set, nil
	}
	sc := Scope{schema: selectorSchema, capability: spec.Capability, revision: revision, percent: spec.Percent, bucketSalt: spec.BucketSalt, bucketKey: spec.BucketKey, highRisk: spec.HighRisk}
	// Compile every string-selector dimension through the same bounded builder; the
	// table keeps the cyclomatic footprint flat as dimensions are added.
	strSets := []struct {
		dst *stringSet
		src []string
	}{
		{&sc.tenants, spec.Tenants},
		{&sc.servers, spec.Servers},
		{&sc.fingerprints, spec.ToolFingerprints},
		{&sc.principals, spec.Principals},
		{&sc.agents, spec.Agents},
		{&sc.clients, spec.Clients},
		{&sc.groups, spec.Groups},
		{&sc.environments, spec.Environments},
		{&sc.exTenants, spec.ExcludeTenants},
		{&sc.exServers, spec.ExcludeServers},
		{&sc.exPrincipals, spec.ExcludePrincipals},
	}
	for _, d := range strSets {
		set, err := mkSet(d.src)
		if err != nil {
			return Scope{}, err
		}
		*d.dst = set
	}
	if err := sc.compileToolsAndBounds(spec, total, lim); err != nil {
		return Scope{}, err
	}
	var err error
	if sc.operations, err = compileOps(spec.Operations, spec.HighRisk); err != nil {
		return Scope{}, err
	}
	if err := validatePercent(spec); err != nil {
		return Scope{}, err
	}
	sc.hash = sc.computeHash()
	sc.built = true
	return sc, nil
}

// compileToolsAndBounds compiles the tool selectors onto sc and enforces the total
// selector and exclusion bounds. total carries the string-selector count already
// accumulated by Compile.
func (sc *Scope) compileToolsAndBounds(spec ScopeSpec, total int, lim Limits) error {
	var err error
	if sc.tools, total, err = mkToolSet(spec.Tools, total, lim); err != nil {
		return err
	}
	if sc.exTools, total, err = mkToolSet(spec.ExcludeTools, total, lim); err != nil {
		return err
	}
	if total > lim.MaxSelectors() {
		return mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "total selector count over limit")
	}
	if (len(sc.exTenants) + len(sc.exServers) + len(sc.exTools) + len(sc.exPrincipals)) > lim.MaxExclusions() {
		return mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "exclusion count over limit")
	}
	return nil
}

func mkToolSet(vals []ToolSel, total int, lim Limits) (toolSet, int, error) {
	set := make(toolSet, len(vals))
	for _, v := range vals {
		if v.Server == "" || v.Name == "" || v.Fingerprint == "" {
			return nil, total, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "tool selector requires server+name+fingerprint")
		}
		if len(v.Server) > lim.MaxValueBytes() || len(v.Name) > lim.MaxValueBytes() || len(v.Fingerprint) > lim.MaxValueBytes() {
			return nil, total, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "tool selector value too long")
		}
		set[v] = struct{}{}
	}
	total += len(set)
	return set, total, nil
}

func compileOps(ops []RiskClass, highRisk bool) (map[RiskClass]struct{}, error) {
	out := make(map[RiskClass]struct{}, len(ops))
	for _, o := range ops {
		if !o.Valid() {
			return nil, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "invalid operation class in scope")
		}
		if o.HighRisk() && !highRisk {
			// Write/destructive can only enter a rollout through an explicit high-risk
			// scope with the same four-eyes/revision binding as other sensitive changes.
			return nil, mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "write/destructive op requires an explicit high-risk scope")
		}
		out[o] = struct{}{}
	}
	// A scope with no explicit operations admits read-only only.
	if len(out) == 0 {
		out[RiskRead] = struct{}{}
	}
	return out, nil
}

func validatePercent(spec ScopeSpec) error {
	if spec.Percent < 0 || spec.Percent > 100 {
		return mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "percent out of range")
	}
	if spec.Percent > 0 && spec.Percent < 100 && spec.BucketSalt == "" {
		// A stable percentage bucket REQUIRES a bound salt; without it the membership
		// could not be reproduced deterministically across restarts/nodes.
		return mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.scope", "percentage bucket requires a bound salt")
	}
	return nil
}

// Capability returns the scope's capability.
func (s Scope) Capability() Capability { return s.capability }

// Revision returns the scope revision.
func (s Scope) Revision() uint64 { return s.revision }

// Hash returns the deterministic content hash of the normalized scope.
func (s Scope) Hash() string { return s.hash }

// HighRisk reports whether this scope is permitted to include write/destructive.
func (s Scope) HighRisk() bool { return s.highRisk }

// SelectorSchema returns the selector-schema version the scope was built under.
func (s Scope) SelectorSchema() int { return s.schema }

// hasInclusion reports whether ANY inclusion dimension is non-empty.
func (s Scope) hasInclusion() bool {
	return !s.tenants.empty() || !s.servers.empty() || !s.fingerprints.empty() || !s.tools.empty() ||
		!s.principals.empty() || !s.agents.empty() || !s.clients.empty() || !s.groups.empty() || !s.environments.empty()
}

// Enumerable reports whether the scope resolves to a frozen, inspectable subject
// set (has concrete inclusion selectors). A pure-percentage scope over an
// unbounded keyspace is NOT enumerable — Canary requires an enumerable scope, so a
// "1% of everything" scope cannot enter Canary.
func (s Scope) Enumerable() bool { return s.built && s.hasInclusion() }

// MatchesNothing reports whether the scope can never match any subject (the safe
// default: no inclusion dimensions and no percentage gate).
func (s Scope) MatchesNothing() bool {
	return !s.built || (!s.hasInclusion() && s.percent == 0)
}

// Contains reports whether subject is inside the scope. It is deterministic and
// performs no I/O or clock read. The evaluation order is: capability isolation →
// exclusions (which only narrow) → inclusion dimensions (AND across non-empty
// dimensions, OR within a dimension) → operation-class admission → percentage
// bucket. An empty scope contains nothing.
func (s Scope) Contains(subj Subject) bool {
	if !s.built || s.capability != subj.Capability {
		return false
	}
	if s.MatchesNothing() {
		return false
	}
	// Exclusions only narrow.
	if s.exTenants.has(subj.Tenant) || s.exServers.has(subj.ServerID) || s.exPrincipals.has(subj.PrincipalID) {
		return false
	}
	if !s.exTools.empty() && s.exTools.has(ToolSel{Server: subj.ServerID, Name: subj.ToolName, Fingerprint: subj.ToolFingerprint}) {
		return false
	}
	// Operation-class admission (fail closed on unknown).
	if !subj.Operation.Valid() {
		return false
	}
	if _, ok := s.operations[subj.Operation]; !ok {
		return false
	}
	// Inclusion dimensions: every non-empty dimension must contain the subject.
	if !s.matchDimensions(subj) {
		return false
	}
	// Percentage bucket (deterministic, stable across restarts).
	return s.inBucket(subj)
}

func (s Scope) matchDimensions(subj Subject) bool {
	// Each inclusion dimension is satisfied when its set is empty (matches anything)
	// or contains the subject's value. Evaluated as a flat table so the cyclomatic
	// footprint stays low as dimensions are added.
	checks := []bool{
		dimOK(s.tenants, subj.Tenant),
		dimOK(s.servers, subj.ServerID),
		dimOK(s.fingerprints, subj.ToolFingerprint),
		s.tools.empty() || s.tools.has(ToolSel{Server: subj.ServerID, Name: subj.ToolName, Fingerprint: subj.ToolFingerprint}),
		dimOK(s.principals, subj.PrincipalID),
		dimOK(s.agents, subj.AgentID),
		dimOK(s.clients, subj.ClientID),
		dimOK(s.environments, subj.Environment),
		s.groups.empty() || s.matchGroup(subj),
	}
	for _, ok := range checks {
		if !ok {
			return false
		}
	}
	return true
}

// AdmitsToolForEvaluation reports whether this scope TARGETS the given tool for a
// Gateway tools/call evaluation, INDEPENDENT of the calling identity. It checks the
// capability, the server and tool selectors, the server/tool exclusions, and that the
// write risk class (the class every tools/call is classified as) is admitted — but NOT
// the request-identity dimensions (principal/agent/client/tenant/environment/group),
// which are supplied per request, not by the catalog. A tool that is Usable AND targeted
// by the scope is one the scope can actually evaluate (rather than fail closed under the
// quarantine hard-override); Contains stays the per-request membership authority.
//
// It is the scope half of the "does this Shadow scope have any evaluable tool" preflight
// gate (Codex P1, PR #1234): a scope that admits only the read class, excludes the tool's
// server, or does not target the tool returns false.
func (s Scope) AdmitsToolForEvaluation(serverID, toolName, fingerprint string) bool {
	if !s.built || s.MatchesNothing() {
		return false
	}
	// An identity inclusion dimension whose every included value is also excluded admits NO
	// request (Contains rejects all), so a Usable tool on an in-scope server is still
	// unreachable — the scope validates as enumerable but evaluates nothing. Reject such a
	// self-contradicting scope here (Codex P2, PR #1234). Only tenant and principal carry both
	// an inclusion and an exclusion set; the identity dimensions without an exclusion set
	// (agent/client/group/environment) can never be self-emptied.
	if fullyExcluded(s.tenants, s.exTenants) || fullyExcluded(s.principals, s.exPrincipals) {
		return false
	}
	// No production Subject carries an Environment — executor.subjectFor never copies
	// in.Input.Server.Environment, so Subject.Environment is always "". A non-empty
	// environments inclusion therefore makes Contains reject EVERY request (dimOK on a
	// non-empty set with an empty value fails), so the scope validates as enumerable but
	// shadows nothing. Fail closed rather than open a zero-evaluation evidence window
	// (Codex P2, PR #1234). Populating Subject.Environment would be a runtime-matching
	// change and is deferred with the approval slice.
	if !s.environments.empty() {
		return false
	}
	// A percentage sub-sample over a FINITE bucket-key inclusion set can be unsatisfiable:
	// a matching request must satisfy BOTH the bucket-key dimension's inclusion set AND the
	// percentage bucket, so if every included bucket key hashes OUTSIDE the bucket, Contains
	// rejects every request even though a Usable tool is targeted (Codex P2, PR #1234).
	if !s.bucketHasSurvivingKey() {
		return false
	}
	if s.exServers.has(serverID) {
		return false
	}
	sel := ToolSel{Server: serverID, Name: toolName, Fingerprint: fingerprint}
	if !s.exTools.empty() && s.exTools.has(sel) {
		return false
	}
	// tools/call is the write risk class; the scope must admit it (a read-only scope
	// targets no tools/call at all).
	if _, ok := s.operations[RiskWrite]; !ok {
		return false
	}
	if !dimOK(s.servers, serverID) {
		return false
	}
	// The fingerprint dimension is a real inclusion selector (a scope may pin exact tool
	// fingerprints); a Usable tool whose fingerprint the scope does not admit is NOT targeted,
	// so it must not satisfy the usable-tool gate for a scope that Contains would never admit
	// (Codex P1, PR #1234).
	if !dimOK(s.fingerprints, fingerprint) {
		return false
	}
	return s.tools.empty() || s.tools.has(sel)
}

// dimOK reports whether a single string-selector inclusion dimension admits val:
// an empty set matches anything; otherwise val must be present.
func dimOK(set stringSet, val string) bool { return set.empty() || set.has(val) }

// fullyExcluded reports whether a non-empty inclusion set is entirely covered by its
// exclusion set — i.e. every included value is also excluded, so the dimension admits no
// value at all. An empty inclusion set (matches anything) is never fully excluded.
func fullyExcluded(incl, excl stringSet) bool {
	if incl.empty() {
		return false
	}
	for v := range incl {
		if !excl.has(v) {
			return false
		}
	}
	return true
}

func (s Scope) matchGroup(subj Subject) bool {
	for _, g := range subj.Groups {
		if s.groups.has(g) {
			return true
		}
	}
	return false
}

// inBucket applies the stable percentage gate. Percent==0 ⇒ dimension-only (no
// gate). Percent==100 ⇒ always in. Otherwise a stable keyed hash decides.
func (s Scope) inBucket(subj Subject) bool {
	if s.percent <= 0 {
		return true
	}
	if s.percent >= 100 {
		return true
	}
	return StableBucket(s.bucketSalt, s.bucketKeyValue(subj)) < uint32(s.percent)
}

func (s Scope) bucketKeyValue(subj Subject) string {
	switch s.bucketKey {
	case BucketByTenant:
		return subj.Tenant
	case BucketByAgent:
		return subj.AgentID
	case BucketByClient:
		return subj.ClientID
	default:
		return subj.PrincipalID
	}
}

// bucketKeyInclusionSet returns the inclusion set on the dimension the percentage bucket
// keys on. A matching request's bucket key is drawn from exactly this dimension, so when
// the set is finite it enumerates every key that can ever be bucketed.
func (s Scope) bucketKeyInclusionSet() stringSet {
	switch s.bucketKey {
	case BucketByTenant:
		return s.tenants
	case BucketByAgent:
		return s.agents
	case BucketByClient:
		return s.clients
	default:
		return s.principals
	}
}

// bucketKeyExclusionSet returns the exclusion set on the bucket-key dimension, or nil when
// that dimension carries none. Only tenant and principal have an exclusion set; a bucket
// keyed by agent or client has no exclusion dimension, so no key is ever excluded there.
func (s Scope) bucketKeyExclusionSet() stringSet {
	switch s.bucketKey {
	case BucketByTenant:
		return s.exTenants
	case BucketByAgent, BucketByClient:
		return nil
	default: // BucketByPrincipal
		return s.exPrincipals
	}
}

// bucketHasSurvivingKey reports whether the percentage bucket can admit at least one
// request GIVEN the scope's inclusion set on the bucket-key dimension. When
// 0 < percent < 100 the bucket keys on a stable subject attribute (principal/tenant/
// agent/client), and a matching request must ALSO satisfy that dimension's inclusion set
// (dimOK) AND its exclusion set, so a FINITE inclusion set enumerates every possible bucket
// key. If every NON-EXCLUDED one hashes outside the bucket, no request can pass and the
// scope shadows nothing. An EMPTY (unbounded) bucket-key set can always produce a surviving
// key, so it is treated as satisfiable (and a pure-percentage scope is not enumerable enough
// for Shadow anyway). Excluded keys are skipped: Contains rejects them before the bucket, so
// a key that is in-bucket but excluded is NOT a survivor (Codex P2, PR #1234).
func (s Scope) bucketHasSurvivingKey() bool {
	if s.percent <= 0 || s.percent >= 100 {
		return true // no sub-sampling gate: every keyed request is in-bucket
	}
	keys := s.bucketKeyInclusionSet()
	if keys.empty() {
		return true // unbounded keyspace ⇒ a surviving key exists for any percent ≥ 1
	}
	excl := s.bucketKeyExclusionSet()
	for k := range keys {
		if excl.has(k) {
			continue // Contains rejects an excluded key before the bucket — never a survivor
		}
		// StableBucket returns [0,100); widening it to int is always safe (avoids an
		// int→uint32 narrowing on s.percent that the lint gate flags). Same boundary as
		// inBucket.
		if int(StableBucket(s.bucketSalt, k)) < s.percent {
			return true
		}
	}
	return false
}

// StableBucket maps (salt, key) deterministically into [0,100). It uses a
// domain-separated SHA-256 of the salt and key — never math/rand, process start
// time, or map iteration order — so the same subject falls in the same bucket
// across restarts and across every node. Changing the percentage does not move a
// subject relative to the bucket boundary; changing the salt (a new revision)
// re-buckets deterministically.
func StableBucket(salt, key string) uint32 {
	h := sha256.New()
	h.Write([]byte("culvert-mcp-rollout-bucket-v1"))
	h.Write([]byte{0})
	h.Write([]byte(salt))
	h.Write([]byte{0})
	h.Write([]byte(key))
	sum := h.Sum(nil)
	// The modulo bounds the value to [0,99], so it always fits uint32.
	return uint32(binary.BigEndian.Uint64(sum[:8]) % 100) // #nosec G115 -- value is modulo 100
}

// computeHash produces a deterministic content hash over the normalized scope
// (sorted, deduped selectors + percentage config + capability + schema). Slice
// order and map iteration order never affect it.
func (s Scope) computeHash() string {
	h := sha256.New()
	h.Write([]byte("culvert-mcp-rollout-scope-v1"))
	writeByte(h, byte(s.schema)) // #nosec G115 -- schema is a tiny constant version tag
	writeByte(h, byte(s.capability))
	writeUint64(h, s.revision)
	writeBool(h, s.highRisk)
	writeInt(h, s.percent)
	writeField(h, "salt", []string{s.bucketSalt})
	writeByte(h, byte(s.bucketKey))
	writeField(h, "tenants", sortedKeys(s.tenants))
	writeField(h, "servers", sortedKeys(s.servers))
	writeField(h, "fingerprints", sortedKeys(s.fingerprints))
	writeField(h, "principals", sortedKeys(s.principals))
	writeField(h, "agents", sortedKeys(s.agents))
	writeField(h, "clients", sortedKeys(s.clients))
	writeField(h, "groups", sortedKeys(s.groups))
	writeField(h, "environments", sortedKeys(s.environments))
	writeField(h, "extenants", sortedKeys(s.exTenants))
	writeField(h, "exservers", sortedKeys(s.exServers))
	writeField(h, "exprincipals", sortedKeys(s.exPrincipals))
	writeField(h, "tools", sortedTools(s.tools))
	writeField(h, "extools", sortedTools(s.exTools))
	writeField(h, "operations", sortedOps(s.operations))
	return hex.EncodeToString(h.Sum(nil))
}

func sortedKeys(set stringSet) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedTools(set toolSet) []string {
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t.Server+"\x1f"+t.Name+"\x1f"+t.Fingerprint)
	}
	sort.Strings(out)
	return out
}

func sortedOps(set map[RiskClass]struct{}) []string {
	out := make([]string, 0, len(set))
	for o := range set {
		out = append(out, o.String())
	}
	sort.Strings(out)
	return out
}

func writeField(h hash.Hash, label string, vals []string) {
	h.Write([]byte(label))
	h.Write([]byte{0x1e})
	writeInt(h, len(vals))
	for _, v := range vals {
		writeInt(h, len(v))
		h.Write([]byte(v))
	}
}

func writeInt(h hash.Hash, v int) {
	var b [8]byte
	// Deterministic length/count serialization for the content hash; v is a bounded
	// non-negative length, so the sign-preserving conversion is safe.
	binary.BigEndian.PutUint64(b[:], uint64(v)) // #nosec G115 -- bounded non-negative length
	h.Write(b[:])
}

func writeUint64(h hash.Hash, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	h.Write(b[:])
}

func writeByte(h hash.Hash, v byte) { h.Write([]byte{v}) }

func writeBool(h hash.Hash, v bool) {
	if v {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
}

// SupportsSelectorSchema reports whether a scope declaring schema version v is
// interpretable by this build. A higher schema is rejected whole (fail closed).
func SupportsSelectorSchema(v int) bool { return v >= 1 && v <= selectorSchema }
