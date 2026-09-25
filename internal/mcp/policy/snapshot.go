package policy

// CreatedMeta is caller-supplied, safe creation metadata for a snapshot. It holds
// no secrets and is carried verbatim (bounded by the document string limits).
type CreatedMeta struct {
	Author    string
	CreatedAt string // caller-supplied RFC3339 string (never a clock read here)
	Note      string
}

// Snapshot is an immutable, capability-local, compiled policy snapshot. It is the
// unit of evaluation and publication. It is DEEPLY IMMUTABLE: rules are compiled
// closures over private copies of all data, so a caller cannot mutate the document
// (or any slice/map it passed) after construction and change evaluation. Its
// default posture is always DENY.
type Snapshot struct {
	schemaVersion int
	capability    Capability
	revision      Revision
	hash          string // deterministic, key-order-independent canonical hash
	description   string
	rules         []*Rule // sorted by ascending priority; unique priorities
	defaultAction Action  // always ActionDeny
	lim           Limits
	meta          CreatedMeta
}

// Capability returns the snapshot's capability namespace.
func (s *Snapshot) Capability() Capability { return s.capability }

// Revision returns the snapshot's policy revision.
func (s *Snapshot) Revision() Revision { return s.revision }

// Hash returns the deterministic canonical snapshot hash (hex). Two logically
// identical documents with different object-key ordering hash the same.
func (s *Snapshot) Hash() string { return s.hash }

// SchemaVersion returns the document schema version.
func (s *Snapshot) SchemaVersion() int { return s.schemaVersion }

// RuleCount returns the number of compiled rules.
func (s *Snapshot) RuleCount() int { return len(s.rules) }

// DefaultAction returns the default (no-match) action — always ActionDeny.
func (s *Snapshot) DefaultAction() Action { return s.defaultAction }

// Description returns the snapshot's safe description metadata.
func (s *Snapshot) Description() string { return s.description }

// Limits returns the snapshot's compiled limits.
func (s *Snapshot) Limits() Limits { return s.lim }

// RuleIDs returns the compiled rule ids in priority order (a fresh copy).
func (s *Snapshot) RuleIDs() []RuleID {
	out := make([]RuleID, len(s.rules))
	for i, r := range s.rules {
		out[i] = r.id
	}
	return out
}

// Rule returns the compiled rule with this id, or nil when the snapshot has none.
//
// It exists for the CANARY ACTIVATION PERMIT (blocker #14), which must know which policy
// FIELDS the winning rule actually consulted. A preflight evaluates one constructed tuple;
// that verdict generalises to every request the activation scope admits only if the winner
// was decided entirely by fields the activation BINDS. Without this accessor the caller
// could observe that a rule won but not what it read, and would have to treat its own tuple
// as representative — which is a sample, not a proof.
//
// It is READ-ONLY and leaks nothing: *Rule's fields are unexported and its accessors expose
// only the closed, developer-authored vocabulary (id, priority, action, reason, obligations,
// condition ids). No rule VALUE — the operator-supplied right-hand side of a condition — is
// reachable through it.
func (s *Snapshot) Rule(id RuleID) *Rule {
	for _, r := range s.rules {
		if r.id == id {
			return r
		}
	}
	return nil
}
