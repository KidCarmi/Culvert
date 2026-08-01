package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Compile strictly parses and compiles a policy document into an immutable,
// capability-local Snapshot, or returns a typed *mcperr error. It is PURE (no
// I/O). It rejects: an unsupported schema version, a wrong/mixed capability, a
// non-DENY default action, a duplicate RuleID, a duplicate priority, a malformed
// action/reason/remediation, an invalid condition, an invalid obligation for the
// action, a Management rule using a non-Management-legal action, and any over-limit
// size. On success every rule is a compiled closure over private copies of its
// data (deeply immutable), and the snapshot carries a deterministic canonical hash.
func Compile(raw []byte, meta CreatedMeta, lim Limits) (*Snapshot, error) {
	rs, err := parseDocument(raw, lim)
	if err != nil {
		return nil, err
	}
	if rs.SchemaVersion != schemaVersionV1 {
		return nil, snapshotErr("unsupported policy schema version")
	}
	capNS, ok := parseCapability(rs.Capability)
	if !ok {
		return nil, snapshotErr("missing or invalid capability")
	}
	if rs.PolicyRevision == 0 {
		return nil, snapshotErr("policy revision must be positive")
	}
	// Default posture is always DENY: an empty or disabled-only snapshot can never
	// become allow-all.
	if da, ok := ParseAction(rs.DefaultAction); !ok || da != ActionDeny {
		return nil, snapshotErr("default_action must be DENY")
	}
	if len(rs.Rules) > lim.MaxRulesPerSnap() {
		return nil, snapshotErr("too many rules")
	}
	rules, err := compileRules(rs.Rules, capNS, lim)
	if err != nil {
		return nil, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].priority < rules[j].priority })
	snap := &Snapshot{
		schemaVersion: rs.SchemaVersion,
		capability:    capNS,
		revision:      Revision(rs.PolicyRevision),
		description:   rs.Description,
		rules:         rules,
		defaultAction: ActionDeny,
		lim:           lim,
		meta:          meta,
	}
	snap.hash = computeHash(snap)
	return snap, nil
}

// compileRules compiles + validates every rule and enforces uniqueness of RuleID
// and priority within the capability namespace.
func compileRules(rrs []rawRule, capNS Capability, lim Limits) ([]*Rule, error) {
	rules := make([]*Rule, 0, len(rrs))
	seenID := make(map[string]struct{}, len(rrs))
	seenPri := make(map[int]struct{}, len(rrs))
	for i := range rrs {
		r, err := compileRule(rrs[i], capNS, lim)
		if err != nil {
			return nil, err
		}
		if _, dup := seenID[string(r.id)]; dup {
			return nil, ruleErr("duplicate rule id")
		}
		if _, dup := seenPri[r.priority]; dup {
			return nil, ruleErr("duplicate rule priority in this namespace")
		}
		seenID[string(r.id)] = struct{}{}
		seenPri[r.priority] = struct{}{}
		rules = append(rules, r)
	}
	return rules, nil
}

func ruleErr(detail string) error {
	return mcperr.New(mcperr.ReasonPolicyRuleInvalid, "policy.compile", detail)
}

// compileRule validates + compiles one rule.
func compileRule(rr rawRule, capNS Capability, lim Limits) (*Rule, error) {
	action, reason, rem, err := compileRuleHeader(rr, capNS, lim)
	if err != nil {
		return nil, err
	}
	if len(rr.Conditions) > lim.MaxConditions() {
		return nil, ruleErr("too many conditions")
	}
	conds := make([]compiledCond, 0, len(rr.Conditions))
	for _, rc := range rr.Conditions {
		c, err := compileCondition(rc, lim)
		if err != nil {
			return nil, err
		}
		conds = append(conds, c)
	}
	obl := buildObligations(rr.Obligations)
	if len(obl.IDs()) > lim.MaxObligations() {
		return nil, ruleErr("too many obligations")
	}
	// allow_destructive is only meaningful on a bounded ALLOW-class action.
	if rr.AllowDestructive && action != ActionAllowOnce && action != ActionAllowForSession {
		return nil, ruleErr("allow_destructive requires a bounded action (ALLOW_ONCE or ALLOW_FOR_SESSION)")
	}
	if err := obl.validateFor(action, capNS, rr.AllowDestructive); err != nil {
		return nil, err
	}
	enabled := rr.Enabled == nil || *rr.Enabled
	return &Rule{
		id:               RuleID(rr.ID),
		priority:         rr.Priority,
		enabled:          enabled,
		conditions:       conds,
		action:           action,
		reason:           reason,
		remediation:      rem,
		obligations:      obl.clone(),
		owner:            rr.Owner,
		expiryUnix:       rr.ExpiryUnix,
		allowDestructive: rr.AllowDestructive,
		rawKey:           canonicalRuleKey(rr, action, reason, rem, obl),
	}, nil
}

// compileRuleHeader validates a rule's id/priority/action/reason/remediation and
// the Management-legal-action constraint, returning the parsed typed values.
func compileRuleHeader(rr rawRule, capNS Capability, lim Limits) (Action, ReasonCode, Remediation, error) {
	if rr.ID == "" || len(rr.ID) > lim.MaxStringBytes() {
		return ActionInvalid, "", "", ruleErr("missing or over-long rule id")
	}
	if rr.Priority <= 0 {
		return ActionInvalid, "", "", ruleErr("rule priority must be positive")
	}
	action, ok := ParseAction(rr.Action)
	if !ok {
		return ActionInvalid, "", "", ruleErr("malformed or unknown action")
	}
	// Management rules are limited to the V1-legal action set (ALLOW/DENY/
	// REQUIRE_APPROVAL); no ordinary Management rule may permit-once/for-session/
	// with-redaction/monitor/quarantine/confirm.
	if capNS == CapManagement && !managementLegalAction(action) {
		return ActionInvalid, "", "", ruleErr("action not legal for a Management rule (V1: ALLOW/DENY/REQUIRE_APPROVAL)")
	}
	reason := ReasonCode(rr.Reason)
	if !reason.Valid() {
		return ActionInvalid, "", "", ruleErr("malformed reason code")
	}
	rem := Remediation(rr.Remediation)
	if !rem.Valid() {
		return ActionInvalid, "", "", ruleErr("malformed or unknown remediation code")
	}
	return action, reason, rem, nil
}

// buildObligations translates the raw obligation shape into the typed Obligations.
func buildObligations(ro *rawObligations) Obligations {
	if ro == nil {
		return Obligations{}
	}
	o := Obligations{
		Logging:           parseLogging(ro.Logging),
		Observation:       parseObservation(ro.Observation),
		RateLimitProfile:  ro.RateLimitProfile,
		Destination:       parseDestination(ro.Destination),
		CredentialProfile: ro.CredentialProfile,
		OnceCall:          ro.OnceCall,
		Confirmation:      ro.Confirmation,
		Approval:          ro.Approval,
		TicketRequired:    ro.TicketRequired,
	}
	if ro.Session != nil {
		o.Session = &SessionGrant{
			SessionBound:   ro.Session.SessionBound,
			TTLSeconds:     ro.Session.TTLSeconds,
			MaxCalls:       ro.Session.MaxCalls,
			RevokeRequired: ro.Session.RevokeRequired,
		}
	}
	if ro.Redaction != nil {
		o.Redaction = &RedactionReq{
			ProfileRef:              ro.Redaction.ProfileRef,
			TransformedHashRequired: ro.Redaction.TransformedHashRequired,
		}
	}
	return o
}

// managementLegalAction reports whether a is legal for a Management rule in V1.
func managementLegalAction(a Action) bool {
	switch a {
	case ActionAllow, ActionDeny, ActionRequireApproval:
		return true
	default:
		return false
	}
}

// computeHash builds the deterministic, key-order-independent snapshot hash over
// the canonical form: schema version, capability, revision, default action, and
// each rule's canonical key in priority order.
func computeHash(s *Snapshot) string {
	h := sha256.New()
	seg := func(b string) {
		var n [8]byte
		putUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write([]byte(b))
	}
	seg("v" + strconv.Itoa(s.schemaVersion))
	seg("cap:" + s.capability.String())
	seg("rev:" + strconv.FormatUint(uint64(s.revision), 10))
	seg("default:" + s.defaultAction.String())
	for _, r := range s.rules {
		seg(r.rawKey)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

// canonicalRuleKey builds an order-independent serialization of a rule for hashing.
// Condition entries are sorted, and set values within a condition are sorted, so
// two documents that differ only in key/order produce the same key.
func canonicalRuleKey(rr rawRule, action Action, reason ReasonCode, rem Remediation, obl Obligations) string {
	var b strings.Builder
	b.WriteString("id=" + rr.ID)
	b.WriteString(";pri=" + strconv.Itoa(rr.Priority))
	enabled := rr.Enabled == nil || *rr.Enabled
	b.WriteString(";en=" + strconv.FormatBool(enabled))
	b.WriteString(";act=" + action.String())
	b.WriteString(";rsn=" + string(reason))
	b.WriteString(";rem=" + string(rem))
	b.WriteString(";exp=" + strconv.FormatInt(rr.ExpiryUnix, 10))
	b.WriteString(";dst=" + strconv.FormatBool(rr.AllowDestructive))
	b.WriteString(";obl=" + canonicalObligations(obl))
	conds := make([]string, 0, len(rr.Conditions))
	for _, c := range rr.Conditions {
		conds = append(conds, canonicalCondKey(c))
	}
	sort.Strings(conds)
	b.WriteString(";cnd=[" + strings.Join(conds, "|") + "]")
	return b.String()
}

// canonicalObligations serializes the FULL obligation payload (not just IDs) into a
// stable key so two rules whose grants differ only in a session TTL/max-calls/
// binding/revocation or a redaction attestation flag hash differently — the
// snapshot hash must distinguish materially different authorization constraints.
func canonicalObligations(o Obligations) string {
	var b strings.Builder
	b.WriteString("log=" + o.Logging.String())
	b.WriteString(";obs=" + o.Observation.String())
	b.WriteString(";rate=" + o.RateLimitProfile)
	b.WriteString(";dest=" + o.Destination.String())
	b.WriteString(";cred=" + o.CredentialProfile)
	b.WriteString(";once=" + strconv.FormatBool(o.OnceCall))
	b.WriteString(";conf=" + strconv.FormatBool(o.Confirmation))
	b.WriteString(";appr=" + strconv.FormatBool(o.Approval))
	b.WriteString(";tick=" + strconv.FormatBool(o.TicketRequired))
	if o.Session != nil {
		s := o.Session
		b.WriteString(";sess=" + strconv.FormatBool(s.SessionBound) + "/" +
			strconv.Itoa(s.TTLSeconds) + "/" + strconv.Itoa(s.MaxCalls) + "/" +
			strconv.FormatBool(s.RevokeRequired))
	}
	if o.Redaction != nil {
		b.WriteString(";red=" + o.Redaction.ProfileRef + "/" +
			strconv.FormatBool(o.Redaction.TransformedHashRequired))
	}
	return b.String()
}

func canonicalCondKey(c rawCondition) string {
	vals := sortedCopy(c.Values)
	return c.Field + "/" + c.Op + "/" + c.Value + "/" + strings.Join(vals, ",") + "/" + c.Start + "-" + c.End
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// parseCapability parses the capability label.
func parseCapability(s string) (Capability, bool) {
	switch s {
	case "gateway":
		return CapGateway, true
	case "management":
		return CapManagement, true
	default:
		return CapabilityUnset, false
	}
}

func parseLogging(s string) LoggingClass {
	switch s {
	case "standard":
		return LogStandard
	case "full":
		return LogFull
	case "audit":
		return LogAudit
	default:
		return LogUnset
	}
}

func parseObservation(s string) ObservationLevel {
	switch s {
	case "summary":
		return ObsSummary
	case "detailed":
		return ObsDetailed
	default:
		return ObsUnset
	}
}

func parseDestination(s string) Destination {
	switch s {
	case "none":
		return DestinationNone
	case "approved":
		return DestinationApproved
	case "internal":
		return DestinationInternal
	case "arbitrary":
		return DestinationArbitrary
	default:
		return DestinationUnknown
	}
}
