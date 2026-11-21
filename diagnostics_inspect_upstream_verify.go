package main

// diagnostics_inspect_upstream_verify.go — operator-contract row for SSL
// inspection rules that do not verify the origin server's certificate.
//
// On an inspected tunnel the client only ever sees the leaf Culvert forges, so
// Culvert's own check of the origin certificate is the only one made. A rule
// can turn that check off inline (tlsSkipVerify) or through a bound decryption
// profile whose certificate verification is "skip". Users still get a valid
// padlock, and the only runtime trace is a per-connection log line. The rule
// list badges the inline toggle only: a rule that skips through its profile
// looks verified there, and a rule whose profile is "strict" keeps the badge
// although it verifies.
//
// Report-only: asks the same resolveInspectSkipVerify the tunnel path uses, so
// the row cannot disagree with what a session would do. Contributes nothing
// when every enabled inspect rule verifies. The row is viewer-visible, so it
// carries counts only — no rule or profile names.

import "fmt"

// checkInspectUpstreamVerify returns zero or one row counting enabled
// SSL-inspection rules whose effective origin certificate verification is off.
func checkInspectUpstreamVerify(rules []PolicyRule) []OperatorContractCheck {
	total, viaProfile := 0, 0
	for i := range rules {
		r := &rules[i]
		if !ruleIsEnabled(r) || r.SSLAction != SSLInspect {
			continue
		}
		if !resolveInspectSkipVerify(&PolicyMatch{Rule: r}, r.TLSSkipVerify) {
			continue
		}
		total++
		// Skipping without the inline toggle can only come from the profile.
		if !r.TLSSkipVerify {
			viaProfile++
		}
	}
	if total == 0 {
		return nil
	}
	msg := fmt.Sprintf("%d enabled SSL-inspection rule(s) do not verify the origin server's certificate — "+
		"traffic they inspect is forwarded to an origin with an untrusted, expired or wrong-host certificate, "+
		"and users still see a valid padlock", total)
	if viaProfile > 0 {
		msg += fmt.Sprintf("; %d of them skip verification through their decryption profile, "+
			"which the rule list's warning badge does not show", viaProfile)
	}
	return []OperatorContractCheck{{
		Code:    "ssl_inspect_upstream_verify",
		Status:  diagWarn,
		Message: msg,
		OperatorAction: "Open Policy → Rules: rules with the \"TLS certificate verification disabled\" badge skip it inline. " +
			"Then open Decryption Profiles: a profile showing \"cert: skip\" turns verification off for every rule bound to it, " +
			"and a profile set to \"strict\" overrides a rule's inline toggle. Origins are verified against this appliance's " +
			"system trust store, so an origin signed by a private CA needs that CA installed there before verification can be " +
			"re-enabled; otherwise keep the exception scoped to the narrowest destination that needs it.",
	}}
}
