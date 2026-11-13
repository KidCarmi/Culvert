package main

// A Stage-1 auth rule's subject is a typed CIDR predicate whose values are
// documented as "a valid IP or CIDR" (validateCIDROrIP). The CIDR form is
// parsed, so it decides on the ADDRESS. The bare-IP form is compared as a
// STRING against the peer address the proxy derived with
// net.SplitHostPort(r.RemoteAddr) — the canonical form Go prints — so it
// decides on the SPELLING.
//
// validateCIDROrIP accepts every spelling net.ParseIP accepts, so the auth API
// takes "2001:DB8::10", "2001:0db8:0000:0000:0000:0000:0000:0010" and
// "::ffff:10.0.0.5" and persists them, and the Stage-1 matcher then never
// matches the client they name. For OutcomeCredentialRequired / OutcomeSSORequired
// that is the FAIL-OPEN direction: resolveAuthOutcomeFrom falls through to the
// global default, so the client is never challenged.
//
// This is the same defect PR #1869/#1874 fixed for an access rule's SourceIP
// (see policy_source_literal_test.go); the auth path kept the string compare.

import (
	"testing"
)

// authCRRuleForSubject builds an enabled, non-expiring CredentialRequired auth
// rule scoped to one subject value and one destination.
func authCRRuleForSubject(subject string) PolicyRule {
	return PolicyRule{
		Name:     "challenge-" + subject,
		RuleType: ruleTypeAuth,
		Priority: 10,
		DestFQDN: "example.com",
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{subject}}},
		},
		Auth: &AuthRuleSpec{
			Outcome: OutcomeCredentialRequired,
			Owner:   "secops",
			Reason:  "regression test",
		},
	}
}

func authCtxFor(clientIP string) RequestContext {
	return RequestContext{
		ClientIP: clientIP,
		Host:     "example.com",
		Protocol: "connect",
		Method:   "CONNECT",
	}
}

// TestAuthSubjectBareIP_DecidesOnAddressNotSpelling is the regression oracle:
// every subject spelling the auth API ACCEPTS for a given address must produce
// the same Stage-1 outcome as the canonical spelling of that address.
func TestAuthSubjectBareIP_DecidesOnAddressNotSpelling(t *testing.T) {
	cases := []struct {
		name     string
		subject  string
		clientIP string
	}{
		{"ipv6 upper case", "2001:DB8::10", "2001:db8::10"},
		{"ipv6 fully expanded", "2001:0db8:0000:0000:0000:0000:0000:0010", "2001:db8::10"},
		{"ipv6 unexpanded zero groups", "2001:db8:0:0:0:0:0:10", "2001:db8::10"},
		{"ipv4-in-ipv6 lower", "::ffff:10.0.0.5", "10.0.0.5"},
		{"ipv4-in-ipv6 upper", "::FFFF:10.0.0.5", "10.0.0.5"},
		{"canonical ipv6 (control)", "2001:db8::10", "2001:db8::10"},
		{"canonical ipv4 (control)", "10.0.0.5", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := authCRRuleForSubject(tc.subject)

			// The write path accepts this value: the operator gets no error.
			if err := validateSubjectMatch(rule.SubjectMatch); err != nil {
				t.Fatalf("validateSubjectMatch(%q) rejected the value on write: %v "+
					"(if the API refuses it, the matcher need not match it)", tc.subject, err)
			}

			d := resolveAuthOutcomeFrom([]PolicyRule{rule}, authCtxFor(tc.clientIP))
			if d.Outcome != OutcomeCredentialRequired {
				t.Errorf("subject %q vs client %q: outcome %q, want %q — "+
					"the rule was accepted on write and never matches, so the client "+
					"falls through to the global default and is NEVER CHALLENGED (fail-open)",
					tc.subject, tc.clientIP, d.Outcome, OutcomeCredentialRequired)
			}
		})
	}
}

// TestAuthSubjectBareIP_DoesNotWidenBeyondTheAddress is the negative control:
// the address-based compare must not match a DIFFERENT address, and a zoned
// literal (which netip rejects as a prefix) must not start matching.
func TestAuthSubjectBareIP_DoesNotWidenBeyondTheAddress(t *testing.T) {
	cases := []struct {
		name     string
		subject  string
		clientIP string
	}{
		{"neighbour address", "2001:DB8::10", "2001:db8::11"},
		{"different family", "::ffff:10.0.0.5", "10.0.0.6"},
		{"ipv4 vs unrelated ipv6", "10.0.0.5", "2001:db8::10"},
		{"zoned literal stays inert", "fe80::1%eth0", "fe80::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := authCRRuleForSubject(tc.subject)
			d := resolveAuthOutcomeFrom([]PolicyRule{rule}, authCtxFor(tc.clientIP))
			if d.Outcome != OutcomeDefault {
				t.Errorf("subject %q vs client %q: outcome %q, want %q — the subject "+
					"must not match an address it does not name",
					tc.subject, tc.clientIP, d.Outcome, OutcomeDefault)
			}
		})
	}
}

// TestAuthSubjectBareIP_ExemptDirectionIsNamed pins the OTHER direction of the
// same fix, so it is a recorded contract and not an accident.
//
// Matching on the address rather than the spelling widens what a rule matches.
// For CredentialRequired/SSORequired that is strictly MORE restrictive (the
// client is now challenged where it previously was not). For OutcomeExempt it
// is MORE PERMISSIVE: an Exempt rule written in a non-canonical spelling used
// to be silently inert, so the client still authenticated; it now waives
// authentication for the address the operator named.
//
// That widening restores the operator's declared intent and is the same
// direction PR #1869 already accepted for an access Allow rule, but it is a
// posture CHANGE for any deployment holding such a rule, so it is asserted
// here rather than left to be discovered. Blast radius stays bounded by the
// two guards Exempt already carries: authRuleHasDestination (or an explicit
// BroadExemption acknowledgement) and the Exempt kill switch.
func TestAuthSubjectBareIP_ExemptDirectionIsNamed(t *testing.T) {
	rule := authCRRuleForSubject("2001:DB8::10")
	rule.Auth.Outcome = OutcomeExempt

	d := resolveAuthOutcomeFrom([]PolicyRule{rule}, authCtxFor("2001:db8::10"))
	if d.Outcome != OutcomeExempt {
		t.Fatalf("outcome %q, want %q — an Exempt rule naming this address now "+
			"matches it (operator intent restored); if this ever stops holding, the "+
			"address-based subject compare has been narrowed, which also reopens the "+
			"CredentialRequired fail-open", d.Outcome, OutcomeExempt)
	}

	// The kill switch must still suppress it: the widening must not create an
	// exemption the operator cannot revoke.
	t.Run("kill switch still suppresses the widened exempt", func(t *testing.T) {
		if authExemptKillSwitchEngaged() {
			t.Skip("kill switch already engaged in this environment")
		}
		t.Cleanup(func() { setAuthExemptDisabled(false) })
		setAuthExemptDisabled(true)
		d := resolveAuthOutcomeFrom([]PolicyRule{rule}, authCtxFor("2001:db8::10"))
		if d.Outcome != OutcomeDefault {
			t.Errorf("outcome %q, want %q — the Exempt kill switch must suppress a "+
				"subject matched by address just as it suppresses one matched by string",
				d.Outcome, OutcomeDefault)
		}
	})
}

// TestAuthSubjectBareIP_MixedPredicateReachesTheAddressCompare covers the
// shape where precomputeSubjectNets actually allocates a nets slice.
//
// It stores a parsed *net.IPNet only for values containing "/", and assigns the
// slice at all only if at least one value parsed — so a predicate holding BOTH
// a CIDR and a bare IP has a non-nil nets whose bare-IP slot is nil, and
// cidrPredicateMatches indexes into it before falling through to
// matchIPOrCIDRAddr. A predicate of bare IPs only leaves nets nil and skips the
// index entirely. Both routes must reach the address compare.
func TestAuthSubjectBareIP_MixedPredicateReachesTheAddressCompare(t *testing.T) {
	cases := []struct {
		name     string
		values   []string
		clientIP string
		want     AuthOutcome
	}{
		{"cidr first, non-canonical bare IP second", []string{"10.0.0.0/8", "2001:DB8::10"}, "2001:db8::10", OutcomeCredentialRequired},
		{"non-canonical bare IP first, cidr second", []string{"2001:DB8::10", "10.0.0.0/8"}, "2001:db8::10", OutcomeCredentialRequired},
		{"the cidr arm still matches on its own", []string{"10.0.0.0/8", "2001:DB8::10"}, "10.1.2.3", OutcomeCredentialRequired},
		{"neither value names the client", []string{"10.0.0.0/8", "2001:DB8::10"}, "192.0.2.7", OutcomeDefault},
		{"bare IPs only (nets stays nil)", []string{"::ffff:10.0.0.5", "2001:DB8::10"}, "10.0.0.5", OutcomeCredentialRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := authCRRuleForSubject("mixed")
			rule.SubjectMatch.All[0].Values = tc.values
			if err := validateSubjectMatch(rule.SubjectMatch); err != nil {
				t.Fatalf("validateSubjectMatch(%v) rejected the values: %v", tc.values, err)
			}
			// Run the real mutator so the precompute is the one production uses.
			precomputeSubjectNets(rule.SubjectMatch)

			d := resolveAuthOutcomeFrom([]PolicyRule{rule}, authCtxFor(tc.clientIP))
			if d.Outcome != tc.want {
				t.Errorf("values %v vs client %q: outcome %q, want %q",
					tc.values, tc.clientIP, d.Outcome, tc.want)
			}
		})
	}
}
