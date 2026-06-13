package main

import (
	"testing"
	"time"
)

// Phase 1 Slice 4 — pure Stage-1 auth-outcome matcher tests.
//
// resolveAuthOutcomeFrom now evaluates persisted auth/exempt rules and returns
// Exempt (with the matched rule) when an enabled, in-scope, in-schedule,
// non-expired auth rule matches; Default otherwise. Pure — no global state, no
// runtime wiring (proxy.go / socks5.go untouched).

// authRule builds a valid, enabled exempt rule scoped to 10.0.5.0/24 →
// updates.example.com, which callers mutate per test.
func authRule() PolicyRule {
	enabled := true
	return PolicyRule{
		Priority: 10,
		Name:     "exempt-printer",
		RuleType: ruleTypeAuth,
		Enabled:  &enabled,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}},
		},
		DestFQDN: "updates.example.com",
		Auth:     &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "legacy firmware"},
	}
}

func matchingCtx() RequestContext {
	return RequestContext{ClientIP: "10.0.5.50", Host: "updates.example.com", Protocol: "http", Method: "GET"}
}

func assertExempt(t *testing.T, d AuthDecision, wantRule string) {
	t.Helper()
	if d.Outcome != OutcomeExempt {
		t.Fatalf("outcome = %q, want Exempt", d.Outcome)
	}
	if d.Rule == nil || d.Rule.Name != wantRule {
		t.Fatalf("Exempt must carry rule %q, got %+v", wantRule, d.Rule)
	}
}

func assertDefault(t *testing.T, d AuthDecision) {
	t.Helper()
	if d.Outcome != OutcomeDefault {
		t.Fatalf("outcome = %q, want Default", d.Outcome)
	}
	if d.Rule != nil {
		t.Errorf("Default must carry no rule, got %+v", d.Rule)
	}
}

// ── Core match / no-match ────────────────────────────────────────────────────

func TestSlice4_MatchingExemptRule(t *testing.T) {
	d := resolveAuthOutcomeFrom([]PolicyRule{authRule()}, matchingCtx())
	assertExempt(t, d, "exempt-printer")
}

func TestSlice4_NoMatchReturnsDefault(t *testing.T) {
	// Host outside the rule's destination.
	d := resolveAuthOutcomeFrom([]PolicyRule{authRule()},
		RequestContext{ClientIP: "10.0.5.50", Host: "other.example.com", Protocol: "http"})
	assertDefault(t, d)
}

func TestSlice4_AccessRulesIgnored(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "allow-all", Action: ActionAllow}, // RuleType "" = access
		{Priority: 2, Name: "block", RuleType: ruleTypeAccess, DestFQDN: "updates.example.com", Action: ActionDrop},
	}
	assertDefault(t, resolveAuthOutcomeFrom(rules, matchingCtx()))
}

// ── Priority ordering ────────────────────────────────────────────────────────

func TestSlice4_PriorityOrdering(t *testing.T) {
	low := authRule()
	low.Name = "low-priority"
	low.Priority = 50
	high := authRule()
	high.Name = "high-priority"
	high.Priority = 5
	// Pass in low-first order; the lower Priority value (high) must win.
	d := resolveAuthOutcomeFrom([]PolicyRule{low, high}, matchingCtx())
	assertExempt(t, d, "high-priority")
}

// ── Enabled / expiry ─────────────────────────────────────────────────────────

func TestSlice4_DisabledRuleIgnored(t *testing.T) {
	r := authRule()
	disabled := false
	r.Enabled = &disabled
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()))
}

func TestSlice4_ExpiredRuleIgnored(t *testing.T) {
	r := authRule()
	r.Auth.ExpiresAt = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()))
}

func TestSlice4_FutureExpiryMatches(t *testing.T) {
	r := authRule()
	r.Auth.ExpiresAt = time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	assertExempt(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()), "exempt-printer")
}

func TestSlice4_MalformedExpiryFailsClosed(t *testing.T) {
	r := authRule()
	r.Auth.ExpiresAt = "not-a-timestamp"
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()))
}

// ── Subject CIDR hit / miss / malformed ──────────────────────────────────────

func TestSlice4_CIDRHit(t *testing.T) {
	d := resolveAuthOutcomeFrom([]PolicyRule{authRule()},
		RequestContext{ClientIP: "10.0.5.1", Host: "updates.example.com", Protocol: "http"})
	assertExempt(t, d, "exempt-printer")
}

func TestSlice4_CIDRMiss(t *testing.T) {
	d := resolveAuthOutcomeFrom([]PolicyRule{authRule()},
		RequestContext{ClientIP: "10.0.6.1", Host: "updates.example.com", Protocol: "http"})
	assertDefault(t, d)
}

func TestSlice4_NilSubjectFailsClosed(t *testing.T) {
	r := authRule()
	r.SubjectMatch = nil
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()))
}

func TestSlice4_UnknownSubjectPredicateFailsClosed(t *testing.T) {
	for _, typ := range []string{"tag", "directory_group", "identity", "device_id", ""} {
		r := authRule()
		r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: typ, Values: []string{"x"}}}}
		if d := resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()); d.Outcome != OutcomeDefault {
			t.Errorf("unknown predicate %q must fail closed, got %q", typ, d.Outcome)
		}
	}
}

func TestSlice4_BadClientIPFailsClosed(t *testing.T) {
	d := resolveAuthOutcomeFrom([]PolicyRule{authRule()},
		RequestContext{ClientIP: "not-an-ip", Host: "updates.example.com", Protocol: "http"})
	assertDefault(t, d)
}

func TestSlice4_MultiCIDRValuesOrMatch(t *testing.T) {
	r := authRule()
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
		{Type: subjectPredicateCIDR, Values: []string{"192.168.0.0/16", "10.0.5.0/24"}},
	}}
	assertExempt(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()), "exempt-printer")
}

// matchSubject is the unit-level seam; exercise hit/miss directly too.
func TestSlice4_MatchSubject(t *testing.T) {
	sm := &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}}
	if !matchSubject(sm, "10.0.5.7") {
		t.Error("expected CIDR hit")
	}
	if matchSubject(sm, "10.0.6.7") {
		t.Error("expected CIDR miss")
	}
	if matchSubject(nil, "10.0.5.7") {
		t.Error("nil subject must fail closed")
	}
	if matchSubject(&SubjectMatch{SchemaVersion: 0, All: sm.All}, "10.0.5.7") {
		t.Error("schemaVersion < 1 must fail closed")
	}
}

// ── Destination hit / miss + category group ──────────────────────────────────

func TestSlice4_DestinationFQDNMissReturnsDefault(t *testing.T) {
	r := authRule()
	r.DestFQDN = "vendor.example.net"
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()))
}

func TestSlice4_DestinationCategoryGroup(t *testing.T) {
	// Classify the host into a default category, then group that category so the
	// rule's destCategoryGroup matches via matchDest → globalCategoryGroups.
	const cat = string(CategorySocial)
	if err := catStore.AddHost(cat, "updates.example.com"); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	t.Cleanup(func() { _ = catStore.RemoveHost(cat, "updates.example.com") })
	if _, err := globalCategoryGroups.Add("vendor-cloud", []string{cat}); err != nil {
		t.Fatalf("add category group: %v", err)
	}
	t.Cleanup(func() { _ = globalCategoryGroups.Delete("vendor-cloud") })

	r := authRule()
	r.DestFQDN = ""
	r.DestCategoryGroup = "vendor-cloud"
	assertExempt(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()), "exempt-printer")

	// A host outside the group does not match.
	d := resolveAuthOutcomeFrom([]PolicyRule{r},
		RequestContext{ClientIP: "10.0.5.1", Host: "elsewhere.example.org", Protocol: "http"})
	assertDefault(t, d)
}

// ── Protocol / method hit / miss ─────────────────────────────────────────────

func TestSlice4_ProtocolMatch(t *testing.T) {
	r := authRule()
	r.Auth.Protocol = "http"
	assertExempt(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()), "exempt-printer")
}

func TestSlice4_ProtocolMiss(t *testing.T) {
	r := authRule()
	r.Auth.Protocol = "connect"
	d := resolveAuthOutcomeFrom([]PolicyRule{r},
		RequestContext{ClientIP: "10.0.5.1", Host: "updates.example.com", Protocol: "http", Method: "GET"})
	assertDefault(t, d)
}

func TestSlice4_EmptyProtocolMatchesAny(t *testing.T) {
	r := authRule() // Protocol unset
	d := resolveAuthOutcomeFrom([]PolicyRule{r},
		RequestContext{ClientIP: "10.0.5.1", Host: "updates.example.com", Protocol: "connect"})
	assertExempt(t, d, "exempt-printer")
}

func TestSlice4_MethodMatch(t *testing.T) {
	r := authRule()
	r.Auth.Method = "POST"
	d := resolveAuthOutcomeFrom([]PolicyRule{r},
		RequestContext{ClientIP: "10.0.5.1", Host: "updates.example.com", Protocol: "http", Method: "POST"})
	assertExempt(t, d, "exempt-printer")
}

func TestSlice4_MethodMiss(t *testing.T) {
	r := authRule()
	r.Auth.Method = "POST"
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx())) // ctx method GET
}

func TestSlice4_MethodIgnoredForConnect(t *testing.T) {
	r := authRule()
	r.Auth.Protocol = "connect"
	r.Auth.Method = "POST" // ignored on connect
	d := resolveAuthOutcomeFrom([]PolicyRule{r},
		RequestContext{ClientIP: "10.0.5.1", Host: "updates.example.com", Protocol: "connect", Method: ""})
	assertExempt(t, d, "exempt-printer")
}

// ── Schedule hit / miss ──────────────────────────────────────────────────────

func TestSlice4_ScheduleHitAndMiss(t *testing.T) {
	// In-schedule: window covers "now" in UTC.
	now := time.Now().UTC()
	today := now.Weekday().String()[:3]
	hit := authRule()
	hit.Schedule = &PolicySchedule{Days: []string{today}, Timezone: "UTC"}
	assertExempt(t, resolveAuthOutcomeFrom([]PolicyRule{hit}, matchingCtx()), "exempt-printer")

	// Out-of-schedule: a day that is not today.
	otherDay := now.Add(48 * time.Hour).Weekday().String()[:3]
	miss := authRule()
	miss.Schedule = &PolicySchedule{Days: []string{otherDay}, Timezone: "UTC"}
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{miss}, matchingCtx()))
}

// A malformed schedule timezone must fail closed (require auth), not silently
// fall back to UTC and grant Exempt. Bulk persistence paths (Load/ReplaceAll)
// skip validatePolicyRule's timezone check, so the matcher must enforce it.
func TestSlice4_MalformedScheduleTimezoneFailsClosed(t *testing.T) {
	r := authRule()
	r.Schedule = &PolicySchedule{Timezone: "Not/AZone"}
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()))

	// A valid timezone with an all-day (no day/time restriction) schedule matches.
	r2 := authRule()
	r2.Schedule = &PolicySchedule{Timezone: "UTC"}
	assertExempt(t, resolveAuthOutcomeFrom([]PolicyRule{r2}, matchingCtx()), "exempt-printer")
}

// ── broadExemption ───────────────────────────────────────────────────────────

func TestSlice4_BroadExemptionMatchesAnyDestination(t *testing.T) {
	r := authRule()
	r.DestFQDN = ""
	r.Auth.BroadExemption = true
	// Any destination from the matched source is exempt.
	for _, host := range []string{"a.example.com", "totally-different.net"} {
		d := resolveAuthOutcomeFrom([]PolicyRule{r},
			RequestContext{ClientIP: "10.0.5.9", Host: host, Protocol: "http"})
		assertExempt(t, d, "exempt-printer")
	}
	// Still scoped by source: outside the CIDR it does not match.
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r},
		RequestContext{ClientIP: "172.16.0.1", Host: "a.example.com", Protocol: "http"}))
}

func TestSlice4_NoDestinationWithoutBroadFailsClosed(t *testing.T) {
	r := authRule()
	r.DestFQDN = ""
	r.Auth.BroadExemption = false // malformed (validation would reject); matcher fails closed
	assertDefault(t, resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()))
}

// ── Reserved outcomes remain inert ───────────────────────────────────────────

// Phase 2 Slice 2 made CredentialRequired resolve; only SSORequired stays
// reserved/inert in the pure resolver.
func TestSlice4_ReservedOutcomesInert(t *testing.T) {
	for _, oc := range []AuthOutcome{OutcomeSSORequired} {
		r := authRule()
		r.Auth.Outcome = oc
		if d := resolveAuthOutcomeFrom([]PolicyRule{r}, matchingCtx()); d.Outcome != OutcomeDefault {
			t.Errorf("reserved outcome %q must be inert (Default), got %q", oc, d.Outcome)
		}
	}
}

// ── First matching exempt wins over a later access rule ──────────────────────

func TestSlice4_ExemptResolvedIndependentOfAccess(t *testing.T) {
	// An access rule at higher precedence does not suppress a Stage-1 match —
	// the two stages are independent; Stage-1 only considers auth rules.
	rules := []PolicyRule{
		{Priority: 1, Name: "access-allow", Action: ActionAllow},
		authRule(),
	}
	assertExempt(t, resolveAuthOutcomeFrom(rules, matchingCtx()), "exempt-printer")
}
