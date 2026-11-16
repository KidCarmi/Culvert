package alerts

// eventname_validation_test.go — SEC-ALERTS-EVENTNAME-1.
//
// ValidateEventNames is the ingress half of the stored-XSS fix: an
// operator-role client could persist an event name carrying markup, which the
// admin UI then rendered into the webhook table for every viewer, operator and
// ADMIN who opened the Alerts panel. The render sink is escaped now; these
// tests pin the shape check so the value cannot reach the webhook file, the
// support bundle or any other consumer either.
//
// The negative cases are the payload shapes that matter at an HTML sink, not a
// generic "weird string" sweep: the tag/attribute breakouts, the quote that
// escapes an attribute, and the control bytes that break a log or wire line.

import (
	"strings"
	"testing"
)

// TestValidateEventNames_AcceptsCatalogShapes is the positive control: every
// name the catalog actually uses, plus the one retired alias, must pass. A
// validator that rejected any of these would silently unsubscribe a live
// webhook, which is the failure normalizeEventNames exists to prevent.
func TestValidateEventNames_AcceptsCatalogShapes(t *testing.T) {
	catalog := []string{
		"admin_ui_unavailable", "auth_verify_saturated", "cdr_unavailable",
		"cert_expiry", "cp_grpc_listener_down", "dns_failure",
		"identity_backend_unreachable", "idp_unreachable", "mcp_gateway_down",
		"panic_contained", "policy_block", "scan_clam_error", "scan_skipped",
		"scan_svc_down", "scan_svc_listener_down", "socks5_listener_down",
		"storage_write_failed", "syslog_feed_down", "threat_detected",
		"threat_feed_stale", "yara_degraded",
	}
	if err := ValidateEventNames(catalog); err != nil {
		t.Fatalf("the real event catalog must validate, got: %v", err)
	}
	// Each one alone, so a failure names the offender.
	for _, ev := range catalog {
		if err := ValidateEventNames([]string{ev}); err != nil {
			t.Errorf("catalog event %q rejected: %v", ev, err)
		}
	}
}

// TestValidateEventNames_AcceptsCatchAll — "*" is a real subscription shape
// (HasSubscriber and the dispatch walk both honour it) and is how an operator
// subscribes to events added later. Rejecting it would be a silent detection
// loss, so it is admitted as a WHOLE name — but only as the whole name.
func TestValidateEventNames_AcceptsCatchAll(t *testing.T) {
	if err := ValidateEventNames([]string{catchAllEvent}); err != nil {
		t.Fatalf("the %q catch-all must be accepted: %v", catchAllEvent, err)
	}
	if err := ValidateEventNames([]string{"policy_block", catchAllEvent}); err != nil {
		t.Fatalf("the catch-all alongside a named event must be accepted: %v", err)
	}
	// A real subscriber must still be found through it, so the shape the
	// validator admits is the shape dispatch honours.
	as := &Store{hooks: []Webhook{{Enabled: true, Events: []string{catchAllEvent}}}}
	if !as.HasSubscriber("panic_contained") {
		t.Error("the catch-all must still match an arbitrary event")
	}
	// The glob is not a character class: it may not hide inside a longer name.
	for _, bad := range []string{"*policy_block", "policy_block*", "poli*cy", "**"} {
		if err := ValidateEventNames([]string{bad}); err == nil {
			t.Errorf("%q must be rejected: the catch-all is only valid as the entire name", bad)
		}
	}
}

// TestValidateEventNames_EmptyAndNil — no subscription is a legitimate state
// (a webhook may be created disabled, or subscribed later).
func TestValidateEventNames_EmptyAndNil(t *testing.T) {
	if err := ValidateEventNames(nil); err != nil {
		t.Errorf("nil events must be accepted, got %v", err)
	}
	if err := ValidateEventNames([]string{}); err != nil {
		t.Errorf("empty events must be accepted, got %v", err)
	}
}

// TestValidateEventNames_RejectsInjectionPayloads is the negative control.
func TestValidateEventNames_RejectsInjectionPayloads(t *testing.T) {
	cases := map[string]string{
		"img onerror":        `<img src=x onerror=alert(1)>`,
		"script tag":         `<script>alert(1)</script>`,
		"svg onload":         `<svg/onload=alert(1)>`,
		"attribute breakout": `" onmouseover="alert(1)`,
		"single quote":       `' onmouseover='alert(1)`,
		"bare angle open":    `policy_block<`,
		"bare angle close":   `policy_block>`,
		"ampersand entity":   `policy_block&amp;`,
		"newline":            "policy_block\nthreat_detected",
		"carriage return":    "policy_block\rthreat_detected",
		"tab":                "policy_block\tthreat_detected",
		"nul byte":           "policy_block\x00",
		"escape byte":        "policy_block\x1b[31m",
		"space":              "policy block",
		"uppercase":          "Policy_Block",
		"hyphen":             "policy-block",
		"dot":                "policy.block",
		"colon":              "policy:block",
		"slash":              "policy/block",
		"backslash":          `policy\block`,
		"unicode separator":  "policy_block ",
		"empty string":       "",
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateEventNames([]string{payload}); err == nil {
				t.Fatalf("payload %q must be rejected", payload)
			}
		})
	}
}

// TestValidateEventNames_RejectsAnyBadMemberOfAGoodList — one poisoned entry
// must refuse the whole list, not be skipped while its siblings pass.
func TestValidateEventNames_RejectsAnyBadMemberOfAGoodList(t *testing.T) {
	events := []string{"policy_block", `<img src=x onerror=alert(1)>`, "threat_detected"}
	if err := ValidateEventNames(events); err == nil {
		t.Fatal("a list containing a markup payload must be rejected")
	}
}

// TestValidateEventNames_LengthBoundary pins both sides of maxEventNameLen, so
// the bound cannot drift to "no bound" unnoticed (CWE-770).
func TestValidateEventNames_LengthBoundary(t *testing.T) {
	atLimit := strings.Repeat("a", maxEventNameLen)
	if err := ValidateEventNames([]string{atLimit}); err != nil {
		t.Errorf("a name of exactly maxEventNameLen (%d) must be accepted, got %v", maxEventNameLen, err)
	}
	overLimit := strings.Repeat("a", maxEventNameLen+1)
	if err := ValidateEventNames([]string{overLimit}); err == nil {
		t.Errorf("a name of maxEventNameLen+1 (%d) must be rejected", maxEventNameLen+1)
	}
}

// TestValidateEventNames_ErrorNamesTheOffender — the 400 an operator gets has
// to say which name was refused, or a long list is undebuggable.
func TestValidateEventNames_ErrorNamesTheOffender(t *testing.T) {
	err := ValidateEventNames([]string{"policy_block", "BAD_NAME"})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "BAD_NAME") {
		t.Errorf("error must name the offending value, got %q", err.Error())
	}
}

// TestNormalizeEventNames_StillMigratesRetiredAlias — the validator must not
// have displaced the rename migration: both the alias and its replacement pass
// validation, and normalize still rewrites the alias.
func TestNormalizeEventNames_StillMigratesRetiredAlias(t *testing.T) {
	if err := ValidateEventNames([]string{"idp_unreachable"}); err != nil {
		t.Fatalf("the retired alias must still validate: %v", err)
	}
	got := normalizeEventNames([]string{"idp_unreachable"})
	if len(got) != 1 || got[0] != "identity_backend_unreachable" {
		t.Fatalf("alias must still migrate, got %v", got)
	}
}
