//go:build uie2e

package main

// ui_ruleid_traffic_e2e_test.go — live-browser coverage for the traffic-feed
// rule deep-link carrying the matched rule's ULID (P0 ruleId slice). Verifies
// in real Chromium that rowHTML renders the rule cell as a trafficGotoRule link
// whose data-arg2 round-trips the ruleId verbatim (the escHtml→dataset
// convention) so navigation can resolve the exact rule by ID, not by name.

import (
	"net/http/httptest"
	"testing"
)

func TestUIE2E_TrafficRuleLinkCarriesRuleID(t *testing.T) {
	const adminUser, pass = "admin-rid-e2e", "Rid-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, "viewer-rid-e2e", pass)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// Render a synthetic feed row through the real rowHTML() into the live-log
	// tbody, then read back the rule link's dataset. A ULID is alphanumeric so
	// the interesting property is that escHtml round-trips it into data-arg2
	// unchanged (the jn/JSON.stringify pattern would wrap it in quotes).
	const wantID = "01HZY8QeRULEIDexample0001"
	const wantName = "block-ads & trackers" // ampersand exercises attribute escaping
	res, err := page.Evaluate(`([name, id]) => {
		const tb = document.getElementById('live-log');
		tb.innerHTML = rowHTML({time:'12:00:00', ip:'1.2.3.4', host:'ex.com',
			status:'OK', ruleMatched:name, ruleId:id, actionTaken:'allow'});
		const a = tb.querySelector('a[data-click="trafficGotoRule"]');
		if (!a) return {ok:false, reason:'no rule link rendered'};
		return {ok:true, arg:a.dataset.arg, arg2:a.dataset.arg2, text:a.textContent};
	}`, []string{wantName, wantID})
	if err != nil {
		t.Fatalf("evaluate rowHTML: %v", err)
	}
	m, _ := res.(map[string]any)
	if m["ok"] != true {
		t.Fatalf("render failed: %v", m["reason"])
	}
	if m["arg"] != wantName {
		t.Errorf("data-arg (rule name) = %q, want %q", m["arg"], wantName)
	}
	if m["arg2"] != wantID {
		t.Errorf("data-arg2 (ruleId) = %q, want the ULID %q round-tripped verbatim", m["arg2"], wantID)
	}
	if m["text"] != wantName {
		t.Errorf("link text = %q, want the rule name %q", m["text"], wantName)
	}

	// And trafficGotoRule must prefer the ID: with two rules sharing a name but
	// different IDs, resolving by the entry's ruleId picks the exact one.
	pick, err := page.Evaluate(`(id) => {
		window.api = async () => ({rules: [
			{name:'dup', id:'AAA', priority:1, ruleType:'access'},
			{name:'dup', id:'BBB', priority:2, ruleType:'access'},
		]});
		let picked = null;
		window.polAnchorRule = (r) => { picked = r.id; };
		return trafficGotoRule('dup', id).then(() => picked);
	}`, "BBB")
	if err != nil {
		t.Fatalf("evaluate trafficGotoRule: %v", err)
	}
	if pick != "BBB" {
		t.Errorf("trafficGotoRule resolved to id %v, want BBB (the entry's ruleId, not the first same-named rule)", pick)
	}
}
