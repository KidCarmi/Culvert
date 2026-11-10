package main

// categorygroup_membership_test.go — regression proofs for the category-GROUP
// fail-open: categoryGroupMatchesHostScratch decided "is this host in ANY
// category of the group?" from the ONE single-winner category the host
// classifies as (hostCatScratch.fusion), not from the host's category
// membership. Since F3b-4 (603e3401e) the armed effective-view path checks
// admin-created categories FIRST, so an admin category covering a host by
// PARENT suffix (admin "webmail" = example.test) wins the classification over
// the built-in "News" EXACT entry for news.example.test — and a Block rule on the
// group {social-media, News} stopped matching news.example.test while a
// single-category destCategory=News rule (membership since finding F-1) still
// blocked it. Owner decision: a group rule matches when the host belongs to ANY
// category in the group — the same membership semantics single-category rules
// use. The admin→SaaS→community classification ORDER is unchanged and still
// pinned below (lookupHostCategory), because logging and the URL-lookup API
// consume it.
//
// Every test builds a private taxonomy (catStore), group store and effective
// view, restoring all three on cleanup, so nothing leaks into other tests.

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

const (
	mbrHostNews    = "news.example.test" // built-in News EXACT + admin webmail by PARENT suffix
	mbrHostWebmail = "example.test"      // admin webmail only
	mbrHostSocial  = "social.example.test"
	mbrHostNone    = "uncategorized.example.invalid"

	mbrGroupID = "grpmbr000001"
)

// installMembershipFixture installs the lab-shaped taxonomy: built-in "News"
// and "Social Media" (served by the effective view when it is armed) and an
// admin-created "lab-webmail" whose PARENT-suffix pattern covers the News host.
// It also installs the group {Social Media, News} and returns a restore-safe
// setup; armed selects whether the signed-feed effective view is installed.
func installMembershipFixture(t *testing.T, armed bool) {
	t.Helper()
	origCat, origGroups := catStore, globalCategoryGroups
	t.Cleanup(func() { catStore, globalCategoryGroups = origCat, origGroups })

	catStore = urlcat.New([]*urlcat.Entry{
		{Name: "News", Hosts: []string{mbrHostNews}, BuiltIn: true},
		{Name: "Social Media", Hosts: []string{mbrHostSocial}, BuiltIn: true},
		{Name: "lab-webmail", Hosts: []string{mbrHostWebmail}, BuiltIn: false},
	})
	if armed {
		swapSaaSView(t, embeddedBaselineView()) // built from the catStore above
	} else {
		swapSaaSView(t, nil)
	}

	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.ReplaceAll([]CategoryGroup{
		// Display-cased, as an operator types them; the store lowers them.
		{ID: mbrGroupID, Name: "non-productive", Categories: []string{"Social Media", "News"}},
	})
}

func mbrGroupMatches(rule *PolicyRule, host string) bool {
	sc := newHostCatScratch(host)
	return categoryGroupMatchesHostScratch(rule, &sc)
}

func mbrRules() (byID, byName *PolicyRule) {
	return &PolicyRule{Name: "by-id", DestCategoryGroup: "non-productive", DestCategoryGroupID: mbrGroupID},
		&PolicyRule{Name: "by-name", DestCategoryGroup: "non-productive"}
}

// THE REGRESSION. With the effective view armed, the admin PARENT-suffix
// category wins the classification, but the host is still a MEMBER of News, so
// the group rule must match — on the ID leg production takes and the name leg
// an un-migrated rule takes.
func TestCategoryGroupMembership_ArmedAdminSuffixDoesNotHideBuiltInMember(t *testing.T) {
	installMembershipFixture(t, true)

	// Precondition: this IS the shape that used to fail open. The single-winner
	// classification (unchanged — logging and the lookup API consume it) is the
	// admin category, while single-category membership says News.
	if cat, tier, _ := lookupHostCategory(mbrHostNews); cat != "lab-webmail" || tier != "admin" {
		t.Fatalf("precondition: lookupHostCategory(%q) = (%q,%q), want (lab-webmail,admin) — "+
			"the F3b-4 admin-first classification order must be unchanged", mbrHostNews, cat, tier)
	}
	if !matchCategory("News", mbrHostNews) {
		t.Fatalf("precondition: single-category membership must report %q in News", mbrHostNews)
	}

	byID, byName := mbrRules()
	for _, r := range []*PolicyRule{byID, byName} {
		if !mbrGroupMatches(r, mbrHostNews) {
			t.Errorf("rule %s: group {Social Media, News} does not match %q although the host is a "+
				"member of News — category-group rules fail open when an admin category covers the "+
				"host by parent suffix", r.Name, mbrHostNews)
		}
		// A host that is a member of a group category AND only of it still matches.
		if !mbrGroupMatches(r, mbrHostSocial) {
			t.Errorf("rule %s: group must match its Social Media member %q", r.Name, mbrHostSocial)
		}
	}
}

// End to end through the access scan: the Block rule on the group applies, i.e.
// the request is not handed to the lower-priority Allow rule.
func TestCategoryGroupMembership_ArmedAccessEvaluateBlocks(t *testing.T) {
	installMembershipFixture(t, true)

	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 10, Name: "block-nonproductive", DestCategoryGroup: "non-productive",
			DestCategoryGroupID: mbrGroupID, Action: ActionBlockPage},
		{Priority: 20, Name: "allow-all", DestFQDN: "*", Action: ActionAllow},
	})
	cases := []struct {
		host, wantRule string
	}{
		{mbrHostNews, "block-nonproductive"}, // the fail-open
		{mbrHostSocial, "block-nonproductive"},
		{mbrHostWebmail, "allow-all"}, // webmail only — not in the group
		{mbrHostNone, "allow-all"},    // uncategorized — never in a group
	}
	for _, c := range cases {
		m := ps.Evaluate("203.0.113.7", "", "unauth", c.host, nil)
		if m == nil || m.Rule == nil {
			t.Errorf("Evaluate(%q) = no match, want %q", c.host, c.wantRule)
			continue
		}
		if m.Rule.Name != c.wantRule {
			t.Errorf("Evaluate(%q) matched %q, want %q", c.host, m.Rule.Name, c.wantRule)
		}
	}
}

// CDR and Stage-1 auth evaluate the SAME destination matcher (matchDestNorm) and
// must agree with the access scan on the regression shape.
func TestCategoryGroupMembership_ArmedCDRAndAuthAgree(t *testing.T) {
	installMembershipFixture(t, true)

	cdr, cleanup := newTestCDRPolicyStore(t, CDRPolicyRule{
		Priority: 10, Name: "cdr-nonproductive", DestCategoryGroup: "non-productive",
		ProfileName: "strict", Mode: "ENFORCE",
	})
	defer cleanup()
	defaults := CDRConfig{DefaultProfile: "default", DefaultMode: "ENFORCE"}
	if d := cdr.Evaluate("203.0.113.7", "", "unauth", mbrHostNews, nil, defaults); d.Source != "rule" {
		t.Errorf("CDR: group rule did not match member %q (source=%q)", mbrHostNews, d.Source)
	}
	if d := cdr.Evaluate("203.0.113.7", "", "unauth", mbrHostWebmail, nil, defaults); d.Source != "default" {
		t.Errorf("CDR: group rule matched non-member %q (source=%q)", mbrHostWebmail, d.Source)
	}

	rule := authRule()
	rule.DestFQDN = ""
	rule.DestCategoryGroup = "non-productive"
	rule.DestCategoryGroupID = mbrGroupID
	ctx := matchingCtx()
	ctx.Host = mbrHostNews
	if d := resolveAuthOutcomeFrom([]PolicyRule{rule}, ctx); d.Outcome != OutcomeExempt {
		t.Errorf("auth: group rule did not match member %q (outcome=%q)", mbrHostNews, d.Outcome)
	}
	ctx.Host = mbrHostWebmail
	if d := resolveAuthOutcomeFrom([]PolicyRule{rule}, ctx); d.Outcome != OutcomeDefault {
		t.Errorf("auth: group rule matched non-member %q (outcome=%q)", mbrHostWebmail, d.Outcome)
	}
}

// CONTROL: membership must not widen to hosts in NEITHER group category — a
// host that is only in the admin category, and a host no tier classifies.
func TestCategoryGroupMembership_ControlNonMembersDoNotMatch(t *testing.T) {
	for _, armed := range []bool{true, false} {
		installMembershipFixture(t, armed)
		byID, byName := mbrRules()
		for _, r := range []*PolicyRule{byID, byName} {
			for _, host := range []string{mbrHostWebmail, "mail." + mbrHostWebmail, mbrHostNone, ""} {
				if mbrGroupMatches(r, host) {
					t.Errorf("armed=%v rule %s: group {Social Media, News} matched %q, which is in "+
						"neither category", armed, r.Name, host)
				}
			}
		}
		// Unknown group stays fail-closed even for a member host.
		if mbrGroupMatches(&PolicyRule{DestCategoryGroup: "no-such-group"}, mbrHostNews) {
			t.Errorf("armed=%v: an unknown group must never match", armed)
		}
		// A resolved ID is authoritative: a stale name pointing at a different
		// (here nonexistent) group must not change the answer.
		if !mbrGroupMatches(&PolicyRule{DestCategoryGroup: "stale-name", DestCategoryGroupID: mbrGroupID}, mbrHostNews) {
			t.Errorf("armed=%v: ID-resolved group must answer from its own membership", armed)
		}
	}
}

// The unarmed (pre-F3b-4) path classified news.example.test as News — the
// built-in entry precedes the admin one — so the group matched there before the
// fix and must still match after it.
func TestCategoryGroupMembership_UnarmedPathUnchanged(t *testing.T) {
	installMembershipFixture(t, false)

	if cat, tier, _ := lookupHostCategory(mbrHostNews); cat != "News" || tier != "admin" {
		t.Fatalf("precondition: unarmed lookupHostCategory(%q) = (%q,%q), want (News,admin)", mbrHostNews, cat, tier)
	}
	byID, byName := mbrRules()
	for _, r := range []*PolicyRule{byID, byName} {
		for _, host := range []string{mbrHostNews, "www." + mbrHostNews, mbrHostSocial} {
			if !mbrGroupMatches(r, host) {
				t.Errorf("unarmed rule %s: group must match member %q", r.Name, host)
			}
		}
	}
}

// DIFFERENTIAL: the group matcher is exactly "OR over the group's categories of
// the single-category membership matcher" — for every probe host, on both paths,
// across groups that do and do not hold the classification winner. This is the
// contract the owner decision states, asserted against the primitive itself so
// the two can never drift apart again.
func TestCategoryGroupMembership_EqualsOrOfSingleCategoryMembership(t *testing.T) {
	groups := [][]string{
		{"Social Media", "News"},
		{"lab-webmail"},
		{"News"},
		{"lab-webmail", "Social Media"},
		{"Streaming"}, // no host in the fixture belongs to it
	}
	hosts := []string{mbrHostNews, "a.b." + mbrHostNews, mbrHostWebmail, "mail." + mbrHostWebmail,
		mbrHostSocial, mbrHostNone, ""}

	for _, armed := range []bool{true, false} {
		installMembershipFixture(t, armed)
		defs := make([]CategoryGroup, 0, len(groups))
		for i, cats := range groups {
			defs = append(defs, CategoryGroup{ID: "grpdiff0000" + string(rune('a'+i)), Name: "diff-" + string(rune('a'+i)), Categories: cats})
		}
		globalCategoryGroups.ReplaceAll(defs)

		for i, cats := range groups {
			rule := &PolicyRule{DestCategoryGroup: defs[i].Name, DestCategoryGroupID: defs[i].ID}
			for _, host := range hosts {
				want := false
				for _, c := range cats {
					if matchCategory(URLCategory(c), host) {
						want = true
					}
				}
				if got := mbrGroupMatches(rule, host); got != want {
					t.Errorf("armed=%v group %v host %q: group matcher=%v, OR of matchCategory=%v",
						armed, cats, host, got, want)
				}
			}
		}
	}
}

// The uncategorized short-circuit in categoryGroupMatchesHostScratch is only
// sound under membership if "no tier classifies the host" implies "the host is a
// member of no category". Pinned over the SHIPPED taxonomy (every built-in host,
// a subdomain of it, a look-alike, and non-members) on both paths: whenever the
// classification is empty, no category the taxonomy knows may claim the host.
func TestCategoryGroupMembership_UncategorizedGuardIsSound(t *testing.T) {
	cats := map[string]struct{}{}
	hosts := map[string]struct{}{"not-in-any-category.example": {}, "example.invalid": {}, "localhost": {}, "": {}}
	for h, cs := range catStore.BuiltInHostMemberships() {
		hosts[h] = struct{}{}
		hosts["deep.sub."+h] = struct{}{}
		hosts["x"+h] = struct{}{}
		for _, c := range cs {
			cats[c] = struct{}{}
		}
	}
	for _, e := range catStore.All() {
		cats[e.Name] = struct{}{}
	}
	uncategorized := 0
	for _, armed := range []bool{false, true} {
		if armed {
			swapSaaSView(t, embeddedBaselineView())
		} else {
			swapSaaSView(t, nil)
		}
		for host := range hosts {
			if cat, _, _ := lookupHostCategory(host); cat != "" {
				continue
			}
			uncategorized++
			for c := range cats {
				if matchCategory(URLCategory(c), host) {
					t.Errorf("armed=%v: %q classifies as uncategorized but is a member of %q — "+
						"the uncategorized guard would drop a group match", armed, host, c)
				}
			}
		}
	}
	if uncategorized == 0 {
		t.Fatal("no uncategorized probe host — the soundness check is vacuous")
	}
}
