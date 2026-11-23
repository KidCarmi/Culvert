//go:build policy_conformance

package policyref

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestIndependence: the reference model may import the standard library only. Importing
// the product (or a product helper such as internal/hostutil) would let a production bug
// leak into the oracle and agree with itself.
func TestIndependence(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources: %v", err)
	}
	for _, f := range files {
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				t.Errorf("%s imports %q: the reference model must use the standard library only", f, p)
			}
		}
		src, err := os.ReadFile(f) //nolint:gosec // own package sources
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(src), "//go:build policy_conformance") {
			t.Errorf("%s must start with the policy_conformance build tag (shadow only)", f)
		}
	}
}

func off() *bool { f := false; return &f }

var env = Env{
	Categories: map[string][]string{"News": {"news.test"}, "Shopping": {"shop.test"}},
	Groups:     map[string][]string{"g1": {"News"}},
}

// Worked examples, one or more per clause. Each is the clause read literally.
func TestSpecExamples(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		req   Request
		want  Outcome
	}{
		{"R1 lower priority wins", []Rule{{Name: "b", Priority: 2}, {Name: "a", Priority: 1}}, Request{Host: "x.test"},
			Outcome{Rule: "a", Specified: true}},
		{"R1 first MATCHING rule", []Rule{{Name: "a", Priority: 1, DestFQDN: "other.test"}, {Name: "b", Priority: 2}},
			Request{Host: "x.test"}, Outcome{Rule: "b", Specified: true}},
		{"R2 matching tie unspecified", []Rule{{Name: "a", Priority: 1}, {Name: "b", Priority: 1}}, Request{Host: "x"},
			Outcome{Why: "R2: tied priority between matching rules a and b"}},
		{"R2 tie with a non-matching rule is fine", []Rule{{Name: "a", Priority: 1}, {Name: "b", Priority: 1, DestFQDN: "no.test"}},
			Request{Host: "x"}, Outcome{Rule: "a", Specified: true}},
		{"R3 disabled skipped", []Rule{{Name: "a", Priority: 1, Enabled: off()}, {Name: "b", Priority: 2}}, Request{Host: "x"},
			Outcome{Rule: "b", Specified: true}},
		{"R4 auth rule inert", []Rule{{Name: "a", Priority: 1, Type: "auth"}}, Request{Host: "x"}, Outcome{Specified: true}},
		{"R6 mapped client in CIDR", []Rule{{Name: "a", SourceIP: "10.0.0.0/8"}}, Request{ClientIP: "::ffff:10.1.2.3", Host: "x"},
			Outcome{Rule: "a", Specified: true}},
		{"R6 zoned client matches no source rule", []Rule{{Name: "a", SourceIP: "fe80::/10"}}, Request{ClientIP: "fe80::1%eth0", Host: "x"},
			Outcome{Specified: true}},
		{"R6 malformed rule source unspecified", []Rule{{Name: "a", SourceIP: "10.0.0.300"}}, Request{ClientIP: "10.0.0.1", Host: "x"},
			Outcome{Why: "R6: rule SourceIP is neither a CIDR nor an address (a)"}},
		{"R7 identity case-insensitive", []Rule{{Name: "a", SourceIdentity: "Alice"}}, Request{Identity: "alice", Host: "x"},
			Outcome{Rule: "a", Specified: true}},
		{"R8 group trimmed, any member", []Rule{{Name: "a", SourceGroup: " Eng "}}, Request{Groups: []string{"x", "eng"}, Host: "x"},
			Outcome{Rule: "a", Specified: true}},
		{"R9 bare aliases scheme", []Rule{{Name: "a", AuthSource: "okta"}}, Request{AuthSource: "oidc:okta", Host: "x"},
			Outcome{Rule: "a", Specified: true}},
		{"R9 different schemes never alias", []Rule{{Name: "a", AuthSource: "oidc:okta"}}, Request{AuthSource: "saml:okta", Host: "x"},
			Outcome{Specified: true}},
		{"R11 bare domain includes subdomains", []Rule{{Name: "a", DestFQDN: "Example.COM."}}, Request{Host: "www.example.com"},
			Outcome{Rule: "a", Specified: true}},
		{"R11 label boundary", []Rule{{Name: "a", DestFQDN: "example.com"}}, Request{Host: "notexample.com"}, Outcome{Specified: true}},
		{"R11 *.d includes apex", []Rule{{Name: "a", DestFQDN: "*.example.com"}}, Request{Host: "example.com"},
			Outcome{Rule: "a", Specified: true}},
		{"R10 IPv6 literal spellings", []Rule{{Name: "a", DestFQDN: "2001:DB8::1"}}, Request{Host: "[2001:db8:0::1]"},
			Outcome{Rule: "a", Specified: true}},
		{"R12 sentinel is unset", []Rule{{Name: "a", DestCategory: "Any"}}, Request{Host: "x"}, Outcome{Rule: "a", Specified: true}},
		{"R12 sentinel casing unspecified", []Rule{{Name: "a", DestCategory: "any"}}, Request{Host: "x"},
			Outcome{Why: "R12: category sentinel spelled any (a)"}},
		{"R12 membership by parent", []Rule{{Name: "a", DestCategory: "news"}}, Request{Host: "a.news.test"},
			Outcome{Rule: "a", Specified: true}},
		{"R13 group membership", []Rule{{Name: "a", DestGroupID: "g1"}}, Request{Host: "news.test"}, Outcome{Rule: "a", Specified: true}},
		{"R13 unknown group fails closed", []Rule{{Name: "a", DestGroupID: "nope"}}, Request{Host: "news.test"}, Outcome{Specified: true}},
		{"R5 conditions are ANDed", []Rule{{Name: "a", DestFQDN: "news.test", SourceIdentity: "bob"}}, Request{Host: "news.test", Identity: "eve"},
			Outcome{Specified: true}},
	}
	for _, c := range cases {
		if got := Evaluate(c.rules, env, c.req); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestStartupDefault(t *testing.T) {
	cases := []struct {
		explicit string
		n        int
		want     string
		spec     bool
	}{
		{"", 0, "allow", true}, {"", 1, "deny", true}, {"allow", 3, "allow", true}, {"deny", 0, "deny", true},
		{"Allow", 0, "", false}, {"block", 1, "", false},
	}
	for _, c := range cases {
		if got, spec := StartupDefault(c.explicit, c.n); got != c.want || spec != c.spec {
			t.Errorf("StartupDefault(%q,%d) = %q,%v want %q,%v", c.explicit, c.n, got, spec, c.want, c.spec)
		}
	}
}
