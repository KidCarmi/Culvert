package main

// Policy Tester authority fidelity.
//
// The tester takes a typed request authority and must answer for the host the
// proxy would actually enforce. net/http parses the authority before
// handleRequest runs, so "b%C3%BCcher.de" is enforced as the IDN it decodes to.
// Before this fix the tester matched the literal percent string and reported no
// match for a destination the data path blocks.
//
// The parity test below sends each authority over a real socket as plain HTTP
// and as CONNECT, asks the tester the same thing, and requires the same answer.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWireDestAuthority(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"example.com", "example.com", true},
		{"example.com:8443", "example.com:8443", true},
		{"Example.COM.", "Example.COM.", true}, // case and trailing dot are the matchers' business
		{"b%C3%BCcher.de", "bücher.de", true},
		{"b%c3%bccher.de:443", "bücher.de:443", true},
		{"xn--bcher-kva.de", "xn--bcher-kva.de", true},
		{"bücher.de", "bücher.de", true}, // typed U-label: accepted, see wireDestAuthority
		{"[2001:db8::7]", "[2001:db8::7]", true},
		{"[2001:db8::7]:443", "[2001:db8::7]:443", true},
		{"192.0.2.7:80", "192.0.2.7:80", true},
		{"b%25C3%25BCcher.de", "b%C3%BCcher.de", true}, // decoded once, to a literal "%": never twice
		{"example.com%2Fadmin", "", false},             // encoded delimiters are refused, not decoded
		{"example.com%3A80", "", false},
		{"exa%6Dple.com", "", false}, // an escaped ASCII letter is not valid in a host
		{"b%C3%BCcher.de%", "", false},
		{"b%ZZcher.de", "", false},
		{"example.com:http", "", false},
		{"2001:db8::7", "", false},
		{"user@example.com", "", false},
		{"user:pw@example.com", "", false},
		{"example.com/x", "", false},
		{"example.com?x", "", false},
		{"example.com#x", "", false},
		{"example.com ", "", false},
		{" example.com", "", false},
		{"exa\tmple.com", "", false},
		{"", "", false},
		{":443", ":443", true}, // an empty host is the handler's business, as on the data path
	}
	for _, c := range cases {
		got, ok := wireDestAuthority(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("wireDestAuthority(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// authorityOutcome is "rule:<name>", "no-match" or "refused".
func wireAuthorityOutcome(t *testing.T, proxyAddr, method, authority string) string {
	t.Helper()
	before := map[string]int64{}
	rules := policyStore.List()
	for i := range rules {
		before[rules[i].Name] = rules[i].HitCount
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if method == http.MethodConnect {
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	} else {
		fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority, authority)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	code := 0
	fmt.Sscanf(line, "HTTP/1.1 %d", &code)
	var hit []string
	rules = policyStore.List()
	for i := range rules {
		if rules[i].HitCount != before[rules[i].Name] {
			hit = append(hit, rules[i].Name)
		}
	}
	sort.Strings(hit)
	switch {
	case code == http.StatusForbidden && len(hit) == 1:
		return "rule:" + hit[0]
	case code == http.StatusForbidden && len(hit) == 0:
		return "no-match"
	case len(hit) == 0:
		return "refused"
	default:
		return fmt.Sprintf("unexpected status=%d rules=%v", code, hit)
	}
}

func testerAuthorityOutcome(t *testing.T, authority string) string {
	t.Helper()
	w := httptest.NewRecorder()
	apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": authority, "sourceIP": "127.0.0.1", "authSource": "unauth"}))
	if w.Code == http.StatusBadRequest {
		return "refused"
	}
	if w.Code != http.StatusOK {
		return fmt.Sprintf("unexpected status=%d", w.Code)
	}
	var m struct {
		Matched bool `json:"matched"`
		Rule    struct {
			Name string `json:"name"`
		} `json:"rule"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode tester response: %v", err)
	}
	if m.Matched {
		return "rule:" + m.Rule.Name
	}
	return "no-match"
}

// TestPolicyTester_AuthorityParityWithRealSockets: for every authority a client
// can put on the wire, the tester names the rule the data path enforces, and
// refuses what the data path refuses.
func TestPolicyTester_AuthorityParityWithRealSockets(t *testing.T) {
	proxyURL := startTestProxy(t) // restores rules and the default action on cleanup
	setDefaultPolicyAction("deny")
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "idn", DestFQDN: "xn--bcher-kva.de", Action: ActionBlockPage},
		{Priority: 2, Name: "plain", DestFQDN: "example.com", Action: ActionBlockPage},
		{Priority: 3, Name: "v6", DestFQDN: "2001:db8::7", Action: ActionBlockPage},
		{Priority: 4, Name: "v4", DestFQDN: "192.0.2.7", Action: ActionBlockPage},
	})
	cases := []struct{ authority, want string }{
		// The defect: an encoded IDN is enforced as its rule, in every spelling.
		{"b%C3%BCcher.de", "rule:idn"},
		{"b%c3%bccher.de:8443", "rule:idn"},
		{"sub.b%C3%BCcher.de:443", "rule:idn"},
		{"xn--bcher-kva.de", "rule:idn"},
		{"XN--BCHER-KVA.DE:443", "rule:idn"},
		// Not-vacuous controls: ordinary authorities are unaffected.
		{"example.com", "rule:plain"},
		{"example.com:8080", "rule:plain"},
		{"Example.COM.:443", "rule:plain"},
		{"other.example.org:443", "no-match"},
		// Decoded exactly once: "%25C3" is a literal "%C3", not the letter it would
		// become on a second pass, so this is NOT the IDN and matches nothing.
		{"b%25C3%25BCcher.de", "no-match"},
		{"[2001:db8::7]", "rule:v6"},
		{"[2001:DB8:0::7]:443", "rule:v6"},
		{"192.0.2.7:80", "rule:v4"},
		{"[::ffff:192.0.2.7]:443", "rule:v4"},
		// Refused by the request parser, so refused by the tester: no decoding of
		// delimiters, no double decoding, no malformed escapes.
		{"example.com%2Fadmin", "refused"},
		{"example.com%3A80", "refused"},
		{"exa%6Dple.com", "refused"},
		{"b%C3%BCcher.de%", "refused"},
		{"b%ZZcher.de", "refused"},
		{"example.com:http", "refused"},
		{"2001:db8::7", "refused"},
		{"user@example.com", "refused"},
	}
	for _, c := range cases {
		rl = newRateLimiter()
		got := map[string]string{
			"http":    wireAuthorityOutcome(t, proxyURL.Host, http.MethodGet, c.authority),
			"connect": wireAuthorityOutcome(t, proxyURL.Host, http.MethodConnect, c.authority),
			"tester":  testerAuthorityOutcome(t, c.authority),
		}
		for path, o := range got {
			if o != c.want {
				t.Errorf("%-26q %-7s = %s, want %s (all paths: %v)", c.authority, path, o, c.want, got)
			}
		}
	}
}

// TestPolicyTester_TypedUnicodeHostStillAnswers pins the one deliberate
// difference: a raw U-label cannot appear on the wire (a client sends the
// A-label), but an administrator types it, and the tester keeps answering.
func TestPolicyTester_TypedUnicodeHostStillAnswers(t *testing.T) {
	proxyURL := startTestProxy(t)
	setDefaultPolicyAction("deny")
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "idn", DestFQDN: "xn--bcher-kva.de", Action: ActionBlockPage}})
	if got := testerAuthorityOutcome(t, "bücher.de:443"); got != "rule:idn" {
		t.Errorf("tester on a typed U-label = %s, want rule:idn", got)
	}
	if got := wireAuthorityOutcome(t, proxyURL.Host, http.MethodConnect, "bücher.de:443"); got != "refused" {
		t.Errorf("wire on a raw U-label = %s, want refused (if this changes, the tester's exception needs revisiting)", got)
	}
}

// TestPolicyTester_SizeTiersMeasureTheDecodedHost: the raw pre-cap still runs
// first, and the canonical tier measures the decoded host.
func TestPolicyTester_SizeTiersMeasureTheDecodedHost(t *testing.T) {
	startTestProxy(t)
	raw := strings.Repeat("a", maxRawDestAuthorityBytes+1)
	if got := testerAuthorityOutcome(t, raw); got != "refused" {
		t.Errorf("raw-oversize authority = %s, want refused", got)
	}
	// Five 60-byte labels in front of an encoded IDN: well under the raw cap,
	// over the canonical bound once decoded and normalized.
	long := strings.Repeat(strings.Repeat("a", 60)+".", 5) + "b%C3%BCcher.de"
	if rawAuthorityOversize(long) {
		t.Fatalf("test input is raw-oversize (%d bytes); it must exercise the canonical tier", len(long))
	}
	if got := testerAuthorityOutcome(t, long); got != "refused" {
		t.Errorf("canonical-oversize encoded authority = %s, want refused", got)
	}
}
