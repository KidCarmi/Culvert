package threatfeed

// Differential coverage for CheckRequestURL — the parsed-URL form of CheckURL
// (see its contract in threatfeed.go).
//
// The change it guards is a COST change, not a policy change: the two entry
// points must return the same verdict for every URL, and the fast path exists
// only to reach that verdict without serialising a *url.URL so this package can
// parse it straight back. So the tests here are written as differentials
// against the string path rather than as expectations about particular URLs —
// the string path is the definition, and anything the fast path answers
// differently is a defect regardless of which answer looks more reasonable.
//
// TestCheckRequestURL_FastPathIsActuallyTaken is the CONTROL. Every other test
// in this file passes trivially if normaliseParsedURL always reports
// handled=false, which is also the cheapest way to "fix" any failure here — and
// it would silently delete the entire optimisation while leaving a green suite.

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// diffFeed is a feed seeded so that both the URL table and the domain table can
// produce hits, plus one allowlisted domain, so a differential covers every
// branch of the shared lookup body rather than just the miss path.
func diffFeed(tb testing.TB) *Feed {
	tb.Helper()
	tf := New()
	tf.mu.Lock()
	tf.enabled = true
	tf.urls = map[string]entry{
		"http://evil.example.com/malware":        {Source: "urlhaus"},
		"https://evil.example.com/a/b":           {Source: "openphish"},
		"http://mixed.example.com/pathwithcaps":  {Source: "urlhaus"},
		"http://port.example.com/p":              {Source: "urlhaus"},
		"http://user.example.com/x":              {Source: "urlhaus"},
		"http://[::1]/x":                         {Source: "urlhaus"},
		"http://escaped.example.com/a%3fb":       {Source: "urlhaus"},
		"http://trailing.example.com":            {Source: "urlhaus"},
		"http://xn--bcher-kva.example.com/books": {Source: "urlhaus"},
	}
	tf.domains = map[string]entry{
		"evil.example.com":     {Source: "urlhaus"},
		"masked.example.com":   {Source: "openphish"},
		"port.example.com":     {Source: "urlhaus"},
		"user.example.com":     {Source: "urlhaus"},
		"nonascii.example.com": {Source: "urlhaus"},
	}
	tf.domainAllowlist = map[string]bool{"masked.example.com": true}
	tf.publishLocked()
	tf.mu.Unlock()
	return tf
}

// diffURLs are the shapes worth naming: each one either exercises a gate
// condition in normaliseParsedURL or is a case where the String()+Parse() round
// trip is NOT obviously the identity. Randomised input (FuzzCheckRequestURL)
// covers the rest; these are here so a regression names itself.
var diffURLs = []string{
	// ── ordinary traffic (the shapes the fast path exists for) ──────────────
	"http://evil.example.com/malware",
	"https://evil.example.com/a/b",
	"http://clean.example.com/some/path?q=1&r=2",
	"http://clean.example.com",
	"http://clean.example.com/",
	"http://trailing.example.com///",
	"https://files.example.com/downloads/report/q3-2026.pdf?token=abc#frag",

	// ── case folding: NormaliseURL lower-cases scheme, host and path ────────
	"http://MIXED.example.com/PathWithCaps",
	"HTTP://Mixed.Example.COM/PATHWITHCAPS",
	"http://EVIL.EXAMPLE.COM/MALWARE",

	// ── authority variants ──────────────────────────────────────────────────
	"http://port.example.com:8080/p",
	"http://user:pass@user.example.com/x",
	"http://user@user.example.com/x",
	"http://host_with_underscore.example.com/x",
	"http://trailing-dot.example.com./x",
	"http://port.example.com:/p",
	// Authorities that survive the gate but canonicalise to an EMPTY host.
	// NormaliseURL answers ("", "") for these; the fast path must too, rather
	// than minting a hostless key like "http:///x". Without them the
	// empty-host guard's removal survives mutation — the verdict is unchanged
	// (a hostless key simply misses) and only the KEY differs, which is
	// exactly what the key-level half of assertAgrees exists to see.
	"http://:8080/x",
	"http://./x",
	"http://../x",

	// ── IP literals, incl. the private-IP exclusion ─────────────────────────
	"http://93.184.216.34/x",
	"http://10.0.0.1/x",
	"http://127.0.0.1/x",
	"http://192.168.1.1:3128/x",
	"http://[::1]/x",
	"http://[2001:db8::1]:443/x",
	"http://[not-an-ipv6/x",

	// ── paths that escape non-trivially through EscapedPath()+unescape ──────
	"http://escaped.example.com/a%3Fb",
	"http://escaped.example.com/a%23b",
	"http://escaped.example.com/a%20b",
	"http://escaped.example.com/a+b",
	"http://escaped.example.com/%2e%2e/x",
	"http://escaped.example.com/caf%C3%A9",

	// ── IDN / non-ASCII ─────────────────────────────────────────────────────
	"http://bücher.example.com/books",
	"http://xn--bcher-kva.example.com/books",
	"http://nonascii.example.com/ÜBER",

	// ── shapes the gate must push down the string path ──────────────────────
	"ftp://evil.example.com/malware",
	"mailto:someone@example.com",
	"//evil.example.com/malware",
	"/relative/only",
	"relative/only",
	"",
	"http://",
	"https://",
	"http:opaque",
	"evil.example.com/malware",
	"evil.example.com",
}

// assertAgrees is the differential proper, and it asserts at BOTH levels on
// purpose.
//
// The KEY level is the load-bearing one: it holds independently of what any
// feed contains, so it catches a fast path that derives the wrong lookup key
// even when that key happens to miss. The verdict level alone is far weaker —
// two different keys that are both absent from the feed produce the same
// (false, "") — and a first draft of these tests asserted only that. It passed
// with the authority gate's port-shape rule deleted, i.e. it could not fail for
// the exact defect the rule exists to prevent.
func assertAgrees(t *testing.T, tf *Feed, label string, u *url.URL) {
	t.Helper()
	raw := u.String()
	if norm, host, handled := normaliseParsedURL(u); handled {
		wantNorm, wantHost := NormaliseURL(raw)
		if norm != wantNorm || host != wantHost {
			t.Errorf("%s: keys diverge — normaliseParsedURL = (%q, %q); NormaliseURL(%q) = (%q, %q)",
				label, norm, host, raw, wantNorm, wantHost)
		}
	}
	gotHit, gotSrc := tf.CheckRequestURL(u)
	wantHit, wantSrc := tf.CheckURL(raw)
	if gotHit != wantHit || gotSrc != wantSrc {
		t.Errorf("%s: verdicts diverge — CheckRequestURL = (%v, %q); CheckURL(%q) = (%v, %q)",
			label, gotHit, gotSrc, raw, wantHit, wantSrc)
	}
}

// TestCheckRequestURL_MatchesCheckURL is the differential over the named
// shapes, at both the key and the verdict level.
func TestCheckRequestURL_MatchesCheckURL(t *testing.T) {
	tf := diffFeed(t)
	for _, raw := range diffURLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue // unparseable input never reaches CheckRequestURL
		}
		assertAgrees(t, tf, raw, u)
	}
}

// TestCheckRequestURL_AllowlistMaskingIsStillCounted pins that the fast path
// reaches the SAME lookup body, not a copy of it: a domain hit suppressed by
// the allowlist must still charge maskedHits, which is the operator's only
// signal that an exemption is overriding live intel.
func TestCheckRequestURL_AllowlistMaskingIsStillCounted(t *testing.T) {
	tf := diffFeed(t)
	before := tf.AllowlistMaskedTotal()
	u, _ := url.Parse("http://masked.example.com/anything")
	if hit, _ := tf.CheckRequestURL(u); hit {
		t.Fatal("allowlisted domain must not report a hit")
	}
	if got := tf.AllowlistMaskedTotal(); got != before+1 {
		t.Errorf("maskedHits = %d, want %d — the fast path is not sharing the lookup body", got, before+1)
	}
}

// TestCheckRequestURL_HandConstructedURLs covers the shapes url.Parse cannot
// produce and the differential above therefore cannot reach: a *url.URL whose
// fields a caller set directly. None is reachable from the request path (net/http
// parses r.URL), but CheckRequestURL takes a *url.URL from anyone, so the
// equivalence must hold for values no parser vouched for — the multi-colon
// authority in particular is the case a naive character scan of the host would
// get wrong in the direction that invents a lookup key.
func TestCheckRequestURL_HandConstructedURLs(t *testing.T) {
	tf := diffFeed(t)
	cases := []*url.URL{
		{Scheme: "http", Host: "a:b:c", Path: "/x"},           // parseHost rejects this
		{Scheme: "http", Host: ":8080", Path: "/x"},           // Hostname() is empty
		{Scheme: "http", Host: ".", Path: "/x"},               // canonicalises to empty
		{Scheme: "http", Host: "evil.example.com", Path: "x"}, // Path without a leading '/'
		{Scheme: "http", Host: "evil.example.com"},            // no path at all
		{Scheme: "HTTP", Host: "evil.example.com", Path: "/malware"},
		{Scheme: "http", Host: "evil.example.com", Opaque: "opaque"},
		{Scheme: "http", Host: "evil.example.com%2e", Path: "/x"},
		{Scheme: "http", Host: "evil.example.com ", Path: "/x"},
		{Scheme: "http", Host: "[::1]", Path: "/x"},
		{Scheme: "http", Path: "/x"}, // no authority
		{Scheme: "http", Host: "evil.example.com", Path: "/malware", RawQuery: "a=b", Fragment: "f"},
		{Scheme: "http", Host: "evil.example.com", Path: "/mal?ware"},
		{Scheme: "http", Host: "evil.example.com", Path: "/mal#ware"},
		{Scheme: "http", Host: "evil.example.com", Path: "/malware", User: url.UserPassword("u", "p")},
	}
	for _, u := range cases {
		assertAgrees(t, tf, fmt.Sprintf("%#v", *u), u)
	}
}

// TestCheckRequestURL_FastPathIsActuallyTaken is the CONTROL described at the
// top of this file. Without it, making normaliseParsedURL always return
// handled=false would pass every other test here while deleting the change.
func TestCheckRequestURL_FastPathIsActuallyTaken(t *testing.T) {
	ordinary := []string{
		"http://files.example.com/downloads/report.pdf?token=abc",
		"https://api.example.com/v1/users",
		"http://example.com",
		"http://93.184.216.34:8080/x",
	}
	for _, raw := range ordinary {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if _, _, handled := normaliseParsedURL(u); !handled {
			t.Errorf("normaliseParsedURL(%q) fell back to the string path — "+
				"the optimisation is not reached for ordinary traffic", raw)
		}
	}
}

// TestCheckRequestURL_DisabledAndNil pins the two guards the request path leans
// on: a disabled feed answers without touching the URL at all, and a nil URL is
// never a hit.
func TestCheckRequestURL_DisabledAndNil(t *testing.T) {
	off := New()
	u, _ := url.Parse("http://evil.example.com/malware")
	if hit, _ := off.CheckRequestURL(u); hit {
		t.Error("disabled feed reported a hit")
	}
	tf := diffFeed(t)
	if hit, src := tf.CheckRequestURL(nil); hit || src != "" {
		t.Errorf("nil URL = (%v, %q), want (false, \"\")", hit, src)
	}
}

// FuzzCheckRequestURL is the open-ended half of the differential. It compares
// the fast path against the string path on arbitrary inputs, at both the key
// level and the verdict level.
func FuzzCheckRequestURL(f *testing.F) {
	for _, raw := range diffURLs {
		f.Add(raw)
	}
	tf := diffFeed(f)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 || strings.ContainsRune(raw, 0) {
			t.Skip()
		}
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		assertAgrees(t, tf, raw, u)
	})
}
