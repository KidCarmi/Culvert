package upstream

// v2_test.go — unit contracts for the Upstream v2 model (2F-C): normalization
// + canonical authority, deterministic YAML identity, sealing bound to the
// authority hash, derived credential state, the single probe classifier,
// eligibility, effective mode, and effective-pool uniqueness.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestV2_NormalizeAndAuthority(t *testing.T) {
	cases := []struct {
		in   Spec
		want string
	}{
		{Spec{Scheme: "HTTP", Host: "Parent.Example.", Port: 0, Username: ""}, "http://parent.example:80"},
		{Spec{Scheme: "https", Host: "parent.example", Port: 3128, Username: "svc"}, "https://svc@parent.example:3128"},
		{Spec{Scheme: "http", Host: "2001:db8::1", Port: 3128}, "http://[2001:db8::1]:3128"},
		{Spec{Scheme: "http", Host: "bücher.example", Port: 8080}, "http://xn--bcher-kva.example:8080"},
	}
	for _, c := range cases {
		got, err := Normalize(c.in)
		if err != nil {
			t.Fatalf("%+v: %v", c.in, err)
		}
		if got.Authority() != c.want {
			t.Fatalf("%+v: authority %q, want %q", c.in, got.Authority(), c.want)
		}
	}
	for _, bad := range []Spec{
		{Scheme: "ftp", Host: "x.example"},
		{Scheme: "http", Host: ""},
		{Scheme: "http", Host: "x.example", Port: 70000},
		{Scheme: "http", Host: "x.example", Username: "a:b"},
		{Scheme: "http", Host: "bad host"},
	} {
		if _, err := Normalize(bad); err == nil {
			t.Fatalf("%+v must be refused", bad)
		}
	}
	a := Spec{Scheme: "http", Host: "parent.example", Port: 3128}
	b := Spec{Scheme: "HTTP", Host: "PARENT.EXAMPLE.", Port: 3128}
	na, _ := Normalize(a)
	nb, _ := Normalize(b)
	if na.AuthorityHash() != nb.AuthorityHash() || na.YAMLID() != nb.YAMLID() || !strings.HasPrefix(na.YAMLID(), "yaml-") || len(na.YAMLID()) != len("yaml-")+26 {
		t.Fatalf("canonical spellings must share hash and YAML id: %s vs %s", na.YAMLID(), nb.YAMLID())
	}
	if IsULID(na.YAMLID()) || !IsULID(NewManagedID()) {
		t.Fatal("managed ids are ULIDs, YAML ids are not")
	}
}

func TestV2_SpecFromURL(t *testing.T) {
	spec, pw, has, err := SpecFromURL("http://svc:secret@Parent.Example:3128/")
	if err != nil || !has || pw != "secret" || spec.Authority() != "http://svc@parent.example:3128" {
		t.Fatalf("got %+v %q %v %v", spec, pw, has, err)
	}
	if _, _, _, err := SpecFromURL("parent.example:3128"); err == nil {
		t.Fatal("schemeless must be refused")
	}
	if _, _, _, err := SpecFromURL("http://parent.example:3128/path"); err == nil {
		t.Fatal("a path must be refused")
	}
}

func TestV2_SealIsBoundToAuthorityAndKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenKey(dir, false); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("a read must never mint: %v", err)
	}
	k, err := OpenKey(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := Normalize(Spec{Scheme: "http", Host: "parent.example", Port: 3128, Username: "svc"})
	idA := NewManagedID()
	sealed, err := k.Seal("pw-1", idA, spec.AuthorityHash(), "t", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed.Ciphertext, "pw-1") || sealed.KeyID != k.KeyID() || sealed.AuthorityHash != spec.AuthorityHash() || sealed.EntryID != idA {
		t.Fatalf("sealed record: %+v", sealed)
	}
	if pt, err := k.Unseal(sealed, idA, spec.AuthorityHash()); err != nil || pt != "pw-1" {
		t.Fatalf("unseal: %q %v", pt, err)
	}
	other, _ := Normalize(Spec{Scheme: "http", Host: "other.example", Port: 3128, Username: "svc"})
	if _, err := k.Unseal(sealed, idA, other.AuthorityHash()); !errors.Is(err, ErrCredentialMismatch) {
		t.Fatalf("a credential must not unwrap for another authority, got %v", err)
	}
	// The binding includes the immutable entry ID: the same authority on a
	// DIFFERENT entry (a transplant after A is removed) must not unwrap.
	idB := NewManagedID()
	if _, err := k.Unseal(sealed, idB, spec.AuthorityHash()); !errors.Is(err, ErrCredentialMismatch) {
		t.Fatalf("a credential must not unwrap for another entry id, got %v", err)
	}
	// Even a record edited to CLAIM another authority or entry cannot
	// unwrap: both are AEAD additional data.
	forged := *sealed
	forged.AuthorityHash = other.AuthorityHash()
	if _, err := k.Unseal(&forged, idA, other.AuthorityHash()); err == nil {
		t.Fatal("a re-labelled ciphertext must not unwrap")
	}
	forgedID := *sealed
	forgedID.EntryID = idB
	if _, err := k.Unseal(&forgedID, idB, spec.AuthorityHash()); err == nil {
		t.Fatal("a re-identified ciphertext must not unwrap")
	}
	if _, err := k.Seal("pw", "", spec.AuthorityHash(), "t", "admin"); err == nil {
		t.Fatal("sealing without an entry id must be refused")
	}
	k2, _ := OpenKey(t.TempDir(), true)
	if _, err := k2.Unseal(sealed, idA, spec.AuthorityHash()); err == nil {
		t.Fatal("another key must not unwrap")
	}
	again, err := OpenKey(dir, false)
	if err != nil || again.KeyID() != k.KeyID() {
		t.Fatalf("reopen: %v %s", err, again.KeyID())
	}
}

func TestV2_CredentialStateAndEligibility(t *testing.T) {
	dir := t.TempDir()
	k, _ := OpenKey(dir, true)
	spec, _ := Normalize(Spec{Scheme: "http", Host: "parent.example", Port: 3128, Username: "svc"})
	id := NewManagedID()
	sealed, _ := k.Seal("pw", id, spec.AuthorityHash(), "t", "admin")
	entry := ManagedEntry{ID: id, Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username, Revision: 1, Source: SourceManaged, Credential: sealed}
	pool := &Pool{}
	pool.SetKey(k, "")
	if err := pool.SetDocument(Document{Entries: []ManagedEntry{entry}}); err != nil {
		t.Fatal(err)
	}
	if st := pool.List()[0].CredentialState; st != CredentialConfigured {
		t.Fatalf("want configured, got %s", st)
	}
	if u, _ := pool.ProxyFunc()(nil); u == nil || u.User == nil {
		t.Fatal("configured entry must be selected with its credential")
	} else if pw, _ := u.User.Password(); pw != "pw" {
		t.Fatalf("password %q", pw)
	}
	// Missing key ⇒ unusable ⇒ never selected.
	pool.SetKey(nil, "key_missing")
	if st := pool.List()[0].CredentialState; st != CredentialUnusable {
		t.Fatalf("want unusable, got %s", st)
	}
	captureFallbackAlerts(t)
	if u, _ := pool.ProxyFunc()(nil); u != nil {
		t.Fatal("unusable must never be selected")
	}
	if eff := pool.Effective(); eff.Mode != ModeDirectFallback || eff.Eligible != 0 {
		t.Fatalf("effective %+v", eff)
	}
	// Mismatch ⇒ never selected.
	pool.SetKey(k, "")
	mis := entry
	c := *sealed
	c.AuthorityHash = "deadbeef"
	mis.Credential = &c
	if err := pool.SetDocument(Document{Entries: []ManagedEntry{mis}}); err != nil {
		t.Fatal(err)
	}
	if st := pool.List()[0].CredentialState; st != CredentialMismatch {
		t.Fatalf("want mismatch, got %s", st)
	}
	if u, _ := pool.ProxyFunc()(nil); u != nil {
		t.Fatal("mismatch must never be selected")
	}
}

type fakeRT struct {
	status int
	err    error
}

func (f fakeRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{StatusCode: f.status, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestV2_ProbeClassifierAndModes(t *testing.T) {
	var _ net.Error = timeoutErr{}
	cases := []struct {
		resp   *http.Response
		err    error
		status string
		reason string
	}{
		{nil, errors.New("dial tcp: connection refused"), ProbeUnhealthy, ReasonConnectFailed},
		{nil, context.DeadlineExceeded, ProbeUnhealthy, ReasonTimeout},
		{nil, timeoutErr{}, ProbeUnhealthy, ReasonTimeout},
		{&http.Response{StatusCode: 407}, nil, ProbeUnhealthy, ReasonProxyAuthFailed},
		{&http.Response{StatusCode: 200}, nil, ProbeHealthy, ReasonNone},
		{&http.Response{StatusCode: 302}, nil, ProbeHealthy, ReasonNone},
		{&http.Response{StatusCode: 503}, nil, ProbeUnhealthy, ReasonProbeHTTPError},
	}
	for _, c := range cases {
		s, r := ClassifyProbe(c.resp, c.err)
		if s != c.status || r != c.reason {
			t.Fatalf("%v/%v: got %s/%s want %s/%s", c.resp, c.err, s, r, c.status, c.reason)
		}
	}
	prev := ProbeTransport
	t.Cleanup(func() { ProbeTransport = prev })
	pool := &Pool{}
	if err := pool.Configure([]Entry{{URL: "http://parent.example:3128"}}, 3, time.Minute); err != nil {
		t.Fatal(err)
	}
	if eff := pool.Effective(); eff.Mode != ModeChained || eff.Eligible != 1 {
		t.Fatalf("an unprobed entry is eligible: %+v", eff)
	}
	ProbeTransport = func(*url.URL) http.RoundTripper { return fakeRT{status: 407} }
	pool.HealthCheck(ProbeManual)
	if st := pool.List()[0]; st.Probe.Status != ProbeUnhealthy || st.Probe.Reason != ReasonProxyAuthFailed || st.Healthy || st.Eligible {
		t.Fatalf("407: %+v", st)
	}
	captureFallbackAlerts(t)
	if eff := pool.Effective(); eff.Mode != ModeNoEligibleParent {
		t.Fatalf("want no_eligible_parent, got %+v", eff)
	}
	if up := pool.Next(); up != nil {
		t.Fatal("no eligible parent")
	}
	if eff := pool.Effective(); eff.Mode != ModeDirectFallback || eff.FallbackTotal != 1 {
		t.Fatalf("want direct_fallback after the first fallback, got %+v", eff)
	}
	ProbeTransport = func(*url.URL) http.RoundTripper { return fakeRT{status: 200} }
	pool.HealthCheck(ProbeManual)
	if pool.Next() == nil {
		t.Fatal("healthy again")
	}
	if eff := pool.Effective(); eff.Mode != ModeChained {
		t.Fatalf("want chained, got %+v", eff)
	}
	if empty := (&Pool{}).Effective(); empty.Mode != ModeNoPool {
		t.Fatalf("want no_pool, got %+v", empty)
	}
}

func TestV2_EffectivePoolUniqueness(t *testing.T) {
	pool := &Pool{}
	if err := pool.Configure([]Entry{{URL: "http://parent.example:3128"}, {URL: "HTTP://PARENT.EXAMPLE:3128/"}}, 3, time.Minute); err == nil {
		t.Fatal("YAML/YAML duplicate must be refused")
	} else if d := new(DuplicateAuthorityError); !errors.As(err, &d) || d.Count != 1 {
		t.Fatalf("want DuplicateAuthorityError{1}, got %v", err)
	}
	if pool.Enabled() {
		t.Fatal("refused YAML leaves the pool unchanged")
	}
	if err := pool.Configure([]Entry{{URL: "http://parent.example:3128"}}, 3, time.Minute); err != nil {
		t.Fatal(err)
	}
	spec, _ := Normalize(Spec{Scheme: "http", Host: "parent.example", Port: 3128})
	managed := ManagedEntry{ID: NewManagedID(), Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Revision: 1, Source: SourceManaged}
	if err := pool.SetDocument(Document{Entries: []ManagedEntry{managed}}); err == nil {
		t.Fatal("YAML/managed duplicate must be refused")
	}
	if len(pool.List()) != 1 {
		t.Fatal("refused document leaves the pool unchanged")
	}
	b := managed
	b.ID = NewManagedID()
	b.Host = "other.example"
	c := b
	c.ID = NewManagedID()
	c.Host = "OTHER.EXAMPLE"
	if err := pool.SetDocument(Document{Entries: []ManagedEntry{b, c}}); err == nil {
		t.Fatal("managed/managed duplicate must be refused")
	}
	if err := pool.SetDocument(Document{Entries: []ManagedEntry{b}}); err != nil {
		t.Fatal(err)
	}
	if got := len(pool.List()); got != 2 {
		t.Fatalf("want yaml + managed = 2, got %d", got)
	}
}

// ── 2F-C correction: engine-level invariants ──

// A credential sealed for entry A, attached to entry B with the same
// authority, is mismatch: never selected, never probed.
func TestV2C_TransplantedCredentialIsMismatch(t *testing.T) {
	dir := t.TempDir()
	k, _ := OpenKey(dir, true)
	spec, _ := Normalize(Spec{Scheme: "http", Host: "parent.example", Port: 3128, Username: "svc"})
	idA, idB := NewManagedID(), NewManagedID()
	sealed, _ := k.Seal("pw", idA, spec.AuthorityHash(), "t", "admin")
	pool := &Pool{}
	pool.SetKey(k, "")
	b := ManagedEntry{ID: idB, Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username, Revision: 1, Source: SourceManaged, Credential: sealed}
	if err := pool.SetDocument(Document{Entries: []ManagedEntry{b}}); err != nil {
		t.Fatal(err)
	}
	if st := pool.List()[0].CredentialState; st != CredentialMismatch {
		t.Fatalf("want mismatch, got %s", st)
	}
	if pool.Next() != nil {
		t.Fatal("a mismatched entry must never be selected")
	}
	prev := ProbeTransport
	t.Cleanup(func() { ProbeTransport = prev })
	probed := 0
	ProbeTransport = func(*url.URL) http.RoundTripper { probed++; return fakeRT{status: 200} }
	pool.HealthCheck(ProbeManual)
	if probed != 0 {
		t.Fatal("a mismatched entry must never be probed")
	}
	if pool.List()[0].Probe.Status != ProbeUnprobed {
		t.Fatal("probe state must stay unprobed")
	}
}

// A YAML inline credential is retained in memory only: configured, selected
// with the password, never in the document, list, entries or legacy URLs.
func TestV2C_YAMLInlineCredentialRetainedInMemoryOnly(t *testing.T) {
	pool := &Pool{}
	if err := pool.Configure([]Entry{{URL: "http://svc:inline-pw@parent.test:3128"}}, 5, time.Minute); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	list := pool.List()
	if len(list) != 1 || list[0].Source != string(SourceYAML) || list[0].CredentialState != CredentialConfigured {
		t.Fatalf("list = %+v", list)
	}
	if strings.Contains(list[0].URL, "@") || strings.Contains(list[0].Authority, "inline-pw") {
		t.Fatalf("display surfaces must be credential-free: %+v", list[0])
	}
	u, err := pool.ProxyFunc()(nil)
	if err != nil || u == nil {
		t.Fatalf("ProxyFunc: %v %v", u, err)
	}
	if pw, _ := u.User.Password(); pw != "inline-pw" {
		t.Fatalf("selection must present the inline password, got %q", pw)
	}
	if len(pool.Document().Entries) != 0 || len(pool.LegacyManagedEntries()) != 0 {
		t.Fatal("a YAML entry must never enter the managed document")
	}
	for _, e := range pool.Entries() {
		if strings.Contains(e.URL, "inline-pw") {
			t.Fatal("Entries() must be credential-free")
		}
	}
	for _, e := range pool.YAMLEntries() {
		if !e.HasInlineSecret() || e.Credential != nil {
			t.Fatalf("yaml entry must carry the inline secret in memory only: %+v", e)
		}
	}
	// The probe seam sees the credential-free authority only.
	prev := ProbeTransport
	t.Cleanup(func() { ProbeTransport = prev })
	var seen []string
	ProbeTransport = func(a *url.URL) http.RoundTripper { seen = append(seen, a.String()); return fakeRT{status: 200} }
	pool.HealthCheck(ProbePeriodic)
	if len(seen) != 1 || strings.Contains(seen[0], "inline-pw") || strings.Contains(seen[0], "@") {
		t.Fatalf("probe seam must receive the credential-free authority, got %v", seen)
	}
	if h := pool.List()[0].Health; h.Status != ProbeHealthy || h.Source != ProbePeriodic || h.LastProbeAt == "" {
		t.Fatalf("health = %+v", h)
	}
}

// effective.since re-stamps only on a mode transition (injected clock).
func TestV2C_EffectiveSinceIsTransitionStamped(t *testing.T) {
	prev := nowRFC3339
	t.Cleanup(func() { nowRFC3339 = prev })
	tick := 0
	nowRFC3339 = func() string { tick++; return time.Date(2026, 9, 4, 0, 0, tick, 0, time.UTC).Format(time.RFC3339) }
	pool := &Pool{}
	a := pool.Effective()
	b := pool.Effective()
	if a.Mode != ModeNoPool || a.Since == "" || a.Since != b.Since {
		t.Fatalf("since must hold while the mode holds: %+v %+v", a, b)
	}
	if err := pool.Configure([]Entry{{URL: "http://parent.test:3128"}}, 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	c := pool.Effective()
	if c.Mode != ModeChained || c.Since == b.Since {
		t.Fatalf("since must re-stamp on a transition: %+v → %+v", b, c)
	}
	if d := pool.Effective(); d.Since != c.Since {
		t.Fatalf("since must hold after the transition: %+v %+v", c, d)
	}
}

// The scheme grammar is http|https only.
func TestV2C_SchemeGrammarIsHTTPOnly(t *testing.T) {
	for _, raw := range []string{"socks5://parent.test:1080", "socks5h://parent.test:1080", "ftp://parent.test:21"} {
		if _, _, _, err := SpecFromURL(raw); err == nil {
			t.Fatalf("%s must be refused", raw)
		}
	}
	if _, err := YAMLEntries([]Entry{{URL: "socks5://parent.test:1080"}}); err == nil {
		t.Fatal("a socks5 YAML seed must be refused")
	}
}
