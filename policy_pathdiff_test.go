//go:build policy_pathdiff

package main

// Cross-path policy differential (verification only, shadow mode).
//
// One logical request is asked of five real paths and the answers are compared:
//
//	http     GET http://AUTHORITY/ through a real listener serving handleRequest
//	connect  CONNECT AUTHORITY through the same listener
//	tester   POST /api/policy/test (apiPolicyTest), the admin Policy Tester
//	eval     policyStore.Evaluate, the shared evaluator entry point
//	reload   the same rule base saved, loaded into a fresh PolicyStore, evaluated
//
// The answer of a path is the NAME of the rule that decided, "-" for no match,
// or "refused:<status>" when the path rejects the request before a decision.
// Every rule's action is Block_Page and the default is deny, so nothing is ever
// dialled. Rule identity is a stronger outcome than allow/deny.
//
// A disagreement is evidence that two paths differ. It is not, by itself,
// evidence that either is wrong: see test/policy-pathdiff/README.md for how each
// class is read against the contracts.

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gen "github.com/KidCarmi/Culvert/internal/pathdiffgen"
)

var pdPaths = []string{"http", "connect", "tester", "eval", "reload"}

type pdEnv struct {
	t        *testing.T
	addr     string
	prov     *testProxyIdentityProvider
	tokN     int
	reload   *PolicyStore
	noIdP    *IdPRegistry // registry without an identity provider: anonymous requests are not challenged
	withIdP  *IdPRegistry // registry with the fake provider, installed only for requests that carry credentials
	tmp      string
	faultyTT bool // negative control only: corrupt the tester's input on purpose
}

func pdSetup(t *testing.T) *pdEnv {
	t.Helper()
	u := startTestProxy(t) // real listener, real handleRequest
	prov := &testProxyIdentityProvider{idByToken: map[string]*Identity{}}
	noIdP := idpRegistry
	withIdP := &IdPRegistry{
		profiles: []*IdPProfile{{ID: "test-idp", Name: "Test IdP", Type: IdPTypeOIDC, Enabled: true, EmailDomains: []string{"example.com"}}},
		live:     map[string]IdentityProvider{"test-idp": prov},
	}
	t.Cleanup(func() { idpRegistry = noIdP })
	setDefaultPolicyAction("deny")
	return &pdEnv{t: t, addr: u.Host, prov: prov, tmp: t.TempDir(), noIdP: noIdP, withIdP: withIdP}
}

func pdRule(r gen.Rule) PolicyRule {
	out := PolicyRule{Priority: r.Priority, Name: r.Name, SourceIP: r.SourceIP, SourceIdentity: r.SourceIdentity,
		SourceGroup: r.SourceGroup, AuthSource: r.AuthSource, DestFQDN: r.DestFQDN, DestCategory: URLCategory(r.DestCategory),
		DestCategoryGroup: r.DestCatGroup, Action: ActionBlockPage}
	if r.Disabled {
		f := false
		out.Enabled = &f
	}
	return out
}

func pdApply(ps *PolicyStore, rules []gen.Rule, ops []gen.Op) {
	in := make([]PolicyRule, len(rules))
	for i := range rules {
		in[i] = pdRule(rules[i])
	}
	ps.ReplaceAll(in)
	for _, op := range ops {
		cur := ps.List()
		switch op.Kind {
		case "replace":
			ps.ReplaceAll(cur)
		case "disable", "delete":
			for i := range cur {
				if cur[i].Name != op.Name {
					continue
				}
				if op.Kind == "delete" {
					ps.DeleteByID(cur[i].ID)
				} else {
					f := false
					cur[i].Enabled = &f
					ps.UpdateByID(cur[i].ID, cur[i])
				}
			}
		}
	}
}

// publish installs the case on the live store and, through a second store that
// owns a file, on disk; reload is a third store that only ever reads that file.
func (e *pdEnv) publish(c *gen.Case) {
	rl = newRateLimiter() // thousands of loopback requests must not trip the limiter
	pdApply(policyStore, c.Rules, c.Ops)
	path := filepath.Join(e.tmp, "policy.json")
	_ = os.Remove(path)
	writer := &PolicyStore{}
	if err := writer.Load(path); err != nil {
		e.t.Fatalf("adopt path: %v", err)
	}
	pdApply(writer, c.Rules, c.Ops)
	if err := writer.SaveErr(); err != nil {
		e.t.Fatalf("save: %v", err)
	}
	e.reload = &PolicyStore{}
	if err := e.reload.Load(path); err != nil {
		e.t.Fatalf("reload: %v", err)
	}
}

func pdHits() map[string]int64 {
	m := map[string]int64{}
	for _, r := range policyStore.List() {
		m[r.Name] += r.HitCount
	}
	return m
}

func pdOutcome(code int, before, after map[string]int64) string {
	var hit []string
	for k, v := range after {
		if v != before[k] {
			hit = append(hit, k)
		}
	}
	sort.Strings(hit)
	switch {
	case code == http.StatusForbidden && len(hit) == 1:
		return hit[0]
	case code == http.StatusForbidden && len(hit) == 0:
		return "-"
	case len(hit) == 0:
		return fmt.Sprintf("refused:%d", code)
	default:
		return fmt.Sprintf("anomaly:%d:%s", code, strings.Join(hit, "+"))
	}
}

func (e *pdEnv) wire(method string, rq *gen.Request, auth string) string {
	var b strings.Builder
	if method == "CONNECT" {
		fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", rq.Authority, rq.Authority)
	} else {
		fmt.Fprintf(&b, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", rq.Authority, rq.Authority)
	}
	if auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", auth)
	}
	b.WriteString("\r\n")
	before := pdHits()
	code := 0
	if rq.RemoteAddr == "" { // real socket
		c, err := net.DialTimeout("tcp", e.addr, 2*time.Second)
		if err != nil {
			e.t.Fatalf("dial proxy: %v", err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(c, b.String())
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		fmt.Sscanf(line, "HTTP/1.1 %d", &code)
	} else { // real handler with a chosen peer address, parsed by net/http's own reader
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(b.String())))
		if err != nil {
			return "refused:parse"
		}
		req.RemoteAddr = rq.RemoteAddr
		w := httptest.NewRecorder()
		handleRequest(w, req)
		code = w.Code
	}
	return pdOutcome(code, before, pdHits())
}

func pdClient(rq *gen.Request) string {
	if rq.RemoteAddr == "" {
		return "127.0.0.1"
	}
	h, _, _ := net.SplitHostPort(rq.RemoteAddr)
	return h
}

// ask returns every path's outcome for one request.
func (e *pdEnv) ask(rq *gen.Request) map[string]string {
	out := map[string]string{}
	ident, src, auth := "", "unauth", ""
	var groups []string
	idpRegistry = e.noIdP
	if rq.Identity != nil {
		idpRegistry = e.withIdP
		e.tokN++
		tok := fmt.Sprintf("tok%d", e.tokN)
		e.prov.idByToken[tok] = &Identity{Sub: rq.Identity.Sub, Groups: rq.Identity.Groups, Provider: rq.Identity.Provider}
		defer delete(e.prov.idByToken, tok)
		auth = base64.StdEncoding.EncodeToString([]byte("u@example.com:" + tok))
		// What the enforcement path resolves (proxy.go resolveRequestAuth): Sub,
		// Groups, and the identity's Provider. An operator reads the same three
		// values off the access log and types them into the tester.
		ident, src, groups = rq.Identity.Sub, rq.Identity.Provider, rq.Identity.Groups
	}
	out["http"] = e.wire("GET", rq, auth)
	out["connect"] = e.wire("CONNECT", rq, auth)

	host := rq.Authority
	if e.faultyTT {
		if i := strings.Index(host, "."); i >= 0 {
			host = host[i+1:]
		}
	}
	w := httptest.NewRecorder()
	apiPolicyTest(w, testerRoleReq(e.t, RoleViewer, map[string]any{
		"host": host, "sourceIP": pdClient(rq), "identity": ident, "authSource": src, "groups": groups}))
	if w.Code != http.StatusOK {
		out["tester"] = fmt.Sprintf("refused:%d", w.Code)
	} else {
		var m struct {
			Matched bool `json:"matched"`
			Rule    struct {
				Name string `json:"name"`
			} `json:"rule"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		out["tester"] = "-"
		if m.Matched {
			out["tester"] = m.Rule.Name
		}
	}

	bare := rq.Authority
	if h, _, err := net.SplitHostPort(bare); err == nil {
		bare = h
	}
	for name, ps := range map[string]*PolicyStore{"eval": policyStore, "reload": e.reload} {
		out[name] = "-"
		if m := ps.Evaluate(pdClient(rq), ident, src, bare, groups); m != nil && m.Rule != nil {
			out[name] = m.Rule.Name
		}
	}
	return out
}

func pdShape(o string) string {
	switch {
	case o == "-":
		return "N"
	case strings.HasPrefix(o, "refused:"), strings.HasPrefix(o, "anomaly:"):
		return o
	default:
		return "M"
	}
}

func pdRefused(o string) bool { return strings.HasPrefix(o, "refused:") }

type pdFinding struct {
	Class   string            `json:"class"`
	Sig     string            `json:"sig"`
	Case    string            `json:"case"`
	Stratum string            `json:"stratum"`
	Tag     string            `json:"tag"`
	Request gen.Request       `json:"request"`
	Base    *gen.Request      `json:"base,omitempty"`
	Out     map[string]string `json:"out"`
	BaseOut map[string]string `json:"base_out,omitempty"`
	Want    string            `json:"want,omitempty"`
	Rules   []gen.Rule        `json:"rules"`
	Ops     []gen.Op          `json:"ops,omitempty"`
}

func pdSig(class, stratum, tag string, o map[string]string) string {
	parts := make([]string, 0, len(pdPaths))
	for _, p := range pdPaths {
		parts = append(parts, p+"="+pdShape(o[p]))
	}
	return class + "|" + stratum + "|" + tag + "|" + strings.Join(parts, " ")
}

// classify applies the frozen comparison semantics to one request.
func pdClassify(c *gen.Case, i int, outs []map[string]string) []pdFinding {
	rq, o := c.Requests[i], outs[i]
	mk := func(class, sig string) pdFinding {
		return pdFinding{Class: class, Sig: sig, Case: c.ID, Stratum: c.Stratum, Tag: rq.Tag, Request: rq, Out: o, Rules: c.Rules, Ops: c.Ops}
	}
	var fs []pdFinding
	decided := map[string]bool{}
	for _, p := range pdPaths {
		if strings.HasPrefix(o[p], "anomaly:") {
			fs = append(fs, mk("anomaly", pdSig("anomaly", c.Stratum, rq.Tag, o)))
		}
		if !pdRefused(o[p]) {
			decided[o[p]] = true
		}
	}
	switch {
	case len(decided) > 1: // X1: paths that decide must name the same rule
		fs = append(fs, mk("decision-split", pdSig("decision-split", c.Stratum, rq.Tag, o)))
	case pdRefused(o["http"]) != pdRefused(o["connect"]): // X2: the two enforcement verbs refuse alike
		fs = append(fs, mk("refusal-split-enforcement", pdSig("refusal-split-enforcement", c.Stratum, rq.Tag, o)))
	case pdRefused(o["http"]) && pdRefused(o["connect"]) && !pdRefused(o["tester"]):
		// The tester answers for a host spelling neither enforcement verb accepts.
		fs = append(fs, mk("tester-answers-unroutable", "tester-answers-unroutable|"+rq.Tag+"|tester="+pdShape(o["tester"])))
	case pdRefused(o["tester"]) && !pdRefused(o["http"]):
		// The tester refuses a request the enforcement path decides.
		fs = append(fs, mk("tester-refuses-routable", "tester-refuses-routable|"+rq.Tag+"|http="+pdShape(o["http"])))
	}
	if c.Stratum == "plain" || c.Stratum == "publish" { // independent oracle on the literal fragment
		if want, ok := gen.DecidePlain(gen.ApplyOps(c.Rules, c.Ops), rq.Authority); ok {
			if want == "" {
				want = "-"
			}
			for _, p := range pdPaths {
				if o[p] != want {
					f := mk("oracle-mismatch", "oracle-mismatch|"+c.Stratum+"|"+p)
					f.Want = want
					fs = append(fs, f)
					break
				}
			}
		}
	}
	if rq.AliasOf >= 0 && gen.Relate(c.Requests[rq.AliasOf].Authority, rq.Authority) == gen.Same {
		base, bo := c.Requests[rq.AliasOf], outs[rq.AliasOf]
		for _, p := range pdPaths {
			if o[p] != bo[p] { // D1-D4: one destination, one decision, on every path
				f := mk("alias-split", "alias-split|"+rq.Tag+"|"+p+"|"+pdShape(bo[p])+"->"+pdShape(o[p]))
				f.Base, f.BaseOut = &base, bo
				fs = append(fs, f)
				break
			}
		}
	}
	return fs
}

type pdStats struct {
	Cases, Requests, Decisions int
	ByStratum                  map[string]map[string]int // stratum -> {requests, match, nomatch, refused}
	Unspecified                map[string]map[string]int // alias tag -> shape transition per path -> count
}

func pdRun(e *pdEnv, cases []gen.Case) ([]pdFinding, *pdStats) {
	st := &pdStats{ByStratum: map[string]map[string]int{}, Unspecified: map[string]map[string]int{}}
	var all []pdFinding
	for ci := range cases {
		c := &cases[ci]
		e.publish(c)
		outs := make([]map[string]string, len(c.Requests))
		for i := range c.Requests {
			outs[i] = e.ask(&c.Requests[i])
		}
		st.Cases++
		bs := st.ByStratum[c.Stratum]
		if bs == nil {
			bs = map[string]int{}
			st.ByStratum[c.Stratum] = bs
		}
		for i := range c.Requests {
			st.Requests++
			st.Decisions += len(pdPaths)
			bs["requests"]++
			switch pdShape(outs[i]["http"]) {
			case "M":
				bs["match"]++
			case "N":
				bs["nomatch"]++
			default:
				bs["refused"]++
			}
			all = append(all, pdClassify(c, i, outs)...)
			rq := c.Requests[i]
			if rq.AliasOf >= 0 && gen.Relate(c.Requests[rq.AliasOf].Authority, rq.Authority) == gen.Unspecified {
				u := st.Unspecified[rq.Tag]
				if u == nil {
					u = map[string]int{}
					st.Unspecified[rq.Tag] = u
				}
				for _, p := range pdPaths {
					u[p+":"+pdShape(outs[rq.AliasOf][p])+"->"+pdShape(outs[i][p])]++
				}
			}
		}
	}
	return all, st
}

// minimise drops rules one at a time while the finding's signature survives,
// then re-asks every path so the recorded outcomes belong to the minimal case.
func pdMinimise(e *pdEnv, f pdFinding) pdFinding {
	build := func(rs []gen.Rule) (*gen.Case, []map[string]string) {
		c := &gen.Case{ID: f.Case, Stratum: f.Stratum, Rules: rs, Ops: f.Ops, Requests: []gen.Request{f.Request}}
		c.Requests[0].AliasOf = -1
		if f.Base != nil {
			c.Requests = []gen.Request{*f.Base, f.Request}
			c.Requests[0].AliasOf, c.Requests[1].AliasOf = -1, 0
		}
		e.publish(c)
		outs := make([]map[string]string, len(c.Requests))
		for i := range c.Requests {
			outs[i] = e.ask(&c.Requests[i])
		}
		return c, outs
	}
	holds := func(rs []gen.Rule) bool {
		c, outs := build(rs)
		for _, g := range pdClassify(c, len(c.Requests)-1, outs) {
			if g.Sig == f.Sig {
				return true
			}
		}
		return false
	}
	rules := append([]gen.Rule{}, f.Rules...)
	for i := 0; i < len(rules); {
		trial := append(append([]gen.Rule{}, rules[:i]...), rules[i+1:]...)
		if holds(trial) {
			rules = trial
		} else {
			i++
		}
	}
	c, outs := build(rules)
	f.Rules, f.Out = c.Rules, outs[len(outs)-1]
	if f.Base != nil {
		f.BaseOut = outs[0]
	}
	if f.Want != "" {
		if w, ok := gen.DecidePlain(gen.ApplyOps(rules, f.Ops), f.Request.Authority); ok {
			if f.Want = w; w == "" {
				f.Want = "-"
			}
		}
	}
	return f
}

func pdEnvOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func pdScale() float64 {
	var s float64 = 1
	fmt.Sscanf(pdEnvOr("PATHDIFF_SCALE", "1"), "%g", &s)
	return s
}

type pdReport struct {
	Seed         string                    `json:"seed"`
	Generator    string                    `json:"generator"`
	Fingerprint  string                    `json:"verifier_fingerprint"`
	Cases        int                       `json:"cases"`
	Requests     int                       `json:"requests"`
	Decisions    int                       `json:"decisions"`
	ByStratum    map[string]map[string]int `json:"by_stratum"`
	Signatures   map[string]int            `json:"signatures"`
	Unspecified  map[string]map[string]int `json:"unspecified_alias_behaviour"`
	Examples     []pdFinding               `json:"minimised_examples"`
	DurationSecs float64                   `json:"duration_seconds"`
}

// pdFingerprint hashes the verifier itself, so a change to the generator, the
// reference or this harness is visible in the baseline even when results match.
func pdFingerprint(t *testing.T) string {
	h := sha256.New()
	for _, f := range []string{"policy_pathdiff_test.go", "internal/pathdiffgen/gen.go", "internal/pathdiffgen/ref.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("fingerprint: %v", err)
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// TestPathDiff_Generated is the campaign. PATHDIFF_SEED selects the seed.
func TestPathDiff_Generated(t *testing.T) {
	seed, scale := pdEnvOr("PATHDIFF_SEED", "dev"), pdScale()
	e := pdSetup(t)
	start := time.Now()
	cases := gen.Generate(seed, scale)
	findings, st := pdRun(e, cases)

	// Anti-vacuity: a stratum in which nothing matches, or everything does, proves nothing.
	for s, b := range st.ByStratum {
		if b["match"]*20 < b["requests"] || b["nomatch"]*50 < b["requests"] {
			t.Errorf("stratum %s is vacuous: %v", s, b)
		}
	}
	sigs := map[string]int{}
	first := map[string]pdFinding{}
	for _, f := range findings {
		if sigs[f.Sig] == 0 {
			first[f.Sig] = f
		}
		sigs[f.Sig]++
	}
	keys := make([]string, 0, len(sigs))
	for k := range sigs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rep := pdReport{Seed: seed, Generator: gen.Version, Fingerprint: pdFingerprint(t), Cases: st.Cases, Requests: st.Requests,
		Decisions: st.Decisions, ByStratum: st.ByStratum, Signatures: sigs, Unspecified: st.Unspecified}
	for _, k := range keys {
		rep.Examples = append(rep.Examples, pdMinimise(e, first[k]))
	}
	rep.DurationSecs = time.Since(start).Seconds()
	t.Logf("seed=%s cases=%d requests=%d path-decisions=%d signatures=%d (%.1fs)", seed, st.Cases, st.Requests, st.Decisions, len(sigs), rep.DurationSecs)
	for _, k := range keys {
		t.Logf("  %5d  %s", sigs[k], k)
	}
	if out := os.Getenv("PATHDIFF_OUT"); out != "" {
		b, _ := json.MarshalIndent(rep, "", " ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pdCheckBaseline(t, seed, scale, rep)
}

// pdCheckBaseline makes drift visible: a signature that appears, disappears or
// changes count, or a changed verifier, fails until the baseline is re-reviewed.
func pdCheckBaseline(t *testing.T, seed string, scale float64, rep pdReport) {
	path := os.Getenv("PATHDIFF_BASELINE")
	if path == "" {
		return
	}
	if os.Getenv("PATHDIFF_WRITE_BASELINE") == "1" {
		b, _ := json.MarshalIndent(map[string]any{"seed": seed, "scale": scale, "generator": rep.Generator,
			"verifier_fingerprint": rep.Fingerprint, "requests": rep.Requests, "signatures": rep.Signatures,
			"by_stratum": rep.ByStratum, "unspecified_alias_behaviour": rep.Unspecified}, "", " ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	var base struct {
		Seed        string                    `json:"seed"`
		Scale       float64                   `json:"scale"`
		Fingerprint string                    `json:"verifier_fingerprint"`
		Requests    int                       `json:"requests"`
		Signatures  map[string]int            `json:"signatures"`
		ByStratum   map[string]map[string]int `json:"by_stratum"`
		Unspecified map[string]map[string]int `json:"unspecified_alias_behaviour"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := json.Unmarshal(b, &base); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if base.Seed != seed || base.Scale != scale {
		t.Fatalf("baseline is for seed=%s scale=%g, this run is seed=%s scale=%g", base.Seed, base.Scale, seed, scale)
	}
	if base.Fingerprint != rep.Fingerprint {
		t.Errorf("verifier changed (fingerprint %s, baseline %s): re-review and regenerate the baseline", rep.Fingerprint, base.Fingerprint)
	}
	if base.Requests != rep.Requests {
		t.Errorf("request count %d differs from baseline %d", rep.Requests, base.Requests)
	}
	for k, n := range rep.Signatures {
		if base.Signatures[k] != n {
			t.Errorf("behaviour drift: %q now %d, baseline %d", k, n, base.Signatures[k])
		}
	}
	for k, n := range base.Signatures {
		if _, ok := rep.Signatures[k]; !ok {
			t.Errorf("behaviour drift: %q was %d in the baseline and no longer occurs", k, n)
		}
	}
	// The outcome tables catch a change that moves every path together, which
	// the cross-path comparison cannot see by construction.
	pdTableDrift(t, "outcomes", base.ByStratum, rep.ByStratum)
	pdTableDrift(t, "alias behaviour", base.Unspecified, rep.Unspecified)
}

func pdTableDrift(t *testing.T, what string, base, now map[string]map[string]int) {
	keys := map[string]bool{}
	for k := range base {
		keys[k] = true
	}
	for k := range now {
		keys[k] = true
	}
	for k := range keys {
		cells := map[string]bool{}
		for c := range base[k] {
			cells[c] = true
		}
		for c := range now[k] {
			cells[c] = true
		}
		for c := range cells {
			if base[k][c] != now[k][c] {
				t.Errorf("behaviour drift (%s): %s %s now %d, baseline %d", what, k, c, now[k][c], base[k][c])
			}
		}
	}
}

// TestPathDiff_Controls: the comparator must stay silent when nothing differs
// and must speak when something does.
func TestPathDiff_Controls(t *testing.T) {
	e := pdSetup(t)
	cases := gen.Generate("control", 0.1)
	digest := func(fs []pdFinding) string {
		h := sha256.New()
		for _, f := range fs {
			fmt.Fprintln(h, f.Sig, f.Case, f.Request.Authority)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	a, _ := pdRun(e, cases)
	b, _ := pdRun(e, cases)
	if digest(a) != digest(b) {
		t.Fatal("two identical runs produced different findings: the harness is not deterministic")
	}
	e.faultyTT = true // the tester is now asked about the parent domain
	c, _ := pdRun(e, cases)
	e.faultyTT = false
	split := 0
	for _, f := range c {
		if f.Class == "decision-split" || f.Class == "oracle-mismatch" {
			split++
		}
	}
	if split <= len(a) {
		t.Fatalf("an injected fault in one path raised findings from %d to only %d: the comparator is not live", len(a), split)
	}
	t.Logf("clean run: %d findings (deterministic); with a fault injected into one path: %d decision splits", len(a), split)
}

// TestPathDiff_Review executes an independent reviewer's predictions
// (PATHDIFF_REVIEW = JSONL file) and prints prediction against observation.
func TestPathDiff_Review(t *testing.T) {
	path := os.Getenv("PATHDIFF_REVIEW")
	if path == "" {
		t.Skip("PATHDIFF_REVIEW not set")
	}
	e := pdSetup(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type revRule struct {
		gen.Rule
		Enabled *bool `json:"enabled"`
	}
	type revReq struct {
		Authority  string `json:"authority"`
		RemoteAddr string `json:"remote_addr"`
		Identity   *struct {
			Sub      string   `json:"sub"`
			Groups   []string `json:"groups"`
			Provider string   `json:"provider"`
		} `json:"identity"`
	}
	var results []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var p struct {
			ID         string              `json:"id"`
			Hypothesis string              `json:"hypothesis"`
			Rules      []revRule           `json:"rules"`
			Requests   []revReq            `json:"requests"`
			Predicted  []map[string]string `json:"predicted"`
		}
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			t.Fatalf("prediction: %v", err)
		}
		c := gen.Case{ID: p.ID, Stratum: "review"}
		for _, r := range p.Rules {
			g := r.Rule
			g.Disabled = r.Enabled != nil && !*r.Enabled
			c.Rules = append(c.Rules, g)
		}
		for _, r := range p.Requests {
			q := gen.Request{Authority: r.Authority, RemoteAddr: r.RemoteAddr, AliasOf: -1, Tag: "review"}
			if r.Identity != nil && r.Identity.Sub != "" {
				q.Identity = &gen.Identity{Sub: r.Identity.Sub, Groups: r.Identity.Groups, Provider: r.Identity.Provider}
			}
			c.Requests = append(c.Requests, q)
		}
		e.publish(&c)
		for i := range c.Requests {
			o := e.ask(&c.Requests[i])
			exact, split := true, false
			seen := map[string]bool{}
			for _, pth := range pdPaths {
				seen[o[pth]] = true
				if i < len(p.Predicted) {
					if want := p.Predicted[i][pth]; want != "" && want != "?" && want != o[pth] && !(want == "refused" && pdRefused(o[pth])) {
						exact = false
					}
				}
			}
			split = len(seen) > 1
			t.Logf("%s req%d %-34q observed=%v predicted=%v exact=%v split=%v", p.ID, i, c.Requests[i].Authority, o, p.Predicted, exact, split)
			results = append(results, map[string]any{"id": p.ID, "request": i, "authority": c.Requests[i].Authority, "observed": o, "exact": exact, "path_split": split})
		}
	}
	if out := os.Getenv("PATHDIFF_REVIEW_OUT"); out != "" {
		b, _ := json.MarshalIndent(results, "", " ")
		_ = os.WriteFile(out, b, 0o644)
	}
}

// TestPathDiff_ActionDispatch covers what the campaign cannot: actions other
// than Block_Page and the default action, against a loopback backend. Each row
// states the reference expectation and the contract it comes from; "?" means the
// contract is open and the row is reported, not asserted.
func TestPathDiff_ActionDispatch(t *testing.T) {
	backend, cb := startCountingBackend(t)
	e := pdSetup(t)
	hostPort := strings.TrimPrefix(backend.URL, "http://")
	host, _, _ := net.SplitHostPort(hostPort)
	rows := []struct {
		action, def, want, contract string
	}{
		{"Allow", "deny", "forward", "POL-001"}, {"Block_Page", "allow", "block", "POL-001"}, {"Drop", "allow", "block", "POL-001"},
		{"Redirect", "allow", "block", "POL-001"}, {"Frobnicate", "allow", "block", "POL-004"}, {"", "deny", "?", "POL-901 (open)"},
		{"allow", "deny", "?", "action spelling (unspecified)"}, {"BLOCK_PAGE", "allow", "?", "action spelling (unspecified)"},
		{"<none>", "allow", "forward", "POL-003"}, {"<none>", "deny", "block", "POL-003"},
	}
	got := map[string]string{}
	for _, row := range rows {
		rl = newRateLimiter()
		var rules []PolicyRule
		if row.action != "<none>" {
			rules = []PolicyRule{{Priority: 1, Name: "r", DestFQDN: host, Action: PolicyAction(row.action), RedirectURL: "http://127.0.0.1:1/"}}
		}
		policyStore.ReplaceAll(rules)
		setDefaultPolicyAction(row.def)
		obs := map[string]string{}
		for _, verb := range []string{"GET", "CONNECT"} {
			before := cb.hitCount()
			c, err := net.DialTimeout("tcp", e.addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			br := bufio.NewReader(c)
			if verb == "GET" {
				fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostPort, hostPort)
			} else {
				fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
			}
			line, _ := br.ReadString('\n')
			code := 0
			fmt.Sscanf(line, "HTTP/1.1 %d", &code)
			if verb == "CONNECT" && code == http.StatusOK { // tunnel is up: prove it reaches the backend
				for l := line; l != "\r\n" && l != ""; l, _ = br.ReadString('\n') {
				}
				fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostPort)
				_, _ = br.ReadString('\n')
			}
			c.Close()
			time.Sleep(20 * time.Millisecond)
			got := "block"
			if cb.hitCount() > before {
				got = "forward"
			}
			obs[verb] = fmt.Sprintf("%s(%d)", got, code)
		}
		w := httptest.NewRecorder()
		apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": hostPort, "sourceIP": "127.0.0.1", "authSource": "unauth"}))
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		tester := fmt.Sprintf("matched=%v action=%v default=%v", m["matched"], m["action"], m["defaultAction"])
		verdict := "as-specified"
		switch {
		case row.want == "?":
			verdict = "unspecified"
		case !strings.HasPrefix(obs["GET"], row.want):
			verdict = "DIFFERS-FROM-CONTRACT"
		}
		key := fmt.Sprintf("action=%q default=%s", row.action, row.def)
		got[key] = fmt.Sprintf("want=%s (%s) http=%s connect=%s tester[%s] %s", row.want, row.contract, obs["GET"], obs["CONNECT"], tester, verdict)
		t.Logf("%-36s %s", key, got[key])
	}
	// CONNECT to a loopback backend is refused before forwarding on every row
	// (the private-destination guard; contract SWG-900 is open), so the forward
	// expectation is checked on plain HTTP only and CONNECT is recorded.
	path := os.Getenv("PATHDIFF_DISPATCH_BASELINE")
	if path == "" {
		return
	}
	if os.Getenv("PATHDIFF_WRITE_BASELINE") == "1" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	for k, v := range got {
		if want[k] != v {
			t.Errorf("behaviour drift: %s\n  now      %s\n  baseline %s", k, v, want[k])
		}
	}
}

// TestPathDiff_DialAlias checks a model invariant the cross-path comparison
// cannot: two spellings that reach the SAME address must get the SAME decision.
// A block rule names the backend's address; the default is allow. Each spelling
// is sent on plain HTTP through the real listener and the backend counts
// arrivals. "reached" for a spelling the rule did not match is a bypass of that
// rule. Which spellings the dialler resolves depends on the resolver in use
// (cgo or pure Go), so the build's choice is recorded with the result.
func TestPathDiff_DialAlias(t *testing.T) {
	backend, cb := startCountingBackend(t)
	e := pdSetup(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "block-backend", DestFQDN: "127.0.0.1", Action: ActionBlockPage}})
	setDefaultPolicyAction("allow")
	got := map[string]string{}
	for _, sp := range []string{"127.0.0.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1", "127.0.1", "0x7f000001", "127.0.0.1.",
		"[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "127.000.000.001", "localhost", "LOCALHOST."} {
		rl = newRateLimiter()
		before, hb := cb.hitCount(), pdHits()
		c, err := net.DialTimeout("tcp", e.addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		fmt.Fprintf(c, "GET http://%s:%s/ HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", sp, port, sp, port)
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		code := 0
		fmt.Sscanf(line, "HTTP/1.1 %d", &code)
		time.Sleep(20 * time.Millisecond)
		rule := "no-rule"
		if pdHits()["block-backend"] != hb["block-backend"] {
			rule = "block-rule"
		}
		reach := "not-reached"
		if cb.hitCount() > before {
			reach = "REACHED"
		}
		got[sp] = fmt.Sprintf("%s status=%d backend=%s", rule, code, reach)
		t.Logf("%-22q %s", sp, got[sp])
	}
	// The same invariant for an IPv6 literal carrying a zone. Recorded as
	// "ipv6-unavailable" where the host has no IPv6 loopback.
	var hits6 int64
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Logf("LEAD not tested here: no IPv6 loopback on this host, so the zoned-literal rows did not run")
	} else {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt64(&hits6, 1)
			_, _ = w.Write([]byte("ok"))
		}), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		_, p6, _ := net.SplitHostPort(ln.Addr().String())
		policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "block-backend", DestFQDN: "::1", Action: ActionBlockPage}})
		for _, sp := range []string{"[::1]", "[0:0:0:0:0:0:0:1]", "[::1%25lo]", "[::1%lo]"} {
			rl = newRateLimiter()
			before, hb := atomic.LoadInt64(&hits6), pdHits()
			c, err := net.DialTimeout("tcp", e.addr, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			fmt.Fprintf(c, "GET http://%s:%s/ HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", sp, p6, sp, p6)
			line, _ := bufio.NewReader(c).ReadString('\n')
			c.Close()
			code := 0
			fmt.Sscanf(line, "HTTP/1.1 %d", &code)
			time.Sleep(20 * time.Millisecond)
			rule, reach := "no-rule", "not-reached"
			if pdHits()["block-backend"] != hb["block-backend"] {
				rule = "block-rule"
			}
			if atomic.LoadInt64(&hits6) > before {
				reach = "REACHED"
			}
			// Recorded, not baselined: the rows exist only where IPv6 loopback does.
			t.Logf("LEAD %-22q %s status=%d backend=%s", sp, rule, code, reach)
		}
	}
	pdCheckMapBaseline(t, "PATHDIFF_DIAL_BASELINE", got)
}

func pdCheckMapBaseline(t *testing.T, env string, got map[string]string) {
	path := os.Getenv(env)
	if path == "" {
		return
	}
	if os.Getenv("PATHDIFF_WRITE_BASELINE") == "1" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	for k, v := range got {
		if want[k] != v {
			t.Errorf("behaviour drift: %s\n  now      %s\n  baseline %s", k, v, want[k])
		}
	}
}
