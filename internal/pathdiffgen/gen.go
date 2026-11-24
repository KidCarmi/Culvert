//go:build policy_pathdiff

package pathdiffgen

import (
	"fmt"
	"math/rand"
	"strings"
)

// Rule mirrors the JSON shape of the product's rule for the fields the
// differential drives. The harness copies it field by field; this package does
// not import the product type.
type Rule struct {
	Priority       int    `json:"priority"`
	Name           string `json:"name"`
	SourceIP       string `json:"sourceIP,omitempty"`
	SourceIdentity string `json:"sourceIdentity,omitempty"`
	SourceGroup    string `json:"sourceGroup,omitempty"`
	AuthSource     string `json:"authSource,omitempty"`
	DestFQDN       string `json:"destFQDN,omitempty"`
	DestCategory   string `json:"destCategory,omitempty"`
	DestCatGroup   string `json:"destCategoryGroup,omitempty"`
	Disabled       bool   `json:"disabled,omitempty"`
}

// Identity is what the fake identity provider returns for a request's user.
type Identity struct {
	Sub      string   `json:"sub"`
	Groups   []string `json:"groups,omitempty"`
	Provider string   `json:"provider"`
}

// Request is one logical request, asked of every path.
type Request struct {
	Authority  string    `json:"authority"`             // host[:port] as the client spells it
	RemoteAddr string    `json:"remote_addr,omitempty"` // "" = real socket from loopback
	Identity   *Identity `json:"identity,omitempty"`    // nil = no credentials
	Tag        string    `json:"tag"`                   // which perturbation produced it
	AliasOf    int       `json:"alias_of"`              // index of the base spelling in the case, -1 = none
}

// Op is a publication step applied before the requests of a Case are asked.
type Op struct {
	Kind string `json:"kind"` // "replace" | "disable" | "delete"
	Name string `json:"name,omitempty"`
}

// Case is one rule base, an optional publication sequence, and requests.
type Case struct {
	ID            string    `json:"id"`
	Stratum       string    `json:"stratum"`
	DefaultAction string    `json:"default_action"`
	Rules         []Rule    `json:"rules"`
	Ops           []Op      `json:"ops,omitempty"`
	Requests      []Request `json:"requests"`
}

var (
	labels = []string{"app", "api", "corp", "intra", "mail", "cdn", "files", "dev", "a1", "x-y", "w3"}
	tlds   = []string{"example", "test", "example.com", "example.org", "invalid"}
	users  = []string{"alice", "bob", "carol", "Dave", "eve@example.com"}
	groups = []string{"engineering", "finance", "ops", "Admins", "all staff"}
)

func name(r *rand.Rand) string {
	n := 1 + r.Intn(3)
	p := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		p = append(p, labels[r.Intn(len(labels))])
	}
	return strings.Join(append(p, tlds[r.Intn(len(tlds))]), ".")
}

func ip4(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d", 1+r.Intn(223), r.Intn(256), r.Intn(256), 1+r.Intn(254))
}

func ip6(r *rand.Rand) string {
	return fmt.Sprintf("2001:db8:%x::%x", r.Intn(0xffff), 1+r.Intn(0xfffe))
}

// destPattern returns a rule destination and one host spelling it is meant to
// cover. The generator states intent only; it does not predict the match.
func destPattern(r *rand.Rand) (pattern, host string) {
	switch r.Intn(9) {
	case 0, 1:
		h := name(r)
		return h, h
	case 2:
		h := name(r)
		return "*." + h, labels[r.Intn(len(labels))] + "." + h
	case 3:
		h := name(r)
		return "*." + h, h
	case 4:
		a := ip4(r)
		return a, a
	case 5:
		a := ip6(r)
		return a, "[" + a + "]"
	case 6:
		return "*", name(r)
	case 7:
		h := name(r)
		return strings.ToUpper(h[:1]) + h[1:] + ".", h
	default:
		a := ip4(r)
		return a[:strings.LastIndex(a, ".")] + ".0/24", a
	}
}

// Perturb returns alternative spellings of an authority's host. Each is a
// generic edit of the string. None is derived from product behaviour.
func perturb(r *rand.Rand, host string) (string, string) {
	bare := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	isV6 := strings.Contains(bare, ":")
	isV4 := !isV6 && strings.Count(bare, ".") == 3 && strings.Trim(bare, "0123456789.") == ""
	type ed struct {
		tag string
		f   func() string
	}
	eds := []ed{
		{"id", func() string { return host }},
		{"upper", func() string { return strings.ToUpper(host) }},
		{"mixcase", func() string {
			b := []byte(host)
			for i := range b {
				if i%2 == 0 && b[i] >= 'a' && b[i] <= 'z' {
					b[i] -= 32
				}
			}
			return string(b)
		}},
		{"port80", func() string { return host + ":80" }},
		{"port443", func() string { return host + ":443" }},
		{"port8443", func() string { return host + ":8443" }},
		{"port_empty", func() string { return host + ":" }},
		{"port0", func() string { return host + ":0" }},
		{"port_big", func() string { return host + ":65536" }},
		{"port_name", func() string { return host + ":http" }},
		{"sp_tail", func() string { return host + " " }},
		{"sp_head", func() string { return " " + host }},
		{"tab", func() string { return host + "\t" }},
		{"nul", func() string { return host + "\x00" }},
		{"userinfo", func() string { return "user@" + host }},
		{"slash", func() string { return host + "/x" }},
		{"backslash", func() string { return host + "\\x" }},
		{"query", func() string { return host + "?x" }},
		{"frag", func() string { return host + "#x" }},
		{"pct_dot", func() string { return strings.Replace(host, ".", "%2e", 1) }},
		{"pct_char", func() string {
			if host == "" {
				return host
			}
			return fmt.Sprintf("%%%02x", host[0]) + host[1:]
		}},
		{"star", func() string { return "*." + host }},
		{"empty", func() string { return "" }},
	}
	if !isV4 && !isV6 {
		eds = append(eds,
			ed{"dot_tail", func() string { return host + "." }},
			ed{"dot_tail2", func() string { return host + ".." }},
			ed{"dot_head", func() string { return "." + host }},
			ed{"dot_dbl", func() string { return strings.Replace(host, ".", "..", 1) }},
			ed{"sub", func() string { return labels[r.Intn(len(labels))] + "." + host }},
			ed{"parent", func() string {
				if i := strings.Index(host, "."); i >= 0 {
					return host[i+1:]
				}
				return host
			}},
			ed{"suffix_glue", func() string { return "evil" + host }},
			ed{"suffix_ext", func() string { return host + ".evil.test" }},
			ed{"fullwidth_dot", func() string { return strings.Replace(host, ".", "．", 1) }},
			ed{"ideo_dot", func() string { return strings.Replace(host, ".", "。", 1) }},
			ed{"idn_u", func() string { return "bücher." + host }},
			ed{"idn_a", func() string { return "xn--bcher-kva." + host }},
			ed{"idn_a_upper", func() string { return "XN--BCHER-KVA." + host }},
			ed{"idn_bad", func() string { return "xn--a-." + host }},
			ed{"underscore", func() string { return "_srv." + host }},
			ed{"homoglyph", func() string { return strings.Replace(host, "a", "а", 1) }},
			ed{"zwsp", func() string { return strings.Replace(host, ".", "​.", 1) }},
			ed{"longlabel", func() string { return strings.Repeat("a", 64) + "." + host }},
		)
	}
	if isV4 {
		var a, b, c, d int
		fmt.Sscanf(bare, "%d.%d.%d.%d", &a, &b, &c, &d)
		eds = append(eds,
			ed{"v4_mapped", func() string { return "[::ffff:" + bare + "]" }},
			ed{"v4_mapped_hex", func() string { return fmt.Sprintf("[::ffff:%02x%02x:%02x%02x]", a, b, c, d) }},
			ed{"v4_compat", func() string { return "[::" + bare + "]" }},
			ed{"v4_hex", func() string { return fmt.Sprintf("0x%x.%d.%d.%d", a, b, c, d) }},
			ed{"v4_octal", func() string { return fmt.Sprintf("0%o.%d.%d.%d", a, b, c, d) }},
			ed{"v4_zeropad", func() string { return fmt.Sprintf("%03d.%03d.%03d.%03d", a, b, c, d) }},
			ed{"v4_int", func() string { return fmt.Sprintf("%d", a<<24|b<<16|c<<8|d) }},
			ed{"v4_short", func() string { return fmt.Sprintf("%d.%d.%d", a, b, c<<8|d) }},
			ed{"v4_dot_tail", func() string { return bare + "." }},
			ed{"v4_neighbor", func() string { return fmt.Sprintf("%d.%d.%d.%d", a, b, c, (d+1)%255) }},
			ed{"v4_bracket", func() string { return "[" + bare + "]" }},
		)
	}
	if isV6 {
		eds = append(eds,
			ed{"v6_upper", func() string { return "[" + strings.ToUpper(bare) + "]" }},
			ed{"v6_expand", func() string { return "[" + strings.Replace(bare, "::", ":0:0:0:0:", 1) + "]" }},
			ed{"v6_leadzero", func() string { return "[" + strings.Replace(bare, "2001:", "2001:0", 1) + "]" }},
			ed{"v6_nobracket", func() string { return bare }},
			ed{"v6_zone", func() string { return "[" + bare + "%25eth0]" }},
			ed{"v6_zone_raw", func() string { return "[" + bare + "%eth0]" }},
			ed{"v6_dblbracket", func() string { return "[[" + bare + "]]" }},
		)
	}
	e := eds[r.Intn(len(eds))]
	return e.f(), e.tag
}

func remoteAddr(r *rand.Rand, ip string) (string, string) {
	port := 1024 + r.Intn(60000)
	if strings.Contains(ip, ":") {
		forms := []struct{ tag, s string }{
			{"v6", ip}, {"v6_upper", strings.ToUpper(ip)},
			{"v6_expand", strings.Replace(ip, "::", ":0:0:0:0:", 1)}, {"v6_zone", ip + "%eth0"},
		}
		f := forms[r.Intn(len(forms))]
		return fmt.Sprintf("[%s]:%d", f.s, port), f.tag
	}
	forms := []struct{ tag, s string }{
		{"v4", ip}, {"v4", ip}, {"v4_mapped", "[::ffff:" + ip + "]"},
	}
	f := forms[r.Intn(len(forms))]
	return fmt.Sprintf("%s:%d", f.s, port), f.tag
}

func srcPattern(r *rand.Rand) (pattern, ip string) {
	switch r.Intn(6) {
	case 0:
		a := ip4(r)
		return a, a
	case 1:
		a := ip4(r)
		return a[:strings.LastIndex(a, ".")] + ".0/24", a
	case 2:
		a := ip6(r)
		return a, a
	case 3:
		a := ip6(r)
		return a[:strings.LastIndex(a, "::")] + "::/48", a
	case 4:
		a := ip4(r)
		return "::ffff:" + a, a
	default:
		a := ip4(r)
		return a + "/32", a
	}
}

func spell(r *rand.Rand, s string) string {
	switch r.Intn(6) {
	case 0:
		return strings.ToUpper(s)
	case 1:
		return " " + s
	case 2:
		return s + " "
	default:
		return s
	}
}

func prios(r *rand.Rand, n int) []int {
	p := r.Perm(n * 3)[:n]
	for i := range p {
		p[i]++
	}
	return p
}

// defAction is always "deny". Under default allow a request that matches no
// rule is forwarded, which would make the harness dial generated hostnames. The
// allow default is exercised by the action-dispatch suite against a loopback
// backend instead.
func defAction(_ *rand.Rand) string { return "deny" }

// plain: literal lower-case names only. The reference can decide every request.
func genPlain(r *rand.Rand) Case {
	n := 1 + r.Intn(5)
	hosts := make([]string, 4)
	for i := range hosts {
		hosts[i] = name(r)
	}
	pr := prios(r, n)
	c := Case{DefaultAction: defAction(r)}
	for i := 0; i < n; i++ {
		d := hosts[r.Intn(len(hosts))]
		if r.Intn(6) == 0 {
			d = "*"
		}
		c.Rules = append(c.Rules, Rule{Priority: pr[i], Name: fmt.Sprintf("r%d", i), DestFQDN: d, Disabled: r.Intn(5) == 0})
	}
	for i := 0; i < 8; i++ {
		h := hosts[r.Intn(len(hosts))]
		if r.Intn(4) == 0 {
			h = name(r)
		}
		c.Requests = append(c.Requests, Request{Authority: h + ":443", Tag: "plain", AliasOf: -1})
	}
	return c
}

func genDest(r *rand.Rand) Case {
	n := 1 + r.Intn(4)
	pr := prios(r, n)
	c := Case{DefaultAction: defAction(r)}
	var insts []string
	for i := 0; i < n; i++ {
		p, h := destPattern(r)
		c.Rules = append(c.Rules, Rule{Priority: pr[i], Name: fmt.Sprintf("r%d", i), DestFQDN: p, Disabled: r.Intn(8) == 0})
		insts = append(insts, h)
	}
	for i := 0; i < 6; i++ {
		base := insts[r.Intn(len(insts))]
		bi := len(c.Requests)
		c.Requests = append(c.Requests, Request{Authority: base + ":443", Tag: "base", AliasOf: -1})
		alt, tag := perturb(r, base)
		if !strings.Contains(tag, "port") && r.Intn(2) == 0 {
			alt += ":443"
		}
		c.Requests = append(c.Requests, Request{Authority: alt, Tag: tag, AliasOf: bi})
	}
	return c
}

func genSrc(r *rand.Rand) Case {
	n := 1 + r.Intn(3)
	pr := prios(r, n)
	c := Case{DefaultAction: defAction(r)}
	var ips []string
	for i := 0; i < n; i++ {
		p, ip := srcPattern(r)
		c.Rules = append(c.Rules, Rule{Priority: pr[i], Name: fmt.Sprintf("r%d", i), SourceIP: p, DestFQDN: "*"})
		ips = append(ips, ip)
	}
	for i := 0; i < 8; i++ {
		ip := ips[r.Intn(len(ips))]
		if r.Intn(4) == 0 {
			ip = ip4(r)
		}
		ra, tag := remoteAddr(r, ip)
		c.Requests = append(c.Requests, Request{Authority: name(r) + ":443", RemoteAddr: ra, Tag: "src:" + tag, AliasOf: -1})
	}
	return c
}

func genIdentity(r *rand.Rand) Case {
	n := 1 + r.Intn(4)
	pr := prios(r, n)
	c := Case{DefaultAction: defAction(r)}
	for i := 0; i < n; i++ {
		ru := Rule{Priority: pr[i], Name: fmt.Sprintf("r%d", i), DestFQDN: "*"}
		switch r.Intn(5) {
		case 0:
			ru.SourceIdentity = spell(r, users[r.Intn(len(users))])
		case 1:
			ru.SourceGroup = spell(r, groups[r.Intn(len(groups))])
		case 2:
			ru.AuthSource = []string{"unauth", "test-idp", "TEST-IDP", "local", "exempt", "okta"}[r.Intn(6)]
		case 3:
			ru.SourceIdentity = users[r.Intn(len(users))]
			ru.SourceGroup = groups[r.Intn(len(groups))]
		default:
			ru.SourceGroup = groups[r.Intn(len(groups))]
			ru.DestFQDN = name(r)
		}
		c.Rules = append(c.Rules, ru)
	}
	for i := 0; i < 8; i++ {
		rq := Request{Authority: name(r) + ":443", Tag: "anon", AliasOf: -1}
		if r.Intn(5) != 0 {
			id := &Identity{Sub: spell(r, users[r.Intn(len(users))]), Provider: "test-idp"}
			for j := r.Intn(3); j > 0; j-- {
				id.Groups = append(id.Groups, spell(r, groups[r.Intn(len(groups))]))
			}
			rq.Identity, rq.Tag = id, "user"
		}
		c.Requests = append(c.Requests, rq)
	}
	return c
}

// stale: rules that reference objects which do not exist. An administrator can
// reach this state when a referenced category or group is deleted afterwards.
func genStale(r *rand.Rand) Case {
	c := Case{DefaultAction: defAction(r)}
	h := name(r)
	refs := []Rule{
		{DestCategory: "No Such Category"}, {DestCategory: "any"}, {DestCategory: "ANY"}, {DestCategory: " "},
		{DestCatGroup: "no-such-group"}, {DestCatGroup: "Any"}, {DestCategory: "Uncategorized"}, {DestCategory: "uncategorized"},
	}
	n := 1 + r.Intn(3)
	pr := prios(r, n+1)
	for i := 0; i < n; i++ {
		ru := refs[r.Intn(len(refs))]
		ru.Priority, ru.Name = pr[i], fmt.Sprintf("r%d", i)
		if r.Intn(2) == 0 {
			ru.DestFQDN = h
		}
		c.Rules = append(c.Rules, ru)
	}
	c.Rules = append(c.Rules, Rule{Priority: pr[n], Name: "fallback", DestFQDN: h})
	for i := 0; i < 4; i++ {
		a := h
		if i%2 == 1 {
			a = name(r)
		}
		c.Requests = append(c.Requests, Request{Authority: a + ":443", Tag: "stale", AliasOf: -1})
	}
	return c
}

// publish: a rule base followed by publication steps; requests are asked after
// the last step, on the live store and on a store reloaded from disk.
func genPublish(r *rand.Rand) Case {
	c := genPlain(r)
	for i := 1 + r.Intn(3); i > 0 && len(c.Rules) > 0; i-- {
		nm := c.Rules[r.Intn(len(c.Rules))].Name
		c.Ops = append(c.Ops, Op{Kind: []string{"disable", "delete", "replace"}[r.Intn(3)], Name: nm})
	}
	return c
}

func genCombo(r *rand.Rand) Case {
	c := genDest(r)
	for i := range c.Rules {
		switch r.Intn(4) {
		case 0:
			c.Rules[i].SourceIP = "127.0.0.1"
		case 1:
			c.Rules[i].SourceIP = "127.0.0.0/8"
		case 2:
			c.Rules[i].AuthSource = "unauth"
		}
	}
	return c
}

// Strata lists each stratum, its generator and its case count at scale 1.
var Strata = []struct {
	Name string
	Gen  func(*rand.Rand) Case
	N    int
}{
	{"plain", genPlain, 300}, {"dest", genDest, 900}, {"src", genSrc, 300}, {"identity", genIdentity, 400},
	{"stale", genStale, 150}, {"publish", genPublish, 250}, {"combo", genCombo, 300},
}

// Version changes whenever the generator's output for a given seed changes.
const Version = "pathdiffgen/1"

// Generate is deterministic in (seed, scale).
func Generate(seed string, scale float64) []Case {
	var out []Case
	for _, s := range Strata {
		var h int64
		for _, b := range []byte(seed + ":" + s.Name) {
			h = h*131 + int64(b)
		}
		r := rand.New(rand.NewSource(h))
		for i := 0; i < int(float64(s.N)*scale); i++ {
			c := s.Gen(r)
			c.ID, c.Stratum = fmt.Sprintf("%s_%s_%04d", s.Name, seed, i), s.Name
			out = append(out, c)
		}
	}
	return out
}
