//go:build socks5_e2e

package main

// cases.go — the case table and how each case is run and judged.
//
// Every case is run over SOCKS5 and then, as the same principal to the same
// destination, as an HTTP CONNECT. Each protocol probe is judged on its own
// (exact reply byte / HTTP status, request-log entry, metric deltas), and then
// the two verdicts are compared ("relation").

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

type modeName = string

const (
	modeEnforce modeName = "enforce"
	modeShadow  modeName = "shadow"
	modeLegacy  modeName = "legacy"
)

// logWant is a request-log expectation. Empty fields are not checked except
// where noted; a field set to "<empty>" must be empty.
type logWant struct {
	method, host, status, rule, action, identity, authSource string
	// forbidStatusPrefix: no entry for this method+host written by the probe
	// may carry a status with this prefix (shadow/legacy: "POLICY_").
	forbidStatusPrefix string
}

const mustBeEmpty = "<empty>"

// probeWant is what one protocol probe must produce.
type probeWant struct {
	obs     string
	log     *logWant
	deltas  map[string]float64 // exact metric deltas across the probe
	sumZero []string           // metric families whose summed delta must be 0
	absent  []string           // metric families that must not exist at all
	ldap    *ldapWant
}

type ldapWant struct {
	desc  string
	match func(ldapEvent) bool
	// sinceStart: search the whole event log of this mode, not only the probe.
	sinceStart bool
}

type relation int

const (
	relParity          relation = iota // same normalised verdict on both protocols
	relInspectContract                 // SOCKS5 refuses what CONNECT inspects; neither tunnels it uninspected
	relModeDifference                  // shadow/legacy: SOCKS5 is not policy-enforced, CONNECT is (expected gap)
	relDocumentedHTTP                  // a recorded difference, not parity (admin-console credential)
)

func (r relation) String() string {
	return [...]string{"same verdict", "inspect contract", "mode difference (expected)", "documented HTTP behaviour"}[r]
}

type tcase struct {
	id, title  string
	socksOpts  socksOpts
	httpCred   *cred
	target     func(u *upstreams) target
	socks      map[modeName]probeWant
	http       map[modeName]probeWant
	rel        map[modeName]relation
	extraNotes string
}

func echoTarget(host string) func(*upstreams) target {
	return func(u *upstreams) target { return target{host: host, port: u.echoPort} }
}

// ── Case builders ───────────────────────────────────────────────────────────

// policyCase is a destination decided by an access rule (or the default).
// enforceObs/status/action describe the enforce verdict; httpObs the CONNECT
// verdict (the same in every mode — CONNECT always enforces).
type policySpec struct {
	id, title     string
	user          *cred
	identity      string // expected identity in the log
	host          string
	tls           bool
	ipLiteral     bool
	rule          string // matched rule, "" for the default action
	enforceObs    string
	enforceStatus string
	enforceAction string
	verdict       string // enforce decisions-metric verdict: allow | block
	reason        string // rule | default | inspection_unsupported
	httpObs       string
	httpStatus    string
	httpAction    string
}

func policyCase(s policySpec) tcase {
	tc := tcase{
		id: s.id, title: s.title,
		socksOpts: socksOpts{cred: s.user},
		httpCred:  s.user,
		socks:     map[modeName]probeWant{},
		http:      map[modeName]probeWant{},
		rel:       map[modeName]relation{},
	}
	host := s.host
	tc.target = func(u *upstreams) target {
		t := target{host: host, port: u.echoPort, tls: s.tls}
		if s.tls {
			t.port = u.tlsPort
		}
		if s.ipLiteral {
			t.host = u.ip
		}
		return t
	}
	hits := map[string]float64{}
	if s.rule != "" {
		hits[ruleHitsKey(s.rule)] = 1
	}
	noHits := map[string]float64{}
	if s.rule != "" {
		noHits[ruleHitsKey(s.rule)] = 0
	}
	shadowVerdict := "allow"
	if s.verdict == "block" {
		shadowVerdict = "would_block"
	}
	passObs := obsTunnel
	if s.tls {
		passObs = obsUninspectedTLS // legacy/shadow: the documented gap enforce closes
	}
	ruleField := s.rule
	if ruleField == "" {
		ruleField = mustBeEmpty
	}
	actionField := s.enforceAction
	if actionField == "" {
		actionField = mustBeEmpty
	}

	enforce := probeWant{
		obs: s.enforceObs,
		log: &logWant{method: "SOCKS5", status: s.enforceStatus, rule: ruleField, action: actionField,
			identity: s.identity, authSource: idpProfileID},
		deltas: merge(map[string]float64{decisionsKey(modeEnforce, s.verdict, s.reason): 1}, hits),
	}
	shadow := probeWant{
		obs: passObs,
		log: &logWant{method: "SOCKS5", status: "OK", rule: mustBeEmpty, identity: s.identity, authSource: idpProfileID,
			forbidStatusPrefix: "POLICY_"},
		deltas: merge(map[string]float64{decisionsKey(modeShadow, shadowVerdict, s.reason): 1}, noHits),
	}
	legacy := probeWant{
		obs: passObs,
		log: &logWant{method: "SOCKS5", status: "OK", rule: mustBeEmpty, identity: s.identity, authSource: idpProfileID,
			forbidStatusPrefix: "POLICY_"},
		deltas: noHits,
		absent: []string{"culvert_socks5_policy_decisions_total", "culvert_socks5_requests_total"},
	}
	tc.socks[modeEnforce], tc.socks[modeShadow], tc.socks[modeLegacy] = enforce, shadow, legacy

	httpAction := s.httpAction
	if httpAction == "" {
		httpAction = mustBeEmpty
	}
	httpWant := probeWant{
		obs: s.httpObs,
		log: &logWant{method: "CONNECT", status: s.httpStatus, rule: ruleField, action: httpAction,
			identity: s.identity, authSource: idpProfileID},
	}
	for _, m := range []modeName{modeEnforce, modeShadow, modeLegacy} {
		tc.http[m] = httpWant
	}
	switch {
	case s.reason == "inspection_unsupported":
		tc.rel[modeEnforce] = relInspectContract
	default:
		tc.rel[modeEnforce] = relParity
	}
	for _, m := range []modeName{modeShadow, modeLegacy} {
		if verdictOf(s.httpObs) == "ALLOW" {
			tc.rel[m] = relParity
		} else {
			tc.rel[m] = relModeDifference
		}
	}
	return tc
}

func merge(a, b map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func allModes(w probeWant) map[modeName]probeWant {
	return map[modeName]probeWant{modeEnforce: w, modeShadow: w, modeLegacy: w}
}

func allRel(r relation) map[modeName]relation {
	return map[modeName]relation{modeEnforce: r, modeShadow: r, modeLegacy: r}
}

func buildCases() []tcase {
	cases := []tcase{
		policyCase(policySpec{id: "P1", title: "Allow rule (LDAP user alice)", user: credAlice, identity: aliceDN, host: hostAllow,
			rule: "allow-clean", enforceObs: obsTunnel, enforceStatus: "OK", enforceAction: "Allow", verdict: "allow", reason: "rule",
			httpObs: obsTunnel, httpStatus: "OK", httpAction: "Allow"}),
		policyCase(policySpec{id: "P2", title: "Drop rule", user: credAlice, identity: aliceDN, host: hostDrop,
			rule: "drop-rule", enforceObs: obsDropRST, enforceStatus: "POLICY_DROP", enforceAction: "Drop", verdict: "block", reason: "rule",
			httpObs: obsDropEOF, httpStatus: "POLICY_DROP", httpAction: "Drop"}),
		policyCase(policySpec{id: "P3", title: "Block_Page rule", user: credAlice, identity: aliceDN, host: hostBlock,
			rule: "block-page", enforceObs: obsReply(0x02), enforceStatus: "POLICY_BLOCK", enforceAction: "Block_Page", verdict: "block", reason: "rule",
			httpObs: obsStatus(403), httpStatus: "POLICY_BLOCK", httpAction: "Block_Page"}),
		policyCase(policySpec{id: "P4", title: "Redirect rule", user: credAlice, identity: aliceDN, host: hostRedirect,
			rule: "redirect-rule", enforceObs: obsReply(0x02), enforceStatus: "POLICY_REDIRECT", enforceAction: "Redirect", verdict: "block", reason: "rule",
			httpObs: obsStatus(302), httpStatus: "POLICY_REDIRECT", httpAction: "Redirect"}),
		policyCase(policySpec{id: "P5", title: "Allow rule with SSL action Inspect", user: credAlice, identity: aliceDN, host: hostInspect, tls: true,
			rule: "inspect-allow", enforceObs: obsReply(0x02), enforceStatus: "POLICY_BLOCK", enforceAction: "inspection_unsupported", verdict: "block", reason: "inspection_unsupported",
			httpObs: obsInspected, httpStatus: "OK", httpAction: "Allow"}),
		policyCase(policySpec{id: "P6", title: "No rule matched, default deny (rules exist)", user: credAlice, identity: aliceDN, host: hostUnlisted,
			enforceObs: obsReply(0x02), enforceStatus: "POLICY_DEFAULT_DENY", verdict: "block", reason: "default",
			httpObs: obsStatus(403), httpStatus: "POLICY_DEFAULT_DENY"}),
		policyCase(policySpec{id: "P7", title: "Group+authSource rule: alice in cn=engineering", user: credAlice, identity: aliceDN, host: hostGroup,
			rule: "group-eng-allow", enforceObs: obsTunnel, enforceStatus: "OK", enforceAction: "Allow", verdict: "allow", reason: "rule",
			httpObs: obsTunnel, httpStatus: "OK", httpAction: "Allow"}),
		policyCase(policySpec{id: "P8", title: "Group rule: bob (cn=finance) falls to Block_Page", user: credBob, identity: bobDN, host: hostGroup,
			rule: "group-others-block", enforceObs: obsReply(0x02), enforceStatus: "POLICY_BLOCK", enforceAction: "Block_Page", verdict: "block", reason: "rule",
			httpObs: obsStatus(403), httpStatus: "POLICY_BLOCK", httpAction: "Block_Page"}),
		policyCase(policySpec{id: "P9", title: "Identity rule: bob's DN allowed", user: credBob, identity: bobDN, host: hostIdentity,
			rule: "identity-bob-allow", enforceObs: obsTunnel, enforceStatus: "OK", enforceAction: "Allow", verdict: "allow", reason: "rule",
			httpObs: obsTunnel, httpStatus: "OK", httpAction: "Allow"}),
		policyCase(policySpec{id: "P10", title: "Identity rule: alice falls to Block_Page", user: credAlice, identity: aliceDN, host: hostIdentity,
			rule: "identity-others-block", enforceObs: obsReply(0x02), enforceStatus: "POLICY_BLOCK", enforceAction: "Block_Page", verdict: "block", reason: "rule",
			httpObs: obsStatus(403), httpStatus: "POLICY_BLOCK", httpAction: "Block_Page"}),
		policyCase(policySpec{id: "P11", title: "IPv4 literal (ATYP 0x01): no FQDN rule can match, default deny", user: credAlice, identity: aliceDN, ipLiteral: true,
			enforceObs: obsReply(0x02), enforceStatus: "POLICY_DEFAULT_DENY", verdict: "block", reason: "default",
			httpObs: obsStatus(403), httpStatus: "POLICY_DEFAULT_DENY"}),
	}
	// P1 is the first authenticated probe of each Culvert process: the
	// directory must have seen alice's real bind.
	p1 := cases[0].socks
	for _, m := range []modeName{modeEnforce, modeShadow, modeLegacy} {
		w := p1[m]
		w.ldap = &ldapWant{desc: "directory saw a successful bind as " + aliceDN, sinceStart: true,
			match: func(e ldapEvent) bool {
				return e.Op == "bind" && strings.EqualFold(e.DN, aliceDN) && e.Result == "success"
			}}
		p1[m] = w
	}
	// IPv4 literal: the ATYP counter moves (shadow/enforce).
	p11 := cases[len(cases)-1].socks
	for _, m := range []modeName{modeEnforce, modeShadow} {
		w := p11[m]
		w.deltas = merge(w.deltas, map[string]float64{`culvert_socks5_requests_total{atyp="ipv4"}`: 1})
		p11[m] = w
	}

	// ── Threat feed: refused in EVERY mode, before policy ───────────────────
	threat := tcase{
		id: "T1", title: "Feed-listed domain (with an Allow rule for it)",
		socksOpts: socksOpts{cred: credAlice}, httpCred: credAlice, target: echoTarget(hostThreat),
		socks: allModes(probeWant{
			obs: obsReply(0x02),
			log: &logWant{method: "SOCKS5", status: "THREAT_BLOCKED", rule: "threatfeed", action: "threat intelligence (e2e-local)",
				identity: aliceDN, authSource: idpProfileID},
			deltas:  map[string]float64{"culvert_threat_feed_blocked_total": 1, ruleHitsKey("threat-listed-allow"): 0},
			sumZero: []string{"culvert_socks5_policy_decisions_total"},
		}),
		http: allModes(probeWant{
			obs: obsStatus(403),
			log: &logWant{method: "CONNECT", status: "THREAT_BLOCKED", rule: "threatfeed", identity: aliceDN, authSource: idpProfileID},
		}),
		rel: allRel(relParity),
	}

	// ── Authentication (mode-independent) ───────────────────────────────────
	authFailLog := &logWant{method: "SOCKS5", host: mustBeEmpty, status: "AUTH_FAIL", action: "invalid_credentials", identity: mustBeEmpty}
	httpAuthFailLog := &logWant{method: "CONNECT", status: "AUTH_FAIL", identity: mustBeEmpty}
	wrongPW := tcase{
		id: "A1", title: "LDAP user, wrong password",
		socksOpts: socksOpts{cred: credAliceWrong}, httpCred: credAliceWrong, target: echoTarget(hostAllow),
		socks: allModes(probeWant{obs: obsAuthFail, log: authFailLog,
			deltas: map[string]float64{authFailKey("invalid_credentials"): 1, authFailKey("provider_not_supported_for_socks5"): 0},
			ldap: &ldapWant{desc: "directory rejected the bind as " + aliceDN + " (49)",
				match: func(e ldapEvent) bool {
					return e.Op == "bind" && strings.EqualFold(e.DN, aliceDN) && e.Result == "invalid_credentials"
				}},
		}),
		http: allModes(probeWant{obs: obsStatus(407), log: httpAuthFailLog}),
		rel:  allRel(relParity),
	}
	adminCred := tcase{
		id: "A2", title: "Admin-console credential (local account, not in the directory)",
		socksOpts: socksOpts{cred: credAdmin}, httpCred: credAdmin, target: echoTarget(hostAllow),
		socks: allModes(probeWant{obs: obsAuthFail, log: authFailLog,
			deltas: map[string]float64{authFailKey("invalid_credentials"): 1},
			ldap: &ldapWant{desc: "directory was asked for (uid=admin) and had no such entry",
				match: func(e ldapEvent) bool { return e.Op == "search" && e.Filter == "(uid=admin)" && e.Entries == 0 }},
		}),
		// CURRENT HTTP behaviour, recorded, not asserted as parity: HTTP proxy
		// Basic still accepts the local admin-console account (auth_source
		// "local"), and the Allow rule then admits it.
		http: allModes(probeWant{obs: obsTunnel,
			log: &logWant{method: "CONNECT", status: "OK", rule: "allow-clean", identity: adminUser, authSource: "local"}}),
		rel:        allRel(relDocumentedHTTP),
		extraNotes: "HTTP proxy Basic accepts the admin-console account (auth_source=local); SOCKS5 never does",
	}
	unknown := tcase{
		id: "A3", title: "Unknown user",
		socksOpts: socksOpts{cred: credUnknown}, httpCred: credUnknown, target: echoTarget(hostAllow),
		socks: allModes(probeWant{obs: obsAuthFail, log: authFailLog,
			deltas: map[string]float64{authFailKey("invalid_credentials"): 1}}),
		http: allModes(probeWant{obs: obsStatus(407), log: httpAuthFailLog}),
		rel:  allRel(relParity),
	}
	noAuth := tcase{
		id: "A4", title: "Client offers only NO-AUTH / sends no credential",
		socksOpts: socksOpts{methods: []byte{0x00}}, target: echoTarget(hostAllow),
		socks: allModes(probeWant{obs: obsNoMethod}),
		http:  allModes(probeWant{obs: obsStatus(407), log: httpAuthFailLog}),
		rel:   allRel(relParity),
	}
	return append(cases, threat, wrongPW, adminCred, unknown, noAuth)
}

// ── Running and judging ─────────────────────────────────────────────────────

type row struct {
	Mode, Case, Title, Protocol, Expected, Observed, Result string
	// Evidence is what was asserted besides the observed outcome (request
	// log, metric deltas, directory events); a row passes only if all held.
	Evidence string
	Problems []string
}

func (r *row) fail(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

type runner struct {
	c         *culvert
	u         *upstreams
	l         *ldapProc
	ldapStart int64 // directory event-log offset when this Culvert process started
	pe        probeEnv
	out       []row
}

func (rn *runner) runCase(tc tcase) {
	mode := rn.c.mode
	t := tc.target(rn.u)
	sw, hw := tc.socks[mode], tc.http[mode]

	sRow := rn.judge(mode, tc, "SOCKS5", sw, t, func() (string, error) {
		return socks5Probe(rn.c.socksAddr(), tc.socksOpts, t, rn.pe)
	})
	hRow := rn.judge(mode, tc, "HTTP CONNECT", hw, t, func() (string, error) {
		return connectProbe(rn.c.proxyAddr(), tc.httpCred, t, rn.pe)
	})

	rel := tc.rel[mode]
	r := row{Mode: mode, Case: tc.id, Title: tc.title, Protocol: "SOCKS5 vs CONNECT", Expected: rel.String()}
	sv, hv := verdictOf(sRow.Observed), verdictOf(hRow.Observed)
	r.Observed = sv + " / " + hv
	switch rel {
	case relParity:
		if sv != hv {
			r.fail("verdicts differ: SOCKS5 %s, CONNECT %s", sv, hv)
		}
	case relInspectContract:
		if sv != "REFUSE" || hv != "INSPECT" {
			r.fail("want SOCKS5 REFUSE (inspection_unsupported) and CONNECT INSPECT, got %s / %s", sv, hv)
		}
	case relModeDifference:
		if sv != "ALLOW" || hv == "ALLOW" {
			r.fail("want SOCKS5 ALLOW (policy not enforced in %s) and CONNECT not ALLOW, got %s / %s", mode, sv, hv)
		}
	case relDocumentedHTTP:
		if sv != "AUTH_REFUSED" || hv != "ALLOW" {
			r.fail("recorded behaviour changed: want SOCKS5 AUTH_REFUSED, CONNECT ALLOW; got %s / %s", sv, hv)
		}
		r.Expected += ": " + tc.extraNotes
	}
	if sRow.Observed == obsUninspectedTLS && mode == modeEnforce {
		r.fail("SOCKS5 tunnelled an inspection-requiring destination UNINSPECTED")
	}
	rn.finish(&r)
	rn.out = append(rn.out, sRow, hRow, r)
}

func (rn *runner) judge(mode modeName, tc tcase, proto string, w probeWant, t target, probe func() (string, error)) row {
	r := row{Mode: mode, Case: tc.id, Title: tc.title, Protocol: proto, Expected: w.obs}
	before, err := rn.c.scrape()
	if err != nil {
		r.fail("metrics before: %v", err)
	}
	logOff := fileSize(rn.c.reqLog)
	ldapOff := fileSize(rn.l.events)

	obs, perr := probe()
	if perr != nil {
		r.Observed = "error: " + perr.Error()
		r.fail("probe: %v", perr)
	} else {
		r.Observed = obs
		if obs != w.obs {
			r.fail("observed %s, expected %s", obs, w.obs)
		}
	}

	if w.log != nil {
		rn.checkLog(&r, w.log, t, logOff)
	}
	if w.ldap != nil {
		off := ldapOff
		if w.ldap.sinceStart {
			off = rn.ldapStart
		}
		if !awaitLDAP(rn.l.events, off, w.ldap.match) {
			r.fail("LDAP: %s — not observed", w.ldap.desc)
		}
	}
	if len(w.deltas)+len(w.sumZero)+len(w.absent) > 0 && before != nil {
		after, err := rn.c.scrape()
		if err != nil {
			r.fail("metrics after: %v", err)
		} else {
			checkMetrics(&r, w, before, after)
		}
	}
	r.Evidence = evidenceSummary(w, t)
	rn.finish(&r)
	return r
}

// evidenceSummary renders what judge asserted beyond the outcome, compactly.
func evidenceSummary(w probeWant, t target) string {
	var parts []string
	if lw := w.log; lw != nil {
		s := "log " + lw.status
		if lw.rule != "" && lw.rule != mustBeEmpty {
			s += " rule=" + lw.rule
		}
		if lw.action != "" && lw.action != mustBeEmpty {
			s += " action=" + lw.action
		}
		if lw.identity != "" && lw.identity != mustBeEmpty {
			s += " id=" + strings.SplitN(lw.identity, ",", 2)[0]
		}
		if lw.authSource != "" {
			s += " src=" + lw.authSource
		}
		if lw.forbidStatusPrefix != "" {
			s += ", no " + lw.forbidStatusPrefix + "* entry"
		}
		parts = append(parts, s)
	}
	keys := make([]string, 0, len(w.deltas))
	for k := range w.deltas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("Δ%s=%g", shortMetric(k), w.deltas[k]))
	}
	for _, f := range w.sumZero {
		parts = append(parts, "Σ"+shortMetric(f)+"=0")
	}
	for _, f := range w.absent {
		parts = append(parts, shortMetric(f)+" absent")
	}
	if w.ldap != nil {
		parts = append(parts, "LDAP: "+w.ldap.desc)
	}
	_ = t
	return strings.Join(parts, "; ")
}

func shortMetric(k string) string {
	r := strings.NewReplacer(
		"culvert_socks5_policy_decisions_total", "decisions",
		"culvert_policy_rule_hits_total", "rule_hits",
		"culvert_socks5_auth_failures_total", "socks5_auth_failures",
		"culvert_threat_feed_blocked_total", "threat_feed_blocked",
		"culvert_socks5_requests_total", "socks5_requests",
		`mode=`, "", `verdict=`, "", `reason=`, "", `rule=`, "", `atyp=`, "", `"`, "")
	return r.Replace(k)
}

func (rn *runner) checkLog(r *row, lw *logWant, t target, off int64) {
	wantHost := lw.host
	if wantHost == "" {
		wantHost = t.host
		if lw.method == "CONNECT" {
			wantHost = fmt.Sprintf("%s:%d", t.host, t.port)
		}
	}
	if wantHost == mustBeEmpty {
		wantHost = ""
	}
	e, all, ok := awaitEntry(rn.c.reqLog, off, func(e reqEntry) bool {
		return e.Method == lw.method && e.Host == wantHost && e.Status == lw.status
	})
	if !ok {
		var seen []string
		for _, x := range all {
			seen = append(seen, x.String())
		}
		r.fail("request log: no %s %q status=%s entry (new entries: %s)", lw.method, wantHost, lw.status, strings.Join(seen, "; "))
		return
	}
	field := func(name, want, got string) {
		switch {
		case want == "":
		case want == mustBeEmpty && got != "":
			r.fail("request log %s: want empty, got %q", name, got)
		case want != mustBeEmpty && want != got:
			r.fail("request log %s: want %q, got %q", name, want, got)
		}
	}
	field("ruleMatched", lw.rule, e.RuleMatched)
	field("actionTaken", lw.action, e.ActionTaken)
	field("identity", lw.identity, e.Identity)
	field("auth_source", lw.authSource, e.AuthSource)
	if lw.forbidStatusPrefix != "" {
		for _, x := range all {
			if x.Method == lw.method && x.Host == wantHost && strings.HasPrefix(x.Status, lw.forbidStatusPrefix) {
				r.fail("request log: unexpected %s entry in %s mode: %s", x.Status, r.Mode, x)
			}
		}
	}
}

func checkMetrics(r *row, w probeWant, before, after metrics) {
	for k, want := range w.deltas {
		got := after[k] - before[k]
		if math.Abs(got-want) > 1e-9 {
			r.fail("metric %s: delta %g, want %g", k, got, want)
		}
	}
	for _, fam := range w.sumZero {
		var sum float64
		for k, v := range after {
			if k == fam || strings.HasPrefix(k, fam+"{") {
				sum += v - before[k]
			}
		}
		if sum != 0 {
			r.fail("metric family %s moved by %g (feed must refuse before policy evaluation)", fam, sum)
		}
	}
	for _, fam := range w.absent {
		if after.hasFamily(fam) {
			r.fail("metric family %s present in %s mode", fam, r.Mode)
		}
	}
}

func (rn *runner) finish(r *row) {
	if len(r.Problems) == 0 {
		r.Result = "PASS"
	} else {
		r.Result = "FAIL"
	}
}

// ── Off-the-shelf clients and environment checks ────────────────────────────

func (rn *runner) runClientChecks(curl string) {
	mode := rn.c.mode
	add := func(id, title, proto, expected, observed string, problems ...string) {
		r := row{Mode: mode, Case: id, Title: title, Protocol: proto, Expected: expected, Observed: observed}
		for _, p := range problems {
			if p != "" {
				r.Problems = append(r.Problems, p)
			}
		}
		rn.finish(&r)
		rn.out = append(rn.out, r)
	}
	// golang.org/x/net/proxy, LDAP user → plain HTTP upstream.
	body, err := xnetProxyGet(rn.c.socksAddr(), credAlice, hostAllow, rn.u.httpPort)
	obs, prob := body, ""
	if err != nil {
		obs, prob = "error: "+err.Error(), "x/net/proxy GET failed: "+err.Error()
	} else if body != upstreamHTTPBody {
		prob = "unexpected body"
	}
	add("C1", "golang.org/x/net/proxy SOCKS5 client, alice -> "+hostAllow, "SOCKS5 (x/net)", upstreamHTTPBody, obs, prob)

	// x/net/proxy with the admin-console credential must fail at auth.
	_, err = xnetProxyGet(rn.c.socksAddr(), credAdmin, hostAllow, rn.u.httpPort)
	obs, prob = "error: <nil>", "admin-console credential accepted over SOCKS5"
	if err != nil {
		obs, prob = "error: "+shortErr(err), ""
		if !strings.Contains(err.Error(), "username/password authentication failed") {
			prob = "unexpected error (want RFC 1929 auth failure): " + err.Error()
		}
	}
	add("C2", "golang.org/x/net/proxy, admin-console credential", "SOCKS5 (x/net)", "error: username/password authentication failed", obs, prob)

	if curl == "" {
		add("C3", "curl --socks5-hostname (skipped: curl not found)", "SOCKS5 (curl)", "-", "skipped")
		return
	}
	out, code, stderr := curlSocks(curl, rn.c.socksAddr(), credAlice, hostAllow, rn.u.httpPort)
	prob = ""
	if code != 0 || out != upstreamHTTPBody {
		prob = fmt.Sprintf("curl exit %d body %q stderr %q", code, out, stderr)
	}
	add("C3", "curl --socks5-hostname, alice -> "+hostAllow, "SOCKS5 (curl)", "exit 0, "+upstreamHTTPBody, fmt.Sprintf("exit %d, %s", code, out), prob)

	out, code, stderr = curlSocks(curl, rn.c.socksAddr(), credAlice, hostThreat, rn.u.httpPort)
	prob = ""
	if code != 97 || !strings.Contains(stderr, "(2)") {
		prob = fmt.Sprintf("want curl exit 97 with SOCKS5 reply 2, got exit %d stderr %q body %q", code, stderr, out)
	}
	add("C4", "curl --socks5-hostname, alice -> "+hostThreat+" (feed-listed)", "SOCKS5 (curl)", "exit 97, reply (2)", fmt.Sprintf("exit %d, %s", code, stderr), prob)
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && strings.Contains(s[i:], "authentication") {
		return s[i+2:]
	}
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
