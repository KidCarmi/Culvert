package main

// session_revocation_chaos_test.go — CHAOS-73 gates.
//
// The defect: `/api/auth/logout` is PUBLIC (correctly — an expired session
// must be able to clear its own cookie) and `revokeSessionCookie` inserted
// whatever cookie it was handed into the process-wide revocation list without
// verifying the HMAC, then rewrote the whole revocations file. An
// unauthenticated caller therefore chose the retained key, its length and its
// expiry; the entries were immortal, persisted, and gossiped fleet-wide.
//
// Every Defect* gate here was verified FAILING against the reintroduced
// pre-fix body (which `preFixRevokeSessionCookie` keeps verbatim, so the gates
// cannot go vacuous), and every Control* gate was verified failing against the
// cheapest wrong fix — refusing every revocation, which passes all nine defect
// gates while silently deleting logout as a security control.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// ── fixture ──────────────────────────────────────────────────────────────────

// chaos73Setup isolates every process-global this plane touches: the
// revocation list, the persistence path, and the counters + rate-limit window
// (a leaked armed window suppresses the log line a later gate asserts on).
func chaos73Setup(t *testing.T) {
	t.Helper()
	if !session.HasSigningKey() {
		initSessionSecret()
	}
	restore := session.Revoked.SwapForTest()
	t.Cleanup(restore)
	resetSessionRevokeCountersForTest()
	t.Cleanup(resetSessionRevokeCountersForTest)
	prev := session.RevocationsPath()
	t.Cleanup(func() { session.SetRevocationsPath(prev) })
	session.SetRevocationsPath("")
}

// forgedCookie builds an UNSIGNED cookie: a well-formed Session payload with
// `pad` bytes of attacker filler and a far-future expiry, plus junk where the
// HMAC belongs. This is what an unauthenticated caller can send.
func forgedCookie(t *testing.T, pad int, tag string) string {
	t.Helper()
	s := session.Session{
		Sub:      "forged-" + tag,
		Provider: "local",
		Exp:      time.Now().Add(100 * 365 * 24 * time.Hour).Unix(),
		Name:     strings.Repeat("A", pad),
	}
	payload, err := json.Marshal(&s)
	if err != nil {
		t.Fatalf("marshal forged session: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload) + ".not-a-valid-hmac"
}

// genuineCookie builds a cookie this appliance really signed.
func genuineCookie(t *testing.T, sub string, ttl time.Duration, groups []string) string {
	t.Helper()
	s := session.Session{
		Sub: sub, Provider: "local", Role: "viewer",
		Exp: time.Now().Add(ttl).Unix(), Jti: session.NewJti(), Groups: groups,
	}
	raw, err := session.Encode(&s)
	if err != nil {
		t.Fatalf("encode genuine session: %v", err)
	}
	return raw
}

// logoutWith drives the REAL handler with the given cookie value and reports
// the status code.
func logoutWith(t *testing.T, cookie string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	apiAuthLogout(rec, req)
	return rec.Code
}

// preFixRevokeSessionCookie is the pre-CHAOS-73 body, VERBATIM. It exists so
// the defect gates can be proven non-vacuous: if a future refactor made the
// forged cookie unparseable for some unrelated reason, every gate below would
// pass while proving nothing, and TestChaos73_DefectProof would catch it.
func preFixRevokeSessionCookie(cookieName string, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	dot := strings.LastIndex(c.Value, ".")
	if dot < 0 {
		return
	}
	b64part := c.Value[:dot]
	if payload, decErr := base64.RawURLEncoding.DecodeString(b64part); decErr == nil {
		var s Session
		if json.Unmarshal(payload, &s) == nil {
			sessionRevoked.Revoke(b64part, time.Unix(s.Exp, 0))
			if err := sessionRevoked.SaveRevocations(); err != nil {
				_ = err
			}
		}
	}
}

// ── DEFECT PROOF ─────────────────────────────────────────────────────────────

// TestChaos73_DefectProof pins that the forged cookie this suite sends really
// IS retained by the pre-fix body. Without it, a change that made the forgery
// inert would turn every defect gate below green while the defect was intact.
func TestChaos73_DefectProof(t *testing.T) {
	chaos73Setup(t)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: forgedCookie(t, 4096, "proof")})

	preFixRevokeSessionCookie(uiSessionCookieName, req)

	if got := session.Revoked.Tracked(); got != 1 {
		t.Fatalf("pre-fix body retained %d entries; want 1 — the forged cookie this suite "+
			"relies on is no longer reaching the insert, so every Defect* gate below is vacuous", got)
	}
}

// ── DEFECT GATES ─────────────────────────────────────────────────────────────

// D1. The core property: an unauthenticated caller cannot make this appliance
// retain anything.
func TestChaos73_DefectUnsignedCookieIsNotRetained(t *testing.T) {
	chaos73Setup(t)
	for i := 0; i < 5; i++ {
		if code := logoutWith(t, forgedCookie(t, 4096, fmt.Sprint(i))); code != http.StatusOK {
			t.Fatalf("logout %d = %d; want 200 (a refusal must not change the response)", i, code)
		}
	}
	if got := session.Revoked.Tracked(); got != 0 {
		t.Errorf("revocation entries = %d; want 0 — unsigned cookies were retained", got)
	}
	if got := sessionRevocationRefusedTotal(); got != 5 {
		t.Errorf("refusals counted = %d; want 5", got)
	}
	if got := session.Refused(session.RevokeUnsigned); got != 5 {
		t.Errorf("unsigned refusals = %d; want 5", got)
	}
}

// D2. The size of the forgery does not matter, and the gate drives a REAL
// net/http server: httptest.NewRequest can set a Cookie header the wire could
// never deliver, which would make this prove less than it claims
// (SEC-BOOTSTRAP-HOST-1's lesson).
func TestChaos73_DefectOversizeForgedCookieIsRefusedOverTheWire(t *testing.T) {
	chaos73Setup(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/logout", apiAuthLogout)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 384 KiB of filler encodes to a ~524 KB cookie, which net/http's default
	// 1 MiB header budget accepts. The pre-fix tree retained every byte.
	cookie := forgedCookie(t, 384*1024, "wire")
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/logout", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Cookie", uiSessionCookieName+"="+cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the wire refused a %d-byte cookie, so this gate cannot test what it claims: %v", len(cookie), err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if got := session.Revoked.Tracked(); got != 0 {
		t.Errorf("a %d-byte forged cookie retained %d entries; want 0", len(cookie), got)
	}
}

// D3. The write amplification. The pre-fix handler rewrote the ENTIRE file
// after every insert, so bytes written grew quadratically in request count
// (measured 17x → 34x → 68x → 135x as n doubled). A refused cookie must write
// NOTHING AT ALL.
func TestChaos73_DefectForgedCookiesWriteNothingToDisk(t *testing.T) {
	chaos73Setup(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)

	for i := 0; i < 40; i++ {
		logoutWith(t, forgedCookie(t, 16*1024, fmt.Sprint(i)))
	}
	if fi, err := os.Stat(path); err == nil {
		t.Errorf("40 unauthenticated requests wrote a %d-byte revocations file; want no file at all", fi.Size())
	} else if !os.IsNotExist(err) {
		t.Errorf("stat: %v", err)
	}
}

// D4. The attacker chose the EXPIRY, which is what made the junk immortal: the
// evictor keys on that same value, so a 100-year expiry can never be reclaimed.
// Once the MAC is verified the expiry is a value WE signed.
func TestChaos73_DefectAttackerChosenExpiryCannotPinAnEntry(t *testing.T) {
	chaos73Setup(t)
	logoutWith(t, forgedCookie(t, 64, "immortal"))
	if got := session.Revoked.Tracked(); got != 0 {
		t.Fatalf("entries = %d; want 0", got)
	}
	// Belt and braces: even an entry that somehow arrived must not outlive a
	// sweep if its expiry has passed, and must not be reclaimable only by a
	// read of that exact key (the standalone-node evictor gap, D8).
	session.Revoked.Sweep()
	if got := session.Revoked.Tracked(); got != 0 {
		t.Errorf("after sweep entries = %d; want 0", got)
	}
}

// D5. A replayed logout of a cookie already on the list must not rewrite the
// file. This is the other half of the quadratic term and it applies to
// AUTHENTICATED callers too, so authentication alone does not close it
// (CHAOS-70: a mutation reporting no change issues no write).
func TestChaos73_DefectReplayedLogoutWritesNothingFurther(t *testing.T) {
	chaos73Setup(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)

	cookie := genuineCookie(t, "replay", time.Hour, nil)
	logoutWith(t, cookie)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("a genuine logout must persist: %v", err)
	}
	first := fi.ModTime()
	firstSize := fi.Size()

	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 20; i++ {
		logoutWith(t, cookie)
	}
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !fi2.ModTime().Equal(first) || fi2.Size() != firstSize {
		t.Errorf("20 replayed logouts rewrote the file (mtime %v→%v, size %d→%d); want no further write",
			first, fi2.ModTime(), firstSize, fi2.Size())
	}
	if got := session.Revoked.Tracked(); got != 1 {
		t.Errorf("entries = %d; want 1", got)
	}
}

// D6. Cluster gossip is an UNTRUSTED origin: a peer chooses the key bytes.
// Authentication cannot reach this path, so it needs the structural bound.
func TestChaos73_DefectRemoteMergeIsBoundedInKeySize(t *testing.T) {
	chaos73Setup(t)
	exp := time.Now().Add(time.Hour).Unix()
	entries := []session.RevocationEntry{
		{Token: strings.Repeat("x", session.MaxRevocationTokenLen+1), Expiry: exp},
		{Token: strings.Repeat("y", 256*1024), Expiry: exp},
	}
	if added := session.Revoked.MergeRevocations(entries); added != 0 {
		t.Errorf("merged %d over-long remote entries; want 0", added)
	}
	if got := session.Refused(session.RevokeOversize); got != 2 {
		t.Errorf("oversize refusals = %d; want 2", got)
	}
}

// D7. ...and in entry COUNT. A peer sent 50,000 entries with no cap before.
func TestChaos73_DefectRemoteMergeIsBoundedInEntryCount(t *testing.T) {
	chaos73Setup(t)
	exp := time.Now().Add(time.Hour).Unix()
	entries := make([]session.RevocationEntry, session.MaxRevocationEntries+500)
	for i := range entries {
		entries[i] = session.RevocationEntry{Token: fmt.Sprintf("remote-%d", i), Expiry: exp}
	}
	added := session.Revoked.MergeRevocations(entries)
	if added > session.MaxRevocationEntries {
		t.Errorf("merged %d entries; want at most the %d cap", added, session.MaxRevocationEntries)
	}
	if got := session.Refused(session.RevokeCapacity); got == 0 {
		t.Error("capacity refusals = 0; a refused remote entry must be counted — it means " +
			"cluster-wide revocation is incomplete on this node")
	}
}

// D8. The missing evictor. Eviction was lazy-on-READ only, which never fires
// for the one key guaranteed never to be presented again — the cookie that
// just logged out — so an UN-CLUSTERED node had no evictor at all and the list
// (and its file, reloaded at every boot) grew for the life of the deployment.
func TestChaos73_DefectExpiredEntriesAreSweptWithoutBeingRead(t *testing.T) {
	chaos73Setup(t)
	past := time.Now().Add(-time.Hour)
	for i := 0; i < 50; i++ {
		session.Revoked.Revoke(fmt.Sprintf("dead-%d", i), past)
	}
	if got := session.Revoked.Tracked(); got != 50 {
		t.Fatalf("setup: entries = %d; want 50", got)
	}
	session.Revoked.Sweep()
	if got := session.Revoked.Tracked(); got != 0 {
		t.Errorf("after sweep entries = %d; want 0 — expired entries are reclaimable "+
			"only by reading their exact key", got)
	}
}

// D9. The Control Plane aggregator retained whatever a node pushed, uncapped,
// and MergedExcluding walks the union of every node's entries on EVERY sync
// call from EVERY node (each node syncs every 3 s).
func TestChaos73_DefectControlPlaneAggregatorIsBounded(t *testing.T) {
	before := clusterRevocationDropTotal()
	exp := time.Now().Add(time.Hour).Unix()

	push := make([]session.RevocationEntry, maxRevocationsPerNode+1000)
	for i := range push {
		push[i] = session.RevocationEntry{Token: fmt.Sprintf("cp-%d", i), Expiry: exp}
	}
	push = append(push, session.RevocationEntry{
		Token: strings.Repeat("z", session.MaxRevocationTokenLen+1), Expiry: exp})

	agg := &revocationAggregator{perNode: map[string][]RevocationEntry{}}
	agg.Update("node-a", push)
	agg.mu.Lock()
	kept := len(agg.perNode["node-a"])
	agg.mu.Unlock()

	if kept > maxRevocationsPerNode {
		t.Errorf("Control Plane retained %d entries from one node; want at most %d",
			kept, maxRevocationsPerNode)
	}
	if clusterRevocationDropTotal() == before {
		t.Error("dropped entries were not counted — a dropped revocation means a session an " +
			"operator killed may still authenticate on other nodes")
	}
}

// ── CONTROLS ─────────────────────────────────────────────────────────────────
//
// The cheapest way to pass every gate above is to refuse every revocation,
// which deletes logout as a security control. Each control below was verified
// FAILING against that shape, and PASSING against both the pre-fix and the
// fixed tree — which is what makes it a control rather than a second defect
// gate.

// C1. Logout must still actually revoke.
func TestChaos73_ControlGenuineLogoutStillRevokes(t *testing.T) {
	chaos73Setup(t)
	cookie := genuineCookie(t, "real-user", time.Hour, nil)
	if _, err := session.Decode(cookie); err != nil {
		t.Fatalf("setup: a freshly signed cookie must decode: %v", err)
	}
	if code := logoutWith(t, cookie); code != http.StatusOK {
		t.Fatalf("logout = %d; want 200", code)
	}
	if got := session.Revoked.Tracked(); got != 1 {
		t.Fatalf("entries = %d; want 1 — logout no longer revokes anything", got)
	}
	if _, err := session.Decode(cookie); err == nil {
		t.Error("the logged-out cookie still decodes; replaying it would keep working")
	}
	if got := sessionRevocationRefusedTotal(); got != 0 {
		t.Errorf("a genuine logout charged %d refusals; want 0", got)
	}
}

// C2. The case the PUBLIC route exists to serve: a genuine but EXPIRED cookie.
// Decode checks the MAC before the expiry, so verification must not break it —
// and it must not be charged to the probe counter, or ordinary next-day logout
// traffic buries the one signal an operator has (D1's counter).
func TestChaos73_ControlExpiredGenuineCookieStillLogsOutQuietly(t *testing.T) {
	chaos73Setup(t)
	cookie := genuineCookie(t, "stale-user", -time.Hour, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	apiAuthLogout(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", rec.Code)
	}
	if got := sessionRevocationRefusedTotal(); got != 0 {
		t.Errorf("an ordinary expired-cookie logout charged %d probe refusals; want 0", got)
	}
	// The cookie must still be cleared, or the browser keeps sending it.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == uiSessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the session cookie was not cleared")
	}
}

// TestChaos73_ExpiredIsStillVisibleInThePerReasonSeries is deliberately NOT
// part of the control above. It asserts behaviour that has no pre-fix
// counterpart (the counter did not exist), so folding it into a control made
// that control fail against the pre-fix tree — i.e. it was a defect gate
// wearing a control's label, which costs the control its whole purpose. Split
// out so the control is a true control.
func TestChaos73_ExpiredIsStillVisibleInThePerReasonSeries(t *testing.T) {
	chaos73Setup(t)
	logoutWith(t, genuineCookie(t, "stale-diag", -time.Hour, nil))
	if got := session.Refused(session.RevokeExpired); got != 1 {
		t.Errorf("per-reason expired count = %d; want 1 — excluded from the probe aggregate, "+
			"but an operator must still be able to see it", got)
	}
}

// C3. A refusal must not be an ORACLE. If a forged cookie produced a different
// status, body or Set-Cookie than a genuine one, an unauthenticated prober
// could use logout to test whether a captured cookie is still valid.
func TestChaos73_ControlRefusalIsNotAnOracle(t *testing.T) {
	chaos73Setup(t)

	run := func(cookie string) (int, string, int) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", http.NoBody)
		req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: cookie})
		rec := httptest.NewRecorder()
		apiAuthLogout(rec, req)
		return rec.Code, rec.Body.String(), len(rec.Result().Cookies())
	}
	gCode, gBody, gCookies := run(genuineCookie(t, "oracle", time.Hour, nil))
	fCode, fBody, fCookies := run(forgedCookie(t, 64, "oracle"))

	if gCode != fCode {
		t.Errorf("status differs: genuine=%d forged=%d — logout is a cookie-validity oracle", gCode, fCode)
	}
	if gBody != fBody {
		t.Errorf("body differs: genuine=%q forged=%q", gBody, fBody)
	}
	if gCookies != fCookies {
		t.Errorf("Set-Cookie count differs: genuine=%d forged=%d", gCookies, fCookies)
	}
}

// C4. Cluster-wide revocation must still work. The cheapest way to pass D6/D7
// is to stop merging, which silently deletes fleet-wide session invalidation.
func TestChaos73_ControlLegitimateRemoteRevocationIsStillMerged(t *testing.T) {
	chaos73Setup(t)
	entries := []session.RevocationEntry{
		{Token: "peer-session-1", Expiry: time.Now().Add(time.Hour).Unix()},
		{Token: "peer-session-2", Expiry: time.Now().Add(2 * time.Hour).Unix()},
	}
	if added := session.Revoked.MergeRevocations(entries); added != 2 {
		t.Fatalf("merged %d legitimate remote entries; want 2", added)
	}
	if !session.Revoked.IsRevoked("peer-session-1") {
		t.Error("a merged remote revocation is not enforced locally")
	}
	// ...and it must still be re-exportable, or the gossip chain breaks.
	if got := len(session.Revoked.ExportRevocations()); got != 2 {
		t.Errorf("exported %d entries; want 2", got)
	}
}

// C5. THE EXEMPTION. A genuine session whose cookie exceeds the untrusted-path
// key bound must STILL be revocable: the bound exists to stop a peer or a file
// growing the map, and refusing to revoke a real session is the one failure
// this control may not have. Same shape as CHAOS-63's configured-username
// exemption, and verified failing against a build that applies the bound on
// the local path too.
func TestChaos73_ControlVerifiedRevocationIsExemptFromTheKeyBound(t *testing.T) {
	chaos73Setup(t)
	// A real IdP can return a very large group set; Encode has no bound.
	groups := make([]string, 0, 600)
	for i := 0; i < 600; i++ {
		groups = append(groups, fmt.Sprintf("CN=group-%04d,OU=Groups,DC=corp,DC=example,DC=com", i))
	}
	cookie := genuineCookie(t, "big-groups", time.Hour, groups)
	dot := strings.LastIndex(cookie, ".")
	if dot <= session.MaxRevocationTokenLen {
		t.Fatalf("setup: payload is %d bytes, not above the %d bound — this control is vacuous",
			dot, session.MaxRevocationTokenLen)
	}
	if code := logoutWith(t, cookie); code != http.StatusOK {
		t.Fatalf("logout = %d; want 200", code)
	}
	if got := session.Revoked.Tracked(); got != 1 {
		t.Fatalf("entries = %d; want 1 — a real session with a large cookie became unrevocable", got)
	}
	if _, err := session.Decode(cookie); err == nil {
		t.Error("the large genuine cookie still decodes after logout")
	}
}

// C6. The bound must be DERIVED, not guessed: it is re-measured against the
// live Encode so a future Session field growth fails the build rather than
// silently pushing ordinary sessions onto the refused path.
func TestChaos73_ControlKeyBoundExceedsABrowserCarriableCookie(t *testing.T) {
	// The de-facto browser limit is 4096 bytes for the whole cookie, so a
	// session whose cookie fits in a browser must fit under the bound with
	// room to spare.
	groups := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		groups = append(groups, fmt.Sprintf("CN=group-%02d,OU=Groups,DC=corp,DC=example,DC=com", i))
	}
	s := session.Session{
		Sub: "a-fairly-long-subject@corp.example.com", Email: "a-fairly-long-subject@corp.example.com",
		Name: "A Fairly Long Display Name", Provider: "oidc", Role: "admin",
		Exp: time.Now().Add(time.Hour).Unix(), Jti: session.NewJti(), Groups: groups,
	}
	raw, err := session.Encode(&s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(raw) > 4096 {
		t.Skipf("fixture cookie is %d bytes, past the browser limit; not the case this control bounds", len(raw))
	}
	payload := len(raw[:strings.LastIndex(raw, ".")])
	if payload >= session.MaxRevocationTokenLen {
		t.Fatalf("a browser-carriable cookie encodes to a %d-byte key, at or above the %d bound — "+
			"ordinary sessions would be refused on the untrusted paths; raise MaxRevocationTokenLen",
			payload, session.MaxRevocationTokenLen)
	}
	if session.MaxRevocationTokenLen < 2*4096 {
		t.Errorf("MaxRevocationTokenLen = %d; want at least twice the 4096-byte browser cookie limit "+
			"so the bound keeps its derived margin", session.MaxRevocationTokenLen)
	}
}

// ── STRUCTURAL WALL ──────────────────────────────────────────────────────────

// TestChaos73_WallNoProductionCallerUsesTheUnverifiedPrimitive AST-walks every
// non-test file of package main and fails on any call to the UNVERIFIED
// Revoke primitive.
//
// Behavioural coverage cannot reach this. Every gate above keeps passing if a
// future handler — a second logout route, an SSO single-logout callback, a
// "revoke this session" admin action — inserts into the list without verifying
// the cookie, because those gates drive apiAuthLogout and nothing else. The
// defect this sweep closed was exactly that shape: one public handler reaching
// a primitive that trusts its input, with a comment asserting the verification
// had already happened somewhere else.
//
// This is CHAOS-70's lesson generalised one step. That wall AST-walked ONE
// FILE and its own note records the consequence: "this sweep's own note claimed
// the transaction lock covered EVERY persisted roster mutation while its
// structural wall AST-walks ui_auth.go only — the claim was broader than the
// wall and the mutator that escaped both lived in another file. Enumerate such
// a class from the PRIMITIVE, not from the file being edited." So this wall is
// scoped to the PRIMITIVE across the whole package, not to session.go.
func TestChaos73_WallNoProductionCallerUsesTheUnverifiedPrimitive(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var scanned int
	var offenders []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) // #nosec G304 -- test-local repo file
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scanned++
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Revoke" {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Name != "sessionRevoked" {
				return true
			}
			offenders = append(offenders,
				fmt.Sprintf("%s:%d", f, fset.Position(call.Pos()).Line))
			return true
		})
	}

	// Not-vacuous: if the glob or the parse stops matching, this wall silently
	// guards nothing. CHAOS-70's pre-existing wall earned its keep exactly here
	// — it fired three consecutive times as call sites moved.
	if scanned < 50 {
		t.Fatalf("scanned only %d production files; the selector has stopped matching and this "+
			"wall is vacuous", scanned)
	}
	if len(offenders) > 0 {
		t.Errorf("sessionRevoked.Revoke (the UNVERIFIED primitive) is called from production code at %v.\n"+
			"Use RevokeVerified, which authenticates the cookie first. A revocation key is the payload "+
			"half of a cookie this appliance signed, so anything that does not verify lets its caller "+
			"choose the retained key, its length and its expiry (CHAOS-73).", offenders)
	}
}

// TestChaos73_WallIsNotVacuous proves the wall's selector really does match
// the shape it forbids, by running the same predicate over a synthetic file.
// Without this, a typo in the receiver or method name would pass forever.
func TestChaos73_WallIsNotVacuous(t *testing.T) {
	const bad = `package main
func offender() { sessionRevoked.Revoke("k", someTime) }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", bad, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var hits int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Revoke" {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != "sessionRevoked" {
			return true
		}
		hits++
		return true
	})
	if hits != 1 {
		t.Fatalf("the wall's selector matched %d times on a file that definitely contains the "+
			"forbidden shape; the wall above cannot fail and is therefore vacuous", hits)
	}
}

// ── RUNBOOK WALLS ────────────────────────────────────────────────────────────

// TestChaos73_WallRunbookNamesRegisteredEndpoints mirrors the CHAOS-70 round-2
// gate for this sweep's runbook. That round found the roster runbook sending
// operators to a path that does not exist, so they got a 404 mid-incident;
// prose cannot be unit-tested but the endpoints it names can.
func TestChaos73_WallRunbookNamesRegisteredEndpoints(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "session-revocation-plane.md")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	registered := map[string]bool{}
	for i := range uiRoutes {
		registered[uiRoutes[i].Path] = true
	}
	found := 0
	for _, m := range regexp.MustCompile(`/api/[A-Za-z0-9/_-]+`).FindAllString(string(data), -1) {
		path := strings.TrimRight(m, "/-_")
		if registered[path] {
			found++
			continue
		}
		t.Errorf("the runbook names %q, which is not registered in uiRoutes — an operator following "+
			"these steps gets a 404", path)
	}
	if found == 0 {
		t.Fatal("the wall matched no /api/ paths in the runbook; its selector has gone stale")
	}
}

// TestChaos73_WallRunbookLogFieldsMatchTheEmitter pins the documented log line
// against what the code really emits.
//
// CHAOS-69 round 3 found its own runbook carrying a pre-rework example with a
// field the emitter never printed, so an operator building log parsing from the
// doc could not tell which bound had fired. A documented log line is a PARSING
// CONTRACT. This gate pins the CONTRACT (the prefix and the field names), not
// the layout, so how many examples the doc shows stays the author's call —
// an earlier draft of CHAOS-69's gate demanded both tiers and would have
// failed the build over formatting.
func TestChaos73_WallRunbookLogFieldsMatchTheEmitter(t *testing.T) {
	chaos73Setup(t)

	// Capture what the emitter really produces, via the shared helper.
	emitted := captureLogger(t, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", http.NoBody)
		req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: forgedCookie(t, 64, "logfields")})
		apiAuthLogout(httptest.NewRecorder(), req)
	})
	if !strings.Contains(emitted, "SESSION_REVOKE_REFUSED") {
		t.Fatalf("the emitter produced no SESSION_REVOKE_REFUSED line (%q); this gate cannot "+
			"compare against the runbook", emitted)
	}

	data, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "session-revocation-plane.md")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	doc := string(data)
	if !strings.Contains(doc, "SESSION_REVOKE_REFUSED") {
		t.Fatal("the runbook no longer documents the SESSION_REVOKE_REFUSED line; this wall is vacuous")
	}
	for _, field := range []string{"reason=", "bytes=", "total=", "action=none"} {
		if !strings.Contains(emitted, field) {
			t.Errorf("the emitter does not print %q, but the runbook documents it", field)
		}
		if !strings.Contains(doc, field) {
			t.Errorf("the runbook does not document the %q field the emitter prints — an operator "+
				"building log parsing from it would miss it", field)
		}
	}
}
