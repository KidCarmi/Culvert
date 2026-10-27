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
	"sync"
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
	// CHAOS-68's durability record (session_revocation_health.go) now composes
	// the same `session_revocation` row and feeds the replay-repair predicate
	// (revocationSaveOwed), so a degraded or vanished-file state leaked by a
	// CHAOS-68 gate would steer these gates into the wrong branch.
	resetSessionRevocationHealthForTest()
	t.Cleanup(resetSessionRevocationHealthForTest)
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

// sessionCookieFor builds the request cookie every gate below sends.
//
// Secure/HttpOnly/SameSite are set only to satisfy gosec G124: they are
// attributes of a RESPONSE cookie and are irrelevant on an inbound request
// cookie, where only Name=Value is serialized onto the wire. The repo's
// existing session tests set them for the same reason — keeping it in one
// helper means the rationale is stated once rather than at five call sites.
func sessionCookieFor(value string) *http.Cookie {
	return &http.Cookie{
		Name: uiSessionCookieName, Value: value,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

// logoutWith drives the REAL handler with the given cookie value and reports
// the status code.
func logoutWith(t *testing.T, cookie string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", http.NoBody)
	req.AddCookie(sessionCookieFor(cookie))
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
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", http.NoBody)
	req.AddCookie(sessionCookieFor(forgedCookie(t, 4096, "proof")))

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
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/auth/logout", http.NoBody)
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

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", http.NoBody)
	req.AddCookie(sessionCookieFor(cookie))
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
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", http.NoBody)
		req.AddCookie(sessionCookieFor(cookie))
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

// chaos73PeerEntry builds a peer-supplied revocation fixture. The token is an
// opaque test label, not a credential; passing it as a parameter keeps gosec's
// literal-value G101 heuristic off fixture strings.
func chaos73PeerEntry(label string, expiry int64) session.RevocationEntry {
	return session.RevocationEntry{Token: label, Expiry: expiry}
}

// C4. Cluster-wide revocation must still work. The cheapest way to pass D6/D7
// is to stop merging, which silently deletes fleet-wide session invalidation.
func TestChaos73_ControlLegitimateRemoteRevocationIsStillMerged(t *testing.T) {
	chaos73Setup(t)
	entries := []session.RevocationEntry{
		chaos73PeerEntry("peer-session-1", time.Now().Add(time.Hour).Unix()),
		chaos73PeerEntry("peer-session-2", time.Now().Add(2*time.Hour).Unix()),
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
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", http.NoBody)
		req.AddCookie(sessionCookieFor(forgedCookie(t, 64, "logfields")))
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

// A MAC-verified revocation of a LARGE genuine cookie is admitted past the key
// bound and persisted; it must still be admitted when the file is reloaded,
// or a restart with the same signing key resurrects the revoked session
// (Codex P1, PR #1591).
func TestChaos73_ControlLargeVerifiedRevocationSurvivesReload(t *testing.T) {
	chaos73Setup(t)
	session.SetRevocationsPath(filepath.Join(t.TempDir(), "revocations.json"))
	groups := make([]string, 0, 600)
	for i := 0; i < 600; i++ {
		groups = append(groups, fmt.Sprintf("CN=group-%04d,OU=Groups,DC=corp,DC=example,DC=com", i))
	}
	cookie := genuineCookie(t, "big-groups-reload", time.Hour, groups)
	if dot := strings.LastIndex(cookie, "."); dot <= session.MaxRevocationTokenLen {
		t.Fatalf("setup: payload is %d bytes, not above the %d bound — this control is vacuous", dot, session.MaxRevocationTokenLen)
	}
	if code := logoutWith(t, cookie); code != http.StatusOK {
		t.Fatalf("logout = %d; want 200", code)
	}

	// Simulate the restart: an empty list reloading the persisted file.
	session.Revoked.SwapForTest() // restored by chaos73Setup's cleanup
	if err := session.Revoked.LoadRevocations(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := session.Revoked.Tracked(); got != 1 {
		t.Fatalf("after reload entries = %d; want 1 — the large revocation was dropped on restart", got)
	}
	if _, err := session.Decode(cookie); err == nil {
		t.Error("the revoked large cookie decodes again after a restart")
	}

	// CONTROL: gossip keeps the bound for the very same entry.
	entries := session.Revoked.ExportRevocations()
	session.Revoked.SwapForTest()
	before := session.Refused(session.RevokeOversize)
	if added := session.Revoked.MergeRevocations(entries); added != 0 {
		t.Errorf("gossip admitted %d oversized entries; the remote path must keep the key bound", added)
	}
	if session.Refused(session.RevokeOversize) <= before {
		t.Error("control: the gossip refusal was not counted as oversize")
	}
}

// An untrusted entry may not claim an expiry no genuine session can have:
// such an entry is never swept until then, and enough of them fill the cap
// and lock out genuine remote revocations (Codex P1, PR #1591).
func TestChaos73_DefectRemoteFarFutureExpiryIsRefused(t *testing.T) {
	chaos73Setup(t)
	far := time.Now().Add(session.MaxSessionLifetime + 2*time.Hour).Unix()
	near := time.Now().Add(session.MaxSessionLifetime).Unix()
	added := session.Revoked.MergeRevocations([]session.RevocationEntry{
		{Token: "far-future", Expiry: far},
		{Token: "within-lifetime", Expiry: near},
	})
	if added != 1 {
		t.Fatalf("merged %d entries; want 1 (only the within-lifetime one)", added)
	}
	if got := session.Refused(session.RevokeFarFuture); got != 1 {
		t.Errorf("far_future refusals = %d; want 1", got)
	}
}

// The Control Plane's retained slice must not keep a backing array sized by
// the peer's request: the per-node cap bounds memory, not just length.
func TestChaos73_DefectControlPlaneRetainedCapacityIsBounded(t *testing.T) {
	prevDrops := clusterRevocationDrops.Load()
	t.Cleanup(func() { clusterRevocationDrops.Store(prevDrops) })
	agg := &revocationAggregator{perNode: map[string][]RevocationEntry{}}
	exp := time.Now().Add(time.Hour).Unix()
	big := make([]RevocationEntry, maxRevocationsPerNode*4)
	for i := range big {
		big[i] = RevocationEntry{Token: fmt.Sprintf("t%06d", i), Expiry: exp}
	}
	agg.Update("dp-1", big)
	if got := cap(agg.perNode["dp-1"]); got > maxRevocationsPerNode {
		t.Fatalf("retained capacity = %d; want at most %d", got, maxRevocationsPerNode)
	}
}

// THE CONTROL FOR THE RELOAD WAIVER, and it is what keeps the waiver narrow.
//
// ControlLargeVerifiedRevocationSurvivesReload above proves the persisted path
// admits an oversized GENUINE entry. On its own that is satisfied just as well
// by a waiver that admits any oversized entry at all, which would re-open the
// disk half of the original defect: a revocations file written by a build that
// predates this sweep holds attacker-chosen keys of arbitrary length, and
// LoadRevocations feeds it straight back in.
//
// So this pins that the waiver is AUTHENTICATED: only an entry carrying a
// valid provenance MAC (written by SaveRevocations for revocations this node
// verified itself) reloads past the key bound. Shape alone was the first
// version of the waiver and reviewers rejected it, because an external writer
// can produce a session-shaped payload with a matching expiry; every case
// below is MAC-less and must be refused, including the shaped ones. Verified
// failing against a build whose waiver returns true unconditionally — a
// mutation that passes every other CHAOS-73 gate, which is why this one is
// not redundant. (internal/session's provenance tests cover wrong-token and
// wrong-expiry MACs.)
func TestChaos73_ControlPersistedOversizeWaiverIsShapeGated(t *testing.T) {
	oversize := session.MaxRevocationTokenLen + 1

	// A session-shaped payload whose own Exp is far future, re-labelled on
	// disk with a near expiry: the two disagree, so it is not our shape.
	inner := session.Session{
		Sub: "mismatched", Provider: "local", Role: "admin",
		Exp: time.Now().Add(72 * time.Hour).Unix(), Jti: session.NewJti(),
		Groups: []string{strings.Repeat("g", oversize)},
	}
	raw, err := json.Marshal(&inner)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	shapedButMismatched := base64.RawURLEncoding.EncodeToString(raw)

	cases := []struct {
		name  string
		entry session.RevocationEntry
	}{
		{
			// Exactly what the vulnerable build wrote: opaque attacker bytes.
			name: "opaque attacker bytes",
			entry: session.RevocationEntry{
				Token:  strings.Repeat("A", oversize),
				Expiry: time.Now().Add(time.Hour).Unix(),
			},
		},
		{
			// Decodes as base64 but is not a Session at all.
			name: "valid base64, not a session",
			entry: session.RevocationEntry{
				Token:  base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("{", oversize))),
				Expiry: time.Now().Add(time.Hour).Unix(),
			},
		},
		{
			name:  "session-shaped but the expiry disagrees",
			entry: session.RevocationEntry{Token: shapedButMismatched, Expiry: time.Now().Add(time.Hour).Unix()},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chaos73Setup(t)
			path := filepath.Join(t.TempDir(), "revocations.json")
			session.SetRevocationsPath(path)

			if len(tc.entry.Token) <= session.MaxRevocationTokenLen {
				t.Fatalf("setup: token is %d bytes, not above the %d bound — this case is vacuous",
					len(tc.entry.Token), session.MaxRevocationTokenLen)
			}
			data, err := json.Marshal([]session.RevocationEntry{tc.entry})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := session.Revoked.LoadRevocations(); err != nil {
				t.Fatalf("load: %v", err)
			}
			if got := session.Revoked.Tracked(); got != 0 {
				t.Errorf("admitted %d oversized entries from the file; want 0 — the reload "+
					"waiver is no longer shape-gated and the disk half of the bound is gone", got)
			}
			if session.Refused(session.RevokeOversize) == 0 {
				t.Error("the refusal was not counted, so an operator has no signal that a " +
					"legacy file is being rejected")
			}
		})
	}
}

// ── CODEX ROUND 2: the retry, the accusation, and the peer's extra field ────

// A revocation whose durable write FAILED must be repaired by the browser's
// retry, not silently lost at the next restart.
//
// Persisting only when the list changes (CHAOS-70's rule) is what removes most
// of the amplification, but it also removes the second chance: the retry
// reports RevokeAlreadyKnown, the handler returns, and nothing rewrites the
// file unless an UNRELATED revocation happens later. Verified failing against
// the previous shape, where the no-change branch returned without saving.
func TestChaos73_DefectFailedPersistIsRetriedByTheReplay(t *testing.T) {
	chaos73Setup(t)
	resetSessionRevocationsDirtyForTest()
	t.Cleanup(resetSessionRevocationsDirtyForTest)

	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-dir")
	path := filepath.Join(missing, "revocations.json")
	session.SetRevocationsPath(path)

	cookie := genuineCookie(t, "persist-retry", time.Hour, nil)

	// First logout: the revocation is recorded in memory and the write fails.
	if code := logoutWith(t, cookie); code != http.StatusOK {
		t.Fatalf("logout = %d; want 200", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("setup: the file exists, so the write did not fail — this gate is vacuous")
	}
	if session.Revoked.Tracked() != 1 {
		t.Fatalf("the revocation is not in memory; want 1 entry")
	}

	// The volume comes back, and the browser retries the logout.
	if err := os.MkdirAll(missing, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if code := logoutWith(t, cookie); code != http.StatusOK {
		t.Fatalf("replayed logout = %d; want 200", code)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- temp path created by this test
	if err != nil {
		t.Fatalf("the failed write was never retried, so the revocation is lost at the next "+
			"restart and the revoked cookie authenticates again: %v", err)
	}
	var entries []session.RevocationEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("persisted %d entries; want 1", len(entries))
	}
}

// THE CONTROL for the retry. The cheapest way to pass the gate above is to
// save on EVERY logout, which restores the write amplification this sweep
// measured at 441 MB from 3.2 MB of input. After a SUCCESSFUL save, a replayed
// logout must write nothing at all.
//
// The instrument is a SENTINEL written over the file, not a deleted file.
// CHAOS-68 (PR #1437, reconciled onto this design) widened the replay repair
// to every provable durability doubt, and a backing file that VANISHED after
// it was written is one of them (AU-35): without the repair, a revocation in
// force in memory is gone at the next restart, the fail-open direction. So
// deleting the file now creates the very condition under which one repair
// write is correct, and the self-limiting repair (the write recreates the
// file, so the next replay finds nothing owed) is pinned by
// TestChaos68_AU45_ControlHealthyRepeatLogoutDoesNotRewrite and this gate's
// unconditional-save mutation alike. A sentinel keeps the file present and
// healthy, so any write at all — the unconditional save this control exists
// to catch — overwrites it.
func TestChaos73_ControlReplayedLogoutStillWritesNothingWhenClean(t *testing.T) {
	chaos73Setup(t)
	resetSessionRevocationsDirtyForTest()
	t.Cleanup(resetSessionRevocationsDirtyForTest)

	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)

	cookie := genuineCookie(t, "no-rewrite", time.Hour, nil)
	if code := logoutWith(t, cookie); code != http.StatusOK {
		t.Fatalf("logout = %d; want 200", code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("setup: the first save did not land: %v", err)
	}

	// Overwrite the file with a sentinel. A clean replay must NOT rewrite it.
	const sentinel = "chaos73-no-rewrite-sentinel"
	if err := os.WriteFile(path, []byte(sentinel), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	for range 3 {
		if code := logoutWith(t, cookie); code != http.StatusOK {
			t.Fatalf("replayed logout = %d; want 200", code)
		}
	}
	got, err := os.ReadFile(path) // #nosec G304 -- temp path created by this test
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != sentinel {
		t.Error("a replayed logout rewrote the file although nothing changed; the " +
			"no-change-no-write rule that removes the quadratic amplification is gone")
	}
}

// The refusal surfaces must not assert that a refusal IS an attack.
//
// A cookie signed under a previous session secret — after a rotation, or after
// a restart that minted a fresh random key — is a genuine cookie from an
// ordinary browser and is refused here as unverifiable. The counter cannot
// tell it from a forgery, so the operator-facing text must not claim it can
// (Codex P2, PR #1591; the same accusation-counter rule CHAOS-65 recorded).
func TestChaos73_RefusalSurfaceDoesNotAssertProbing(t *testing.T) {
	chaos73Setup(t)
	if code := logoutWith(t, forgedCookie(t, 32, "accusation")); code != http.StatusOK {
		t.Fatalf("logout = %d; want 200", code)
	}
	row := checkSessionRevocation()
	if row.Status != diagWarn {
		t.Fatalf("row status = %v; want warn after a refusal", row.Status)
	}
	text := row.Message + " " + row.OperatorAction
	if strings.Contains(text, "Ordinary traffic does not produce this") {
		t.Error("the row still asserts that ordinary traffic cannot produce a refusal; a " +
			"session-secret rotation makes every old cookie unverifiable and ordinary " +
			"browsers produce exactly this")
	}
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "rotation") && !strings.Contains(lower, "key change") {
		t.Error("the row does not name the benign cause, so an operator is sent hunting an " +
			"attacker after their own key rotation")
	}
	if !strings.Contains(lower, "could not verify") && !strings.Contains(lower, "unverifiable") {
		t.Error("the row should describe the cookie as unverifiable rather than as forged")
	}
}

// A peer's provenance field is never retained or re-broadcast.
//
// `Prov` is decodable on the SyncRevocations wire (the RPC carries raw JSON),
// and the per-node bounds measure the TOKEN, so a malfunctioning or hostile
// node can attach an arbitrarily large value that the Control Plane stores and
// fans to every other node every 3 s. Verified failing against the previous
// `kept = append(kept, e)`.
func TestChaos73_DefectPeerProvenanceIsNotRetained(t *testing.T) {
	agg := &revocationAggregator{perNode: map[string][]RevocationEntry{}}
	huge := strings.Repeat("P", 1<<20) // 1 MiB, well inside the inbound budget
	agg.Update("node-a", []RevocationEntry{{
		Token: "ordinary-token", Expiry: time.Now().Add(time.Hour).Unix(), Prov: huge,
	}})

	agg.mu.Lock()
	kept := agg.perNode["node-a"]
	agg.mu.Unlock()

	if len(kept) != 1 {
		t.Fatalf("retained %d entries; want 1 — the entry itself is legitimate", len(kept))
	}
	if kept[0].Prov != "" {
		t.Errorf("retained %d bytes of peer-supplied provenance; the per-node bound measures "+
			"the token only, so this is unbounded state the CP also re-broadcasts",
			len(kept[0].Prov))
	}
	if kept[0].Token != "ordinary-token" {
		t.Errorf("token = %q; the legitimate part of the entry must survive", kept[0].Token)
	}
}

// TestChaos73_WallSavesGoThroughTheCoordinator AST-walks every non-test file
// of package main and fails on a direct `sessionRevoked.SaveRevocations()`
// outside persistRevocations.
//
// The dirty-state retry is only as good as the set of writers that maintain
// it. The control-plane revocation-sync loop called SaveRevocations directly,
// so a failure there left the file behind memory with nothing recording that a
// retry was owed — and a later logout, finding nothing dirty, wrote nothing
// (CodeRabbit, PR #1591).
//
// Scoped to the PRIMITIVE rather than to one file, for the reason CHAOS-70
// recorded and this PR has now hit twice: the writer that escapes a claim
// lives in a file nobody thought to look at.
func TestChaos73_WallSavesGoThroughTheCoordinator(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(pkgSourceDir())
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	checked, offenders := 0, []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), name), nil, 0)
		if err != nil {
			continue // not this gate's job to police parse errors
		}
		checked++
		// The coordinator's body is the one place allowed to make the call,
		// so take its byte range and walk EVERYTHING else.
		//
		// Descending only into *ast.FuncDecl would miss a call inside a
		// package-level function literal (`var save = func() { ... }`): that
		// is a production writer, it bypasses the coordinator exactly as a
		// named function would, and the wall was blind to it (CodeRabbit,
		// PR #1591). The not-vacuous probe below keeps that honest.
		var skipLo, skipHi token.Pos
		for _, decl := range file.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if ok && d.Name.Name == "persistRevocations" && d.Body != nil {
				skipLo, skipHi = d.Body.Pos(), d.Body.End()
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if skipLo.IsValid() && call.Pos() >= skipLo && call.Pos() < skipHi {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SaveRevocations" {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Name != "sessionRevoked" {
				return true
			}
			offenders = append(offenders, fmt.Sprintf("%s:%d", name, fset.Position(call.Pos()).Line))
			return true
		})
	}
	if checked < 50 {
		t.Fatalf("only %d non-test files parsed; the selector is not matching the package "+
			"and this wall is vacuous", checked)
	}
	if len(offenders) > 0 {
		t.Errorf("direct sessionRevoked.SaveRevocations() outside persistRevocations: %v — "+
			"a save that bypasses the coordinator does not record that a retry is owed when "+
			"it fails", offenders)
	}
}

// TestChaos73_WallPersistHoldsOneLockOverSaveAndFlag pins that
// persistRevocations takes persistMu BEFORE it writes and before either
// dirty-flag store, so the save and the record of whether it landed are one
// critical section.
//
// Routing every writer through the coordinator (the wall above) orders the
// FILE: saveMu is held across snapshot-and-write, so the rename that lands
// last carries the newest snapshot. It says nothing about the flag, which
// lives out here in main and is stored after SaveRevocations has returned and
// released saveMu. A goroutine whose write succeeded can be descheduled right
// there and land its Store(false) after a later goroutine whose write FAILED
// stored true: the flag then reads "in step" while the file is behind memory,
// persistRevocationsIfDirty returns early, nothing ever repairs the file, and
// a restart resurrects the revoked session (CodeRabbit, PR #1591).
//
// Structural because the window is a deschedule between two statements:
// there is no deterministic way to drive it from a test, and a probabilistic
// one would pass against the defect most runs. Removing the Lock line — the
// cheapest wrong fix, and exactly the pre-fix shape — fails this gate.
// persistShape is what the wall below reads out of persistRevocations: the
// byte offset of each call it cares about, so their ORDER can be asserted.
type persistShape struct {
	lockAt          int   // earliest persistMu.Lock, -1 if absent
	saves           []int // sessionRevoked.SaveRevocations
	stores          []int // sessionRevocationsDirty.Store
	allUnlocks      []int // every persistMu.Unlock, however spelled
	deferredUnlocks map[int]bool
}

// readPersistShape walks one function body and records those offsets. Split
// out from the gate so each stays within the repository's complexity budget.
func readPersistShape(fset *token.FileSet, fn *ast.FuncDecl) persistShape {
	sh := persistShape{lockAt: -1, deferredUnlocks: map[int]bool{}}
	named := func(n ast.Node) (recv, name string, off int, ok bool) {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return "", "", 0, false
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return "", "", 0, false
		}
		id, isID := sel.X.(*ast.Ident)
		if !isID {
			return "", "", 0, false
		}
		return id.Name, sel.Sel.Name, fset.Position(call.Pos()).Offset, true
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		// An unlock that is NOT deferred releases the lock part-way through
		// the body, which is the defect wearing a lock.
		if d, isDefer := n.(*ast.DeferStmt); isDefer {
			if recv, name, off, ok := named(d.Call); ok && recv == "persistMu" && name == "Unlock" {
				sh.deferredUnlocks[off] = true
			}
			return true
		}
		recv, name, off, ok := named(n)
		if !ok {
			return true
		}
		switch {
		case recv == "persistMu" && name == "Lock":
			if sh.lockAt < 0 || off < sh.lockAt {
				sh.lockAt = off
			}
		case recv == "sessionRevoked" && name == "SaveRevocations":
			sh.saves = append(sh.saves, off)
		case recv == "sessionRevocationsDirty" && name == "Store":
			sh.stores = append(sh.stores, off)
		case recv == "persistMu" && name == "Unlock":
			sh.allUnlocks = append(sh.allUnlocks, off)
		}
		return true
	})
	return sh
}

func TestChaos73_WallPersistHoldsOneLockOverSaveAndFlag(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), "session_revocation_bounds.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse session_revocation_bounds.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "persistRevocations" {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("persistRevocations not found; this wall is watching a function that no " +
			"longer exists and proves nothing")
	}

	sh := readPersistShape(fset, fn)
	lockAt, saves, stores := sh.lockAt, sh.saves, sh.stores
	deferredUnlocks, allUnlocks := sh.deferredUnlocks, sh.allUnlocks

	// Not vacuous: the body must still contain the write and BOTH flag stores
	// this gate claims to be ordering.
	if len(saves) != 1 {
		t.Fatalf("found %d SaveRevocations calls in persistRevocations, want 1; the "+
			"coordinator no longer has the shape this wall asserts", len(saves))
	}
	if len(stores) != 2 {
		t.Fatalf("found %d sessionRevocationsDirty.Store calls, want 2 (the failure and "+
			"success arms); this wall is not ordering what it claims", len(stores))
	}

	if lockAt < 0 {
		t.Fatalf("persistRevocations never calls persistMu.Lock: the save and the " +
			"dirty-flag store are not one critical section, so a succeeded-then-" +
			"descheduled writer can clear the flag a failed writer set, and the file " +
			"stays behind memory with no retry owed")
	}
	for _, off := range append(append([]int{}, saves...), stores...) {
		if off < lockAt {
			t.Errorf("a save or dirty-flag store at offset %d precedes persistMu.Lock at %d; "+
				"everything the coordinator does must be under the one lock", off, lockAt)
		}
	}

	// Taking the lock is not enough: it has to still be HELD at the stores.
	// Locking only around the write and unlocking before the flag update is
	// the cheapest wrong fix, and it leaves the defect exactly intact.
	if len(deferredUnlocks) == 0 {
		t.Errorf("persistRevocations takes persistMu but never defers the Unlock; the " +
			"lock must be released at return, not part-way through the body")
	}
	for _, off := range allUnlocks {
		if !deferredUnlocks[off] {
			t.Errorf("persistMu.Unlock at offset %d is not deferred: the lock is dropped "+
				"before the dirty-flag store, so a succeeded-then-descheduled writer can "+
				"still clear the flag a failed writer set", off)
		}
	}
}

// TestChaos73_ControlConcurrentPersistsLeaveTheFileAndFlagAgreeing drives the
// coordinator from many goroutines at once and asserts the end state is
// honest: either the flag is dirty, or the file on disk carries every
// revocation still in memory.
//
// This is a CONTROL, not a defect gate. The race above is a deschedule window
// too narrow to hit reliably, so this passes on the pre-fix tree too; its job
// is to prove the lock did not introduce a deadlock or a lost write, and to
// give the race detector something real to inspect.
func TestChaos73_ControlConcurrentPersistsLeaveTheFileAndFlagAgreeing(t *testing.T) {
	chaos73Setup(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.json")
	session.SetRevocationsPath(path)

	const writers = 24
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			session.Revoked.Revoke(fmt.Sprintf("tok-%d", i), time.Now().Add(time.Hour))
			persistRevocations()
			persistRevocationsIfDirty()
		}(i)
	}
	wg.Wait()

	// A final persist from the quiescent state: whatever the concurrent phase
	// left behind, the file must now match memory.
	persistRevocations()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read revocations file: %v", err)
	}
	var onDisk []session.RevocationEntry
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("unmarshal revocations file: %v", err)
	}
	if len(onDisk) != writers {
		t.Errorf("file holds %d revocations, memory holds %d; a concurrent save lost a "+
			"revocation that a restart would then resurrect", len(onDisk), writers)
	}
	if sessionRevocationsDirty.Load() {
		t.Error("dirty after a successful quiescent persist: the flag would force an " +
			"endless retry of a write that already landed")
	}
}

// TestChaos73_WallPersistFailureLogIsSanitized pins that the persist-failure
// log passes its error through sanitizeLog rather than logging it bare.
//
// The error is object-derived and carries untrusted content: SaveRevocations
// marshals the revocation entries, whose tokens arrive over cluster gossip
// and from the on-disk file, so a marshal failure can fold a peer-supplied
// token into the message. Logged raw, that token can carry newlines and
// forge whole log lines (CWE-117). CodeQL traced three such flows to this one
// statement and posted alert 418 on PR #1591.
//
// sanitizeLog leads with strings.ReplaceAll, which is the barrier CodeQL
// recognises; %q keeps the value visibly one field. CodeQL itself only
// comments on NEW code, so without this gate a later edit back to a bare %v
// would land silently.
func TestChaos73_WallPersistFailureLogIsSanitized(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), "session_revocation_bounds.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse session_revocation_bounds.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "persistRevocations" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("persistRevocations not found; this wall proves nothing")
	}

	logs, sanitized := 0, 0
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Printf" {
			return true
		}
		logs++
		for _, arg := range call.Args {
			inner, ok := arg.(*ast.CallExpr)
			if !ok {
				continue
			}
			if id, ok := inner.Fun.(*ast.Ident); ok && id.Name == "sanitizeLog" {
				sanitized++
			}
		}
		return true
	})

	// Not vacuous: the coordinator must still log on the failure arm.
	if logs != 1 {
		t.Fatalf("found %d Printf calls in persistRevocations, want 1; this wall is "+
			"no longer watching the statement CodeQL flagged", logs)
	}
	if sanitized == 0 {
		t.Error("persistRevocations logs its error without sanitizeLog: a revocation " +
			"token supplied over gossip can reach the log through the marshal error " +
			"and forge log lines (CWE-117)")
	}
}

// ─── SEC-REVDIAG-1 — every untrusted-origin drop must reach the contract row ───
//
// checkSessionRevocation's `dropped` sum omitted session.RevokeFarFuture, the
// third refusal admitUntrustedLocked charges. A node that dropped ONLY
// far-future entries therefore took the diagOK branch and reported "no
// refusals, no drops" — on the one authenticated surface whose own doc comment
// says a dropped entry "means a session an operator deliberately killed may
// still authenticate, here or on another node" (CWE-778; the underlying drop is
// CWE-613).
//
// It is the one reason here with a BENIGN trigger, which is what makes the
// omission matter rather than being a hardening detail. admitUntrustedLocked
// refuses a gossiped entry whose expiry exceeds now + MaxSessionLifetime +
// revocationExpirySkew; MaxSessionLifetime is exactly 7 days and
// /api/session-timeout admits hours up to 168, so at the maximum SUPPORTED TTL
// the whole inter-node clock-skew budget is one hour. A cluster with
// session_timeout=168h and a peer more than an hour ahead drops that peer's
// legitimate revocations and, pre-fix, said revocation was healthy.

// TestChaos73_DefectFarFutureDropReachesTheContractRow is the defect gate: it
// drives the real gossip path, so it measures the sum the row actually
// computes rather than a counter poked directly.
func TestChaos73_DefectFarFutureDropReachesTheContractRow(t *testing.T) {
	chaos73Setup(t)

	far := time.Now().Add(session.MaxSessionLifetime + 2*time.Hour).Unix()
	if added := session.Revoked.MergeRevocations([]session.RevocationEntry{
		{Token: "far-future-from-a-skewed-peer", Expiry: far},
	}); added != 0 {
		t.Fatalf("gossip admitted %d far-future entries; the premise of this gate is that it drops them", added)
	}
	if got := session.Refused(session.RevokeFarFuture); got != 1 {
		t.Fatalf("far_future refusals = %d, want 1 — the drop did not happen and this gate is vacuous", got)
	}

	row := checkSessionRevocation()
	if row.Status != diagWarn {
		t.Errorf("row status = %v after a dropped remote revocation, want warn — the row reports a "+
			"revocation that did not take effect as healthy:\n  %s", row.Status, row.Message)
	}
	if strings.Contains(row.Message, "no drops") {
		t.Errorf("the row says %q while an entry was dropped", row.Message)
	}
	if !strings.Contains(row.Message, "1 session-revocation entries were dropped") {
		t.Errorf("the row does not count the drop: %q", row.Message)
	}
}

// TestChaos73_DefectEveryUntrustedDropReachesTheContractRow is the structural
// half: the row's sum must carry EVERY refusal admitUntrustedLocked charges, so
// a reason added later cannot be silently left out of the operator surface the
// way RevokeFarFuture was. Charging one of each through the real gossip path
// also proves the terms are not double-counted.
func TestChaos73_DefectEveryUntrustedDropReachesTheContractRow(t *testing.T) {
	chaos73Setup(t)

	// admitUntrustedLocked's three counted refusals, in the order it tests
	// them. RevokeExpired is deliberately NOT one of them — an already-expired
	// entry is not a refusal worth counting, and the row must not inflate on it.
	untrusted := []session.RevokeReason{session.RevokeOversize, session.RevokeFarFuture, session.RevokeCapacity}

	live := time.Now().Add(time.Hour).Unix()
	if added := session.Revoked.MergeRevocations([]session.RevocationEntry{
		{Token: strings.Repeat("O", session.MaxRevocationTokenLen+1), Expiry: live},
		{Token: "far-future", Expiry: time.Now().Add(session.MaxSessionLifetime + 2*time.Hour).Unix()},
		{Token: "already-expired", Expiry: time.Now().Add(-time.Hour).Unix()},
	}); added != 0 {
		t.Fatalf("gossip admitted %d entries; want 0", added)
	}

	var want int64
	for _, r := range untrusted {
		want += session.Refused(r)
	}
	want += clusterRevocationDropTotal()
	if want == 0 {
		t.Fatal("no refusal was charged — the gate is vacuous")
	}
	if got := session.Refused(session.RevokeExpired); got != 0 {
		t.Errorf("an already-expired gossip entry was charged as a refusal (%d); the row would inflate on ordinary expiry", got)
	}

	row := checkSessionRevocation()
	if !strings.Contains(row.Message, fmt.Sprintf("%d session-revocation entries were dropped", want)) {
		t.Errorf("the row's drop count does not equal the sum of every untrusted-origin refusal (%d):\n  %s\n"+
			"Every reason admitUntrustedLocked charges must be a term in checkSessionRevocation's sum", want, row.Message)
	}
}

// TestChaos73_DropSurfaceNamesTheBenignCause applies this file's own
// accusation rule (TestChaos73_RefusalSurfaceDoesNotAssertProbing) to the drop
// branch. The most likely cause of a far-future drop is clock skew inside the
// operator's own cluster, so the row must not send them hunting a hostile peer.
func TestChaos73_DropSurfaceNamesTheBenignCause(t *testing.T) {
	chaos73Setup(t)

	if added := session.Revoked.MergeRevocations([]session.RevocationEntry{
		{Token: "far-future", Expiry: time.Now().Add(session.MaxSessionLifetime + 2*time.Hour).Unix()},
	}); added != 0 {
		t.Fatalf("gossip admitted %d far-future entries; want 0", added)
	}
	row := checkSessionRevocation()
	lower := strings.ToLower(row.Message + " " + row.OperatorAction)
	if !strings.Contains(lower, "clock") {
		t.Error("the drop row does not name clock skew, the one benign cause of a far-future drop, so an " +
			"operator whose cluster lost time sync is sent looking for a hostile peer")
	}
	if !strings.Contains(lower, "expiry") && !strings.Contains(lower, "lifetime") {
		t.Error("the drop row does not name the expiry bound as a cause, so the far-future drop is " +
			"indistinguishable from an over-long key or a full cap")
	}
}

// TestChaos73_ControlCleanStateStillReportsHealthy is the negative control: the
// widened sum must not make an untouched node warn.
//
// "Untouched" means a node with durable persistence configured and working.
// CHAOS-68 (PR #1437, reconciled onto this row) deliberately WARNs on the
// unconfigured default, because there every revocation is lost on restart, so
// the clean baseline for the admission sum is a configured node whose file has
// been written — the only state in which no other branch has anything to say.
func TestChaos73_ControlCleanStateStillReportsHealthy(t *testing.T) {
	chaos73Setup(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)
	if persistRevocations() != persistLanded {
		t.Fatal("setup: the baseline save did not land")
	}
	row := checkSessionRevocation()
	if row.Status != diagOK {
		t.Errorf("row status = %v on a clean node, want ok: %s", row.Status, row.Message)
	}
	if !strings.Contains(row.Message, "no drops") {
		t.Errorf("clean row = %q, want the healthy text", row.Message)
	}
}
