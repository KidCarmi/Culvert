package main

import (
	"crypto/rand"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// CHAOS-68 round 3 — the two logout findings.
//
// The sweep's whole premise is that a Culvert cookie is self-contained, so the
// revocation list is the ONLY way to withdraw a live session's authority. Two
// defects sat directly on that claim and are pinned here.

// logoutTestSession mints a genuine, signed proxy session cookie and returns
// the cookie value together with the b64 payload the revocation list keys on
// (everything before the final dot — the split Decode itself performs).
func logoutTestSession(t *testing.T, sub string) (value, key string) {
	t.Helper()
	if !session.HasSigningKey() {
		initSessionSecret()
	}
	// The Jti MUST be unique per call, and this is the one line in the file
	// worth reading twice. `Exp` has second granularity and every other field
	// here is fixed, so a deterministic Jti makes the whole payload
	// byte-identical between two mints in the same wall-clock second — which
	// under `-count=2` means the second "freshly minted" cookie is exactly the
	// one the first run just revoked, and the precondition fails with
	// "session: revoked".
	//
	// That is the C5.1 defect reproduced inside the test written to check
	// revocation: `Session.Jti`'s own doc comment records that it was added
	// because "without Jti the (Sub, Role, Exp-in-seconds) tuple yielded a
	// byte-identical payload, identical b64, identical HMAC, and an
	// effectively-revoked cookie if any prior login of that tuple had been
	// revoked". A fixture that hard-codes the uniqueness field defeats the
	// mechanism it exists to provide (caught by CI's determinism lane, which
	// runs -count=2; a plain -shuffle=on run passes).
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		t.Fatalf("rand: %v", err)
	}
	raw, err := encodeSession(&Session{
		Sub: sub,
		Exp: time.Now().Add(time.Hour).Unix(),
		Jti: hex.EncodeToString(jti),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		t.Fatalf("encoded session has no signature separator: %q", raw)
	}
	return raw, raw[:dot]
}

func logoutRequestWithCookie(name, value string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/logout", http.NoBody)
	// Only Name=Value serializes on an inbound cookie; the rest satisfies gosec G124.
	req.AddCookie(&http.Cookie{
		Name: name, Value: value,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return req
}

// TestChaos68_ProxyLogoutRevokesTheSessionToken is the Codex P1 defect gate.
//
// authLogout used to call clearSessionCookie and nothing else. Clearing a
// cookie is a request to the browser, not a withdrawal of authority: the token
// stayed valid until its natural expiry, so a retained or stolen copy replayed
// against this node or any other. This is the PROXY session, which proxy.go's
// identity arm reads for identity- and group-scoped policy, so the window was
// an enforcement gap on the data plane.
//
// Verified FAILING against the pre-fix body (clear-only): the session still
// decodes after logout.
func TestChaos68_ProxyLogoutRevokesTheSessionToken(t *testing.T) {
	withChaos68Revocations(t)
	value, key := logoutTestSession(t, "chaos68-proxy-logout")

	if _, err := decodeSession(value); err != nil {
		t.Fatalf("precondition: freshly minted session must decode, got %v", err)
	}

	authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, value))

	if !sessionRevoked.IsRevoked(key) {
		t.Error("proxy logout did not revoke the session token: the cookie stays replayable until it expires")
	}
	if _, err := decodeSession(value); err == nil {
		t.Error("the logged-out proxy cookie still decodes, so it still carries authority")
	}
}

// TestChaos68_ForgedLogoutCookieCreatesNoRevocation pins the hardening that
// makes the fix above safe to apply.
//
// revokeSessionCookie used to read the expiry with a bare base64+JSON decode
// and revoke whatever it found, verifying nothing — while BOTH its call sites
// are logout handlers on the public allowlist. The revocation map is uncapped
// and each entry expires at a time taken FROM THE COOKIE, and every call
// marshals the whole list to disk and gossips it fleet-wide, so one
// unauthenticated caller could mint arbitrarily many effectively permanent
// entries across the fleet (CHAOS-63's write-amplification shape, aimed at the
// control that withdraws session authority).
//
// Verified FAILING against the pre-fix body: the forged payload is revoked.
func TestChaos68_ForgedLogoutCookieCreatesNoRevocation(t *testing.T) {
	withChaos68Revocations(t)
	if !session.HasSigningKey() {
		initSessionSecret()
	}
	// A well-formed payload with a far-future expiry and a signature that is
	// simply wrong — exactly what an unauthenticated caller can send.
	forgedPayload := "eyJzdWIiOiJjaGFvczY4LWZvcmdlZCIsImV4cCI6NDEwMjQ0NDgwMH0"
	forged := forgedPayload + ".not-a-valid-signature"

	if _, err := decodeSession(forged); err == nil {
		t.Fatal("precondition: the forged cookie must not verify")
	}

	authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, forged))
	apiAuthLogout(httptest.NewRecorder(), func() *http.Request {
		req := logoutRequestWithCookie(uiSessionCookieName, forged)
		req.Method = http.MethodPost
		return req
	}())

	if sessionRevoked.IsRevoked(forgedPayload) {
		t.Error("an unverified cookie was added to the revocation list: a public endpoint can now grow it without bound, on disk and across the fleet")
	}
}

// TestChaos68_AdminLogoutStillRevokes is the CONTROL.
//
// The cheapest way to pass the forged-cookie gate is to stop revoking at all,
// which would silently delete the logout half of the whole plane. Both logout
// paths must still revoke a GENUINE session.
func TestChaos68_AdminLogoutStillRevokes(t *testing.T) {
	withChaos68Revocations(t)
	value, key := logoutTestSession(t, "chaos68-admin-logout")

	req := logoutRequestWithCookie(uiSessionCookieName, value)
	req.Method = http.MethodPost
	apiAuthLogout(httptest.NewRecorder(), req)

	if !sessionRevoked.IsRevoked(key) {
		t.Error("admin logout stopped revoking: the hardening removed the behaviour it was meant to protect")
	}
}

// TestChaos68_UnwritablePathIsNotReportedDurable is the Codex P2 defect gate.
//
// LoadRevocations treated os.IsNotExist as a clean first run and returned,
// while Configured was already true — so revocationsAreDurable() claimed a
// revocation would survive a restart even though the parent directory did not
// exist and the first save was guaranteed to fail. The cluster API, the
// diagnostics row and the metric all stayed green until some later logout
// happened to be the first write.
//
// Verified FAILING against the pre-fix body (bare `return nil`): durable reads
// true on an unwritable path.
func TestChaos68_UnwritablePathIsNotReportedDurable(t *testing.T) {
	// resetDiagVerdictGlobals, NOT just the session-revocation record: this
	// test deliberately makes a save FAIL, and a failed durable write also
	// trips the STORAGE write-health plane (`Storage: DURABLE WRITE FAILED`),
	// which folds into the aggregate /api/diagnostics verdict. Resetting only
	// this sweep's own globals leaves that one degraded for the rest of the
	// binary, so a later test asserting `Verdict != diagFail` fails depending
	// on order — visible only under -shuffle/-count=2.
	//
	// CLAUDE.md records this exact trap from this exact sweep ("a diagFail-
	// capable contract row whose state is a PROCESS-GLOBAL must be registered
	// in resetDiagVerdictGlobals in the SAME change"), and these tests were
	// written without applying it. withChaos68Revocations additionally swaps
	// the global revocation list so entries do not leak between tests.
	resetDiagVerdictGlobals(t)
	withChaos68Revocations(t)

	// A path whose PARENT does not exist: the file is absent (the first-run
	// branch) and no write to it can ever succeed.
	bad := t.TempDir() + "/no-such-dir/revocations.json"
	prev := session.RevocationsPath()
	session.SetRevocationsPath(bad)
	t.Cleanup(func() { session.SetRevocationsPath(prev) })

	noteRevocationPersistenceConfigured(bad)
	if err := sessionRevoked.LoadRevocations(); err != nil {
		t.Fatalf("an absent file must not be a load error: %v", err)
	}

	if revocationsAreDurable() {
		t.Error("an unwritable revocations path was reported durable: the operator sees green until the first logout discovers the path is bad")
	}
}

// TestChaos68_WritablePathIsStillDurable is the CONTROL for the gate above.
//
// The cheapest way to pass it is to report every node non-durable, which would
// make the signal useless and page every correctly configured appliance. A good
// path must still read durable — and the probe must have actually created the
// file, which is what proves the claim was earned rather than assumed.
func TestChaos68_WritablePathIsStillDurable(t *testing.T) {
	resetDiagVerdictGlobals(t)
	withChaos68Revocations(t)

	good := t.TempDir() + "/revocations.json"
	prev := session.RevocationsPath()
	session.SetRevocationsPath(good)
	t.Cleanup(func() { session.SetRevocationsPath(prev) })

	noteRevocationPersistenceConfigured(good)
	if err := sessionRevoked.LoadRevocations(); err != nil {
		t.Fatalf("LoadRevocations on a good path: %v", err)
	}

	if !revocationsAreDurable() {
		t.Error("a writable revocations path was reported non-durable")
	}
	if _, err := os.Stat(good); err != nil {
		t.Errorf("the boot probe did not create the revocations file, so durability was assumed rather than proven: %v", err)
	}
}

// TestChaos68_ExistingFileOnUnwritablePathIsNotReportedDurable is the Codex P2
// gate from the second round, at the surface the finding named.
//
// TestChaos68_UnwritablePathIsNotReportedDurable above covers the ABSENT file.
// A file that already EXISTS and parses cleanly took LoadRevocations' success
// path and never attempted a write, so a node whose volume had since been
// remounted read-only reported durable here, on /api/diagnostics, on /metrics
// and on the cluster API — until some later logout became the first write and
// discovered otherwise. Same unearned green, one branch over.
//
// Root bypasses DAC, so this cannot run as root;
// internal/session's TestChaos68_ExistingFileIsProbedForWritability covers the
// same branch uid-independently, so it is never left unguarded.
//
// Verified FAILING against the pre-fix body (probe only under os.IsNotExist).
func TestChaos68_ExistingFileOnUnwritablePathIsNotReportedDurable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny writes")
	}
	// A failed durable write also trips the STORAGE write-health plane, which
	// folds into the aggregate /api/diagnostics verdict — see the comment on
	// TestChaos68_UnwritablePathIsNotReportedDurable.
	resetDiagVerdictGlobals(t)
	withChaos68Revocations(t)

	dir := t.TempDir()
	path := dir + "/revocations.json"
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	// Read-execute only: the file stays readable, no temp can be created
	// beside it, so the write fails exactly as on a read-only mount.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	prev := session.RevocationsPath()
	session.SetRevocationsPath(path)
	t.Cleanup(func() { session.SetRevocationsPath(prev) })

	noteRevocationPersistenceConfigured(path)
	if err := sessionRevoked.LoadRevocations(); err != nil {
		t.Fatalf("a readable revocations file must not be a load error: %v", err)
	}

	if revocationsAreDurable() {
		t.Error("an existing revocations file on an unwritable path was reported durable: the operator sees green until the first logout discovers the volume is read-only")
	}
}

// ---------------------------------------------------------------------------
// AU-45 (Codex round 4) — a repeat logout can REPAIR a failed persistence.
//
// AU-30 made logout authenticate the cookie before writing anything, which was
// right and closed a fleet-wide write-amplification hole. But it routed that
// through Decode, which REJECTS an already-revoked token — so a logout whose
// SaveRevocations failed transiently could never be repaired by retrying it:
// the second attempt was refused at the door, before reaching the save.
//
// On a standalone appliance that is terminal. Every other path that rewrites
// this file needs a PEER (SyncRevocations wants a Data Plane, the poll loop
// wants a Control Plane, the bundle merge wants a standby), and the default
// deployment has none — so the node stayed degraded until some unrelated
// revocation happened, and a restart brought the cookie back to life. AU-41's
// lesson one topology over.

// DEFECT: retrying logout after a failed save persists the revocation.
//
// Verified FAILING against the pre-fix body (session.Decode in place of
// session.DecodeForRevocation): the retry returns at the decode and the file
// is never written.
func TestChaos68_AU45_RepeatLogoutRepairsAFailedPersist(t *testing.T) {
	withChaos68Revocations(t)
	value, key := logoutTestSession(t, "chaos68-au45-repair")

	prev := session.RevocationsPath()
	t.Cleanup(func() { session.SetRevocationsPath(prev) })

	// The volume is unwritable when the user first logs out.
	session.SetRevocationsPath(filepath.Join(t.TempDir(), "no-such-dir", "revocations.json"))
	authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, value))

	if !sessionRevoked.IsRevoked(key) {
		t.Fatal("precondition: the first logout must revoke in memory")
	}
	if !sessionRevocationPersistDegraded.Load() {
		t.Fatal("precondition: the failed save must mark durability degraded")
	}

	// The transient fault clears and the user retries logout with the SAME
	// retained cookie — the only repair a standalone node has.
	good := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(good)
	authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, value))

	data, err := os.ReadFile(good) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("the retry did not write the revocations file, so a restart resurrects the logged-out cookie: %v", err)
	}
	if !strings.Contains(string(data), key) {
		t.Errorf("the revocations file does not carry the revoked token: %s", data)
	}
	if sessionRevocationPersistDegraded.Load() {
		t.Error("durability is still reported degraded after a save that landed")
	}
}

// CONTROL: a healthy node does NOT rewrite the file on every repeat logout.
//
// The cheapest way to pass the gate above is to persist unconditionally — which
// turns a once-per-cookie write into a per-request marshal, fsync, rename and
// fleet-wide gossip, driven by anyone replaying one valid cookie against a
// PUBLIC route. That is the write-amplification shape CHAOS-63 exists for,
// aimed at the control that withdraws session authority, so the repair must be
// gated on durability actually being in doubt.
//
// The instrument is a SENTINEL written into the file rather than deleting it:
// a missing file is itself a reason to write (AU-35), so os.Remove would create
// the very condition this control means to rule out.
func TestChaos68_AU45_ControlHealthyRepeatLogoutDoesNotRewrite(t *testing.T) {
	withChaos68Revocations(t)
	value, _ := logoutTestSession(t, "chaos68-au45-healthy")

	prev := session.RevocationsPath()
	t.Cleanup(func() { session.SetRevocationsPath(prev) })
	good := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(good)

	authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, value))
	if _, err := os.ReadFile(good); err != nil { // #nosec G304 -- test-owned temp path
		t.Fatalf("precondition: the first logout must persist: %v", err)
	}

	const sentinel = "chaos68-au45-sentinel"
	if err := os.WriteFile(good, []byte(sentinel), 0o600); err != nil {
		t.Fatalf("scribble sentinel: %v", err)
	}
	for i := 0; i < 3; i++ {
		authLogout(httptest.NewRecorder(), logoutRequestWithCookie(sessionCookieName, value))
	}

	data, err := os.ReadFile(good) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != sentinel {
		t.Error("a repeat logout rewrote the revocations file on a healthy node: every replay of one valid cookie now costs a marshal, an fsync and a fleet-wide gossip on a public route")
	}
}

// DecodeForRevocation keeps every check that makes the logout write safe, and
// drops only the one that blocks the repair.
func TestChaos68_AU45_DecodeForRevocationKeepsTheSafetyChecks(t *testing.T) {
	withChaos68Revocations(t)
	value, key := logoutTestSession(t, "chaos68-au45-decode")

	// A forged signature is refused — this is what stops an unauthenticated
	// caller minting revocation entries (AU-30), and it is the whole reason
	// this seam is safe to have at all.
	if _, err := session.DecodeForRevocation("eyJzdWIiOiJ4IiwiZXhwIjo0MTAyNDQ0ODAwfQ.not-a-signature"); err == nil {
		t.Error("DecodeForRevocation accepted a forged cookie: a public route can now mint revocations")
	}

	// An already-revoked cookie IS accepted — the defect this exists to fix.
	sessionRevoked.Revoke(key, time.Now().Add(time.Hour))
	if _, err := session.Decode(value); err == nil {
		t.Fatal("precondition: Decode must reject a revoked cookie")
	}
	if _, err := session.DecodeForRevocation(value); err != nil {
		t.Errorf("DecodeForRevocation rejected an already-revoked cookie, so the repair path is unreachable: %v", err)
	}

	// An expired cookie is still refused: it authenticates nothing, so
	// admitting it would only let a caller write entries for past expiries.
	expired, err := session.Encode(&session.Session{Sub: "chaos68-au45-expired", Exp: time.Now().Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatalf("mint expired: %v", err)
	}
	if _, err := session.DecodeForRevocation(expired); err == nil {
		t.Error("DecodeForRevocation accepted an expired cookie")
	}
}

// WALL: DecodeForRevocation has exactly one caller.
//
// It is a decode that deliberately ignores revocation, so a second caller
// reaching for it as an authentication primitive would be a silent bypass —
// admitting a session this node has already revoked, or one whose account was
// deleted. Behavioural coverage cannot see that; only an inventory can.
func TestChaos68_AU45_WallDecodeForRevocationHasOneCaller(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	callers := map[string]int{}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				sel, ok := m.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil || sel.Sel.Name != "DecodeForRevocation" {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "session" {
					callers[fn.Name.Name]++
				}
				return true
			})
			return false
		})
	}
	if scanned == 0 {
		t.Fatal("scanned no source files — the wall is vacuous")
	}

	// The seam's own doc comment points a future reader at this wall by name.
	// A stale reference there is the CHAOS-70 round-2 defect (a document naming
	// something that does not exist), and it is cheap to pin rather than trust.
	src, err := os.ReadFile("internal/session/session.go")
	if err != nil {
		t.Fatalf("read seam source: %v", err)
	}
	const self = "TestChaos68_AU45_WallDecodeForRevocationHasOneCaller"
	if !strings.Contains(string(src), self) {
		t.Errorf("DecodeForRevocation's doc comment does not name %s, so a reader told a wall protects it cannot find one", self)
	}
	if len(callers) != 1 || callers["revokeSessionCookie"] == 0 {
		t.Errorf("session.DecodeForRevocation must be called only by revokeSessionCookie, found %v — a decode that ignores revocation is an authentication bypass anywhere else", callers)
	}
}
