package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/lockout"
)

// ─── CHAOS-58 — the public admin-login endpoint's attacker-controlled username ─
//
// POST /api/auth/login is on the public allowlist. Every failed attempt copied
// the caller's username verbatim into the lockout maps, the in-memory audit
// ring and the DURABLE audit JSONL (a 50 MB rotating file keeping exactly one
// archive). Nothing bounded the value, so the 1 MiB body cap and the 60/min
// per-IP API rate limit together admitted ~60 MiB/min of attacker bytes from one
// unauthenticated client — enough to rotate the entire retained compliance
// record away in under two minutes, with no disk fault and no write error for
// the storage-health plane to notice.
//
// The gates below are split deliberately: the first three FAIL against the
// pre-fix handler; the rest are CONTROLS proving the bound did not break the
// login path it sits in front of (a guard that rejected everything would pass
// every defect gate while being far worse than the defect).

// chaos58ClientIP is the peer address jsonReq stamps on every request, and
// therefore the IP half of every lockout key these tests must inspect. Asserting
// against any other address would make the gates below pass vacuously.
const chaos58ClientIP = "127.0.0.1"

// chaos58WantStatus asserts the status WITHOUT dumping the response body.
// assertStatus echoes the body on failure, and the pre-fix handler answers an
// oversize login by reflecting the megabyte username back — re-verifying these
// defect gates against the old shape then produced megabytes of test output.
// A gate for a log-amplification defect must not be one itself.
func chaos58WantStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("status = %d, want %d (body suppressed: %d bytes)", w.Code, want, w.Body.Len())
	}
}

// chaos58Body builds a login POST carrying an n-byte username.
func chaos58Body(n int) *http.Request {
	return jsonReq(http.MethodPost, "/api/auth/login", map[string]string{
		"user": strings.Repeat("A", n),
		"pass": "irrelevant",
	})
}

// chaos58Roster seeds one real admin so the handler reaches the ordinary
// credential path (a node with no credential backend takes apiAuthLogin's
// pre-setup bypass, where every login succeeds and the control gates below
// would prove nothing). It is a local, untagged equivalent of the uie2e
// suite's seedUIRoster.
func chaos58Roster(t *testing.T, user, pass string) {
	t.Helper()
	snapshotCfgUIUsers(t)
	prevFile := cfg.uiUsersFile
	cfg.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	t.Cleanup(func() { cfg.SetUIUsersFile(prevFile) })

	if err := cfg.SetAuth("chaos58-bootstrap", "Chaos58-bootstrap-1!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() { _ = cfg.SetAuth("", "") })
	if !cfg.IsConfigured() {
		t.Fatal("cfg.IsConfigured() is false — the pre-setup bypass would admit every login")
	}
	if err := cfg.SetUIUser(user, pass, RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	initSecret(t)
}

// TestChaos58_OversizeUsernameRejectedBeforeAnyState is the primary gate: the
// oversize attempt is refused with 400 and counted.
func TestChaos58_OversizeUsernameRejectedBeforeAnyState(t *testing.T) {
	snapshotLoginLimiter(t)
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	before := loginOversizeRejected.Load()
	w := httptest.NewRecorder()
	apiAuthLogin(w, chaos58Body(1<<20))

	chaos58WantStatus(t, w, http.StatusBadRequest)
	if got := loginOversizeRejected.Load(); got != before+1 {
		t.Errorf("loginOversizeRejected = %d, want %d — the rejection is invisible to an operator", got, before+1)
	}
}

// TestChaos58_OversizeUsernameNeverReachesTheDurableAuditLog is the DEFECT gate
// for the compliance-record destruction. It measures the BYTES the login path
// commits to the durable audit JSONL, which is the resource the attack consumes.
//
// Pre-fix, each attempt wrote its whole username into the file: 8 x 512 KiB =
// 4 MiB, i.e. ~8% of the 50 MB rotation budget from eight requests. Post-fix the
// entries are O(1) and the whole run costs a few kilobytes.
func TestChaos58_OversizeUsernameNeverReachesTheDurableAuditLog(t *testing.T) {
	snapshotLoginLimiter(t)
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	restoreAudit := audit.ResetForTest()
	t.Cleanup(func() {
		_ = audit.Close()
		restoreAudit()
	})
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := audit.Init(path); err != nil {
		t.Fatalf("audit.Init: %v", err)
	}

	const attempts, nameBytes = 8, 512 * 1024
	for i := 0; i < attempts; i++ {
		w := httptest.NewRecorder()
		apiAuthLogin(w, chaos58Body(nameBytes))
		chaos58WantStatus(t, w, http.StatusBadRequest)
	}
	// Flush is synchronous in internal/audit (unlike reqlog/logsink), so the
	// file already reflects every entry by the time Add returns.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	// A generous ceiling: the eight bounded entries cost single-digit KiB, while
	// the pre-fix shape costs 4 MiB. Anything in between is still a regression.
	const ceiling = 64 * 1024
	if info.Size() > ceiling {
		t.Errorf("durable audit log grew to %d bytes from %d oversize login attempts (limit %d) — "+
			"attacker-chosen bytes are reaching the compliance record",
			info.Size(), attempts, ceiling)
	}
	// The attempt must still be RECORDED — bounding the bytes must not silently
	// delete the evidence that the admin plane is being probed.
	body, err := os.ReadFile(path) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(body), "auth.login.rejected") {
		t.Error("no auth.login.rejected entry in the audit log — the probe left no trace at all")
	}
}

// TestChaos58_OversizeUsernameCreatesNoLockoutEntry is the DEFECT gate for the
// heap axis: the pre-fix handler parked ~2 MiB per attempt in the two lockout
// maps for at least lockout.Window, which the janitor cannot sweep sooner.
func TestChaos58_OversizeUsernameCreatesNoLockoutEntry(t *testing.T) {
	snapshotLoginLimiter(t)
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	huge := strings.Repeat("A", 1<<20)
	for i := 0; i < lockout.MaxAttempts+3; i++ {
		w := httptest.NewRecorder()
		apiAuthLogin(w, chaos58Body(1<<20))
		chaos58WantStatus(t, w, http.StatusBadRequest)
	}
	// Nothing was recorded, so the limiter still offers a full budget — checked
	// through the limiter's own clamped key, which is where a pre-fix entry
	// would now live.
	if left := loginLimiter.AttemptsLeft(chaos58ClientIP, huge); left != lockout.MaxAttempts {
		t.Errorf("AttemptsLeft = %d, want %d — the rejected attempts still created limiter state", left, lockout.MaxAttempts)
	}
	for _, e := range loginLimiter.Snapshot() {
		if len(e.Username) > lockout.MaxUsernameKeyLen {
			t.Errorf("lockout snapshot exposed a %d-byte username", len(e.Username))
		}
	}
}

// TestChaos58_LimitBoundaryIsExact is the CONTROL that the guard rejects only
// what it must: a name of exactly maxUsernameLen goes through to the ordinary
// credential path, one byte more does not.
func TestChaos58_LimitBoundaryIsExact(t *testing.T) {
	snapshotLoginLimiter(t)
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	const adminUser, pass = "chaos58-admin", "Chaos58-pass-1!" // #nosec G101 -- test-only fixture
	chaos58Roster(t, adminUser, pass)

	w := httptest.NewRecorder()
	apiAuthLogin(w, chaos58Body(maxUsernameLen))
	if w.Code == http.StatusBadRequest {
		t.Errorf("a %d-byte username was rejected; the limit is inclusive", maxUsernameLen)
	}

	w = httptest.NewRecorder()
	apiAuthLogin(w, chaos58Body(maxUsernameLen+1))
	chaos58WantStatus(t, w, http.StatusBadRequest)
}

// TestChaos58_ConfiguredOversizeUsernameStillAuthenticates is the CONTROL for
// the availability half, and it is the one the first draft of this change got
// wrong (Codex review, PR #1320).
//
// The draft asserted that no local account could carry a name past the bound,
// because apiSetupComplete and the user-creation API cap at 64. They are not
// the only creation paths: `-user`/`auth.user` reach cfg.SetAuth and
// `--reset-password` reaches cfg.SetUIUser, and neither store bounds the name
// (validateAuthStartupCredentials validates only the password). So an over-long
// username can already be a valid persisted admin, and refusing it here would
// lock that operator out of their own admin UI on upgrade — a hardening change
// turned into an outage for the one person who has to fix it.
func TestChaos58_ConfiguredOversizeUsernameStillAuthenticates(t *testing.T) {
	snapshotLoginLimiter(t)
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	// A name well past maxUsernameLen, created through the store directly —
	// exactly what the CLI/YAML and --reset-password paths do.
	longUser := strings.Repeat("L", maxUsernameLen*3)
	const pass = "Chaos58-long-pass-1!" // #nosec G101 -- test-only fixture
	chaos58Roster(t, longUser, pass)

	w := httptest.NewRecorder()
	apiAuthLogin(w, jsonReq(http.MethodPost, "/api/auth/login", map[string]string{"user": longUser, "pass": pass}))
	chaos58WantStatus(t, w, http.StatusOK)
	if loginOversizeRejected.Load() != 0 {
		t.Error("a CONFIGURED account was counted as an oversize rejection")
	}

	// The wrong password for that same configured account must still be a
	// normal 401, not a 400 — the guard must not intercept it either.
	w = httptest.NewRecorder()
	apiAuthLogin(w, jsonReq(http.MethodPost, "/api/auth/login", map[string]string{"user": longUser, "pass": "wrong-" + pass}))
	chaos58WantStatus(t, w, http.StatusUnauthorized)

	// And an equally long name that names NOTHING is still refused — the
	// exemption must be account-scoped, not a blanket hole in the bound.
	w = httptest.NewRecorder()
	apiAuthLogin(w, chaos58Body(maxUsernameLen*3))
	chaos58WantStatus(t, w, http.StatusBadRequest)
	if loginOversizeRejected.Load() != 1 {
		t.Errorf("loginOversizeRejected = %d, want 1 — the unknown oversize name was not refused",
			loginOversizeRejected.Load())
	}
}

// TestChaos58_LoginNameConfiguredMatchesVerifyUIUser pins the invariant the
// exemption rests on: the guard may refuse only names VerifyUIUser could never
// authenticate. A divergence between the two resolutions is an admin lockout,
// so it is checked directly rather than inferred — including the legacy
// single-user case that Config.UIUserExists (roster-only) would have missed.
func TestChaos58_LoginNameConfiguredMatchesVerifyUIUser(t *testing.T) {
	snapshotCfgUIUsers(t)
	prevFile := cfg.uiUsersFile
	cfg.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	t.Cleanup(func() { cfg.SetUIUsersFile(prevFile) })

	const legacyUser, rosterUser = "chaos58-legacy", "chaos58-roster"
	const pass = "Chaos58-invariant-1!" // #nosec G101 -- test-only fixture
	if err := cfg.SetAuth(legacyUser, pass); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() { _ = cfg.SetAuth("", "") })
	if err := cfg.SetUIUser(rosterUser, pass, RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}

	for _, name := range []string{legacyUser, rosterUser} {
		if _, ok := cfg.VerifyUIUser(name, pass); !ok {
			t.Fatalf("VerifyUIUser(%q) = false; the fixture is wrong", name)
		}
		if !cfg.LoginNameConfigured(name) {
			t.Errorf("LoginNameConfigured(%q) = false while VerifyUIUser authenticates it — "+
				"the guard would refuse a real admin's login", name)
		}
	}
	if cfg.LoginNameConfigured("chaos58-nobody") {
		t.Error("LoginNameConfigured admitted a name that names no account")
	}
}

// TestChaos58_OrdinaryLoginUnaffected is the no-regression CONTROL: a real
// credential still authenticates and a wrong one still returns 401 and still
// feeds the lockout counter. A guard that broke either would pass every gate
// above while disabling admin access or brute-force protection.
func TestChaos58_OrdinaryLoginUnaffected(t *testing.T) {
	snapshotLoginLimiter(t)
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	const adminUser, pass = "chaos58-ok-admin", "Chaos58-ok-pass-1!" // #nosec G101 -- test-only fixture
	chaos58Roster(t, adminUser, pass)

	w := httptest.NewRecorder()
	apiAuthLogin(w, jsonReq(http.MethodPost, "/api/auth/login", map[string]string{"user": adminUser, "pass": pass}))
	assertStatus(t, w, http.StatusOK)

	before := loginLimiter.AttemptsLeft(chaos58ClientIP, adminUser)
	w = httptest.NewRecorder()
	apiAuthLogin(w, jsonReq(http.MethodPost, "/api/auth/login", map[string]string{"user": adminUser, "pass": "wrong-" + pass}))
	assertStatus(t, w, http.StatusUnauthorized)
	if after := loginLimiter.AttemptsLeft(chaos58ClientIP, adminUser); after >= before {
		t.Errorf("AttemptsLeft went %d -> %d on a failed login; the lockout counter stopped advancing", before, after)
	}
	if loginOversizeRejected.Load() != 0 {
		t.Error("an ordinary-length username was counted as oversize")
	}
}

// TestChaos58_RejectionIsOnTheMetricsSurface pins the operator's only signal
// that the endpoint is being probed: the 400 is otherwise invisible.
func TestChaos58_RejectionIsOnTheMetricsSurface(t *testing.T) {
	snapshotLoginLimiter(t)
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	w := httptest.NewRecorder()
	apiAuthLogin(w, chaos58Body(1<<20))
	chaos58WantStatus(t, w, http.StatusBadRequest)

	var buf strings.Builder
	liveFeedWritePrometheus(&buf)
	out := buf.String()
	if !strings.Contains(out, "# TYPE culvert_login_oversize_rejected_total counter") {
		t.Error("culvert_login_oversize_rejected_total is missing its TYPE line")
	}
	if !strings.Contains(out, "culvert_login_oversize_rejected_total 1") {
		t.Errorf("counter not exposed with the observed value; exposition:\n%s", out)
	}
}

// TestChaos58_TruncateForAuditMarksWhatItCut keeps a truncated audit actor from
// ever being mistaken for the value that was actually submitted.
func TestChaos58_TruncateForAuditMarksWhatItCut(t *testing.T) {
	if got := truncateForAudit("short"); got != "short" {
		t.Errorf("truncateForAudit mutated a value within the bound: %q", got)
	}
	got := truncateForAudit(strings.Repeat("A", 5000))
	if !strings.Contains(got, "truncated, 5000 bytes") {
		t.Errorf("truncation is not self-describing: %q", got)
	}
	if len(got) > loginAuditActorMax+64 {
		t.Errorf("truncated value is %d bytes, want the bound plus a short marker", len(got))
	}
	// A multi-byte rune straddling the cut must not leave a half-encoded rune,
	// at every width and every alignment (the 4-byte case is what a 3-step
	// boundary search gets wrong).
	for _, r := range []string{"a", "é", "€", "𝄞"} {
		for pad := 0; pad < 4; pad++ {
			multi := truncateForAudit(strings.Repeat("x", pad) + strings.Repeat(r, 200))
			body, _, _ := strings.Cut(multi, "…")
			if string([]rune(body)) != body {
				t.Errorf("rune %q pad %d: truncateForAudit cut inside a rune", r, pad)
			}
		}
	}
	// Invalid UTF-8 must still come back bounded rather than empty.
	if got := truncateForAudit(strings.Repeat("\x80", 500)); !strings.HasPrefix(got, "\x80") {
		t.Errorf("invalid UTF-8 truncated to an unexpected shape: %q", got[:min(len(got), 16)])
	}
}

// TestChaos58_OversizeLogLineIsRateLimited pins that the flood cannot buy log
// bandwidth: the whole defect was an attacker turning one request into a large
// write, so the mitigation must not re-open that on the process log.
func TestChaos58_OversizeLogLineIsRateLimited(t *testing.T) {
	resetLoginOversizeStateForTest()
	t.Cleanup(resetLoginOversizeStateForTest)

	if !noteLoginOversizeLog() {
		t.Fatal("the first rejection must log immediately (onset visibility)")
	}
	for i := 0; i < 100; i++ {
		if noteLoginOversizeLog() {
			t.Fatalf("a second log line was permitted %d rejections into the window", i+2)
		}
	}
}
