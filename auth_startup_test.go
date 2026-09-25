package main

// auth_startup_test.go — P4.4 / S1 coverage for the extracted auth
// startup slice.
//
// Resolver tests are pure (no globals touched). Loader tests mutate
// the package-global `cfg` singleton; isolation is via whitebox
// snapshot+restore of the auth-related fields (ProxyPort, UIPort,
// user, passHash, uiUsers, uiUsersFile) under cfg.mu.Lock.
//
// **Do NOT** restore via production APIs like cfg.SetAuth("", "") +
// cfg.DeleteUIUser(name): those go through guardrails (e.g.
// "cannot delete the last admin user") that depend on the *current*
// cfg.uiUsers state, which is non-deterministic under -shuffle=on
// -count=2. snapshotAuthGlobals captures the unexported fields by
// direct field access and restores them by direct assignment, so
// cleanup is structurally deterministic regardless of test order.

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/goccy/go-yaml"
)

var authStartupLoggerMu sync.Mutex

func ensureAuthStartupTestLogger(t *testing.T) {
	t.Helper()
	authStartupLoggerMu.Lock()
	defer authStartupLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// snapshotAuthGlobals captures every cfg field the loadAuth slice
// touches and restores them on t.Cleanup. It bypasses production
// APIs (SetAuth, SetUIUser, DeleteUIUser, SetUIUsersFile) so cleanup
// cannot be foiled by production guardrails — specifically the
// "cannot delete the last admin user" check in DeleteUIUser, which
// fails non-deterministically under -shuffle=on -count=2 when other
// tests' residual cfg.uiUsers state makes the seeded user the last
// admin.
//
// The snapshot deep-copies cfg.uiUsers (map + per-user uiAdminUser
// struct + the passHash / backupCodes slices) so the test can
// mutate the live map freely; restoration replaces the map
// wholesale. cfg.cache is cleared after restore because passHash
// changes invalidate cached verify results.
func snapshotAuthGlobals(t *testing.T) {
	t.Helper()
	cfg.mu.Lock()
	oldProxyPort := cfg.ProxyPort
	oldUIPort := cfg.UIPort
	oldUser := cfg.user
	oldPassHash := append([]byte(nil), cfg.passHash...)
	oldUIUsersFile := cfg.uiUsersFile
	var oldUIUsers map[string]*uiAdminUser
	if cfg.uiUsers != nil {
		oldUIUsers = make(map[string]*uiAdminUser, len(cfg.uiUsers))
		for k, v := range cfg.uiUsers {
			uCopy := *v
			uCopy.passHash = append([]byte(nil), v.passHash...)
			uCopy.backupCodes = append([]string(nil), v.backupCodes...)
			oldUIUsers[k] = &uCopy
		}
	}
	cfg.mu.Unlock()

	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.ProxyPort = oldProxyPort
		cfg.UIPort = oldUIPort
		cfg.user = oldUser
		cfg.passHash = oldPassHash
		cfg.uiUsersFile = oldUIUsersFile
		cfg.uiUsers = oldUIUsers
		cfg.mu.Unlock()
		cfg.cache.clear()
	})
}

// ─── Resolver ────────────────────────────────────────────────────────

func TestResolveAuthStartupConfig_Zero(t *testing.T) {
	got := resolveAuthStartupConfig(0, 0, "", "", "")
	want := authStartupConfig{}
	if got != want {
		t.Errorf("got %+v\nwant %+v (zero values)", got, want)
	}
}

func TestResolveAuthStartupConfig_PropagatesAllFields(t *testing.T) {
	got := resolveAuthStartupConfig(8080, 9090, "admin", "Sup3rSecret!", "/data/ui_users.json")
	want := authStartupConfig{
		ProxyPort:   8080,
		UIPort:      9090,
		AuthUser:    "admin",
		AuthPass:    "Sup3rSecret!",
		UIUsersFile: "/data/ui_users.json",
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// TestResolveAuthStartupConfig_TrimsUsernameWhitespace proves the resolver
// strips leading/trailing whitespace from the resolved admin username before
// it ever reaches cfg.SetAuth. Every OTHER local-admin-credential entry point
// (apiSetupComplete's web setup wizard) already does this trim on the exact
// same field; this resolver — the CLI -user flag / config.yaml auth.user
// merge — did not, which is reachable with plain, syntactically valid YAML:
// a literal block scalar (`user: |` instead of `user: admin`) always carries
// a trailing "\n" per the YAML spec, a common habit when a value is
// templated or copy-pasted from a multi-line-safe style guide. The stored
// admin username then becomes "admin\n" verbatim — permanently unusable,
// since nothing typed into the login form can produce a trailing newline —
// with no error at startup and no indication of the cause (see
// TestLoadAuth_YAMLBlockScalarUsernameStillLogsIn for the full round-trip).
// The password field is deliberately NOT trimmed here: unlike a username, a
// password may legitimately contain leading/trailing whitespace, and
// trimming it would silently narrow what operators can configure.
func TestResolveAuthStartupConfig_TrimsUsernameWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		rawUser  string
		wantUser string
	}{
		{"trailing newline (YAML literal block scalar)", "admin\n", "admin"},
		{"leading and trailing spaces", "  admin  ", "admin"},
		{"trailing carriage return + newline", "admin\r\n", "admin"},
		{"clean value unaffected", "admin", "admin"},
		{"whitespace-only collapses to empty (clear/unconfigured)", "   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAuthStartupConfig(8080, 9090, tt.rawUser, "Sup3rSecret!", "")
			if got.AuthUser != tt.wantUser {
				t.Errorf("resolveAuthStartupConfig(.., %q, ..).AuthUser = %q; want %q", tt.rawUser, got.AuthUser, tt.wantUser)
			}
		})
	}
}

// TestLoadAuth_YAMLBlockScalarUsernameStillLogsIn reproduces the production
// scenario end to end: a config.yaml written with a YAML literal block
// scalar for auth.user (legal, common styling for a "no special characters
// to escape" string) is unmarshaled with the REAL parser this codebase uses
// (goccy/go-yaml, config.go), merged exactly as main.go's loadFileConfigAndFlags
// does (CLI flag empty ⇒ FileConfig wins, unchanged), and loaded via loadAuth.
// The admin operator then does the only thing they can do at a login prompt:
// type the username with no trailing newline. Before the fix, the stored
// username carried the YAML-inserted "\n" and cfg.VerifyAuth("admin", ...)
// returned false — a silent, total lockout traceable only by inspecting the
// raw bytes of config.yaml.
func TestLoadAuth_YAMLBlockScalarUsernameStillLogsIn(t *testing.T) {
	ensureAuthStartupTestLogger(t)
	snapshotAuthGlobals(t)

	const testPass = "P4-4-block-scalar-pw!" // #nosec G101 -- synthetic test fixture; never leaves this test

	yamlSrc := []byte("auth:\n  user: |\n    admin\n  pass: " + testPass + "\n")
	var fc FileConfig
	if err := yaml.Unmarshal(yamlSrc, &fc); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if fc.Auth.User != "admin\n" {
		t.Fatalf("fixture assumption broken: fc.Auth.User = %q; want the literal block scalar's trailing newline (\"admin\\n\") — otherwise this test is not exercising the YAML footgun it claims to", fc.Auth.User)
	}

	// Mirrors main.go: s.authU = firstStr(*s.user, s.fc.Auth.User) with the
	// CLI flag left at its unset default "".
	cliUserFlag := ""
	authU := firstStr(cliUserFlag, fc.Auth.User)

	loadAuth(resolveAuthStartupConfig(8080, 9090, authU, fc.Auth.Pass, ""))

	if !cfg.VerifyAuth("admin", testPass) {
		t.Error(`cfg.VerifyAuth("admin", ...) = false after loading a config.yaml auth.user written as a YAML literal block scalar; the admin can never log in because nothing typed at a login prompt can carry the block scalar's trailing newline`)
	}
}

// ─── Credential validation ─────────────────────────────────────────────
//
// Every other place a local admin credential is set — the web setup
// wizard (apiSetupComplete), the admin config-auth API handler, and
// --reset-password (via SetUIUser) — rejects a password that fails
// validatePasswordComplexity. The CLI -user/-pass flags and the YAML
// auth.user/auth.pass keys resolve into this exact authStartupConfig
// and previously reached cfg.SetAuth with no such gate, so an operator
// could stand up a fully "configured" admin account with e.g.
// -user admin -pass x, silently bypassing the wizard's 8-char/
// upper+lower+digit floor on the real authentication boundary.
// validateAuthStartupCredentials closes that gap; these are its tests.

func TestValidateAuthStartupCredentials(t *testing.T) {
	tests := []struct {
		name    string
		auth    authStartupConfig
		wantErr bool
	}{
		{
			name: "empty user is the clear/unconfigured case, exempt regardless of password",
			auth: authStartupConfig{AuthUser: "", AuthPass: ""},
		},
		{
			name:    "non-empty user with too-short password is rejected",
			auth:    authStartupConfig{AuthUser: "admin", AuthPass: "x"},
			wantErr: true,
		},
		{
			name:    "non-empty user with lowercase-only password is rejected",
			auth:    authStartupConfig{AuthUser: "admin", AuthPass: "alllowercase"},
			wantErr: true,
		},
		{
			name: "non-empty user with a complexity-satisfying password is accepted",
			auth: authStartupConfig{AuthUser: "admin", AuthPass: "Sup3rSecret!"},
		},
		{
			// Codex review, PR #1443: resolveAuthStartupConfig trims
			// AuthUser, so a whitespace-only -user/auth.user value now
			// resolves to "". Silently treating that the same as "never
			// configured" would call cfg.SetAuth("", pass) — which DISABLES
			// local auth entirely, discarding the password that was
			// supplied, with no error pointing at the cause. An empty
			// username paired with a real password must be rejected, not
			// silently exempted.
			name:    "empty user with a non-empty password is rejected, not silently exempted",
			auth:    authStartupConfig{AuthUser: "", AuthPass: "Sup3rSecret!"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthStartupCredentials(tt.auth)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAuthStartupCredentials(%+v) error = %v, wantErr %v", tt.auth, err, tt.wantErr)
			}
		})
	}
}

// ─── Loader ──────────────────────────────────────────────────────────

func TestLoadAuth_SetsPorts(t *testing.T) {
	ensureAuthStartupTestLogger(t)
	snapshotAuthGlobals(t)

	loadAuth(authStartupConfig{
		ProxyPort: 18080,
		UIPort:    19090,
	})

	if cfg.ProxyPort != 18080 {
		t.Errorf("cfg.ProxyPort = %d; want 18080", cfg.ProxyPort)
	}
	if cfg.UIPort != 19090 {
		t.Errorf("cfg.UIPort = %d; want 19090", cfg.UIPort)
	}
}

func TestLoadAuth_SetsLocalBcrypt(t *testing.T) {
	ensureAuthStartupTestLogger(t)
	snapshotAuthGlobals(t)

	const testUser = "p4-4-test-admin"
	const testPass = "P4-4-test-password!" // #nosec G101 -- synthetic test fixture; never leaves this test

	loadAuth(authStartupConfig{
		AuthUser: testUser,
		AuthPass: testPass,
	})

	if !cfg.AuthEnabled() {
		t.Fatal("cfg.AuthEnabled() = false after loadAuth with non-empty user/pass")
	}
	if !cfg.VerifyAuth(testUser, testPass) {
		t.Errorf("cfg.VerifyAuth(%q, …) = false; want true after loadAuth", testUser)
	}
	if cfg.VerifyAuth(testUser, "wrong-password") {
		t.Error("cfg.VerifyAuth with wrong password returned true; want false")
	}
}

// TestLoadAuth_EmptyUIUsersFile_NoFileTouched verifies the
// `if auth.UIUsersFile != ""` guard. We pre-set a sentinel path via
// cfg.SetUIUsersFile, run loadAuth with UIUsersFile="", then call
// cfg.SaveUIUsersFile — if the loader had reset the path to empty,
// Save would no-op; if it left the sentinel intact, Save writes a
// file at the sentinel path. Stat the sentinel to confirm.
func TestLoadAuth_EmptyUIUsersFile_NoFileTouched(t *testing.T) {
	ensureAuthStartupTestLogger(t)
	snapshotAuthGlobals(t)

	sentinel := filepath.Join(t.TempDir(), "sentinel.json")
	cfg.SetUIUsersFile(sentinel)

	loadAuth(authStartupConfig{
		ProxyPort: 18080,
		UIPort:    19090,
		// UIUsersFile intentionally empty.
	})

	if err := cfg.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile after empty-UIUsersFile loadAuth: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("sentinel file %q missing after Save; loadAuth must not have cleared cfg.uiUsersFile: %v", sentinel, err)
	}
}

// TestLoadAuth_LoadsUIUsersFromFile writes a valid UI users
// envelope to t.TempDir() and verifies loadAuth populates cfg via
// LoadUIUsersFile.
func TestLoadAuth_LoadsUIUsersFromFile(t *testing.T) {
	ensureAuthStartupTestLogger(t)
	snapshotAuthGlobals(t)

	// Build a valid envelope: one persisted UI user. We mint the
	// hash via cfg's own API by adding the user first, then dumping
	// to disk; this exercises the round-trip and avoids us having
	// to hand-encode a bcrypt hash.
	const seedUser = "p4-4-seed-admin"
	const seedPass = "Seed-Pass-123!"
	path := filepath.Join(t.TempDir(), "users.json")

	cfg.SetUIUsersFile(path)
	if err := cfg.SetUIUser(seedUser, seedPass, RoleAdmin); err != nil {
		t.Fatalf("seed SetUIUser: %v", err)
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed SaveUIUsersFile: %v", err)
	}
	// Reset path + remove the in-memory copy of the seeded user so
	// loadAuth has to repopulate from disk to make the post-condition
	// meaningful. Bypass cfg.DeleteUIUser to avoid the production
	// "cannot delete the last admin user" guard, which fails
	// non-deterministically under -shuffle=on -count=2. The
	// snapshotAuthGlobals helper restores cfg.uiUsers wholesale on
	// t.Cleanup, so we do not need a manual cleanup here.
	cfg.SetUIUsersFile("")
	cfg.mu.Lock()
	delete(cfg.uiUsers, seedUser)
	cfg.mu.Unlock()

	// Now exercise the loader.
	loadAuth(authStartupConfig{
		UIUsersFile: path,
	})

	role, ok := cfg.VerifyUIUser(seedUser, seedPass)
	if !ok {
		t.Fatalf("VerifyUIUser(%q) = (_, false) after loadAuth; expected user to load from disk", seedUser)
	}
	if role != RoleAdmin {
		t.Errorf("loaded user role = %v; want RoleAdmin", role)
	}
}

// TestLoadAuth_MissingUIUsersFileIsNonFatal points UIUsersFile at a
// path that doesn't exist. cfg.LoadUIUsersFile returns nil in that
// case (not an error), so the loader exercises the else-if branch
// and emits no failure log line. The contract is "non-fatal" —
// asserting absence of panic is the actual invariant.
func TestLoadAuth_MissingUIUsersFileIsNonFatal(t *testing.T) {
	ensureAuthStartupTestLogger(t)
	snapshotAuthGlobals(t)

	missing := filepath.Join(t.TempDir(), "does-not-exist.json")

	loadAuth(authStartupConfig{
		UIUsersFile: missing,
	})

	// If loadAuth panicked or log.Fatalf'd, the test process would
	// have exited before reaching here. Reaching this line is the
	// assertion: the missing path is non-fatal.
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("missing-file test created the file at %q; expected it to stay absent", missing)
	}
}
