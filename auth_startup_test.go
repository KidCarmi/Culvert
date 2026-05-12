package main

// auth_startup_test.go — P4.4 / S1 coverage for the extracted auth
// startup slice.
//
// Resolver tests are pure (no globals touched). Loader tests
// mutate the package-global `cfg` singleton; isolation follows the
// established d0_helpers_test.go / pkce_ui2_test.go patterns:
//   - cfg.SetAuth("", "") clears local bcrypt credentials.
//   - cfg.SetUIUsersFile("") clears the persisted-users path.
//   - cfg.DeleteUIUser(name) removes a specific test user.
// All UI users created by tests use a unique discriminator prefix
// so cleanup is precise and tests cannot collide with each other
// or with pre-existing users under -shuffle=on / -count=2.

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
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

// snapshotAuthGlobals saves the cfg state that loadAuth touches and
// arranges restoration on t.Cleanup. cfg has unexported fields
// (user, passHash, uiUsers, uiUsersFile) that can only be cleared
// via cfg's own API — the cleanup uses those APIs rather than
// reaching into the struct.
//
// The cleanup uses cfg.SetAuth("", "") (clears local bcrypt) and
// cfg.SetUIUsersFile("") (clears the persisted-users path),
// matching the existing test conventions in d0_helpers_test.go and
// pkce_ui2_test.go. Any UI users created during a test must be
// cleaned up by that test via cfg.DeleteUIUser(name).
func snapshotAuthGlobals(t *testing.T) {
	t.Helper()
	oldProxyPort := cfg.ProxyPort
	oldUIPort := cfg.UIPort
	t.Cleanup(func() {
		cfg.ProxyPort = oldProxyPort
		cfg.UIPort = oldUIPort
		_ = cfg.SetAuth("", "")
		cfg.SetUIUsersFile("")
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
	const testPass = "P4-4-test-password!"

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
	// Reset path + remove the user so loadAuth has to repopulate
	// from disk to make the post-condition meaningful.
	cfg.SetUIUsersFile("")
	if err := cfg.DeleteUIUser(seedUser); err != nil {
		t.Fatalf("seed DeleteUIUser: %v", err)
	}
	t.Cleanup(func() {
		_ = cfg.DeleteUIUser(seedUser)
	})

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
