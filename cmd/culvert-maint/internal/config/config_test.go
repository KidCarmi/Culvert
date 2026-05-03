package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig is a small helper that writes body to a TOML file under
// t.TempDir() and returns the path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// minimalValid is the smallest valid config body — only the required key
// is set; all other fields receive their defaults.
const minimalValid = `compose_project_dir = "/srv/culvert"`

// TestLoad_DefaultsApplied exercises one branch per config key.
// Splitting would obscure which keys are checked against which defaults.
//
//nolint:cyclop // one default-check per config key; splitting obscures the matrix
func TestLoad_DefaultsApplied(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalValid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ComposeProjectDir != "/srv/culvert" {
		t.Errorf("ComposeProjectDir: got %q", cfg.ComposeProjectDir)
	}
	if cfg.ComposeFile != "docker-compose.yml" {
		t.Errorf("ComposeFile default: got %q", cfg.ComposeFile)
	}
	if cfg.SocketPath != "/run/culvert-maint.sock" {
		t.Errorf("SocketPath default: got %q", cfg.SocketPath)
	}
	if cfg.StateDir != "/var/lib/culvert-maint" {
		t.Errorf("StateDir default: got %q", cfg.StateDir)
	}
	if cfg.PrivilegeMode != PrivilegeSudoers {
		t.Errorf("PrivilegeMode default: got %q", cfg.PrivilegeMode)
	}
	if cfg.HealthBaseURL.String() != "http://127.0.0.1:8080" {
		t.Errorf("HealthBaseURL default: got %q", cfg.HealthBaseURL.String())
	}
	if cfg.HealthPath != "/health" {
		t.Errorf("HealthPath default: got %q", cfg.HealthPath)
	}
	if cfg.ReadyPath != "/ready" {
		t.Errorf("ReadyPath default: got %q", cfg.ReadyPath)
	}
	if cfg.OperationTimeout != 30*time.Minute {
		t.Errorf("OperationTimeout default: got %s", cfg.OperationTimeout)
	}
	if cfg.StageTimeout != 5*time.Minute {
		t.Errorf("StageTimeout default: got %s", cfg.StageTimeout)
	}
	if cfg.LogRetentionDays != 30 {
		t.Errorf("LogRetentionDays default: got %d", cfg.LogRetentionDays)
	}
	if cfg.AllowedBackupDir != "/backup" {
		t.Errorf("AllowedBackupDir default: got %q", cfg.AllowedBackupDir)
	}
	if cfg.ImageAllowlist == nil {
		t.Fatal("ImageAllowlist must be compiled")
	}
	// Spot-check the default regex matches an expected ref + rejects an unrelated one.
	if !cfg.ImageAllowlist.MatchString("ghcr.io/kidcarmi/culvert:v1.0.0") {
		t.Error("default ImageAllowlist should match a tagged ghcr.io culvert image")
	}
	if cfg.ImageAllowlist.MatchString("docker.io/library/alpine:latest") {
		t.Error("default ImageAllowlist must NOT match a non-allowlisted registry")
	}
}

func TestLoad_MissingComposeProjectDirFailsClosed(t *testing.T) {
	p := writeConfig(t, ``) // empty body — required key missing
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected error when compose_project_dir missing")
	}
	if !strings.Contains(err.Error(), "compose_project_dir") {
		t.Errorf("error must name compose_project_dir, got: %v", err)
	}
}

func TestLoad_RelativeComposeProjectDirFailsClosed(t *testing.T) {
	_, err := Load(writeConfig(t, `compose_project_dir = "relative/path"`))
	if err == nil {
		t.Fatal("expected error for relative compose_project_dir")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("error should mention 'absolute', got: %v", err)
	}
}

func TestLoad_UnknownPrivilegeModeFailsClosed(t *testing.T) {
	body := minimalValid + "\nprivilege_mode = \"yolo\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for unknown privilege_mode")
	}
	if !strings.Contains(err.Error(), "privilege_mode") {
		t.Errorf("error must name privilege_mode, got: %v", err)
	}
}

func TestLoad_DockerGroupLabAccepted(t *testing.T) {
	body := minimalValid + "\nprivilege_mode = \"docker_group_lab\""
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("docker_group_lab should be accepted: %v", err)
	}
	if cfg.PrivilegeMode != PrivilegeDockerGroupLab {
		t.Errorf("got %q", cfg.PrivilegeMode)
	}
}

func TestLoad_InvalidDurationFailsClosed(t *testing.T) {
	body := minimalValid + "\noperation_timeout = \"never\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
	if !strings.Contains(err.Error(), "operation_timeout") {
		t.Errorf("error must name operation_timeout, got: %v", err)
	}
}

func TestLoad_NegativeStageTimeoutFailsClosed(t *testing.T) {
	body := minimalValid + "\nstage_timeout = \"-1s\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for negative stage_timeout")
	}
}

func TestLoad_InvalidHealthURLFailsClosed(t *testing.T) {
	body := minimalValid + "\nhealth_base_url = \"::not a url::\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for invalid health_base_url")
	}
}

func TestLoad_InvalidHealthSchemeFailsClosed(t *testing.T) {
	body := minimalValid + "\nhealth_base_url = \"ftp://1.2.3.4\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for non-http(s) scheme")
	}
}

func TestLoad_HealthPathMustBeAbsolute(t *testing.T) {
	body := minimalValid + "\nhealth_path = \"health\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error when health_path missing leading /")
	}
}

func TestLoad_InvalidImageAllowlistRegexFailsClosed(t *testing.T) {
	// Unbalanced bracket; should fail to compile.
	body := minimalValid + "\nimage_allowlist = \"[unbalanced\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "image_allowlist") {
		t.Errorf("error must name image_allowlist, got: %v", err)
	}
}

func TestLoad_UnknownKeyFailsClosed(t *testing.T) {
	body := minimalValid + "\nthis_key_does_not_exist = 42"
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for unknown TOML key")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("error should mention 'unknown key', got: %v", err)
	}
}

func TestLoad_RelativeSocketPathFailsClosed(t *testing.T) {
	body := minimalValid + "\nsocket_path = \"sock\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for relative socket_path")
	}
}

func TestLoad_ComposeFileWithSlashFailsClosed(t *testing.T) {
	body := minimalValid + "\ncompose_file = \"sub/compose.yml\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error when compose_file contains a path separator")
	}
}

func TestLoad_NegativeLogRetentionFailsClosed(t *testing.T) {
	body := minimalValid + "\nlog_retention_days = -1"
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for negative log_retention_days")
	}
}

func TestLoad_RelativeAllowedBackupDirFailsClosed(t *testing.T) {
	body := minimalValid + "\nallowed_backup_dir = \"backup\""
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected error for relative allowed_backup_dir")
	}
}

func TestLoad_NonexistentFileReturnsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "no-such-file.toml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_EmptyPathReturnsError(t *testing.T) {
	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}
