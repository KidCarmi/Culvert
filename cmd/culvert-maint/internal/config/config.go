// Package config loads and validates the Maintenance Agent configuration
// from /etc/culvert-maint/config.toml. Validation is fail-closed: any
// missing-required key, unknown enum value, malformed duration / URL /
// regex, or non-absolute path causes Load to return an error rather than
// silently substituting a default.
//
// The contract is documented in roadmap/D1.6-maintenance-agent-
// implementation-plan.md § 1.3 (D1.6a slice).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// PrivilegeMode selects how the agent is allowed to invoke `docker compose`.
type PrivilegeMode string

const (
	// PrivilegeSudoers — production default. The agent prepends `sudo`
	// to every `docker compose` invocation; /etc/sudoers.d/culvert-maint
	// bounds the privilege to a fixed allowlist.
	PrivilegeSudoers PrivilegeMode = "sudoers"

	// PrivilegeDockerGroupLab — dev/lab opt-in. The culvert-maint user
	// is in the `docker` group; effectively root-equivalent.
	PrivilegeDockerGroupLab PrivilegeMode = "docker_group_lab"
)

// Config is the parsed and validated agent configuration. Defaults are
// applied during Load; required-without-default keys cause Load to fail.
type Config struct {
	// Required. Directory containing the operator's docker-compose.yml.
	// Used as cwd for every `docker compose` invocation.
	ComposeProjectDir string

	// Filename within ComposeProjectDir. Default "docker-compose.yml".
	ComposeFile string

	// UDS path. Default "/run/culvert-maint.sock". Mode is fixed at
	// 0660 regardless of config.
	SocketPath string

	// State directory root. Default "/var/lib/culvert-maint".
	StateDir string

	// Privilege model. Default PrivilegeSudoers.
	PrivilegeMode PrivilegeMode

	// Host-published proxy endpoint for health checks.
	// Default "http://127.0.0.1:8080".
	HealthBaseURL *url.URL

	// Path on HealthBaseURL for liveness probe. Default "/health".
	HealthPath string

	// Path on HealthBaseURL for readiness probe. Default "/ready".
	ReadyPath string

	// Hard ceiling on a single operation. Default 30m.
	OperationTimeout time.Duration

	// Default per-stage timeout. Default 5m.
	StageTimeout time.Duration

	// Retention for operations/<op_id>.log and audit.jsonl. Default 30.
	LogRetentionDays int

	// Backup-path policy: every --backup / --restore argument the agent
	// forwards to the cli service must, after filepath.Clean, have this
	// prefix. THIS IS THE PATH AS SEEN BY THE CLI CONTAINER, not the
	// host filesystem. Default "/backup".
	AllowedBackupDir string

	// Default upgrade-target image-ref allowlist (compiled regex).
	ImageAllowlist *regexp.Regexp
}

// rawConfig mirrors the TOML on-disk layout. Unknown keys cause Load to
// fail (toml.DecodeFile with strict mode).
type rawConfig struct {
	ComposeProjectDir string `toml:"compose_project_dir"`
	ComposeFile       string `toml:"compose_file"`
	SocketPath        string `toml:"socket_path"`
	StateDir          string `toml:"state_dir"`
	PrivilegeMode     string `toml:"privilege_mode"`
	HealthBaseURL     string `toml:"health_base_url"`
	HealthPath        string `toml:"health_path"`
	ReadyPath         string `toml:"ready_path"`
	OperationTimeout  string `toml:"operation_timeout"`
	StageTimeout      string `toml:"stage_timeout"`
	LogRetentionDays  *int   `toml:"log_retention_days"`
	AllowedBackupDir  string `toml:"allowed_backup_dir"`
	ImageAllowlist    string `toml:"image_allowlist"`
}

const (
	defaultComposeFile      = "docker-compose.yml"
	defaultSocketPath       = "/run/culvert-maint.sock"
	defaultStateDir         = "/var/lib/culvert-maint"
	defaultPrivilegeMode    = string(PrivilegeSudoers)
	defaultHealthBaseURL    = "http://127.0.0.1:8080"
	defaultHealthPath       = "/health"
	defaultReadyPath        = "/ready"
	defaultOperationTimeout = "30m"
	defaultStageTimeout     = "5m"
	defaultLogRetention     = 30
	defaultAllowedBackupDir = "/backup"
	defaultImageAllowlist   = `^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`
)

// Load reads, parses, and validates the config at path. Returns the
// Config on success, or an error describing exactly which key failed.
// On any failure, the agent must NOT proceed with partial defaults.
func Load(path string) (*Config, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return validate(raw)
}

// readFile loads the TOML file with strict decoding (unknown keys fail).
func readFile(path string) (*rawConfig, error) {
	if path == "" {
		return nil, errors.New("config: path is empty")
	}
	var raw rawConfig
	md, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config: unknown key(s) in %s: %s", path, strings.Join(keys, ", "))
	}
	return &raw, nil
}

// validate applies defaults and runs all fail-closed checks. Many
// independent checks live here; splitting per field would scatter the
// "this key, this rule" logic without making it more readable.
//
//nolint:cyclop,gocognit,funlen // 13 fail-closed checks, one per config key
func validate(raw *rawConfig) (*Config, error) {
	cfg := &Config{}

	// compose_project_dir — required, no default.
	if strings.TrimSpace(raw.ComposeProjectDir) == "" {
		return nil, errors.New("config: compose_project_dir is required")
	}
	if !filepath.IsAbs(raw.ComposeProjectDir) {
		return nil, fmt.Errorf("config: compose_project_dir must be absolute: %q", raw.ComposeProjectDir)
	}
	cfg.ComposeProjectDir = filepath.Clean(raw.ComposeProjectDir)

	// compose_file — default docker-compose.yml. Must be a base name
	// (no path separator) so it joins safely under compose_project_dir.
	cf := raw.ComposeFile
	if cf == "" {
		cf = defaultComposeFile
	}
	if cf != filepath.Base(cf) || strings.ContainsAny(cf, "/\\") {
		return nil, fmt.Errorf("config: compose_file must be a bare filename, got %q", cf)
	}
	cfg.ComposeFile = cf

	// socket_path — default /run/culvert-maint.sock. Must be absolute.
	sp := raw.SocketPath
	if sp == "" {
		sp = defaultSocketPath
	}
	if !filepath.IsAbs(sp) {
		return nil, fmt.Errorf("config: socket_path must be absolute: %q", sp)
	}
	cfg.SocketPath = filepath.Clean(sp)

	// state_dir — default /var/lib/culvert-maint. Must be absolute.
	sd := raw.StateDir
	if sd == "" {
		sd = defaultStateDir
	}
	if !filepath.IsAbs(sd) {
		return nil, fmt.Errorf("config: state_dir must be absolute: %q", sd)
	}
	cfg.StateDir = filepath.Clean(sd)

	// privilege_mode — default sudoers. Closed enum.
	pm := raw.PrivilegeMode
	if pm == "" {
		pm = defaultPrivilegeMode
	}
	switch PrivilegeMode(pm) {
	case PrivilegeSudoers, PrivilegeDockerGroupLab:
		cfg.PrivilegeMode = PrivilegeMode(pm)
	default:
		return nil, fmt.Errorf("config: privilege_mode must be %q or %q, got %q",
			PrivilegeSudoers, PrivilegeDockerGroupLab, pm)
	}

	// health_base_url — default http://127.0.0.1:8080. Must parse.
	hbu := raw.HealthBaseURL
	if hbu == "" {
		hbu = defaultHealthBaseURL
	}
	hu, err := url.Parse(hbu)
	if err != nil {
		return nil, fmt.Errorf("config: health_base_url is malformed: %w", err)
	}
	if hu.Scheme != "http" && hu.Scheme != "https" {
		return nil, fmt.Errorf("config: health_base_url scheme must be http or https, got %q", hu.Scheme)
	}
	if hu.Host == "" {
		return nil, fmt.Errorf("config: health_base_url must have a host: %q", hbu)
	}
	cfg.HealthBaseURL = hu

	// health_path / ready_path — default /health and /ready. Must start with /.
	hp := raw.HealthPath
	if hp == "" {
		hp = defaultHealthPath
	}
	if !strings.HasPrefix(hp, "/") {
		return nil, fmt.Errorf("config: health_path must start with /, got %q", hp)
	}
	cfg.HealthPath = hp

	rp := raw.ReadyPath
	if rp == "" {
		rp = defaultReadyPath
	}
	if !strings.HasPrefix(rp, "/") {
		return nil, fmt.Errorf("config: ready_path must start with /, got %q", rp)
	}
	cfg.ReadyPath = rp

	// operation_timeout — default 30m. time.ParseDuration; positive.
	ot := raw.OperationTimeout
	if ot == "" {
		ot = defaultOperationTimeout
	}
	d, err := time.ParseDuration(ot)
	if err != nil {
		return nil, fmt.Errorf("config: operation_timeout is malformed: %w", err)
	}
	if d <= 0 {
		return nil, fmt.Errorf("config: operation_timeout must be positive, got %s", d)
	}
	cfg.OperationTimeout = d

	// stage_timeout — default 5m. Same rules.
	st := raw.StageTimeout
	if st == "" {
		st = defaultStageTimeout
	}
	d2, err := time.ParseDuration(st)
	if err != nil {
		return nil, fmt.Errorf("config: stage_timeout is malformed: %w", err)
	}
	if d2 <= 0 {
		return nil, fmt.Errorf("config: stage_timeout must be positive, got %s", d2)
	}
	cfg.StageTimeout = d2

	// log_retention_days — default 30. Must be > 0 if present.
	lr := defaultLogRetention
	if raw.LogRetentionDays != nil {
		if *raw.LogRetentionDays <= 0 {
			return nil, fmt.Errorf("config: log_retention_days must be positive, got %d", *raw.LogRetentionDays)
		}
		lr = *raw.LogRetentionDays
	}
	cfg.LogRetentionDays = lr

	// allowed_backup_dir — default /backup. Must be absolute.
	abd := raw.AllowedBackupDir
	if abd == "" {
		abd = defaultAllowedBackupDir
	}
	if !filepath.IsAbs(abd) {
		return nil, fmt.Errorf("config: allowed_backup_dir must be absolute: %q", abd)
	}
	cfg.AllowedBackupDir = filepath.Clean(abd)

	// image_allowlist — default per the plan. Must compile.
	ial := raw.ImageAllowlist
	if ial == "" {
		ial = defaultImageAllowlist
	}
	rx, err := regexp.Compile(ial)
	if err != nil {
		return nil, fmt.Errorf("config: image_allowlist is not a valid regex: %w", err)
	}
	cfg.ImageAllowlist = rx

	return cfg, nil
}
