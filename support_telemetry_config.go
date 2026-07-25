package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// support_telemetry_config.go — M7 Slice 2 (roadmap/M7-proactive-telemetry-plan.md
// §4/§9/§14): the node-local telemetry CONSENT switch, config, and bearer-auth
// posture. This slice is, like Slice 1, STRICTLY ZERO EGRESS: it stores an
// origin + a bearer credential and computes whether the (future, Slice 3)
// sender WOULD be allowed to run — nothing here dials, sends, retries, or
// starts a background worker. It mirrors the existing consent-switch shape
// (support_upload.go's uploadConfig, §2 table) so the pattern stays
// consistent across support surfaces: node-local JSON, fail-closed load,
// atomic 0600 persist, a redacted read model, and full independence from
// every other consent/config surface (upload, OTLP, Prometheus, alerts).
//
// Bearer-mandatory (§4): telemetryEnabled() is the ONLY gate a future sender
// may consult, and it requires Enabled, a validated+canonical Origin, AND a
// non-empty Credential — an origin-only posture can never read as enabled.

// telemetryConfig is the node-local, default-OFF telemetry configuration.
// Credential is the per-appliance bearer credential the (future) Slice 3
// sender would present as `Authorization: Bearer <credential>` (§3.1/§4).
// Persisted RAW in the 0600 config — same tier as uploadConfig.Credential /
// metrics_token / upstream proxy credentials (CLAUDE.md "Upstream pool
// durability") — and NEVER echoed by the read model (telemetryStatusView
// reports only CredentialSet). Field named Credential (not Secret/Token) so
// gosec G117's secret-pattern lint does not trip, matching uploadConfig.
type telemetryConfig struct {
	Enabled    bool   `json:"enabled"`
	Origin     string `json:"origin,omitempty"`
	Credential string `json:"credential,omitempty"`
}

var telemetryConfigMu sync.Mutex

func telemetryConfigPath() string { return filepath.Join(dataDir, "support", "telemetry_config.json") }

// errTelemetryConfigUnsafe is the sentinel for a config file whose TYPE or
// PERMISSIONS make it unsafe to trust (symlink, non-regular file, or
// group/other-readable). It never carries the file's contents.
var errTelemetryConfigUnsafe = errors.New("telemetry config file is not a secure regular 0600 file")

// telemetryConfigFileSafe enforces the storage contract on the config file
// BEFORE its bytes are read: the bearer credential inside is the sole
// authenticated appliance-attribution mechanism for telemetry v1 (§4), so a
// file that any local user could read — or that is a symlink redirecting the
// read somewhere else entirely — must never produce a ready/effectively
// enabled posture.
//
// Uses Lstat (not Stat) so a SYMLINK is seen as a symlink rather than
// silently followed to its target. Group/other permission bits are
// best-effort CORRECTED to 0600 (an operator-friendly self-heal, matching
// how the rest of the appliance treats its own state files); if the
// correction fails the config is REJECTED rather than trusted. Returns nil
// when the file is absent (a missing config is simply "disabled", not
// unsafe).
func telemetryConfigFileSafe(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // absent ⇒ disabled, not unsafe
		}
		return errTelemetryConfigUnsafe
	}
	// Reject a symlink outright: following it would read (and trust) bytes
	// from a path the operator never approved, and "fixing" the mode would
	// chmod the target.
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink", errTelemetryConfigUnsafe)
	}
	// Reject anything that is not a plain file (directory, device, socket,
	// FIFO) — a FIFO in particular would block or feed attacker-chosen bytes.
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", errTelemetryConfigUnsafe)
	}
	// Group/other bits set ⇒ another local account can read the bearer
	// credential. Try to self-heal to 0600; fail closed if we cannot.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			return fmt.Errorf("%w: mode %04o and chmod failed", errTelemetryConfigUnsafe, perm)
		}
		logger.Printf("telemetry: corrected insecure permissions on telemetry config (was %04o, now 0600)", perm)
	}
	return nil
}

// loadTelemetryConfigLocked reads the config. Absent, empty, corrupt JSON,
// or an UNSAFE file (symlink, non-regular, group/other-readable and
// un-correctable) all fail CLOSED to the zero value (disabled, no origin, no
// credential) — an unreadable or untrustworthy config can never produce an
// enabled posture. Caller holds telemetryConfigMu.
func loadTelemetryConfigLocked() telemetryConfig {
	path := telemetryConfigPath()
	if err := telemetryConfigFileSafe(path); err != nil {
		// Log the POSTURE only — never the file contents or the credential.
		logger.Printf("telemetry: refusing to load config: %v", sanitizeLog(err.Error()))
		return telemetryConfig{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return telemetryConfig{}
	}
	var c telemetryConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return telemetryConfig{} // fail-closed: a corrupt/empty config disables telemetry
	}
	return c
}

// saveTelemetryConfigLocked atomically persists the config at 0600. Caller
// holds telemetryConfigMu.
func saveTelemetryConfigLocked(c telemetryConfig) error {
	if err := os.MkdirAll(filepath.Dir(telemetryConfigPath()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(telemetryConfigPath(), b, 0o600)
}

// telemetryConfigGet returns the current node-local telemetry config
// (fail-closed).
func telemetryConfigGet() telemetryConfig {
	telemetryConfigMu.Lock()
	defer telemetryConfigMu.Unlock()
	return loadTelemetryConfigLocked()
}

// telemetryEnabledFromConfig is the pure gate logic (§4): true only when
// Enabled, the Origin re-validates as a canonical https telemetry endpoint
// (re-checked at read time — not merely trusted from disk — so a hand-edited
// or downgraded config with a now-invalid origin fails closed), AND a
// non-empty bearer Credential is configured. An origin without a credential
// (or vice versa) never produces an enabled posture.
func telemetryEnabledFromConfig(c telemetryConfig) bool {
	if !c.Enabled || c.Credential == "" {
		return false
	}
	_, err := validateTelemetryEndpoint(c.Origin)
	return err == nil
}

// telemetryEnabled is the single gate a future sender (Slice 3) MUST consult.
// Slice 2 has no sender, so nothing calls this outside the read model/tests
// yet — but the contract is load-bearing now so Slice 3 can wire against it
// unchanged.
func telemetryEnabled() bool { return telemetryEnabledFromConfig(telemetryConfigGet()) }

// loadTelemetryConfigAtStartup is the SYNCHRONOUS startup validation step
// (§14 Slice 2 persistence contract): it loads and validates the node-local
// telemetry config once during loadPersistentAdminState so an operator
// learns at boot — not on the next admin page load — that a config is
// malformed, has unsafe permissions/type, or carries an invalid origin.
//
// STRICTLY ZERO EGRESS AND ZERO BACKGROUND WORK. This function reads one
// local file and logs the resulting posture. It starts NO goroutine, NO
// timer/ticker, NO sender or spool, performs NO DNS resolution, and makes NO
// network call of any kind — validateTelemetryEndpoint is documented
// config-time-only (no network I/O), and there is no sender in this build
// for it to arm. It is deliberately infallible from the caller's point of
// view: every failure mode already degrades to the fail-closed disabled
// posture inside loadTelemetryConfigLocked, so boot is never blocked by a
// bad telemetry config.
//
// The credential VALUE is never logged — only whether one is set.
func loadTelemetryConfigAtStartup() {
	c := telemetryConfigGet()
	status := telemetryStatusFromConfig(c)
	switch {
	case !c.Enabled && c.Origin == "" && c.Credential == "":
		logger.Printf("Telemetry: off (no consent configured; no sender exists in this build)")
	case status == "ready":
		// Report the CANONICAL origin only (telemetryStatusFor sanitizes),
		// so a hand-edited origin carrying userinfo can never reach the log.
		logger.Printf("Telemetry: consent configured and valid (origin=%s, credential set) — NOTE: no sender exists in this build, nothing is transmitted",
			sanitizeLog(telemetryStatusFor(c).Origin))
	default:
		logger.Printf("Telemetry: not effective (status=%s) — telemetry stays off", sanitizeLog(status))
	}
}

// telemetryStatusFromConfig computes the precise status vocabulary (§14):
// disabled | origin_invalid | credential_missing | ready. Priority order:
// an explicit Enabled=false always reads "disabled" regardless of any other
// field (an admin who turned telemetry off should never see a scarier
// status); otherwise a missing/invalid origin takes precedence over a
// missing credential, since the origin is the more fundamental prerequisite.
func telemetryStatusFromConfig(c telemetryConfig) string {
	if !c.Enabled {
		return "disabled"
	}
	if _, err := validateTelemetryEndpoint(c.Origin); err != nil {
		return "origin_invalid"
	}
	if c.Credential == "" {
		return "credential_missing"
	}
	return "ready"
}

// telemetryStatusView is the redacted read model — the ONLY shape the
// telemetry config surface (API, audit before/after, GUI) ever exposes.
// The credential is represented ONLY as CredentialSet; its value is never
// serialized anywhere by this type, and Origin is only ever the CANONICAL
// re-validated form (see telemetryStatusFor).
type telemetryStatusView struct {
	Enabled          bool   `json:"enabled"`
	EffectiveEnabled bool   `json:"effective_enabled"`
	Origin           string `json:"origin,omitempty"`
	CredentialSet    bool   `json:"credential_set"`
	Status           string `json:"status"`
}

// telemetryStatusFor builds the redacted read model for a given config value
// (used directly by the API handler and by the audit before/after diff, so
// neither path ever needs to re-derive it from a fresh disk read).
//
// SANITIZATION IS LOAD-BEARING (§9: "the read model returns only the
// canonical safe origin; it never exposes userinfo or secret material").
// The PUT handler canonicalizes before persisting, but the ON-DISK config is
// NOT a trusted input: it can be hand-edited, restored from an older//foreign
// backup, or corrupted. So Origin is re-validated HERE and only the
// canonical form is ever copied into the view — never c.Origin verbatim.
// An origin that fails validation (userinfo, query, fragment, path, bad
// port, private IP, non-https) is OMITTED entirely and reported as
// origin_invalid, so a persisted `https://user:secret@host` can never be
// echoed back through GET/PUT responses, rendered in the GUI, or serialized
// into an audit before/after snapshot.
func telemetryStatusFor(c telemetryConfig) telemetryStatusView {
	v := telemetryStatusView{
		Enabled:          c.Enabled,
		EffectiveEnabled: telemetryEnabledFromConfig(c),
		CredentialSet:    c.Credential != "",
		Status:           telemetryStatusFromConfig(c),
	}
	// Only a canonical, re-validated origin is ever exposed. On failure the
	// field stays empty (omitempty) rather than leaking the raw value.
	if canonical, err := validateTelemetryEndpoint(c.Origin); err == nil {
		v.Origin = canonical
	}
	return v
}

// telemetryStatus reads the current config and returns its redacted view.
func telemetryStatus() telemetryStatusView { return telemetryStatusFor(telemetryConfigGet()) }

// validateTelemetryEndpointShape checks every STRUCTURAL constraint on an
// already-parsed origin (scheme, userinfo, fragment, query, host, port,
// path) — split out of validateTelemetryEndpoint purely to stay under the
// repo's cyclomatic-complexity threshold; it carries no independent
// behavior of its own.
func validateTelemetryEndpointShape(u *url.URL) error {
	if u.Scheme != "https" {
		return errors.New("origin must be https")
	}
	if u.User != nil {
		return errors.New("origin must not contain userinfo (user:pass@)")
	}
	if u.Fragment != "" {
		return errors.New("origin must not contain a fragment")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("origin must not contain a query")
	}
	if u.Hostname() == "" {
		return errors.New("origin must include a host")
	}
	// url.Parse/Port() accept any numeric string after the colon without
	// range-checking it — "https://host:99999" parses "cleanly" but is not
	// a dialable TCP port. Reject explicitly rather than persisting an
	// endpoint that can never be reached.
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("origin port must be a valid TCP port (1-65535)")
		}
	}
	// Origin only — no operator-provided path, except an optional canonical
	// "/" (normalized away by the caller).
	if p := u.EscapedPath(); p != "" && p != "/" {
		return errors.New("origin must not contain a path")
	}
	return nil
}

// validateTelemetryEndpoint enforces the hardened endpoint-canonicalization
// contract (§9): https-only, a real non-empty host, no userinfo, no
// fragment, no query, no operator-provided path (only an optional trailing
// "/", normalized away), and no private/internal literal IP (v4 or v6,
// IPv6-zone-stripped, mirroring validateUploadOrigin). Performs NO network
// I/O — DNS-rebind defenses are a Slice 3 (dial-time) concern (§9). On
// success returns the CANONICAL origin (lower-cased scheme+host[:port], no
// trailing slash) — the exact string the config stores and the read model
// returns.
func validateTelemetryEndpoint(origin string) (string, error) {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return "", errors.New("origin must not be empty")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "", errors.New("invalid origin URL")
	}
	if err := validateTelemetryEndpointShape(u); err != nil {
		return "", err
	}
	host := u.Hostname()
	// Strip an IPv6 zone (e.g. "fe80::1%eth0") before parsing — a scoped
	// literal otherwise makes net.ParseIP return nil and the private-IP
	// check would mistake a link-local literal for an ordinary hostname
	// (mirrors validateUploadOrigin's Codex-flagged fix).
	zoneStripped := host
	if i := strings.IndexByte(zoneStripped, '%'); i >= 0 {
		zoneStripped = zoneStripped[:i]
	}
	if ip := net.ParseIP(zoneStripped); ip != nil && isPrivateIP(ip) {
		return "", errors.New("origin is a private/internal address; refused")
	}
	// Canonical form: lower-cased scheme + host[:port], no path/query/fragment.
	return "https://" + strings.ToLower(u.Host), nil
}

// maxTelemetryCredentialLen bounds the stored bearer credential. Real TAC
// bearer tokens are far shorter; the cap exists so a malformed or hostile
// PUT cannot write an unbounded blob into the 0600 config file.
const maxTelemetryCredentialLen = 4096

// validateTelemetryCredential bounds a caller-supplied bearer credential.
// It must be non-empty after trimming, within the length cap, and free of
// control characters — a credential is placed verbatim into an
// `Authorization: Bearer …` header by the future Slice 3 sender, so an
// embedded CR/LF would be a header-injection primitive, and a NUL or other
// control byte has no legitimate place in a bearer token (RFC 6750 token68).
// The credential VALUE never appears in the returned error.
func validateTelemetryCredential(cred string) error {
	if strings.TrimSpace(cred) == "" {
		return errors.New("credential must not be blank")
	}
	if len(cred) > maxTelemetryCredentialLen {
		return fmt.Errorf("credential must be at most %d bytes", maxTelemetryCredentialLen)
	}
	for _, r := range cred {
		if r < 0x20 || r == 0x7f {
			return errors.New("credential must not contain control characters")
		}
	}
	return nil
}

// apiSupportTelemetryConfig manages the node-local telemetry consent/config
// (§4/§14). GET (admin) reads the redacted posture; PUT (admin) sets
// enabled/origin/credential, validated and audited. Node-local — no
// saveConfigVersion, no admin_settings.json, no CP→DP sync (mirrors the
// upload config's independence, ADR-0011/P6 consent separation). This
// handler cannot cause egress: it only reads/writes a local JSON file.
func apiSupportTelemetryConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Admin-only for BOTH read and write: the posture reveals the TAC
		// origin and whether a bearer credential is configured — consent
		// configuration, not general operational status — so the whole
		// surface is admin-gated. (The separate Slice 1 telemetry PREVIEW
		// route keeps its own independently-governed RBAC contract.)
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, telemetryStatus())

	case http.MethodPut:
		handleTelemetryConfigPut(w, r)

	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// telemetryConfigPutBody is the PUT request shape (§4 preserve/replace/clear
// credential semantics).
type telemetryConfigPutBody struct {
	Enabled         bool   `json:"enabled"`
	Origin          string `json:"origin"`
	Credential      string `json:"credential"`       // set the bearer credential; empty ⇒ keep existing
	ClearCredential bool   `json:"clear_credential"` // explicitly remove the stored credential
}

// validateTelemetryConfigPut runs every PUT-body rejection rule and returns
// the CANONICAL origin to persist (empty when none was supplied). It is a
// pure function taken before the config lock, which is what makes "failed
// validation never partially mutates or persists" structurally true rather
// than merely a code-ordering convention. The returned error text never
// echoes the credential value.
func validateTelemetryConfigPut(body telemetryConfigPutBody) (string, error) {
	// No ambiguous combination: replace and clear in the same request is
	// rejected outright rather than silently picking one.
	if body.ClearCredential && body.Credential != "" {
		return "", errors.New("cannot both set and clear the credential in the same request")
	}
	// A supplied credential must be well-formed BEFORE anything is persisted.
	if body.Credential != "" {
		if err := validateTelemetryCredential(body.Credential); err != nil {
			return "", err
		}
	}
	origin := strings.TrimSpace(body.Origin)
	if origin != "" {
		canon, err := validateTelemetryEndpoint(origin)
		if err != nil {
			return "", err
		}
		origin = canon
	}
	// Enabling requires a valid origin — an origin-less enable is refused
	// up front (§4), same shape as uploadConfig's "cannot enable without an
	// origin" gate. A bare disable is always allowed.
	if body.Enabled && origin == "" {
		return "", errors.New("cannot enable telemetry without a valid https origin")
	}
	return origin, nil
}

// handleTelemetryConfigPut validates and applies a telemetry config update
// (admin). Failed validation never partially mutates or persists the
// config — every rejection returns before the config lock is taken.
func handleTelemetryConfigPut(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body telemetryConfigPutBody
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	origin, err := validateTelemetryConfigPut(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	telemetryConfigMu.Lock()
	existing := loadTelemetryConfigLocked()
	next := telemetryConfig{Enabled: body.Enabled, Origin: origin, Credential: existing.Credential}
	credOutcome := "preserved"
	switch {
	case body.ClearCredential:
		next.Credential = ""
		credOutcome = "cleared"
	case body.Credential != "":
		next.Credential = body.Credential
		credOutcome = "replaced"
	}
	// Bearer-mandatory (§4): enabling with no credential is refused at PUT —
	// UNLESS this request is the explicit clear action, which is documented
	// to force the EFFECTIVE posture unavailable rather than being blocked
	// (the persisted Enabled intent survives; telemetryEnabled() already
	// reads false the instant the credential is gone).
	if next.Enabled && next.Credential == "" && !body.ClearCredential {
		telemetryConfigMu.Unlock()
		http.Error(w, "cannot enable telemetry without a bearer credential", http.StatusBadRequest)
		return
	}
	before := telemetryStatusFor(existing)
	err = saveTelemetryConfigLocked(next)
	telemetryConfigMu.Unlock()
	if err != nil {
		http.Error(w, "persist telemetry config", http.StatusInternalServerError)
		return
	}
	after := telemetryStatusFor(next)
	// Audit detail never contains the credential value — only the outcome
	// (preserved/replaced/cleared) and the canonical (non-secret) origin.
	// Before/after are the redacted view (credential_set bool only).
	detail := fmt.Sprintf("enabled=%t origin=%s credential=%s", next.Enabled, sanitizeLog(next.Origin), credOutcome)
	auditEventDiff(r, "support.telemetry.config", "telemetry", detail, before, after)
	jsonOK(w, after)
}
