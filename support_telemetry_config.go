package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// Credential that passes the full validateTelemetryCredential contract — an
// origin-only posture, or one carrying a malformed credential, can never read
// as enabled. Both the origin and the credential are re-validated at READ
// time: the on-disk config is untrusted input, not a trusted cache.

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

// maxTelemetryConfigFileBytes caps the config file. The real file is a
// three-field JSON object of a few hundred bytes (the credential itself is
// capped at maxTelemetryCredentialLen), so 64 KiB is generous. The cap exists
// because loadTelemetryConfigAtStartup reads this file synchronously during
// boot: an oversized file — grown by a buggy writer, a bad restore, or a
// local process with write access — would otherwise be slurped into memory in
// full before any JSON validation runs, turning a config problem into
// boot-time memory pressure. Enforced twice (see readTelemetryConfigBytes):
// from the descriptor's own metadata, and again as a hard bound on the read
// itself.
const maxTelemetryConfigFileBytes = 64 << 10

// readTelemetryConfigBytes opens the config ONCE and makes every trust
// decision against THAT DESCRIPTOR — never against the pathname again. The
// bearer credential inside is the sole authenticated appliance-attribution
// mechanism for telemetry v1 (§4), so a file that any local user could read,
// or a symlink redirecting the read somewhere the operator never approved,
// must never produce a ready/effectively-enabled posture.
//
// DESCRIPTOR-BOUND BY CONSTRUCTION (the TOCTOU contract). An earlier version
// did Lstat(path) → checks → Chmod(path) → ReadFile(path); those calls each
// re-resolve the pathname, so they do not necessarily agree on an inode. A
// local process able to write the support directory could swap the path
// between the check and the read and defeat both guarantees this function
// makes. Here:
//
//   - os.OpenFile carries oNoFollow, so the open ITSELF refuses a symlink —
//     there is no window in which a symlink can be substituted, because
//     nothing re-opens the name afterwards.
//   - oNonBlock keeps the open from hanging if the path is a FIFO (opening a
//     FIFO for read blocks until a writer appears); f.Stat() then rejects it
//     as non-regular.
//   - f.Stat() (fstat), f.Chmod() (fchmod) and the read all operate on the
//     already-open descriptor, so they cannot be redirected to a different
//     inode.
//
// Group/other permission bits are best-effort CORRECTED to 0600 (an
// operator-friendly self-heal, matching how the rest of the appliance treats
// its own state files); if the correction fails the config is REJECTED rather
// than trusted. Returns (nil, nil) when the file is absent — a missing config
// is simply "disabled", not unsafe. No error it returns ever carries the file
// contents or the credential.
func readTelemetryConfigBytes(path string) ([]byte, error) {
	// #nosec G304 -- fixed filename under dataDir; oNoFollow refuses a symlink
	// at open time and every subsequent check is made on this descriptor.
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow|oNonBlock, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // absent ⇒ disabled, not unsafe
		}
		// ELOOP (oNoFollow refused a symlink), EACCES, ENOTDIR, … all fail
		// closed. The OS error is deliberately not wrapped in: it is not
		// needed to describe the posture.
		return nil, fmt.Errorf("%w: cannot be opened as a plain non-symlink file", errTelemetryConfigUnsafe)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot stat the open file", errTelemetryConfigUnsafe)
	}
	// Reject anything that is not a plain file (directory, device, socket,
	// FIFO). On Unix oNoFollow already excluded symlinks at open time.
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", errTelemetryConfigUnsafe)
	}
	// Cheap metadata rejection so an oversized file is refused without
	// allocating for it. This is an optimisation, NOT the bound — the read
	// below is bounded independently, because this size can be stale.
	if sz := fi.Size(); sz > maxTelemetryConfigFileBytes {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte cap", errTelemetryConfigUnsafe, sz, maxTelemetryConfigFileBytes)
	}
	// Group/other bits set ⇒ another local account can read the bearer
	// credential. Self-heal to 0600 through the DESCRIPTOR (fchmod), so the
	// mode change lands on the file we validated and not on whatever the
	// pathname resolves to now. Fail closed if we cannot.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		if chmodErr := f.Chmod(0o600); chmodErr != nil {
			return nil, fmt.Errorf("%w: mode %04o and fchmod failed", errTelemetryConfigUnsafe, perm)
		}
		logger.Printf("telemetry: corrected insecure permissions on telemetry config (was %04o, now 0600)", perm)
	}
	return readBoundedTelemetryConfig(f)
}

// readBoundedTelemetryConfig reads an already-validated descriptor under a
// hard byte bound.
//
// The f.Stat() size check in the caller is NOT sufficient on its own: a
// regular file can grow between the fstat and the read, so trusting the
// stat'd size would reintroduce the unbounded-allocation problem through a
// narrower window. Reading through an io.LimitReader of cap+1 and rejecting
// anything that reaches cap+1 closes it — the extra byte is what makes
// "exactly at the cap" distinguishable from "at least one byte too long".
func readBoundedTelemetryConfig(f *os.File) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, maxTelemetryConfigFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read failed", errTelemetryConfigUnsafe)
	}
	if len(b) > maxTelemetryConfigFileBytes {
		return nil, fmt.Errorf("%w: exceeds the %d-byte cap while being read", errTelemetryConfigUnsafe, maxTelemetryConfigFileBytes)
	}
	return b, nil
}

// loadTelemetryConfigLocked reads the config. Absent, empty, corrupt JSON,
// or an UNSAFE file (symlink, non-regular, oversized, group/other-readable
// and un-correctable) all fail CLOSED to the zero value (disabled, no origin,
// no credential) — an unreadable or untrustworthy config can never produce an
// enabled posture. Caller holds telemetryConfigMu.
func loadTelemetryConfigLocked() telemetryConfig {
	b, err := readTelemetryConfigBytes(telemetryConfigPath())
	if err != nil {
		// Log the POSTURE only — never the file contents or the credential.
		logger.Printf("telemetry: refusing to load config: %v", sanitizeLog(err.Error()))
		return telemetryConfig{}
	}
	if len(b) == 0 {
		return telemetryConfig{} // absent or empty ⇒ disabled
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

// telemetryCredentialUsable is the SINGLE validity predicate for a stored
// bearer credential, shared by the enabled gate and the status computation so
// the two can never drift apart.
//
// It applies the full validateTelemetryCredential contract (non-blank,
// within the length cap, no control characters) to whatever is currently
// held — including a credential that arrived on disk rather than through
// PUT. The PUT validator alone is not sufficient: the config file can be
// hand-edited, restored from a foreign backup, migrated, or corrupted, and
// a persisted `token\r\nInjected: value` would otherwise read as "usable"
// and hand the future Slice 3 sender a header-injection primitive through
// the very gate it is told to trust.
func telemetryCredentialUsable(cred string) bool {
	return validateTelemetryCredential(cred) == nil
}

// telemetryEnabledFromConfig is the pure gate logic (§4): true only when
// Enabled, the Origin re-validates as a canonical https telemetry endpoint
// (re-checked at read time — not merely trusted from disk — so a hand-edited
// or downgraded config with a now-invalid origin fails closed), AND a bearer
// Credential is present AND well-formed. An origin without a credential (or
// vice versa) never produces an enabled posture, and neither does a
// malformed one.
func telemetryEnabledFromConfig(c telemetryConfig) bool {
	if !c.Enabled || !telemetryCredentialUsable(c.Credential) {
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
// disabled | origin_invalid | credential_missing | credential_invalid |
// ready. Priority order: an explicit Enabled=false always reads "disabled"
// regardless of any other field (an admin who turned telemetry off should
// never see a scarier status); otherwise a missing/invalid origin takes
// precedence over a credential problem, since the origin is the more
// fundamental prerequisite.
//
// credential_missing and credential_invalid are deliberately distinct: both
// are equally ineffective, but an admin looking at a config that DOES carry
// a credential needs to be told it is malformed rather than being sent
// hunting for one that is not there. Reporting the shape of the problem
// leaks nothing — the value itself never reaches the read model.
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
	if !telemetryCredentialUsable(c.Credential) {
		return "credential_invalid"
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
	next := telemetryConfig{Enabled: body.Enabled, Origin: origin}
	credOutcome := "preserved"
	switch {
	case body.ClearCredential:
		credOutcome = "cleared"
	case body.Credential != "":
		next.Credential = body.Credential
		credOutcome = "replaced"
	case existing.Credential == "" || telemetryCredentialUsable(existing.Credential):
		// Nothing to carry forward, or a well-formed one to carry forward.
		next.Credential = existing.Credential
	default:
		// A MALFORMED persisted credential is never carried forward by a PUT
		// that omits one — preserving it would launder a hand-edited or
		// corrupted value through an ordinary admin save. It is dropped, and
		// the outcome is recorded so the audit trail shows why. The value
		// itself is not echoed anywhere.
		credOutcome = "dropped_invalid"
	}
	// Bearer-mandatory (§4): enabling with no usable credential is refused at
	// PUT — UNLESS this request is the explicit clear action, which is
	// documented to force the EFFECTIVE posture unavailable rather than being
	// blocked (the persisted Enabled intent survives; telemetryEnabled()
	// already reads false the instant the credential is gone).
	if next.Enabled && next.Credential == "" && !body.ClearCredential {
		telemetryConfigMu.Unlock()
		msg := "cannot enable telemetry without a bearer credential"
		if credOutcome == "dropped_invalid" {
			msg = "the stored bearer credential is malformed; supply a new credential to enable telemetry"
		}
		http.Error(w, msg, http.StatusBadRequest)
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
