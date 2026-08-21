package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// support_upload.go — M6 Secure Upload, PR-1 (the zero-egress SPINE).
//
// This slice deliberately ships NO network code. It establishes the safe
// foundation everything else stacks on:
//   - the upload posture/state vocabulary the queue + client build on,
//   - a node-local, default-OFF upload CONFIG (TAC origin + enable flag), and
//   - the admin surface to manage it, reporting "not_enabled" until an operator
//     EXPLICITLY configures an origin AND enables it.
//
// Nothing here can cause an outbound connection: there is no client, no timer,
// no trigger, no scheduler. Per-bundle consent and the actual resumable upload
// path are later PRs (SECURE-UPLOAD-ARCHITECTURE.md §2/§4); TestNoAutoUpload
// pins that no auto-upload path exists in this slice.
//
// Consent SEPARATION (ADR-0011/P6): the upload switch is INDEPENDENT of bundle
// collection, remote support, and telemetry — enabling one never enables
// another. TestConsentSeparation pins it.
//
// Node-local like the recipient registry (support_recipients.go): the config is
// operational state — OFF export/import, config-version rollback, and CP→DP
// sync (no saveConfigVersion). The upload lifecycle state vocabulary
// (queued/uploading/uploaded/deferred/rejected) lands with the queue/state
// machine in a later PR — it is deliberately absent here since PR-1 has no
// state to drive.

// uploadConfig is the node-local, default-OFF upload configuration. PR-1 carries
// only the enable flag and the TAC origin; the per-appliance credential and the
// TAC recipient trust key arrive with the client/trust PRs — no secret is
// persisted until the code that consumes it exists.
type uploadConfig struct {
	Enabled bool   `json:"enabled"`          // master switch; default false → not_enabled
	Origin  string `json:"origin,omitempty"` // TAC upload base URL (https; never a private host)
	// Credential is the per-appliance bearer credential (tenant-scoped) the upload
	// client sends to the gateway. Optional — a gateway may authenticate the
	// appliance by mTLS instead, in which case this stays empty. Persisted RAW in
	// the 0600 config (same layer as metrics_token / upstream proxy credentials)
	// and NEVER echoed by the read model (uploadStatus reports only credential_set).
	// gosec G117: the field is named Credential (not secret/token/password) so the
	// secret-pattern lint does not trip. #nosec-free by naming.
	Credential string `json:"credential,omitempty"`
}

var uploadConfigMu sync.Mutex

func uploadConfigPath() string { return filepath.Join(dataDir, "support", "upload_config.json") }

// loadUploadConfigLocked reads the config. Absent or corrupt ⇒ the zero value
// (disabled) — fail-closed: an unreadable config never enables egress. Caller
// holds uploadConfigMu.
func loadUploadConfigLocked() uploadConfig {
	b, err := os.ReadFile(uploadConfigPath())
	if err != nil {
		return uploadConfig{}
	}
	var c uploadConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return uploadConfig{} // fail-closed: a corrupt config disables upload
	}
	return c
}

// saveUploadConfigLocked atomically persists the config at 0600. Caller holds
// uploadConfigMu.
func saveUploadConfigLocked(c uploadConfig) error {
	if err := os.MkdirAll(filepath.Dir(uploadConfigPath()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := uploadConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, uploadConfigPath())
}

// uploadConfigGet returns the current node-local upload config (fail-closed).
func uploadConfigGet() uploadConfig {
	uploadConfigMu.Lock()
	defer uploadConfigMu.Unlock()
	return loadUploadConfigLocked()
}

// uploadEnabled is the single gate every future upload path MUST consult: true
// only when an operator has explicitly enabled upload AND set an origin. Default
// (and fail-closed) is false, so the feature is not_enabled and no egress is
// possible until deliberately configured.
func uploadEnabled() bool {
	c := uploadConfigGet()
	return c.Enabled && c.Origin != ""
}

// validateUploadOrigin enforces the SSRF posture on the operator-set origin
// (SECURE-UPLOAD-ARCHITECTURE.md §4): https only, a real host, and — for a
// literal IP — never a private/internal address. A hostname is accepted
// syntactically here; the resolving dial-time SSRF guard (added with the upload
// client) rejects it if it resolves private, mirroring the release-catalog
// config-time/dial-time split. This function performs NO network I/O.
func validateUploadOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return errors.New("invalid origin URL")
	}
	if u.Scheme != "https" {
		return errors.New("origin must be https")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("origin must include a host")
	}
	// Strip an IPv6 zone (e.g. "fe80::1%eth0" → "fe80::1") before parsing: a
	// scoped literal like https://[fe80::1%25eth0] otherwise makes net.ParseIP
	// return nil, so the private-IP check would mistake a link-local literal for
	// a hostname and let it save (Codex). The dial-time guard fails closed on
	// zoned IPv6 too, but the config-time gate must reject it up front.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil && isPrivateIP(ip) {
		return errors.New("origin is a private/internal address; refused (use offline export for air-gapped transfer)")
	}
	return nil
}

// uploadStatus is the read model for the admin surface. When disabled or
// incompletely configured it reports "not_enabled"; it never exposes a secret
// (PR-1 stores none).
func uploadStatus() map[string]any {
	c := uploadConfigGet()
	m := map[string]any{
		"enabled": c.Enabled,
		"state":   "not_enabled",
	}
	if c.Enabled && c.Origin != "" {
		m["state"] = "enabled"
	}
	if c.Origin != "" {
		m["origin"] = c.Origin
		if u, err := url.Parse(c.Origin); err == nil {
			m["origin_host"] = u.Hostname()
		}
	}
	// Never expose the credential itself — only whether one is set.
	m["credential_set"] = c.Credential != ""
	return m
}

// apiSupportUploadConfig manages the node-local upload config. GET (viewer) reads
// the posture; PUT (admin) sets the enable flag + origin, validated + audited.
// Node-local — no saveConfigVersion (mirrors the recipient registry). This
// handler cannot cause egress: it only reads/writes a local JSON file.
func apiSupportUploadConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, uploadStatus())

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Enabled         bool   `json:"enabled"`
			Origin          string `json:"origin"`
			Credential      string `json:"credential"`       // set the bearer credential; empty ⇒ keep existing
			ClearCredential bool   `json:"clear_credential"` // explicitly remove the stored credential
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		origin := strings.TrimSpace(body.Origin)
		if origin != "" {
			if err := validateUploadOrigin(origin); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		// Enabling requires an origin — you cannot arm upload with no destination.
		// A bare disable (enabled=false) is always allowed.
		if body.Enabled && origin == "" {
			http.Error(w, "cannot enable upload without an origin", http.StatusBadRequest)
			return
		}
		uploadConfigMu.Lock()
		// Preserve the stored credential across posture flips: an empty credential in
		// the body means "leave it", so toggling enabled/origin never silently wipes
		// it. ClearCredential is the explicit remove. A provided credential replaces.
		next := uploadConfig{Enabled: body.Enabled, Origin: origin, Credential: loadUploadConfigLocked().Credential}
		switch {
		case body.ClearCredential:
			next.Credential = ""
		case body.Credential != "":
			next.Credential = body.Credential
		}
		err := saveUploadConfigLocked(next)
		uploadConfigMu.Unlock()
		if err != nil {
			http.Error(w, "persist upload config", http.StatusInternalServerError)
			return
		}
		// Audit the posture flip (no secret in object/detail — the origin is
		// retrievable via GET and is not confidential, but we keep the audit line
		// to the posture itself).
		outcome := "disabled"
		if body.Enabled {
			outcome = "enabled"
		}
		auditEvent(r, "support.upload.config", "upload", outcome)
		jsonOK(w, uploadStatus())

	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
