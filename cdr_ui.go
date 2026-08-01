package main

// Phase 2c — admin API handlers for the Sluice CDR integration.
//
// Endpoints are mounted under /api/cdr/ and follow the same conventions
// as /api/policy (see apiPolicy in ui.go):
//
//   - GET  /api/cdr/config            admin view of the effective CDR runtime config
//   - GET  /api/cdr/instances         list enrolled Sluice instances
//   - POST /api/cdr/instances/enroll  {endpoint, token, fingerprint, name} → Enroll + persist
//   - DELETE /api/cdr/instances       ?name=…  → remove registry entry + shred certs
//   - GET  /api/cdr/policies          list CDR policy rules
//   - POST /api/cdr/policies          add a CDR policy rule
//   - DELETE /api/cdr/policies        ?name=… → remove a CDR policy rule
//   - GET  /api/cdr/health            proxy to the active Sluice's Health RPC
//   - POST /api/cdr/test              admin tests a file via REPORT_ONLY mode
//
// RBAC: reads require RoleViewer, mutations require RoleAdmin.  Enrollment
// and test are admin-only because they exercise live credentials / the
// engine path.
//
// Config rollback (saveConfigVersion): CDR mutations DO NOT call
// saveConfigVersion. CDR state (cdr_enabled, cdr_instances.json,
// cdr_policies.json) is per-CP local and not in the rollback surface —
// captureConfigBackup (configversion.go) does not read it, and
// applyConfigBackup does not restore it. The earlier header comment
// claiming "every mutation calls saveConfigVersion ... so the admin can
// rollback" was aspirational and not honored by the implementation;
// per roadmap/CATEGORY-D-PRIME-DIRECTION.md §3 the misleading
// saveConfigVersion calls have been removed. The audit trail
// (auditEvent / auditEventDiff) remains the appropriate observability
// tier. cdr.instance.revoke_rpc is additionally security-sensitive
// (must never silently un-revoke a compromised credential); see
// apiCDRRevokeRPC for the contract.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/KidCarmi/Sluice/pkg/sluiceauth"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── /api/cdr/config ────────────────────────────────────────────────────────

// cdrConfigToggleRequest is the JSON body for PUT /api/cdr/config.
// Narrow on purpose — other fields (fail_mode, default_profile, etc.)
// still come from YAML/CLI.  Runtime toggling is limited to enable/
// disable because the other settings have subtle implications that
// deserve a config review + restart.
type cdrConfigToggleRequest struct {
	Enabled bool `json:"enabled"`
}

// apiCDRConfig handles:
//
//	GET — return the effective runtime CDR configuration + derived
//	      convenience fields (clientActive, failOpen) for the GUI.
//	PUT — admin-only toggle of the runtime-enable sentinel.  Flips
//	      cdr.enabled at runtime AND persists to /data/cdr_enabled so
//	      the choice survives a restart.  Triggers initCDRClient /
//	      shutdownCDRClient so the pool matches the new state
//	      without operator action.
func apiCDRConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		apiCDRConfigGet(w, r)
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiCDRConfigToggle(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiCDRConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := cdrActiveConfig()
	clientActive := cdrActiveClient() != nil
	jsonOK(w, map[string]any{
		"enabled":           cfg.Enabled,
		"endpoint":          cfg.Endpoint,
		"failMode":          cfg.FailMode,
		"defaultProfile":    cfg.DefaultProfile,
		"defaultMode":       cfg.DefaultMode,
		"timeoutSec":        cfg.TimeoutSec,
		"maxFileSizeMB":     cfg.MaxFileSizeMB,
		"chunkSizeKB":       cfg.ChunkSizeKB,
		"serverFingerprint": cfg.ServerFingerprint,
		"certsDir":          cfg.CertsDir,
		"clientActive":      clientActive,
		"failOpen":          cfg.CDRFailOpen(),
	})
}

// apiCDRConfigToggle flips cdr.enabled at runtime, persists to the
// sentinel file so the choice survives restart, and drives the pool
// state: enable → initCDRClient so any enrolled instances become
// live; disable → shutdownCDRClient so the pool drains.  Both paths
// are idempotent — re-enabling when already on (or disabling when
// already off) is a no-op.
func apiCDRConfigToggle(w http.ResponseWriter, r *http.Request) {
	var req cdrConfigToggleRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	before := cdrActiveConfig()
	if err := setCDREnabledRuntime(req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := cdrActiveConfig()
	if req.Enabled {
		if rerr := initCDRClient(cfg); rerr != nil {
			logger.Printf("CDR: runtime toggle → enabled but init failed: %q",
				sanitizeLog(rerr.Error()))
		}
	} else {
		shutdownCDRClient()
	}
	auditEventDiff(r, "cdr.config.toggle", "cdr.enabled",
		fmt.Sprintf("enabled=%t", req.Enabled), before.Enabled, req.Enabled)
	// No saveConfigVersion — see file header for the rollback contract.
	jsonOK(w, map[string]any{
		"enabled":      req.Enabled,
		"clientActive": cdrActiveClient() != nil,
	})
}

// ─── /api/cdr/instances ─────────────────────────────────────────────────────

// apiCDRInstances handles GET (list) and DELETE (remove).  Add happens via
// apiCDREnroll so the cert bundle arrives from Sluice in the same flow.
func apiCDRInstances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		list := cdrInstances.List()
		ver, updatedAt := cdrInstances.Version()
		// Snapshot the live pool once and index by name so enrichment
		// below is O(1) per instance instead of re-scanning the pool
		// (and re-acquiring its RLock) for every registry entry.
		pooled := make(map[string]*cdrPooledClient, cdrPool.Len())
		for _, pc := range cdrPool.List() {
			pooled[pc.Name] = pc
		}
		// Enrich each entry with cert-expiry metadata so the GUI can
		// render a countdown + banner without having to parse PEMs
		// itself.  Errors are non-fatal — we just omit the expiry
		// fields for instances whose cert we can't read (admin will
		// see "—" in the GUI and we log server-side).
		enriched := make([]map[string]any, 0, len(list))
		for _, inst := range list {
			entry := cdrInstanceToMap(inst)
			if expiry, err := loadCertExpiry(inst.ClientCertPath); err == nil {
				entry["clientCertNotAfter"] = expiry.UTC().Format(time.RFC3339)
				entry["clientCertDaysRemaining"] = daysUntil(expiry)
			}
			// Merge in the live pool state (circuit-breaker + poller health)
			// so an admin can see WHY the proxy is routing around or
			// skipping an instance without needing Prometheus or SSH.
			if pc, ok := pooled[inst.Name]; ok {
				stats := pc.Breaker.Stats()
				entry["cbState"] = stats.State
				entry["cbConsecFails"] = stats.ConsecFails
				entry["cbTotalOpens"] = stats.TotalOpens
				entry["cbTotalTrips"] = stats.TotalTrips
				entry["poolHealthy"] = pc.Healthy()
			}
			enriched = append(enriched, entry)
		}
		jsonOK(w, map[string]any{
			"instances": enriched,
			"count":     len(enriched),
			"version":   ver,
			"updatedAt": updatedAt,
		})

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		inst := cdrInstances.Get(name)
		if inst == nil {
			http.Error(w, "instance not found", http.StatusNotFound)
			return
		}

		// Remove registry entry first so no new calls route here, then
		// shred the cert material on disk.  Best-effort shredding:
		// missing files aren't fatal (admin may have already cleaned).
		ok, err := cdrInstances.RemoveByName(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "instance not found", http.StatusNotFound)
			return
		}
		shredCDRCerts(inst)

		// If this was the active-client instance, drop the client so we
		// stop trying to dial it.  The next safeCDRSanitize call gets the
		// SKIPPED path until an admin re-enrolls.
		if cdrActiveClient() != nil {
			shutdownCDRClient()
			logger.Printf("CDR: instance %q removed — client shut down; re-enroll to re-enable", sanitizeLog(name))
		}

		auditEventDiff(r, "cdr.instance.remove", name, "removed enrolled Sluice instance", inst, nil)
		// No saveConfigVersion — see file header.
		jsonOK(w, map[string]any{"removed": name})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// shredCDRCerts removes the PEM bundle backing an enrolled instance.
// Errors are logged but not returned — the registry entry is already gone
// and we don't want to block the operator on disk cleanup races.
func shredCDRCerts(inst *CDREnrolledInstance) {
	// Defence-in-depth: refuse to delete anything outside cdrCertsRoot.
	// Even though the paths were written by persistCDREnrollment through
	// the sanitised dir, a compromised instances file could point
	// anywhere — we decline to act on a path whose cleaned form
	// escapes the root.  CodeQL sees the check as an explicit
	// sanitiser for the os.Remove sink.
	rootWithSep := cdrCertsRoot + string(filepath.Separator)
	paths := []string{inst.CACertPath, inst.ClientCertPath, inst.ClientKeyPath}
	// CA-3: also purge the client-key at-rest sidecars (the encrypted-migration
	// plaintext backup and the model-B KEK), so revoking a migrated instance
	// leaves no raw private-key or wrapping-key material behind. Both are
	// derived from ClientKeyPath and live under the same sanitised root.
	if inst.ClientKeyPath != "" {
		paths = append(paths,
			inst.ClientKeyPath+".plaintext.bak",
			inst.ClientKeyPath+cdrClientKEKSuffix,
		)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		cleaned := filepath.Clean(p)
		if !strings.HasPrefix(cleaned, rootWithSep) {
			logger.Printf("CDR: shred refused — path %q escapes root", sanitizeLog(cleaned))
			continue
		}
		if err := os.Remove(cleaned); err != nil && !os.IsNotExist(err) {
			logger.Printf("CDR: shred %q failed: %v", sanitizeLog(cleaned), err)
		}
	}
}

// ─── /api/cdr/instances/enroll ─────────────────────────────────────────────

// cdrEnrollRequest is the JSON body for POST /api/cdr/instances/enroll.
type cdrEnrollRequest struct {
	Name              string `json:"name"`
	Endpoint          string `json:"endpoint"`
	ServerFingerprint string `json:"serverFingerprint"`
	Token             string `json:"token"`
}

// apiCDREnroll performs the full enrollment flow:
//
//  1. Call Sluice.Enroll with {endpoint, token, fingerprint} — TOFU-verifies
//     the server cert against the pasted fingerprint.
//  2. Persist the returned CA + client cert + client key to
//     /data/integrations/sluice/<name>/{ca,client}.pem + client.key (0600).
//  3. Add the instance to cdrInstances registry.
//  4. If CDR is enabled in config, (re-)init the active client so the new
//     certs pick up immediately without a restart.
//
// On any failure mid-flow, we tear down partially-written state so the
// admin can retry without cleaning up by hand.
func apiCDREnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req cdrEnrollRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := validateEnrollRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Reject duplicates early — better UX than a write failure halfway
	// through.  Note: this is not TOCTOU-safe against concurrent enrolls
	// but cdrInstances.Add() rejects duplicates authoritatively.
	if cdrInstances.Get(req.Name) != nil {
		http.Error(w, "name already enrolled", http.StatusConflict)
		return
	}

	// 1. Exchange token for certs.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	resp, err := Enroll(ctx, req.Endpoint, req.ServerFingerprint, req.Token)
	if err != nil {
		logger.Printf("CDR: enrollment RPC failed for %q: %v", sanitizeLog(req.Name), err)
		http.Error(w, fmt.Sprintf("enrollment failed: %v", err), http.StatusBadGateway)
		return
	}

	// 2. Persist certs under the sanitised per-instance directory.
	//    cdrInstanceCertsDir re-validates the name AND the resolved path
	//    so CodeQL sees a clear taint-sanitisation boundary.
	stored, err := persistCDREnrollment(req, resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Auto-enable on first enrollment + re-init the pool.  An admin
	//    clicking "Enroll" in the GUI obviously wants CDR running —
	//    but the v0.1 design required `cdr.enabled: true` in YAML or a
	//    CLI flag, so fresh installs fell into a "registry has entries
	//    but no client dialled" hole.  We flip the runtime sentinel
	//    here (survives restarts) and kick the client init so the Pool
	//    tab goes green immediately.  Failure on the sentinel write
	//    is logged but non-fatal: the in-memory flag still flips, so
	//    this session works; only a restart would revert.
	cfg := cdrActiveConfig()
	if !cfg.Enabled {
		if terr := setCDREnabledRuntime(true); terr != nil {
			logger.Printf("CDR: auto-enable on enroll: persist sentinel: %q",
				sanitizeLog(terr.Error()))
		}
		cfg = cdrActiveConfig() // pick up the flipped flag
		logger.Printf("CDR: auto-enabled on first enrollment (%q)", sanitizeLog(req.Name))
	}
	if cfg.Enabled {
		if rerr := initCDRClient(cfg); rerr != nil {
			logger.Printf("CDR: enroll succeeded but client re-init failed: %q",
				sanitizeLog(rerr.Error()))
		}
	}

	auditEventDiff(r, "cdr.instance.enroll", req.Name,
		fmt.Sprintf("endpoint=%s fingerprint=%s", req.Endpoint, shortFingerprint(req.ServerFingerprint)),
		nil, stored)
	// No saveConfigVersion — see file header.
	jsonOK(w, stored)
}

// persistCDREnrollment writes the PEM bundle to the validated per-
// instance directory and registers the instance.  On any failure
// rolls back written files so the operator can retry cleanly.
// Extracted from apiCDREnroll to keep that function under the funlen
// threshold and to give CodeQL a single sanitisation seam.
func persistCDREnrollment(req cdrEnrollRequest, resp *pb.EnrollResponse) (CDREnrolledInstance, error) {
	dir, err := cdrInstanceCertsDir(req.Name)
	if err != nil {
		return CDREnrolledInstance{}, fmt.Errorf("invalid instance name: %w", err)
	}
	if mkerr := os.MkdirAll(dir, 0o700); mkerr != nil {
		return CDREnrolledInstance{}, fmt.Errorf("create certs dir: %w", mkerr)
	}
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	paths := writtenPaths{}
	if werr := writeCertFile(caPath, resp.CaCert, &paths); werr != nil {
		paths.cleanup()
		return CDREnrolledInstance{}, werr
	}
	if werr := writeCertFile(certPath, resp.ClientCert, &paths); werr != nil {
		paths.cleanup()
		return CDREnrolledInstance{}, werr
	}
	if werr := writeCertFile(keyPath, resp.ClientKey, &paths); werr != nil {
		paths.cleanup()
		return CDREnrolledInstance{}, werr
	}
	inst := CDREnrolledInstance{
		Name:              req.Name,
		Endpoint:          req.Endpoint,
		ServerFingerprint: req.ServerFingerprint,
		CACertPath:        caPath,
		ClientCertPath:    certPath,
		ClientKeyPath:     keyPath,
		EnrolledAt:        time.Now().UTC(),
	}
	stored, aerr := cdrInstances.Add(inst)
	if aerr != nil {
		paths.cleanup()
		return CDREnrolledInstance{}, aerr
	}
	return stored, nil
}

// writtenPaths tracks PEM files written during an enrollment flow so we
// can roll back on failure.
type writtenPaths struct{ paths []string }

func (p *writtenPaths) add(path string) { p.paths = append(p.paths, path) }
func (p *writtenPaths) cleanup() {
	for _, path := range p.paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logger.Printf("CDR: rollback remove %q failed: %v", sanitizeLog(path), err)
		}
	}
}

// writeCertFile writes pem content to path with 0600 perms, tracking the
// written path in `seen` so the caller can clean up on failure.
func writeCertFile(path string, pem []byte, seen *writtenPaths) error {
	if len(pem) == 0 {
		return fmt.Errorf("empty PEM for %s", filepath.Base(path))
	}
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	seen.add(path)
	return nil
}

// cdrInstanceNameRE is a strict allowlist for names used as directory
// components on disk.  First character must be alphanum; the remainder
// alphanum plus dash / dot / underscore; length 1–64.  Deliberately
// narrower than POSIX filenames so CodeQL's taint analyser can see the
// validation and so operators can't accidentally hit edge cases with
// unicode, control characters, or shell metacharacters.
var cdrInstanceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// validateEnrollRequest rejects invalid inputs early so we don't bother
// Sluice with obviously-bad tokens.
func validateEnrollRequest(req cdrEnrollRequest) error {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return errors.New("name is required")
	}
	if !cdrInstanceNameRE.MatchString(name) {
		return errors.New("name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63} (no slashes, no '..', no unicode, no control chars)")
	}
	if strings.TrimSpace(req.Endpoint) == "" {
		return errors.New("endpoint is required")
	}
	if strings.TrimSpace(req.Token) == "" {
		return errors.New("token is required")
	}
	if strings.TrimSpace(req.ServerFingerprint) == "" {
		return errors.New("serverFingerprint is required (TOFU pin)")
	}
	return nil
}

// cdrCertsRoot is the parent directory under which every enrolled
// instance's mTLS bundle lives.  Constant — never constructed from
// user input.
const cdrCertsRoot = "/data/integrations/sluice"

// cdrInstanceCertsDir returns the per-instance cert directory after
// verifying that the resolved path is STILL inside cdrCertsRoot even if
// `name` somehow evaded the allowlist.  Returns an error when the name
// or the resolved path fails any check — gives CodeQL's taint analyser
// a clear sanitiser boundary to stop flagging the downstream os.*
// callers.
func cdrInstanceCertsDir(name string) (string, error) {
	if !cdrInstanceNameRE.MatchString(name) {
		return "", fmt.Errorf("invalid instance name")
	}
	dir := filepath.Join(cdrCertsRoot, name)
	cleaned := filepath.Clean(dir)
	// Must still be strictly inside the root.
	rootWithSep := cdrCertsRoot + string(filepath.Separator)
	if !strings.HasPrefix(cleaned, rootWithSep) || cleaned == cdrCertsRoot {
		return "", fmt.Errorf("certs dir escaped root")
	}
	return cleaned, nil
}

// shortFingerprint returns an 8-hex-char prefix for audit logs.  Never
// persisted — only a one-time convenience for operator readability.
func shortFingerprint(fp string) string {
	n := normaliseFingerprint(fp)
	if len(n) > 8 {
		return n[:8] + "…"
	}
	return n
}

// ─── /api/cdr/policies ──────────────────────────────────────────────────────

// apiCDRPolicies handles GET (list), POST (add), and DELETE (remove).
func apiCDRPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		rules := cdrPolicyStore.List()
		ver, updatedAt := cdrPolicyStore.Version()
		jsonOK(w, map[string]any{
			"rules":     rules,
			"count":     len(rules),
			"version":   ver,
			"epoch":     cdrPolicyStore.Epoch(),
			"updatedAt": updatedAt,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var rule CDRPolicyRule
		if err := decodeJSON(r, &rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(rule.Name) == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		added, err := cdrPolicyStore.Add(rule)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEventDiff(r, "cdr.policy.add", added.Name,
			fmt.Sprintf("priority=%d profile=%s mode=%s", added.Priority, added.ProfileName, added.Mode),
			nil, added)
		// No saveConfigVersion — see file header.
		jsonOK(w, added)

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		ok, err := cdrPolicyStore.RemoveByName(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		auditEventDiff(r, "cdr.policy.remove", name, "removed CDR policy rule", name, nil)
		// No saveConfigVersion — see file header.
		jsonOK(w, map[string]any{"removed": name})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─── /api/cdr/instances/revoke ─────────────────────────────────────────────

// cdrRevokeRequest is the JSON body for POST /api/cdr/instances/revoke.
// Distinct from the DELETE path on /api/cdr/instances which only prunes
// our local registry — this one actually tells Sluice to refuse future
// RPCs from the named instance's client cert.
type cdrRevokeRequest struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

// apiCDRRevokeRPC calls Sluice.RevokeClient for the instance with the
// given name, targeting its CURRENT client cert's SHA-256 fingerprint.
// Sluice v0.2 refuses self-revocation (InvalidArgument) — Culvert must
// always call this from a DIFFERENT instance than the one being
// revoked.  Phase 2d-1's pool + circuit breaker means we use ANY
// other pooled client to make the call.
//
// On success the local registry entry is pruned so the GUI doesn't
// show a dead reference — if the operator wants to re-enroll under
// the same name later, they can.
func apiCDRRevokeRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req cdrRevokeRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	target := cdrInstances.Get(name)
	if target == nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	// Derive the target's fingerprint from its client cert on disk.
	fp, err := loadCertFingerprint(target.ClientCertPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("load target cert: %v", err), http.StatusInternalServerError)
		return
	}

	// Pick ANY other active pool member to make the call — Sluice
	// refuses self-revocation, and even if it didn't, revoking from
	// the same client we're about to invalidate mid-RPC is nonsense.
	caller := cdrPickOtherClient(name)
	if caller == nil {
		http.Error(w, "no other active Sluice instance to issue revoke; enroll a second instance first",
			http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if _, err := caller.RevokeClient(ctx, &pb.RevokeClientRequest{
		Fingerprint: fp,
		Reason:      strings.TrimSpace(req.Reason),
	}); err != nil {
		http.Error(w, fmt.Sprintf("RevokeClient: %v", err), http.StatusBadGateway)
		return
	}

	// Prune the local registry entry now that its cert is dead on
	// the Sluice side.  shredCDRCerts removes the PEMs from disk.
	_, _ = cdrInstances.RemoveByName(name)
	shredCDRCerts(target)
	if cdrActiveClient() != nil {
		// Drop the pool entry by re-init so we stop trying to dial
		// the revoked instance.
		if rerr := initCDRClient(cdrActiveConfig()); rerr != nil {
			logger.Printf("CDR: revoke %q succeeded but reinit failed: %q",
				sanitizeLog(name), sanitizeLog(rerr.Error()))
		}
	}

	auditEventDiff(r, "cdr.instance.revoke_rpc", name,
		fmt.Sprintf("fingerprint=%s reason=%q", shortFingerprint(fp), sanitizeLog(req.Reason)),
		target, nil)
	// Intentionally NOT calling saveConfigVersion: RPC revocation must
	// never silently rollback. A revoke is issued because the credential
	// or endpoint was compromised, misbehaving, or otherwise needs to be
	// retired; restoring a revocation via "rollback to vN" would
	// un-revoke the credential silently — a security regression by
	// definition. Same shape as auth.password_change in PR #261. CDR
	// state is also not in the rollback surface (captureConfigBackup
	// does NOT read cdr_instances.json) so the call was misleading even
	// before the security concern. Category D-sec finding from
	// roadmap/CONFIG-VERSIONING-TRIAGE.md + roadmap/CATEGORY-D-PRIME-DIRECTION.md.
	jsonOK(w, map[string]any{"revoked": name, "fingerprint": fp})
}

// loadCertFingerprint reads a PEM cert and returns its SHA-256
// hex fingerprint via the sluiceauth canonical helper.
func loadCertFingerprint(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}
	cleaned := filepath.Clean(path)
	rootWithSep := cdrCertsRoot + string(filepath.Separator)
	if !strings.HasPrefix(cleaned, rootWithSep) {
		return "", fmt.Errorf("path outside cdr certs root")
	}
	data, err := os.ReadFile(cleaned)
	if err != nil {
		return "", err
	}
	return sluiceauth.Fingerprint(data)
}

// cdrPickOtherClient returns any active pooled client whose instance
// name is NOT `exclude`.  Used by RevokeClient to find a caller that
// isn't the target.  Returns nil when no such client exists.
func cdrPickOtherClient(exclude string) *CDRClient {
	for _, pc := range cdrPool.List() {
		if pc.Name == exclude {
			continue
		}
		if pc.Breaker.Allow() {
			return pc.Client
		}
	}
	return nil
}

// ─── /api/cdr/health ────────────────────────────────────────────────────────

// apiCDRHealth is a live proxy to Sluice.Health.  Returns the most recent
// cached response when available (updated by the background poller); when
// no cache is available, issues an on-demand call with a 5s deadline.
// Admins use this to verify cert validity + see available profiles.
func apiCDRHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	if cached := cdrHealthSnapshot(); cached != nil {
		out := healthToJSON(cached)
		out["lastSeen"] = cdrHealthLastSeenAt().UTC().Format("2006-01-02T15:04:05Z07:00")
		jsonOK(w, out)
		return
	}
	client := cdrActiveClient()
	if client == nil {
		http.Error(w, "no active CDR client", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := client.Health(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("health probe failed: %v", err), http.StatusBadGateway)
		return
	}
	jsonOK(w, healthToJSON(resp))
}

// healthToJSON flattens the proto response into a GUI-friendly JSON map.
// Keeps proto details out of the public API contract.
func healthToJSON(h *pb.HealthResponse) map[string]any {
	profiles := make([]map[string]any, 0, len(h.Profiles))
	for _, p := range h.Profiles {
		if p == nil {
			continue
		}
		profiles = append(profiles, map[string]any{
			"name":             p.Name,
			"description":      p.Description,
			"capabilities":     p.Capabilities,
			"maxFileSizeBytes": p.MaxFileSizeBytes,
		})
	}
	return map[string]any{
		"healthy":        h.Healthy,
		"version":        h.Version,
		"supportedTypes": h.SupportedTypes,
		"activeWorkers":  h.ActiveWorkers,
		"maxWorkers":     h.MaxWorkers,
		"queueDepth":     h.QueueDepth,
		"filesProcessed": h.FilesProcessed,
		"threatsRemoved": h.ThreatsRemoved,
		"profiles":       profiles,
	}
}

// ─── /api/cdr/test ──────────────────────────────────────────────────────────

// apiCDRTest accepts a file upload from the admin and runs it through
// Sluice with mode=REPORT_ONLY, so the original bytes come back unchanged
// but the admin can see exactly which threats the engine would flag.
// Uses the admin's request context (no synthetic identity) so audit
// events attribute the run to the right human.
//
// Accepts either multipart/form-data with a "file" field OR raw bytes in
// the body with Content-Type carrying the file's true MIME.
//
// Responds with the full Sanitize result + a summary of detected threats.
func apiCDRTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	client := cdrActiveClient()
	if client == nil {
		http.Error(w, "no active CDR client", http.StatusServiceUnavailable)
		return
	}

	body, filename, ct, err := readCDRTestUpload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := cdrActiveConfig()
	if int64(len(body)) > cfg.maxFileSizeBytes() {
		http.Error(w, "file exceeds max_file_size_mb", http.StatusRequestEntityTooLarge)
		return
	}

	header := &pb.SanitizeHeader{
		Filename:      filename,
		ContentType:   ct,
		ContentLength: int64(len(body)),
		RequestId:     "admin-test-" + time.Now().UTC().Format("20060102T150405Z"),
		ProfileName:   cfg.DefaultProfile,
		Mode:          pb.Mode_REPORT_ONLY,
		Tags:          map[string]string{"direction": "admin_test"},
		PolicyVersion: cdrPolicyVersionString(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := client.Sanitize(ctx, header, bytes.NewReader(body))
	if err != nil {
		http.Error(w, fmt.Sprintf("Sanitize failed: %v", err), http.StatusBadGateway)
		return
	}

	auditEventDiff(r, "cdr.test", filename,
		fmt.Sprintf("size=%d status=%s threats=%d duration_ms=%d",
			len(body), res.Status.String(), len(res.Threats), res.DurationMs),
		nil, nil)

	jsonOK(w, map[string]any{
		"status":          res.Status.String(),
		"originalType":    res.OriginalType,
		"originalSize":    res.OriginalSize,
		"sanitizedSize":   res.SanitizedSize,
		"durationMs":      res.DurationMs,
		"threats":         res.Threats,
		"errorMessage":    res.ErrorMessage,
		"sanitizedSha256": res.SanitizedSHA256,
	})
}

// readCDRTestUpload accepts multipart/form-data (field: "file") OR a raw
// body with Content-Type carrying the MIME.  Returns the body bytes, a
// filename hint, and the effective content-type.
func readCDRTestUpload(r *http.Request) (body []byte, filename, contentType string, err error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		// Cap the total multipart body BEFORE parsing so a huge boundary
		// count or oversized part cannot exhaust memory.  The
		// MaxBytesReader wrapper is the stdlib-recommended sanitiser;
		// gosec G120 cannot statically prove the pairing, so suppressed
		// with reason.
		r.Body = http.MaxBytesReader(nil, r.Body, 64<<20)
		if err := r.ParseMultipartForm(64 << 20); err != nil { // #nosec G120 -- MaxBytesReader above caps body
			return nil, "", "", fmt.Errorf("parse multipart: %w", err)
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			return nil, "", "", fmt.Errorf("form file 'file': %w", err)
		}
		defer func() { _ = file.Close() }()
		body, err := io.ReadAll(io.LimitReader(file, 64<<20))
		if err != nil {
			return nil, "", "", fmt.Errorf("read upload: %w", err)
		}
		return body, hdr.Filename, firstStr(hdr.Header.Get("Content-Type"), "application/octet-stream"), nil
	}
	// Raw body fallback.
	var rerr error
	body, rerr = io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if rerr != nil {
		return nil, "", "", fmt.Errorf("read body: %w", rerr)
	}
	fn := firstStr(r.URL.Query().Get("filename"), "upload.bin")
	return body, fn, firstStr(ct, "application/octet-stream"), nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// Placeholder so this file compiles without the health-poller dependency.
// Overridden by cdr_health.go's real implementation.
var cdrHealthSnapshot = func() *pb.HealthResponse { return nil }

// cdrInstanceToMap flattens a CDREnrolledInstance to a JSON-safe map.
// Kept separate from the struct tags so we can add computed fields
// (e.g. cert expiry) without polluting the persisted shape.
func cdrInstanceToMap(inst *CDREnrolledInstance) map[string]any {
	return map[string]any{
		"name":              inst.Name,
		"endpoint":          inst.Endpoint,
		"serverFingerprint": inst.ServerFingerprint,
		"caCertPath":        inst.CACertPath,
		"clientCertPath":    inst.ClientCertPath,
		"clientKeyPath":     inst.ClientKeyPath,
		"enrolledAt":        inst.EnrolledAt.UTC().Format(time.RFC3339),
		"version":           inst.Version,
		"lastHealth":        formatOptionalTime(inst.LastHealth),
		"enabled":           inst.IsEnabled(),
	}
}

// formatOptionalTime returns "" when t is zero, else RFC3339.
func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// loadCertExpiry reads a PEM-encoded cert file and returns its NotAfter
// timestamp via the sluiceauth canonical parser (v0.2).  Returns an
// error when the path escapes cdrCertsRoot, the file is missing, or
// the PEM doesn't parse.  Callers treat "can't read" as "expiry
// unknown" rather than a hard failure.
func loadCertExpiry(path string) (time.Time, error) {
	if path == "" {
		return time.Time{}, errors.New("empty path")
	}
	cleaned := filepath.Clean(path)
	// Defence-in-depth: only read paths under cdrCertsRoot so a
	// tampered registry can't coerce us into reading arbitrary
	// files (CodeQL CWE-22 guard mirroring shredCDRCerts).
	rootWithSep := cdrCertsRoot + string(filepath.Separator)
	if !strings.HasPrefix(cleaned, rootWithSep) {
		return time.Time{}, fmt.Errorf("path outside cdr certs root")
	}
	data, err := os.ReadFile(cleaned)
	if err != nil {
		return time.Time{}, err
	}
	return sluiceauth.NotAfter(data)
}

// daysUntil returns integer days between now and t.  Negative when t
// is in the past.  Uses 24h days (not wall-clock calendar days) since
// the semantic we want is "how much cert life is left", which is
// interval-based, not human-calendar-based.
func daysUntil(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}

// jsonOK / decodeJSON / auditEventDiff / sessionAdmin live in ui.go
// and configversion.go respectively. No redefinition here.

// unused guard — keeps the json import alive if a caller comments out the
// JSON paths during iteration.  Harmless in production.
var _ = json.Marshal

// registerCDRRoutes wires the CDR (Sluice) integration admin endpoints
// (Phase 2c). All routes are gated by uiAuthMiddleware; per-handler RBAC
// is the handler's responsibility.
func registerCDRRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/cdr/config", apiCDRConfig)
	mux.HandleFunc("/api/cdr/instances", apiCDRInstances)
	mux.HandleFunc("/api/cdr/instances/enroll", apiCDREnroll)
	mux.HandleFunc("/api/cdr/instances/revoke", apiCDRRevokeRPC)
	mux.HandleFunc("/api/cdr/policies", apiCDRPolicies)
	mux.HandleFunc("/api/cdr/health", apiCDRHealth)
	mux.HandleFunc("/api/cdr/test", apiCDRTest)
}
