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
// Every mutation calls `saveConfigVersion(actor, action)` so the admin can
// diff + rollback from the Config Versions panel.

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

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── /api/cdr/config ────────────────────────────────────────────────────────

// apiCDRConfig returns the effective CDR runtime configuration as seen by
// the proxy: the last CDRConfig wired into initCDRClient, plus a handful of
// derived fields the GUI uses without having to recompute.
func apiCDRConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
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
		jsonOK(w, map[string]any{
			"instances": list,
			"count":     len(list),
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
		saveConfigVersion(sessionAdmin(r), "cdr.instance.remove")
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
	for _, p := range []string{inst.CACertPath, inst.ClientCertPath, inst.ClientKeyPath} {
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

	// 3. Re-init client if CDR is enabled so the new certs take effect
	//    without requiring a restart.  Failure here is non-fatal: we've
	//    still persisted the instance, so a later boot / manual
	//    reinit will pick it up.  We sanitizeLog the error because it
	//    may include user-controlled names coming back up the stack
	//    (CWE-117 mitigation).
	cfg := cdrActiveConfig()
	if cfg.Enabled {
		if rerr := initCDRClient(cfg); rerr != nil {
			logger.Printf("CDR: enroll succeeded but client re-init failed: %q",
				sanitizeLog(rerr.Error()))
		}
	}

	auditEventDiff(r, "cdr.instance.enroll", req.Name,
		fmt.Sprintf("endpoint=%s fingerprint=%s", req.Endpoint, shortFingerprint(req.ServerFingerprint)),
		nil, stored)
	saveConfigVersion(sessionAdmin(r), "cdr.instance.enroll")
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
		saveConfigVersion(sessionAdmin(r), "cdr.policy.add")
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
		saveConfigVersion(sessionAdmin(r), "cdr.policy.remove")
		jsonOK(w, map[string]any{"removed": name})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
		"status":         res.Status.String(),
		"originalType":   res.OriginalType,
		"originalSize":   res.OriginalSize,
		"sanitizedSize":  res.SanitizedSize,
		"durationMs":     res.DurationMs,
		"threats":        res.Threats,
		"errorMessage":   res.ErrorMessage,
		"sanitizedSha256": res.SanitizedSHA256,
	})
}

// readCDRTestUpload accepts multipart/form-data (field: "file") OR a raw
// body with Content-Type carrying the MIME.  Returns the body bytes, a
// filename hint, and the effective content-type.
func readCDRTestUpload(r *http.Request) ([]byte, string, string, error) {
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return nil, "", "", fmt.Errorf("read body: %w", err)
	}
	fn := firstStr(r.URL.Query().Get("filename"), "upload.bin")
	return body, fn, firstStr(ct, "application/octet-stream"), nil
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// Placeholder so this file compiles without the health-poller dependency.
// Overridden by cdr_health.go's real implementation.
var cdrHealthSnapshot = func() *pb.HealthResponse { return nil }

// jsonOK / decodeJSON / auditEventDiff / saveConfigVersion / sessionAdmin
// live in ui.go and configversion.go respectively.  No redefinition here.

// unused guard — keeps the json import alive if a caller comments out the
// JSON paths during iteration.  Harmless in production.
var _ = json.Marshal
