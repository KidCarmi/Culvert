package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/canary"
)

// Shadow Exit Review attestation — durable root wiring (§1, Canary Activation Gate).
//
// canary.ShadowExitAttestation is the PURE, schema-versioned record + validator. This file owns
// the durable I/O (a schema-versioned JSON file under dataDir, atomically written 0600,
// fail-closed + quarantined on corruption), the CURRENT runtime identity fact (the build
// `version`), the admin-only creation/revocation surface, and shadowExitReviewAttested() — the
// single consumer that feeds canary.Facts.ShadowExitReviewPassed.
//
// Hard rules (never relax): the attestation is NEVER written on startup, NEVER synthesized
// because tests passed, and NEVER created by anything but an explicit privileged admin action.
// shadowExitReviewAttested() only READS. A corrupt/unknown-schema file NEVER attests (it is
// quarantined and treated as absent). A build change invalidates a prior attestation (identity
// binding) so a materially changed runtime is never covered by an old review.

// shadowExitAttestationPath is the durable location. Operator-owned, fixed under dataDir.
func shadowExitAttestationPath() string {
	return filepath.Join(dataDir, "mcp_shadow_exit_review.json")
}

// currentRuntimeIdentity is the software identity an attestation is bound to. Build version is
// the linker-injected stamp (`version`); a redeploy to a different build changes it, so a prior
// attestation no longer covers the current runtime.
func currentRuntimeIdentity() canary.RuntimeIdentity {
	return canary.RuntimeIdentity{BuildVersion: version}
}

// loadShadowExitAttestation reads the durable attestation. A missing file returns (nil, nil)
// (no attestation — the fail-closed default). A corrupt/undecodable file is QUARANTINED (moved
// aside) and returns (nil, nil) so the node fails closed to "not attested" rather than trusting
// garbage; the quarantine is surfaced via the existing state-corruption alerting. A read error
// on an existing file (transient) is returned so the caller does not misread it as "absent".
func loadShadowExitAttestation() (*canary.ShadowExitAttestation, error) {
	path := shadowExitAttestationPath()
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var a canary.ShadowExitAttestation
	if derr := strictDecodeAttestationJSON(raw, &a); derr != nil {
		// Corruption (bad JSON, unknown fields, trailing data): quarantine and fail closed.
		quarantineCorruptStateFile("mcp_shadow_exit_review", path, derr)
		return nil, nil
	}
	return &a, nil
}

// strictDecodeAttestationJSON decodes exactly one JSON value into v, rejecting unknown fields and any
// trailing data — the same discipline the tooltrust/policylearn stores use so a malformed or
// tampered record is treated as corruption, not silently accepted.
func strictDecodeAttestationJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// shadowExitReviewAttested reports whether a durable, PASSED Shadow Exit Review attestation
// exists AND is bound to the CURRENT runtime identity. It is the single source of truth for
// canary.Facts.ShadowExitReviewPassed. Fail-closed: any load error, missing/corrupt record,
// wrong schema, non-PASSED status, or build-identity mismatch returns false. It NEVER writes.
func shadowExitReviewAttested() bool {
	a, err := loadShadowExitAttestation()
	if err != nil {
		// A transient read error on an existing file is not proof of attestation — fail closed.
		return false
	}
	return canary.AttestationValid(a, currentRuntimeIdentity())
}

// saveShadowExitAttestation atomically writes the attestation (0600). Returns the error so the
// admin handler can report an honest persist failure (never a false durable success).
func saveShadowExitAttestation(a *canary.ShadowExitAttestation) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if err := fileutil.AtomicWrite(shadowExitAttestationPath(), raw, 0o600); err != nil {
		// ErrReplacedNotSynced means the target already carries the new content (only the
		// parent-dir fsync failed) — the durable domain HOLDS the write, so it is a success
		// for our purposes; any other error is a real persist failure.
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			return nil
		}
		return err
	}
	return nil
}

// apiMCPShadowExitReview is the admin surface for the Shadow Exit Review attestation.
//
//	GET    -> viewer: report the current attestation status (truthful; never the raw evidence)
//	POST   -> admin: CREATE the attestation (the explicit privileged review sign-off)
//	DELETE -> admin: REVOKE the attestation (a review no longer stands)
//
// The POST is the ONLY path that writes a PASSED attestation. It binds the record to the actor,
// the current runtime identity, and the supplied exact review/evidence identity. It is audited.
// It is NEVER auto-invoked.
func apiMCPShadowExitReview(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		apiMCPShadowExitReviewGet(w, r)
	case http.MethodPost:
		apiMCPShadowExitReviewPost(w, r)
	case http.MethodDelete:
		apiMCPShadowExitReviewDelete(w, r)
	default:
		mcpMethodNotAllowed(w)
	}
}

// apiMCPShadowExitReviewGet reports the attestation posture without leaking evidence content.
func apiMCPShadowExitReviewGet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	a, _ := loadShadowExitAttestation()
	reason := canary.ValidateAttestation(a, currentRuntimeIdentity())
	resp := map[string]any{
		"attested":        reason == canary.AttestationOK,
		"reason":          string(reason),
		"current_build":   version,
		"schema_expected": canary.ShadowExitAttestationSchemaVersion,
	}
	if a != nil {
		// Bounded, non-sensitive fields only — never the raw evidence bundle.
		resp["review_id"] = a.ReviewID
		resp["attested_by"] = a.AttestedBy
		resp["attested_build"] = a.Identity.BuildVersion
		resp["attested_at_unix_nano"] = a.AttestedAtUnixNano
	}
	jsonOK(w, resp)
}

// apiMCPShadowExitReviewPost creates the durable PASSED attestation (admin-only, audited).
func apiMCPShadowExitReviewPost(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		ReviewID       string `json:"review_id"`
		EvidenceDigest string `json:"evidence_digest"`
	}
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.ReviewID == "" || req.EvidenceDigest == "" {
		http.Error(w, "shadow_exit_review_id_and_evidence_required", http.StatusBadRequest)
		return
	}
	a := &canary.ShadowExitAttestation{
		SchemaVersion:      canary.ShadowExitAttestationSchemaVersion,
		Status:             canary.ShadowExitStatusPassed,
		ReviewID:           req.ReviewID,
		EvidenceDigest:     req.EvidenceDigest,
		Identity:           currentRuntimeIdentity(),
		AttestedBy:         sessionAdmin(r),
		AttestedAtUnixNano: time.Now().UnixNano(),
	}
	if err := saveShadowExitAttestation(a); err != nil {
		auditEvent(r, "mcp.canary.shadow-exit-review.attest", req.ReviewID, "persist_failed")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"attested": false, "persisted": false, "error": "attestation_persist_failed"})
		return
	}
	auditEvent(r, "mcp.canary.shadow-exit-review.attest", req.ReviewID, "shadow_exit_review_passed")
	jsonOK(w, map[string]any{"attested": true, "persisted": true, "review_id": req.ReviewID, "attested_build": version})
}

// apiMCPShadowExitReviewDelete revokes the attestation (admin-only, audited). Revocation is
// removing the durable record; the next readiness read fails closed to "not attested".
func apiMCPShadowExitReviewDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if err := os.Remove(shadowExitAttestationPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		auditEvent(r, "mcp.canary.shadow-exit-review.revoke", "", "remove_failed")
		http.Error(w, "attestation_revoke_failed", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "mcp.canary.shadow-exit-review.revoke", "", "")
	jsonOK(w, map[string]any{"attested": false, "revoked": true})
}
