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

// currentRuntimeIdentity is the software identity an attestation is bound to. The build stamp is the
// linker-injected version, COMPOSED with the immutable commit digest (`buildCommit`) when present, so
// the identity is UNIQUE PER COMMIT — two commits released under the same tag get distinct identities
// and cannot share an attestation/rehearsal/runtime record (Codex P1). A redeploy to a different build
// changes it, so a prior attestation no longer covers the current runtime. Local builds have no commit
// stamp and version "dev", so they remain non-attestable via RuntimeIdentity.Valid()'s placeholder set.
func currentRuntimeIdentity() canary.RuntimeIdentity {
	return canary.RuntimeIdentity{BuildVersion: composeBuildStamp(version, buildCommit)}
}

// composeBuildStamp binds the version tag to the immutable commit digest as "<version>+<commit>" when
// a commit is stamped, so the runtime identity is unique per commit rather than per (reusable) tag.
// With no commit stamp it is the bare version, preserving the local/"dev" placeholder behavior.
func composeBuildStamp(ver, commit string) string {
	if commit == "" {
		return ver
	}
	return ver + "+" + commit
}

// loadShadowExitAttestation is a PURE read of the durable attestation. A missing file returns
// (nil, nil) (no attestation — the fail-closed default). A corrupt/undecodable file also returns
// (nil, nil) so the node fails closed to "not attested" rather than trusting garbage — but it does
// NOT quarantine (rename) the file: this predicate is read on the activation-commit path while it
// already holds mcpRollout.durableMu, so a side-effecting rename here could neither take that lock
// (to be serialized against a concurrent POST/DELETE) without self-deadlocking, nor safely rename
// without it — the TOCTOU that would let a viewer read move aside a valid replacement (Codex P2).
// Moving a corrupt file aside (repair + visibility) is done by sweepCorruptShadowExitAttestation,
// which holds durableMu for the whole read+quarantine so it is atomic against the writers. A
// transient read error on an existing file is returned so the caller does not misread it as absent.
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
		return nil, nil // corrupt ⇒ fail closed to not-attested (quarantine is the sweep's job)
	}
	return &a, nil
}

// sweepCorruptShadowExitAttestation quarantines a corrupt attestation (moves it aside so the
// state-corruption alerting fires and the operator sees it), holding mcpRollout.durableMu across the
// READ and the quarantine so the compare-and-rename is ATOMIC against a concurrent admin POST/DELETE
// (which hold the same lock). This closes the TOCTOU where a stale read could rename a valid
// replacement installed after the read (Codex P2). It must NOT be called from a path already holding
// durableMu (the activation commit) — only from admin read surfaces that hold no lock. A missing,
// unreadable, or now-valid file is left untouched.
func sweepCorruptShadowExitAttestation() {
	rr := getMCPRollout()
	rr.durableMu.Lock()
	defer rr.durableMu.Unlock()
	path := shadowExitAttestationPath()
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		return // absent/unreadable — nothing to quarantine
	}
	var a canary.ShadowExitAttestation
	if derr := strictDecodeAttestationJSON(raw, &a); derr != nil {
		quarantineCorruptStateFile("mcp_shadow_exit_review", path, derr)
	}
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
	// The attestation is a DURABLE Canary prerequisite that authorizes a live-mode transition, so a
	// write that is visible but not crash-durable must NOT be reported as persisted:
	// fileutil.ErrReplacedNotSynced (the replacement landed but the parent-dir fsync failed) is
	// returned as a failure. Because that error is POST-rename, the not-durable record is already
	// visible at the target — removeVisibleFileAfterNotSyncedWrite removes it before returning, so a
	// write the POST reports as persisted:false is not readable by the gate (Codex P1).
	//
	// The whole write + compensating cleanup runs under mcpRollout.durableMu — the SAME lock the
	// activation commit holds while it reads the attestation (canaryNodeFactsLocked →
	// shadowExitReviewAttested) and the DELETE holds while it revokes. Without it, a commit could
	// observe the transient VISIBLE replacement in the window between a not-synced rename and its
	// removal and install Canary from a record the POST then reports as not persisted (Codex P1). No
	// caller of this function holds durableMu, so taking it here cannot self-deadlock.
	path := shadowExitAttestationPath()
	rr := getMCPRollout()
	rr.durableMu.Lock()
	defer rr.durableMu.Unlock()
	return removeVisibleFileAfterNotSyncedWrite(path, attestationAtomicWrite(path, raw, 0o600))
}

// attestationAtomicWrite is the durable-write seam for the attestation (tests inject failures,
// including fileutil.ErrReplacedNotSynced, to prove the write fails closed).
var attestationAtomicWrite = fileutil.AtomicWrite

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
	// Quarantine a corrupt attestation here (serialized under durableMu), not on the pure read path,
	// so the compare-and-quarantine cannot race a concurrent POST/DELETE (Codex P2). This handler
	// holds no lock, so the sweep is free to take durableMu.
	sweepCorruptShadowExitAttestation()
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
	// The evidence digest must be a canonical hex SHA-256 digest that identifies the exact reviewed
	// evidence bundle — a nonempty-but-arbitrary value ("x", "not-a-digest") must not be attestable
	// (Codex P2). Enforced here at the trust boundary; ValidateAttestation enforces it again on read.
	if !canary.ValidEvidenceDigest(req.EvidenceDigest) {
		http.Error(w, "shadow_exit_evidence_digest_must_be_hex_sha256", http.StatusBadRequest)
		return
	}
	// An attestation is only meaningful if it binds to a UNIQUE runtime identity — a placeholder or
	// non-unique build stamp ("dev" on a local/untagged build) cannot prove which code was reviewed, so
	// refuse to create one here rather than write a record that will never validate on read (Codex P1).
	if !currentRuntimeIdentity().Valid() {
		http.Error(w, "shadow_exit_review_requires_a_uniquely_versioned_build", http.StatusConflict)
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
	// Serialize the revocation with the activation commit AND make the unlink crash-durable.
	// The commit reads the attestation INSIDE mcpRollout.durableMu (canaryNodeFactsLocked →
	// shadowExitReviewAttested), so taking the same lock here makes revoke-vs-activate mutually
	// exclusive: a commit can never install Canary from an attestation that a concurrent,
	// already-acknowledged revocation removed (Codex P1). The unlink is then fsynced to the parent
	// directory so a crash right after the API returns revoked:true cannot resurrect the old PASSED
	// record and satisfy the gate again (Codex P1). Only a crash-durable removal is acknowledged.
	rr := getMCPRollout()
	rr.durableMu.Lock()
	err := removeAttestationDurable()
	rr.durableMu.Unlock()
	if err != nil {
		auditEvent(r, "mcp.canary.shadow-exit-review.revoke", "", "remove_failed")
		http.Error(w, "attestation_revoke_failed", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "mcp.canary.shadow-exit-review.revoke", "", "")
	jsonOK(w, map[string]any{"attested": false, "revoked": true})
}

// removeAttestationDurable unlinks the attestation and fsyncs the parent directory so the removal is
// crash-durable before the caller acknowledges the revocation. A missing file is success (already
// revoked); a non-ENOENT unlink error or a parent-dir sync failure is returned so the handler reports
// the revocation as failed rather than acknowledging a removal a crash could undo.
func removeAttestationDurable() error {
	path := shadowExitAttestationPath()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncParentDir(path)
}
