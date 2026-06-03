package main

// CA-3 PR6 — key-at-rest audit events + read-only diagnostics status.
//
// Two operator-safe surfaces on top of the CA-3 key-at-rest work (PRs #319,
// #320, #321/#323, #331):
//
//   - auditKeyAtRest(): emits audit-ring entries for key-at-rest lifecycle
//     outcomes (migration completed/failed, unlock failed). Per ADR §10 the
//     Object is a LOGICAL NAME only (cluster-ca / dp-node / cdr-client) — never
//     key bytes, passphrases, fingerprints, serials, SANs, subjects, node IDs,
//     paths, or file contents. Detail is always empty for the same reason.
//
//   - checkKeyAtRest(): a read-only OperatorContract check surfaced through the
//     existing /api/diagnostics endpoint, reporting per-subsystem encryption
//     MODE (on/off) and the process KEK SOURCE (env / file) as enums only. It
//     never reads, derives, or exposes any key/KEK material — it only reflects
//     which opt-in env vars are set and which KEK provider would be selected.
//
// Scope: diagnostics/status + audit only. No backup/restore, no rollback/
// ConfigSnapshot, no metrics, no mandatory KMS, no key-material exposure, no new
// write/unlock paths, and no secret accepted over the web.

import (
	"fmt"
	"strings"
	"time"
)

// keyAtRestActor is the synthetic actor for system-initiated key-at-rest audit
// events (migrations run at startup/load, outside any HTTP request). It is an
// identifier, not an address, and contains no secret.
const keyAtRestActor = "system@key-at-rest"

// CA-3 key-at-rest audit action names (ADR §10). Only the events that map to
// real code paths today are defined here.
const (
	auditKeyAtRestMigrateCompleted = "keyatrest.migrate.completed"
	auditKeyAtRestMigrateFailed    = "keyatrest.migrate.failed"
	auditKeyAtRestUnlockFailed     = "keyatrest.unlock.failed"
)

// Logical subsystem names used as the audit Object and in diagnostics. These are
// non-secret identifiers, never paths or key material.
const (
	keyAtRestObjClusterCA = "cluster-ca"
	keyAtRestObjDPNode    = "dp-node"
	keyAtRestObjCDRClient = "cdr-client"
)

// auditKeyAtRest writes a key-at-rest lifecycle event to the audit ring with a
// system actor. object MUST be a logical subsystem name (cluster-ca / dp-node /
// cdr-client); never pass key material, a path, or a fingerprint. Detail is
// intentionally omitted.
func auditKeyAtRest(action, object string) {
	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  keyAtRestActor,
		Action: action,
		Object: object,
	})
}

// processKEKSource reports the process-level KEK source as a non-secret enum.
// CULVERT_KEK (env, model C) is global and takes precedence everywhere when set
// to a usable value; otherwise subsystems fall back to their own local model-B
// KEK file ("file"). It never exposes key bytes — the env value is only probed
// for validity, and the decoded bytes are discarded.
func processKEKSource() string {
	if _, err := newEnvKEKProvider(envKEKName).KEK(); err == nil {
		return "env"
	}
	return "file"
}

// checkKeyAtRest reports the CA-3 key-at-rest posture for the operator contract.
// It is read-only and exposes only enums (mode on/off, KEK source), never key
// material. When no subsystem has encryption enabled it returns an informational
// OK (the feature is opt-in).
func checkKeyAtRest() OperatorContractCheck {
	enabled := make([]string, 0, 3)
	if clusterCAKeyEncryptionEnabled() {
		enabled = append(enabled, keyAtRestObjClusterCA)
	}
	if dpNodeKeyEncryptionEnabled() {
		enabled = append(enabled, keyAtRestObjDPNode)
	}
	if cdrClientKeyEncryptionEnabled() {
		enabled = append(enabled, keyAtRestObjCDRClient)
	}

	if len(enabled) == 0 {
		return OperatorContractCheck{
			Code:    "key_at_rest",
			Status:  diagOK,
			Message: "key-at-rest encryption disabled (opt-in; private keys stored as plaintext PEM 0600)",
		}
	}

	return OperatorContractCheck{
		Code:   "key_at_rest",
		Status: diagOK,
		Message: fmt.Sprintf("key-at-rest encryption enabled for: %s; KEK source: %s",
			strings.Join(enabled, ", "), processKEKSource()),
	}
}
