package main

import "sync"

// object_reference_gate.go — the reference-integrity mutation gate (2D-B
// final correction, Blocker B / §§4–8; recorded gap: POLICY-REFS-PLAN.md).
//
// THE DEFECT IT CLOSES: every shared-object delete ran as
// deleteBlockedByReferences(...) — scan says "unreferenced" — followed by a
// separate store delete. A reference writer landing between the scan and the
// delete (rule create/edit, group-membership write, Policy Learning
// Accept-to-Draft, bulk install) could commit a reference to the object being
// deleted: both requests 2xx, and a Deny rule scoped to the deleted category
// silently stops matching — fail-open, exactly what the walk exists to
// prevent.
//
// THE GATE: one process-wide RWMutex, deliberately narrow — NOT a generic
// config transaction framework. The gate serializes the two sides; the
// DELETE-FIRST serial order is closed by the writer-side target validation
// (policy_ref_validation.go): a shared-side writer validates its reference
// targets under the gate before committing, so a writer waking after a
// successful delete refuses (structured 400) instead of committing a
// dangling reference.
//
//   - EXCLUSIVE side (Lock): an object DELETE holds it across the
//     authoritative reference scan AND the durable deletion, so the scan's
//     verdict is still true when the delete lands. Bulk installs (config
//     import's apply region, config-version rollback, CP→DP snapshot apply)
//     are exclusive too: a bulk install both removes objects and installs
//     references, so it must not interleave with either side.
//   - SHARED side (RLock): reference-CREATING/CHANGING writers — live/staged
//     access-rule create + edit, auth-rule create + edit, category-group
//     create + membership edit (groups reference categories), decryption-
//     profile update (the rename cascade rewrites rule references), Policy
//     Learning Accept-to-Draft. Concurrent reference writers never conflict
//     with each other; each serializes only against deletes/bulk installs.
//
// AUDITED NON-HOLDERS (§6 — classified, deliberately outside the gate):
//   - rule delete / bulk-delete / reorder / move, auth-rule delete/reorder,
//     draft discard-staged: reference-REMOVING or order-only — they cannot
//     create a dangling reference; at worst a delete's scan sees a
//     just-removed reference and over-blocks (the safe direction).
//   - draft commit / revert: the objectReferences walk already covers the
//     ACTIVE draft candidate, so commit only promotes references the scan
//     could already see, and revert discards references — neither creates a
//     reference invisible to a concurrent scan.
//   - startup loaders (Load, before any listener): exempt by ordering.
//
// LOCK ORDER (acyclic; the gate is OUTERMOST): objectReferenceMutationGate →
// { policy writeGate / policyDraft coordinator mu / PolicyStore mu /
//
//	catgroup mutMu / decryptprofile mutMu / urlcat mutMu /
//	configRollbackMu → adminSettingsMu (rollback's feed slice) }.
//
// The gate is acquired only at handler / bulk-apply entry, before any store
// or coordinator lock; nothing reachable under those locks acquires the gate
// (objectReferences, captureConfigBackup, CurrentConfigSnapshot and every
// store accessor are read-only w.r.t. the gate), so no cycle exists. Shared
// acquisitions must never nest (an RLock inside an RLock can deadlock
// against a queued writer) — each handler acquires exactly once at its top.
var objectReferenceMutationGate sync.RWMutex

// refScanDeleteLock enters the exclusive side: the caller owns the reference
// scan + durable delete (or a bulk install) as one atomic decision.
func refScanDeleteLock() { objectReferenceMutationGate.Lock() }

// refScanDeleteUnlock leaves the exclusive side.
func refScanDeleteUnlock() { objectReferenceMutationGate.Unlock() }

// refWriteLock enters the shared side: the caller creates or changes
// references to shared objects.
func refWriteLock() { objectReferenceMutationGate.RLock() }

// refWriteUnlock leaves the shared side.
func refWriteUnlock() { objectReferenceMutationGate.RUnlock() }
