// Record-ref re-validation for RISK-022 PR-E (slice E1c, design §0 P0-E).
//
// The reconciler feeds refs from an on-disk, UNAUTHENTICATED journal record to
// root `docker pull`/`tag`. This file is the trust gate that keeps that safe:
// before any docker action, every actionable ref (PriorRef/TargetRef) must
// pass, all pure/side-effect-free:
//  1. the repo-bound exact-digest gate (runner.ValidatePinnedDigestRef — the
//     same check the apply handler + sudoers pattern enforce), so a
//     foreign-repo or tag "pin" is rejected;
//  2. ref⇔digest consistency — the digest embedded in the ref must equal the
//     record's bare-digest field, so the digest the reconciler REASONS about
//     is the one it DEPLOYS (closes the decision-digest / action-digest split).
//
// NOTE on image_allowlist (design §0 P0-E refinement): the allowlist is an
// ADMISSION-time policy — the apply handler matches the operator's ORIGINAL
// image_ref, which may be a TAG (`repo:v1`), then resolves it to a digest ref
// stored in the journal. Re-matching a tag-scoped allowlist against the resolved
// `repo@sha256:` ref would spuriously reject a policy-admitted upgrade, so the
// allowlist is deliberately NOT re-checked here. The reconcile-time trust
// control is repo-binding + ref⇔digest, which already blocks the crown-jewel
// foreign-repo injection: an attacker can at most name a different digest of the
// SAME configured proxyRepo, and one who can push a malicious digest there has
// already compromised the source of truth (the allowlist would not have helped).
//
// A record that fails is a loud-stop for the caller (reconcileDecision returns
// actLoudStop when RefValid is false); this file just computes RefValid.
package server

import (
	"fmt"
	"strings"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/runner"
)

// validateRecordRef re-validates one (ref, bareDigest) pair from a journal
// record. proxyRepo binds the repo.
func validateRecordRef(ref, bareDigest, proxyRepo string) error {
	if ref == "" {
		return fmt.Errorf("empty ref")
	}
	if err := runner.ValidatePinnedDigestRef(ref, proxyRepo); err != nil {
		return fmt.Errorf("repo-bound pin: %w", err)
	}
	// ref⇔digest consistency: the digest embedded in ref must equal the record's
	// bare-digest field.
	const marker = "@sha256:"
	i := strings.Index(ref, marker)
	if i < 0 {
		return fmt.Errorf("ref %q has no @sha256: digest", ref)
	}
	embedded := ref[i+len(marker):]
	want := strings.TrimPrefix(bareDigest, "sha256:")
	if want == "" {
		return fmt.Errorf("record has no digest to cross-check ref %q", ref)
	}
	if embedded != want {
		return fmt.Errorf("ref digest %q does not match record digest %q", embedded, want)
	}
	return nil
}

// validateReconcileRefs returns whether ALL actionable refs in rec are safe to
// feed to docker. An absent ref/digest pair is skipped (a record legitimately
// may carry only one), but at least one actionable ref must be present and
// valid — a record with no validatable ref is not actionable and returns
// (false, reason). The first failing ref's reason is returned for the audit
// trail.
func validateReconcileRefs(rec *journal.Record, proxyRepo string) (valid bool, reason string) {
	checked := 0
	if rec.TargetRef != "" || rec.TargetDigest != "" {
		if err := validateRecordRef(rec.TargetRef, rec.TargetDigest, proxyRepo); err != nil {
			return false, "target: " + err.Error()
		}
		checked++
	}
	if rec.PriorRef != "" || rec.PriorDigest != "" {
		if err := validateRecordRef(rec.PriorRef, rec.PriorDigest, proxyRepo); err != nil {
			return false, "prior: " + err.Error()
		}
		checked++
	}
	if checked == 0 {
		return false, "no actionable ref in record"
	}
	return true, ""
}
