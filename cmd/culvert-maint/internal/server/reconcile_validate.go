// Record-ref re-validation for RISK-022 PR-E (slice E1c, design §0 P0-E).
//
// The reconciler feeds refs from an on-disk, UNAUTHENTICATED journal record to
// root `docker pull`/`tag`. This file is the trust gate that keeps that safe:
// before any docker action, every actionable ref (PriorRef/TargetRef) must
// pass, all pure/side-effect-free:
//  1. the repo-bound exact-digest gate (runner.ValidatePinnedDigestRef — the
//     same check the apply handler + sudoers pattern enforce), so a
//     foreign-repo or tag "pin" is rejected;
//  2. the operator's image_allowlist (enforced only by the apply HANDLER, which
//     reconcile does NOT go through — so it must be re-applied here);
//  3. ref⇔digest consistency — the digest embedded in the ref must equal the
//     record's bare-digest field, so the digest the reconciler REASONS about
//     is the one it DEPLOYS (closes the decision-digest / action-digest split).
//
// A record that fails is a loud-stop for the caller (reconcileDecision returns
// actLoudStop when RefValid is false); this file just computes RefValid.
package server

import (
	"fmt"
	"regexp"
	"strings"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/runner"
)

// validateRecordRef re-validates one (ref, bareDigest) pair from a journal
// record. proxyRepo binds the repo; allow is the operator image_allowlist.
func validateRecordRef(ref, bareDigest, proxyRepo string, allow *regexp.Regexp) error {
	if ref == "" {
		return fmt.Errorf("empty ref")
	}
	if err := runner.ValidatePinnedDigestRef(ref, proxyRepo); err != nil {
		return fmt.Errorf("repo-bound pin: %w", err)
	}
	if allow == nil || !allow.MatchString(ref) {
		return fmt.Errorf("ref %q not permitted by image_allowlist", ref)
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
func validateReconcileRefs(rec *journal.Record, proxyRepo string, allow *regexp.Regexp) (valid bool, reason string) {
	checked := 0
	if rec.TargetRef != "" || rec.TargetDigest != "" {
		if err := validateRecordRef(rec.TargetRef, rec.TargetDigest, proxyRepo, allow); err != nil {
			return false, "target: " + err.Error()
		}
		checked++
	}
	if rec.PriorRef != "" || rec.PriorDigest != "" {
		if err := validateRecordRef(rec.PriorRef, rec.PriorDigest, proxyRepo, allow); err != nil {
			return false, "prior: " + err.Error()
		}
		checked++
	}
	if checked == 0 {
		return false, "no actionable ref in record"
	}
	return true, ""
}
