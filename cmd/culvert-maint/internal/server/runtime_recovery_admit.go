// Runtime recovery admission (ADR-0062 slice 6, PR 3): every condition is
// checked on fresh facts; the first that does not hold is the reason, and
// nothing changes. See runtime_recovery.go for the list.
package server

import (
	"context"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/runtimehealth"
)

// Refusal reasons (RuntimeRecoveryAttempt.Reason) of admission.
const (
	rrSettleOpen        = "settle_window_open"
	rrLockHeld          = "lock_held"
	rrDockerUnreadable  = "docker_unreadable"
	rrNotRunning        = "proxy_not_running"
	rrIdentityChanged   = "identity_changed"
	rrTagUnreadable     = "pinned_tag_unreadable"
	rrTagDiffers        = "tag_differs_from_running"
	rrProvenanceUnread  = "provenance_unreadable"
	rrNoProvenance      = "no_provenance"
	rrInstalledRefBad   = "installed_ref_invalid"
	rrGatedUnreadable   = "gated_history_unreadable"
	rrNotGated          = "restore_image_not_gated"
	rrRestoreRefBad     = "restore_ref_not_allowed"
	rrRestoreNotLocal   = "restore_image_not_local"
	rrAttemptsUnread    = "attempts_unreadable"
	rrAttemptsExhausted = "attempts_exhausted"
)

// admitRuntimeRecovery checks admission for trig. locked: the caller holds the
// maintenance lock as the runtime.recover operation (otherwise any holder
// refuses).
func (s *Server) admitRuntimeRecovery(ctx context.Context, trig runtimeTrigger, locked bool) (adm *runtimeAdmission, why string) {
	if s.settleRemaining() > 0 {
		return nil, rrSettleOpen
	}
	if h := s.opts.Ops.Holder(); h != nil && (!locked || h.Kind != ops.KindRuntimeRecover) {
		return nil, rrLockHeld
	}
	if why = s.admitIdentity(ctx, trig); why != "" {
		return nil, why
	}
	if adm, why = s.recoverySource(trig.imageID); why != "" {
		return nil, why
	}
	if why = s.admitRestoreImage(ctx, adm); why != "" {
		return nil, why
	}
	compat, _ := dataCompat(s.restoreCompatFacts(ctx, adm.r.Ref))
	switch compat {
	case compatIncompatible:
		return nil, "restore_incompatible"
	case compatUnknown:
		return nil, "restore_compatibility_unknown"
	}
	a, err := s.opts.RuntimeHealth.ReadRecoverAttempts()
	if err != nil {
		return nil, rrAttemptsUnread
	}
	adm.attempts = a
	if adm.begun = a.For(adm.sourceOpID, adm.x); adm.begun >= runtimehealth.MaxRecoverAttempts {
		return nil, rrAttemptsExhausted
	}
	return adm, ""
}

// recoverySourceInForce reports whether sourceOpID can still authorize a
// recovery: it is the install installed.json names or a record still in the
// journal. Anything that cannot be read counts as in force, so a count is
// kept rather than forgotten.
func (s *Server) recoverySourceInForce(sourceOpID string) bool {
	if in, err := s.opts.RuntimeHealth.ReadInstalled(); err != nil || (in != nil && in.OpID == sourceOpID) {
		return true
	}
	_, found, err := s.opts.Journal.Read(sourceOpID)
	return err != nil || found
}

// admitIdentity: the proxy container the samples were of runs, and the fixed
// tag is on its image.
func (s *Server) admitIdentity(ctx context.Context, trig runtimeTrigger) string {
	pc, err := s.opts.Runner.ReadProxyContainer(ctx)
	switch {
	case err != nil:
		return rrDockerUnreadable
	case !pc.Present || !pc.Running:
		return rrNotRunning
	case pc.ContainerID != trig.containerID || normID(pc.ImageID) != normID(trig.imageID):
		return rrIdentityChanged
	}
	tag, err := s.opts.Runner.PinnedTagImageID(ctx)
	switch {
	case err != nil || tag == "":
		return rrTagUnreadable
	case normID(tag) != normID(pc.ImageID):
		return rrTagDiffers
	}
	return ""
}

// recoverySource finds the change of this agent that put x there: the last
// verified upgrade (installed.json) or a kept upgrade record. Its prior is the
// restore image; which reference restores it comes from gated.json.
func (s *Server) recoverySource(x string) (adm *runtimeAdmission, why string) {
	in, err := s.opts.RuntimeHealth.ReadInstalled()
	if err != nil {
		return nil, rrProvenanceUnread
	}
	if in != nil && normID(in.ImageID) == normID(x) {
		if validateRecordRef(in.Ref, in.Digest, s.opts.Cfg.ProxyRepo) != nil {
			return nil, rrInstalledRefBad
		}
		return &runtimeAdmission{sourceOpID: in.OpID, x: x, xRef: in.Ref, xDigest: in.Digest,
			r: runtimehealth.GatedEntry{ImageID: in.ReplacedImageID}}, ""
	}
	rec, why := s.keptUpgradeFor(x)
	if why != "" {
		return nil, why
	}
	return &runtimeAdmission{sourceOpID: rec.OpID, x: x, xRef: rec.TargetRef, xDigest: rec.TargetDigest,
		r: runtimehealth.GatedEntry{ImageID: rec.PriorImageID}}, ""
}

// keptUpgradeFor returns a kept upgrade record of this agent whose target is
// x, with validated references and a prior other than x.
func (s *Server) keptUpgradeFor(x string) (rec *journal.Record, why string) {
	recs, err := s.opts.Journal.List()
	if err != nil {
		return nil, rrProvenanceUnread
	}
	for i := range recs {
		cand := &recs[i]
		if cand.Kind != ops.KindUpgradeApply || cand.Mode != "" || cand.FromNewerAgent() || s.opts.Ops.IsRunning(cand.OpID) {
			continue
		}
		if normID(cand.TargetImageID) != normID(x) || cand.PriorImageID == "" || normID(cand.PriorImageID) == normID(x) {
			continue
		}
		if ok, _ := validateReconcileRefs(cand, s.opts.Cfg.ProxyRepo); !ok || cand.TargetRef == "" {
			continue
		}
		return cand, ""
	}
	return nil, rrNoProvenance
}

// admitRestoreImage: R was gated, its gated reference passes the repo-bound
// exact-digest gate and the image allowlist, and it is local as R. Fills
// adm.r with the gated entry.
func (s *Server) admitRestoreImage(ctx context.Context, adm *runtimeAdmission) string {
	h, err := s.opts.RuntimeHealth.ReadGated()
	if err != nil {
		return rrGatedUnreadable
	}
	var entry *runtimehealth.GatedEntry
	if h != nil {
		for i := range h.Entries {
			if normID(h.Entries[i].ImageID) == normID(adm.r.ImageID) {
				entry = &h.Entries[i]
			}
		}
	}
	if entry == nil {
		return rrNotGated
	}
	ref, digest := s.validatedRef([]string{entry.Ref})
	if ref == "" || digest != entry.Digest {
		return rrRestoreRefBad
	}
	if id, lerr := s.opts.Runner.LocalImageID(ctx, ref); lerr != nil || normID(id) != normID(entry.ImageID) {
		return rrRestoreNotLocal
	}
	adm.r = *entry
	return ""
}

// restoreCompatFacts reads what dataCompat judges for the restore reference.
func (s *Server) restoreCompatFacts(ctx context.Context, ref string) (runner.EpochRange, error, *runner.DataEpoch, error) {
	rng, rerr := s.opts.Runner.ImageDataEpochRange(ctx, ref)
	de, derr := s.opts.Runner.ReadDataEpoch(ctx)
	return rng, rerr, de, derr
}
