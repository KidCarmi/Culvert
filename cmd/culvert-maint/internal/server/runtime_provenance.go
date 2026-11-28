// Provenance for runtime recovery (ADR-0062 slice 6, PR 1; owner decision
// 2026-11-28: act only on images this agent installed).
package server

import (
	"log"
	"time"

	"culvert-maint/internal/runtimehealth"
)

// noteInstalledBestEffort records, after an upgrade's health gate and digest
// verify passed, the image it installed and the image it replaced. Only when
// the runtime health store is set (runtime_health_interval on). A failure is
// logged and changes nothing about the upgrade: without the record a later
// runtime recovery simply has no provenance and does not act.
func (s *Server) noteInstalledBestEffort(acc *upgradeApplyAccumulator) {
	st := s.opts.RuntimeHealth
	if st == nil || acc.runningAfterID == "" || acc.priorImageID == "" || acc.priorImageID == acc.runningAfterID {
		return
	}
	in := runtimehealth.Installed{
		OpID: acc.opID, Kind: "upgrades.apply",
		ImageID: acc.runningAfterID, Ref: acc.pinnedRef, Digest: acc.pinnedDigest,
		ReplacedImageID: acc.priorImageID, ReplacedRef: acc.priorRef,
		InstalledAt: time.Now().UTC(),
	}
	if err := st.WriteInstalled(in); err != nil {
		log.Printf("culvert-maint: WARN: the installed-image record could not be written: %q", err.Error())
	}
}
