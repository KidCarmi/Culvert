package main

// diagnostics_cdr_client_cert.go — operator-contract row for the client
// certificates Culvert presents to enrolled Sluice (CDR) instances.
//
// The health poller renews a Sluice client certificate automatically once
// fewer than cdrRenewWindow days remain (maybeRenewExpiringClients), but a
// renewal that keeps failing is recorded only in the application log. The
// remaining validity was visible only as a badge in CDR → Instances, so the
// one-page diagnostics report stayed green until the certificate expired, the
// instance stopped authenticating, and CDR went enabled-reduced or dark.
//
// Report-only: reads each enrolled instance's certificate NotAfter through the
// same path-guarded loadCertExpiry the instances API uses. No renewal is
// triggered, no breaker or registry state is touched. Contributes nothing while
// CDR is disabled or every enabled instance has more than
// cdrClientCertWarnDays left. The row is viewer-visible, so it carries counts
// only — no instance names, endpoints or paths.

import (
	"fmt"
	"time"
)

// cdrClientCertWarnDays is the remaining validity below which the row warns.
// Renewal starts at cdrRenewWindow (30) days, so reaching 14 means roughly two
// weeks of failed renewals; it also matches the GUI's red "renew now" badge.
const cdrClientCertWarnDays = 14

// checkCDRClientCertExpiry returns zero or one row summarizing enabled Sluice
// instances whose client certificate has expired or is about to.
func checkCDRClientCertExpiry() []OperatorContractCheck {
	if !cdrActiveConfig().Enabled {
		return nil
	}
	return cdrClientCertExpiryRows(cdrInstances.SnapshotView(), time.Now())
}

func cdrClientCertExpiryRows(insts []CDREnrolledInstance, now time.Time) []OperatorContractCheck {
	expired, expiring := 0, 0
	soonest := -1
	for i := range insts {
		inst := &insts[i]
		if !inst.IsEnabled() {
			continue
		}
		notAfter, err := loadCertExpiry(inst.ClientCertPath)
		if err != nil {
			continue // unreadable: the instances panel shows "-" for it too
		}
		// Branch on the timestamp: daysUntil truncates toward zero, so the
		// first 24h after expiry would otherwise read as "0 days left".
		if !now.Before(notAfter) {
			expired++
			continue
		}
		days := int(notAfter.Sub(now).Hours() / 24)
		if days >= cdrClientCertWarnDays {
			continue
		}
		expiring++
		if soonest < 0 || days < soonest {
			soonest = days
		}
	}
	if expired == 0 && expiring == 0 {
		return nil
	}
	var msg string
	switch {
	case expired > 0 && expiring > 0:
		msg = fmt.Sprintf("%d Sluice instance client certificate(s) have expired and %d more expire within %d days — "+
			"expired instances cannot authenticate to Sluice, so CDR cannot use them", expired, expiring, cdrClientCertWarnDays)
	case expired > 0:
		msg = fmt.Sprintf("%d Sluice instance client certificate(s) have expired — those instances cannot authenticate "+
			"to Sluice, so CDR cannot use them", expired)
	default:
		msg = fmt.Sprintf("%d Sluice instance client certificate(s) expire within %d days (soonest in %d days) and "+
			"automatic renewal has not replaced them", expiring, cdrClientCertWarnDays, soonest)
	}
	return []OperatorContractCheck{{
		Code:    "cdr_client_cert",
		Status:  diagWarn,
		Message: msg,
		OperatorAction: fmt.Sprintf("Open CDR → Instances; the Cert expires column shows each instance's remaining validity. "+
			"Culvert renews these certificates automatically over the Sluice connection once fewer than %d days remain, "+
			"so a certificate this close to (or past) expiry means renewal is failing or not running: confirm the instance "+
			"is reachable and healthy there, and note that the renewal poller starts only when CDR is enabled at startup "+
			"(a node that enabled CDR at runtime renews nothing until it restarts). If it still does not renew, Revoke "+
			"the instance and re-enroll it with a fresh token and fingerprint from the Sluice admin.", cdrRenewWindow),
	}}
}
