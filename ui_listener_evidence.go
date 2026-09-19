package main

// FE-6B.1 correction round (B1) — the admin listener's ACTIVATION EVIDENCE.
//
// The certificate the admin UI serves was previously CLAIMED from a boot-time
// selection flag (uiCustomTLSActive: resolveUITLSCertKey picked the persisted
// pair before startUI ran). That flag never observes whether the listener
// bound or what it serves, and it stays true after the persisted pair is
// replaced or deleted without a restart — so GET /api/certificates showed pair
// B's identity beside `active: true` while the listener still served A, and
// GET /api/settings/network agreed with it because both read the same
// variable. Agreement between two projections of one flag is not evidence.
//
// This file records what the listener ACTUALLY serves, from the one place that
// knows: adminUIServeOnce, at the instant the bind succeeds, with the pair it
// loaded (or the self-signed configuration it was handed). The record is:
//
//	state    serving | unknown  — "serving" only between an observed bind and
//	                              the serve call returning; "unknown" before
//	                              the first bind, and again once a serve ended
//	                              (the retry loop is rebinding).
//	posture  tls_custom      the persisted GUI-uploaded pair (customUITLSCertPath)
//	         tls_configured  an explicit -tls-cert/-tls-key pair
//	         tls_self_signed the auto self-signed certificate
//	         plain_http      no certificate (-ui-no-tls, or the self-sign fallback)
//	         unknown         no bind observed
//	served   the served leaf's public identity (fingerprint in the inventory's
//	         format, subject, validity) — present iff the posture is a TLS one.
//
// `servesPersistedPair` — and therefore the legacy `uiCert.active` and
// `ui_custom_cert_active` fields — is DERIVED at read time: the posture is
// tls_custom AND the persisted pair is complete and valid AND its certificate's
// fingerprint equals the served one. It is never a stored flag. Activation
// that has not been observed is reported UNKNOWN, never claimed.
//
// Residual, recorded: adminUIServeOnce validates the operator pair with one
// read and http.Server.ServeTLS re-reads the files a few microseconds later
// (the CHAOS-57 HTTP/2 note explains why the double read stays); a pair
// replaced in exactly that window is served but recorded as its predecessor
// until the next bind. The persisted-pair writers run through the staged
// marker transition, so an atomic replace lands whole on either side of it.

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

const (
	adminListenerServing = "serving"
	adminListenerUnknown = "unknown"

	adminListenerPostureCustom     = "tls_custom"
	adminListenerPostureConfigured = "tls_configured"
	adminListenerPostureSelfSigned = "tls_self_signed"
	adminListenerPosturePlainHTTP  = "plain_http"
	adminListenerPostureUnknown    = "unknown"
)

// adminServedCert is the served leaf's PUBLIC identity — never key material.
type adminServedCert struct {
	Fingerprint string
	Subject     string
	NotBefore   time.Time
	NotAfter    time.Time
}

type adminListenerEvidence struct {
	State   string
	Posture string
	Served  *adminServedCert // nil unless Posture is a TLS posture
}

var (
	adminListenerMu  sync.Mutex
	adminListenerRec = adminListenerEvidence{State: adminListenerUnknown, Posture: adminListenerPostureUnknown}
)

// recordAdminListenerServing is called by adminUIServeOnce AFTER the bind
// succeeded and BEFORE Serve starts, with the posture it decided and the leaf
// it will serve (nil for plain HTTP).
func recordAdminListenerServing(posture string, leaf *x509.Certificate) {
	rec := adminListenerEvidence{State: adminListenerServing, Posture: posture}
	if leaf != nil {
		rec.Served = &adminServedCert{
			Fingerprint: ca.FingerprintOf(leaf),
			Subject:     leaf.Subject.CommonName,
			NotBefore:   leaf.NotBefore.UTC(),
			NotAfter:    leaf.NotAfter.UTC(),
		}
	}
	adminListenerMu.Lock()
	adminListenerRec = rec
	adminListenerMu.Unlock()
}

// recordAdminListenerLost is called when a serve call returns — shutdown or a
// fault the retry loop will rebind after. Either way the bound listener is
// gone and nothing about what is served can be asserted until the next bind.
func recordAdminListenerLost() {
	adminListenerMu.Lock()
	adminListenerRec = adminListenerEvidence{State: adminListenerUnknown, Posture: adminListenerPostureUnknown}
	adminListenerMu.Unlock()
}

// adminListenerEvidenceNow returns a copy of the current evidence.
func adminListenerEvidenceNow() adminListenerEvidence {
	adminListenerMu.Lock()
	rec := adminListenerRec
	adminListenerMu.Unlock()
	if rec.Served != nil {
		s := *rec.Served
		rec.Served = &s
	}
	return rec
}

// adminListenerPostureFor decides the bounded posture a bind is about to
// serve: the persisted GUI-uploaded pair, an explicit operator pair, the auto
// self-signed certificate, or plain HTTP.
func adminListenerPostureFor(certFile string, customTLS, selfSigned bool) string {
	switch {
	case customTLS && certFile == customUITLSCertPath():
		return adminListenerPostureCustom
	case customTLS:
		return adminListenerPostureConfigured
	case selfSigned:
		return adminListenerPostureSelfSigned
	default:
		return adminListenerPosturePlainHTTP
	}
}

// adminListenerServesPersistedPair is the DERIVED activation fact behind the
// legacy `uiCert.active` / `ui_custom_cert_active`: the listener is observed
// serving the persisted GUI pair, i.e. the posture is tls_custom and the
// served certificate IS the complete, valid pair persisted right now.
func adminListenerServesPersistedPair() bool {
	rec := adminListenerEvidenceNow()
	if rec.State != adminListenerServing || rec.Posture != adminListenerPostureCustom || rec.Served == nil {
		return false
	}
	ev := uiPairEvidenceNow()
	if ev.class != uiPairComplete || !ev.valid {
		return false
	}
	leaf := persistedUICertLeaf()
	return leaf != nil && ca.FingerprintOf(leaf) == rec.Served.Fingerprint
}

// adminListenerReadModel is the server-owned listener object published on
// GET /api/certificates (`listener`) and GET /api/settings/network
// (`ui_listener`) — the SAME object on both reads.
func adminListenerReadModel() map[string]any {
	rec := adminListenerEvidenceNow()
	out := map[string]any{
		"state":               rec.State,
		"posture":             rec.Posture,
		"servesPersistedPair": adminListenerServesPersistedPair(),
	}
	if rec.Served != nil {
		out["servedCertificate"] = map[string]any{
			"fingerprint": rec.Served.Fingerprint,
			"subject":     rec.Served.Subject,
			"notBefore":   rec.Served.NotBefore.Format(time.RFC3339),
			"notAfter":    rec.Served.NotAfter.Format(time.RFC3339),
		}
	}
	return out
}

// resetAdminListenerEvidenceForTest clears the record. Test isolation only;
// called from resetAdminUIHealthForTest.
func resetAdminListenerEvidenceForTest() {
	recordAdminListenerLost()
}
