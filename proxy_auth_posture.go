package main

// proxy_auth_posture.go — the durable proxy-authentication posture (owner
// decision "Durable Authentication Posture", 2026-11-23; ADR-0063; contract
// AUTH-006).
//
// INVARIANT: once proxy authentication has been established on a node it
// cannot disappear silently. Only an explicit, authorized policy decision —
// the Exempt global default or a scoped Exempt authentication rule — admits
// traffic without credentials. Removing, disabling or failing to load the last
// proxy identity provider never does.
//
// Before this, a node with no admin-roster accounts whose last proxy provider
// went away read as "no backend": resolveRequestAuth's no-backend inert guard
// let every request through to Stage 2 as "unauth", and SOCKS5 offered
// NO-AUTH. Provider AVAILABILITY decided whether authentication was required.
// Now the ratchet (internal/authposture, a Config field so it is reset with
// the rest of the auth state) is the authority: established + no usable
// provider = the existing fail-closed "required but nothing can verify" state
// of owner Decision 2 (#2048) — HTTP 407, SOCKS5 USER/PASS only and refused.
//
// ACTIVATION PATHS (every place a proxy identity provider becomes usable), and
// how each sets the marker:
//
//   - Admin API create/update/enable of an IdP profile (POST /api/idp,
//     PUT /api/idp/{id}) → IdPRegistry.Upsert: WRITE-AHEAD. After the
//     candidate compiled and BEFORE the registry file is persisted or the
//     provider published, establishProxyAuthPosture; if the marker cannot be
//     written, Upsert fails with errIdPPersistFailed (HTTP 500) and nothing
//     changes. The legacy-LDAP import (POST /api/idp/legacy-ldap/import) also
//     reaches Upsert but stores a DISABLED profile, which activates nothing.
//   - CP→DP snapshot apply → IdPRegistry.ReplaceAll: WRITE-AHEAD, same order
//     (after the compile loop, before persist/publish); a failure rejects the
//     snapshot (the existing ReplaceAll rejection path), so the DP keeps its
//     previous registry and the next snapshot retries. A later snapshot that
//     carries no provider, or omits the field, never clears it: nothing does.
//   - CP→DP posture replication → ConfigSnapshot.ProxyAuthEstablished, merged
//     in syncSnapshotIdPProfiles on every DP apply path: true establishes the
//     DP's marker WRITE-AHEAD (failure rejects the snapshot), false/absent is a
//     no-op. So a DP enrolled after the CP's last provider was removed is
//     established, not fresh. The CP captures it in CurrentConfigSnapshot and
//     republishes when migration or recovery establishes it outside an admin
//     write (republishProxyAuthPostureOnControlPlane).
//   - Startup load of the registry file → IdPRegistry.Load, and the CHAOS-87
//     recovery loop publishing a profile that was dark at boot →
//     FAIL-CLOSED: the posture is raised even if the marker cannot be written
//     (the activation cannot be refused: the profile is already on disk), the
//     status reports not_durable, and the next activation retries the write.
//   - Startup wiring of a legacy (config.yaml) ldap/oidc provider →
//     loadLegacyAuthProviders: FAIL-CLOSED, as above.
//   - Config import (POST /api/config/import) and config-version rollback carry
//     NO identity provider (idp_profiles is Sensitive and off both surfaces,
//     config_surfaces.go), so they can neither establish nor clear the posture.
//     Backup restore is offline: the restored registry is loaded at the next
//     start (the startup path above), and the marker itself is merged
//     monotonically by the restore (restore.go stageProxyAuthPosture).
//
// WRITE ORDERING AND CRASH WINDOWS. The marker is written with the repository's
// durable atomic writer (atomicWriteFile → internal/fileutil.AtomicWrite: temp
// file, fsync, rename, directory fsync), so it is never torn.
//
//   - Write-ahead paths: marker durable → registry file durable → provider
//     published → activation reported. A crash after the marker and before
//     the registry write leaves "established, provider not saved": the node
//     restarts refusing authentication-required traffic until a provider is
//     configured (fail closed, never open). A crash before the marker write
//     leaves nothing changed. There is no moment at which an activation has
//     been reported and the marker is not durable.
//   - Fail-closed paths: the provider is already durable configuration; the
//     posture is raised in memory immediately. If the write fails, the
//     configuration that triggered it (registry profile, config.yaml block) is
//     itself the migration evidence below whenever the marker is missing.
//     Residual window: a node with a FRESH record whose fail-closed write
//     failed and whose provider is then deleted (another durable write that
//     would have to succeed on the same disk) restarts fresh; the
//     proxy_auth_posture Diagnostics row reports not_durable meanwhile.
//
// MIGRATION (marker file missing, i.e. the first start of this build, or a
// marker removed by hand). initProxyAuthPosture runs before anything can
// activate a provider; completeProxyAuthPostureMigration runs once all
// evidence is loaded (registry, legacy providers, admin settings) and before
// the SOCKS5 pre-posture gate opens and the HTTP proxy listener starts. If
// there is ANY evidence that proxy authentication was configured — at least
// one IdP profile stored in the registry (enabled or not), a legacy provider
// wired, a legacy config.yaml ldap block (wired or retired), or the durable
// legacy-LDAP retirement sentinel — the node is established ("migration:
// <evidence>"). Otherwise it is fresh, and a fresh record is written so the
// migration does not re-run on every start (a later, disabled-only profile
// then does not establish it at the next restart). A provider that is live at
// startup has already established the posture through the Load hook.
//
// A corrupt or unreadable marker is ESTABLISHED (fail closed), left untouched
// on disk for inspection, logged, and surfaced by the proxy_auth_posture row.
//
// Nothing lowers the posture: no API, no config write, no snapshot, no
// rollback. The only way back to unauthenticated operation is explicit policy
// (Exempt). An operator with host access can still remove the marker file;
// the next start then re-derives the posture from the evidence above.

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/KidCarmi/Culvert/internal/authposture"
)

// proxyAuthPostureFileName is the marker beside the other persisted state.
const proxyAuthPostureFileName = "proxy_auth_posture.json"

// proxyAuthPostureTarPath is the marker's path inside a backup archive.
const proxyAuthPostureTarPath = "data/" + proxyAuthPostureFileName

// proxyAuthPostureCode is the operator-contract row code.
const proxyAuthPostureCode = "proxy_auth_posture"

// proxyAuthPosturePath is where this node keeps its marker.
func proxyAuthPosturePath() string { return filepath.Join(dataDir, proxyAuthPostureFileName) }

// ProxyAuthEstablished reports whether proxy authentication is required even
// with no usable proxy identity provider. One atomic load: no lock, no
// allocation, no I/O (the proxy hot path reads it).
func (c *Config) ProxyAuthEstablished() bool {
	if c == nil {
		return false
	}
	r := c.authPosture.Load()
	return r != nil && r.Established()
}

// proxyAuthPosture returns c's ratchet, creating an empty (in-memory, not
// established) one on first use.
func (c *Config) proxyAuthPosture() *authposture.Ratchet {
	if r := c.authPosture.Load(); r != nil {
		return r
	}
	c.authPosture.CompareAndSwap(nil, new(authposture.Ratchet))
	return c.authPosture.Load()
}

// initProxyAuthPosture opens the marker at startup, BEFORE any path that can
// activate a provider (registry load, legacy providers, cluster snapshots).
func initProxyAuthPosture(path string) {
	outcome, err := cfg.proxyAuthPosture().Open(path, atomicWriteFile, nil)
	switch outcome {
	case authposture.OutcomeEstablished:
		st := cfg.proxyAuthPosture().Status()
		logger.Printf("AuthPosture: proxy authentication ESTABLISHED since %s (by %q)", st.Since, sanitizeLog(st.By))
	case authposture.OutcomeCorrupt, authposture.OutcomeUnreadable:
		logWarnf("AuthPosture: the proxy authentication posture marker is %s; treating proxy authentication as ESTABLISHED (fail closed): %q",
			cfg.proxyAuthPosture().Status().Problem, sanitizeLog(fmt.Sprint(err)))
	case authposture.OutcomeMissing:
		logger.Printf("AuthPosture: no posture marker yet; it is derived from the configured providers once startup has loaded them")
	case authposture.OutcomeFresh:
		logger.Printf("AuthPosture: proxy authentication not established (no proxy identity provider has been activated on this node)")
	}
}

// establishProxyAuthPosture is the WRITE-AHEAD activation hook: call it before
// the activation is persisted or published, and refuse the activation when it
// returns an error.
func establishProxyAuthPosture(by string) error {
	changed, err := cfg.proxyAuthPosture().Establish(by, time.Now())
	if err != nil {
		logWarnf("AuthPosture: could not persist the proxy authentication posture (%q); the activation is refused: %q",
			sanitizeLog(by), sanitizeLog(err.Error()))
		return err
	}
	if changed {
		noteProxyAuthEstablished(by)
	}
	return nil
}

// establishProxyAuthPostureFailClosed is the hook for an activation that cannot
// be refused (startup load, IdP recovery): the posture is raised even when the
// marker cannot be written. It reports whether this call raised it.
func establishProxyAuthPostureFailClosed(by string) bool {
	changed, err := cfg.proxyAuthPosture().EstablishFailClosed(by, time.Now())
	if err != nil {
		logWarnf("AuthPosture: proxy authentication is ESTABLISHED for this process but the marker could not be written (%q): %q",
			sanitizeLog(by), sanitizeLog(err.Error()))
	}
	if changed {
		noteProxyAuthEstablished(by)
	}
	return changed
}

// republishProxyAuthPostureOnControlPlane republishes the config snapshot on a
// Control Plane whose posture was just established OUTSIDE an admin write: the
// startup migration (which runs after the CP's first publish) and IdP
// recovery. Admin and snapshot paths publish on their own. Must not be called
// with the IdP registry lock held (the capture reads the registry).
func republishProxyAuthPostureOnControlPlane() {
	if !isControlPlaneRole() {
		return
	}
	if err := publishCurrentConfigSnapshot(); err != nil {
		logWarnf("AuthPosture: could not republish the config snapshot with the established posture: %q", sanitizeLog(err.Error()))
	}
}

// noteProxyAuthEstablished logs and audits the one-time transition. Audited
// only: the posture is not configuration and creates no config version.
func noteProxyAuthEstablished(by string) {
	logger.Printf("AuthPosture: proxy authentication ESTABLISHED (by %q): from now on, losing every proxy identity provider refuses authentication-required traffic instead of admitting it",
		sanitizeLog(by))
	now := time.Now()
	auditAdd(AuditEntry{
		TS:     now.UnixMilli(),
		Time:   now.Format("2006-01-02 15:04:05"),
		Actor:  "system",
		Action: "auth.proxy_posture.established",
		Object: proxyAuthPostureCode,
		Detail: "proxy authentication established (" + by + "); only an Exempt authentication rule or the Exempt default admits traffic without credentials from now on",
	})
}

// proxyAuthProfileActivation describes a registry profile activation for the
// marker's "by" field.
func proxyAuthProfileActivation(origin string, p *IdPProfile) string {
	if p == nil {
		return origin
	}
	return origin + ": identity provider profile " + strconv.Quote(p.ID) + " (" + string(p.Type) + ")"
}

// establishForLiveSet is ReplaceAll's write-ahead hook: it establishes the
// posture when the candidate set publishes at least one live provider.
func establishForLiveSet(origin string, profiles []*IdPProfile, live map[string]IdentityProvider) error {
	for _, p := range profiles {
		if p != nil && live[p.ID] != nil {
			return establishProxyAuthPosture(proxyAuthProfileActivation(origin, p))
		}
	}
	return nil
}

// proxyAuthPostureEvidence names durable evidence that proxy authentication
// was configured on this node, or "" when there is none (see MIGRATION above).
func proxyAuthPostureEvidence() string {
	if idpRegistry != nil {
		if n := len(idpRegistry.All()); n > 0 {
			return strconv.Itoa(n) + " identity provider profile(s) stored in the registry"
		}
	}
	switch {
	case cfg != nil && cfg.ProviderEnabled():
		return "a legacy proxy identity provider configured in config.yaml"
	case legacyLDAPYAMLConfig() != nil:
		return "a legacy ldap block in config.yaml"
	case legacyLDAPRetired():
		return "the legacy LDAP retirement sentinel"
	}
	return ""
}

// completeProxyAuthPostureMigration settles a missing marker once every source
// of evidence is loaded. A no-op unless initProxyAuthPosture found the marker
// missing and no activation has established the posture since.
func completeProxyAuthPostureMigration() {
	if cfg == nil || !cfg.proxyAuthPosture().MigrationPending() {
		return
	}
	if ev := proxyAuthPostureEvidence(); ev != "" {
		if establishProxyAuthPostureFailClosed("migration: " + ev) {
			republishProxyAuthPostureOnControlPlane()
		}
		return
	}
	if err := cfg.proxyAuthPosture().RecordFresh(time.Now()); err != nil {
		logWarnf("AuthPosture: could not record the fresh posture (the next start evaluates it again): %q", sanitizeLog(err.Error()))
		return
	}
	logger.Printf("AuthPosture: fresh installation: no proxy identity provider has ever been configured; the posture is established by the first provider activation")
}

// proxyAuthProviderUsable reports whether anything LIVE can authenticate proxy
// traffic: a legacy provider, a compiled registry credential provider, or a
// live interactive (SSO) provider. Diagnostics only (allocates).
func proxyAuthProviderUsable() bool {
	if cfg != nil && cfg.ProviderEnabled() {
		return true
	}
	if idpRegistry == nil {
		return false
	}
	return len(idpRegistry.EnabledCredentialProviders()) > 0 || idpRegistry.HasEnabledInteractiveProvider()
}

// checkProxyAuthPosture is the read-only posture row. It names no file path,
// account or roster fact (only the posture and the provider that established
// it, which a viewer can already list under Identity Providers), so every role
// sees the same row.
func checkProxyAuthPosture() OperatorContractCheck {
	if cfg == nil {
		return OperatorContractCheck{Code: proxyAuthPostureCode, Status: diagOK, Message: "proxy authentication has not been established on this node"}
	}
	st := cfg.proxyAuthPosture().Status()
	switch {
	case !st.Established:
		return OperatorContractCheck{
			Code:    proxyAuthPostureCode,
			Status:  diagOK,
			Message: "proxy authentication has not been established on this node: no proxy identity provider has ever been activated (fresh installation)",
		}
	case st.Problem == authposture.ProblemCorrupt || st.Problem == authposture.ProblemUnreadable:
		return OperatorContractCheck{
			Code:   proxyAuthPostureCode,
			Status: diagFail,
			Message: "the proxy authentication posture marker in the data directory is " + string(st.Problem) +
				", so proxy authentication is treated as ESTABLISHED (fail closed): with no usable proxy identity provider, traffic that requires authentication is refused",
			OperatorAction: "Inspect " + proxyAuthPostureFileName + " in the data directory (the startup log names the error): restore its permissions/ownership or restore it from a backup. Culvert never rewrites or deletes it. Removing it makes the next start re-derive the posture from the configured identity providers.",
		}
	}
	origin := fmt.Sprintf("since %s, by %s", st.Since, st.By)
	if !proxyAuthProviderUsable() {
		return OperatorContractCheck{
			Code:   proxyAuthPostureCode,
			Status: diagFail,
			Message: "proxy authentication is established on this node (" + origin + ") and no usable proxy identity provider remains: " +
				"every request that requires authentication is refused (HTTP 407; SOCKS5 offers only username/password and refuses it). " +
				"Only an Exempt authentication rule or the Exempt default admits traffic without credentials",
			OperatorAction: "Restore a proxy identity provider under Identity Providers (create, re-enable or repair an LDAP, OIDC or SAML profile; the startup log names a profile that failed to load). Removing providers never turns proxy authentication off. If some traffic must be admitted without credentials, say so explicitly with a scoped Exempt authentication rule or the Exempt default.",
		}
	}
	row := OperatorContractCheck{
		Code:    proxyAuthPostureCode,
		Status:  diagOK,
		Message: "proxy authentication is established on this node (" + origin + ") and a proxy identity provider is usable",
	}
	if st.Problem == authposture.ProblemNotDurable {
		row.Status = diagWarn
		row.Message += "; the posture marker could not be written, so it is held for this process only"
		row.OperatorAction = "Check that the data directory is writable (the log names the write error); the next identity provider change retries the write. Until it lands, a restart re-establishes the posture only while a provider is still configured, so fix the write before removing providers."
	}
	return row
}
