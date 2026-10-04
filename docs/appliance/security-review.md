# Appliance security review

This is a scoped source review and regression record for the appliance security
candidate based on `61b670fe`. It is not an enterprise certification or a claim
that a new OVA has passed ESXi qualification. The earlier live qualification
covered `36b5407e`; it does not qualify the changes described here.

## Confirmed authorization defects and fixes

| Finding | Reproduction before the fix | Correction and regression |
| --- | --- | --- |
| P1: first-boot setup token bypass | With a per-instance setup token configured, an unauthenticated POST to `/api/auth/users` with a missing or wrong token returned 200 and created an administrator. `uiAuthMiddleware` granted every request the bootstrap administrator role while setup was incomplete. | Protected `/api/` bootstrap requests now require the same token as `/api/setup/complete`. `TestSetupToken_ProtectsBootstrapAdminRoutes` drives the real user-creation handler. Public setup routing/static assets remain available; a setup token does not authenticate after setup. |
| P1: proxy session accepted as an administrator session | A cookie emitted by the real proxy `setSessionCookie` issuer, renamed from `ps_session` to `ps_ui_session`, reached administrator-only `/api/auth/users` with HTTP 200. Both cookies used the shared HMAC format; the UI accepted external providers and promoted an empty role to administrator. | The UI issuer writes a signed `aud=culvert-admin-ui` purpose. The UI reader requires that purpose, the actual local UI provider, an explicit enrolled role, and a current local account. Tests cover genuine portal-token replay, missing/wrong purpose, and purpose modification without a new signature. The shared decoder and proxy reader remain purpose-neutral. |
| P2: a demoted administrator retained authority | After the real user-management handler demoted an administrator to viewer, password verification reported viewer but its existing signed cookie still reached administrator-only APIs with HTTP 200. | The UI reader bounds the role by both the signed cookie and a locked snapshot of the current roster. Demotion applies immediately; promotion does not elevate an existing lower-role cookie. Tests exercise actual demotion, promotion, deleted accounts, and unknown roles. |

The UI cookie change deliberately requires existing sessions without the signed
UI purpose to sign in again. Role-less legacy cookies also require a new login;
they cannot be distinguished safely from proxy-portal credentials. Current UI
cookies are issued only by the local login/setup path. The SPA setup branch uses
public `/api/setup/status`, then `/api/setup/complete` with the setup-token header;
dashboard requests are not required to claim the appliance.

The token-unset installation mode retains its historical open bootstrap behavior.
The appliance first-boot path supplies a random per-instance token. This fix does
not claim that generic deployments without that token have a protected bootstrap
window.

## Trust and network boundaries still relevant

* Release management verifies the catalog using the baked Sigstore trust root
  and pinned GitHub workflow/tag identity by default. The signed index binds
  manifest hashes; manifests bind image digests. Catalog expiry and a persisted
  version/time floor reject stale/replayed catalogs. Operator trust overrides
  remain explicit startup configuration. See `release_catalog_verify.go`,
  `release_catalog_sigstore.go`, `release_catalog_freshness.go`, and
  `release_wiring.go`.
* Candidate first boot exports its unsigned-image exception only in the installer
  subshell, conditional on the candidate manifest. This does not disable the
  application release-catalog verifier. A candidate remains unsuitable as proof
  of production release signing or trusted artifact distribution.
* The maintenance socket checks kernel `SO_PEERCRED` against configured UIDs;
  its mode is 0660. Upgrade/rollback handlers constrain repository references and
  verify the running digest, but do not independently verify a signed release
  authorization. They trust the allowlisted client process. A compromised proxy
  process can therefore bypass the proxy's catalog policy when requesting an
  otherwise allowed image. Moving the release authorization boundary into the
  host agent needs a reviewed signed-intent policy, including offline recovery
  and rollback; no such architecture is claimed as implemented here.
* The standalone maintenance installer defaults its cosign verifier to a mutable
  `v3.0.6` container tag. A digest override exists, but the default verifier supply
  chain still needs pinning. Production qualification also needs evidence of
  signing-root/identity distribution and rotation, revoked/expired trust handling,
  and signed upgrade/rollback behavior. No private signing key was inspected.
* Docker publishes administrator port 9090 on every interface. The appliance's
  nftables INPUT policy does not filter that forwarded container traffic.
  Application `-ui-allow-ip` filtering exists and is empty by default. A management
  network boundary must be enforced at the actual publication/forwarding path or
  by an explicit application allowlist. Changing this default requires recovery
  and remote-access qualification; this review changed no host firewall or bind
  address. [Docker documents the INPUT/OUTPUT bypass for published ports](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw).

## Evidence and outstanding qualification

The focused bootstrap/session/authentication/audit regressions ran successfully
against the real production Go files on Windows, including repeated shuffled
runs. A broader targeted run reached an existing Windows directory-fsync
limitation in an open-mode persistence test; that result is not a product pass.
The complete Linux root test package cross-compiled. Cross-compilation does not
execute Linux PAM, socket-peer, systemd, Docker, or ESXi behavior.

CI should run the focused `TestSetupToken`, `TestUISessionRole`, `TestSessionRole`,
`TestAuthStatus`, `TestSessionAdmin`, and authentication/audit fixture consumers,
plus the ordinary root and maintenance-agent Linux gates. A newly built candidate
still needs import/first-boot qualification, operator SSH allow/deny tests, local
recovery, authenticated setup, update/reboot/restore, and signed-release evidence.
No live VM or host networking was changed by this review. Artifact-content checks
are recorded separately in [security-artifact-audit.md](security-artifact-audit.md).

## Code and licensing boundary

The repository's [LICENSE](../../LICENSE) remains MIT and was not modified. It
currently grants broad reuse rights subject to its stated conditions. Restricting
SSH, checking signatures, omitting development files, and stripping binaries do
not provide confidentiality against an OVA or hypervisor owner. Compiled Go
programs and their embedded frontend can be extracted from the appliance. A
different commercial or distribution policy is a separate business decision;
this work does not promise theft-proof code.
