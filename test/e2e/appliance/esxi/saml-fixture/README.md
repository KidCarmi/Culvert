# Exact-appliance browser SSO qualification fixture

This host-only fixture signs synthetic SAML assertions. It does not install
software, change authentication internals, configure the appliance, or qualify
OIDC. Its public metadata is imported using the appliance's authenticated
`POST /api/idp` API. The signing key stays in process memory and disappears
when the one-hour process ends. Only browser connections whose peer is the
approved controller address `192.168.1.189` are admitted.

Source review: appliance `7e53720d06f525f4e5fdbfec42f52840d5b734e2`.
Production OIDC discovery and token/JWKS transports reject private addresses;
the in-process OIDC test replaces these transports. A host-local OIDC fixture
therefore cannot qualify these unchanged appliance bytes through supported
configuration. Keep that leg **BLOCKED** unless a real public HTTPS IdP is
available. Do not replace the appliance's dialer or weaken its SSRF policy.

## Preparation and configuration (root controller only)

1. Complete the normal baseline qualification and retain a fresh authenticated
   backup before this temporary campaign. Pin the VM UUID, OVA/image identities,
   guest origin, helper source/binary hashes and browser executable/version.
   Use a new private evidence directory and a separate admin HTTP cookie jar.
   Never put the admin cookie/password into the browsing context.
2. Authenticated `GET /api/settings/network`, `/api/sso-ip-binding`,
   `/api/sso-ip-binding/bindings`, `/api/idp`, `/api/policy`, `/api/authpolicy`
   and `/api/policy/draft`; retain the snapshots privately. Require no other
   live SSO binding, no policy draft, and no fixture-name collision. Redacted
   IdP GET responses are **not** a full secret-bearing configuration backup;
   leave existing profiles untouched.
3. If `base_url` differs from the actual `https://<guest>:9090` origin, save
   the four writable network fields and `POST /api/settings/network` with
   only `base_url` changed. Preserve `ui_sans`, `trust_forwarded_headers`
   and `trusted_proxy_cidrs`. Read back and verify. Do not trust forwarded
   headers or add a trusted proxy for this campaign.
4. Download `/auth/saml/metadata`, verify the entity is the exact guest origin
   and ACS is that origin plus `/auth/saml/callback`; retain/hash the XML.
5. Build the helper from the frozen controller checkout:

   ```text
   go build -o <private-tools>/saml-fixture.exe ./test/e2e/appliance/esxi/saml-fixture
   saml-fixture.exe --sp-metadata <private>/sp.xml --sp-metadata-sha256 <full-sha256> --sp-base https://<guest>:9090 --out <new-private>/idp
   ```

   `--out` must not exist. Parent directories must already exist. The helper
   binds only `192.168.1.189:18443`, writes `idp-metadata.xml` and
   `fixture-ready.json`, and does not write a private key. Run the host process
   with its window hidden. No firewall expansion is needed for this browser-
   local fixture; the appliance does not connect to the IdP.
6. Authenticated `POST /api/idp` with a fresh unique ID/name, `type: "saml"`,
   `enabled: true`, `knownGroups: ["engineering", "finance"]`, and:

   ```json
   {"saml":{"metadataXml":"<exact emitted metadata XML>","nameIdFormat":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress","groupsAttribute":"groups","emailAttribute":"email","nameAttribute":"displayName"}}
   ```

   Merge that `saml` object into the profile; do not POST it by itself. Record
   the returned profile ID. The fixture's Alice is `alice@example.com` in
   `engineering`; Bob is `bob@example.com` in `finance`. These are synthetic
   test identities, not UI administrators.
7. Authenticated `PUT /api/sso-ip-binding`:

   ```json
   {"enabled":true,"ttlMinutes":5,"excludeCidrs":[]}
   ```

8. Isolate access rules for source `192.168.1.189/32`, destination
   `example.com`: engineering may access; finance is denied. Constrain the
   allow to the fixture IdP's **bare ID** via `authSource` (actual activity
   uses `sso-ip:<id>`), and enable traffic logging. Prefer adding uniquely
   named rules at verified unused priorities before any existing matching
   rule. If the baseline already occupies that position, save the exact
   affected rule and update it by stable ID with `ifVersion`; do not reorder
   unrelated rules or replace the whole rulebase. Require Stage-1 Default
   or SSORequired for this traffic, with no exemption. GET/read-back and
   `/api/policy/test` can preflight intended matching, but are not traffic
   evidence. For the HTTPS CONNECT leg use the supported `sslAction: "Bypass"`
   on the scoped allow rule, retaining public origin certificate validation.
   This tests successful authenticated tunneling, not TLS inspection/scanning;
   retain the separate ClamAV/inspection qualification.

All authenticated mutations must send `Origin: https://<guest>:9090` and the
admin cookie through the established TLS/credential procedure. Record mutation
receipts and stop on a failed response or unexpected read-back. Never count
synthetic policy simulation as successful browser enforcement.

## Browser journey and concrete evidence

Use a disposable Chromium profile/context, explicit proxy
`http://<guest>:8080`, and bypass only the UI origin and fixture address:
`<-loopback>;<guest>:9090;192.168.1.189:18443`. Disable QUIC for a deterministic
HTTP CONNECT transport. Do not supply proxy username/password, inject a portal
cookie, or set `X-User-Identity`. Handle only the UI's already authorized lab
certificate exception; keep public `https://example.com` certificate checking.

Record browser version and launch arguments, timestamped navigation results,
status/title or response-body hash, actual peer/proxy remote address where
available, and authenticated appliance activity/binding snapshots per phase.
Use unique run/path markers for HTTP and narrow UTC windows plus subject and
CONNECT host for HTTPS. Close active pages/tunnels between users/settings;
existing established tunnels are not proof of a new authorization decision.

1. No binding: browse `http://example.com/<run-marker>`; expect sign-in flow
   through `/auth/select` to the fixture. No proxy credential is presented.
2. Click `#login-alice`. Let the actual browser submit the signed POST to
   `/auth/saml/callback` and perform `/auth/saml/complete`; do not manually
   copy cookies or callback fields. Inspect the admin-only bindings endpoint:
   exact controller address, Alice subject, engineering group, fixture ID.
3. Visit HTTP and HTTPS `example.com` through the proxy. Require actual
   origin responses (use `/` if the marked path returns an origin 404), a
   successful browser CONNECT for HTTPS, and matching appliance attribution
   `alice@example.com` / `sso-ip:<fixture-id>` with the intended allow rule.
4. From a same-origin UI page in the same browser context, POST
   `/auth/logout` with same-origin `fetch`. Require the binding absent, close
   old connections, and show a new HTTP/HTTPS attempt cannot reuse Alice.
5. Sign in as Bob using the real flow. Require finance in the binding,
   HTTP 403 and a refused **new** HTTPS CONNECT, with matching Bob/deny
   activity. A browser tunnel error alone is not sufficient; preserve the
   proxy response and denial activity.
6. Disable binding with `PUT /api/sso-ip-binding` (preserve TTL/exclusions).
   Require zero bindings, no sign-in redirect for new unauthenticated traffic,
   and challenge/denial with explicit disabled reason. Re-enable with
   `excludeCidrs: ["192.168.1.189/32"]`; prove a direct fresh SAML login
   cannot create a binding and new proxy requests remain unauthenticated.
7. For each HTTPS phase start a fresh browser process with a new private
   `--log-net-log=<absolute-private-json>` file. Reuse context state only for
   the same synthetic user if needed (store it privately). The IP binding is
   node-side, so a clean browser process on the same controller address also
   exercises it without passing cookies to the origin. Browser flags must
   still pin the intended proxy. Close Chromium to flush the file.

Extract bounded CONNECT evidence with:

```text
python browser-connect-proof.py <private-netlog.json> --expected-status 200 --out <new-proof.json>
```

Use the phase's observed expected denial code (403 or 407) for denial legs.
The extractor correlates `HTTP_TRANSACTION_SEND_TUNNEL_HEADERS` and
`HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS` by source, requires the exact
authority, retains preceding failures and refuses presented proxy credentials.
These are Chromium's [actual tunnel request/response events](https://github.com/chromium/chromium/blob/main/net/http/http_proxy_client_socket.cc).
It does not prove origin content, identity or TLS verification by itself.
Keep raw NetLog, HAR, cookies, SAML forms and state private; sanitized proof
never includes header values. A 502 can never satisfy the successful leg.

## Cleanup and limits

Logout/revoke only the fixture binding, delete the exact added profile, remove
only added test rule IDs or restore saved changed rules with fresh version
fences, restore previous binding settings and writable network fields, then
GET/read-back all touched surfaces. Compare rule definitions, not live hit
counters/timestamps. Do not restore from a redacted IdP listing or overwrite
an unexpected concurrent change. On cleanup failure keep the candidate
blocked and preserve the fixture records. Stop only the known fixture process;
retain public metadata, test-only trust disposition and sanitized evidence.
No fixture key, profile or test trust belongs in a deliverable OVA.

Report this as exact-OVA SAML/browser transport qualification with a synthetic
IdP. It is not vendor IdP interoperability, OIDC qualification, HTTP/2 proxy
transport, or evidence that IP binding separates clients behind shared NAT.
IP inference is the explicitly enabled product mechanism, so controller
processes sharing this IP also share the temporary identity.
