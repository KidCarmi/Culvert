# On-appliance LDAP/AD qualification — bad788e5 OVA against a Samba AD DC

Lab run 38054826481 (lab commit `05cd1df9`), the RETAINED bad788e5 OVA
(`87c8ae61…`) in a disposable QEMU guest. The directory is Samba provisioned
as an Active Directory domain controller on the runner from Ubuntu's own
packages, keeping Samba's AD default (simple binds need transport
encryption), with a certificate issued by a lab internal CA. **An AD
stand-in, not Microsoft AD**: Kerberos/NTLM/Negotiate, channel binding,
LDAP-signing policy and nested groups are not exercised. 75 pass, 0 fail.

| row | result |
|---|---|
| plain `ldap://` | refused by the directory: `Strong Auth Required` (expected; a hardened AD does the same) |
| **LDAPS verified against the internal CA** | **FAILS: `x509: certificate signed by unknown authority`. The appliance has no setting for a directory CA (`ldapTLSConfig` trusts only the image's public roots).** |
| LDAPS with `tlsSkipVerify` | works: dial, TLS, service bind, search, alice's bind; groups include `CN=ProxyUsers`. **Everything below ran on this unsafe transport, the only one that works.** |
| profile created; bind password write-only | pass; not returned by `GET /api/idp` |
| auth required | `defaultAuthOutcome = Default` |
| credential matrix through the proxy | no creds 407 · alice 200 · wrong password 407 · bob (no group) 403 · disabled carol 407 · unknown 407 · `*` 407 · DN as username 407 |
| identity in the request log | alice: `CN=alice,CN=Users,DC=corp,DC=example`, rule `lab-ldap-allow-proxyusers`, Allow; bob: his DN, `POLICY_DEFAULT_DENY` |
| directory stopped | uncached dave 407 (fail closed) |
| directory restarted | dave 200 with no appliance action |

**Correction to the leg as run:** the intended block rule
(`lab-ldap-block-others`) was NOT created — the harness sent
`"action":"Block"`, the API accepts `Block_Page`/`Drop`, and the 400 was not
checked (`L2-rule-block.txt`). Bob's 403 therefore came from the appliance's
default-deny posture, not from that rule. It still shows the property
under test (bob authenticated but has no group-scoped allow); the harness
now creates `Block_Page` and fails the leg if either rule is refused.

**Operator facts found on the way:**
* Samba's auto-generated self-signed LDAPS certificate has a negative
  serial number; Go's `crypto/x509` refuses to parse it, so LDAPS fails
  even with skip-verify (run 38053967889). A DC needs a properly issued
  certificate.
* Pilot gap: an AD whose LDAPS certificate comes from an internal CA cannot
  be used with verification. The only working options are skip-verify
  (unsafe) or plaintext (refused by a hardened directory).
