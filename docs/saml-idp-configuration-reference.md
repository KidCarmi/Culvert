# SAML 2.0 IdP Configuration Reference

This document covers what an IT administrator must configure in each supported Identity Provider (IdP)
to create a Service Provider (SP) integration. It also documents what attributes each IdP sends back
in the SAML assertion, so those values can be mapped to the `SAMLProfileConfig` fields
(`GroupsAttribute`, `EmailAttribute`, `NameAttribute`, `NameIDFormat`) in the IdP registry.

**Last updated:** March 2026
**Applies to:** ProxyShield SAML SP (`auth_saml.go`, `auth_idp.go`)

---

## Common SP Values (What You Provide to Every IdP)

Before configuring any IdP, collect these values from your running ProxyShield instance. They are
derived from the `base_url` in `config.yaml`.

| Field | Value Pattern | Description |
|---|---|---|
| **SP Entity ID** | `https://<base_url>/saml/metadata` | Unique identifier for this SP |
| **ACS URL** | `https://<base_url>/saml/acs` | Where the IdP POSTs the SAML response |
| **Metadata URL** | `https://<base_url>/saml/metadata` | Self-describing SP metadata (XML) |
| **SP Signing Certificate** | Downloaded from the metadata URL | Optional; used if the IdP requires signed AuthnRequests |

All ACS URLs **must** use HTTPS. HTTP is rejected by the SP and most IdPs.

The crewjam/saml library used by ProxyShield enforces SP-initiated SSO only
(`AllowIDPInitiated: false`), so IdP-initiated flows are not supported.

---

## NameID Format Reference

Choose the format that best matches what the IdP will send. The value goes in the
`nameIdFormat` field of `SAMLProfileConfig`.

| Short Name | URN |
|---|---|
| **emailAddress** | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| **persistent** | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |
| **transient** | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` |
| **unspecified** | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` |
| **kerberos** | `urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos` |
| **windowsDomain** | `urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName` |

The SP defaults to `emailAddress` when `nameIdFormat` is left empty. For Entra ID and ADFS,
`persistent` or `emailAddress` is recommended. For Keycloak, `emailAddress` or `username`
(Keycloak-specific shorthand) is most common.

---

## 1. Generic SAML 2.0

### What the Admin Configures in the IdP

Any standards-compliant IdP requires at minimum:

| Field | Value | Notes |
|---|---|---|
| **SP Entity ID** | `https://<base_url>/saml/metadata` | Must be globally unique |
| **ACS URL** | `https://<base_url>/saml/acs` | HTTP-POST binding required |
| **NameID Format** | `emailAddress` or `persistent` | Must match `nameIdFormat` config |
| **SP Certificate** | Optional PEM cert from metadata | Only if IdP validates signed requests |
| **Relay State** | Optional; set if IdP requires a default landing path | Passed through unchanged |

Binding: always use **HTTP-POST** for the ACS. HTTP-Redirect is only for the AuthnRequest.

### Attributes Sent in the Assertion

There is no mandated standard set beyond the NameID subject. Common practice:

| Attribute Name | Value | Notes |
|---|---|---|
| NameID (Subject) | Email or opaque ID | Format varies by IdP configuration |
| `email` | user@example.com | Basic profile |
| `displayName` or `cn` | Full name | |
| `groups` or `memberOf` | Array of group names | Must be explicitly configured |

### SAMLProfileConfig Mapping

```json
{
  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "emailAttribute": "email",
  "nameAttribute": "displayName",
  "groupsAttribute": "groups"
}
```

### Metadata URL

Available when the IdP publishes a standard metadata endpoint. Provide it as `metadataUrl`.
If not available, paste the raw XML into `metadataXml`.

---

## 2. Okta

### What the Admin Configures in Okta Admin Console

Path: **Applications → Applications → Create App Integration → SAML 2.0**

| Okta Field | Value |
|---|---|
| **Single Sign-On URL** (ACS URL) | `https://<base_url>/saml/acs` |
| **Audience URI (SP Entity ID)** | `https://<base_url>/saml/metadata` |
| **Name ID format** | `EmailAddress` (recommended) |
| **Application username** | `Email` |
| **Default RelayState** | Optional; set to your post-login landing page |
| **Attribute Statements** | Add custom user attributes (see below) |
| **Group Attribute Statements** | Add a group statement (see below) |

Okta does **not** support importing SP metadata XML; all fields must be entered manually.

#### Required Attribute Statements

Okta only sends 4 attributes by default: `FirstName`, `LastName`, `email`, `login`.
Add any additional attributes under **Attribute Statements (Optional)**.

| Name | Name Format | Value (Okta Expression Language) |
|---|---|---|
| `email` | Basic | `user.email` |
| `firstName` | Basic | `user.firstName` |
| `lastName` | Basic | `user.lastName` |

#### Group Attribute Statement

To send group memberships, add a **Group Attribute Statement** on the same tab:

| Field | Value |
|---|---|
| **Name** | `groups` (or `memberOf` — must match your `groupsAttribute` config) |
| **Name format** | Basic |
| **Filter** | `Matches regex` → `.*` (sends all groups) or use `Starts with` to filter |

The attribute name is admin-defined and must exactly match what ProxyShield expects in
`groupsAttribute`.

### Attributes Sent in the Assertion

| Attribute Name | Source |
|---|---|
| NameID (Subject) | Okta username / email (per "Application username" setting) |
| `email` | `user.email` |
| `firstName` | `user.firstName` |
| `lastName` | `user.lastName` |
| `groups` | Okta group names (filtered by the Group Attribute Statement rule) |

### Metadata URL

Available after saving the app. Found at: **Sign On tab → More details → Metadata URL**.
Copy this link as `metadataUrl` in the profile. Okta recommends the metadata URL over
static XML so that certificate rollovers are handled automatically.

### SAMLProfileConfig Mapping

```json
{
  "metadataUrl": "https://<okta-domain>/app/<app-id>/sso/saml/metadata",
  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "emailAttribute": "email",
  "nameAttribute": "firstName",
  "groupsAttribute": "groups"
}
```

### Typical NameID Format

`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
(Okta sends the user's email as the NameID subject when "Application username = Email")

---

## 3. Microsoft Entra ID (formerly Azure AD)

### What the Admin Configures in the Entra Portal

Path: **Entra ID → Enterprise Applications → New Application → Create your own application**
Then: **Single sign-on → SAML → Basic SAML Configuration**

| Entra Field | Value | Required |
|---|---|---|
| **Identifier (Entity ID)** | `https://<base_url>/saml/metadata` | Yes |
| **Reply URL (ACS URL)** | `https://<base_url>/saml/acs` | Yes |
| **Sign on URL** | `https://<base_url>/` | Optional (SP-initiated) |
| **Logout URL** | `https://<base_url>/logout` | Optional |

Under **SAML Certificates**, download the **Federation Metadata XML** or copy the
**App Federation Metadata URL** — use this as `metadataUrl`.

#### Attributes and Claims

Path: **Single sign-on → Attributes & Claims → Edit**

Default claims issued by Entra ID:

| Claim Name | Attribute URI | Source Attribute |
|---|---|---|
| Unique User Identifier (NameID) | (NameID) | `user.userprincipalname` by default |
| `emailaddress` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `user.mail` |
| `givenname` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | `user.givenname` |
| `surname` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | `user.surname` |
| `name` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `user.userprincipalname` |

**Recommendation:** Change the NameID source attribute to `user.mail` to send an email address
rather than a UPN.

#### Group Claims

To send group memberships, click **Add a group claim** in the Attributes & Claims editor:
- Select **Security groups** (recommended to avoid the 150-group token limit).
- Or select **Groups assigned to the application** for large directories.
- The group OID is sent by default; to send the `sAMAccountName` or display name, change
  **Source attribute** to `cloud.displayname` (for cloud groups) or sync from on-prem AD.

The group attribute URI is:
`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`

**Warning:** If a user is a member of more than 150 groups, Entra ID omits the groups claim
entirely from the SAML assertion. Use "Groups assigned to the application" as the scope to
stay under the limit.

### Attributes Sent in the Assertion

| Attribute Name (as received) | Notes |
|---|---|
| NameID | UPN or email, depending on claim configuration |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | User's email |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | First name |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | Last name |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | UPN |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` | Group OIDs or display names |

The `extractSAMLIdentity` function in `auth_saml.go` already handles the long-form
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` and
`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` URIs natively.

### Metadata URL

Format: `https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml`
Or copy the **App Federation Metadata URL** from the SAML Certificates section.

### SAMLProfileConfig Mapping

```json
{
  "metadataUrl": "https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml",
  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "emailAttribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  "nameAttribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  "groupsAttribute": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
}
```

Because `auth_saml.go` also matches the long-form URI constants directly in its `switch` cases,
leaving `emailAttribute` and `groupsAttribute` empty will also work for Entra ID — the built-in
fallback URIs will be matched automatically.

### Typical NameID Format

`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` (after changing NameID source to `user.mail`)
or `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` (default pairing with UPN)

---

## 4. Google Workspace

### What the Admin Configures in Google Admin Console

Path: **Admin Console → Apps → Web and mobile apps → Add App → Add custom SAML app**

Super administrator privileges required.

| Step | Field | Value |
|---|---|---|
| App details | App name | Any descriptive name |
| Service Provider details | **ACS URL** | `https://<base_url>/saml/acs` |
| Service Provider details | **Entity ID** | `https://<base_url>/saml/metadata` |
| Service Provider details | **Start URL** | Optional; leave blank for SP-initiated only |
| Service Provider details | **Signed response** | Check if SP requires the full response to be signed (default: assertion only) |
| Service Provider details | **Name ID format** | `EMAIL` |
| Service Provider details | **Name ID** | `Basic Information > Primary email` |

After saving the Service Provider details, proceed to **Attribute mapping**.

#### Attribute Mapping

Click **Add mapping** for each attribute the SP expects. Google Directory attributes on the left,
SP attribute name on the right. Attribute names are **case-sensitive**.

| Google Directory Attribute | App Attribute (SP name) |
|---|---|
| Basic Information > Primary email | `email` |
| Basic Information > First name | `firstName` |
| Basic Information > Last name | `lastName` |

#### Group Membership (Optional)

In the **Group membership** section, add up to 75 Google Groups. Set the **App attribute** value
to `groups` (must match `groupsAttribute` config). Only groups the user is actually a member of
are included in the assertion — the full list of 75 acts as an allowed-set filter.

### Attributes Sent in the Assertion

| Attribute Name | Notes |
|---|---|
| NameID (Subject) | Primary email address (always sent) |
| `email` | If mapped |
| `firstName` | If mapped |
| `lastName` | If mapped |
| `groups` | If group membership section is configured |

Google does not send groups automatically; they must be explicitly configured in the
Group membership section of the app. Custom Directory attributes (e.g., department, manager)
can be mapped if added as custom attributes in the Directory schema.

### Metadata URL

Google provides IdP metadata as a downloadable XML file from the **Google Identity Provider details**
page (Step 2 of the wizard). There is no live metadata URL by default; download the XML and paste it
into `metadataXml`, or re-download it if the certificate changes.

Alternatively, the metadata can be fetched at:
`https://accounts.google.com/o/saml2/idp?idpid=<C-XXXXXXX>`
where the `idpid` is shown in the SSO URL on the Google IdP details page.

### SAMLProfileConfig Mapping

```json
{
  "metadataXml": "<EntityDescriptor ...>...</EntityDescriptor>",
  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "emailAttribute": "email",
  "nameAttribute": "firstName",
  "groupsAttribute": "groups"
}
```

### Typical NameID Format

`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
Google always sends the user's primary email as the NameID value.

---

## 5. ADFS (Active Directory Federation Services)

### What the Admin Configures in ADFS Management

Path: **AD FS Management → Relying Party Trusts → Add Relying Party Trust**

#### Option A: Import from Metadata (Recommended)

1. Select **Import data about the relying party published online or on a local network**.
2. Enter `https://<base_url>/saml/metadata` as the Federation metadata address.
3. ADFS will auto-populate the identifiers, ACS URL, and certificates.

#### Option B: Manual Entry

| Screen | Field | Value |
|---|---|---|
| Configure URL | Enable SAML 2.0 WebSSO protocol | Checked |
| Configure URL | Relying party SAML 2.0 SSO service URL | `https://<base_url>/saml/acs` |
| Configure Identifiers | Relying party trust identifier | `https://<base_url>/saml/metadata` |
| Configure Certificate | Service Provider certificate | Import from SP metadata (optional) |

**Note:** ADFS requires HTTPS. HTTP ACS URLs will be rejected at configuration time.

#### Claim Issuance Policy (Claim Rules)

After creating the trust, right-click → **Edit Claim Issuance Policy** → **Add Rule**.

##### Rule 1: Send email as NameID

Template: **Send LDAP Attributes as Claims**

| LDAP Attribute | Outgoing Claim Type |
|---|---|
| `E-Mail-Addresses` | `Name ID` |

Or alternatively map `User-Principal-Name` to `Name ID` if UPN is preferred.

##### Rule 2: Send user attributes

Template: **Send LDAP Attributes as Claims**, Attribute Store: **Active Directory**

| LDAP Attribute | Outgoing Claim Type |
|---|---|
| `E-Mail-Addresses` | `E-Mail Address` → URI: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| `Given-Name` | `Given Name` → URI: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` |
| `Surname` | `Surname` → URI: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` |
| `Display-Name` | `Name` → URI: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` |

##### Rule 3: Send group membership

**Option A — Send a single specific group:**

Template: **Send Group Membership as a Claim**

- User's group: Browse to the AD security group
- Outgoing claim type: `Group`
- Outgoing claim value: the group's display name (e.g., `VPN-Users`)

**Option B — Send all token-groups (multiple groups via LDAP rule):**

Template: **Send LDAP Attributes as Claims**

| LDAP Attribute | Outgoing Claim Type |
|---|---|
| `Token-Groups - Unqualified Names` | `Group` (custom type: `http://schemas.xmlsoap.org/claims/Group`) |

##### Rule 4: Transform Name ID (if needed)

Template: **Transform an Incoming Claim**

- Incoming claim type: `E-Mail Address`
- Outgoing claim type: `Name ID`
- Outgoing name ID format: `Email`

#### Security Settings (Advanced Tab)

Set the **Secure hash algorithm** to match what the SP expects (SHA-256 recommended).

### Attributes Sent in the Assertion

| Claim URI | Description |
|---|---|
| NameID | Email or UPN, depending on rule configuration |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | Email |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` | First name |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` | Last name |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | Display name / UPN |
| `http://schemas.xmlsoap.org/claims/Group` | Group memberships (one value per claim or multi-value) |
| `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` | Alternative group URI |

The `extractSAMLIdentity` function handles both group URI variants natively.

### Metadata URL

ADFS publishes its IdP metadata at:
`https://<adfs-hostname>/FederationMetadata/2007-06/FederationMetadata.xml`

This URL is stable and can be used as `metadataUrl`. It is accessible only within the corporate
network by default; firewall rules may need to be opened for the ProxyShield instance.

### SAMLProfileConfig Mapping

```json
{
  "metadataUrl": "https://<adfs-host>/FederationMetadata/2007-06/FederationMetadata.xml",
  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "emailAttribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  "nameAttribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  "groupsAttribute": "http://schemas.xmlsoap.org/claims/Group"
}
```

As with Entra ID, leaving `emailAttribute` and `groupsAttribute` empty also works because
`auth_saml.go` matches the long-form URIs as built-in fallbacks.

### Typical NameID Format

`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` (after the email-as-NameID rule)
or `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` (ADFS default when no rule constrains it)

---

## 6. Keycloak

### What the Admin Configures in Keycloak Admin Console

Path: **Admin Console → Realm → Clients → Create client**

| Field | Value | Notes |
|---|---|---|
| **Client type** | SAML | Select on creation screen |
| **Client ID** | `https://<base_url>/saml/metadata` | This becomes the SP Entity ID |
| **Name** | Any descriptive label | |

After saving, configure the **Settings** tab:

| Setting | Value |
|---|---|
| **Valid redirect URIs** | `https://<base_url>/saml/acs` |
| **Master SAML Processing URL** | `https://<base_url>/saml/acs` |
| **Assertion Consumer Service POST Binding URL** | `https://<base_url>/saml/acs` |
| **Sign documents** | ON |
| **Sign assertions** | ON (recommended) |
| **Force Name ID Format** | ON |
| **Name ID Format** | `email` |
| **Client Signature Required** | OFF (unless SP sends signed AuthnRequests) |
| **Encrypt Assertions** | OFF (unless SP handles decryption) |

**Important:** The `Client ID` in Keycloak is the SP Entity ID. It must exactly match the
`entityID` attribute in the SP metadata that Keycloak reads.

#### Attribute Mappers

Keycloak does not send user attributes by default in SAML responses. Configure mappers under
**Clients → [client] → Client scopes → [client-id]-dedicated → Mappers → Add mapper → By configuration**.

| Mapper Type | Token Claim / Attribute Name | User Attribute |
|---|---|---|
| User Property | `email` | `email` |
| User Property | `firstName` | `firstName` |
| User Property | `lastName` | `lastName` |
| Group list | `groups` | (Group membership) |
| Role list | `roles` | (Realm/client roles) |

For the group mapper, set **Single Group Attribute** to ON to send all groups as multiple values
of a single attribute rather than one attribute per group.

The attribute names in mappers must exactly match what ProxyShield expects in `groupsAttribute`,
`emailAttribute`, and `nameAttribute`.

#### Groups vs. Roles in Keycloak

Keycloak distinguishes between **Groups** (organizational hierarchy) and **Roles** (permission sets).

- Use the **Group list** mapper with attribute name `groups` to send group paths.
- Use the **Role list** mapper with attribute name `roles` (or `Role`) to send realm/client roles.
- Set `groupsAttribute` to whichever attribute name carries the relevant membership data.

### Attributes Sent in the Assertion

| Attribute Name | Notes |
|---|---|
| NameID (Subject) | Email address when Name ID Format = `email` |
| `email` | Requires User Property mapper |
| `firstName` | Requires User Property mapper |
| `lastName` | Requires User Property mapper |
| `groups` | Requires Group list mapper |
| `roles` or `Role` | Requires Role list mapper |

By default (no mappers configured), Keycloak sends only the NameID. All other attributes
must be explicitly added via mappers.

### Metadata URL

Keycloak publishes IdP metadata at:
`https://<keycloak-host>/realms/<realm>/protocol/saml/descriptor`

Use this as `metadataUrl`. The URL is public by default and refreshes automatically on
certificate rotation.

### SAMLProfileConfig Mapping

```json
{
  "metadataUrl": "https://<keycloak-host>/realms/<realm>/protocol/saml/descriptor",
  "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "emailAttribute": "email",
  "nameAttribute": "firstName",
  "groupsAttribute": "groups"
}
```

### Typical NameID Format

`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
(when **Force Name ID Format** is ON and **Name ID Format** is set to `email`)

---

## Quick-Reference Summary Table

| IdP | Admin Portal Path | Entity ID Field Name | ACS Field Name | Groups Attribute Name | Metadata URL Available |
|---|---|---|---|---|---|
| **Generic SAML 2.0** | Varies | SP Entity ID | ACS URL | `groups` (convention) | Usually yes |
| **Okta** | Applications → SAML 2.0 wizard | Audience URI (SP Entity ID) | Single Sign-On URL | Admin-defined (e.g. `groups`) | Yes (Sign On tab) |
| **Entra ID** | Enterprise Apps → SSO → SAML | Identifier (Entity ID) | Reply URL (ACS URL) | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` | Yes (App Federation Metadata URL) |
| **Google Workspace** | Apps → Web and mobile apps → Custom SAML | Entity ID | ACS URL | Admin-defined (e.g. `groups`) | Downloadable XML; static URL via `idpid` param |
| **ADFS** | AD FS Management → Relying Party Trusts | Relying party trust identifier | SAML 2.0 SSO service URL | `http://schemas.xmlsoap.org/claims/Group` | Yes (`/FederationMetadata/2007-06/FederationMetadata.xml`) |
| **Keycloak** | Admin Console → Clients → Create | Client ID | Master SAML Processing URL + ACS Binding URL | `groups` (via Group list mapper) | Yes (`/realms/<realm>/protocol/saml/descriptor`) |

---

## Attribute Name Handling in auth_saml.go

The `extractSAMLIdentity` function in `auth_saml.go` applies the following precedence when
extracting identity data from an assertion:

**Email** — matched against (first wins):
1. The value of `cfg.EmailAttribute` (admin-configured)
2. `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` (Entra ID / ADFS long-form URI)
3. `urn:oid:0.9.2342.19200300.100.1.3` (eduPerson `mail` OID)
4. NameID value, if it contains `@`

**Display name** — matched against (first wins):
1. The value of `cfg.NameAttribute` (admin-configured)
2. `cn`
3. `displayName`
4. `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`

**Groups** — collected from all matching attributes (all appended):
1. The value of `cfg.GroupsAttribute` (admin-configured)
2. `memberOf`
3. `Role`
4. `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`
5. `http://schemas.xmlsoap.org/claims/Group`

For Entra ID and ADFS, the built-in long-form URI fallbacks mean that `emailAttribute` and
`groupsAttribute` can be left empty and attribute extraction will still work correctly with
default Entra ID / ADFS claim rules.

---

## Sources

- [SSO Using SAML 2.0 — SSOTools](https://ssotools.com/blog/sso-using-saml-2-0-comprehensive-guide)
- [Okta: Create SAML app integrations (Classic Engine)](https://help.okta.com/en-us/Content/Topics/Apps/Apps_App_Integration_Wizard_SAML.htm)
- [Okta: Define group attribute statements (Identity Engine)](https://help.okta.com/oie/en-us/content/topics/apps/define-group-attribute-statements.htm)
- [Okta: Application Integration Wizard SAML field reference](https://help.okta.com/en-us/content/topics/apps/aiw-saml-reference.htm)
- [Microsoft: Enable SAML SSO for an enterprise application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso)
- [Microsoft: Customize SAML token claims](https://learn.microsoft.com/en-us/entra/identity-platform/saml-claims-customization)
- [Microsoft: Configure group claims for applications](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims)
- [Google: Set up your own custom SAML app](https://support.google.com/a/answer/6087519?hl=en)
- [Google: SSO assertion requirements](https://support.google.com/a/answer/6330801?hl=en)
- [Microsoft: Create Relying Party Trusts in AD FS (StorageGRID docs)](https://docs.netapp.com/us-en/storagegrid/admin/creating-relying-party-trusts-in-ad-fs.html)
- [Microsoft: Create a Rule to Send Group Membership as a Claim](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/create-a-rule-to-send-group-membership-as-a-claim)
- [Zendesk: Mapping attributes from Active Directory with ADFS and SAML](https://support.zendesk.com/hc/en-us/articles/4408842661530-Mapping-attributes-from-Active-Directory-with-ADFS-and-SAML)
- [WorkOS: Keycloak SAML integration](https://workos.com/docs/integrations/keycloak-saml)
- [Last9: How to Configure SAML SSO with Keycloak](https://last9.io/blog/how-to-configure-saml-sso-with-keycloak/)
- [Keycloak: Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [AWS IAM: Configure SAML assertions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html)
