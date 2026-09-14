# IdP registry compile — third-party reachability and config sync

**Applies to:** every appliance with at least one enabled OIDC or SAML identity
provider in the IdP registry (`/api/idp`, admin UI → Identity Providers).
**Sweep:** CHAOS-66 (`roadmap/CHAOS-ENGINEERING-REVIEW.md` §36).

---

## 1. What "compiling a profile" means

When Culvert turns a stored IdP profile into a live provider it performs
**outbound HTTP to an origin the operator named in that profile**:

| Profile type | Fetch at compile | Budget |
|---|---|---|
| SAML with `metadata_url` | `GET <metadata_url>` | shared compile envelope (15 s) |
| SAML with `metadata_xml` | none — the document is inline | — |
| OIDC | `GET <issuer>/.well-known/openid-configuration` | shared compile envelope (15 s) |
| LDAP | none | — |

A compile happens when:

* the process boots and loads `idp_profiles.json`;
* an admin creates or updates a profile (`POST`/`PUT /api/idp`);
* a **control-plane snapshot** arrives on a Data Plane and the profile's
  configuration has changed.

That last line is the one that changed in CHAOS-66. A Data Plane polls its
control plane every 30 s, and **any** config mutation anywhere in the fleet
advances the snapshot version — so before this change, editing one policy rule
made every node re-fetch every SAML metadata document and every OIDC discovery
document. A profile whose configuration is unchanged is now **reused**, and no
fetch happens.

---

## 2. Symptom: "this node is not applying new policy/auth config"

On the Data Plane poll path the IdP sync runs **before** the rest of the
snapshot is applied, and a failure aborts the apply. If an IdP's metadata or
discovery endpoint cannot be reached while a **changed** profile needs
compiling, the node keeps serving on its previous configuration:

* no new blocklist entries,
* no new or edited policy rules,
* no rate-limit, IP-filter or session-key changes,
* the last-good snapshot is not refreshed and the version counter does not
  advance, so the next poll retries the same fetch.

### How it shows up

| Surface | What you see |
|---|---|
| `GET /api/diagnostics` | operator-contract check **`dp_config_snapshot_apply`** = `fail` |
| Process log | `DataPlane: config snapshot v<N> apply incomplete: idp profile sync: idp "<id>" compile error: …` |
| `/metrics` | `culvert_idp_compile_failures_total` climbing |

`dp_config_snapshot_apply` is deliberately the **only** name for this state.
CHAOS-66 added no second alert and no second contract row: the operator action
is identical whatever rejected the snapshot, and a second name for one root
cause is two pages for one action.

### What to do

1. Confirm the cause is an IdP compile — the log line names the profile id.
2. Check that the named profile's `metadata_url` / `issuer` host is reachable
   **from the Data Plane node** (not just from the control plane): DNS, egress
   policy, the IdP's own status page.
3. The node is still proxying. Nothing about the data path is degraded; the
   configuration is simply frozen at its last applied version.
4. If the IdP will be unavailable for a long time and the config change is
   urgent, either fix reachability or disable the affected profile on the
   control plane — a disabled profile is never compiled.

---

## 3. Metrics

Emitted **only** when at least one IdP profile is configured. A node with no
identity providers exports none of these, so a flat zero can never be confused
with a registry that has stopped working.

| Series | Meaning |
|---|---|
| `culvert_idp_compile_total` | providers built from scratch — each OIDC/SAML one is an outbound fetch |
| `culvert_idp_compile_failures_total` | builds that failed; on the snapshot path a failure rejects the whole IdP sync |
| `culvert_idp_compile_reused_total` | snapshot applies that reused an already-compiled provider and skipped the fetch |

**Expected shape on a healthy fleet:** `reused_total` dominates
`compile_total`. A node where `compile_total` tracks the snapshot rate is
recompiling on every apply — which means the profile is genuinely changing each
time, or the fingerprint is not recognising it as stable. Either is worth a
look, because every one of those compiles is traffic at the identity provider.

**Paging suggestion:** alert on `increase(culvert_idp_compile_failures_total[15m]) > 0`
**together with** the `dp_config_snapshot_apply` check, not on the counter
alone — a single failure during a deliberate profile edit is expected.

---

## 4. Picking up a rotated IdP signing certificate

**This is the one operational limitation to know about.**

SAML metadata and OIDC discovery are fetched **once, when the profile is
compiled, and are never refreshed** (register row **AU-6**). The IdP signing
certificate inside a SAML metadata document is the only thing that validates an
assertion signature, so when the identity provider rotates it — Azure AD rolls
automatically, Okta and ADFS rotate on a schedule — SAML logins begin failing
with a signature-validation error and **keep failing until the profile is
compiled again**.

Two operator actions force a fresh fetch:

1. **Re-save the profile** (admin UI → Identity Providers → Save, or
   `PUT /api/idp/<id>`). An admin save deliberately always recompiles, even
   when nothing in the profile changed — this is why the reuse rule added in
   CHAOS-66 applies to the control-plane snapshot path only.
2. **Disable and re-enable the profile.** A disabled profile has no live
   provider, so re-enabling always compiles.

A process restart also works, but is the heavier option.

> OIDC is **not** affected in the same way: its JWKS key set has its own
> refreshing cache with a rate floor and a hard stale ceiling (CHAOS-49 /
> SEC-JWKS-1, `docs/operator/identity-backend-availability.md`). Only the
> discovery *document* is fetched once, and its endpoint URLs rarely change.

---

## 5. Budgets

All third-party work performed by **one** registry operation shares a single
15-second envelope (`idpCompileBudget`) — it is not a fresh allowance per
profile. A deployment with one IdP profile behaves exactly as it did before;
only the fan-out case shrinks, so a node with several profiles and an
unreachable origin no longer spends profile-count × 15 s on its poll goroutine
or during boot.

At boot a compile failure is logged and skipped, never fatal: a node that
cannot reach its identity provider still comes up and still proxies.

---

## 6. Related

* `docs/operator/identity-backend-availability.md` — reachability of the
  credential back ends at request time (CHAOS-47/49).
* `docs/operator/ldap-directory-stalls.md` — the directory that accepts and
  then stops answering (CHAOS-58).
* `roadmap/CHAOS-ENGINEERING-REVIEW.md` §36 — the full finding, the residual
  risks, and the gate inventory.
