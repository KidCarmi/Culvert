# TLS Inspection Deployment

Deploying MITM TLS inspection: CA generation/import, trust distribution, bypass, rotation, and the places the workflow blocks.

> **Enterprise-readiness verdict:** **Auto-generated-CA inspection is production-ready. Bring-your-own-CA (internal PKI) inspection is not**, because the imported CA is ECDSA-only, non-persistent, and clobbered by auto-rotation. Evaluate carefully before committing to internal-PKI-signed inspection.

---

## 1. Enabling inspection (auto-generated CA — the supported path)

1. Set `CULVERT_CA_PASSPHRASE` and `-ca-path /data/ca.bundle`.
2. On first start Culvert generates an **ECDSA P-256 root CA** (Subject `O=Culvert, CN=Culvert Root CA`, 10-year validity) and writes `ca.bundle`.

> **The canonical `scripts/install.sh` path auto-encrypts.** On a **fresh** install, `setup_at_rest_encryption()` (install.sh:1036-1094) sets `CULVERT_CA_PASSPHRASE` (and `CULVERT_LOG_PASSPHRASE`) in `.env` — default choice auto-generates a strong 40-char passphrase, and a non-interactive `curl … | bash` run auto-generates it too. So the standard installer encrypts the CA key out of the box; **save the generated passphrase it prints.**
>
> **⚠ Empty passphrase is a key-custody risk, not a disable switch — on the non-installer paths.** If you deploy **manually** (`docker compose up` / `docker build` without exporting `CULVERT_CA_PASSPHRASE`), choose installer option **[3] "Skip — store unencrypted"**, or add inspection to an **existing** deployment where the installer left the CA passphrase to you, then with the passphrase empty `LoadOrInitCA` still generates the CA and `SaveCA` writes the key as **plaintext PEM** (`internal/ca/ca.go:194-235`) — **inspection stays ACTIVE and forges leaves with an unencrypted root key.** Do not assume "no passphrase = inspection off." Tunnel-only degradation happens only in a *different* case: an **existing, already-encrypted** `ca.bundle` that cannot be decrypted (wrong/missing passphrase) → CA load fails (non-fatal) → `/health` shows `ssl_inspection: load_failed`/`unavailable`. **Always confirm the passphrase is set and `ssl_inspection: ready` on `GET /health`.**
3. Key at rest: PBKDF2-SHA256 (600k iterations) + AES-256-GCM, atomic 0600 write.
4. Leaf certs are forged on the fly (24h validity, LRU cache 10k/1h).

**Back up `ca.bundle` immediately** — losing it (and the passphrase) means re-issuing and re-distributing a new root to every endpoint.

**Evidence:** `internal/ca/ca.go:145-186,211-236`.

## 2. Importing your own CA (internal PKI) — read the caveats first

You *can* upload an internal-PKI intermediate via **Certificates → Upload Custom Certificate** (target *MITM / SSL Inspection*) or `POST /api/certs/upload` (`target=mitm`, PEM cert + key). But three hard limitations apply:

> **⛔ GAP-PKI-02 — ECDSA only.** RSA keys are rejected ("only ECDSA private keys are supported for MITM CA"). Many enterprise PKIs (Microsoft ADCS) issue RSA. Workaround: mint a dedicated **ECDSA P-256 sub-CA** from your internal root and import that.

> **⛔ GAP-PKI-01 — not persisted.** The GUI upload sets the CA in memory only; there is **no `SaveCA`**. On restart the proxy reverts to the on-disk `ca.bundle`. Verified by adversarial review. Workaround: stage the EC PEM bundle (cert + `EC PRIVATE KEY` concatenated) at `-ca-path` on disk so `LoadCA`/`ImportBundle` picks it up durably — this requires host access and is EC-only.

> **⛔ GAP-PKI-03 — auto-rotation overwrites it.** At the 30-day-before-expiry mark, auto-rotation calls `InitCA` and generates a fresh **Culvert-generated** root, silently replacing your imported CA. There is no opt-out flag. Workaround: import with long validity, monitor expiry externally, and plan a manual re-import.

**Accepted formats:** PEM only; no PKCS#12/DER (GAP-PKI-04 — convert with `openssl pkcs12 -nodes` off-box). The private key must be supplied (the CA forges leaves).

## 3. CA distribution (trust push to endpoints)

Download the root: **Certificates → Download Root CA (.pem)**, or:

```bash
curl -k https://<host>:9090/api/ca-cert -o culvert-ca.pem   # viewer role
```

Only the certificate is exportable — never the private key. Distribute to endpoint trust stores:

| Platform | Command / method |
|---|---|
| Debian/Ubuntu | `cp culvert-ca.pem /usr/local/share/ca-certificates/culvert-ca.crt && update-ca-certificates` |
| RHEL/CentOS | `cp culvert-ca.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust` |
| macOS | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain culvert-ca.pem` |
| Windows (GPO) | Computer Config → Policies → Windows Settings → Security → Public Key Policies → Trusted Root CAs |
| Windows (PS) | `Import-Certificate -FilePath culvert-ca.pem -CertStoreLocation Cert:\LocalMachine\Root` |
| MDM (Intune/Jamf) | Trusted Root Certificate profile |
| Chrome/Firefox | Settings → Certificates → Authorities → Import |

**Ownership:** trust distribution is an endpoint-management (GPO/MDM) task, not a Culvert function. Plan it with the desktop team before enabling inspection fleet-wide.

## 4. Bypass rules (do NOT inspect these)

Cert-pinned apps, banking, healthcare, and mTLS-protected origins must bypass inspection. Configure via **SSL Inspection Bypass** or `GET/POST/DELETE /api/ssl-bypass` (operator role): FQDN globs (`*.bank.com`) or `~`-prefixed regexes, persisted to `ssl_bypass.json`. Per-rule `SSLAction: Bypass` also works; the bypass matcher is an always-bypass override.

> **GAP-PKI-06 — origin mTLS.** Culvert presents no client certificate to inspected origins; an origin requiring mutual TLS returns `502`. **Bypass** those hosts (opaque relay preserves the client's own mTLS). Non-TLS over CONNECT (SSH/RDP) falls back to a raw relay automatically.

- **Adaptive decryption exclusion (automatic, opt-in fail-open).** Separately from the bypass rules above, a decryption profile can opt a rule into `OnInspectError=="fail-open"`: hosts that repeatedly fail decryption are learned into a scoped, TTL-bounded cache and subsequent CONNECTs to them bypass automatically — see [`docs/operator/decryption-auto-exclusions.md`](../operator/decryption-auto-exclusions.md).
- **Native HTTP/2 inspection** is a separate, opt-in per-rule/profile setting that inspects the tunnel as HTTP/2 instead of downgrading to HTTP/1.1 — see [`docs/operator/http2-inspection.md`](../operator/http2-inspection.md).

## 5. Rotation & expiry

- **Automatic:** a 24h loop rotates when the CA is ≤30 days from expiry, with **dual-CA overlap** (old CA retained as secondary; leaves chain both so clients trusting either validate).
- **Manual:** `POST /api/ca/rotate` (admin; two-step confirmation token). Warning: invalidates all leaf certs; clients must trust the new CA.
- **Distribution window:** leaves are valid 24h, so distribute the new root before the old leaves expire. Set a `cert_expiry` webhook alert.

> **GAP-PKI-05 — expiry watchdog drift.** The `cert_expiry` alert fires only *when rotation occurs*; the documented "startup alert if ≤30 days" is not implemented. In an in-memory-only CA posture there is no independent expiry warning — poll `GET /api/ca/status` (`expiresIn`) from external monitoring.

## 6. Privacy & operational ownership

- Inspection decrypts user traffic — coordinate with legal/HR and exempt sensitive categories (banking, health) via bypass.
- Own the CA lifecycle: passphrase custody, `ca.bundle` backup, trust distribution, rotation-window comms.
- Key custody: the root CA key is protected only by `CULVERT_CA_PASSPHRASE` (not the CA-3 KEK system). An HSM `KeyProvider` seam exists but is not wired into the leaf-signing hot path.

## 7. Validation & rollback

- **Validate:** from a pilot endpoint with the root trusted, browse an inspected HTTPS site → no cert warning; browse a bypassed site → origin's own cert presented. Confirm `/health` `ssl_inspection: ready`.
- **Rollback:** to stop inspecting a host, add it to SSL bypass (immediate). To disable inspection entirely, remove `-ca-path`/passphrase and restart (proxy falls back to plain forwarding). To undo a bad rotation, the dual-CA overlap keeps the prior CA valid until its own expiry.

## 8. Checklist

- [ ] `CULVERT_CA_PASSPHRASE` set; `/health` shows `ssl_inspection: ready`.
- [ ] `ca.bundle` backed up (encrypted).
- [ ] Root CA distributed to a pilot endpoint and verified.
- [ ] Bypass list populated (pinned/banking/mTLS/internal-CA hosts).
- [ ] `cert_expiry` alert webhook configured; external expiry monitoring on `/api/ca/status`.
- [ ] If using internal PKI: EC sub-CA minted; **known** that GUI import is non-persistent and auto-rotation will clobber it — durable path is the on-disk bundle.
