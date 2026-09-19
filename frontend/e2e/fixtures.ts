// FE-3 e2e fixtures: instance URLs, the seeded roster (created by
// scripts/e2e-smoke.sh via -ui-users-file — the repository's supported
// durable-roster mechanism; NO test-only bypass exists in production code),
// and an RFC 6238 TOTP generator so the browser test can answer the real
// server's two-factor challenge.
import { createHmac } from "node:crypto";

export const AUTH_URL =
  process.env["CULVERT_E2E_BASE_URL"] ?? "http://127.0.0.1:19090";
export const FRESH_URL =
  process.env["CULVERT_E2E_FRESH_URL"] ?? "http://127.0.0.1:19091";
export const SETUPFAIL_URL =
  process.env["CULVERT_E2E_SETUPFAIL_URL"] ?? "http://127.0.0.1:19092";
/** 2F-G: the appliance whose config.yaml seeds a read-only `yaml` upstream
 * entry (see scripts/e2e-smoke.sh). */
export const YAML_URL =
  process.env["CULVERT_E2E_YAML_URL"] ?? "http://127.0.0.1:19093";
/** FE-6A.1: the appliance whose IdP registry file is CORRUPT (quarantined
 * at boot) and whose config.yaml carries a legacy `ldap:` block that is
 * present, active and not retired (see scripts/e2e-smoke.sh). */
export const IDPQ_URL =
  process.env["CULVERT_E2E_IDPQ_URL"] ?? "http://127.0.0.1:19094";
/** FE-6A.2: the write-journey appliance (corrupt registry + legacy block). */
export const IDPW_URL =
  process.env["CULVERT_E2E_IDPW_URL"] ?? "http://127.0.0.1:19095";
/** FE-6B.1: the appliance with a persisted, passphrase-sealed inspection CA
 * and no UI pair at boot (the spec seeds one through the admin API). */
export const CERT_URL =
  process.env["CULVERT_E2E_CERT_URL"] ?? "http://127.0.0.1:19096";
/** FE-6B.1: the DEGRADED appliance — malformed CA bundle (load failed), a
 * corrupt persisted UI pair, and a pre-seeded operation ledger. */
export const CERTDEG_URL =
  process.env["CULVERT_E2E_CERTDEG_URL"] ?? "http://127.0.0.1:19097";
/** FE-6B.1 correction round: the appliance that boots WITH a persisted UI
 * pair (A) on disk and WITHOUT -ui-no-tls — its admin listener serves A over
 * real TLS, so the published served identity can be checked against the
 * certificate a TLS client actually receives. */
export const CERTTLS_URL =
  process.env["CULVERT_E2E_CERTTLS_URL"] ?? "https://127.0.0.1:19098";
/** FE-6B.1 correction round: where the harness generated pair B for CERTTLS. */
export const CERTTLS_UI_PAIR_DIR =
  process.env["CULVERT_E2E_CERTTLS_UI_PAIR_DIR"] ?? "";
/** FE-6B.1: where the harness generated the UI leaf pair the spec uploads. */
export const CERT_UI_PAIR_DIR =
  process.env["CULVERT_E2E_CERT_UI_PAIR_DIR"] ?? "";
/** FE-6B.1: CERTDEG's data root (a leak needle — never in any answer). */
export const CERTDEG_DATA_DIR =
  process.env["CULVERT_E2E_CERTDEG_DATA_DIR"] ?? "/data";
/** FE-6B.1: the CERT appliance's CA passphrase (a leak needle). */
export const CA_PASSPHRASE_CANARY =
  process.env["CULVERT_E2E_CA_PASSPHRASE_CANARY"] ??
  "E2E-CA-PASSPHRASE-never-in-browser";
/** FE-6A.2 correction: the harness's minimal LDAP responder (cmd/ldapstub) —
 * the directory an ENABLED LDAP profile must reach at the write boundary. */
export const LDAP_STUB_URL =
  process.env["CULVERT_E2E_LDAP_STUB_URL"] ?? "ldap://127.0.0.1:19389";
/** PR-C1: the AUTH appliance's per-instance data root (CULVERT_DATA_DIR,
 * exported by scripts/e2e-smoke.sh) — where its admin_settings.json lives
 * for the on-disk ciphertext needle checks. Defaults to the appliance's
 * built-in root. */
export const AUTH_DATA_DIR =
  process.env["CULVERT_E2E_AUTH_DATA_DIR"] ?? "/data";

export const ADMIN_STATE = "e2e/.state/admin.json";
export const EMPTY_STATE = { cookies: [], origins: [] };

// Seeded roster (bcrypt hashes live in the harness script, not here).
export const USERS = {
  admin: { user: "admin", pass: "Password123", role: "admin" },
  operator: { user: "op-user", pass: "OperatorPass1", role: "operator" },
  viewer: { user: "view-user", pass: "ViewerPass1", role: "viewer" },
  totp: { user: "totp-user", pass: "TotpPass123", role: "admin" },
} as const;

export const TOTP_SECRET = "JBSWY3DPEHPK3PXP"; // base32, seeded for totp-user
export const BACKUP_CODE = "RESCUE-CODE-7"; // one seeded backup code

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/=+$/, "").toUpperCase()) {
    const idx = B32.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238: HMAC-SHA1, 30s step, 6 digits — matches internal/totp. */
export function totpCode(secret: string, atMs = Date.now()): string {
  const counter = Math.floor(atMs / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", base32Decode(secret)).update(buf).digest();
  const off = (h[h.length - 1] ?? 0) & 0xf;
  const code =
    (((h[off] ?? 0) & 0x7f) << 24) |
    (((h[off + 1] ?? 0) & 0xff) << 16) |
    (((h[off + 2] ?? 0) & 0xff) << 8) |
    ((h[off + 3] ?? 0) & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}
