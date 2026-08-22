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
