// FE-6A.1 — Administrators READ client: fail-closed runtime decoders over
// the frozen FE-6A.0 roster read model (ui_auth.go apiAuthUsers GET →
// store.go UIUserInfo + RosterRevision, node-local) and the login lock set
// (apiAuthLockouts GET → internal/lockout LockedEntry + Generation,
// node-local). READ ONLY: no create / update / delete / password / TOTP /
// lockout-reset call lives here — the slice exposes none.
//
// Secret boundary: the roster read model carries no credential material by
// construction (UIUserInfo has no hash, seed or backup code). The browser
// refuses independently: a user record carrying pass_hash / totp_secret /
// backup_codes / password / totp_last_counter (any spelling) is a DECODE
// FAILURE — never rendered, never cached. Both endpoints are admin-only
// (uiRoutes); a 403 is the server's authoritative role verdict and is
// rendered as a bounded state by the page, never retried into.
import { apiRequest } from "./client";
import { readRole } from "./auth";
import type { Role } from "./auth";
import {
  DecodeError,
  field,
  isRecord,
  readArray,
  readBoolean,
  readEnum,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

/** Keys that name credential / second-factor material (any spelling). */
export const ROSTER_SECRET_KEYS: readonly string[] = [
  "pass_hash",
  "passHash",
  "password",
  "pass",
  "totp_secret",
  "totpSecret",
  "backup_codes",
  "backupCodes",
  "totp_last_counter",
  "totpLastCounter",
  "secret",
  "ciphertext",
];

function refuseSecretKeys(v: unknown, path: string): void {
  if (Array.isArray(v)) {
    v.forEach((el, i) => {
      refuseSecretKeys(el, `${path}[${String(i)}]`);
    });
    return;
  }
  if (!isRecord(v)) return;
  for (const k of Object.keys(v)) {
    if (ROSTER_SECRET_KEYS.includes(k)) {
      throw new DecodeError(
        `${path}.${k}`,
        "no credential material (never reaches the browser)",
        "[redacted]",
      );
    }
    refuseSecretKeys(v[k], `${path}.${k}`);
  }
}

// ── Models ─────────────────────────────────────────────────────────────────

export interface AdminUser {
  username: string;
  /** the DURABLE role (the roster commit is the authority) */
  role: Role;
  /** TOTP enrollment present — the seed is never exposed */
  totpEnabled: boolean;
  /** per-user security generation: every session is bound to the generation
   * it was issued under; a role/credential change advances it */
  securityGeneration: number;
}

export interface AdminRoster {
  users: readonly AdminUser[];
  /** server-minted roster fencing token */
  revision: number;
  scope: "node-local";
}

export const LOCKOUT_TIERS = ["account", "pair"] as const;
export type LockoutTier = (typeof LOCKOUT_TIERS)[number];

export interface Lockout {
  tier: LockoutTier;
  username: string;
  /** pair tier only: the locked source IP */
  ip?: string;
  secondsRemaining: number;
}

export interface Lockouts {
  lockouts: readonly Lockout[];
  /** server-owned generation of the lock SET */
  generation: number;
  scope: "node-local";
}

/** Three EXPLICIT administrator postures (correction, blocker 5): a fail-closed
 * read model never assumes the backend's at-least-one-admin invariant. */
export const ROSTER_POSTURES = ["none", "last_admin", "multiple"] as const;
export type RosterPosture = (typeof ROSTER_POSTURES)[number];

export interface RosterFacts {
  total: number;
  adminCount: number;
  /** the username of the ONLY admin, when exactly one remains (the server
   * refuses demoting or deleting it: errRosterLastAdmin) — else null */
  lastAdmin: string | null;
  posture: RosterPosture;
}

// ── Decoders ───────────────────────────────────────────────────────────────

const decodeAdminUser: Decoder<AdminUser> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  return {
    username: field(o, "username", readString, path),
    role: field(o, "role", readRole, path),
    // Always on the wire (UIUserInfo, no omitempty): its absence is a
    // contract violation, never "not configured" (correction, blocker 2).
    totpEnabled: field(o, "totpEnabled", readBoolean, path),
    securityGeneration: field(o, "securityGeneration", readNumber, path),
  };
};

export const decodeAdminRoster: Decoder<AdminRoster> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  return {
    // ListUIUsers always returns a non-nil slice (UserList.users required,
    // not nullable): a missing or null roster is refused, never rendered as
    // "no accounts" (correction, blocker 2).
    users: field(o, "users", readArray(decodeAdminUser), path),
    revision: field(o, "revision", readNumber, path),
    scope: field(o, "scope", readEnum(["node-local"] as const), path),
  };
};

const decodeLockout: Decoder<Lockout> = (v, path = "$") => {
  const o = readRecord(v, path);
  const ip = opt(o, "ip", readString, path);
  return {
    tier: field(o, "tier", readEnum(LOCKOUT_TIERS), path),
    username: field(o, "username", readString, path),
    ...(ip !== undefined ? { ip } : {}),
    secondsRemaining: field(o, "seconds_remaining", readNumber, path),
  };
};

export const decodeLockouts: Decoder<Lockouts> = (v, path = "$") => {
  const o = readRecord(v, path);
  const raw = o["lockouts"];
  return {
    lockouts:
      raw === undefined || raw === null
        ? []
        : readArray(decodeLockout)(raw, `${path}.lockouts`),
    generation: field(o, "generation", readNumber, path),
    scope: field(o, "scope", readEnum(["node-local"] as const), path),
  };
};

/** Pure derivation over the decoded roster (no server field is invented). */
export function rosterFacts(r: AdminRoster): RosterFacts {
  const admins = r.users.filter((u) => u.role === "admin");
  const posture: RosterPosture =
    admins.length === 0
      ? "none"
      : admins.length === 1
        ? "last_admin"
        : "multiple";
  return {
    total: r.users.length,
    adminCount: admins.length,
    lastAdmin: posture === "last_admin" ? (admins[0]?.username ?? null) : null,
    posture,
  };
}

// ── Reads (GET only; both admin-only per uiRoutes) ─────────────────────────

export function getAdminRoster(signal?: AbortSignal): Promise<AdminRoster> {
  return apiRequest(
    "/api/auth/users",
    decodeAdminRoster,
    signal !== undefined ? { signal } : {},
  );
}

export function getLockouts(signal?: AbortSignal): Promise<Lockouts> {
  return apiRequest(
    "/api/auth/lockouts",
    decodeLockouts,
    signal !== undefined ? { signal } : {},
  );
}
