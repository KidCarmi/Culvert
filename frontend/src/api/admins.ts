// FE-6A.1 — Administrators READ client: fail-closed runtime decoders over
// the frozen FE-6A.0 roster read model (ui_auth.go apiAuthUsers GET →
// store.go UIUserInfo + RosterRevision, node-local) and the login lock set
// (apiAuthLockouts GET → internal/lockout LockedEntry + Generation,
// node-local), plus — FE-6A.2 — the WRITE client: create / update / delete
// an account, clear a lockout and change one's own password as action-bound,
// fence-carrying (query string), never-retrying calls whose 2xx is a verdict
// only when it proves the target identity and the contracted facts, and
// whose refusal is a verdict only inside the ENDPOINT-SPECIFIC allowlist
// (ADMIN_REFUSAL_CONTRACT). TOTP enrollment stays out of scope (GAP-2).
//
// Secret boundary: the roster read model carries no credential material by
// construction (UIUserInfo has no hash, seed or backup code). The browser
// refuses independently: a user record carrying pass_hash / totp_secret /
// backup_codes / password / totp_last_counter (any spelling) is a DECODE
// FAILURE — never rendered, never cached. Both endpoints are admin-only
// (uiRoutes); a 403 is the server's authoritative role verdict and is
// rendered as a bounded state by the page, never retried into.
import { ApiError, apiRequest } from "./client";
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
  // REQUIRED nullable slice (apiAuthLockouts always emits the key; OpenAPI:
  // required + nullable): a MISSING key is a decode failure — a malformed
  // response must never render "No active lockouts" — while `null` stays
  // the empty slice (correction round 2, D4).
  if (!("lockouts" in o)) {
    throw new DecodeError(`${path}.lockouts`, "array or null", undefined);
  }
  const raw = o["lockouts"];
  return {
    lockouts:
      raw === null ? [] : readArray(decodeLockout)(raw, `${path}.lockouts`),
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

// ═══════════════════════════════════════════════════════════════════════════
// FE-6A.2 — WRITE client
// ═══════════════════════════════════════════════════════════════════════════

const BOOL_TRUE: Decoder<true> = (v, path = "$") => {
  if (v !== true) throw new DecodeError(path, "true", v);
  return true;
};

function bindUser(
  u: AdminUser,
  username: string,
  role: Role | undefined,
  path: string,
): void {
  if (u.username !== username)
    throw new DecodeError(
      `${path}.user.username`,
      `the target account ${username}`,
      u.username,
    );
  if (role !== undefined && u.role !== role)
    throw new DecodeError(
      `${path}.user.role`,
      `the submitted role ${role}`,
      u.role,
    );
}

export interface UserCreateResult {
  ok: true;
  user: AdminUser;
  revision: number;
  persisted: boolean;
}

export interface UserUpdateResult extends UserCreateResult {
  sessionsRevoked: boolean;
  selfAffected: boolean;
  securityGeneration: number;
}

export interface UserDeleteResult {
  ok: true;
  deleted: true;
  username: string;
  revision: number;
  persisted: boolean;
  sessionsRevoked: boolean;
  selfAffected: boolean;
}

export interface ChangePasswordResult {
  ok: true;
  revision: number;
  persisted: boolean;
  sessionsRevoked: boolean;
  selfAffected: boolean;
  securityGeneration: number;
}

export interface ClearLockoutResult {
  ok: true;
  username: string;
  generation: number;
  scope: "node-local";
}

export interface CreateUserInput {
  username: string;
  password: string;
  role: Role;
}
export interface UpdateUserInput {
  username: string;
  role?: Role;
  password?: string;
}

const fenced = (path: string, key: string, value: number): string =>
  `${path}?${key}=${encodeURIComponent(String(value))}`;
const withSignal = (signal?: AbortSignal): { signal?: AbortSignal } =>
  signal !== undefined ? { signal } : {};

/** POST /api/auth/users?revision= — create is never an upsert. */
export function createAdminUser(
  input: CreateUserInput,
  revision: number,
  signal?: AbortSignal,
): Promise<UserCreateResult> {
  const decoder: Decoder<UserCreateResult> = (v, path = "$") => {
    const o = readRecord(v, path);
    refuseSecretKeys(o, path);
    field(o, "ok", BOOL_TRUE, path);
    const user = field(o, "user", decodeAdminUser, path);
    bindUser(user, input.username, input.role, path);
    return {
      ok: true,
      user,
      revision: field(o, "revision", readNumber, path),
      persisted: field(o, "persisted", readBoolean, path),
    };
  };
  return apiRequest(fenced("/api/auth/users", "revision", revision), decoder, {
    method: "POST",
    body: {
      username: input.username,
      password: input.password,
      role: input.role,
    },
    ...withSignal(signal),
  });
}

/** PUT /api/auth/users?revision= — role and/or password; the session facts
 * (sessionsRevoked / selfAffected) are REQUIRED on the answer. */
export function updateAdminUser(
  input: UpdateUserInput,
  revision: number,
  signal?: AbortSignal,
): Promise<UserUpdateResult> {
  const decoder: Decoder<UserUpdateResult> = (v, path = "$") => {
    const o = readRecord(v, path);
    refuseSecretKeys(o, path);
    field(o, "ok", BOOL_TRUE, path);
    const user = field(o, "user", decodeAdminUser, path);
    bindUser(user, input.username, input.role, path);
    return {
      ok: true,
      user,
      revision: field(o, "revision", readNumber, path),
      persisted: field(o, "persisted", readBoolean, path),
      sessionsRevoked: field(o, "sessionsRevoked", readBoolean, path),
      selfAffected: field(o, "selfAffected", readBoolean, path),
      securityGeneration: field(o, "securityGeneration", readNumber, path),
    };
  };
  const body: Record<string, string> = { username: input.username };
  if (input.role !== undefined) body["role"] = input.role;
  if (input.password !== undefined) body["password"] = input.password;
  return apiRequest(fenced("/api/auth/users", "revision", revision), decoder, {
    method: "PUT",
    body,
    ...withSignal(signal),
  });
}

/** DELETE /api/auth/users?username=&revision= — bodiless. */
export function deleteAdminUser(
  username: string,
  revision: number,
  signal?: AbortSignal,
): Promise<UserDeleteResult> {
  const decoder: Decoder<UserDeleteResult> = (v, path = "$") => {
    const o = readRecord(v, path);
    refuseSecretKeys(o, path);
    field(o, "ok", BOOL_TRUE, path);
    field(o, "deleted", BOOL_TRUE, path);
    const got = field(o, "username", readString, path);
    if (got !== username)
      throw new DecodeError(
        `${path}.username`,
        `the deleted account ${username}`,
        got,
      );
    return {
      ok: true,
      deleted: true,
      username: got,
      revision: field(o, "revision", readNumber, path),
      persisted: field(o, "persisted", readBoolean, path),
      sessionsRevoked: field(o, "sessionsRevoked", readBoolean, path),
      selfAffected: field(o, "selfAffected", readBoolean, path),
    };
  };
  const qs = new URLSearchParams({ username, revision: String(revision) });
  return apiRequest(`/api/auth/users?${qs.toString()}`, decoder, {
    method: "DELETE",
    ...withSignal(signal),
  });
}

/** POST /api/auth/change-password?generation= — fenced on the caller's own
 * security generation (GET /api/auth/status); snake_case body by contract. */
export function changeOwnPassword(
  input: { currentPassword: string; newPassword: string },
  generation: number,
  signal?: AbortSignal,
): Promise<ChangePasswordResult> {
  const decoder: Decoder<ChangePasswordResult> = (v, path = "$") => {
    const o = readRecord(v, path);
    refuseSecretKeys(o, path);
    field(o, "ok", BOOL_TRUE, path);
    return {
      ok: true,
      revision: field(o, "revision", readNumber, path),
      persisted: field(o, "persisted", readBoolean, path),
      sessionsRevoked: field(o, "sessionsRevoked", readBoolean, path),
      selfAffected: field(o, "selfAffected", readBoolean, path),
      securityGeneration: field(o, "securityGeneration", readNumber, path),
    };
  };
  return apiRequest(
    fenced("/api/auth/change-password", "generation", generation),
    decoder,
    {
      method: "POST",
      body: {
        current_password: input.currentPassword,
        new_password: input.newPassword,
      },
      ...withSignal(signal),
    },
  );
}

/** POST /api/auth/lockouts?generation= — clears every lock for the username. */
export function clearLockout(
  username: string,
  generation: number,
  signal?: AbortSignal,
): Promise<ClearLockoutResult> {
  const decoder: Decoder<ClearLockoutResult> = (v, path = "$") => {
    const o = readRecord(v, path);
    field(o, "ok", BOOL_TRUE, path);
    const got = field(o, "username", readString, path);
    if (got !== username)
      throw new DecodeError(
        `${path}.username`,
        `the cleared account ${username}`,
        got,
      );
    const gen = field(o, "generation", readNumber, path);
    if (gen < 1) throw new DecodeError(`${path}.generation`, ">= 1", gen);
    return {
      ok: true,
      username: got,
      generation: gen,
      scope: field(o, "scope", readEnum(["node-local"] as const), path),
    };
  };
  return apiRequest(
    fenced("/api/auth/lockouts", "generation", generation),
    decoder,
    {
      method: "POST",
      body: { username },
      ...withSignal(signal),
    },
  );
}

// ── Endpoint-specific typed refusals ───────────────────────────────────────

export const ADMIN_ENDPOINTS = [
  "users.create",
  "users.update",
  "users.delete",
  "change_password",
  "lockouts.clear",
] as const;
export type AdminEndpoint = (typeof ADMIN_ENDPOINTS)[number];
type AdminFence = "revision" | "generation" | null;

interface AdminCodeContract {
  status: number;
  /** which fence fact a stale / precondition_required refusal must carry */
  fence: AdminFence;
}

const COMMON: Record<string, AdminCodeContract> = {
  invalid_input: { status: 400, fence: null },
  forbidden: { status: 403, fence: null },
  method_not_allowed: { status: 405, fence: null },
};
const ROSTER: Record<string, AdminCodeContract> = {
  ...COMMON,
  stale: { status: 409, fence: "revision" },
  precondition_required: { status: 428, fence: "revision" },
  persist_failed: { status: 500, fence: null },
  persistence_not_configured: { status: 503, fence: null },
};

/** Exactly the codes each endpoint can emit (ui_auth.go handlers +
 * writeRosterRefusal) at their contracted status. */
export const ADMIN_REFUSAL_CONTRACT: Readonly<
  Record<AdminEndpoint, Readonly<Record<string, AdminCodeContract>>>
> = {
  "users.create": {
    ...ROSTER,
    user_exists: { status: 409, fence: null },
    last_admin: { status: 409, fence: null },
  },
  "users.update": {
    ...ROSTER,
    not_found: { status: 404, fence: null },
    last_admin: { status: 409, fence: null },
  },
  "users.delete": {
    ...ROSTER,
    not_found: { status: 404, fence: null },
    last_admin: { status: 409, fence: null },
  },
  change_password: {
    ...COMMON,
    invalid_credentials: { status: 403, fence: null },
    not_found: { status: 404, fence: null },
    stale: { status: 409, fence: "generation" },
    precondition_required: { status: 428, fence: "generation" },
    persist_failed: { status: 500, fence: null },
    persistence_not_configured: { status: 503, fence: null },
  },
  "lockouts.clear": {
    ...COMMON,
    not_found: { status: 404, fence: null },
    stale: { status: 409, fence: "generation" },
    precondition_required: { status: 428, fence: "generation" },
  },
};

export interface AdminRefusal {
  endpoint: AdminEndpoint;
  status: number;
  code: string;
  facts: { revision?: number; generation?: number };
}

function parsedBody(err: ApiError): Record<string, unknown> | null {
  if (err.bodyText === undefined) return null;
  try {
    const v: unknown = JSON.parse(err.bodyText);
    return isRecord(v) ? v : null;
  } catch {
    return null;
  }
}
const safeNumber = (v: unknown): number | undefined =>
  typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : undefined;

/** A verdict ONLY for a code the endpoint can emit, at its status, with its
 * fence fact when one is required; the server's `error` line never leaves. */
export function asAdminRefusal(
  err: unknown,
  endpoint: AdminEndpoint,
): AdminRefusal | null {
  if (
    !(err instanceof ApiError) ||
    err.kind !== "http" ||
    err.status === undefined
  )
    return null;
  const body = parsedBody(err);
  if (body === null) return null;
  const code = body["code"];
  if (typeof code !== "string") return null;
  const contract = ADMIN_REFUSAL_CONTRACT[endpoint][code];
  if (contract === undefined || contract.status !== err.status) return null;
  const cur = isRecord(body["current"]) ? body["current"] : {};
  const facts: AdminRefusal["facts"] = {};
  const revision = safeNumber(cur["revision"]);
  if (revision !== undefined) facts.revision = revision;
  const generation = safeNumber(cur["generation"]);
  if (generation !== undefined) facts.generation = generation;
  if (contract.fence === "revision" && facts.revision === undefined)
    return null;
  if (contract.fence === "generation" && facts.generation === undefined)
    return null;
  return { endpoint, status: err.status, code, facts };
}

/** Any endpoint's verdict test for the UNPROVEN classifier. */
function anyAdminRefusal(err: ApiError): boolean {
  return ADMIN_ENDPOINTS.some((e) => asAdminRefusal(err, e) !== null);
}

/** True when the mutation MAY be applied but no trustworthy verdict exists. */
export function adminUnproven(err: unknown): boolean {
  if (!(err instanceof ApiError)) return true;
  switch (err.kind) {
    case "target":
      return false;
    case "network":
    case "timeout":
    case "aborted":
    case "contenttype":
    case "decode":
    case "toolarge":
      return true;
    case "http":
      if (err.status === 401 || err.status === 403) return false;
      return !anyAdminRefusal(err);
  }
}
