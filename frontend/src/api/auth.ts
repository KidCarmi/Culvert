// FE-3 setup/auth API surface + runtime decoders. Backend semantics verified
// against ui_auth.go (apiSetupStatus / apiSetupComplete / apiAuthLogin /
// apiAuthStatus / apiAuthLogout) — the server is authoritative; every payload
// crosses a runtime decoder and malformed "success" fails CLOSED into a
// DecodeError (surfaced as a controlled authentication error, never an
// authenticated state).
//
// Pre-setup bootstrap window (ui_auth.go:190-192): while !cfg.IsConfigured()
// the server reports {loggedIn:true, user:"", role:"admin"} because the
// bootstrap window grants admin authority to every request. That is NOT a
// human session — the decoder marks it `bootstrap: true` and the state
// machine (which always reads /api/setup/status FIRST) never treats it as an
// authenticated identity.
import { apiRequest } from "./client";
import {
  DecodeError,
  field,
  readBoolean,
  readEnum,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

export type Role = "admin" | "operator" | "viewer";

// Server doctrine (store.go:333-349): viewer(1) < operator(2) < admin(3).
export const ROLES: readonly Role[] = ["admin", "operator", "viewer"];
export const readRole: Decoder<Role> = readEnum(ROLES);

export interface SetupStatus {
  needsSetup: boolean;
  tlsFallback: boolean;
  tlsFallbackReason: string;
}

export type AuthStatus =
  | { loggedIn: false; tlsFallback: boolean; tlsFallbackReason: string }
  | {
      loggedIn: true;
      user: string;
      role: Role;
      /** the pre-setup bootstrap shape (user === ""), never a human session */
      bootstrap: boolean;
      tlsFallback: boolean;
      tlsFallbackReason: string;
    };

export type LoginResult =
  { kind: "totp_required" } | { kind: "ok"; user: string; role: Role };

// ── decoders ───────────────────────────────────────────────────────────────

function readTLSFallback(o: Record<string, unknown>): {
  tlsFallback: boolean;
  tlsFallbackReason: string;
} {
  return {
    tlsFallback: field(o, "ui_tls_fallback", readBoolean),
    tlsFallbackReason: field(o, "ui_tls_fallback_reason", readString),
  };
}

export const decodeSetupStatus: Decoder<SetupStatus> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    needsSetup: field(o, "needsSetup", readBoolean, path),
    ...readTLSFallback(o),
  };
};

export const decodeAuthStatus: Decoder<AuthStatus> = (v, path = "$") => {
  const o = readRecord(v, path);
  const loggedIn = field(o, "loggedIn", readBoolean, path);
  const tls = readTLSFallback(o);
  if (!loggedIn) return { loggedIn: false, ...tls };
  const user = field(o, "user", readString, path);
  const role = field(o, "role", readRole, path);
  if (user === "" && role !== "admin") {
    // The ONLY evidenced empty-identity shape is the pre-setup bootstrap
    // window, which always carries role admin — anything else is malformed.
    throw new DecodeError(`${path}.user`, "non-empty identity", user);
  }
  return { loggedIn: true, user, role, bootstrap: user === "", ...tls };
};

export const decodeLoginResponse: Decoder<LoginResult> = (v, path = "$") => {
  const o = readRecord(v, path);
  if ("totp_required" in o) {
    if (field(o, "totp_required", readBoolean, path))
      return { kind: "totp_required" };
    throw new DecodeError(`${path}.totp_required`, "true", o["totp_required"]);
  }
  if (!field(o, "ok", readBoolean, path)) {
    throw new DecodeError(`${path}.ok`, "true", o["ok"]);
  }
  const user = field(o, "user", readString, path);
  if (user === "")
    throw new DecodeError(`${path}.user`, "non-empty identity", user);
  return { kind: "ok", user, role: field(o, "role", readRole, path) };
};

export const decodeOKResponse: Decoder<{ ok: true }> = (v, path = "$") => {
  const o = readRecord(v, path);
  if (!field(o, "ok", readBoolean, path)) {
    throw new DecodeError(`${path}.ok`, "true", o["ok"]);
  }
  return { ok: true };
};

/** /api/stats used purely as a protected session probe: the payload is
 * discarded — only "the session was accepted by a protected endpoint"
 * matters. Shape is validated as an object, nothing more is trusted. */
export const decodeProbe: Decoder<undefined> = (v, path = "$") => {
  readRecord(v, path);
  return undefined;
};

// ── API calls ──────────────────────────────────────────────────────────────

export function getSetupStatus(): Promise<SetupStatus> {
  return apiRequest("/api/setup/status", decodeSetupStatus, {
    unauthorizedPolicy: "expected", // public endpoint; never a session verdict
  });
}

export function getAuthStatus(): Promise<AuthStatus> {
  return apiRequest("/api/auth/status", decodeAuthStatus, {
    unauthorizedPolicy: "expected", // public endpoint; reports state, never 401s a session away
  });
}

/** POST /api/auth/login. A 401 here is EXPECTED application behavior
 * (invalid password / invalid TOTP) — never the session boundary. On
 * totp_required the caller re-POSTs the SAME credentials plus the code. */
export function postLogin(
  user: string,
  pass: string,
  totp?: string,
): Promise<LoginResult> {
  const body: Record<string, string> = { user, pass };
  if (totp !== undefined && totp !== "") body["totp"] = totp;
  return apiRequest("/api/auth/login", decodeLoginResponse, {
    method: "POST",
    body,
    unauthorizedPolicy: "expected",
  });
}

export function postLogout(): Promise<{ ok: true }> {
  return apiRequest("/api/auth/logout", decodeOKResponse, {
    method: "POST",
    unauthorizedPolicy: "expected", // logging out must never re-enter the boundary
  });
}

/** POST /api/setup/complete — credential path ONLY. The open/unauth mode the
 * API also accepts is deliberately NOT exposed: repository evidence
 * (ui_middleware.go:254-296, store.go:596-600, auth_startup.go) shows that
 * after {unauth:true} the admin UI requires credentials that no in-band path
 * can create — recovery exists only via -user/-pass flags, auth.user YAML,
 * or --reset-password on the appliance shell. The legacy GUI never exposed
 * it either (static/index.html setup wizard is credential-only). */
export function postSetupComplete(
  user: string,
  pass: string,
): Promise<{ ok: true }> {
  return apiRequest("/api/setup/complete", decodeOKResponse, {
    method: "POST",
    body: { user, pass },
    unauthorizedPolicy: "expected",
  });
}

/** Protected-endpoint session probe (viewer-readable /api/stats,
 * uiRoutes MinRole=viewer). Uses the DEFAULT boundary 401 policy — a 401
 * here means the session was refused by a protected endpoint. */
export function probeSession(): Promise<undefined> {
  return apiRequest("/api/stats", decodeProbe);
}
