// FE-3 §20 unit matrix (framework-free half): decoders, the authoritative
// machine, the 401 boundary policy + concurrent collapse, RBAC ordering,
// route intent, and the setup credential validators.
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiRequest, setUnauthorizedHandler } from "../api/client";
import {
  decodeAuthStatus,
  decodeLoginResponse,
  decodeOKResponse,
  decodeSetupStatus,
} from "../api/auth";
import type { AuthStatus, SetupStatus } from "../api/auth";
import { DecodeError, readRecord } from "../api/decode";
import { createQueryClient } from "../api/query";
import { AuthMachine } from "../auth/machine";
import { hasRole } from "../auth/rbac";
import { resolveRouteIntent } from "../auth/routeIntent";
import { registerAuthCleanup } from "../auth/teardown";
import { passwordProblem, usernameProblem } from "../features/auth/validation";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  setUnauthorizedHandler(null);
});

const tls = { ui_tls_fallback: false, ui_tls_fallback_reason: "" };

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

describe("setup/auth decoders", () => {
  it("decodes setup status incl. TLS fallback fields", () => {
    expect(
      decodeSetupStatus({
        needsSetup: true,
        ui_tls_fallback: true,
        ui_tls_fallback_reason: "self-sign failed",
      }),
    ).toEqual({
      needsSetup: true,
      tlsFallback: true,
      tlsFallbackReason: "self-sign failed",
    });
    expect(() => decodeSetupStatus({ needsSetup: "yes", ...tls })).toThrow(
      DecodeError,
    );
    expect(() => decodeSetupStatus({ needsSetup: true })).toThrow(DecodeError); // TLS fields required
  });

  it("decodes logged-out and authenticated auth status", () => {
    expect(decodeAuthStatus({ loggedIn: false, ...tls })).toEqual({
      loggedIn: false,
      tlsFallback: false,
      tlsFallbackReason: "",
    });
    const ok = decodeAuthStatus({
      loggedIn: true,
      user: "op",
      role: "operator",
      ...tls,
    });
    expect(ok).toMatchObject({
      loggedIn: true,
      user: "op",
      role: "operator",
      bootstrap: false,
    });
  });

  it("marks the pre-setup bootstrap shape intentionally", () => {
    const boot = decodeAuthStatus({
      loggedIn: true,
      user: "",
      role: "admin",
      ...tls,
    });
    expect(boot).toMatchObject({ loggedIn: true, user: "", bootstrap: true });
    // An empty identity with any NON-admin role has no evidenced meaning.
    expect(() =>
      decodeAuthStatus({ loggedIn: true, user: "", role: "viewer", ...tls }),
    ).toThrow(DecodeError);
  });

  it("rejects invalid roles and malformed payloads", () => {
    expect(() =>
      decodeAuthStatus({ loggedIn: true, user: "x", role: "root", ...tls }),
    ).toThrow(DecodeError);
    expect(() => decodeAuthStatus({ loggedIn: true, ...tls })).toThrow(
      DecodeError,
    );
    expect(() => decodeAuthStatus("nope")).toThrow(DecodeError);
  });

  it("decodes the login union and rejects impossible shapes", () => {
    expect(decodeLoginResponse({ totp_required: true })).toEqual({
      kind: "totp_required",
    });
    expect(
      decodeLoginResponse({ ok: true, user: "admin", role: "admin" }),
    ).toEqual({
      kind: "ok",
      user: "admin",
      role: "admin",
    });
    expect(() => decodeLoginResponse({ totp_required: false })).toThrow(
      DecodeError,
    );
    expect(() =>
      decodeLoginResponse({ ok: true, user: "", role: "admin" }),
    ).toThrow(DecodeError);
    expect(() => decodeLoginResponse({ ok: false })).toThrow(DecodeError);
    expect(() =>
      decodeLoginResponse({ ok: true, user: "a", role: "boss" }),
    ).toThrow(DecodeError);
    expect(decodeOKResponse({ ok: true })).toEqual({ ok: true });
    expect(() => decodeOKResponse({ ok: false })).toThrow(DecodeError);
  });
});

// ---------------------------------------------------------------------------
// 401 policy (§4) + concurrent collapse (§5)
// ---------------------------------------------------------------------------

describe("401 policy", () => {
  it("expected-policy 401 does NOT invoke the boundary handler", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("Invalid credentials\n", { status: 401 }),
        ),
    );
    const boundary = vi.fn();
    setUnauthorizedHandler(boundary);
    const err = await apiRequest("/api/auth/login", readRecord, {
      method: "POST",
      body: { user: "u", pass: "p" },
      unauthorizedPolicy: "expected",
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(boundary).not.toHaveBeenCalled();
  });

  it("boundary-policy 401 (the default) invokes the handler", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(new Response("Unauthorized\n", { status: 401 })),
    );
    const boundary = vi.fn();
    setUnauthorizedHandler(boundary);
    await apiRequest("/api/stats", readRecord).catch(() => undefined);
    expect(boundary).toHaveBeenCalledTimes(1);
  });

  it("five simultaneous boundary 401s collapse to ONE teardown", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(new Response("Unauthorized\n", { status: 401 })),
    );
    const qc = createQueryClient();
    const machine = new AuthMachine(qc, {
      getSetupStatus: () => Promise.reject(new Error("not used")),
      getAuthStatus: () => Promise.reject(new Error("not used")),
      postLogout: () => Promise.resolve({ ok: true }),
    });
    let teardowns = 0;
    const unregister = registerAuthCleanup(() => {
      teardowns += 1;
    });
    let transitions = 0;
    const unsub = machine.subscribe((s) => {
      if (s.phase === "unauthenticated") transitions += 1;
    });
    setUnauthorizedHandler(() => {
      void machine.sessionExpired();
    });
    await Promise.all(
      Array.from({ length: 5 }, () =>
        apiRequest("/api/stats", readRecord).catch(() => undefined),
      ),
    );
    await machine.sessionExpired(); // join whatever is still in flight
    expect(teardowns).toBe(1); // one teardown run
    expect(transitions).toBe(1); // one state transition
    expect(machine.getState().phase).toBe("unauthenticated");
    unregister();
    unsub();
  });
});

// ---------------------------------------------------------------------------
// AuthMachine (§2)
// ---------------------------------------------------------------------------

function machineWith(
  setup: SetupStatus | Error,
  auth: AuthStatus | Error,
  postLogout: () => Promise<{ ok: true }> = () => Promise.resolve({ ok: true }),
): AuthMachine {
  return new AuthMachine(createQueryClient(), {
    getSetupStatus: () =>
      setup instanceof Error ? Promise.reject(setup) : Promise.resolve(setup),
    getAuthStatus: () =>
      auth instanceof Error ? Promise.reject(auth) : Promise.resolve(auth),
    postLogout,
  });
}

const noTLS = { tlsFallback: false, tlsFallbackReason: "" };

describe("auth state machine", () => {
  it("boot orders setup/status FIRST: needsSetup wins", async () => {
    const m = machineWith(
      { needsSetup: true, ...noTLS },
      new Error("auth/status must not be needed"),
    );
    const s = await m.boot();
    expect(s.phase).toBe("setup_required");
  });

  it("configured + logged out → unauthenticated", async () => {
    const m = machineWith(
      { needsSetup: false, ...noTLS },
      { loggedIn: false, ...noTLS },
    );
    expect((await m.boot()).phase).toBe("unauthenticated");
  });

  it("configured + valid identity → authenticated with role", async () => {
    const m = machineWith(
      { needsSetup: false, ...noTLS },
      {
        loggedIn: true,
        user: "ops",
        role: "operator",
        bootstrap: false,
        ...noTLS,
      },
    );
    const s = await m.boot();
    expect(s.phase).toBe("authenticated");
    expect(s.user).toBe("ops");
    expect(s.role).toBe("operator");
  });

  it("configured + bootstrap shape fails CLOSED to auth_error", async () => {
    const m = machineWith(
      { needsSetup: false, ...noTLS },
      { loggedIn: true, user: "", role: "admin", bootstrap: true, ...noTLS },
    );
    expect((await m.boot()).phase).toBe("auth_error");
  });

  it("transport/decode failure → auth_error, never an assumed session", async () => {
    const m = machineWith(new Error("connection refused"), new Error("unused"));
    const s = await m.boot();
    expect(s.phase).toBe("auth_error");
    expect(s.user).toBe("");
  });

  it("TLS fallback fields carry through every phase", async () => {
    const warm = { tlsFallback: true, tlsFallbackReason: "self-sign failed" };
    const m = machineWith({ needsSetup: true, ...warm }, new Error("unused"));
    const s = await m.boot();
    expect(s.tlsFallback).toBe(true);
    expect(s.tlsFallbackReason).toBe("self-sign failed");
  });

  it("logout posts once, duplicates join, honest unconfirmed outcome", async () => {
    const postLogout = vi
      .fn<() => Promise<{ ok: true }>>()
      .mockRejectedValue(new Error("net down"));
    const m = machineWith(
      { needsSetup: false, ...noTLS },
      { loggedIn: false, ...noTLS },
      postLogout,
    );
    const [a, b] = await Promise.all([m.logout(), m.logout()]);
    expect(postLogout).toHaveBeenCalledTimes(1); // duplicates joined
    expect(a?.serverConfirmed).toBe(false); // unknown network outcome — honest
    expect(b?.serverConfirmed).toBe(false);
    expect(m.getState().phase).toBe("unauthenticated");
    expect(m.getState().logoutNote).toBe("unconfirmed");
  });

  it("confirmed logout reports confirmed", async () => {
    const m = machineWith(
      { needsSetup: false, ...noTLS },
      { loggedIn: false, ...noTLS },
    );
    const out = await m.logout();
    expect(out.serverConfirmed).toBe(true);
    expect(m.getState().logoutNote).toBe("confirmed");
  });
});

// ---------------------------------------------------------------------------
// RBAC + route intent (§14/§15)
// ---------------------------------------------------------------------------

describe("rbac ordering", () => {
  it("mirrors server doctrine viewer < operator < admin", () => {
    expect(hasRole("admin", "viewer")).toBe(true);
    expect(hasRole("admin", "admin")).toBe(true);
    expect(hasRole("operator", "viewer")).toBe(true);
    expect(hasRole("operator", "admin")).toBe(false);
    expect(hasRole("viewer", "viewer")).toBe(true);
    expect(hasRole("viewer", "operator")).toBe(false);
  });
});

describe("route intent", () => {
  it("honors known internal routes and falls back to Overview", () => {
    expect(resolveRouteIntent("/design-system", "viewer")).toBe(
      "/design-system",
    );
    expect(resolveRouteIntent("/", "viewer")).toBe("/");
    expect(resolveRouteIntent("/no/such/route", "admin")).toBe("/");
    expect(resolveRouteIntent("https://evil.example/app/", "admin")).toBe("/");
    expect(resolveRouteIntent("", "admin")).toBe("/");
  });

  it("falls back to Overview when the new role is not authorized (mechanism)", () => {
    // Synthetic table: proves the role arm without faking production routes.
    const table = [
      { path: "/", minRole: "viewer" },
      { path: "/governance", minRole: "admin" },
    ] as const;
    expect(resolveRouteIntent("/governance", "admin", table)).toBe(
      "/governance",
    );
    expect(resolveRouteIntent("/governance", "operator", table)).toBe("/");
    expect(resolveRouteIntent("/governance", "viewer", table)).toBe("/");
  });
});

// ---------------------------------------------------------------------------
// Setup credential validators (§8/§20)
// ---------------------------------------------------------------------------

describe("setup validation mirror", () => {
  it("usernames: 1–64 after trim", () => {
    expect(usernameProblem("admin")).toBeUndefined();
    expect(usernameProblem("  ")).toBeDefined();
    expect(usernameProblem("a".repeat(65))).toBeDefined();
    expect(usernameProblem(` ${"a".repeat(64)} `)).toBeUndefined();
  });

  it("passwords: length, classes, and the 72-BYTE bcrypt limit", () => {
    expect(passwordProblem("Password1")).toBeUndefined();
    expect(passwordProblem("short1A")).toBeDefined(); // < 8
    expect(passwordProblem("alllowercase1")).toBeDefined(); // no upper
    expect(passwordProblem("ALLUPPERCASE1")).toBeDefined(); // no lower
    expect(passwordProblem("NoDigitsHere")).toBeDefined(); // no digit
    expect(passwordProblem(`Aa1${"x".repeat(70)}`)).toBeDefined(); // 73 bytes — over
    expect(passwordProblem(`Aa1${"x".repeat(69)}`)).toBeUndefined(); // exactly 72 — allowed
    // Byte semantics, not characters: 24 × '€' (3 bytes) + "Aa1" = 75 bytes.
    expect(passwordProblem(`Aa1${"€".repeat(24)}`)).toBeDefined();
  });
});
