// FE-6A.2 RED matrix — Administrators MUTATION API rows, written against the
// frozen FE-6A.1 baseline 98d4a6c8 BEFORE any product change (api/admins.ts
// is GET-only by construction; every row fails at import resolution).
//
//   B1 verbs, fences (query string; the body never carries the fence),
//      bodies (create {username,password,role}; update {username, role?,
//      password?}; delete bodiless; change-password snake_case;
//      lockout clear {username}); secrets never in the URL.
//   B2 success is action-bound: create/update answer the target user with
//      revision + persisted; update/delete/change-password carry the
//      sessionsRevoked/selfAffected facts; lockout clear echoes the username
//      and a generation ≥ 1.
//   B3 endpoint-specific refusal allowlists — a code the endpoint cannot emit
//      (user_exists on PUT, last_admin on lockouts, persist_failed on
//      lockouts) is NOT a verdict; unknown codes never are; fences carry
//      their current token.
//   B4 wrong media type / transport loss ⇒ unproven, sent once.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import {
  ADMIN_REFUSAL_CONTRACT,
  adminUnproven,
  asAdminRefusal,
  changeOwnPassword,
  clearLockout,
  createAdminUser,
  deleteAdminUser,
  updateAdminUser,
} from "../api/admins";
import { decodeAuthStatus } from "../api/auth";
import { RAW, jsonResponse } from "./fe6a2-fixtures";

const PASSWORD = "NewPassw0rd-CANARY";
const CURRENT = "OldPassw0rd-CANARY";

interface Call {
  url: string;
  method: string;
  body: unknown;
  rawBody: unknown;
}
let calls: Call[];
let answer: (c: Call) => Response | Promise<Response>;
beforeEach(() => {
  calls = [];
  answer = () => jsonResponse({}, 500);
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const raw = init?.body;
      const c: Call = {
        url: String(input),
        method: init?.method ?? "GET",
        body: typeof raw === "string" ? JSON.parse(raw) : undefined,
        rawBody: raw,
      };
      calls.push(c);
      return Promise.resolve(answer(c));
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
const httpErr = (status: number, body: unknown): ApiError =>
  new ApiError("http", `HTTP ${String(status)}`, status, JSON.stringify(body));
const user = (
  username: string,
  role: string,
  gen: number,
  totp = false,
): Record<string, unknown> => ({
  username,
  role,
  totpEnabled: totp,
  securityGeneration: gen,
});

describe("B1 verbs, fences, bodies", () => {
  it("create: POST /api/auth/users?revision, body {username,password,role}", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        user: user("alice", "operator", 6),
        revision: 5,
        persisted: true,
      });
    await createAdminUser(
      { username: "alice", password: PASSWORD, role: "operator" },
      4,
    );
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("/api/auth/users?revision=4");
    expect(calls[0]?.body).toEqual({
      username: "alice",
      password: PASSWORD,
      role: "operator",
    });
    expect(calls[0]?.url).not.toContain(PASSWORD);
  });
  it("update: PUT /api/auth/users?revision, only the supplied fields", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        user: user("bob", "viewer", 7, true),
        revision: 5,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: false,
        securityGeneration: 7,
      });
    await updateAdminUser({ username: "bob", role: "viewer" }, 4);
    expect(calls[0]?.method).toBe("PUT");
    expect(calls[0]?.url).toBe("/api/auth/users?revision=4");
    expect(calls[0]?.body).toEqual({ username: "bob", role: "viewer" });
    answer = () =>
      jsonResponse({
        ok: true,
        user: user("bob", "operator", 8, true),
        revision: 6,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: false,
        securityGeneration: 8,
      });
    await updateAdminUser({ username: "bob", password: PASSWORD }, 5);
    expect(calls[1]?.body).toEqual({ username: "bob", password: PASSWORD });
    expect(calls[1]?.url).not.toContain(PASSWORD);
  });
  it("delete: DELETE /api/auth/users?username&revision, bodiless", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: true,
        username: "bob",
        revision: 6,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: false,
      });
    await deleteAdminUser("bob", 5);
    expect(calls[0]?.method).toBe("DELETE");
    expect(calls[0]?.url).toBe("/api/auth/users?username=bob&revision=5");
    expect(calls[0]?.rawBody).toBeUndefined();
  });
  it("change-password: POST /api/auth/change-password?generation, snake_case body", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        revision: 7,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: true,
        securityGeneration: 9,
      });
    await changeOwnPassword(
      { currentPassword: CURRENT, newPassword: PASSWORD },
      8,
    );
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("/api/auth/change-password?generation=8");
    expect(calls[0]?.body).toEqual({
      current_password: CURRENT,
      new_password: PASSWORD,
    });
    expect(calls[0]?.url).not.toContain(PASSWORD);
    expect(calls[0]?.url).not.toContain(CURRENT);
  });
  it("lockout clear: POST /api/auth/lockouts?generation, body {username}", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        username: "bob",
        generation: 13,
        scope: "node-local",
      });
    await clearLockout("bob", 12);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("/api/auth/lockouts?generation=12");
    expect(calls[0]?.body).toEqual({ username: "bob" });
  });
});

describe("B2 success is action-bound", () => {
  it("create binds the username and role, requires revision + persisted", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        user: user("alice", "operator", 6),
        revision: 5,
        persisted: true,
      });
    const r = await createAdminUser(
      { username: "alice", password: PASSWORD, role: "operator" },
      4,
    );
    expect(r.user.username).toBe("alice");
    expect(r.revision).toBe(5);
    for (const body of [
      {
        ok: true,
        user: user("someone", "operator", 6),
        revision: 5,
        persisted: true,
      },
      {
        ok: true,
        user: user("alice", "admin", 6),
        revision: 5,
        persisted: true,
      },
      { ok: true, user: user("alice", "operator", 6), persisted: true },
      { ok: true, user: user("alice", "operator", 6), revision: 5 },
      {
        ok: false,
        user: user("alice", "operator", 6),
        revision: 5,
        persisted: true,
      },
      {
        ok: true,
        user: { ...user("alice", "operator", 6), pass_hash: "$2a$10$x" },
        revision: 5,
        persisted: true,
      },
    ]) {
      calls = [];
      answer = () => jsonResponse(body);
      await expect(
        createAdminUser(
          { username: "alice", password: PASSWORD, role: "operator" },
          4,
        ),
      ).rejects.toBeInstanceOf(ApiError);
      expect(calls).toHaveLength(1);
    }
  });
  it("update requires the session facts and preserves the TOTP truth from the wire", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        user: user("bob", "viewer", 7, true),
        revision: 5,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: false,
        securityGeneration: 7,
      });
    const r = await updateAdminUser({ username: "bob", role: "viewer" }, 4);
    expect(r.sessionsRevoked).toBe(true);
    expect(r.selfAffected).toBe(false);
    expect(r.user.totpEnabled).toBe(true);
    expect(r.securityGeneration).toBe(7);
    answer = () =>
      jsonResponse({
        ok: true,
        user: user("bob", "viewer", 7, true),
        revision: 5,
        persisted: true,
      });
    await expect(
      updateAdminUser({ username: "bob", role: "viewer" }, 4),
    ).rejects.toBeInstanceOf(ApiError);
  });
  it("delete requires deleted:true + the same username + both session facts", async () => {
    for (const body of [
      {
        ok: true,
        deleted: true,
        username: "carol",
        revision: 6,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: false,
      },
      {
        ok: true,
        deleted: false,
        username: "bob",
        revision: 6,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: false,
      },
      {
        ok: true,
        deleted: true,
        username: "bob",
        revision: 6,
        persisted: true,
      },
    ]) {
      answer = () => jsonResponse(body);
      await expect(deleteAdminUser("bob", 5)).rejects.toBeInstanceOf(ApiError);
    }
    answer = () =>
      jsonResponse({
        ok: true,
        deleted: true,
        username: "bob",
        revision: 6,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: true,
      });
    const r = await deleteAdminUser("bob", 5);
    expect(r.selfAffected).toBe(true);
  });
  it("change-password requires all six facts; lockout clear binds the username", async () => {
    answer = () =>
      jsonResponse({
        ok: true,
        revision: 7,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: true,
      });
    await expect(
      changeOwnPassword({ currentPassword: CURRENT, newPassword: PASSWORD }, 8),
    ).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse({
        ok: true,
        username: "carol",
        generation: 13,
        scope: "node-local",
      });
    await expect(clearLockout("bob", 12)).rejects.toBeInstanceOf(ApiError);
    answer = () =>
      jsonResponse({
        ok: true,
        username: "bob",
        generation: 13,
        scope: "node-local",
      });
    expect((await clearLockout("bob", 12)).generation).toBe(13);
  });
  it("the auth status decoder exposes the caller's security generation", () => {
    const s = decodeAuthStatus({
      loggedIn: true,
      user: "admin",
      role: "admin",
      securityGeneration: 4,
      ui_tls_fallback: false,
    });
    expect(s.loggedIn ? s.securityGeneration : null).toBe(4);
  });
});

describe("B3 endpoint-specific refusal allowlists", () => {
  it("each endpoint recognises only the codes it can emit, at the contracted status", () => {
    expect(Object.keys(ADMIN_REFUSAL_CONTRACT).sort()).toEqual([
      "change_password",
      "lockouts.clear",
      "users.create",
      "users.delete",
      "users.update",
    ]);
    const stale = asAdminRefusal(
      httpErr(409, { error: RAW, code: "stale", current: { revision: 9 } }),
      "users.update",
    );
    expect(stale?.code).toBe("stale");
    expect(stale?.facts.revision).toBe(9);
    const gen = asAdminRefusal(
      httpErr(409, { error: RAW, code: "stale", current: { generation: 14 } }),
      "lockouts.clear",
    );
    expect(gen?.facts.generation).toBe(14);
    expect(
      asAdminRefusal(
        httpErr(409, { error: RAW, code: "last_admin" }),
        "users.update",
      )?.code,
    ).toBe("last_admin");
    expect(
      asAdminRefusal(
        httpErr(409, { error: RAW, code: "last_admin" }),
        "users.delete",
      )?.code,
    ).toBe("last_admin");
    expect(
      asAdminRefusal(
        httpErr(409, { error: RAW, code: "user_exists" }),
        "users.create",
      )?.code,
    ).toBe("user_exists");
    expect(
      asAdminRefusal(
        httpErr(403, { error: RAW, code: "invalid_credentials" }),
        "change_password",
      )?.code,
    ).toBe("invalid_credentials");
    expect(
      asAdminRefusal(
        httpErr(503, { error: RAW, code: "persistence_not_configured" }),
        "users.create",
      )?.code,
    ).toBe("persistence_not_configured");
    expect(
      asAdminRefusal(
        httpErr(404, { error: RAW, code: "not_found" }),
        "lockouts.clear",
      )?.code,
    ).toBe("not_found");
    // codes the endpoint cannot emit are not verdicts
    expect(
      asAdminRefusal(
        httpErr(409, { error: RAW, code: "user_exists" }),
        "users.update",
      ),
    ).toBeNull();
    expect(
      asAdminRefusal(
        httpErr(409, { error: RAW, code: "last_admin" }),
        "lockouts.clear",
      ),
    ).toBeNull();
    expect(
      asAdminRefusal(
        httpErr(500, { error: RAW, code: "persist_failed" }),
        "lockouts.clear",
      ),
    ).toBeNull();
    expect(
      asAdminRefusal(
        httpErr(403, { error: RAW, code: "invalid_credentials" }),
        "users.update",
      ),
    ).toBeNull();
    // unknown code / wrong status / missing fence fact
    expect(
      asAdminRefusal(
        httpErr(409, { error: RAW, code: "made_up" }),
        "users.create",
      ),
    ).toBeNull();
    expect(
      asAdminRefusal(
        httpErr(500, { error: RAW, code: "stale", current: { revision: 9 } }),
        "users.update",
      ),
    ).toBeNull();
    expect(
      asAdminRefusal(
        httpErr(428, { error: RAW, code: "precondition_required" }),
        "users.update",
      ),
    ).toBeNull();
    expect(adminUnproven(httpErr(409, { error: RAW, code: "made_up" }))).toBe(
      true,
    );
    expect(
      adminUnproven(
        httpErr(409, { error: RAW, code: "stale", current: { revision: 9 } }),
      ),
    ).toBe(false);
    expect(adminUnproven(new ApiError("http", "x", 403, "Forbidden"))).toBe(
      false,
    );
  });
});

describe("B4 media type and transport", () => {
  it("text/plain 200 is unproven; a network death is unproven; nothing retries", async () => {
    answer = () =>
      new Response("ok", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    const e1 = await deleteAdminUser("bob", 5).catch((e: unknown) => e);
    expect(adminUnproven(e1)).toBe(true);
    expect(calls).toHaveLength(1);
    calls = [];
    answer = () => Promise.reject(new TypeError("Failed to fetch"));
    const e2 = await createAdminUser(
      { username: "alice", password: PASSWORD, role: "viewer" },
      4,
    ).catch((e: unknown) => e);
    expect(adminUnproven(e2)).toBe(true);
    expect(calls).toHaveLength(1);
  });
});
