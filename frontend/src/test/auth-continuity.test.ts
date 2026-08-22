// FE-3 identity/role-continuity proofs (§6 A–G): every transition that ends
// or REPLACES an authenticated identity runs the FULL boundary teardown
// exactly once, with the query cache cleared BEFORE listeners first observe
// the new identity. Behavioral — a sentinel session value is seeded into the
// QueryClient and its absence is captured at the exact emission moment.
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiRequest, setUnauthorizedHandler } from "../api/client";
import type { AuthStatus } from "../api/auth";
import { readRecord } from "../api/decode";
import { createQueryClient } from "../api/query";
import { AuthMachine } from "../auth/machine";
import { registerAuthCleanup } from "../auth/teardown";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  setUnauthorizedHandler(null);
});

const noTLS = { tlsFallback: false, tlsFallbackReason: "" };

const adminSession: AuthStatus = {
  loggedIn: true,
  user: "admin",
  role: "admin",
  bootstrap: false,
  ...noTLS,
};

interface Fixture {
  machine: AuthMachine;
  qc: ReturnType<typeof createQueryClient>;
  session: { current: AuthStatus | Error };
  statusCalls: () => number;
  teardowns: () => number;
  unregister: () => void;
}

function authenticatedFixture(): Promise<Fixture> {
  const qc = createQueryClient();
  const session: Fixture["session"] = { current: adminSession };
  let calls = 0;
  const machine = new AuthMachine(qc, {
    getSetupStatus: () => Promise.resolve({ needsSetup: false, ...noTLS }),
    getAuthStatus: () => {
      calls += 1;
      return session.current instanceof Error
        ? Promise.reject(session.current)
        : Promise.resolve(session.current);
    },
    postLogout: () => Promise.resolve({ ok: true }),
  });
  let teardowns = 0;
  const unregister = registerAuthCleanup(() => {
    teardowns += 1;
  });
  return machine.boot().then((s) => {
    if (s.phase !== "authenticated") throw new Error("fixture boot failed");
    return {
      machine,
      qc,
      session,
      statusCalls: () => calls,
      teardowns: () => teardowns,
      unregister,
    };
  });
}

const SENTINEL_KEY = ["session", "sentinel"];

describe("identity/role continuity (§6)", () => {
  it("A: different user revalidates → ONE teardown; cache cleared BEFORE the new identity is observed", async () => {
    const fx = await authenticatedFixture();
    fx.qc.setQueryData(SENTINEL_KEY, "admin-session-data");
    let sentinelAtFirstViewerEmission: unknown = "never-observed";
    const unsub = fx.machine.subscribe((s) => {
      if (
        s.phase === "authenticated" &&
        s.user === "view-user" &&
        sentinelAtFirstViewerEmission === "never-observed"
      ) {
        sentinelAtFirstViewerEmission = fx.qc.getQueryData(SENTINEL_KEY);
      }
    });
    fx.session.current = {
      loggedIn: true,
      user: "view-user",
      role: "viewer",
      bootstrap: false,
      ...noTLS,
    };
    await fx.machine.revalidateAuthenticatedSession();
    expect(fx.teardowns()).toBe(1); // exactly one full boundary teardown
    expect(sentinelAtFirstViewerEmission).toBeUndefined(); // cleared FIRST
    const s = fx.machine.getState();
    expect(s.phase).toBe("authenticated");
    expect(s.user).toBe("view-user");
    expect(s.role).toBe("viewer");
    unsub();
    fx.unregister();
  });

  it("B: same user, changed role → ONE teardown before the new role renders", async () => {
    const fx = await authenticatedFixture();
    fx.qc.setQueryData(SENTINEL_KEY, "admin-role-data");
    let sentinelAtFirstViewerRole: unknown = "never-observed";
    const unsub = fx.machine.subscribe((s) => {
      if (
        s.phase === "authenticated" &&
        s.role === "viewer" &&
        sentinelAtFirstViewerRole === "never-observed"
      ) {
        sentinelAtFirstViewerRole = fx.qc.getQueryData(SENTINEL_KEY);
      }
    });
    fx.session.current = {
      loggedIn: true,
      user: "admin",
      role: "viewer",
      bootstrap: false,
      ...noTLS,
    };
    await fx.machine.revalidateAuthenticatedSession();
    expect(fx.teardowns()).toBe(1);
    expect(sentinelAtFirstViewerRole).toBeUndefined();
    expect(fx.machine.getState().role).toBe("viewer");
    expect(fx.machine.getState().user).toBe("admin");
    unsub();
    fx.unregister();
  });

  it("C: same user + same role → NO teardown; TLS fields may refresh", async () => {
    const fx = await authenticatedFixture();
    fx.qc.setQueryData(SENTINEL_KEY, "still-here");
    fx.session.current = {
      ...adminSession,
      tlsFallback: true,
      tlsFallbackReason: "self-sign failed",
    };
    await fx.machine.revalidateAuthenticatedSession();
    expect(fx.teardowns()).toBe(0);
    expect(fx.qc.getQueryData(SENTINEL_KEY)).toBe("still-here");
    const s = fx.machine.getState();
    expect(s.phase).toBe("authenticated");
    expect(s.user).toBe("admin");
    expect(s.tlsFallback).toBe(true);
    fx.unregister();
  });

  it("D: server loggedOut → teardown → unauthenticated with the session-ended reason", async () => {
    const fx = await authenticatedFixture();
    fx.qc.setQueryData(SENTINEL_KEY, "gone-soon");
    fx.session.current = { loggedIn: false, ...noTLS };
    await fx.machine.revalidateAuthenticatedSession();
    expect(fx.teardowns()).toBe(1);
    expect(fx.qc.getQueryData(SENTINEL_KEY)).toBeUndefined();
    const s = fx.machine.getState();
    expect(s.phase).toBe("unauthenticated");
    expect(s.boundaryNote).toBe("session_ended");
    fx.unregister();
  });

  it("E: bootstrap identity while previously authenticated → teardown → auth_error", async () => {
    const fx = await authenticatedFixture();
    fx.session.current = {
      loggedIn: true,
      user: "",
      role: "admin",
      bootstrap: true,
      ...noTLS,
    };
    await fx.machine.revalidateAuthenticatedSession();
    expect(fx.teardowns()).toBe(1);
    expect(fx.machine.getState().phase).toBe("auth_error");
    fx.unregister();
  });

  it("E2: malformed identity payload (decode failure) fails closed with teardown", async () => {
    const fx = await authenticatedFixture();
    fx.session.current = new ApiError(
      "decode",
      "$.role: expected one of admin|operator|viewer",
    );
    await fx.machine.revalidateAuthenticatedSession();
    expect(fx.teardowns()).toBe(1);
    expect(fx.machine.getState().phase).toBe("auth_error");
    fx.unregister();
  });

  it("F: transport failure preserves the current identity — no teardown, no fake state", async () => {
    const fx = await authenticatedFixture();
    fx.qc.setQueryData(SENTINEL_KEY, "survives-transport-blip");
    for (const kind of ["network", "timeout"] as const) {
      fx.session.current = new ApiError(kind, "unreachable");
      await fx.machine.revalidateAuthenticatedSession();
    }
    fx.session.current = new ApiError("http", "HTTP 503", 503, "busy");
    await fx.machine.revalidateAuthenticatedSession();
    expect(fx.teardowns()).toBe(0);
    expect(fx.qc.getQueryData(SENTINEL_KEY)).toBe("survives-transport-blip");
    const s = fx.machine.getState();
    expect(s.phase).toBe("authenticated");
    expect(s.user).toBe("admin"); // identity never replaced by guessed state
    fx.unregister();
  });

  it("F2: five concurrent revalidations of one identity change → ONE read, ONE teardown, ONE transition", async () => {
    const fx = await authenticatedFixture();
    const callsBefore = fx.statusCalls();
    let viewerEmissions = 0;
    const unsub = fx.machine.subscribe((s) => {
      if (s.phase === "authenticated" && s.user === "view-user")
        viewerEmissions += 1;
    });
    fx.session.current = {
      loggedIn: true,
      user: "view-user",
      role: "viewer",
      bootstrap: false,
      ...noTLS,
    };
    await Promise.all(
      Array.from({ length: 5 }, () =>
        fx.machine.revalidateAuthenticatedSession(),
      ),
    );
    expect(fx.statusCalls() - callsBefore).toBe(1); // joined, no request storm
    expect(fx.teardowns()).toBe(1);
    expect(viewerEmissions).toBe(1);
    unsub();
    fx.unregister();
  });

  it("G: racing boundary 401 + identity-change revalidation → ONE teardown", async () => {
    const fx = await authenticatedFixture();
    // The revalidation discovers a DIFFERENT identity while boundary 401s
    // fire concurrently: the collapsed boundary admits exactly one teardown
    // and one final transition (whichever transition starts first wins; the
    // joiner's finalize is dropped).
    fx.session.current = {
      loggedIn: true,
      user: "view-user",
      role: "viewer",
      bootstrap: false,
      ...noTLS,
    };
    await Promise.all([
      fx.machine.revalidateAuthenticatedSession(),
      fx.machine.sessionExpired(),
      fx.machine.sessionExpired(),
    ]);
    expect(fx.teardowns()).toBe(1); // one authentication boundary, total
    const phase = fx.machine.getState().phase;
    expect(["unauthenticated", "authenticated"]).toContain(phase);
    fx.unregister();
  });

  it("refresh() itself never swaps an authenticated identity without the boundary", async () => {
    const fx = await authenticatedFixture();
    fx.qc.setQueryData(SENTINEL_KEY, "pre-swap");
    let sentinelAtSwap: unknown = "never-observed";
    const unsub = fx.machine.subscribe((s) => {
      if (
        s.phase === "authenticated" &&
        s.user === "op-user" &&
        sentinelAtSwap === "never-observed"
      ) {
        sentinelAtSwap = fx.qc.getQueryData(SENTINEL_KEY);
      }
    });
    fx.session.current = {
      loggedIn: true,
      user: "op-user",
      role: "operator",
      bootstrap: false,
      ...noTLS,
    };
    await fx.machine.refresh();
    expect(fx.teardowns()).toBe(1);
    expect(sentinelAtSwap).toBeUndefined();
    expect(fx.machine.getState().user).toBe("op-user");
    unsub();
    fx.unregister();
  });

  it("boundary 401s reported through the client join the same collapsed boundary", async () => {
    const fx = await authenticatedFixture();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(new Response("Unauthorized\n", { status: 401 })),
    );
    setUnauthorizedHandler(() => {
      void fx.machine.sessionExpired();
    });
    fx.session.current = {
      loggedIn: true,
      user: "view-user",
      role: "viewer",
      bootstrap: false,
      ...noTLS,
    };
    await Promise.all([
      apiRequest("/api/stats", readRecord).catch(() => undefined),
      apiRequest("/api/stats", readRecord).catch(() => undefined),
      fx.machine.revalidateAuthenticatedSession(),
    ]);
    expect(fx.teardowns()).toBe(1);
    fx.unregister();
  });
});
