// FE-3 boundary-unification proofs (§2 A–D + §3): explicit logout joins the
// SAME collapsed boundary as sessionExpired and identity replacement, the
// client teardown runs exactly once per authenticated episode, and the
// user-initiated logout is authoritative about the final UX. A deliberately
// NON-idempotent cleanup owner (throws on a second run) stands in for the
// FE-4 SSE/timer/Blob owners.
import { afterEach, describe, expect, it } from "vitest";
import type { AuthStatus } from "../api/auth";
import { createQueryClient } from "../api/query";
import { AuthMachine } from "../auth/machine";
import { registerAuthCleanup } from "../auth/teardown";

const noTLS = { tlsFallback: false, tlsFallbackReason: "" };

const adminSession: AuthStatus = {
  loggedIn: true,
  user: "admin",
  role: "admin",
  bootstrap: false,
  ...noTLS,
};

const loggedOut: AuthStatus = { loggedIn: false, ...noTLS };

/** drain microtasks so a racing chain reaches its boundary join before the
 * gate is released — keeps the race shape deterministic. */
const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

interface Fixture {
  machine: AuthMachine;
  session: { current: AuthStatus };
  logoutPosts: () => number;
  runs: () => number;
  /** holds the boundary open inside the teardown until released */
  release: () => void;
  unregister: () => void;
}

let cleanups: Array<() => void> = [];
afterEach(() => {
  for (const fn of cleanups) fn();
  cleanups = [];
});

// An authenticated machine whose postLogout behaves like the real server
// (revokes: subsequent status reads report loggedOut) and whose FIRST
// registered cleanup owner is NON-idempotent and gates the boundary.
async function fixture(): Promise<Fixture> {
  const session: Fixture["session"] = { current: adminSession };
  let posts = 0;
  const machine = new AuthMachine(createQueryClient(), {
    getSetupStatus: () => Promise.resolve({ needsSetup: false, ...noTLS }),
    getAuthStatus: () => Promise.resolve(session.current),
    postLogout: () => {
      posts += 1;
      session.current = loggedOut; // server revokes the shared session
      return Promise.resolve({ ok: true });
    },
  });
  let runs = 0;
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const unregister = registerAuthCleanup(() => {
    runs += 1;
    if (runs > 1) {
      throw new Error(
        "cleanup owner executed twice — owners are NOT idempotent",
      );
    }
    return gate; // the boundary stays open until the test releases it
  });
  cleanups.push(unregister);
  const s = await machine.boot();
  if (s.phase !== "authenticated") throw new Error("fixture boot failed");
  return {
    machine,
    session,
    logoutPosts: () => posts,
    runs: () => runs,
    release,
    unregister,
  };
}

describe("logout-boundary unification (§2)", () => {
  it("A: logout + same-identity revalidation → one POST, one teardown, deliberate-logout UX", async () => {
    const fx = await fixture();
    // Revalidation starts FIRST and confirms the same identity (no teardown
    // from it); logout races in behind it.
    const reval = fx.machine.revalidateAuthenticatedSession();
    const out = fx.machine.logout();
    await tick(); // logout reaches its boundary join before the gate opens
    fx.release();
    const [, logout] = await Promise.all([reval, out]);
    expect(fx.logoutPosts()).toBe(1);
    expect(fx.runs()).toBe(1); // exactly one teardown
    expect(logout.serverConfirmed).toBe(true);
    const s = fx.machine.getState();
    expect(s.phase).toBe("unauthenticated");
    expect(s.logoutNote).toBe("confirmed"); // deliberate-logout UX
    expect(s.boundaryNote).toBeNull(); // never "Management session ended"
  });

  it("B: logout + revalidation discovering loggedOut → one teardown, logout UX wins", async () => {
    const fx = await fixture();
    // The server session is already gone (revoked elsewhere): revalidation
    // discovers loggedOut and starts the boundary (held open by the gate);
    // the explicit logout joins it authoritatively.
    fx.session.current = loggedOut;
    const reval = fx.machine.revalidateAuthenticatedSession();
    const out = fx.machine.logout();
    await tick(); // logout reaches its boundary join before the gate opens
    fx.release();
    await Promise.all([reval, out]);
    expect(fx.runs()).toBe(1); // one teardown total
    expect(fx.logoutPosts()).toBe(1);
    const s = fx.machine.getState();
    expect(s.phase).toBe("unauthenticated");
    expect(s.logoutNote).not.toBeNull(); // the deliberate logout finalized
    expect(s.boundaryNote).toBeNull(); // session-ended did NOT win the race
  });

  it("C: logout + identity-replacement revalidation → one teardown, explicit logout wins", async () => {
    const fx = await fixture();
    // The cookie was replaced by a viewer elsewhere; tab-A revalidation
    // starts adopting it (boundary held open) while the user clicks
    // Sign out. The deliberate logout must win the final UX.
    fx.session.current = {
      loggedIn: true,
      user: "view-user",
      role: "viewer",
      bootstrap: false,
      ...noTLS,
    };
    const reval = fx.machine.revalidateAuthenticatedSession();
    const out = fx.machine.logout();
    await tick(); // logout reaches its boundary join before the gate opens
    fx.release();
    await Promise.all([reval, out]);
    expect(fx.runs()).toBe(1); // one teardown total
    const s = fx.machine.getState();
    expect(s.phase).toBe("unauthenticated"); // NOT the adopted viewer shell
    expect(s.user).toBe("");
    expect(s.logoutNote).not.toBeNull();
    expect(s.boundaryNote).toBeNull();
  });

  it("D: logout + boundary 401 → one teardown, no transition storm, logout UX final", async () => {
    const fx = await fixture();
    let unauthenticatedEmissions = 0;
    const unsub = fx.machine.subscribe((s) => {
      if (s.phase === "unauthenticated") unauthenticatedEmissions += 1;
    });
    cleanups.push(unsub);
    // A boundary 401 starts the expiry boundary (held open); the user's
    // Sign out races in.
    const expiry = fx.machine.sessionExpired();
    const out = fx.machine.logout();
    await tick(); // logout reaches its boundary join before the gate opens
    fx.release();
    await Promise.all([expiry, out]);
    expect(fx.runs()).toBe(1); // one teardown total
    expect(unauthenticatedEmissions).toBe(1); // one final transition, no storm
    const s = fx.machine.getState();
    expect(s.logoutNote).toBe("confirmed"); // deliberate logout authoritative
    expect(s.boundaryNote).toBeNull(); // "session ended" never replaced it
  });

  it("logout AFTER a completed expiry boundary transitions without re-running owners", async () => {
    const fx = await fixture();
    fx.release(); // boundary gate open from the start
    await fx.machine.sessionExpired(); // episode torn down, session-ended UX
    expect(fx.runs()).toBe(1);
    expect(fx.machine.getState().boundaryNote).toBe("session_ended");
    // The user still clicks Sign out: one POST, NO second owner execution,
    // and the deliberate-logout UX replaces the session-ended reason.
    const out = await fx.machine.logout();
    expect(fx.logoutPosts()).toBe(1);
    expect(fx.runs()).toBe(1); // the non-idempotent owner did NOT run again
    expect(out.serverConfirmed).toBe(true);
    const s = fx.machine.getState();
    expect(s.logoutNote).toBe("confirmed");
    expect(s.boundaryNote).toBeNull();
  });

  it("a NEW authenticated episode re-arms exactly-once teardown", async () => {
    const fx = await fixture();
    fx.release();
    await fx.machine.logout(); // episode 1 torn down (runs=1)
    expect(fx.runs()).toBe(1);
    // Sign back in (fresh authoritative read) → new episode.
    fx.session.current = adminSession;
    const s = await fx.machine.refresh();
    expect(s.phase).toBe("authenticated");
    // Episode 2 expiry: the owner runs exactly once more — not zero (the
    // new episode's resources must be cleaned), not twice.
    await fx.machine.sessionExpired();
    expect(fx.runs()).toBe(2);
  });
});
