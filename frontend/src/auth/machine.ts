// FE-3 authoritative auth state machine (§2 + identity-continuity
// hardening). ONE explicit machine decides what the application may render;
// nothing is derived from route location, UI elements, remembered browser
// state, or a login/setup response alone — the SERVER is authoritative, and
// every transition into `authenticated` happens through a FRESH
// /api/setup/status → /api/auth/status read.
//
//   booting
//     └─ GET /api/setup/status
//          ├─ needsSetup=true  → setup_required
//          └─ needsSetup=false
//               └─ GET /api/auth/status
//                    ├─ loggedIn=false                  → unauthenticated
//                    ├─ loggedIn=true + valid identity  → authenticated
//                    ├─ loggedIn=true + bootstrap shape → auth_error (the
//                    │    pre-setup bootstrap identity while CONFIGURED is
//                    │    an impossible payload — fail closed, §3)
//                    └─ malformed / transport error     → auth_error
//
// IDENTITY CONTINUITY: the session cookie is shared same-origin across tabs,
// so the identity behind it can be REPLACED underneath a running tab (sign
// out + sign in as someone else elsewhere). Every transition that replaces
// or ends an AUTHENTICATED identity — session-expiry 401, revalidation
// discovering loggedOut, a DIFFERENT user, a DIFFERENT role, or an invalid
// identity payload — runs the FULL auth-boundary teardown FIRST, through ONE
// collapsed in-flight boundary (`runBoundaryTransition`): a racing boundary
// 401 and an identity-change revalidation can never produce two teardown
// runs or two final transitions. Only a same-user same-role confirmation
// skips the teardown.
//
// Identity/session data lives ONLY here (plain memory) — never in the
// TanStack Query cache, never in browser storage. Auth reads are direct
// apiRequest calls; `revalidateAuthenticatedSession` (wired to v2 route
// transitions and window focus/visibility restoration) is the
// identity-continuity mechanism — it REPLACED the earlier /api/stats
// protected-endpoint probe, which only proved "this cookie can reach a
// viewer-readable endpoint", not "the cookie still belongs to the identity
// this tab renders".
import type { QueryClient } from "@tanstack/react-query";
import { ApiError } from "../api/client";
import { getAuthStatus, getSetupStatus, postLogout } from "../api/auth";
import type { AuthStatus, Role, SetupStatus } from "../api/auth";
import { runAuthTeardown } from "./teardown";

export type AuthPhase =
  | "booting"
  | "setup_required"
  | "unauthenticated"
  | "authenticated"
  | "auth_error";

export interface AuthState {
  phase: AuthPhase;
  /** authenticated identity ("" outside `authenticated`) */
  user: string;
  role: Role | null;
  tlsFallback: boolean;
  tlsFallbackReason: string;
  /** bounded, non-sensitive detail for the auth_error retry screen */
  errorDetail: string;
  /** honest logout outcome (§12): null outside the post-logout screen */
  logoutNote: "confirmed" | "unconfirmed" | null;
  /** memory-only boundary reason (§8): the session the app believed in is
   * no longer valid (expiry, revocation, deletion, replacement — the 401 or
   * loggedOut answer does not say which, so neither do we). Never
   * persisted; cleared on successful authentication. */
  boundaryNote: "session_ended" | null;
}

export interface LogoutOutcome {
  serverConfirmed: boolean;
}

interface AuthAPI {
  getSetupStatus: () => Promise<SetupStatus>;
  getAuthStatus: () => Promise<AuthStatus>;
  postLogout: () => Promise<{ ok: true }>;
}

const initialState: AuthState = {
  phase: "booting",
  user: "",
  role: null,
  tlsFallback: false,
  tlsFallbackReason: "",
  errorDetail: "",
  logoutNote: null,
  boundaryNote: null,
};

export class AuthMachine {
  private state: AuthState = initialState;
  private readonly listeners = new Set<(s: AuthState) => void>();
  private readonly qc: QueryClient;
  private readonly api: AuthAPI;
  /** THE collapsed authentication boundary: every teardown-carrying
   * transition (boundary 401, revalidation-discovered logout / identity
   * change / invalid identity, refresh-discovered replacement) runs
   * through here. Concurrent boundaries join the first — one teardown,
   * one final transition; the joiner's own finalize is dropped (its next
   * trigger re-observes the settled state). */
  private boundaryInFlight: Promise<void> | null = null;
  /** §12: duplicate logout submissions join the first. */
  private logoutInFlight: Promise<LogoutOutcome> | null = null;
  /** concurrent revalidation triggers join one status read + boundary. */
  private revalidateInFlight: Promise<AuthState> | null = null;

  constructor(qc: QueryClient, api?: AuthAPI) {
    this.qc = qc;
    this.api = api ?? { getSetupStatus, getAuthStatus, postLogout };
  }

  getState(): AuthState {
    return this.state;
  }

  subscribe(fn: (s: AuthState) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private set(partial: Partial<AuthState>): void {
    this.state = { ...this.state, ...partial };
    for (const fn of [...this.listeners]) fn(this.state);
  }

  /** The single collapsed boundary: full teardown FIRST, then exactly one
   * final transition. The query cache is cleared BEFORE listeners can
   * observe the finalized state. */
  private runBoundaryTransition(finalize: () => void): Promise<void> {
    if (this.boundaryInFlight !== null) return this.boundaryInFlight;
    this.boundaryInFlight = (async () => {
      try {
        await runAuthTeardown(this.qc);
      } finally {
        try {
          finalize();
        } finally {
          this.boundaryInFlight = null;
        }
      }
    })();
    return this.boundaryInFlight;
  }

  /** Initial boot: purposeful booting phase, then the authoritative reads. */
  async boot(): Promise<AuthState> {
    this.set({ ...initialState });
    return this.refresh();
  }

  /** Controlled retry from auth_error. */
  async retry(): Promise<AuthState> {
    return this.boot();
  }

  /** Adopt a fresh authenticated status. If a DIFFERENT authenticated
   * identity/role is currently rendered, the full boundary teardown runs
   * FIRST — the old identity's cache and state never survive into the new
   * one's render. Same identity ⇒ plain confirmation (no teardown). */
  private async adoptAuthenticated(
    auth: AuthStatus & { loggedIn: true },
  ): Promise<void> {
    const finalize = (): void => {
      this.set({
        phase: "authenticated",
        user: auth.user,
        role: auth.role,
        tlsFallback: auth.tlsFallback,
        tlsFallbackReason: auth.tlsFallbackReason,
        errorDetail: "",
        logoutNote: null,
        boundaryNote: null, // cleared on successful authentication (§8)
      });
    };
    const prev = this.state;
    const replaced =
      prev.phase === "authenticated" &&
      (prev.user !== auth.user || prev.role !== auth.role);
    if (replaced) {
      await this.runBoundaryTransition(finalize);
    } else {
      finalize();
    }
  }

  /** Leave an authenticated identity for a non-authenticated phase: the
   * teardown-carrying boundary when an identity was rendered, a plain
   * transition otherwise. */
  private async leaveAuthenticated(finalize: () => void): Promise<void> {
    if (this.state.phase === "authenticated") {
      await this.runBoundaryTransition(finalize);
    } else {
      finalize();
    }
  }

  /** The single authoritative resolution path (§2): fresh setup/status,
   * then fresh auth/status. Used by boot, by the post-login and post-setup
   * confirmations, and by the auth_error retry — a login or setup response
   * is never trusted on its own. Does not flash `booting` (callers that
   * want the loading shell use boot()). */
  async refresh(): Promise<AuthState> {
    try {
      const setup = await this.api.getSetupStatus();
      if (setup.needsSetup) {
        await this.leaveAuthenticated(() => {
          this.set({
            phase: "setup_required",
            user: "",
            role: null,
            tlsFallback: setup.tlsFallback,
            tlsFallbackReason: setup.tlsFallbackReason,
            errorDetail: "",
          });
        });
        return this.state;
      }
      const auth = await this.api.getAuthStatus();
      if (!auth.loggedIn) {
        await this.leaveAuthenticated(() => {
          this.set({
            phase: "unauthenticated",
            user: "",
            role: null,
            tlsFallback: auth.tlsFallback,
            tlsFallbackReason: auth.tlsFallbackReason,
            errorDetail: "",
          });
        });
        return this.state;
      }
      if (auth.bootstrap) {
        // Configured appliance reporting the pre-setup bootstrap identity:
        // an impossible payload. Fail closed (§3) — never render an
        // authenticated surface for an empty identity.
        await this.leaveAuthenticated(() => {
          this.set({
            phase: "auth_error",
            user: "",
            role: null,
            errorDetail: "server reported an invalid session identity",
          });
        });
        return this.state;
      }
      await this.adoptAuthenticated(auth);
      return this.state;
    } catch (err) {
      await this.leaveAuthenticated(() => {
        this.set({
          phase: "auth_error",
          user: "",
          role: null,
          errorDetail:
            err instanceof Error
              ? err.message.slice(0, 300)
              : "authentication state unavailable",
        });
      });
      return this.state;
    }
  }

  /** Identity-continuity revalidation. A FRESH /api/auth/status read (no
   * cache, no persistence) compared against the identity this tab renders:
   *   A. server loggedOut         → boundary teardown → unauthenticated
   *                                 (+ session_ended reason)
   *   B. same user + same role    → NO teardown; TLS fields may refresh
   *   C. different user           → boundary teardown FIRST, then the new
   *                                 identity renders
   *   D. different role           → boundary teardown FIRST, then the new
   *                                 role-derived UI renders
   *   E. bootstrap/invalid shape  → boundary teardown → auth_error
   *   F. transport failure        → preserve current state: a transient
   *                                 inability to revalidate is NOT evidence
   *                                 the identity changed
   * Concurrent triggers join one in-flight revalidation. */
  revalidateAuthenticatedSession(): Promise<AuthState> {
    if (this.state.phase !== "authenticated")
      return Promise.resolve(this.state);
    if (this.revalidateInFlight !== null) return this.revalidateInFlight;
    this.revalidateInFlight = (async () => {
      try {
        let auth: AuthStatus;
        try {
          auth = await this.api.getAuthStatus();
        } catch (err) {
          if (
            err instanceof ApiError &&
            (err.kind === "decode" || err.kind === "contenttype")
          ) {
            // E: the server ANSWERED with an invalid identity payload —
            // fail closed, never keep rendering the old identity on it.
            await this.runBoundaryTransition(() => {
              this.set({
                phase: "auth_error",
                user: "",
                role: null,
                errorDetail: "server returned an invalid session identity",
              });
            });
          }
          // F: network/timeout/HTTP faults are transport, not evidence.
          return this.state;
        }
        if (this.state.phase !== "authenticated") return this.state; // a boundary already landed
        if (!auth.loggedIn) {
          // A: the session this tab believed in is gone.
          await this.runBoundaryTransition(() => {
            this.set({
              phase: "unauthenticated",
              user: "",
              role: null,
              tlsFallback: auth.tlsFallback,
              tlsFallbackReason: auth.tlsFallbackReason,
              errorDetail: "",
              logoutNote: null,
              boundaryNote: "session_ended",
            });
          });
          return this.state;
        }
        if (auth.bootstrap) {
          // E: impossible payload while configured.
          await this.runBoundaryTransition(() => {
            this.set({
              phase: "auth_error",
              user: "",
              role: null,
              errorDetail: "server reported an invalid session identity",
            });
          });
          return this.state;
        }
        if (this.state.user === auth.user && this.state.role === auth.role) {
          // B: confirmed continuity — no teardown; TLS posture may refresh.
          this.set({
            tlsFallback: auth.tlsFallback,
            tlsFallbackReason: auth.tlsFallbackReason,
          });
          return this.state;
        }
        // C/D: the cookie now belongs to a different user or role.
        await this.adoptAuthenticated(auth);
        return this.state;
      } finally {
        this.revalidateInFlight = null;
      }
    })();
    return this.revalidateInFlight;
  }

  /** §5: idempotent authentication-boundary transition for boundary 401s.
   * Joins the SAME collapsed boundary as identity-change revalidation —
   * exactly one teardown, one transition, no logout POST (the server
   * already refused the session). */
  sessionExpired(): Promise<void> {
    return this.runBoundaryTransition(() => {
      this.set({
        phase: "unauthenticated",
        user: "",
        role: null,
        errorDetail: "",
        logoutNote: null,
        boundaryNote: "session_ended",
      });
    });
  }

  /** §12 explicit logout: one POST (duplicates join), then the FULL
   * teardown, then an honest outcome — an unknown network result never
   * claims the server token was revoked. Local sensitive state is cleared
   * regardless. */
  logout(): Promise<LogoutOutcome> {
    if (this.logoutInFlight !== null) return this.logoutInFlight;
    this.logoutInFlight = (async () => {
      let serverConfirmed = false;
      try {
        await this.api.postLogout();
        serverConfirmed = true;
      } catch {
        // unknown outcome — serverConfirmed stays false, represented honestly
      }
      await runAuthTeardown(this.qc);
      if (serverConfirmed) {
        // Confirm via a fresh status read where practical (§12).
        try {
          const auth = await this.api.getAuthStatus();
          if (auth.loggedIn && !auth.bootstrap) serverConfirmed = false;
        } catch {
          // status unreachable: keep the POST's own success as the signal
        }
      }
      this.set({
        phase: "unauthenticated",
        user: "",
        role: null,
        errorDetail: "",
        logoutNote: serverConfirmed ? "confirmed" : "unconfirmed",
        boundaryNote: null, // a deliberate sign-out is not a "session ended"
      });
      this.logoutInFlight = null;
      return { serverConfirmed };
    })();
    return this.logoutInFlight;
  }
}
