// FE-3 authoritative auth state machine (§2). ONE explicit machine decides
// what the application may render; nothing is derived from route location,
// UI elements, remembered browser state, or a login/setup response alone —
// the SERVER is authoritative, and every transition into `authenticated`
// happens through a FRESH /api/setup/status → /api/auth/status read.
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
// Identity/session data lives ONLY here (plain memory) — never in the
// TanStack Query cache, never in browser storage. Auth reads are direct
// apiRequest calls, so there is no cached auth entry to configure gcTime
// for; the one session-scoped QUERY (the /api/stats probe) declares
// gcTime: 0 at its call site (§7).
import type { QueryClient } from "@tanstack/react-query";
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
};

export class AuthMachine {
  private state: AuthState = initialState;
  private readonly listeners = new Set<(s: AuthState) => void>();
  private readonly qc: QueryClient;
  private readonly api: AuthAPI;
  /** §5: the single in-flight boundary transition every concurrent
   * boundary-401 joins — teardown runs at most once per expiry. */
  private teardownInFlight: Promise<void> | null = null;
  /** §12: duplicate logout submissions join the first. */
  private logoutInFlight: Promise<LogoutOutcome> | null = null;

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

  /** Initial boot: purposeful booting phase, then the authoritative reads. */
  async boot(): Promise<AuthState> {
    this.set({ ...initialState });
    return this.refresh();
  }

  /** Controlled retry from auth_error. */
  async retry(): Promise<AuthState> {
    return this.boot();
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
        this.set({
          phase: "setup_required",
          user: "",
          role: null,
          tlsFallback: setup.tlsFallback,
          tlsFallbackReason: setup.tlsFallbackReason,
          errorDetail: "",
        });
        return this.state;
      }
      const auth = await this.api.getAuthStatus();
      if (!auth.loggedIn) {
        this.set({
          phase: "unauthenticated",
          user: "",
          role: null,
          tlsFallback: auth.tlsFallback,
          tlsFallbackReason: auth.tlsFallbackReason,
          errorDetail: "",
        });
        return this.state;
      }
      if (auth.bootstrap) {
        // Configured appliance reporting the pre-setup bootstrap identity:
        // an impossible payload. Fail closed (§3) — never render an
        // authenticated surface for an empty identity.
        this.set({
          phase: "auth_error",
          user: "",
          role: null,
          errorDetail: "server reported an invalid session identity",
        });
        return this.state;
      }
      this.set({
        phase: "authenticated",
        user: auth.user,
        role: auth.role,
        tlsFallback: auth.tlsFallback,
        tlsFallbackReason: auth.tlsFallbackReason,
        errorDetail: "",
        logoutNote: null,
      });
      return this.state;
    } catch (err) {
      this.set({
        phase: "auth_error",
        user: "",
        role: null,
        errorDetail:
          err instanceof Error
            ? err.message.slice(0, 300)
            : "authentication state unavailable",
      });
      return this.state;
    }
  }

  /** §5: idempotent authentication-boundary transition. The first boundary
   * 401 starts the teardown; every concurrent boundary 401 joins the SAME
   * promise. Exactly one teardown, one transition, no logout POST (the
   * server already refused the session). */
  sessionExpired(): Promise<void> {
    if (this.teardownInFlight !== null) return this.teardownInFlight;
    this.teardownInFlight = (async () => {
      try {
        await runAuthTeardown(this.qc);
      } finally {
        this.set({
          phase: "unauthenticated",
          user: "",
          role: null,
          errorDetail: "",
          logoutNote: null,
        });
        this.teardownInFlight = null;
      }
    })();
    return this.teardownInFlight;
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
      });
      this.logoutInFlight = null;
      return { serverConfirmed };
    })();
    return this.logoutInFlight;
  }
}
