// FE-3 authentication-boundary teardown (§6). Runs BEFORE another identity's
// application state may render, on: session-expiry 401, explicit logout,
// user change, role change.
//
// Owned directly here: TanStack cancellation + cache clear (steps 1-2).
// Everything a FUTURE owner will hold (SSE connections, timers/polling,
// Blob URLs, secret-bearing forms, configuration candidates/drafts,
// role-derived caches) registers a cleanup through registerAuthCleanup —
// a deliberately small registration boundary, not an event bus. At FE-3
// no such owner exists yet; nothing fake is registered.
import type { QueryClient } from "@tanstack/react-query";
import { authBoundaryTeardown } from "../api/query";

type AuthCleanup = () => void | Promise<void>;

const cleanups = new Set<AuthCleanup>();

/** registerAuthCleanup: future resource owners (SSE, timers, Blob URLs,
 * drafts) register here; returns the unregister function. */
export function registerAuthCleanup(fn: AuthCleanup): () => void {
  cleanups.add(fn);
  return () => cleanups.delete(fn);
}

/** runAuthTeardown: cancel in-flight queries, clear the cache, then run
 * every registered owner cleanup. A throwing cleanup is contained — the
 * boundary always completes. */
export async function runAuthTeardown(qc: QueryClient): Promise<void> {
  await authBoundaryTeardown(qc); // cancelQueries + clear (FE-2 §6.Q4 helper)
  for (const fn of [...cleanups]) {
    try {
      await fn();
    } catch {
      // contained: one broken owner must not stop the boundary
    }
  }
}

/** test seam: the number of registered cleanups (no enumeration). */
export function registeredCleanupCount(): number {
  return cleanups.size;
}
