// TanStack Query security profile (FE-2 §14 + qualification hardening;
// FRONTEND-SECURITY-CONTRACT §6). ONE central configuration; no product
// queries exist yet.
//
// networkMode: "always" on BOTH queries and mutations is load-bearing.
// TanStack's default "online" mode pauses work while the browser's
// OnlineManager reports offline and RESUMES it when connectivity returns —
// an implicit offline queue and deferred mutation replay, both banned by the
// profile. CULVERT is a LAN appliance: browser online/offline state is not
// the authority for whether the management origin is reachable. Every
// request executes immediately and either succeeds or surfaces the API
// client's network/timeout error at the moment the administrator acted.
// Never add offline persistence, never call resumePausedMutations.
import { QueryClient } from "@tanstack/react-query";
import { isRetryableError } from "./client";

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        networkMode: "always",
        refetchOnWindowFocus: false, // Q2
        refetchOnReconnect: false, // Q2 — reconnect is not a refresh trigger
        retry: (failureCount, error) =>
          failureCount < 2 && isRetryableError(error), // classified, bounded
        staleTime: 5_000,
        // No persistence plugin, no offline queue (Q2): the cache is
        // in-memory only.
      },
      mutations: {
        networkMode: "always",
        retry: false, // Q1 — always
      },
    },
  });
}

// FE-3 rule (recorded now, wired then — contract §6.Q3/§6.Q4):
//   • auth/setup/session queries that can carry sensitive or
//     session-specific data declare `gcTime: 0` — they are never retained
//     after their observers unmount;
//   • every authentication boundary (logout, 401, user change, role change)
//     runs the FULL teardown below BEFORE any other identity's application
//     state is rendered, alongside the call-site-owned steps: close SSE,
//     stop timers/polling, revoke Blob URLs, clear secret-bearing forms and
//     configuration candidates.
export async function authBoundaryTeardown(qc: QueryClient): Promise<void> {
  await qc.cancelQueries();
  qc.clear();
}
