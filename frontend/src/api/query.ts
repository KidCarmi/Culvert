// TanStack Query security profile (FE-2 §14; FRONTEND-SECURITY-CONTRACT §6).
// ONE central configuration; no product queries exist yet.
import { QueryClient } from "@tanstack/react-query";
import { isRetryableError } from "./client";

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false, // Q2
        retry: (failureCount, error) =>
          failureCount < 2 && isRetryableError(error), // classified, bounded
        staleTime: 5_000,
        // No persistence plugin, no offline queue (Q2): networkMode stays
        // default-online; the cache is in-memory only.
      },
      mutations: {
        retry: false, // Q1 — always
      },
    },
  });
}

// authBoundaryTeardown (contract §6.Q4): FE-3 wires this to real
// 401/logout/user-change events, plus SSE close, timer stops, Blob URL
// revocation and secret-form clearing at the call sites that own them.
export async function authBoundaryTeardown(qc: QueryClient): Promise<void> {
  await qc.cancelQueries();
  qc.clear();
}
