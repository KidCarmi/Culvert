// FE-4 hardening §9–§11: authentication-boundary cancellation proofs.
// Queries: the FE-3 boundary (runAuthTeardown → QueryClient.cancelQueries)
// must reach the NETWORK layer — the underlying fetch AbortSignals become
// aborted — and no in-flight result may enter the next identity's cache.
// Mutations: TanStack's cancelQueries does not own mutation requests, so the
// active-diagnostic run holds its own AbortController (runOwner) wired to
// the same boundary via registerAuthCleanup.
import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { fetchOverview } from "../features/overview/OverviewPage";
import { getAudit } from "../api/ops";
import { runDiagnose } from "../api/diagnose";
import { createDiagnoseRunOwner } from "../features/diagnostics/runOwner";
import { registerAuthCleanup, runAuthTeardown } from "../auth/teardown";

// A fetch stub for a delayed request: records the AbortSignal each call
// received and — like the real fetch — rejects with AbortError when that
// signal aborts; it never resolves otherwise.
function stubHangingFetch(): AbortSignal[] {
  const captured: AbortSignal[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((_path: unknown, init?: RequestInit) => {
      const sig = init?.signal;
      if (sig instanceof AbortSignal) captured.push(sig);
      return new Promise<Response>((_resolve, reject) => {
        sig?.addEventListener("abort", () => {
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      });
    }),
  );
  return captured;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("query cancellation at the auth boundary (§9/§11)", () => {
  it("overview: the boundary aborts all five in-flight snapshot fetches and nothing enters the next identity's cache", async () => {
    const captured = stubHangingFetch();
    const qc = new QueryClient();
    const p = qc.fetchQuery({
      queryKey: ["ops", "overview"],
      queryFn: ({ signal }) => fetchOverview(signal),
      retry: false,
    });
    p.catch(() => {
      // rejection asserted below; prevent unhandled-rejection noise
    });
    await vi.waitFor(() => {
      expect(captured.length).toBe(5);
    });
    expect(captured.every((s) => !s.aborted)).toBe(true);

    // B: the authentication boundary fires.
    await runAuthTeardown(qc);

    // C: the underlying fetch AbortSignals are aborted — cancellation
    // reached the wire, not just the cache.
    expect(captured.every((s) => s.aborted)).toBe(true);
    await expect(p).rejects.toBeTruthy();

    // D: the next identity starts with NO snapshot from the old identity.
    expect(qc.getQueryData(["ops", "overview"])).toBeUndefined();
    expect(qc.getQueryCache().getAll()).toHaveLength(0);
  });

  it("audit: representative single-query proof of the same contract", async () => {
    const captured = stubHangingFetch();
    const qc = new QueryClient();
    const p = qc.fetchQuery({
      queryKey: ["ops", "audit"],
      queryFn: ({ signal }) =>
        getAudit(
          { offset: 0, limit: 100, fromMs: 0, toMs: 1, source: "memory" },
          signal,
        ),
      retry: false,
    });
    p.catch(() => {
      // rejection asserted below
    });
    await vi.waitFor(() => {
      expect(captured.length).toBe(1);
    });
    await runAuthTeardown(qc);
    expect(captured[0]?.aborted).toBe(true);
    await expect(p).rejects.toBeTruthy();
    expect(qc.getQueryData(["ops", "audit"])).toBeUndefined();
  });
});

describe("diagnose run ownership (§10/§11)", () => {
  it("one controller per run: a new run aborts its predecessor; settle clears only the active run", () => {
    const owner = createDiagnoseRunOwner();
    const first = owner.begin();
    expect(owner.active()).toBe(true);
    const second = owner.begin();
    expect(first.aborted).toBe(true); // no duplicate controllers survive
    expect(second.aborted).toBe(false);
    owner.settle(first); // a superseded run must not clear its successor
    expect(owner.active()).toBe(true);
    owner.settle(second); // ownership cleared after settle
    expect(owner.active()).toBe(false);
  });

  it("abort() cancels the active run and clears ownership (unmount path)", () => {
    const owner = createDiagnoseRunOwner();
    const sig = owner.begin();
    owner.abort();
    expect(sig.aborted).toBe(true);
    expect(owner.active()).toBe(false);
  });

  it("a delayed diagnose request aborts at the auth boundary and its result cannot render", async () => {
    const captured = stubHangingFetch();
    const owner = createDiagnoseRunOwner();
    const unregister = registerAuthCleanup(() => {
      owner.abort();
    });
    try {
      // A: a delayed diagnose run starts.
      const sig = owner.begin();
      const p = runDiagnose("storage", undefined, sig).finally(() => {
        owner.settle(sig);
      });
      p.catch(() => {
        // rejection asserted below
      });
      await vi.waitFor(() => {
        expect(captured.length).toBe(1);
      });

      // B: logout/session boundary fires the registered owner cleanup.
      await runAuthTeardown(new QueryClient());

      // C: the diagnostic request controller aborted at the network layer.
      expect(captured[0]?.aborted).toBe(true);
      // D: the mutation settles as a REJECTION after the boundary — no
      // result object exists to render, and ownership is released.
      await expect(p).rejects.toMatchObject({ kind: "aborted" });
      expect(owner.active()).toBe(false);
    } finally {
      unregister();
    }
  });
});
