// Slice 2A §15/§27: Policy Tester explicit-run request ownership. The tester
// POST is side-effect free but it is still a mutation-shaped request TanStack
// cancelQueries does not own, so it rides the shared explicit-run owner
// (extracted from FE-4 diagnostics): predecessor aborted, unmount abort,
// authentication-boundary abort, and no result may render into the next
// identity. The FE-4 diagnostics suite pins the same owner through its
// original import path — both consumers share one implementation.
import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { runPolicyTest } from "../api/policy";
import { createRequestRunOwner } from "../shared/runOwner";
import { createDiagnoseRunOwner } from "../features/diagnostics/runOwner";
import { registerAuthCleanup, runAuthTeardown } from "../auth/teardown";

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

describe("tester run ownership (§15)", () => {
  it("shares ONE implementation with FE-4 diagnostics (no fork)", () => {
    expect(createDiagnoseRunOwner).toBe(createRequestRunOwner);
  });

  it("a new tester run aborts its predecessor at the network layer", async () => {
    const captured = stubHangingFetch();
    const owner = createRequestRunOwner();
    const s1 = owner.begin();
    const p1 = runPolicyTest({ host: "a.test" }, s1).finally(() => {
      owner.settle(s1);
    });
    p1.catch(() => {
      /* asserted below */
    });
    await vi.waitFor(() => {
      expect(captured.length).toBe(1);
    });
    const s2 = owner.begin(); // supersede
    const p2 = runPolicyTest({ host: "b.test" }, s2).finally(() => {
      owner.settle(s2);
    });
    p2.catch(() => {
      /* hangs until cleanup */
    });
    expect(captured[0]?.aborted).toBe(true);
    await expect(p1).rejects.toMatchObject({ kind: "aborted" });
    expect(owner.active()).toBe(true); // successor still owned
    owner.abort(); // test cleanup (unmount path)
    await expect(p2).rejects.toMatchObject({ kind: "aborted" });
  });

  it("unmount abort cancels the active run and clears ownership", async () => {
    const captured = stubHangingFetch();
    const owner = createRequestRunOwner();
    const sig = owner.begin();
    const p = runPolicyTest({ host: "x.test" }, sig).finally(() => {
      owner.settle(sig);
    });
    p.catch(() => {
      /* asserted below */
    });
    await vi.waitFor(() => {
      expect(captured.length).toBe(1);
    });
    owner.abort(); // component unmount
    expect(captured[0]?.aborted).toBe(true);
    await expect(p).rejects.toMatchObject({ kind: "aborted" });
    expect(owner.active()).toBe(false);
  });

  it("the authentication boundary aborts an in-flight tester run and its result cannot render into the next identity", async () => {
    const captured = stubHangingFetch();
    const owner = createRequestRunOwner();
    const unregister = registerAuthCleanup(() => {
      owner.abort();
    });
    try {
      const sig = owner.begin();
      let rendered: unknown = null;
      const p = runPolicyTest({ host: "boundary.test" }, sig)
        .then((result) => {
          rendered = result; // would be the render path
          return result;
        })
        .finally(() => {
          owner.settle(sig);
        });
      p.catch(() => {
        /* asserted below */
      });
      await vi.waitFor(() => {
        expect(captured.length).toBe(1);
      });

      await runAuthTeardown(new QueryClient()); // logout / session boundary

      expect(captured[0]?.aborted).toBe(true);
      await expect(p).rejects.toMatchObject({ kind: "aborted" });
      expect(rendered).toBeNull(); // no prior-identity result rendered
      expect(owner.active()).toBe(false);
    } finally {
      unregister();
    }
  });
});
