// Explicit-run request ownership (FE-4 hardening §10, generalized in 2A).
// TanStack's cancelQueries does NOT own an in-flight MUTATION request, so an
// explicitly-started run (Active Diagnostics, Policy Tester) holds its own
// AbortController: exactly one controller per active run (starting a new run
// aborts a predecessor — no duplicate controllers survive), ownership is
// cleared after settle, and abort() is wired to both component unmount and
// the FE-3 authentication boundary (registerAuthCleanup). Abort cancels the
// CLIENT request and releases client state — it cannot undo server work that
// already executed.
//
// This is the FE-4 diagnostics owner, extracted verbatim once a second real
// consumer (the 2A Policy Tester) existed — no event bus, no framework.

export interface RequestRunOwner {
  /** Start a run: aborts any predecessor, takes ownership, returns the
   * run's signal. */
  begin(): AbortSignal;
  /** Settle a run: releases ownership ONLY if `sig` is still the active
   * run's signal (a superseded run must not clear its successor). */
  settle(sig: AbortSignal): void;
  /** Abort the active run (unmount / auth boundary) and clear ownership. */
  abort(): void;
  /** test seam: whether a controller is currently owned. */
  active(): boolean;
}

export function createRequestRunOwner(): RequestRunOwner {
  let controller: AbortController | null = null;
  return {
    begin(): AbortSignal {
      controller?.abort();
      const c = new AbortController();
      controller = c;
      return c.signal;
    },
    settle(sig: AbortSignal): void {
      if (controller !== null && controller.signal === sig) controller = null;
    },
    abort(): void {
      controller?.abort();
      controller = null;
    },
    active(): boolean {
      return controller !== null;
    },
  };
}
