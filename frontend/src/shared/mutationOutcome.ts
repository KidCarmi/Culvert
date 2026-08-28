// Shared mutation-outcome helpers (2A-M doctrine, lifted for 2B): a mutation
// whose transport died (network / timeout / abort) has an UNKNOWN outcome —
// it is never a confirmed failure — while any HTTP status is a known verdict.
import { ApiError } from "../api/client";

/** Is a mutation outcome UNKNOWN (client never observed a server verdict)? */
export function unknownOutcome(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.kind === "network" || err.kind === "timeout" || err.kind === "aborted")
  );
}

/** Bounded, safe-to-render server detail with a truthful fallback. */
export function serverErrorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.bodyText !== undefined && err.bodyText !== "") return err.bodyText;
    return err.message;
  }
  return fallback;
}
