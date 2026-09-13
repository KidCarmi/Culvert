// FE-6A.1 — bounded presentation of a failed READ. Only the error CLASS and
// the HTTP status are rendered; the server's error line, the dependency
// text and the request target never reach the DOM (FRONTEND-SECURITY-
// CONTRACT: raw dependency errors, file paths and transport errors are never
// shown). `what` names the read model in the operator's words.
import { ApiError } from "../api/client";
import { isRecord } from "../api/decode";

export function readErrorSummary(err: unknown, what: string): string {
  if (err instanceof ApiError) {
    switch (err.kind) {
      case "http":
        return `The appliance answered HTTP ${String(err.status ?? 0)}; the ${what} could not be read.`;
      case "contenttype":
      case "decode":
        return `The appliance's answer${err.status !== undefined ? ` (HTTP ${String(err.status)})` : ""} could not be verified as the ${what}; nothing from it is shown.`;
      case "timeout":
        return "The read timed out.";
      case "network":
        return "The appliance could not be reached.";
      default:
        return `The ${what} could not be read.`;
    }
  }
  return `The ${what} could not be read.`;
}

/** The bounded refusal `code` from a typed JSON refusal body — a verdict ONLY
 * when it is one of the codes the endpoint is contracted to answer
 * (`allowed`); anything else, including a well-formed but foreign code, is
 * null. The server's `error` line is deliberately never surfaced
 * (FE-6A.1 correction, blocker 1: a "code" field is a bounded class, not a
 * string to be echoed). */
export function refusalCodeOf<T extends string>(
  err: unknown,
  allowed: readonly T[],
): T | null {
  if (!(err instanceof ApiError) || err.bodyText === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(err.bodyText);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;
  const code = parsed["code"];
  if (typeof code !== "string") return null;
  const hit = allowed.find((a) => a === code);
  return hit ?? null;
}
