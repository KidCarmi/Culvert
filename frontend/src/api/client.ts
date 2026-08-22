// Typed API client foundation (FE-2 §12; FRONTEND-SECURITY-CONTRACT §1/§2/§7).
//
//   request → HTTP status → Content-Type → parse into unknown
//           → supplied runtime decoder → trusted typed value
//
// Errors are modeled HONESTLY as the backend produces them: (status,
// text/plain) via http.Error — no invented JSON envelope. Mutations use only
// POST/PUT/DELETE (PATCH is outside the server's CSRF/limit classification —
// contract §2.C1). Real auth/session behavior (401 → teardown + login) is
// wired in FE-3; FE-2 provides the callback boundary only.
import { DecodeError } from "./decode";
import type { Decoder } from "./decode";

export type ApiErrorKind =
  "http" | "network" | "timeout" | "aborted" | "decode" | "contenttype";

const MAX_ERROR_TEXT = 2000;

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;
  /** bounded, safe-to-render server text (text/plain contract) */
  readonly bodyText: string | undefined;

  constructor(
    kind: ApiErrorKind,
    message: string,
    status?: number,
    bodyText?: string,
  ) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.bodyText =
      bodyText !== undefined ? bodyText.slice(0, MAX_ERROR_TEXT) : undefined;
  }

  /** 403: the server is authoritative about roles; the client may be stale. */
  get forbidden(): boolean {
    return this.kind === "http" && this.status === 403;
  }

  get unauthorized(): boolean {
    return this.kind === "http" && this.status === 401;
  }
}

type Method = "GET" | "POST" | "PUT" | "DELETE";

export interface RequestOptions {
  method?: Method;
  /** JSON-serialized body for mutating requests */
  body?: unknown;
  signal?: AbortSignal;
  timeoutMs?: number;
}

// The authentication-boundary callback (FE-3 wires the real teardown +
// login flow; contract §6.Q4). Registered once at app bootstrap.
let on401: (() => void) | null = null;
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  on401 = fn;
}

const DEFAULT_TIMEOUT_MS = 30_000;

export async function apiRequest<T>(
  path: string,
  decoder: Decoder<T>,
  opts: RequestOptions = {},
): Promise<T> {
  const method: Method = opts.method ?? "GET";
  const timeout = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const signal =
    opts.signal !== undefined
      ? AbortSignal.any([opts.signal, timeout])
      : timeout;

  let resp: Response;
  try {
    const init: RequestInit = {
      method,
      signal,
      credentials: "same-origin",
      redirect: "error",
    };
    if (opts.body !== undefined) {
      init.body = JSON.stringify(opts.body);
      init.headers = { "Content-Type": "application/json" };
    }
    resp = await fetch(path, init);
  } catch (err) {
    if (timeout.aborted)
      throw new ApiError("timeout", `request to ${path} timed out`);
    if (opts.signal?.aborted === true)
      throw new ApiError("aborted", `request to ${path} aborted`);
    throw new ApiError(
      "network",
      `network failure reaching ${path}: ${String(err)}`,
    );
  }

  if (!resp.ok) {
    const text = await safeText(resp);
    if (resp.status === 401) on401?.();
    throw new ApiError(
      "http",
      `${path}: HTTP ${String(resp.status)}`,
      resp.status,
      text,
    );
  }

  if (resp.status === 204) {
    return decoder(undefined, "$");
  }
  const ct = resp.headers.get("Content-Type") ?? "";
  if (!ct.startsWith("application/json")) {
    throw new ApiError(
      "contenttype",
      `${path}: unexpected Content-Type ${ct}`,
      resp.status,
    );
  }

  let parsed: unknown;
  try {
    parsed = await resp.json();
  } catch {
    throw new ApiError(
      "decode",
      `${path}: response body is not valid JSON`,
      resp.status,
    );
  }
  try {
    return decoder(parsed, "$");
  } catch (err) {
    if (err instanceof DecodeError) {
      throw new ApiError("decode", `${path}: ${err.message}`, resp.status);
    }
    throw err;
  }
}

async function safeText(resp: Response): Promise<string> {
  try {
    return (await resp.text()).slice(0, MAX_ERROR_TEXT);
  } catch {
    return "";
  }
}

/** Retry classification (contract §6.Q2): never on 4xx; bounded on network
 * failures and selected 5xx. */
export function isRetryableError(err: unknown): boolean {
  if (!(err instanceof ApiError)) return false;
  if (err.kind === "network" || err.kind === "timeout") return true;
  if (err.kind === "http" && err.status !== undefined) {
    return err.status === 502 || err.status === 503 || err.status === 504;
  }
  return false;
}
