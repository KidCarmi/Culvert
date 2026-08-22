// Typed API client foundation (FE-2 §12 + qualification hardening;
// FRONTEND-SECURITY-CONTRACT §1/§2/§7).
//
//   request → target boundary → HTTP status → Content-Type → parse into
//   unknown → supplied runtime decoder → trusted typed value
//
// TRUST BOUNDARY: this client talks to the CULVERT admin API namespace
// `/api/*` ONLY. Any other target — absolute URLs, protocol-relative URLs,
// relative paths, /auth/* browser surfaces, /assets/*, scheme smuggling —
// is rejected BEFORE fetch is called (credentials: "same-origin" limits
// credential inclusion, not where a request may go). /auth/* redirect flows
// are browser NAVIGATION surfaces and never go through the JSON client.
//
// Errors are modeled HONESTLY as the backend produces them: (status,
// text/plain) via http.Error — no invented JSON envelope, and the error body
// is read through a BOUNDED streaming reader (never "download everything,
// then slice"). Mutations use only POST/PUT/DELETE (PATCH is outside the
// server's CSRF/limit classification — contract §2.C1). Real auth/session
// behavior (401 → teardown + login) is wired in FE-3; FE-2 provides the
// callback boundary only.
import { DecodeError } from "./decode";
import type { Decoder } from "./decode";

export type ApiErrorKind =
  | "target"
  | "http"
  | "network"
  | "timeout"
  | "aborted"
  | "decode"
  | "contenttype";

// Bounded error-body budget: an appliance API error is a short text/plain
// line. Read at most MAX_ERROR_BYTES off the wire, present at most
// MAX_ERROR_TEXT_CHARS.
const MAX_ERROR_BYTES = 4096;
const MAX_ERROR_TEXT_CHARS = 2000;

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
      bodyText !== undefined
        ? bodyText.slice(0, MAX_ERROR_TEXT_CHARS)
        : undefined;
  }

  /** 403: the server is authoritative about roles; the client may be stale. */
  get forbidden(): boolean {
    return this.kind === "http" && this.status === 403;
  }

  get unauthorized(): boolean {
    return this.kind === "http" && this.status === 401;
  }
}

// assertApiTarget: the canonical-path gate. Accepts only a local absolute
// path inside the admin API namespace. Nothing is normalized — an unsafe
// shape is REJECTED, never repaired into a safe-looking one.
export function assertApiTarget(path: string): void {
  const lower = path.toLowerCase();
  const bad =
    !path.startsWith("/api/") || // excludes absolute/protocol-relative/relative/other namespaces
    path.startsWith("//") ||
    path.includes("\\") ||
    path.includes("..") ||
    lower.includes("%5c") || // encoded backslash
    lower.includes("%2e%2e") || // encoded traversal
    // eslint-disable-next-line no-control-regex -- rejecting raw control bytes IS the gate
    /[\s\u0000-\u001f]/.test(path); // whitespace / control characters
  if (bad) {
    throw new ApiError(
      "target",
      `refused non-API request target ${JSON.stringify(path)}`,
    );
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
  assertApiTarget(path); // BEFORE any fetch — failed validation never dials

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
    const text = await readBoundedErrorText(resp);
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
  if (!isJSONContentType(resp.headers.get("Content-Type"))) {
    throw new ApiError(
      "contenttype",
      `${path}: unexpected Content-Type ${resp.headers.get("Content-Type") ?? "(none)"}`,
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

// isJSONContentType: exact media-type comparison — the type before any `;`
// parameters, case-insensitive. `application/jsonp`, `text/json`, and an
// absent header are all rejected; prefix matching is not used.
export function isJSONContentType(header: string | null): boolean {
  if (header === null) return false;
  const mediaType = (header.split(";", 1)[0] ?? "").trim().toLowerCase();
  return mediaType === "application/json";
}

// readBoundedErrorText: bounded STREAMING error-body reader. Reads at most
// MAX_ERROR_BYTES from the wire (then cancels the stream — the rest of the
// body is never consumed), decodes UTF-8 safely across chunk boundaries,
// retains at most MAX_ERROR_TEXT_CHARS. Any failure yields "" — an error
// body must never itself become a failure mode, and it is never logged.
export async function readBoundedErrorText(resp: Response): Promise<string> {
  const body = resp.body;
  if (body === null) return "";
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let bytes = 0;
  let text = "";
  try {
    while (bytes < MAX_ERROR_BYTES && text.length < MAX_ERROR_TEXT_CHARS) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value !== undefined) {
        const room = MAX_ERROR_BYTES - bytes;
        const chunk = value.byteLength > room ? value.subarray(0, room) : value;
        bytes += chunk.byteLength;
        text += decoder.decode(chunk, { stream: true });
      }
    }
    text += decoder.decode(); // flush a trailing partial code point safely
  } catch {
    return "";
  } finally {
    // Stop consuming: the source may be arbitrarily large.
    try {
      await reader.cancel();
    } catch {
      /* already closed */
    }
  }
  return text.slice(0, MAX_ERROR_TEXT_CHARS);
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
