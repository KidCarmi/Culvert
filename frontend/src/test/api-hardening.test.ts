// FE-2 qualification-hardening proofs (FRONTEND-SECURITY-CONTRACT §1/§2/§6):
//   • API target boundary — fetch is NEVER invoked for a rejected target;
//   • bounded STREAMING error-body reader — stops early, cancels the source;
//   • exact Content-Type media-type comparison;
//   • TanStack offline semantics — networkMode "always" behavior observed via
//     onlineManager (real function calls, not configuration reads).
import { afterEach, describe, expect, it, vi } from "vitest";
import { MutationObserver, onlineManager } from "@tanstack/react-query";
import {
  ApiError,
  apiRequest,
  assertApiTarget,
  isJSONContentType,
  readBoundedErrorText,
} from "../api/client";
import { readRecord } from "../api/decode";
import { createQueryClient } from "../api/query";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  onlineManager.setOnline(true); // never leak offline state into other tests
});

// ---------------------------------------------------------------------------
// §1 API target boundary
// ---------------------------------------------------------------------------

const ACCEPTED_TARGETS = [
  "/api/auth/status",
  "/api/foo?x=1",
  "/api/ca-cert", // hyphens are legal API path bytes
  "/api/policy/rules",
] as const;

const REJECTED_TARGETS = [
  "https://example.com/api/x", // absolute URL
  "http://example.com/api/x", // absolute URL (cleartext)
  "HTTPS://EXAMPLE.COM/api/x", // absolute URL, case games
  "//example.com/api/x", // protocol-relative
  "api/x", // relative path
  "/apifoo", // outside the namespace
  "/auth/logout", // browser navigation surface, never the JSON client
  "/assets/x.js", // static asset namespace
  "/app/", // SPA shell
  "javascript:alert(1)", // scheme smuggling
  "data:text/html,x", // scheme smuggling
  "/api/a\\b", // backslash
  "/api/..%5Cx", // encoded backslash
  "/api/%2e%2e/x", // encoded traversal
  "/api/%2E%2E/x", // encoded traversal, upper-case
  "/api/../admin", // dot-dot traversal
  "/api/a b", // whitespace
  "/api/a\tb", // tab
  "/api/a\nb", // newline
  "/api/a\u0000b", // NUL
  "/api/a\u001fb", // C0 control
  "", // empty
] as const;

describe("assertApiTarget", () => {
  it("accepts admin-API paths verbatim", () => {
    for (const target of ACCEPTED_TARGETS) {
      expect(() => {
        assertApiTarget(target);
      }).not.toThrow();
    }
  });

  it("rejects every non-API shape without normalizing it", () => {
    for (const target of REJECTED_TARGETS) {
      let caught: unknown;
      try {
        assertApiTarget(target);
      } catch (err) {
        caught = err;
      }
      expect(
        caught,
        `expected rejection for ${JSON.stringify(target)}`,
      ).toBeInstanceOf(ApiError);
      if (caught instanceof ApiError) expect(caught.kind).toBe("target");
    }
  });
});

describe("apiRequest target boundary", () => {
  it("NEVER invokes fetch for a rejected target", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    for (const target of REJECTED_TARGETS) {
      const err = await apiRequest(target, readRecord).catch((e: unknown) => e);
      expect(
        err,
        `expected ApiError for ${JSON.stringify(target)}`,
      ).toBeInstanceOf(ApiError);
      if (err instanceof ApiError) expect(err.kind).toBe("target");
    }
    expect(fetchSpy).not.toHaveBeenCalled(); // zero dials across the whole table
  });

  it("invokes fetch with the exact accepted path", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchSpy);
    await apiRequest("/api/auth/status", readRecord);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0]?.[0]).toBe("/api/auth/status");
  });
});

// ---------------------------------------------------------------------------
// §2 bounded streaming error-body reader
// ---------------------------------------------------------------------------

// A pull-based synthetic stream: every pull enqueues one `chunkBytes`-byte
// chunk of "a"s, up to `totalChunks` pulls. Counts pulls and records cancel.
function syntheticStream(
  chunkBytes: number,
  totalChunks: number,
): {
  stream: ReadableStream<Uint8Array>;
  state: { pulls: number; cancelled: boolean };
} {
  const state = { pulls: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>({
    pull(controller): void {
      if (state.pulls >= totalChunks) {
        controller.close();
        return;
      }
      state.pulls += 1;
      controller.enqueue(new Uint8Array(chunkBytes).fill(0x61)); // "a"
    },
    cancel(): void {
      state.cancelled = true;
    },
  });
  return { stream, state };
}

describe("readBoundedErrorText", () => {
  it("stops reading a huge body well before consuming it, and cancels", async () => {
    // 1 MiB potential body in 1 KiB chunks; the budget is 4096 bytes /
    // 2000 chars, so only a handful of pulls may ever happen.
    const { stream, state } = syntheticStream(1024, 1024);
    const resp = new Response(stream, { status: 500 });
    const text = await readBoundedErrorText(resp);
    expect(text).toBe("a".repeat(2000)); // MAX_ERROR_TEXT_CHARS retained
    expect(state.pulls).toBeLessThanOrEqual(4); // ≤ MAX_ERROR_BYTES / chunk
    expect(state.cancelled).toBe(true); // the rest of the body is abandoned
  });

  it("is UTF-8 safe across chunk boundaries", async () => {
    const euro = new TextEncoder().encode("€"); // 3 bytes
    const first = new Uint8Array([0x61, 0x62, euro[0] ?? 0]); // "ab" + byte 1/3
    const rest = new Uint8Array([euro[1] ?? 0, euro[2] ?? 0, 0x63, 0x64]); // bytes 2-3 + "cd"
    const stream = new ReadableStream<Uint8Array>({
      start(controller): void {
        controller.enqueue(first);
        controller.enqueue(rest);
        controller.close();
      },
    });
    const text = await readBoundedErrorText(
      new Response(stream, { status: 500 }),
    );
    expect(text).toBe("ab€cd");
  });

  it("yields empty text for a bodyless response", async () => {
    const text = await readBoundedErrorText(
      new Response(null, { status: 500 }),
    );
    expect(text).toBe("");
  });
});

// ---------------------------------------------------------------------------
// §3 exact Content-Type comparison
// ---------------------------------------------------------------------------

describe("isJSONContentType", () => {
  it("accepts application/json with parameters, case-insensitively", () => {
    expect(isJSONContentType("application/json")).toBe(true);
    expect(isJSONContentType("application/json; charset=utf-8")).toBe(true);
    expect(isJSONContentType("Application/JSON")).toBe(true);
    expect(isJSONContentType("  application/json ; charset=utf-8")).toBe(true);
  });

  it("rejects lookalikes, other types, and absence", () => {
    expect(isJSONContentType("application/jsonp")).toBe(false);
    expect(isJSONContentType("text/json")).toBe(false);
    expect(isJSONContentType("text/html")).toBe(false);
    expect(isJSONContentType("application/json-seq")).toBe(false);
    expect(isJSONContentType("")).toBe(false);
    expect(isJSONContentType(null)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// §5 offline semantics observed through onlineManager (A–E)
// ---------------------------------------------------------------------------

describe("query offline semantics (networkMode: always)", () => {
  it("A: a query created while offline executes its queryFn immediately", async () => {
    onlineManager.setOnline(false);
    const qc = createQueryClient();
    const queryFn = vi.fn<() => Promise<string>>().mockResolvedValue("live");
    const out = await qc.fetchQuery({ queryKey: ["offline-query"], queryFn });
    expect(out).toBe("live");
    expect(queryFn).toHaveBeenCalledTimes(1); // executed, not paused
    qc.clear();
  });

  it("B: a mutation fired while offline executes immediately, never pauses", async () => {
    onlineManager.setOnline(false);
    const qc = createQueryClient();
    const mutationFn = vi.fn<() => Promise<string>>().mockResolvedValue("done");
    const observer = new MutationObserver(qc, { mutationFn });
    const out = await observer.mutate(undefined);
    expect(out).toBe("done");
    expect(mutationFn).toHaveBeenCalledTimes(1);
    expect(observer.getCurrentResult().isPaused).toBe(false);
    expect(
      qc
        .getMutationCache()
        .getAll()
        .filter((m) => m.state.isPaused),
    ).toEqual([]);
    qc.clear();
  });

  it("C: a failed offline mutation is NOT replayed when connectivity returns", async () => {
    onlineManager.setOnline(false);
    const qc = createQueryClient();
    const mutationFn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValue(new Error("appliance unreachable"));
    const observer = new MutationObserver(qc, { mutationFn });
    await expect(observer.mutate(undefined)).rejects.toThrow(
      "appliance unreachable",
    );
    expect(mutationFn).toHaveBeenCalledTimes(1);

    onlineManager.setOnline(true); // "reconnect"
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(mutationFn).toHaveBeenCalledTimes(1); // no deferred replay, ever
    expect(
      qc
        .getMutationCache()
        .getAll()
        .filter((m) => m.state.isPaused),
    ).toEqual([]);
    qc.clear();
  });

  it("D: mutations never retry", async () => {
    const qc = createQueryClient();
    const mutationFn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValue(new Error("boom"));
    const observer = new MutationObserver(qc, { mutationFn });
    await expect(observer.mutate(undefined)).rejects.toThrow("boom");
    expect(mutationFn).toHaveBeenCalledTimes(1); // retry: false
    qc.clear();
  });

  it("E: the profile pins networkMode always + refetchOnReconnect false explicitly", () => {
    const d = createQueryClient().getDefaultOptions();
    expect(d.queries?.networkMode).toBe("always");
    expect(d.mutations?.networkMode).toBe("always");
    expect(d.queries?.refetchOnReconnect).toBe(false);
    expect(d.queries?.refetchOnWindowFocus).toBe(false);
    expect(d.mutations?.retry).toBe(false);
  });
});
