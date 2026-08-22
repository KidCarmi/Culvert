// 2A-M §13/§14: the bounded binary download client preserves the JSON
// client's fundamentals (target gate, media-type allowlist, bounded body,
// abort) and never yields a truncated download as success.
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiDownloadRequest } from "../api/client";

function respond(
  body: BodyInit | null,
  init: ResponseInit & { headers?: Record<string, string> },
): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve(new Response(body, init))),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

async function kindOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (err) {
    return err instanceof ApiError ? err.kind : "other";
  }
}

describe("download client (§13/§14)", () => {
  it("rejects non-API targets BEFORE any fetch", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    for (const bad of [
      "https://evil.example/api/export",
      "//evil.example/api/export",
      "/auth/logout",
      "/api/../etc",
    ]) {
      await expect(
        apiDownloadRequest(bad, ["application/json"]),
      ).rejects.toMatchObject({ kind: "target" });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("accepts an allowlisted media type (parameters tolerated) and returns the blob", async () => {
    respond('{"logs":[]}', {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    });
    const res = await apiDownloadRequest("/api/export?format=json", [
      "application/json",
    ]);
    expect(res.mediaType).toBe("application/json");
    expect(await res.blob.text()).toContain("logs");
  });

  it("rejects an unexpected media type — arbitrary server bytes never become a download", async () => {
    respond("<html>oops</html>", {
      status: 200,
      headers: { "Content-Type": "text/html" },
    });
    expect(await kindOf(apiDownloadRequest("/api/export", ["text/csv"]))).toBe(
      "contenttype",
    );
  });

  it("rejects an explicit Content-Length over the cap before reading", async () => {
    respond("x", {
      status: 200,
      headers: {
        "Content-Type": "text/csv",
        "Content-Length": String(1024 * 1024),
      },
    });
    expect(
      await kindOf(
        apiDownloadRequest("/api/export?format=csv", ["text/csv"], {
          maxBytes: 1000,
        }),
      ),
    ).toBe("toolarge");
  });

  it("enforces the cap at the streaming reader when Content-Length is absent/dishonest — controlled error, no partial success", async () => {
    // A stream that yields forever without a Content-Length header.
    let cancelled = false;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(64 * 1024));
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          new Response(endless, {
            status: 200,
            headers: { "Content-Type": "text/csv" },
          }),
        ),
      ),
    );
    expect(
      await kindOf(
        apiDownloadRequest("/api/export?format=csv", ["text/csv"], {
          maxBytes: 256 * 1024,
        }),
      ),
    ).toBe("toolarge");
    expect(cancelled).toBe(true); // the reader was cancelled after the cap
  });

  it("propagates HTTP errors with the bounded server text", async () => {
    respond("forbidden", {
      status: 403,
      headers: { "Content-Type": "text/plain" },
    });
    await expect(
      apiDownloadRequest("/api/export", ["application/json"]),
    ).rejects.toMatchObject({
      kind: "http",
      status: 403,
      bodyText: "forbidden",
    });
  });

  it("an aborted download rejects with kind=aborted", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_p: unknown, init?: RequestInit) =>
          new Promise<Response>((_res, reject) => {
            init?.signal?.addEventListener("abort", () => {
              reject(new DOMException("aborted", "AbortError"));
            });
          }),
      ),
    );
    const c = new AbortController();
    const p = apiDownloadRequest("/api/export", ["text/csv"], {
      signal: c.signal,
    });
    const settled = kindOf(p);
    c.abort();
    expect(await settled).toBe("aborted");
  });
});
