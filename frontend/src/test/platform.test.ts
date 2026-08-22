// FE-2 platform unit tests: theme storage module, decoder helpers, API
// client boundary, query-profile defaults.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DecodeError,
  field,
  readArray,
  readBoolean,
  readEnum,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "../api/decode";
import { ApiError, apiRequest, isRetryableError } from "../api/client";
import { createQueryClient } from "../api/query";
import {
  readThemePreference,
  resolveTheme,
  setTheme,
} from "../design-system/theme";

// jsdom has no matchMedia; the theme module needs a minimal stub.
beforeEach(() => {
  vi.stubGlobal("matchMedia", (q: string) => ({
    matches: q.includes("dark"),
    media: q,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
});
afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

describe("theme module", () => {
  it("persists only valid preferences and stamps data-theme", () => {
    setTheme("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(localStorage.getItem("culvert-theme")).toBe("light");
    setTheme("system"); // system removes the key (no duplicated resolved state)
    expect(localStorage.getItem("culvert-theme")).toBeNull();
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark"); // stubbed OS pref
  });

  it("rejects garbage stored values", () => {
    localStorage.setItem("culvert-theme", "hotdog-stand");
    expect(readThemePreference()).toBe("system");
  });

  it("resolves system against prefers-color-scheme", () => {
    expect(resolveTheme("system")).toBe("dark");
    expect(resolveTheme("light")).toBe("light");
  });
});

describe("decoders", () => {
  it("reads primitives and composes", () => {
    const obj = readRecord({ a: "x", n: 3, ok: true, list: ["p", "q"] });
    expect(field(obj, "a", readString)).toBe("x");
    expect(field(obj, "n", readNumber)).toBe(3);
    expect(field(obj, "ok", readBoolean)).toBe(true);
    expect(field(obj, "list", readArray(readString))).toEqual(["p", "q"]);
    expect(field(obj, "missing", readOptional(readString))).toBeUndefined();
    expect(readEnum(["ok", "fail"])("ok")).toBe("ok");
  });

  it("fails closed with precise paths", () => {
    expect(() => readString(42)).toThrow(DecodeError);
    const obj = readRecord({ list: ["p", 7] });
    expect(() => field(obj, "list", readArray(readString))).toThrow(
      /\$\.list\[1\]/,
    );
    expect(() => readEnum(["a", "b"])("c")).toThrow(DecodeError);
  });
});

describe("api client", () => {
  it("decodes a JSON success through the boundary", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    const out = await apiRequest("/api/x", (v) =>
      field(readRecord(v), "ok", readBoolean),
    );
    expect(out).toBe(true);
  });

  it("models backend errors as bounded (status, text)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("forbidden\n", { status: 403 })),
    );
    const err = await apiRequest("/api/x", readRecord).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    if (err instanceof ApiError) {
      expect(err.status).toBe(403);
      expect(err.forbidden).toBe(true);
      expect(err.bodyText).toBe("forbidden\n");
    }
  });

  it("rejects non-JSON success bodies and decode failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("<html>", {
          status: 200,
          headers: { "Content-Type": "text/html" },
        }),
      ),
    );
    const err = await apiRequest("/api/x", readRecord).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    if (err instanceof ApiError) expect(err.kind).toBe("contenttype");
  });

  it("classifies retries: never 4xx, bounded 5xx/network", () => {
    expect(isRetryableError(new ApiError("http", "", 403, ""))).toBe(false);
    expect(isRetryableError(new ApiError("http", "", 409, ""))).toBe(false);
    expect(isRetryableError(new ApiError("http", "", 503, ""))).toBe(true);
    expect(isRetryableError(new ApiError("network", ""))).toBe(true);
    expect(isRetryableError(new Error("x"))).toBe(false);
  });
});

describe("query profile", () => {
  it("applies the CULVERT security defaults", () => {
    const qc = createQueryClient();
    const d = qc.getDefaultOptions();
    expect(d.queries?.refetchOnWindowFocus).toBe(false);
    expect(d.mutations?.retry).toBe(false);
    expect(typeof d.queries?.retry).toBe("function");
  });
});
