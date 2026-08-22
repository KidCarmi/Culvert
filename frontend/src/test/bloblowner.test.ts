// 2A-M §16: download/Blob ownership lifecycle — supersession, delivery
// gating, unmount + FE-3 authentication-boundary cleanup, and object-URL
// revocation (no URL crosses an identity boundary; cleanup is safe when a
// component unmount follows the collapsed boundary).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import {
  createDownloadOwner,
  sanitizeDownloadFilename,
} from "../shared/blobOwner";
import { registerAuthCleanup, runAuthTeardown } from "../auth/teardown";

let created: string[];
let revoked: string[];
let counter: number;

beforeEach(() => {
  created = [];
  revoked = [];
  counter = 0;
  vi.stubGlobal("URL", {
    ...URL,
    createObjectURL: vi.fn(() => {
      counter += 1;
      const u = `blob:test/${String(counter)}`;
      created.push(u);
      return u;
    }),
    revokeObjectURL: vi.fn((u: string) => {
      revoked.push(u);
    }),
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

const blob = new Blob(["x"], { type: "text/csv" });

describe("download owner (§16)", () => {
  it("delivers an active run: URL created, download triggered, URL revoked, ownership cleared", () => {
    const owner = createDownloadOwner();
    const sig = owner.begin();
    const clicks: string[] = [];
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(function (this: HTMLAnchorElement) {
        clicks.push(`${this.href}|${this.download}`);
      });
    try {
      expect(owner.deliver(sig, blob, "culvert-recent-traffic-x.csv")).toBe(
        true,
      );
    } finally {
      clickSpy.mockRestore();
    }
    expect(clicks).toHaveLength(1);
    expect(clicks[0]).toContain("culvert-recent-traffic-x.csv");
    expect(created).toHaveLength(1);
    expect(revoked).toEqual(created); // revoked after hand-off
    expect(owner.active()).toBe(false);
  });

  it("a new download supersedes: predecessor aborted, its result cannot deliver", () => {
    const owner = createDownloadOwner();
    const s1 = owner.begin();
    const s2 = owner.begin();
    expect(s1.aborted).toBe(true);
    expect(s2.aborted).toBe(false);
    expect(owner.deliver(s1, blob, "old.csv")).toBe(false); // stale run
    expect(created).toHaveLength(0); // no URL was ever created for it
  });

  it("abortAndRevoke (unmount) cancels the run and no later delivery happens", () => {
    const owner = createDownloadOwner();
    const sig = owner.begin();
    owner.abortAndRevoke();
    expect(sig.aborted).toBe(true);
    expect(owner.deliver(sig, blob, "late.csv")).toBe(false);
    expect(created).toHaveLength(0);
    // Safe to call again (unmount after the collapsed boundary).
    owner.abortAndRevoke();
  });

  it("the FE-3 authentication boundary aborts the in-flight download; no object URL crosses identities", async () => {
    const owner = createDownloadOwner();
    const unregister = registerAuthCleanup(() => {
      owner.abortAndRevoke();
    });
    try {
      const sig = owner.begin();
      await runAuthTeardown(new QueryClient());
      expect(sig.aborted).toBe(true);
      expect(owner.active()).toBe(false);
      expect(owner.deliver(sig, blob, "leak.csv")).toBe(false);
      expect(created).toHaveLength(0);
    } finally {
      unregister();
    }
  });
});

describe("filename gate (§15)", () => {
  it("deterministic names pass through; hostile names are neutralized", () => {
    expect(sanitizeDownloadFilename("culvert-recent-traffic-1.json")).toBe(
      "culvert-recent-traffic-1.json",
    );
    expect(sanitizeDownloadFilename("../../etc/passwd")).not.toContain("/");
    expect(sanitizeDownloadFilename("a\r\nb.csv")).not.toMatch(/[\r\n]/);
    expect(sanitizeDownloadFilename("<img>.csv")).not.toContain("<");
    expect(sanitizeDownloadFilename("")).toBe("download");
  });
});
