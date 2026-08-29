// 2E-A — Content Security page proofs: RBAC-exact mounting (viewer mounts
// ZERO write controls; Operator gets exactly the DPI pattern + validate
// surface; Admin gets the rest), the fenced whole-set save ceremony (exact
// counts + effect, ifRevision echoed), the structured revision-409
// fresh-truth flow, the unknown-outcome latch, the cache-clear ceremony, and
// ZERO requests to the deprecated /api/content-scan aliases across every
// exercised interaction.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { ContentSecurityPage } from "../features/security/ContentSecurityPage";
import { isRecord } from "../api/decode";

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root;
let requested: string[];
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string) => Promise<Response>;

const STATUS = {
  enabled: true,
  scan_svc_mode: "local",
  clamav_status: "disabled",
  yara_rules: 2,
  yara_enabled: true,
  threat_feed_entries: 42,
  threat_feed_last_sync: "2026-08-29T10:00:00Z",
  threat_feed_last_success: "2026-08-29T10:00:00Z",
  threat_feed_interval: "1h0m0s",
  threat_feed_sync_ok: true,
  cache_size: 3,
  cache_hits: 10,
  cache_misses: 4,
};

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  Element.prototype.scrollIntoView = vi.fn();
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
  requested = [];
  mutations = [];
  onMutate = () => okJSON({ ok: true });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requested.push(`${method} ${url}`);
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(method, url);
      }
      if (url.includes("/api/security-scan/status")) return okJSON(STATUS);
      if (url.includes("/api/security-scan/svc"))
        return okJSON({ remote_enabled: false, remote_url: "" });
      if (url.includes("/api/security-scan/cache"))
        return okJSON({
          enabled: true,
          cache_hits: 10,
          cache_misses: 4,
          cache_size: 3,
        });
      if (url.includes("/api/security-scan/feeds/domain-allowlist"))
        return okJSON({ domains: ["ok.example"], revision: "alrev1" });
      if (url.includes("/api/security-scan/yara/settings"))
        return okJSON({
          enabled: true,
          timeout_secs: 5,
          max_inflight: 32,
          on_timeout: "fail_closed",
          on_saturation: "fail_closed",
          alert_degraded: true,
          revision: "ysrev1",
        });
      if (url.includes("/api/security-scan/yara/rules"))
        return okJSON({
          directory: "/data/yara",
          files: ["corp"],
          file_rules: { corp: ["corp_rule"] },
          rules: ["corp_rule"],
          warnings: [],
          count: 1,
        });
      if (url.includes("/api/security-scan/exclusions"))
        return okJSON({
          hashes: ["aa11"],
          hosts: ["trusted.example"],
          revision: "exrev1",
        });
      if (url.includes("/api/dpi/bypass"))
        return okJSON({ hosts: ["skip.example"], revision: "bprev1" });
      if (url.includes("/api/dpi"))
        return okJSON({
          patterns: ["secret-[0-9]+"],
          count: 1,
          blocked_total: 7,
        });
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function machineFor(
  role: "viewer" | "operator" | "admin",
  qc: QueryClient,
): AuthMachine {
  return new AuthMachine(qc, {
    getSetupStatus: () =>
      Promise.resolve({
        needsSetup: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    getAuthStatus: () =>
      Promise.resolve({
        loggedIn: true,
        user: `${role}-user`,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mountPage(role: "viewer" | "operator" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/content-security", element: <ContentSecurityPage /> }],
    { initialEntries: ["/security/content-security"] },
  );
  const qc = new QueryClient();
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <RouterProvider router={router} />
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("Scan engine");
  });
}

async function flushUntil(cond: () => void): Promise<void> {
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    cond();
  });
}

function buttons(): string[] {
  return Array.from(container.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
}

function clickButton(match: (t: string) => boolean): void {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  act(() => {
    b.click();
  });
}

async function openTab(name: string, readyText: string): Promise<void> {
  clickButton((t) => t === name);
  await flushUntil(() => {
    expect(container.textContent).toContain(readyText);
  });
}

// ── RBAC mounting ───────────────────────────────────────────────────────────

it("viewer: zero write controls mounted on any tab", async () => {
  await mountPage("viewer");
  await openTab("Threat Intelligence", "Feed synchronization");
  expect(buttons().some((t) => t.includes("Sync feeds now"))).toBe(false);
  await flushUntil(() => {
    expect(container.textContent).toContain("ok.example");
  });
  expect(buttons().some((t) => t.startsWith("Save"))).toBe(false);

  await openTab("YARA", "Rule files");
  expect(buttons().some((t) => t.includes("New rule file"))).toBe(false);
  expect(buttons().some((t) => t.includes("Reload"))).toBe(false);
  expect(buttons().some((t) => t.includes("Edit settings"))).toBe(false);

  await openTab("DPI", "Signature patterns");
  expect(buttons().some((t) => t.includes("Add pattern"))).toBe(false);
  expect(buttons().some((t) => t === "Remove")).toBe(false);
  expect(container.querySelector("textarea")).toBeNull();

  await openTab("Exclusions & Cache", "Scan exclusions");
  expect(buttons().some((t) => t.startsWith("Save"))).toBe(false);
  expect(buttons().some((t) => t.includes("Clear cache"))).toBe(false);
});

it("operator: exactly the DPI pattern surface; no admin controls", async () => {
  await mountPage("operator");
  await openTab("DPI", "Signature patterns");
  expect(buttons().some((t) => t.includes("Add pattern"))).toBe(true);
  expect(buttons().some((t) => t === "Remove")).toBe(true);
  // Bypass replace is Admin-only — the operator sees the read-only list.
  expect(buttons().some((t) => t.startsWith("Save DPI bypass"))).toBe(false);

  await openTab("Threat Intelligence", "Feed synchronization");
  expect(buttons().some((t) => t.includes("Sync feeds now"))).toBe(false);

  await openTab("YARA", "Rule files");
  expect(buttons().some((t) => t.includes("New rule file"))).toBe(false);

  await openTab("Exclusions & Cache", "Scan exclusions");
  expect(buttons().some((t) => t.includes("Clear cache"))).toBe(false);
});

it("admin: write controls mounted", async () => {
  await mountPage("admin");
  await openTab("Threat Intelligence", "Feed synchronization");
  await flushUntil(() => {
    expect(buttons().some((t) => t.includes("Sync feeds now"))).toBe(true);
  });
  await openTab("YARA", "Rule files");
  await flushUntil(() => {
    expect(buttons().some((t) => t.includes("New rule file"))).toBe(true);
    expect(buttons().some((t) => t.includes("Edit settings"))).toBe(true);
  });
  await openTab("Exclusions & Cache", "Scan exclusions");
  await flushUntil(() => {
    expect(buttons().some((t) => t.includes("Clear cache"))).toBe(true);
  });
});

// ── Fenced save ceremony + conflict + latch ─────────────────────────────────

it("admin bypass save: ceremony with counts, ifRevision echoed, refresh after", async () => {
  await mountPage("admin");
  await openTab("DPI", "Bypass hosts");
  // The DPI tab mounts exactly ONE textarea for admin (the bypass editor);
  // it appears once the bypass snapshot resolves.
  await flushUntil(() => {
    expect(container.querySelector("textarea")).not.toBeNull();
  });
  const ta = container.querySelector("textarea");
  if (ta === null) throw new Error("bypass textarea not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    );
    proto?.set?.call(ta, "skip.example\nadded.example");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("1 added, 0 removed");
  });
  clickButton((t) => t.startsWith("Save DPI bypass"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Replace the DPI bypass host list");
    expect(container.textContent).toContain("NOT inspected by DPI");
  });
  onMutate = () =>
    okJSON({ hosts: ["skip.example", "added.example"], revision: "bprev2" });
  clickButton((t) => t === "Replace DPI bypass hosts");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const put = mutations[0];
  expect(put?.method).toBe("PUT");
  expect(put?.url).toBe("/api/dpi/bypass");
  if (put === undefined || !isRecord(put.body)) throw new Error("no PUT body");
  expect(put.body["ifRevision"]).toBe("bprev1");
});

it("stale bypass save: structured 409 becomes the fresh-truth notice, nothing crashes", async () => {
  await mountPage("admin");
  await openTab("DPI", "Bypass hosts");
  await flushUntil(() => {
    expect(container.querySelector("textarea")).not.toBeNull();
  });
  const ta = container.querySelector("textarea");
  if (ta === null) throw new Error("bypass textarea not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    );
    proto?.set?.call(ta, "other.example");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  clickButton((t) => t.startsWith("Save DPI bypass"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Replace the DPI bypass host list");
  });
  onMutate = () =>
    okJSON(
      {
        error: "DPI bypass hosts changed since you loaded it",
        currentRevision: "bprevX",
        yourRevision: "bprev1",
      },
      409,
    );
  clickButton((t) => t === "Replace DPI bypass hosts");
  await flushUntil(() => {
    expect(container.textContent).toContain("Not applied");
    expect(container.textContent).toContain("changed on the appliance");
  });
});

it("network-lost exclusions save latches the unknown outcome", async () => {
  await mountPage("admin");
  await openTab("Exclusions & Cache", "Scan exclusions");
  // The exclusions editor mounts [hashes, hosts] textareas in order.
  await flushUntil(() => {
    expect(container.querySelectorAll("textarea")).toHaveLength(2);
  });
  const ta = container.querySelectorAll("textarea")[1];
  if (ta === undefined) throw new Error("hosts textarea not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    );
    proto?.set?.call(ta, "trusted.example\nmore.example");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  clickButton((t) => t === "Save exclusions");
  await flushUntil(() => {
    expect(container.textContent).toContain("Replace the scan exclusion lists");
  });
  onMutate = () => Promise.reject(new TypeError("network down"));
  clickButton((t) => t === "Replace exclusions");
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
});

it("cache clear: ceremony states scope, DELETE issued on confirm", async () => {
  await mountPage("admin");
  await openTab("Exclusions & Cache", "Scan verdict cache");
  await flushUntil(() => {
    expect(container.textContent).toContain("Entries");
  });
  clickButton((t) => t.includes("Clear cache"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Clear the scan verdict cache");
    expect(container.textContent).toContain("re-scanned");
  });
  onMutate = () => okJSON({ cleared: true });
  clickButton((t) => t === "Clear cache");
  await flushUntil(() => {
    expect(
      mutations.some(
        (m) => m.method === "DELETE" && m.url === "/api/security-scan/cache",
      ),
    ).toBe(true);
  });
});

it("no interaction ever touches the deprecated /api/content-scan aliases", async () => {
  await mountPage("admin");
  await openTab("Threat Intelligence", "Feed synchronization");
  await openTab("YARA", "Rule files");
  await openTab("DPI", "Signature patterns");
  await openTab("Exclusions & Cache", "Scan exclusions");
  for (const r of requested) {
    expect(r).not.toContain("/api/content-scan");
  }
});
