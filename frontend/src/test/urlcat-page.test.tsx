// 2D-B page proofs: category list truth (Admin vs Baseline type, "UT1
// community feed" label — never generic "feed-backed"), fenced strict create
// + structured stale-revision 409 handling, the bounded host editor's line
// count / cap mirror, delete blocked by references (server 409 authoritative),
// manual lookup with "Uncategorized" as taxonomy truth, signed status null +
// stale (LKG-serving) + unknown-state rendering, managed-DP read-only
// settings posture, cluster_publish_rejected as local-save-succeeded, and the
// overrides clear-all ceremony with counts.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { UrlCategoriesPage } from "../features/objects/UrlCategoriesPage";

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
let stateBody: unknown;
let refsBody: unknown;
let statusBody: unknown;
let settingsBody: unknown;
let overridesBody: unknown;
let feedStatusBody: unknown;
let lookupBody: unknown;
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string) => Promise<Response>;

const SIGNED_STATUS_BASE = {
  state: "fresh",
  configured: true,
  enabled: true,
  managed: true,
  authority: "standalone",
  protocol: "signed_manifest_v1",
  url: "",
  active_source: "downloaded",
  provenance: "downloaded",
  signature_status: "verified",
  compiled_trusted: false,
  stale: false,
  host_count: 12,
  category_count: 3,
  override_count: 1,
  not_modified: false,
  failures_since_start: 0,
  consecutive_failures: 0,
  never_succeeded: false,
  syncing: false,
  waiting_for_authority: false,
  recovering: false,
  critical: false,
  active_feed_version: 7,
  generated_at: "2026-08-20T00:00:00Z",
  manifest_expires_at: "2027-02-20T00:00:00Z",
  last_activation_delta: { hosts_added: 5, hosts_removed: 0, hosts_changed: 1 },
  last_successful_activation: "2026-08-20T01:00:00Z",
  last_outcome: "ok",
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
  stateBody = {
    categories: [
      { name: "Social", hosts: ["a.example"], builtIn: false, feedBacked: true },
      { name: "Finance", hosts: ["b.example"], builtIn: true, feedBacked: false },
    ],
    revision: "rev-1",
  };
  refsBody = { object: { type: "category", name: "Social" }, referencedBy: [] };
  statusBody = SIGNED_STATUS_BASE;
  settingsBody = {
    managed: true,
    enabled: true,
    url: "",
    protocol: "signed_manifest_v1",
    refresh_seconds: 0,
    official_url:
      "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
    editable: true,
    revision: "srev-1",
    resolved: {
      url: "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
      protocol: "signed_manifest_v1",
      enabled: true,
      refresh_seconds: 86400,
    },
  };
  overridesBody = {
    overrides: {
      added: { "work.example.com": "business" },
      tombstones: ["ads.example.com"],
    },
    editable: true,
    revision: "orev-1",
  };
  feedStatusBody = {
    ut1: {
      configured: true,
      entries: 4200,
      lastSync: "2026-08-27T00:00:00Z",
      intervalSeconds: 86400,
      syncFailures: 0,
    },
    saas: {
      configured: true,
      enabled: true,
      state: "fresh",
      activeFeedVersion: 7,
      provenance: "downloaded",
      lastSuccess: "2026-08-20T01:00:00Z",
      syncFailures: 0,
      stale: false,
    },
  };
  lookupBody = {
    host: "unknown.example",
    category: "",
    tier: "",
    matchedBy: "",
    blocked: false,
    blockSource: "",
  };
  mutations = [];
  onMutate = () => okJSON({ name: "x", revision: "rev-2" });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(method, url);
      }
      if (url.includes("/api/objects/references")) return okJSON(refsBody);
      if (url.includes("/api/urlcat/state")) return okJSON(stateBody);
      if (url.includes("/api/urlcat/lookup")) return okJSON(lookupBody);
      if (url.includes("/api/urlcat/feed-status")) return okJSON(feedStatusBody);
      if (url.includes("/api/saas-feed/status")) return okJSON(statusBody);
      if (url.includes("/api/saas-feed/settings")) return okJSON(settingsBody);
      if (url.includes("/api/saas-feed/overrides")) return okJSON(overridesBody);
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

async function mount(role: "viewer" | "operator" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/objects/url-categories", element: <UrlCategoriesPage /> }],
    { initialEntries: ["/objects/url-categories"] },
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
    expect(container.textContent).toContain("Social");
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

function findButton(match: (t: string) => boolean): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  return b;
}

function click(b: HTMLButtonElement): void {
  act(() => {
    b.click();
  });
}

// ── Categories tab truth ───────────────────────────────────────────────────

it("renders type truth and the UT1 community label — never generic feed-backed", async () => {
  await mount("viewer");
  expect(container.textContent).toContain("Admin");
  expect(container.textContent).toContain("Baseline / built-in");
  expect(container.textContent).toContain("UT1 community feed");
  expect(container.textContent).not.toContain("Feed-backed");
  // Viewer: no write controls.
  const buttons = Array.from(container.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
  expect(buttons.some((t) => t.includes("Create category"))).toBe(false);
});

it("strict create sends the fenced POST and the editor mirrors the host cap", async () => {
  await mount("operator");
  click(findButton((t) => t.includes("Create category")));
  const name = container.querySelector<HTMLInputElement>("dialog input");
  const hostsTa = container.querySelector<HTMLTextAreaElement>("dialog textarea");
  if (name === null || hostsTa === null) throw new Error("editor not open");
  act(() => {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set?.call(name, "Media");
    name.dispatchEvent(new Event("input", { bubbles: true }));
    Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set?.call(hostsTa, "m1.example\nm2.example\n");
    hostsTa.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("2 hosts");
    expect(container.textContent).toContain("server limit 10000");
  });
  click(findButton((t) => t === "Create"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  if (m === undefined) throw new Error("no mutation");
  expect(m.method).toBe("POST");
  expect(m.url).toContain("ifRevision=rev-1");
  expect(m.body).toEqual({ name: "Media", hosts: ["m1.example", "m2.example"] });
});

it("a stale-revision 409 renders the Not applied notice — never a silent overwrite", async () => {
  await mount("operator");
  onMutate = () =>
    okJSON(
      {
        error: "taxonomy revision conflict",
        currentRevision: "rev-9",
        yourRevision: "rev-1",
      },
      409,
    );
  click(findButton((t) => t.includes("Edit hosts")));
  click(findButton((t) => t === "Save hosts"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Not applied");
    expect(container.textContent).toContain("stale revision");
  });
});

it("a delete refused by references renders the server's consumers", async () => {
  await mount("operator");
  onMutate = () =>
    okJSON(
      {
        error: "category is referenced",
        object: { type: "category", name: "Social" },
        referencedBy: [
          { consumerType: "rule", id: "01AB", name: "Block Social" },
        ],
      },
      409,
    );
  click(findButton((t) => t.includes("Delete")));
  await flushUntil(() => {
    expect(container.textContent).toContain("Delete category — Social");
  });
  click(findButton((t) => t === "Delete category"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Delete refused — still referenced");
    expect(container.textContent).toContain("Block Social");
  });
});

// ── Lookup tab ─────────────────────────────────────────────────────────────

it("lookup runs manually and renders Uncategorized as taxonomy truth", async () => {
  await mount("viewer");
  click(findButton((t) => t === "Lookup"));
  const input = container.querySelector<HTMLInputElement>("input");
  if (input === null) throw new Error("no lookup input");
  act(() => {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set?.call(input, "unknown.example");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await flushUntil(() => {
    expect(findButton((t) => t === "Run lookup").disabled).toBe(false);
  });
  click(findButton((t) => t === "Run lookup"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Uncategorized");
    expect(container.textContent).toContain("not an access verdict");
  });
});

// ── Signed SaaS Feed tab ───────────────────────────────────────────────────

it("stale state renders the LKG-serving truth, never 'not serving'", async () => {
  statusBody = { ...SIGNED_STATUS_BASE, state: "stale", stale: true };
  await mount("admin");
  click(findButton((t) => t === "Signed SaaS Feed"));
  await flushUntil(() => {
    expect(container.textContent).toContain("stale (LKG serving)");
    expect(container.textContent).toContain(
      "Traffic categorization has NOT stopped",
    );
  });
});

it("never_succeeded nulls render as Never activated — no zeros, no epochs", async () => {
  statusBody = {
    ...SIGNED_STATUS_BASE,
    state: "embedded",
    never_succeeded: true,
    active_feed_version: null,
    generated_at: null,
    manifest_expires_at: null,
    last_activation_delta: null,
    last_successful_activation: null,
    last_outcome: null,
  };
  await mount("admin");
  click(findButton((t) => t === "Signed SaaS Feed"));
  await flushUntil(() => {
    expect(container.textContent).toContain("No signed generation");
    expect(container.textContent).toContain("Never activated");
    expect(container.textContent).not.toContain("0 new hosts");
    expect(container.textContent).not.toContain("1970");
  });
});

it("an unknown state renders the degraded callout — never coerced healthy", async () => {
  statusBody = { ...SIGNED_STATUS_BASE, state: "hyper_fresh_v2" };
  await mount("admin");
  click(findButton((t) => t === "Signed SaaS Feed"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Unknown feed state");
    expect(container.textContent).toContain("hyper_fresh_v2");
  });
});

it("managed-DP settings render CP ownership and no save control", async () => {
  settingsBody = {
    managed: true,
    enabled: true,
    url: "",
    protocol: "signed_manifest_v1",
    refresh_seconds: 0,
    official_url:
      "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
    editable: false,
    revision: "srev-1",
  };
  statusBody = { ...SIGNED_STATUS_BASE, authority: "managed-data-plane" };
  await mount("admin");
  click(findButton((t) => t === "Signed SaaS Feed"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Control-plane managed");
  });
  const buttons = Array.from(container.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
  expect(buttons.some((t) => t === "Save configuration")).toBe(false);
});

it("cluster_publish_rejected renders local-saved-fleet-rejected — never Save failed", async () => {
  await mount("admin");
  click(findButton((t) => t === "Signed SaaS Feed"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Save configuration");
  });
  onMutate = () =>
    okJSON({
      managed: true,
      enabled: true,
      url: "",
      protocol: "signed_manifest_v1",
      refresh_seconds: 43200,
      official_url:
        "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
      editable: true,
      revision: "srev-2",
      cluster_publish_rejected: "snapshot rejected",
    });
  // Interval-only change: plain save (no T2 dialog).
  const refreshInput = Array.from(
    container.querySelectorAll<HTMLInputElement>("input"),
  ).find((el) => el.placeholder === "24h");
  if (refreshInput === undefined) throw new Error("no interval input");
  act(() => {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set?.call(refreshInput, "12h");
    refreshInput.dispatchEvent(new Event("input", { bubbles: true }));
  });
  click(findButton((t) => t === "Save configuration"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Saved locally — fleet publish rejected",
    );
    expect(container.textContent).toContain(
      "Data-plane nodes remain on the last valid published configuration",
    );
  });
  const m = mutations[0];
  if (m === undefined) throw new Error("no mutation");
  expect(m.url).toContain("ifRevision=srev-1");
});

// ── Overrides tab ──────────────────────────────────────────────────────────

it("overrides render subtree copy and clear-all shows counts in the T2 dialog", async () => {
  await mount("admin");
  click(findButton((t) => t === "Overrides"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Subtree scope");
    expect(container.textContent).toContain("Added (1)");
    expect(container.textContent).toContain("Tombstones (1)");
  });
  // Empty every editor → clear-all ceremony with counts.
  const tas = Array.from(container.querySelectorAll<HTMLTextAreaElement>("textarea"));
  act(() => {
    for (const ta of tas) {
      Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value",
      )?.set?.call(ta, "");
      ta.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
  await flushUntil(() => {
    expect(findButton((t) => t === "Clear all overrides").disabled).toBe(false);
  });
  click(findButton((t) => t === "Clear all overrides"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Clear ALL overrides");
    expect(container.textContent).toContain("Total to remove");
  });
  onMutate = () => okJSON({ ok: true, overrides: {}, revision: "none" });
  click(findButton((t) => t === "Clear all"));
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const m = mutations[0];
  if (m === undefined) throw new Error("no mutation");
  expect(m.method).toBe("PUT");
  expect(m.url).toContain("ifRevision=orev-1");
  expect(m.body).toEqual({});
});

it("a stale override replacement renders the conflict notice and keeps the set", async () => {
  await mount("admin");
  click(findButton((t) => t === "Overrides"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Added (1)");
  });
  const ta = container.querySelector<HTMLTextAreaElement>("textarea");
  if (ta === null) throw new Error("no textarea");
  act(() => {
    Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set?.call(ta, "other.example.com = business");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  onMutate = () =>
    okJSON(
      {
        error: "override revision conflict",
        currentRevision: "orev-9",
        yourRevision: "orev-1",
      },
      409,
    );
  await flushUntil(() => {
    expect(findButton((t) => t === "Replace override set").disabled).toBe(false);
  });
  click(findButton((t) => t === "Replace override set"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Replace override set");
  });
  click(findButton((t) => t === "Replace set"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Not applied — overrides changed");
  });
});
