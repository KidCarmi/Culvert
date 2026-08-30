// 2E-B — Decryption page proofs: RBAC-exact mounting (viewer mounts ZERO
// mutation controls; operator gets exactly the volatile exclusion actions;
// admin adds privacy/rotation/tunables), node-local copy, the T2 privacy-off
// ceremony, the T3 typed rotation ceremony (bound to fresh truth, no
// CA-rotation wording confusion), the rotation unknown-outcome latch resolved
// by comparing key_id against fresh GET truth (never a blind retry), the
// tunables stale-conflict flow (form preserved), and the volatile-cache
// evict/clear semantics.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { DecryptionPage } from "../features/security/DecryptionPage";
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
// Mutable privacy fixture (the rotation-resolution tests move key_id).
let privacyKeyId: string;
let privacyRedact: boolean;

const HEALTH = {
  sessions: {
    total: 5,
    by_outcome: { inspected: 4, "future-outcome": 1 },
    by_decision_source: { policy_inspect: 5 },
    by_tls_version: { "1.3": 5 },
  },
  failures: {
    total: 1,
    by_category: { handshake: 1 },
    by_stage: { client_hello: 1 },
    top: [{ category: "handshake", stage: "client_hello", count: 1 }],
  },
  coverage: { inspected: 4, bypassed: 1, failed: 0, inspected_ratio: 0.8 },
  trend: [],
  autoexclude: {
    active: 1,
    pending: 0,
    hit_total: 2,
    rescue_total: 0,
    surge_total: 0,
    fail_open_profiles: 1,
    fail_open_rules: 1,
  },
};

const EXCLUSIONS = {
  exclusions: [
    {
      scope_id: "prof-1",
      scope_name: "fail-open",
      host: "pinned.example",
      reason: "client_pinned",
      learned_at: "2026-08-30T10:00:00Z",
      expires_at: "2026-08-30T11:00:00Z",
      hits: 3,
      client_count: 2,
    },
  ],
  truncated: false,
  stats: {
    active: 1,
    pending: 0,
    confirm_n: 2,
    ttl_secs: 43200,
    pinned_ttl_secs: 3600,
    window_secs: 600,
    max_entries: 4096,
  },
  tunables_revision: "sha256:tun1",
  fail_open_profiles: 1,
  fail_open_rules: 1,
  scope_rule_counts: { "prof-1": 1 },
  scope_names: { "prof-1": "fail-open" },
};

const TUNABLES_META = {
  defaults: {
    confirm_n: 2,
    ttl_secs: 43200,
    pinned_ttl_secs: 3600,
    window_secs: 600,
    max_entries: 4096,
  },
  bounds: {
    confirm_n: { min: 2, max: 10 },
    ttl_secs: { min: 60, max: 604800 },
    pinned_ttl_secs: { min: 60, max: 604800 },
    window_secs: { min: 10, max: 86400 },
    max_entries: { min: 256, max: 262144 },
  },
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
  privacyKeyId = "gen-aaaa";
  privacyRedact = true;
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
      if (url.includes("/api/decryption/health")) return okJSON(HEALTH);
      if (url.includes("/api/decryption/redaction"))
        return okJSON({
          redact_hosts: privacyRedact,
          scope: "traffic_destination",
          scope_fields: ["host", "uri", "dec.host", "dec.sni", "top_hosts"],
          key_provisioned: true,
          key_id: privacyKeyId,
          revision: `sha256:rev-${privacyKeyId}-${String(privacyRedact)}`,
        });
      if (url.includes("/api/decryption-exclusions/tunables"))
        return okJSON(TUNABLES_META);
      if (url.includes("/api/decryption-exclusions")) return okJSON(EXCLUSIONS);
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
    [{ path: "/security/decryption", element: <DecryptionPage /> }],
    { initialEntries: ["/security/decryption"] },
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
    expect(container.textContent).toContain("Coverage — since process start");
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

it("viewer: zero mutation controls on any tab; lifetime labels + node-local copy present", async () => {
  await mountPage("viewer");
  expect(container.textContent).toContain("since process start");
  await openTab("Destination Privacy", "Destination privacy");
  expect(container.textContent).toContain("Node-local");
  expect(buttons().some((t) => t.includes("Enable destination"))).toBe(false);
  expect(buttons().some((t) => t.includes("Disable destination"))).toBe(false);
  expect(buttons().some((t) => t.includes("Rotate pseudonym"))).toBe(false);
  await openTab("Auto-Exclusions", "Learned exclusions");
  expect(container.textContent).toContain("Volatile / runtime-generated");
  expect(buttons().some((t) => t === "Evict")).toBe(false);
  expect(buttons().some((t) => t.includes("Clear all"))).toBe(false);
  expect(container.textContent).not.toContain("Cache tuning");
});

it("operator: exactly the volatile exclusion actions; no privacy/tunable controls", async () => {
  await mountPage("operator");
  await openTab("Auto-Exclusions", "Learned exclusions");
  expect(buttons().some((t) => t === "Evict")).toBe(true);
  expect(buttons().some((t) => t.includes("Clear all"))).toBe(true);
  expect(container.textContent).not.toContain("Cache tuning");
  await openTab("Destination Privacy", "Destination privacy");
  expect(buttons().some((t) => t.includes("Disable destination"))).toBe(false);
  expect(buttons().some((t) => t.includes("Rotate pseudonym"))).toBe(false);
});

it("admin: privacy, rotation, and tunable controls mount", async () => {
  await mountPage("admin");
  await openTab("Destination Privacy", "Destination privacy");
  expect(buttons().some((t) => t.includes("Disable destination"))).toBe(true);
  expect(buttons().some((t) => t.includes("Rotate pseudonym"))).toBe(true);
  await openTab("Auto-Exclusions", "Learned exclusions");
  await flushUntil(() => {
    expect(container.textContent).toContain("Cache tuning");
  });
});

// ── destination privacy ceremonies ──────────────────────────────────────────

it("privacy OFF is a T2 ceremony; the PUT asserts the reviewed revision", async () => {
  await mountPage("admin");
  await openTab("Destination Privacy", "Destination privacy");
  clickButton((t) => t.includes("Disable destination"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Disable destination privacy");
    expect(container.textContent).toContain("More destination detail");
  });
  // Truthful semantics: never claims to disable encryption/inspection.
  expect(container.textContent).not.toContain("disables encryption");
  onMutate = () =>
    okJSON({
      redact_hosts: false,
      key_rotated: false,
      key_id: privacyKeyId,
      revision: "sha256:next",
    });
  clickButton((t) => t === "Disable destination privacy");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const put = mutations[0];
  if (put === undefined || !isRecord(put.body)) throw new Error("no body");
  expect(put.body["redact_hosts"]).toBe(false);
  expect(put.body["ifRevision"]).toBe("sha256:rev-gen-aaaa-true");
  expect(put.body["rotate_key"]).toBeUndefined();
});

it("rotation is a T3 typed ceremony bound to fresh truth, with no CA confusion", async () => {
  await mountPage("admin");
  await openTab("Destination Privacy", "Destination privacy");
  clickButton((t) => t.includes("Rotate pseudonym"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Rotate the destination-pseudonym key",
    );
    expect(container.textContent).toContain(
      "NOT the TLS inspection Root CA",
    );
    expect(container.textContent).toContain("no longer correlate");
  });
  // The typed word gates the confirm.
  const input = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes("Type ROTATE"),
  );
  if (input === undefined) throw new Error("typed-ceremony input not found");
  onMutate = () => {
    privacyKeyId = "gen-bbbb";
    return okJSON({
      redact_hosts: true,
      key_rotated: true,
      key_id: "gen-bbbb",
      revision: "sha256:rot",
    });
  };
  clickButton((t) => t === "Rotate pseudonym key");
  expect(mutations).toHaveLength(0); // refused before the word is typed
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    proto?.set?.call(input, "ROTATE");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const put = mutations[0];
  if (put === undefined || !isRecord(put.body)) throw new Error("no body");
  expect(put.body["rotate_key"]).toBe(true);
  expect(put.body["ifRevision"]).toBe("sha256:rev-gen-aaaa-true");
  await flushUntil(() => {
    expect(container.textContent).toContain("New pseudonym generation: gen-bbbb");
  });
});

it("rotation unknown outcome latches and resolves LANDED from fresh key_id truth", async () => {
  await mountPage("admin");
  await openTab("Destination Privacy", "Destination privacy");
  clickButton((t) => t.includes("Rotate pseudonym"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type ROTATE");
  });
  const input = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes("Type ROTATE"),
  );
  if (input === undefined) throw new Error("typed input not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    proto?.set?.call(input, "ROTATE");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  // The rotation LANDED on the appliance but the response was lost.
  onMutate = () => {
    privacyKeyId = "gen-cccc";
    return Promise.reject(new TypeError("network down"));
  };
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  // Resolution comes from fresh GET truth — never a blind repeat.
  clickButton((t) => t === "Refresh state");
  await flushUntil(() => {
    expect(container.textContent).toContain("Rotation landed");
    expect(container.textContent).toContain("exactly once");
  });
  expect(mutations).toHaveLength(1); // no second rotation was dispatched
});

// ── auto-exclusions ─────────────────────────────────────────────────────────

it("evict: exact target, volatile copy, refreshed truth after", async () => {
  await mountPage("operator");
  await openTab("Auto-Exclusions", "Learned exclusions");
  clickButton((t) => t === "Evict");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Evict the exclusion for pinned.example",
    );
    expect(container.textContent).toContain(
      "may be attempted for decryption again",
    );
  });
  onMutate = () => okJSON({ ok: true, removed: true });
  clickButton((t) => t === "Evict exclusion");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  expect(mutations[0]?.url).toBe(
    "/api/decryption-exclusions?scope=prof-1&host=pinned.example",
  );
  await flushUntil(() => {
    expect(container.textContent).toContain("evicted");
  });
});

it("clear-all: T2 ceremony that never claims to delete policy", async () => {
  await mountPage("operator");
  await openTab("Auto-Exclusions", "Learned exclusions");
  clickButton((t) => t.includes("Clear all learned exclusions"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Clear all learned exclusions");
    expect(container.textContent).toContain(
      "does not delete Decryption Profiles or policy rules",
    );
  });
  onMutate = () => okJSON({ ok: true, cleared: 1 });
  clickButton((t) => t === "Clear all exclusions");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
    expect(container.textContent).toContain("Cleared 1 learned exclusion");
  });
  expect(mutations[0]?.method).toBe("DELETE");
  expect(mutations[0]?.url).toBe("/api/decryption-exclusions");
});

// ── tunables ────────────────────────────────────────────────────────────────

it("tunables: tightening saves directly with the fence; a stale 409 preserves the form", async () => {
  await mountPage("admin");
  await openTab("Auto-Exclusions", "Learned exclusions");
  await flushUntil(() => {
    expect(container.textContent).toContain("Cache tuning");
  });
  const confirmInput = Array.from(container.querySelectorAll("input")).find(
    (i) => (i.labels?.[0]?.textContent ?? "").includes("Confirm count"),
  );
  if (confirmInput === undefined) throw new Error("confirm_n input not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    proto?.set?.call(confirmInput, "4"); // tightening — no ceremony
    confirmInput.dispatchEvent(new Event("input", { bubbles: true }));
  });
  onMutate = () =>
    okJSON(
      {
        error: "auto-exclusion tunables changed since you loaded it",
        currentRevision: "sha256:tunX",
        yourRevision: "sha256:tun1",
      },
      409,
    );
  clickButton((t) => t === "Save tunables");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  expect(mutations[0]?.url).toContain("ifRevision=sha256%3Atun1");
  await flushUntil(() => {
    expect(container.textContent).toContain("your entries are preserved");
  });
  // The candidate value survives the conflict for review.
  expect(confirmInput.value).toBe("4");
});

it("tunables: a relaxing change requires the guardrail ceremony", async () => {
  await mountPage("admin");
  await openTab("Auto-Exclusions", "Learned exclusions");
  await flushUntil(() => {
    expect(container.textContent).toContain("Cache tuning");
  });
  const ttlInput = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes("Entry TTL"),
  );
  if (ttlInput === undefined) throw new Error("ttl input not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    proto?.set?.call(ttlInput, "86400"); // longer bypass — relaxation
    ttlInput.dispatchEvent(new Event("input", { bubbles: true }));
  });
  clickButton((t) => t === "Save tunables");
  await flushUntil(() => {
    expect(container.textContent).toContain("Relax auto-exclusion guardrails");
  });
  expect(mutations).toHaveLength(0); // nothing dispatched before confirmation
  onMutate = () =>
    okJSON({
      confirm_n: 2,
      ttl_secs: 86400,
      pinned_ttl_secs: 3600,
      window_secs: 600,
      max_entries: 4096,
      revision: "sha256:tun2",
    });
  clickButton((t) => t === "Save relaxed tunables");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
    expect(container.textContent).toContain("durable and applied");
  });
});

it("no interaction touches CDR, content-security writes, or certificate endpoints", async () => {
  await mountPage("admin");
  await openTab("Destination Privacy", "Destination privacy");
  await openTab("Auto-Exclusions", "Learned exclusions");
  for (const r of requested) {
    expect(r).not.toContain("/api/cdr");
    expect(r).not.toContain("/api/security-scan");
    expect(r).not.toContain("/api/certs");
    expect(r).not.toContain("/api/ca/");
  }
});
