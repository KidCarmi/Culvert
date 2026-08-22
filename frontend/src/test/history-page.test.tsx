// 2A-M §5/§8: History & Storage role posture + unknown-outcome doctrine.
// Viewer mounts NO mutation controls (not disabled fakes — absent); an
// admin Save whose outcome the client never observed (network loss) keeps
// the prior snapshot, declares the outcome unconfirmed, blocks further
// mutations, and resolves ONLY via a fresh successful GET. Critically, a
// FAILED refresh must NOT resolve the latch: the query deliberately keeps
// the previous snapshot in cache on a failed refetch, so cached data is
// never proof of server confirmation — only a refetch that actually
// SUCCEEDED (fresh dataUpdatedAt) clears mutation uncertainty.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createQueryClient } from "../api/query";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { HistoryPage } from "../features/monitor/HistoryPage";

const retentionJSON = {
  enabled: true,
  configurable: true,
  retentionDays: 30,
  retentionMaxGB: 2.5,
  encrypted: false,
  encryptionAvailable: false,
  usage: {
    enabled: true,
    bytes: 4096,
    dropped: 0,
    pruned: 0,
    count: 42,
    capped: false,
    oldestMs: 0,
  },
  estimate: {
    avgEntryBytes: 350,
    reqPerMin: 1,
    bytesPerDay: 500_000,
    bytesPerWeek: 3_500_000,
    bytesPerMonth: 15_000_000,
  },
  guard: {
    criticalDiskPct: 95,
    minimalMode: false,
    loggingMode: "Normal",
    lastCleanupMs: 0,
    lastCleanupReason: "",
    pressureBytes: 0,
    pressureCount: 0,
    warning: "",
  },
};

// A second, distinguishable server state (S2) so resolution tests prove
// FRESH server adoption rather than a re-render of cached S1.
const retentionJSONv2 = {
  ...retentionJSON,
  retentionDays: 14,
  usage: { ...retentionJSON.usage, count: 7 },
};

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  // jsdom does not implement <dialog>.showModal()/close() (the prototype has
  // no such members to spy on); the wrapper only needs the `open` property to
  // track, so model exactly that.
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
  role: "viewer" | "admin",
  qc: ReturnType<typeof createQueryClient>,
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
        user: role,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

function okJSON(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

// Mutable per-test handlers so a test can change what the NEXT GET (or the
// purge POST) does mid-flow — e.g. serve S1, then fail, then serve S2.
let onGet: () => Promise<Response>;
let onPost: () => Promise<Response>;

/** Route the page's fetches: GET retention serves onGet (default: the S1
 * fixture); PUT behavior is injectable; POST purge serves onPost. */
function stubFetch(onPut: () => Promise<Response>): ReturnType<typeof vi.fn> {
  onGet = () => okJSON(retentionJSON);
  onPost = () => Promise.reject(new TypeError("no POST expected"));
  const fn = vi.fn((input: unknown, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/api/logs/retention") && method === "GET") {
      return onGet();
    }
    if (url.includes("/api/logs/retention") && method === "PUT") {
      return onPut();
    }
    if (url.includes("/api/logs/purge") && method === "POST") {
      return onPost();
    }
    return Promise.reject(new TypeError(`unexpected fetch ${method} ${url}`));
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

async function mount(role: "viewer" | "admin"): Promise<void> {
  const qc = createQueryClient();
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <HistoryPage />
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    expect(container.textContent).toContain("Persistent history");
  });
}

function buttons(): string[] {
  return Array.from(container.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
}

function findButton(match: (text: string) => boolean): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  expect(b).toBeDefined();
  if (b === undefined) throw new Error("button not found");
  return b;
}

/** dd value rendered next to the Posture card's dt label. */
function kv(label: string): string {
  const dt = Array.from(container.querySelectorAll("dt")).find(
    (d) => d.textContent === label,
  );
  return dt?.nextElementSibling?.textContent ?? "";
}

async function settle(): Promise<void> {
  await act(async () => {
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

async function clickAndSettle(btn: HTMLButtonElement): Promise<void> {
  await act(async () => {
    btn.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

it("viewer mounts the read surface + export, and NO mutation controls exist", async () => {
  stubFetch(() => Promise.reject(new TypeError("no PUT expected")));
  await mount("viewer");
  const b = buttons();
  expect(b.some((t) => t.includes("Export recent memory — JSON"))).toBe(true);
  expect(b.some((t) => t.includes("Export recent memory — CSV"))).toBe(true);
  expect(b.some((t) => t.includes("Edit history settings"))).toBe(false);
  expect(b.some((t) => t.includes("Purge"))).toBe(false);
  expect(container.textContent).toContain("Retention days");
});

it("admin Save with an unobserved outcome: prior snapshot kept, outcome declared unconfirmed, mutations blocked until a fresh GET", async () => {
  stubFetch(() => Promise.reject(new TypeError("network down"))); // PUT dies
  await mount("admin");

  // Enter edit and save.
  act(() => {
    Array.from(container.querySelectorAll("button"))
      .find((b) => b.textContent?.includes("Edit history settings"))
      ?.click();
  });
  await vi.waitFor(() => {
    expect(container.textContent).toContain("Save history settings");
  });
  await act(async () => {
    Array.from(container.querySelectorAll("button"))
      .find((b) => b.textContent?.includes("Save history settings"))
      ?.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });

  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    expect(container.textContent).toContain("Save outcome unconfirmed");
  });
  // Prior snapshot still truthful; nothing claims the settings changed.
  expect(container.textContent).toContain("Retention days");
  expect(container.textContent).not.toContain("Save failed, nothing changed");
  // Mutations are blocked while unresolved: the edit affordance is disabled,
  // purge is disabled.
  const editBtn = Array.from(container.querySelectorAll("button")).find((b) =>
    b.textContent?.includes("Edit history settings"),
  );
  expect(editBtn?.disabled).toBe(true);
  const purgeBtn = Array.from(container.querySelectorAll("button")).find((b) =>
    b.textContent?.includes("Purge retained history"),
  );
  expect(purgeBtn?.disabled).toBe(true);

  // A fresh successful GET resolves the uncertainty.
  await act(async () => {
    Array.from(container.querySelectorAll("button"))
      .find((b) => b.textContent?.includes("Refresh current state"))
      ?.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    expect(container.textContent).not.toContain("Save outcome unconfirmed");
  });
  expect(editBtn?.disabled).toBe(false);
});

it("unknown Save: a FAILED refresh keeps the latch and blocked controls; only a fresh successful GET (S2) resolves and is adopted", async () => {
  stubFetch(() => Promise.reject(new TypeError("network down"))); // PUT dies
  await mount("admin");
  // A. initial GET succeeded with S1.
  expect(kv("Retention days")).toBe("30");

  // B/C. Save with an unobserved outcome → unknown latch.
  await clickAndSettle(findButton((t) => t.includes("Edit history settings")));
  await vi.waitFor(() => {
    expect(container.textContent).toContain("Save history settings");
  });
  await clickAndSettle(findButton((t) => t.includes("Save history settings")));
  await vi.waitFor(async () => {
    await settle();
    expect(container.textContent).toContain("Save outcome unconfirmed");
  });

  // E. the resolving refresh FAILS. The cache deliberately keeps S1, so
  // cached data must NOT be read as server confirmation.
  onGet = () => Promise.reject(new TypeError("still down"));
  await clickAndSettle(findButton((t) => t.includes("Refresh current state")));
  await vi.waitFor(async () => {
    await settle();
    // G. SnapshotBar reports the failed refresh over the previous snapshot.
    expect(container.textContent).toContain(
      "Refresh failed — showing previous snapshot",
    );
  });
  // F. old S1 remains rendered.
  expect(kv("Retention days")).toBe("30");
  // H. the unknown latch REMAINS.
  expect(container.textContent).toContain("Save outcome unconfirmed");
  // I/J. Edit and Purge remain blocked.
  expect(findButton((t) => t.includes("Edit history settings")).disabled).toBe(
    true,
  );
  expect(
    findButton((t) => t.includes("Purge retained history…")).disabled,
  ).toBe(true);

  // K. a later GET succeeds with S2 (distinguishable from cached S1).
  onGet = () => okJSON(retentionJSONv2);
  await clickAndSettle(findButton((t) => t.includes("Refresh current state")));
  await vi.waitFor(async () => {
    await settle();
    // L. only now does the latch clear.
    expect(container.textContent).not.toContain("Save outcome unconfirmed");
  });
  // M. controls re-enable.
  expect(findButton((t) => t.includes("Edit history settings")).disabled).toBe(
    false,
  );
  expect(
    findButton((t) => t.includes("Purge retained history…")).disabled,
  ).toBe(false);
  // N. rendered state is the FRESH server state S2, not cached S1.
  expect(kv("Retention days")).toBe("14");
});

it("unknown Purge: failed refresh keeps 'Purge outcome unconfirmed' and no success ack; a later successful GET resolves", async () => {
  stubFetch(() => Promise.reject(new TypeError("no PUT expected")));
  await mount("admin");
  onPost = () => Promise.reject(new TypeError("network down")); // purge dies

  // A. run the T2 ceremony into an unknown outcome.
  await clickAndSettle(
    findButton((t) => t.includes("Purge retained history…")),
  );
  await vi.waitFor(() => {
    expect(container.textContent).toContain("Purge persistent traffic history");
  });
  await clickAndSettle(findButton((t) => t === "Purge retained history"));
  await vi.waitFor(async () => {
    await settle();
    expect(container.textContent).toContain("Purge outcome unconfirmed");
  });
  expect(container.textContent).toContain(
    "The appliance may have completed the purge before the connection was lost. Refresh History & Storage before taking another destructive action.",
  );

  // B. first resolving refresh FAILS.
  onGet = () => Promise.reject(new TypeError("still down"));
  await clickAndSettle(findButton((t) => t.includes("Refresh current state")));
  await vi.waitFor(async () => {
    await settle();
    expect(container.textContent).toContain(
      "Refresh failed — showing previous snapshot",
    );
  });
  // C/D. the unconfirmed declaration remains; no success acknowledgement is
  // fabricated (cached count/bytes are not proof of purge success).
  expect(container.textContent).toContain("Purge outcome unconfirmed");
  expect(container.textContent).not.toContain("Retained history purged");
  // E. Purge remains blocked.
  expect(
    findButton((t) => t.includes("Purge retained history…")).disabled,
  ).toBe(true);

  // F. a later successful GET resolves the latch.
  onGet = () => okJSON(retentionJSONv2);
  await clickAndSettle(findButton((t) => t.includes("Refresh current state")));
  await vi.waitFor(async () => {
    await settle();
    expect(container.textContent).not.toContain("Purge outcome unconfirmed");
  });
  expect(
    findButton((t) => t.includes("Purge retained history…")).disabled,
  ).toBe(false);
});
