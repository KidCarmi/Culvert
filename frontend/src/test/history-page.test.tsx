// 2A-M §5/§8: History & Storage role posture + unknown-outcome doctrine.
// Viewer mounts NO mutation controls (not disabled fakes — absent); an
// admin Save whose outcome the client never observed (network loss) keeps
// the prior snapshot, declares the outcome unconfirmed, blocks further
// mutations, and resolves ONLY via a fresh successful GET.
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

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
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

/** Route the page's fetches: GET retention serves the fixture; PUT behavior
 * is injectable per test. */
function stubFetch(onPut: () => Promise<Response>): ReturnType<typeof vi.fn> {
  const fn = vi.fn((input: unknown, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (url.includes("/api/logs/retention") && method === "GET") {
      return Promise.resolve(
        new Response(JSON.stringify(retentionJSON), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    }
    if (url.includes("/api/logs/retention") && method === "PUT") {
      return onPut();
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
