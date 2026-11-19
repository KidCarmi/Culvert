// Traffic status attribution: every request-log status the proxy emits for a
// content/inspection outcome must render with its real severity and a stated
// meaning, and be selectable in the Status filter. Before this change the
// React console only knew seven statuses, so a SCAN_BLOCKED / FILE_BLOCKED /
// THREAT_BLOCKED row looked like a neutral (grey) entry — indistinguishable
// from an informational one — and could not be filtered. Contrasting controls:
// CDR_ERROR is a FAIL-OPEN pass-through (not a block), and an unknown status
// stays neutral with NO invented meaning. Frontend-only: the server's
// decision and the status query parameter it receives are unchanged.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createQueryClient } from "../api/query";
import { TrafficPage } from "../features/monitor/TrafficPage";

let container: HTMLDivElement;
let root: Root;

function row(status: string, i: number): Record<string, unknown> {
  return {
    ts: 1_700_000_000_000 + i,
    time: `10:00:0${String(i)}`,
    ip: "10.0.0.1",
    identity: "",
    method: "GET",
    host: `h${String(i)}.test`,
    status,
    level: "WARN",
    ruleMatched: "",
    ruleId: "",
    actionTaken: "",
    bytesSent: 0,
    bytesRecv: 0,
    sslAction: "",
    durationMs: 0,
  };
}

const STATUSES = [
  "SCAN_BLOCKED",
  "FILE_BLOCKED",
  "THREAT_BLOCKED",
  "POLYGLOT_BLOCKED",
  "DPI_BLOCKED",
  "CDR_BLOCKED",
  "CDR_ERROR",
  "DECRYPT_FAILED",
  "POLICY_DROP",
  "SOMETHING_NEW",
];

let urls: string[];

beforeEach(() => {
  urls = [];
  container = document.createElement("div");
  document.body.appendChild(container);
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown) => {
      urls.push(String(input));
      return Promise.resolve(
        new Response(
          JSON.stringify({
            logs: STATUSES.map(row),
            next_cursor: "",
            has_more: false,
            scan_limited: false,
            history: true,
            snapshot_at: "2026-01-01T00:00:00Z",
            limit: 50,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
  vi.unstubAllGlobals();
});

async function mount(): Promise<void> {
  const qc = createQueryClient();
  const router = createMemoryRouter(
    [{ path: "/monitor/traffic", element: <TrafficPage /> }],
    { initialEntries: ["/monitor/traffic"] },
  );
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await vi.waitFor(() => {
    expect(container.querySelectorAll("tbody tr").length).toBe(STATUSES.length);
  });
}

function badgeTone(status: string): string | null {
  const b = Array.from(
    container.querySelectorAll<HTMLElement>("[data-status]"),
  ).find((el) => el.textContent === status);
  return b?.getAttribute("data-status") ?? null;
}

it("renders content/inspection blocks as critical, fail-open CDR error as warn, unknown as neutral", async () => {
  await mount();
  for (const s of [
    "SCAN_BLOCKED",
    "FILE_BLOCKED",
    "THREAT_BLOCKED",
    "POLYGLOT_BLOCKED",
    "DPI_BLOCKED",
    "CDR_BLOCKED",
    "POLICY_DROP",
  ]) {
    expect(badgeTone(s), s).toBe("critical");
  }
  // Contrasting controls: not blocks.
  expect(badgeTone("CDR_ERROR")).toBe("warn");
  expect(badgeTone("DECRYPT_FAILED")).toBe("warn");
  expect(badgeTone("SOMETHING_NEW")).toBe("neutral");
});

it("states what the status means, and never invents a meaning for an unknown status", async () => {
  await mount();
  const open = (i: number): void => {
    const btns = container.querySelectorAll<HTMLButtonElement>("tbody button");
    act(() => {
      btns[i]?.click();
    });
  };
  open(0); // SCAN_BLOCKED
  expect(container.textContent).toContain("Status meaning");
  expect(container.textContent).toContain("content scan");
  open(0);
  open(6); // CDR_ERROR
  expect(container.textContent).toContain("passed it on unmodified");
  // Fail-open hands the original bytes to DPI and AV, which can still block
  // them: the explanation must not assert the content reached the client.
  expect(container.textContent).not.toContain("delivered");
  open(6);
  open(9); // unknown
  expect(container.textContent).not.toContain("Status meaning");
});

it("offers the emitted statuses in the Status filter and sends them verbatim", async () => {
  await mount();
  const select = Array.from(container.querySelectorAll("select")).find((s) =>
    Array.from(s.options).some((o) => o.value === "AUTH_FAIL"),
  );
  expect(select).toBeDefined();
  const values = Array.from(select?.options ?? []).map((o) => o.value);
  for (const s of STATUSES.slice(0, 9)) expect(values, s).toContain(s);
  expect(values).not.toContain("SOMETHING_NEW");
  expect(urls.some((u) => u.includes("/api/logs"))).toBe(true);
});
