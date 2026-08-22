// FE-3 §20 component matrix: TOTP two-step flow (transition, invalid 401
// without the boundary, 429 lockout, success clearing secret state) and the
// setup persistence-failure 500 (retryable, form preserved). Rendered
// through the REAL AuthProvider/machine with stubbed status API + stubbed
// fetch for the auth-flow POSTs.
import { act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createQueryClient } from "../api/query";
import type { AuthStatus } from "../api/auth";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { registerAuthCleanup } from "../auth/teardown";
import { LoginPage } from "../features/auth/LoginPage";
import { SetupPage } from "../features/auth/SetupPage";
import { ToastProvider } from "../design-system/toast";

let container: HTMLDivElement;
let root: Root;
let unregisterCleanup: (() => void) | null = null;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement("div");
  document.body.appendChild(container);
});
afterEach(async () => {
  await act(async () => {
    root.unmount();
    await Promise.resolve();
  });
  container.remove();
  unregisterCleanup?.();
  unregisterCleanup = null;
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const noTLS = { tlsFallback: false, tlsFallbackReason: "" };

interface Fixture {
  machine: AuthMachine;
  session: { current: AuthStatus };
}

function loginFixture(): Fixture {
  const session: Fixture["session"] = {
    current: { loggedIn: false, ...noTLS },
  };
  const qc = createQueryClient();
  const machine = new AuthMachine(qc, {
    getSetupStatus: () => Promise.resolve({ needsSetup: false, ...noTLS }),
    getAuthStatus: () => Promise.resolve(session.current),
    postLogout: () => Promise.resolve({ ok: true }),
  });
  return { machine, session };
}

async function mount(fx: Fixture, page: "login" | "setup"): Promise<void> {
  const qc = createQueryClient();
  await fx.machine.boot();
  root = createRoot(container);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <ToastProvider>
          <AuthProvider machine={fx.machine}>
            <MemoryRouter initialEntries={["/"]}>
              <Routes>
                <Route
                  path="/"
                  element={page === "login" ? <LoginPage /> : <SetupPage />}
                />
              </Routes>
            </MemoryRouter>
          </AuthProvider>
        </ToastProvider>
      </QueryClientProvider>,
    );
    await Promise.resolve();
  });
}

function inputByLabel(label: string): HTMLInputElement {
  const labels = [...container.querySelectorAll("label")];
  const hit = labels.find((l) => (l.textContent ?? "").includes(label));
  if (hit === null || hit === undefined)
    throw new Error(`label not found: ${label}`);
  const id = hit.getAttribute("for") ?? "";
  const input = document.getElementById(id);
  if (!(input instanceof HTMLInputElement))
    throw new Error(`input not found for: ${label}`);
  return input;
}

async function type(input: HTMLInputElement, value: string): Promise<void> {
  const desc = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  );
  await act(async () => {
    desc?.set?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await Promise.resolve();
  });
}

async function submitForm(): Promise<void> {
  const form = container.querySelector("form");
  if (form === null) throw new Error("form not found");
  await act(async () => {
    form.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    // Let the async submit settle (fetch stub microtasks).
    await new Promise((r) => setTimeout(r, 0));
    await Promise.resolve();
  });
}

it("TOTP: transition, invalid 401 w/o boundary, lockout, success clears secrets", async () => {
  const fx = loginFixture();
  let teardowns = 0;
  unregisterCleanup = registerAuthCleanup(() => {
    teardowns += 1;
  });
  const jsonOK = (body: unknown): Response =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  const fetchMock = vi
    .fn()
    // 1: credentials accepted, TOTP enrolled → totp_required, no cookie
    .mockResolvedValueOnce(jsonOK({ totp_required: true }))
    // 2: invalid TOTP → EXPECTED 401
    .mockResolvedValueOnce(new Response("Invalid TOTP code\n", { status: 401 }))
    // 3: lockout → 429 with the server's bounded message
    .mockResolvedValueOnce(
      new Response("Account temporarily locked. Try again in 300 seconds.\n", {
        status: 429,
      }),
    )
    // 4: success
    .mockResolvedValueOnce(
      jsonOK({ ok: true, user: "totpuser", role: "operator" }),
    );
  vi.stubGlobal("fetch", fetchMock);

  await mount(fx, "login");
  await type(inputByLabel("Username"), "totpuser");
  await type(inputByLabel("Password"), "Password123");
  await submitForm();

  // Step 2 rendered; focus is inside the code input (§19).
  const code = inputByLabel("Authenticator or backup code");
  expect(code.getAttribute("type")).toBe("text"); // backup codes are not digits-only
  expect(document.activeElement).toBe(code);

  // Invalid code → controlled error, NO global teardown.
  await type(code, "000000");
  await submitForm();
  expect(container.textContent).toContain("Invalid TOTP code");
  expect(teardowns).toBe(0);
  expect(fx.machine.getState().phase).toBe("unauthenticated");

  // Lockout → server message shown, no auto-retry (exactly one more fetch).
  await type(inputByLabel("Authenticator or backup code"), "111111");
  const callsBefore = fetchMock.mock.calls.length;
  await submitForm();
  expect(fetchMock.mock.calls.length).toBe(callsBefore + 1);
  expect(container.textContent).toContain("Account temporarily locked");

  // Success: session becomes visible via the FRESH auth/status read; secret
  // state is cleared immediately.
  fx.session.current = {
    loggedIn: true,
    user: "totpuser",
    role: "operator",
    bootstrap: false,
    ...noTLS,
  };
  await type(inputByLabel("Authenticator or backup code"), "222222");
  await submitForm();
  expect(fx.machine.getState().phase).toBe("authenticated");
  expect(fx.machine.getState().user).toBe("totpuser");
  const inputsAfter = [...container.querySelectorAll("input")];
  for (const i of inputsAfter) {
    expect(i.value).toBe(""); // no password/TOTP survives in mounted inputs
  }
});

it("login 401 renders a form error without any boundary transition", async () => {
  const fx = loginFixture();
  let teardowns = 0;
  unregisterCleanup = registerAuthCleanup(() => {
    teardowns += 1;
  });
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValue(
        new Response("Invalid credentials\n", { status: 401 }),
      ),
  );
  await mount(fx, "login");
  await type(inputByLabel("Username"), "admin");
  await type(inputByLabel("Password"), "WrongPass1");
  await submitForm();
  expect(container.textContent).toContain("Invalid credentials");
  expect(teardowns).toBe(0);
  expect(fx.machine.getState().phase).toBe("unauthenticated");
});

it("setup persistence-failure 500 stays retryable and preserves the form", async () => {
  const session: Fixture["session"] = {
    current: { loggedIn: false, ...noTLS },
  };
  const qc = createQueryClient();
  const machine = new AuthMachine(qc, {
    getSetupStatus: () => Promise.resolve({ needsSetup: true, ...noTLS }),
    getAuthStatus: () => Promise.resolve(session.current),
    postLogout: () => Promise.resolve({ ok: true }),
  });
  const fetchMock = vi
    .fn()
    .mockResolvedValue(
      new Response(
        "internal error: admin credentials could not be saved to disk; setup did not complete — check disk space/permissions and retry\n",
        { status: 500 },
      ),
    );
  vi.stubGlobal("fetch", fetchMock);
  await mount({ machine, session }, "setup");

  await type(inputByLabel("Administrator username"), "root-admin");
  await type(inputByLabel("Password"), "Password123");
  await type(inputByLabel("Confirm password"), "Password123");
  await submitForm();

  expect(container.textContent).toContain("Setup did NOT complete");
  expect(container.textContent).toContain("retrying is safe");
  // The form is NOT wiped on a retryable server persistence error.
  expect(inputByLabel("Administrator username").value).toBe("root-admin");
  expect(inputByLabel("Password").value).toBe("Password123");
  expect(machine.getState().phase).toBe("setup_required");

  // Retry reaches the server again — nothing latched client-side.
  const before = fetchMock.mock.calls.length;
  await submitForm();
  expect(fetchMock.mock.calls.length).toBe(before + 1);
});
