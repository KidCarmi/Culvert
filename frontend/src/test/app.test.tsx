import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it } from "vitest";
import { App } from "../app/App";

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
});

it("mounts the foundation shell", () => {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
  });
  expect(container.textContent).toContain("CULVERT");
  expect(container.textContent).toContain("Frontend Platform Foundation");
  act(() => {
    root.unmount();
  });
  container.remove();
});
