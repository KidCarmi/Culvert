import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router";
import { createQueryClient } from "./api/query";
import "./design-system/tokens.css";
import "./design-system/base.css";
import { initTheme } from "./design-system/theme";
import { ToastProvider } from "./design-system/toast";
import { AuthProvider } from "./auth/AuthProvider";
import { createAppRouter } from "./app/router";

// Theme applies synchronously before first paint — no flash, no reload on
// later switches (design-system/theme.ts is the sanctioned storage module).
initTheme();

const queryClient = createQueryClient();
const router = createAppRouter();

const root = document.getElementById("root");
if (root === null) {
  throw new Error("culvert-frontend: #root element missing from shell");
}
createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  </StrictMode>,
);
