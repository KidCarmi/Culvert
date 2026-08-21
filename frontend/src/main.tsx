import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app/App";
import "./app/app.css";

const root = document.getElementById("root");
if (root === null) {
  throw new Error("culvert-frontend: #root element missing from shell");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
