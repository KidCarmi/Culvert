// FE-6B.1 GREEN-run finding: the sign-in gate renders AT the requested URL
// and used to navigate to the resolved PATHNAME only, dropping a deep link's
// query string (`/app/security/certificates?tab=ca` signed in onto the
// Certificates tab). `intentSearch` carries the browser's own search string
// through sign-in ONLY when the role may visit the exact route it addressed.
import { expect, it } from "vitest";
import { intentSearch, resolveRouteIntent } from "../auth/routeIntent";

it("carries the query only onto the exact resolved route", () => {
  const intent = "/security/certificates";
  const resolved = resolveRouteIntent(intent, "viewer");
  expect(resolved).toBe(intent);
  expect(intentSearch(resolved, intent, "?tab=ca")).toBe("?tab=ca");
  // an unauthorized or unknown intent falls back to Overview and carries nothing
  expect(
    intentSearch(
      resolveRouteIntent("/governance", "viewer"),
      "/governance",
      "?tab=ca",
    ),
  ).toBe("");
  expect(
    intentSearch(resolveRouteIntent("/nope", "admin"), "/nope", "?x=1"),
  ).toBe("");
  // only a browser search string (`?…`) is ever carried
  expect(intentSearch(intent, intent, "")).toBe("");
  expect(intentSearch(intent, intent, "?")).toBe("");
  expect(intentSearch(intent, intent, "tab=ca")).toBe("");
  expect(intentSearch(intent, intent, "//evil.example")).toBe("");
});
