// FE-6A.2 CORRECTION RED — the recovery marker accepts the IMPORT action
// (Blocker 1: an unproven import answer must be recoverable through the
// same subject-bound, non-secret marker as a create, never re-imported).
// On 64da0df0 the action grammar is create|update, so the write is refused.
import { beforeEach, expect, it } from "vitest";
import {
  IDP_RECOVERY_KEY,
  readIdPRecovery,
  writeIdPRecovery,
} from "../features/objects/idpRecovery";

const OWNER = "admin-user";
const OP = "6a2e0000-0000-4000-8000-00000000c0de";

beforeEach(() => {
  sessionStorage.clear();
});

it("CM1 an import marker is written, read back by its owner and never carries a secret", () => {
  const ok = writeIdPRecovery(OWNER, {
    operationId: OP,
    action: "import",
    profileId: "",
    name: "Imported legacy LDAP",
    type: "ldap",
    candidateDigest: "0123456789abcdef",
    fence: "r-doc-1",
    cutover: false,
    startedAt: 1,
  });
  expect(ok).toBe(true);
  const read = readIdPRecovery(OWNER);
  expect(read.kind).toBe("valid");
  if (read.kind === "valid") expect(read.marker.action).toBe("import");
  const raw = sessionStorage.getItem(IDP_RECOVERY_KEY) ?? "";
  expect(raw).toContain('"action":"import"');
  expect(raw).not.toMatch(/bindPassword|clientSecret|metadataXml/);
});

it("CM2 a stored import marker survives the grammar check on read", () => {
  sessionStorage.setItem(
    IDP_RECOVERY_KEY,
    JSON.stringify({
      version: 1,
      subject: OWNER,
      operationId: OP,
      action: "import",
      profileId: "",
      name: "Imported legacy LDAP",
      type: "ldap",
      candidateDigest: "0123456789abcdef",
      fence: "r-doc-1",
      cutover: false,
      startedAt: 1,
    }),
  );
  expect(readIdPRecovery(OWNER).kind).toBe("valid");
});
