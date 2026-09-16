// FE-6A.2 — Identity Provider WRITE surface: the editor, the ceremonies at
// their tiers, the recovery banner and the bounded outcome callouts.
//
// Rules carried here (contract §G C1/C5/C10, §8 D1–D6, D15):
//   • secrets (client secret, bind password, inline SAML metadata, the test
//     credential) live ONLY in this dialog tree's component state — never in
//     the page, a marker, storage, the URL or a notice; closing the dialog
//     unmounts them;
//   • an explicit clear is an explicit checkbox (the "" wire semantics);
//   • every ceremony receives the FROZEN reviewed candidate + fence from the
//     page and never re-reads tokens; T3 gates never confirm on Enter;
//   • no server prose is rendered: refusals show the bounded code + typed
//     facts, the directory test shows step classes only.
import { useState } from "react";
import type { JSX } from "react";
import {
  Button,
  Callout,
  KeyValue,
  Mono,
  StatusBadge,
} from "../../design-system/primitives";
import {
  ConfirmationDialog,
  Dialog,
  DialogBody,
  DialogFooter,
} from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";

type KVItems = Array<readonly [string, JSX.Element | string]>;

function fenceItems(initial: IdPProfile | null, fence: string): KVItems {
  return initial !== null
    ? [
        ["Id", <Mono key="id">{initial.id}</Mono>],
        ["Fenced on entry revision", fence],
      ]
    : [["Fenced on document revision", <Mono key="d">{fence}</Mono>]];
}
import {
  Checkbox,
  InputField,
  SelectField,
  TextareaField,
} from "../../design-system/forms";
import { consumerDestination } from "../policy/WhereUsed";
import { IDP_TYPES, specCarriesSecret } from "../../api/idp";
import type {
  IdPProfile,
  IdPRefusal,
  IdPTestReport,
  IdPTestStepError,
  IdPTestStepName,
  IdPType,
  IdPWriteSpec,
  LegacyLDAP,
  LegacyLDAPPresentFacts,
  OIDCDiscovery,
} from "../../api/idp";
import type { IdPRecoveryMarker } from "./idpRecovery";

// ── Draft ──────────────────────────────────────────────────────────────────

export interface ProviderDraft {
  type: IdPType;
  name: string;
  enabled: boolean;
  priority: string;
  emailDomains: string;
  knownGroups: string;
  oidc: {
    issuer: string;
    clientId: string;
    clientSecret: string;
    clearSecret: boolean;
    scopes: string;
    groupsClaim: string;
    requiredScope: string;
    requiredAudience: string;
    tlsSkipVerify: boolean;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    introspectionEndpoint: string;
    userinfoEndpoint: string;
    jwksUri: string;
  };
  saml: {
    metadataUrl: string;
    metadataXml: string;
    clearXml: boolean;
    nameIdFormat: string;
    groupsAttribute: string;
    emailAttribute: string;
    nameAttribute: string;
  };
  ldap: {
    url: string;
    startTls: boolean;
    tlsSkipVerify: boolean;
    bindDn: string;
    bindPassword: string;
    clearBind: boolean;
    baseDn: string;
    userFilter: string;
    emailAttribute: string;
    nameAttribute: string;
    groupAttribute: string;
    requiredGroup: string;
    cacheTtlSeconds: string;
  };
}

export function draftFrom(p: IdPProfile | null): ProviderDraft {
  const d: ProviderDraft = {
    type: p?.type ?? "oidc",
    name: p?.name ?? "",
    enabled: p?.enabled ?? false,
    priority: String(p?.priority ?? 0),
    emailDomains: (p?.emailDomains ?? []).join(", "),
    knownGroups: (p?.knownGroups ?? []).join("\n"),
    oidc: {
      issuer: "",
      clientId: "",
      clientSecret: "",
      clearSecret: false,
      scopes: "",
      groupsClaim: "",
      requiredScope: "",
      requiredAudience: "",
      tlsSkipVerify: false,
      authorizationEndpoint: "",
      tokenEndpoint: "",
      introspectionEndpoint: "",
      userinfoEndpoint: "",
      jwksUri: "",
    },
    saml: {
      metadataUrl: "",
      metadataXml: "",
      clearXml: false,
      nameIdFormat: "",
      groupsAttribute: "",
      emailAttribute: "",
      nameAttribute: "",
    },
    ldap: {
      url: "",
      startTls: false,
      tlsSkipVerify: false,
      bindDn: "",
      bindPassword: "",
      clearBind: false,
      baseDn: "",
      userFilter: "",
      emailAttribute: "",
      nameAttribute: "",
      groupAttribute: "",
      requiredGroup: "",
      cacheTtlSeconds: "0",
    },
  };
  if (p === null) return d;
  switch (p.type) {
    case "oidc":
      d.oidc = {
        ...d.oidc,
        issuer: p.oidc.issuer,
        clientId: p.oidc.clientId,
        scopes: p.oidc.scopes.join(" "),
        groupsClaim: p.oidc.groupsClaim,
        requiredScope: p.oidc.requiredScope,
        requiredAudience: p.oidc.requiredAudience,
        tlsSkipVerify: p.oidc.tlsSkipVerify,
        authorizationEndpoint: p.oidc.authorizationEndpoint,
        tokenEndpoint: p.oidc.tokenEndpoint,
        introspectionEndpoint: p.oidc.introspectionEndpoint,
        userinfoEndpoint: p.oidc.userinfoEndpoint,
        jwksUri: p.oidc.jwksUri,
      };
      break;
    case "saml":
      d.saml = {
        ...d.saml,
        metadataUrl: p.saml.metadataUrl,
        nameIdFormat: p.saml.nameIdFormat,
        groupsAttribute: p.saml.groupsAttribute,
        emailAttribute: p.saml.emailAttribute,
        nameAttribute: p.saml.nameAttribute,
      };
      break;
    case "ldap":
      d.ldap = {
        ...d.ldap,
        url: p.ldap.url,
        startTls: p.ldap.startTls,
        tlsSkipVerify: p.ldap.tlsSkipVerify,
        bindDn: p.ldap.bindDn,
        baseDn: p.ldap.baseDn,
        userFilter: p.ldap.userFilter,
        emailAttribute: p.ldap.emailAttribute,
        nameAttribute: p.ldap.nameAttribute,
        groupAttribute: p.ldap.groupAttribute,
        requiredGroup: p.ldap.requiredGroup,
        cacheTtlSeconds: String(p.ldap.cacheTtlSeconds),
      };
      break;
  }
  return d;
}

/** The draft with every secret field blanked — what may be REMEMBERED for a
 * re-send prefill (never the material). */
export function stripSecrets(d: ProviderDraft): ProviderDraft {
  return {
    ...d,
    oidc: { ...d.oidc, clientSecret: "" },
    saml: { ...d.saml, metadataXml: "" },
    ldap: { ...d.ldap, bindPassword: "" },
  };
}

export function draftDirty(a: ProviderDraft, b: ProviderDraft): boolean {
  return JSON.stringify(a) !== JSON.stringify(b);
}

const list = (s: string, sep: RegExp): string[] =>
  s
    .split(sep)
    .map((x) => x.trim())
    .filter((x) => x !== "");

/** Local validation only mirrors what the appliance REQUIRES before it will
 * accept the body; the verdict is always the appliance's. */
export function draftToSpec(
  d: ProviderDraft,
  mode: "create" | "edit",
  initial: IdPProfile | null,
): IdPWriteSpec | string {
  const name = d.name.trim();
  if (name === "") return "A name is required.";
  const priority = Number(d.priority);
  if (!Number.isInteger(priority) || priority < 0)
    return "Priority must be a whole number ≥ 0.";
  const base = {
    name,
    enabled: d.enabled,
    priority,
    emailDomains: list(d.emailDomains, /[,\s]+/),
    knownGroups: list(d.knownGroups, /[\n,]+/),
  };
  switch (d.type) {
    case "oidc": {
      if (!/^https:\/\/\S+$/.test(d.oidc.issuer.trim()))
        return "The OIDC issuer must be an https:// URL.";
      const secret = d.oidc.clearSecret
        ? ""
        : d.oidc.clientSecret !== ""
          ? d.oidc.clientSecret
          : undefined;
      return {
        ...base,
        type: "oidc",
        oidc: {
          issuer: d.oidc.issuer.trim(),
          clientId: d.oidc.clientId.trim(),
          scopes: list(d.oidc.scopes, /[,\s]+/),
          groupsClaim: d.oidc.groupsClaim.trim(),
          requiredScope: d.oidc.requiredScope.trim(),
          requiredAudience: d.oidc.requiredAudience.trim(),
          tlsSkipVerify: d.oidc.tlsSkipVerify,
          authorizationEndpoint: d.oidc.authorizationEndpoint.trim(),
          tokenEndpoint: d.oidc.tokenEndpoint.trim(),
          introspectionEndpoint: d.oidc.introspectionEndpoint.trim(),
          userinfoEndpoint: d.oidc.userinfoEndpoint.trim(),
          jwksUri: d.oidc.jwksUri.trim(),
          ...(secret !== undefined ? { clientSecret: secret } : {}),
        },
      };
    }
    case "saml": {
      const url = d.saml.metadataUrl.trim();
      const xml = d.saml.metadataXml;
      const keepsInline =
        mode === "edit" &&
        initial?.type === "saml" &&
        initial.saml.inlineMetadataConfigured &&
        !d.saml.clearXml &&
        xml === "";
      if (url !== "" && (xml !== "" || keepsInline))
        return "SAML takes EITHER a metadata URL OR inline metadata — clear one.";
      if (url === "" && xml === "" && !keepsInline)
        return "SAML needs a metadata URL or the inline metadata document.";
      const inline = d.saml.clearXml ? "" : xml !== "" ? xml : undefined;
      return {
        ...base,
        type: "saml",
        saml: {
          metadataUrl: url,
          nameIdFormat: d.saml.nameIdFormat.trim(),
          groupsAttribute: d.saml.groupsAttribute.trim(),
          emailAttribute: d.saml.emailAttribute.trim(),
          nameAttribute: d.saml.nameAttribute.trim(),
          ...(inline !== undefined ? { metadataXml: inline } : {}),
        },
      };
    }
    case "ldap": {
      const url = d.ldap.url.trim();
      if (!/^ldaps?:\/\/\S+$/.test(url))
        return "The directory URL must be ldap:// or ldaps:// host[:port].";
      if (d.ldap.baseDn.trim() === "") return "A base DN is required.";
      const ttl = Number(d.ldap.cacheTtlSeconds);
      if (!Number.isInteger(ttl) || ttl < 0)
        return "The cache TTL must be a whole number of seconds (0 = default).";
      const bind = d.ldap.clearBind
        ? ""
        : d.ldap.bindPassword !== ""
          ? d.ldap.bindPassword
          : undefined;
      return {
        ...base,
        type: "ldap",
        ldap: {
          url,
          startTls: d.ldap.startTls,
          tlsSkipVerify: d.ldap.tlsSkipVerify,
          bindDn: d.ldap.bindDn.trim(),
          baseDn: d.ldap.baseDn.trim(),
          userFilter: d.ldap.userFilter.trim(),
          emailAttribute: d.ldap.emailAttribute.trim(),
          nameAttribute: d.ldap.nameAttribute.trim(),
          groupAttribute: d.ldap.groupAttribute.trim(),
          requiredGroup: d.ldap.requiredGroup.trim(),
          cacheTtlSeconds: ttl,
          ...(bind !== undefined ? { bindPassword: bind } : {}),
        },
      };
    }
  }
}

/** The write retires the legacy authenticator iff it lands an ENABLED ldap
 * profile while the legacy block is present and not retired (ui_auth.go
 * idpLegacyCutoverHook) — the page decides the ceremony from this. */
export function carriesCutover(
  spec: IdPWriteSpec,
  legacy: LegacyLDAP | undefined,
): (LegacyLDAP & { present: true }) | null {
  if (spec.type !== "ldap" || !spec.enabled) return null;
  if (legacy === undefined || !legacy.present || legacy.retired) return null;
  return legacy;
}

// ── Test / discovery state (owned by the page, rendered here) ──────────────

export type TestState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "report"; report: IdPTestReport }
  | { kind: "refused"; refusal: IdPRefusal }
  | { kind: "unproven"; status: number | undefined };

export type DiscoverState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "done"; found: number }
  | { kind: "refused"; refusal: IdPRefusal }
  | { kind: "unproven"; status: number | undefined };

const STEP_LABEL: Record<IdPTestStepName, string> = {
  reachable: "Directory reachable",
  tls: "TLS",
  service_bind: "Service bind",
  base_dn: "Base DN",
  user_lookup: "User lookup",
  user_auth: "User authentication",
};
const STEP_ERROR_LABEL: Record<IdPTestStepError, string> = {
  timeout: "timed out",
  tls_failed: "TLS failed",
  unreachable: "unreachable",
  invalid_credentials: "invalid credentials",
  no_such_object: "no such object",
  insufficient_access: "insufficient access",
  directory_error: "directory error",
};

function TestReport({ report }: { report: IdPTestReport }): JSX.Element {
  return (
    <div>
      {report.ok ? (
        <StatusBadge status="ok">Directory test passed</StatusBadge>
      ) : (
        <StatusBadge status="critical">
          Directory test failed — nothing was changed
        </StatusBadge>
      )}
      <ul>
        {report.steps.map((s) => (
          <li key={s.name}>
            {STEP_LABEL[s.name]}:{" "}
            {s.skipped
              ? "skipped"
              : s.ok
                ? "ok"
                : s.error !== undefined
                  ? STEP_ERROR_LABEL[s.error]
                  : "failed"}
            {s.durationMs !== undefined ? ` (${String(s.durationMs)} ms)` : ""}
          </li>
        ))}
      </ul>
      {report.identity !== undefined && (
        <div>
          Resolved <Mono>{report.identity.sub}</Mono> ·{" "}
          {String(report.identity.groupCount)} group
          {report.identity.groupCount === 1 ? "" : "s"}
        </div>
      )}
    </div>
  );
}

// ── The editor ─────────────────────────────────────────────────────────────

export interface EditorProps {
  mode: "create" | "edit";
  initial: IdPProfile | null;
  draft: ProviderDraft;
  onChange: (d: ProviderDraft) => void;
  onReview: () => void;
  onCancel: () => void;
  pending: boolean;
  error: string | null;
  test: TestState;
  onTest: (cred: { username: string; password: string }) => void;
  discover: DiscoverState;
  onDiscover: (issuer: string) => void;
  onDiscovered?: (d: OIDCDiscovery) => void;
}

export function ProviderEditorDialog(p: EditorProps): JSX.Element {
  const { draft: d, onChange } = p;
  const [testUser, setTestUser] = useState("");
  const [testPass, setTestPass] = useState("");
  const set = (patch: Partial<ProviderDraft>): void => {
    onChange({ ...d, ...patch });
  };
  const initialConfigured = (): boolean => {
    const i = p.initial;
    if (i === null || p.mode !== "edit") return false;
    switch (i.type) {
      case "oidc":
        return i.oidc.clientSecretConfigured;
      case "saml":
        return i.saml.inlineMetadataConfigured;
      case "ldap":
        return i.ldap.bindCredentialConfigured;
    }
  };
  const configured = initialConfigured();
  return (
    <Dialog
      open
      onClose={p.pending ? () => undefined : p.onCancel}
      title={
        p.mode === "create"
          ? "New identity provider"
          : `Edit provider ${p.initial?.name ?? ""}`
      }
      closeOnEscape={!p.pending}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!p.pending) p.onReview();
        }}
      >
        <DialogBody>
          {p.mode === "edit" && p.initial !== null && (
            <KeyValue
              items={[
                ["Id", <Mono key="id">{p.initial.id}</Mono>],
                ["Loaded revision", String(p.initial.revision)],
              ]}
            />
          )}
          {p.mode === "create" ? (
            <SelectField
              label="Type"
              value={d.type}
              onChange={(e) => {
                const t = IDP_TYPES.find((x) => x === e.target.value);
                if (t !== undefined) set({ type: t });
              }}
            >
              {IDP_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </SelectField>
          ) : (
            <KeyValue items={[["Type", <Mono key="t">{d.type}</Mono>]]} />
          )}
          <InputField
            label="Name"
            required
            value={d.name}
            onChange={(e) => set({ name: e.target.value })}
            autoComplete="off"
          />
          <Checkbox
            label="Enabled"
            checked={d.enabled}
            onChange={(e) => set({ enabled: e.target.checked })}
          />
          <InputField
            label="Priority"
            type="number"
            min={0}
            value={d.priority}
            onChange={(e) => set({ priority: e.target.value })}
          />
          <InputField
            label="Email domains"
            help="Comma-separated routing hints"
            value={d.emailDomains}
            onChange={(e) => set({ emailDomains: e.target.value })}
            autoComplete="off"
          />
          <TextareaField
            label="Known groups"
            help="One per line"
            value={d.knownGroups}
            onChange={(e) => set({ knownGroups: e.target.value })}
            rows={2}
          />
          {d.type === "oidc" && (
            <>
              <InputField
                label="Issuer"
                required
                value={d.oidc.issuer}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, issuer: e.target.value } })
                }
                autoComplete="off"
              />
              <div>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  disabled={
                    p.pending ||
                    p.discover.kind === "running" ||
                    d.oidc.issuer.trim() === ""
                  }
                  onClick={() => p.onDiscover(d.oidc.issuer.trim())}
                >
                  {p.discover.kind === "running"
                    ? "Discovering…"
                    : "Discover endpoints"}
                </Button>{" "}
                {p.discover.kind === "done" && (
                  <span>
                    {String(p.discover.found)} endpoint(s) filled from the
                    issuer's discovery document
                  </span>
                )}
                {p.discover.kind === "refused" && (
                  <StatusBadge status="warn">
                    Discovery refused: {p.discover.refusal.code}
                  </StatusBadge>
                )}
                {p.discover.kind === "unproven" && (
                  <StatusBadge status="unknown">
                    Discovery outcome unproven — nothing was filled
                  </StatusBadge>
                )}
              </div>
              <InputField
                label="Client ID"
                value={d.oidc.clientId}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, clientId: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Client secret"
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                help={
                  configured
                    ? "A secret is configured (write-only). Leave blank to keep it."
                    : "Write-only: sent once, never read back."
                }
                value={d.oidc.clientSecret}
                disabled={d.oidc.clearSecret}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, clientSecret: e.target.value } })
                }
              />
              {configured && (
                <Checkbox
                  label="Clear the client secret"
                  checked={d.oidc.clearSecret}
                  onChange={(e) =>
                    set({
                      oidc: {
                        ...d.oidc,
                        clearSecret: e.target.checked,
                        clientSecret: "",
                      },
                    })
                  }
                />
              )}
              <InputField
                label="Scopes"
                help="Space-separated"
                value={d.oidc.scopes}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, scopes: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Groups claim"
                value={d.oidc.groupsClaim}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, groupsClaim: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Required scope"
                value={d.oidc.requiredScope}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, requiredScope: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Required audience"
                value={d.oidc.requiredAudience}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, requiredAudience: e.target.value } })
                }
                autoComplete="off"
              />
              <Checkbox
                label="Skip TLS certificate verification (security-effective)"
                checked={d.oidc.tlsSkipVerify}
                onChange={(e) =>
                  set({ oidc: { ...d.oidc, tlsSkipVerify: e.target.checked } })
                }
              />
              {(d.oidc.authorizationEndpoint !== "" ||
                d.oidc.tokenEndpoint !== "" ||
                d.oidc.jwksUri !== "") && (
                <KeyValue
                  items={[
                    [
                      "Authorization endpoint",
                      d.oidc.authorizationEndpoint || "—",
                    ],
                    ["Token endpoint", d.oidc.tokenEndpoint || "—"],
                    [
                      "Introspection endpoint",
                      d.oidc.introspectionEndpoint || "—",
                    ],
                    ["Userinfo endpoint", d.oidc.userinfoEndpoint || "—"],
                    ["JWKS URI", d.oidc.jwksUri || "—"],
                  ]}
                />
              )}
            </>
          )}
          {d.type === "saml" && (
            <>
              <InputField
                label="Metadata URL"
                value={d.saml.metadataUrl}
                onChange={(e) =>
                  set({ saml: { ...d.saml, metadataUrl: e.target.value } })
                }
                autoComplete="off"
              />
              <TextareaField
                label="Metadata XML"
                help={
                  configured
                    ? "Inline metadata is configured (write-only). Leave blank to keep it."
                    : "Inline metadata document (write-only: sent once, never read back)."
                }
                value={d.saml.metadataXml}
                disabled={d.saml.clearXml}
                onChange={(e) =>
                  set({ saml: { ...d.saml, metadataXml: e.target.value } })
                }
                rows={4}
                spellCheck={false}
              />
              {configured && (
                <Checkbox
                  label="Clear the inline metadata"
                  checked={d.saml.clearXml}
                  onChange={(e) =>
                    set({
                      saml: {
                        ...d.saml,
                        clearXml: e.target.checked,
                        metadataXml: "",
                      },
                    })
                  }
                />
              )}
              <InputField
                label="NameID format"
                value={d.saml.nameIdFormat}
                onChange={(e) =>
                  set({ saml: { ...d.saml, nameIdFormat: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Groups attribute"
                value={d.saml.groupsAttribute}
                onChange={(e) =>
                  set({ saml: { ...d.saml, groupsAttribute: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Email attribute"
                value={d.saml.emailAttribute}
                onChange={(e) =>
                  set({ saml: { ...d.saml, emailAttribute: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Name attribute"
                value={d.saml.nameAttribute}
                onChange={(e) =>
                  set({ saml: { ...d.saml, nameAttribute: e.target.value } })
                }
                autoComplete="off"
              />
            </>
          )}
          {d.type === "ldap" && (
            <>
              <InputField
                label="Directory URL"
                required
                help="ldap:// or ldaps:// host[:port]"
                value={d.ldap.url}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, url: e.target.value } })
                }
                autoComplete="off"
              />
              <Checkbox
                label="StartTLS"
                checked={d.ldap.startTls}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, startTls: e.target.checked } })
                }
              />
              <Checkbox
                label="Skip TLS certificate verification (security-effective)"
                checked={d.ldap.tlsSkipVerify}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, tlsSkipVerify: e.target.checked } })
                }
              />
              <InputField
                label="Bind DN"
                value={d.ldap.bindDn}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, bindDn: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Bind password"
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                help={
                  configured
                    ? "A bind credential is configured (write-only). Leave blank to keep it."
                    : "Write-only: sent once, never read back."
                }
                value={d.ldap.bindPassword}
                disabled={d.ldap.clearBind}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, bindPassword: e.target.value } })
                }
              />
              {configured && (
                <Checkbox
                  label="Clear the bind credential (anonymous bind)"
                  checked={d.ldap.clearBind}
                  onChange={(e) =>
                    set({
                      ldap: {
                        ...d.ldap,
                        clearBind: e.target.checked,
                        bindPassword: "",
                      },
                    })
                  }
                />
              )}
              <InputField
                label="Base DN"
                required
                value={d.ldap.baseDn}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, baseDn: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="User filter"
                help="exactly one %s"
                value={d.ldap.userFilter}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, userFilter: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Email attribute"
                value={d.ldap.emailAttribute}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, emailAttribute: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Name attribute"
                value={d.ldap.nameAttribute}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, nameAttribute: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Group attribute"
                value={d.ldap.groupAttribute}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, groupAttribute: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Required group"
                value={d.ldap.requiredGroup}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, requiredGroup: e.target.value } })
                }
                autoComplete="off"
              />
              <InputField
                label="Cache TTL (seconds)"
                type="number"
                min={0}
                help="0 = default (300); otherwise 10–86400"
                value={d.ldap.cacheTtlSeconds}
                onChange={(e) =>
                  set({ ldap: { ...d.ldap, cacheTtlSeconds: e.target.value } })
                }
              />
              <fieldset>
                <legend>Directory test (nothing is persisted)</legend>
                <InputField
                  label="Test username"
                  value={testUser}
                  onChange={(e) => setTestUser(e.target.value)}
                  autoComplete="off"
                />
                <InputField
                  label="Test password"
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  help="Transient: sent once with the test, never stored."
                  value={testPass}
                  onChange={(e) => setTestPass(e.target.value)}
                />
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  disabled={p.pending || p.test.kind === "running"}
                  onClick={() => {
                    p.onTest({ username: testUser, password: testPass });
                    setTestPass("");
                  }}
                >
                  {p.test.kind === "running"
                    ? "Testing (up to 60 s)…"
                    : "Test directory"}
                </Button>
                {p.test.kind === "report" && (
                  <TestReport report={p.test.report} />
                )}
                {p.test.kind === "refused" && (
                  <Callout variant="warning" title="Test refused" role="status">
                    <Mono>{p.test.refusal.code}</Mono> (HTTP{" "}
                    {String(p.test.refusal.status)})
                  </Callout>
                )}
                {p.test.kind === "unproven" && (
                  <Callout
                    variant="unknown"
                    title="Test outcome unproven"
                    role="status"
                  >
                    The directory test did not return a verifiable report
                    {p.test.status !== undefined
                      ? ` (HTTP ${String(p.test.status)})`
                      : ""}
                    . It is NOT a pass.
                  </Callout>
                )}
              </fieldset>
            </>
          )}
          {p.error !== null && (
            <Callout variant="critical" title="Cannot submit" role="alert">
              {p.error}
            </Callout>
          )}
        </DialogBody>
        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            onClick={p.onCancel}
            disabled={p.pending}
          >
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={p.pending}>
            Review and save
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}

// ── Ceremonies ─────────────────────────────────────────────────────────────

interface CeremonyCommon {
  result: ConfirmResult;
  errorText?: string;
  onCancel: () => void;
}

function specMaterial(spec: IdPWriteSpec): string {
  switch (spec.type) {
    case "oidc":
      return "the OIDC client secret";
    case "saml":
      return "the inline SAML metadata document";
    case "ldap":
      return "the LDAP bind password";
  }
}

/** T2 — a create/update carrying write-only credential material. */
export function ReviewCeremony(
  p: CeremonyCommon & {
    mode: "create" | "edit";
    initial: IdPProfile | null;
    spec: IdPWriteSpec;
    onConfirm: () => void;
  },
): JSX.Element {
  const carries = specCarriesSecret(p.spec);
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={
        p.mode === "create"
          ? "Review and create the provider"
          : "Review and save the provider"
      }
      body={
        <KeyValue
          items={[
            ["Name", p.spec.name],
            ["Type", <Mono key="t">{p.spec.type}</Mono>],
            ["State", p.spec.enabled ? "Enabled" : "Disabled"],
            ...(p.initial !== null
              ? fenceItems(p.initial, String(p.initial.revision))
              : []),
          ]}
        />
      }
      impact={
        carries
          ? `This request carries credential material (${specMaterial(p.spec)}). It is sent once in the request body, stored write-only by the appliance and never read back or shown again.`
          : "The provider profile is replaced under its revision fence; a concurrent change is refused, never overwritten."
      }
      rollback="Edit the provider again; credential material can be cleared explicitly."
      confirmLabel="Save provider"
      destructive={false}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

/** T2 by tier, typed by construction — the legacy-LDAP authority cutover:
 * the operator types the SERVER's confirm value (the legacy directory URL);
 * the reviewed provider, its fence and the operationId stay bound. */
export function CutoverCeremony(
  p: CeremonyCommon & {
    spec: IdPWriteSpec;
    initial: IdPProfile | null;
    fence: string;
    operationId: string;
    legacy: LegacyLDAPPresentFacts & { present: true };
    onConfirm: () => void;
  },
): JSX.Element {
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Retire the legacy YAML LDAP authenticator"
      body={
        <div>
          <p>
            Enabling this LDAP provider retires the config.yaml{" "}
            <Mono>ldap:</Mono> block <Mono>{p.legacy.url}</Mono> as the proxy
            authenticator. The cutover is durable: it survives restarts and
            disabling or deleting the provider, and there is no API to undo it.
          </p>
          <KeyValue
            items={[
              ["Provider", p.spec.name],
              ...fenceItems(p.initial, p.fence),
              ["Operation", <Mono key="op">{p.operationId}</Mono>],
              [
                "Legacy directory being retired",
                <Mono key="u">{p.legacy.url}</Mono>,
              ],
            ]}
          />
        </div>
      }
      impact="Users authenticating through the legacy block switch to this registry provider; the appliance records the cutover durably before it publishes."
      rollback="None through the API — offline break-glass only."
      confirmLabel="Retire and enable"
      confirmWord={p.legacy.cutoverConfirmValue}
      typedValue={typed}
      onTypedChange={setTyped}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

/** T3 — delete requires the exact provider id; the loaded revision is bound. */
export function DeleteProviderCeremony(
  p: CeremonyCommon & { profile: IdPProfile; onConfirm: () => void },
): JSX.Element {
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Delete provider"
      body={
        <KeyValue
          items={[
            ["Name", p.profile.name],
            ["Id", <Mono key="id">{p.profile.id}</Mono>],
            ["Type", <Mono key="t">{p.profile.type}</Mono>],
            ["Fenced on entry revision", String(p.profile.revision)],
          ]}
        />
      }
      impact="Users authenticating through this provider lose it immediately on every node once the fleet publishes; a provider referenced by an authentication rule is refused (409 referenced) and left in place."
      rollback="None — irreversible (the profile and its write-only material are removed)."
      confirmLabel="Delete provider"
      confirmWord={p.profile.id}
      typedValue={typed}
      onTypedChange={setTyped}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

/** T2 by tier, typed by construction — repair requires the exact quarantine
 * evidence (shown ONLY here). */
export function RepairCeremony(
  p: CeremonyCommon & { evidence: string; onConfirm: () => void },
): JSX.Element {
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Repair the identity-provider registry"
      body={
        <p>
          The registry file was found corrupt at boot and moved aside as{" "}
          <Mono>{p.evidence}</Mono>. Repair acknowledges the quarantine: the
          registry stays EMPTY and starts accepting writes again; the
          quarantined copy is left on disk as evidence.
        </p>
      }
      impact="Every provider that was in the corrupt file stays absent until re-created; nothing is written to disk by the repair itself."
      rollback="The quarantined copy remains on disk for an operator to inspect or restore offline."
      confirmLabel="Repair"
      confirmWord={p.evidence}
      typedValue={typed}
      onTypedChange={setTyped}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

/** T2 — import the legacy YAML block as a DISABLED managed profile. */
export function ImportCeremony(
  p: CeremonyCommon & {
    legacy: LegacyLDAP & { present: true };
    /** a re-send of an UNRESOLVED import: the SAME operation is dispatched
     * again (the appliance's ledger replays or refuses it), never a new one */
    boundOperationId?: string;
    onConfirm: () => void;
  },
): JSX.Element {
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Import the legacy YAML LDAP configuration"
      body={
        <>
          <p>
            Creates a managed LDAP provider from the config.yaml{" "}
            <Mono>ldap:</Mono> block <Mono>{p.legacy.url}</Mono>. The managed
            profile is <strong>created disabled</strong>: test it, then enable
            it (enabling runs the authority cutover ceremony).
          </p>
          {p.boundOperationId !== undefined && (
            <p>
              Re-sends the unresolved operation{" "}
              <Mono>{p.boundOperationId}</Mono>; the appliance replays a
              committed import or refuses a changed one — nothing is imported
              twice.
            </p>
          )}
        </>
      }
      impact="The import is fenced on the loaded registry revision and identified by an operation id recorded before dispatch. The legacy bind credential is copied server-side into the write-only profile material; it never transits this browser. The YAML file is not modified."
      rollback="Delete the imported provider; the legacy block stays the authenticator until a cutover."
      confirmLabel="Import"
      destructive={false}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

/** Typed abandon of an unresolved operation marker (nothing is sent). */
export function AbandonCeremony(
  p: CeremonyCommon & { marker: IdPRecoveryMarker; onConfirm: () => void },
): JSX.Element {
  const [typed, setTyped] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={3}
      title="Abandon the unresolved operation"
      body={
        <KeyValue
          items={[
            ["Operation", <Mono key="op">{p.marker.operationId}</Mono>],
            [
              "Intent",
              `${p.marker.action} ${p.marker.name} (${p.marker.type})`,
            ],
          ]}
        />
      }
      impact="Only this browser's recovery marker is discarded; the appliance's ledger record (if any) is untouched and stays visible on the legacy card lookup."
      rollback="None — the marker cannot be re-created."
      confirmLabel="Abandon"
      confirmWord={p.marker.operationId}
      typedValue={typed}
      onTypedChange={setTyped}
      result={p.result}
      {...(p.errorText !== undefined ? { errorText: p.errorText } : {})}
      onConfirm={p.onConfirm}
      onCancel={p.onCancel}
    />
  );
}

// ── Bounded outcome callouts ───────────────────────────────────────────────

export function IdPFenceCallout({
  refusal,
}: {
  refusal: IdPRefusal;
}): JSX.Element {
  const token =
    refusal.facts.documentRevision !== undefined
      ? `registry document revision ${refusal.facts.documentRevision}`
      : `entry revision ${String(refusal.facts.revision ?? 0)}`;
  return (
    <Callout
      variant="warning"
      title={
        refusal.code === "stale"
          ? "Stale fence — nothing was written"
          : "Fence required — nothing was written"
      }
      role="alert"
    >
      <Mono>{refusal.code}</Mono> (HTTP {String(refusal.status)}). The
      appliance's current {token}. Review the refreshed registry and repeat the
      change; nothing was retried.
    </Callout>
  );
}

const REFUSAL_TITLE: Record<string, string> = {
  referenced: "Refused — the provider is referenced by authentication rules",
  provider_compile_failed: "Refused — the provider could not be constructed",
  preflight_failed:
    "Refused — the directory connection preflight failed; nothing was written",
  import_source_required:
    "Refused — the import named no reviewed legacy source; nothing was written",
  import_source_stale:
    "Refused — the legacy source changed since it was reviewed; nothing was written (re-read and review the current source)",
  invalid_input: "Refused — the appliance rejected the candidate",
  vanished: "Refused — the provider no longer exists",
  not_found: "Refused — not found",
  persist_failed:
    "Refused — the registry write did not persist; nothing changed",
  outcome_unknown: "Outcome unknown — the write may have landed",
  registry_degraded: "Refused — the registry is degraded (repair it first)",
  persistence_not_configured:
    "Refused — this node has no registry persistence path",
  operation_id_required:
    "Refused — this write retires the legacy authenticator and needs an operation identity",
  cutover_confirm_required:
    "Refused — the cutover needs its confirmation value",
  confirm_mismatch: "Refused — the confirmation value did not match",
  operation_mismatch:
    "Refused — this operation identity is bound to a different candidate",
  operation_in_progress: "Refused — this operation is still being decided",
  operation_aborted:
    "Refused — this operation was aborted earlier; nothing was written",
  operation_outcome_unknown:
    "Refused — this operation's outcome awaits reconciliation",
  operation_ledger_degraded: "Refused — the operation ledger is degraded",
  operation_ledger_full:
    "Refused — the operation ledger is full of unresolved intents",
  operation_unsettled:
    "Refused — an earlier intent on this profile is unsettled",
  not_degraded: "Refused — the registry is not degraded",
  repair_unavailable: "Refused — the quarantine could not be completed at boot",
  upstream_error: "Refused — the issuer could not be reached",
  forbidden: "Refused — insufficient role",
  method_not_allowed: "Refused — method not allowed",
};

export function IdPRefusalCallout({
  refusal,
}: {
  refusal: IdPRefusal;
}): JSX.Element {
  const f = refusal.facts;
  return (
    <Callout
      variant={refusal.code === "outcome_unknown" ? "unknown" : "warning"}
      title={REFUSAL_TITLE[refusal.code] ?? "Refused"}
      role="alert"
    >
      <Mono>{refusal.code}</Mono> (HTTP {String(refusal.status)})
      {f.step !== undefined && (
        <span>
          {" "}
          · step <Mono>{f.step}</Mono>
        </span>
      )}
      {f.reason !== undefined && (
        <span>
          {" "}
          · reason <Mono>{f.reason}</Mono>
        </span>
      )}
      {f.detail !== undefined && (
        <span>
          {" "}
          · <Mono>{f.detail}</Mono> — look the operation up; do not retry
        </span>
      )}
      {f.confirmValue !== undefined &&
        refusal.code !== "cutover_confirm_required" && (
          <span> · the confirmation must match exactly</span>
        )}
      {f.revision !== undefined && (
        <span> · current entry revision {String(f.revision)}</span>
      )}
      {f.references !== undefined && (
        <ul>
          {f.references.map((r) => (
            <li key={`${r.consumerType}:${r.id}`}>{consumerDestination(r)}</li>
          ))}
        </ul>
      )}
    </Callout>
  );
}

export function IdPUnprovenCallout({
  action,
  status,
}: {
  action: string;
  status: number | undefined;
}): JSX.Element {
  return (
    <Callout
      variant="unknown"
      title={`Outcome unproven — ${action}`}
      role="alert"
    >
      The answer to this action could not be verified
      {status !== undefined ? ` (HTTP ${String(status)})` : ""}. The change may
      already be applied on the appliance; nothing was retried. Every mutation
      stays blocked until a registry read succeeds.
    </Callout>
  );
}
