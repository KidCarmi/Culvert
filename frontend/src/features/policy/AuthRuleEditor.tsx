// 2C.2 — the Authentication Rule editor (create + edit). ADMIN-only (the
// backend is intentionally stricter than the Stage-2 operator surface — do
// not lower). Stage-1 changes are LIVE immediately: there is no draft staging
// for auth rules, and the editor says so on every save; when an Access-Policy
// Draft is active it additionally warns (§9) that a save invalidates that
// draft's running-generation baseline — non-blocking, the backend permits it.
//
// Schema fidelity (§11): the form is seeded from writeSeedFromAuthView, which
// REFUSES any rule this client cannot faithfully rebuild (unknown outcome,
// unknown predicate type, missing spec) — such rules are read-only in the
// list and never reach this editor. Field visibility mirrors the SERVER
// validator without re-implementing it: providerRefs only for SSORequired,
// broadExemption only for Exempt, a destination note per outcome. Server
// warnings and errors render verbatim (§14).
import { useMemo, useState, type JSX } from "react";
import { Button, Callout } from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import {
  Checkbox,
  InputField,
  SelectField,
  TextareaField,
} from "../../design-system/forms";
import type {
  AuthOutcome,
  AuthRuleView,
  AuthRuleWrite,
  IdPProviderRef,
} from "../../api/policyAuth";
import {
  AUTH_OUTCOMES,
  AUTH_PROTOCOLS,
  SUBJECT_PREDICATE_CIDR,
  writeSeedFromAuthView,
} from "../../api/policyAuth";
import type { PolicyConflict } from "../../api/policyWrite";
import styles from "./policy.module.css";

export interface AuthRuleEditorOptions {
  categories: readonly string[];
  categoryGroups: readonly string[];
  providers: readonly IdPProviderRef[];
}

export type AuthRuleEditorMode =
  { kind: "create" } | { kind: "edit"; rule: AuthRuleView };

export interface AuthRuleEditorProps {
  mode: AuthRuleEditorMode;
  options: AuthRuleEditorOptions;
  /** the server's Exempt-is-not-Allow note, rendered verbatim (§12) */
  exemptNote: string;
  /** an Access-Policy Draft is currently active (§9 pre-save warning) */
  draftActive: boolean;
  blocked: boolean;
  pending: boolean;
  conflict: PolicyConflict | null;
  serverError: string;
  onSubmit: (write: AuthRuleWrite) => void;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
}

function emptyAuthWrite(): AuthRuleWrite {
  return {
    name: "",
    enabled: undefined,
    outcome: "Exempt",
    protocol: "",
    method: "",
    owner: "",
    reason: "",
    expiresAt: "",
    broadExemption: false,
    providerRefs: [],
    predicates: [{ type: SUBJECT_PREDICATE_CIDR, values: [] }],
    destFQDN: "",
    destCategory: "",
    destCategoryGroup: "",
    schedule: undefined,
    comment: "",
  };
}

/** Client-side mirror of the server validator (UX only, server authoritative). */
export function validateAuthWrite(w: AuthRuleWrite): string {
  if (w.name.trim() === "") return "A rule name is required.";
  if (w.owner.trim() === "") return "An owner is required.";
  if (w.reason.trim() === "") return "A reason is required.";
  if (
    w.predicates.length === 0 ||
    w.predicates.every((p) => p.values.length === 0)
  ) {
    return "At least one source IP or CIDR is required — an auth rule must be scoped to specific clients.";
  }
  const hasDest =
    w.destFQDN !== "" || w.destCategory !== "" || w.destCategoryGroup !== "";
  if (w.outcome === "Exempt" && !hasDest && !w.broadExemption) {
    return "An Exempt rule requires a destination, or the explicit all-destinations acknowledgement.";
  }
  if (w.outcome !== "Exempt" && !hasDest) {
    return `A ${w.outcome} rule requires a destination (FQDN, category, or category group).`;
  }
  return "";
}

const OUTCOME_HELP: Record<AuthOutcome, string> = {
  Exempt:
    "Skips end-user authentication for matching requests. NOT an allow — Stage-2 Access Policy still decides, and default-deny still applies.",
  CredentialRequired:
    "A non-interactive credential challenge (407) before the request proceeds. Not Allow or Block — Stage-2 decides after authentication.",
  SSORequired:
    "An interactive browser SSO redirect before the request proceeds; non-browser and CONNECT clients are failed closed (403). Stage-2 decides after SSO completes.",
};

function OptionSelectLocal({
  label,
  help,
  value,
  options,
  noneLabel,
  onChange,
}: {
  label: string;
  help?: string;
  value: string;
  options: readonly string[];
  noneLabel: string;
  onChange: (v: string) => void;
}): JSX.Element {
  const missing = value !== "" && !options.includes(value);
  return (
    <SelectField
      label={label}
      {...(help !== undefined ? { help } : {})}
      value={value}
      onChange={(e) => {
        onChange(e.target.value);
      }}
    >
      <option value="">{noneLabel}</option>
      {missing && <option value={value}>{value} (not in current list)</option>}
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </SelectField>
  );
}

/** Newline/comma-separated CIDR entry for one subject predicate group. */
function cidrTextToValues(text: string): readonly string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

export function AuthRuleEditor(props: AuthRuleEditorProps): JSX.Element {
  const {
    mode,
    options,
    exemptNote,
    draftActive,
    blocked,
    pending,
    conflict,
    serverError,
    onSubmit,
    onCancel,
    onDirtyChange,
  } = props;

  const seed = useMemo<AuthRuleWrite>(() => {
    if (mode.kind === "edit") {
      // The page only opens the editor for editable rules; a refusal here is
      // a defensive fallback, never a silent guess.
      return writeSeedFromAuthView(mode.rule) ?? emptyAuthWrite();
    }
    return emptyAuthWrite();
  }, [mode]);
  const [w, setWState] = useState<AuthRuleWrite>(seed);
  // The CIDR textareas hold raw text so typing commas/newlines round-trips;
  // parsed values are derived on change and at submit.
  const [cidrTexts, setCidrTexts] = useState<readonly string[]>(
    seed.predicates.map((p) => p.values.join("\n")),
  );
  const [clientError, setClientError] = useState("");

  const setW = (patch: Partial<AuthRuleWrite>): void => {
    setWState((cur) => ({ ...cur, ...patch }));
    onDirtyChange(true);
  };

  const setCidrText = (idx: number, text: string): void => {
    setCidrTexts((cur) => cur.map((t, i) => (i === idx ? text : t)));
    setWState((cur) => ({
      ...cur,
      predicates: cur.predicates.map((p, i) =>
        i === idx
          ? { type: SUBJECT_PREDICATE_CIDR, values: cidrTextToValues(text) }
          : p,
      ),
    }));
    onDirtyChange(true);
  };

  const addPredicate = (): void => {
    setCidrTexts((cur) => [...cur, ""]);
    setWState((cur) => ({
      ...cur,
      predicates: [
        ...cur.predicates,
        { type: SUBJECT_PREDICATE_CIDR, values: [] },
      ],
    }));
    onDirtyChange(true);
  };

  const removePredicate = (idx: number): void => {
    setCidrTexts((cur) => cur.filter((_, i) => i !== idx));
    setWState((cur) => ({
      ...cur,
      predicates: cur.predicates.filter((_, i) => i !== idx),
    }));
    onDirtyChange(true);
  };

  const toggleProviderRef = (id: string): void => {
    setWState((cur) => ({
      ...cur,
      providerRefs: cur.providerRefs.includes(id)
        ? cur.providerRefs.filter((r) => r !== id)
        : [...cur.providerRefs, id],
    }));
    onDirtyChange(true);
  };

  const submit = (): void => {
    const err = validateAuthWrite(w);
    setClientError(err);
    if (err !== "") return;
    onSubmit(w);
  };

  const interactiveProviders = options.providers.filter(
    (p) => p.interactive && p.enabled,
  );
  // Dangling refs (§13): selected on the rule but not an enabled interactive
  // provider — surfaced degraded, preserved unless deliberately removed,
  // never silently dropped on round-trip.
  const danglingRefs = w.providerRefs.filter(
    (r) => !interactiveProviders.some((p) => p.id === r),
  );

  const title =
    mode.kind === "create"
      ? "New authentication rule"
      : `Edit authentication rule: ${mode.rule.name}`;

  return (
    <Dialog open onClose={pending ? () => undefined : onCancel} title={title}>
      <DialogBody>
        <p className={styles.editorScope}>
          Authentication rules take effect IMMEDIATELY in the running Stage-1
          policy when saved — they are never staged into the Access-Policy
          Draft, and Require Commit does not apply to them.
        </p>
        {draftActive && (
          <Callout variant="warning" title="An Access Policy Draft is active">
            Saving this change takes effect immediately in the running Stage-1
            policy and will invalidate that draft&apos;s running-generation
            baseline — the draft will need to be reverted and re-staged before
            it can be committed.
          </Callout>
        )}

        {conflict !== null && (
          <Callout variant="warning" title="The rulebase changed" role="alert">
            {conflict.error} Your entries are preserved below. Refresh the
            rulebase, review the current state, and save again deliberately.
          </Callout>
        )}
        {serverError !== "" && (
          <Callout variant="critical" title="The appliance rejected the rule">
            {serverError}
          </Callout>
        )}
        {clientError !== "" && (
          <Callout variant="warning" title="Check the form">
            {clientError}
          </Callout>
        )}
        {blocked && (
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The last change&apos;s outcome is unconfirmed. Refresh the rulebase
            before submitting again — your entries stay here for review.
          </Callout>
        )}

        <fieldset className={styles.editorGroup}>
          <legend>Rule</legend>
          <InputField
            label="Rule name"
            required
            value={w.name}
            onChange={(e) => {
              setW({ name: e.target.value });
            }}
          />
          <SelectField
            label="Outcome"
            help={OUTCOME_HELP[w.outcome]}
            value={w.outcome}
            onChange={(e) => {
              const v = e.target.value;
              if (v === "Exempt" || v === "CredentialRequired" || v === "SSORequired") {
                setW({ outcome: v });
              }
            }}
          >
            {AUTH_OUTCOMES.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </SelectField>
          {w.outcome === "Exempt" && exemptNote !== "" && (
            <Callout variant="info" title="Exempt is not Allow">
              {exemptNote}
            </Callout>
          )}
          <Checkbox
            label="Enabled"
            checked={w.enabled ?? true}
            onChange={(e) => {
              setW({ enabled: e.target.checked });
            }}
          />
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Source scope (client IPs / CIDRs)</legend>
          {cidrTexts.map((text, idx) => (
            // Position-keyed: source groups have no identity beyond their slot.
            <div key={idx}>
              <TextareaField
                label={
                  cidrTexts.length === 1
                    ? "IPs / CIDRs (one per line)"
                    : `Source group ${String(idx + 1)} (one per line)`
                }
                help="Requests must match EVERY source group; values within a group are alternatives (OR)."
                value={text}
                onChange={(e) => {
                  setCidrText(idx, e.target.value);
                }}
              />
              {cidrTexts.length > 1 && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    removePredicate(idx);
                  }}
                >
                  Remove source group {String(idx + 1)}
                </Button>
              )}
            </div>
          ))}
          <Button size="sm" variant="ghost" onClick={addPredicate}>
            Add source group
          </Button>
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Destination</legend>
          <InputField
            label="Destination FQDN"
            help="Exact host or wildcard pattern (e.g. *.example.com)."
            value={w.destFQDN}
            onChange={(e) => {
              setW({ destFQDN: e.target.value });
            }}
          />
          <OptionSelectLocal
            label="Destination category"
            value={w.destCategory}
            options={options.categories}
            noneLabel="(none)"
            onChange={(v) => {
              setW({ destCategory: v });
            }}
          />
          <OptionSelectLocal
            label="Destination category group"
            value={w.destCategoryGroup}
            options={options.categoryGroups}
            noneLabel="(none)"
            onChange={(v) => {
              setW({ destCategoryGroup: v });
            }}
          />
          {w.outcome === "Exempt" ? (
            <Checkbox
              label="Waive authentication for ALL destinations (broad exemption)"
              checked={w.broadExemption}
              onChange={(e) => {
                setW({ broadExemption: e.target.checked });
              }}
            />
          ) : (
            <p className={styles.editorScope}>
              A {w.outcome} rule requires a concrete destination — a blanket
              scope is not permitted for challenge outcomes.
            </p>
          )}
        </fieldset>

        {w.outcome === "SSORequired" && (
          <fieldset className={styles.editorGroup}>
            <legend>SSO identity providers</legend>
            <p className={styles.editorScope}>
              Leave all unchecked to accept ANY compatible enabled interactive
              provider (OIDC or SAML). Selecting providers restricts which may
              satisfy this rule. No provider secrets are shown or required.
            </p>
            {interactiveProviders.length === 0 && danglingRefs.length === 0 && (
              <Callout variant="warning" title="No interactive IdP available">
                No enabled OIDC or SAML identity provider is configured.
                SSORequired can be saved without provider restrictions, but the
                runtime will fail matching requests closed until one exists.
              </Callout>
            )}
            {interactiveProviders.map((p) => (
              <Checkbox
                key={p.id}
                label={`${p.name === "" ? p.id : p.name} (${p.type})`}
                checked={w.providerRefs.includes(p.id)}
                onChange={() => {
                  toggleProviderRef(p.id);
                }}
              />
            ))}
            {danglingRefs.map((r) => (
              <div key={r}>
                <Checkbox
                  label={`${r} — no longer an enabled interactive provider`}
                  checked
                  onChange={() => {
                    toggleProviderRef(r);
                  }}
                />
              </div>
            ))}
            {danglingRefs.length > 0 && (
              <Callout variant="warning" title="Unresolved provider reference">
                A referenced provider is missing, disabled, or not interactive.
                It is preserved unless you uncheck it — but the appliance will
                refuse to save while an unresolved reference remains.
              </Callout>
            )}
          </fieldset>
        )}

        <fieldset className={styles.editorGroup}>
          <legend>Conditions</legend>
          <SelectField
            label="Protocol"
            value={w.protocol}
            onChange={(e) => {
              const v = e.target.value;
              if (v === "" || v === "http" || v === "connect")
                setW({ protocol: v });
            }}
          >
            {AUTH_PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                {p === "" ? "Any" : p}
              </option>
            ))}
          </SelectField>
          <InputField
            label="HTTP method (optional)"
            help={
              w.protocol === "connect"
                ? "Ignored for the connect protocol (the appliance flags this)."
                : "Empty = any method."
            }
            value={w.method}
            onChange={(e) => {
              setW({ method: e.target.value });
            }}
          />
          <InputField
            label="Expires at (optional)"
            help="RFC3339 UTC timestamp, e.g. 2027-01-01T00:00:00Z. Empty = no expiry (flagged as a breadth risk)."
            value={w.expiresAt}
            onChange={(e) => {
              setW({ expiresAt: e.target.value });
            }}
          />
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Ownership</legend>
          <InputField
            label="Owner"
            required
            help="Who is accountable for this authentication exception."
            value={w.owner}
            onChange={(e) => {
              setW({ owner: e.target.value });
            }}
          />
          <TextareaField
            label="Reason"
            required
            value={w.reason}
            onChange={(e) => {
              setW({ reason: e.target.value });
            }}
          />
          <TextareaField
            label="Comment (optional)"
            value={w.comment}
            onChange={(e) => {
              setW({ comment: e.target.value });
            }}
          />
        </fieldset>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" disabled={pending} onClick={onCancel}>
          Cancel
        </Button>
        <Button
          disabled={blocked || pending || conflict !== null}
          onClick={submit}
        >
          {pending
            ? "Saving…"
            : mode.kind === "create"
              ? "Create rule (live)"
              : "Save changes (live)"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
