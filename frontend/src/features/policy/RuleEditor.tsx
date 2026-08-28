// 2B.2 — the Access Rule editor (create + edit) as a deliberate dialog that
// works at 1024×768 / ~200% zoom. Fields are grouped semantically (§33);
// action-specific behavior mirrors the SERVER validator (§34) without
// inventing semantics: Redirect requires an absolute http/https redirectURL,
// TLS/decryption controls surface only for Inspect (values are PRESERVED
// when hidden, never cleared), schedules round-trip exactly.
//
// Editing is FULL REPLACEMENT: the form is seeded from the write-fidelity
// view (writeSeedFromView) so every editable field — including the absent
// tri-states — is preserved unless the operator deliberately changes it.
// Server-owned metadata is displayed nowhere here and never submitted.
//
// Mutation doctrine (§13/§14/§24/§25): every submit is fenced with the
// version of the snapshot being edited; retry=false; no optimistic state.
// A structured 409 blocks resubmission until the caller refetches server
// truth (form content preserved); an unknown transport outcome latches the
// page-level uncertainty and keeps the form content for review.
import { useMemo, useState, type JSX } from "react";
import { Button, Callout, Spinner } from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import {
  Checkbox,
  InputField,
  SelectField,
  TextareaField,
} from "../../design-system/forms";
import type { PolicyRuleView, PolicySchedule } from "../../api/policy";
import type {
  AccessRuleWrite,
  PolicyConflict,
  RuleAction,
  RuleSSLAction,
} from "../../api/policyWrite";
import {
  RULE_ACTIONS,
  SSL_ACTIONS,
  isRuleAction,
  isRuleSSLAction,
  writeSeedFromView,
} from "../../api/policyWrite";
import styles from "./policy.module.css";

const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;

export interface RuleEditorOptions {
  categories: readonly string[];
  categoryGroups: readonly string[];
  fileProfiles: readonly string[];
  decryptionProfiles: readonly string[];
}

export type RuleEditorMode =
  { kind: "create" } | { kind: "edit"; rule: PolicyRuleView };

export interface RuleEditorProps {
  mode: RuleEditorMode;
  /** true while the surrounding surface targets the shared draft candidate */
  staged: boolean;
  options: RuleEditorOptions;
  /** submit is disabled while the page-level uncertainty latch is armed */
  blocked: boolean;
  pending: boolean;
  /** the structured 409 for THIS form's last submit (caller-owned) */
  conflict: PolicyConflict | null;
  /** bounded server validation detail for the last submit */
  serverError: string;
  onSubmit: (write: AccessRuleWrite) => void;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
}

function emptyWrite(): AccessRuleWrite {
  return {
    name: "",
    priority: 0,
    enabled: undefined,
    sourceIP: "",
    sourceIdentity: "",
    sourceGroup: "",
    authSource: "",
    destFQDN: "",
    destCategory: "",
    destCategoryGroup: "",
    destCountry: [],
    schedule: undefined,
    sslAction: "Bypass",
    fileFiltering: false,
    fileProfile: "",
    logFullUri: false,
    logTraffic: undefined,
    stripAlpn: undefined,
    tlsSkipVerify: false,
    decryptionProfile: "",
    action: "Allow",
    redirectURL: "",
    comment: "",
    ruleType: "access",
  };
}

/** Client-side mirror of the server validator (UX only, server authoritative). */
export function validateWrite(w: AccessRuleWrite): string {
  if (w.name.trim() === "") return "A rule name is required.";
  if (w.action === "Redirect") {
    if (w.redirectURL === "")
      return "A redirect URL is required when the action is Redirect.";
    if (!/^https?:\/\/.+/.test(w.redirectURL))
      return "The redirect URL must be an absolute http/https URL.";
  }
  const s = w.schedule;
  if (s !== undefined && s.timezone !== "") {
    try {
      new Intl.DateTimeFormat("en-US", { timeZone: s.timezone });
    } catch {
      return `Unknown schedule timezone: ${s.timezone}`;
    }
  }
  return "";
}

/** A select over an option source that also keeps a value the source does not
 * (yet) list — a stale option list must never silently rewrite a rule. */
function OptionSelect({
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

export function RuleEditor(props: RuleEditorProps): JSX.Element {
  const {
    mode,
    staged,
    options,
    blocked,
    pending,
    conflict,
    serverError,
    onSubmit,
    onCancel,
    onDirtyChange,
  } = props;

  const seed = useMemo<AccessRuleWrite>(
    () => (mode.kind === "edit" ? writeSeedFromView(mode.rule) : emptyWrite()),
    [mode],
  );
  const [w, setWState] = useState<AccessRuleWrite>(seed);
  const [clientError, setClientError] = useState("");
  const setW = (patch: Partial<AccessRuleWrite>): void => {
    setWState((cur) => {
      const next = { ...cur, ...patch };
      onDirtyChange(true);
      return next;
    });
  };

  const scheduleOn = w.schedule !== undefined;
  const sched: PolicySchedule = w.schedule ?? {
    days: [],
    timeStart: "",
    timeEnd: "",
    timezone: "",
  };
  const setSched = (patch: Partial<PolicySchedule>): void => {
    setW({ schedule: { ...sched, ...patch } });
  };

  const submit = (): void => {
    const err = validateWrite(w);
    setClientError(err);
    if (err !== "") return;
    onSubmit(w);
  };

  const title =
    mode.kind === "create" ? "New access rule" : `Edit rule: ${mode.rule.name}`;

  return (
    <Dialog open onClose={pending ? () => undefined : onCancel} title={title}>
      <DialogBody>
        <p className={styles.editorScope}>
          {staged
            ? "This change will be STAGED in the shared Policy Draft — it does not change enforcement until the draft is committed."
            : "This change is LIVE immediately after saving."}
        </p>

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
          <legend>Identity / Source</legend>
          <InputField
            label="Rule name"
            required
            value={w.name}
            onChange={(e) => {
              setW({ name: e.target.value });
            }}
          />
          {mode.kind === "create" && (
            <InputField
              label="Priority (optional)"
              help="Requested evaluation slot. Leave 0 to let the appliance assign the next slot; a taken slot is reassigned by the server."
              inputMode="numeric"
              value={w.priority === 0 ? "" : String(w.priority)}
              onChange={(e) => {
                const n = Number(e.target.value);
                setW({
                  priority: Number.isInteger(n) && n > 0 ? n : 0,
                });
              }}
            />
          )}
          <Checkbox
            label="Rule enabled"
            checked={w.enabled ?? true}
            onChange={(e) => {
              setW({ enabled: e.target.checked });
            }}
          />
          <InputField
            label="Source IP / CIDR"
            help="Empty matches any client."
            value={w.sourceIP}
            onChange={(e) => {
              setW({ sourceIP: e.target.value });
            }}
          />
          <InputField
            label="Source identity"
            help="Authenticated username; empty matches any."
            value={w.sourceIdentity}
            onChange={(e) => {
              setW({ sourceIdentity: e.target.value });
            }}
          />
          <InputField
            label="Source group"
            help="IdP group/role membership; empty matches any."
            value={w.sourceGroup}
            onChange={(e) => {
              setW({ sourceGroup: e.target.value });
            }}
          />
          <InputField
            label="Auth source"
            help='IdP name (e.g. "okta", "local") or "unauth"; empty matches any.'
            value={w.authSource}
            onChange={(e) => {
              setW({ authSource: e.target.value });
            }}
          />
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Destination</legend>
          <InputField
            label="Destination FQDN"
            help="Exact or *.wildcard host; empty matches any."
            value={w.destFQDN}
            onChange={(e) => {
              setW({ destFQDN: e.target.value });
            }}
          />
          <OptionSelect
            label="URL category"
            value={w.destCategory}
            options={options.categories}
            noneLabel="(any category)"
            onChange={(v) => {
              setW({ destCategory: v });
            }}
          />
          <OptionSelect
            label="Category group"
            value={w.destCategoryGroup}
            options={options.categoryGroups}
            noneLabel="(no category group)"
            onChange={(v) => {
              setW({ destCategoryGroup: v });
            }}
          />
          <InputField
            label="Destination countries"
            help="Comma-separated ISO 3166-1 alpha-2 codes (e.g. DE,FR); empty matches any."
            value={w.destCountry.join(",")}
            onChange={(e) => {
              const codes = e.target.value
                .split(",")
                .map((c) => c.trim().toUpperCase())
                .filter((c) => c !== "");
              setW({ destCountry: codes });
            }}
          />
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Schedule</legend>
          <Checkbox
            label="Active on a schedule (otherwise always active)"
            checked={scheduleOn}
            onChange={(e) => {
              setW({
                schedule: e.target.checked
                  ? { days: [], timeStart: "", timeEnd: "", timezone: "" }
                  : undefined,
              });
            }}
          />
          {scheduleOn && (
            <>
              <div className={styles.dayRow}>
                {WEEKDAYS.map((d) => (
                  <Checkbox
                    key={d}
                    label={d}
                    checked={sched.days.includes(d)}
                    onChange={(e) => {
                      const days = e.target.checked
                        ? [...sched.days, d]
                        : sched.days.filter((x) => x !== d);
                      setSched({ days });
                    }}
                  />
                ))}
              </div>
              <InputField
                label="Start time"
                help='24-hour "HH:MM"; empty = any.'
                value={sched.timeStart}
                onChange={(e) => {
                  setSched({ timeStart: e.target.value });
                }}
              />
              <InputField
                label="End time"
                help='24-hour "HH:MM"; empty = any.'
                value={sched.timeEnd}
                onChange={(e) => {
                  setSched({ timeEnd: e.target.value });
                }}
              />
              <InputField
                label="Timezone"
                help="IANA name (e.g. Europe/Berlin); empty = UTC."
                value={sched.timezone}
                onChange={(e) => {
                  setSched({ timezone: e.target.value });
                }}
              />
            </>
          )}
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Action</legend>
          <SelectField
            label="Action"
            value={w.action}
            onChange={(e) => {
              const v = e.target.value;
              if (isRuleAction(v)) setW({ action: v });
            }}
          >
            {RULE_ACTIONS.map((a: RuleAction) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </SelectField>
          {w.action === "Redirect" && (
            <InputField
              label="Redirect URL"
              required
              help="Absolute http/https URL the client is redirected to."
              value={w.redirectURL}
              onChange={(e) => {
                setW({ redirectURL: e.target.value });
              }}
            />
          )}
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>TLS / Decryption</legend>
          <SelectField
            label="SSL action"
            help="Inspect decrypts matching tunnels; Bypass relays them opaquely."
            value={w.sslAction}
            onChange={(e) => {
              const v = e.target.value;
              if (isRuleSSLAction(v)) setW({ sslAction: v });
            }}
          >
            {SSL_ACTIONS.map((a: RuleSSLAction) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </SelectField>
          {w.sslAction === "Inspect" && (
            <>
              <OptionSelect
                label="Decryption profile"
                help="Governs how the tunnel is decrypted; overrides the inline TLS toggles below."
                value={w.decryptionProfile}
                options={options.decryptionProfiles}
                noneLabel="(no profile — inline settings apply)"
                onChange={(v) => {
                  setW({ decryptionProfile: v });
                }}
              />
              <Checkbox
                label="Inspect HTTP/2 natively (do not downgrade the tunnel to HTTP/1.1)"
                checked={w.stripAlpn === false}
                onChange={(e) => {
                  // Tri-state: false = native H2; explicit true = downgrade
                  // (same behavior as the pre-feature absent value).
                  setW({ stripAlpn: e.target.checked ? false : true });
                }}
              />
              <Checkbox
                label="Skip upstream certificate verification (use with caution)"
                checked={w.tlsSkipVerify}
                onChange={(e) => {
                  setW({ tlsSkipVerify: e.target.checked });
                }}
              />
            </>
          )}
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>File handling</legend>
          <OptionSelect
            label="File profile"
            help="Selecting a profile enables file-type filtering for matching traffic."
            value={w.fileProfile}
            options={options.fileProfiles}
            noneLabel="(no file filtering profile)"
            onChange={(v) => {
              // Mirror the server: a selected profile implies filtering on.
              setW({ fileProfile: v, fileFiltering: v !== "" });
            }}
          />
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Logging</legend>
          <Checkbox
            label="Log allowed traffic matching this rule"
            checked={w.logTraffic ?? true}
            onChange={(e) => {
              setW({ logTraffic: e.target.checked });
            }}
          />
          <Checkbox
            label="Log the full request URI (HTTPS requires SSL Inspect)"
            checked={w.logFullUri}
            onChange={(e) => {
              setW({ logFullUri: e.target.checked });
            }}
          />
        </fieldset>

        <fieldset className={styles.editorGroup}>
          <legend>Metadata / Comment</legend>
          <TextareaField
            label="Comment"
            help="Why this rule exists — shown in rule details and audit diffs."
            value={w.comment}
            onChange={(e) => {
              setW({ comment: e.target.value });
            }}
          />
        </fieldset>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button
          variant="primary"
          disabled={pending || blocked || conflict !== null}
          onClick={submit}
        >
          {pending ? <Spinner label="Saving" /> : null}
          {mode.kind === "create" ? "Create rule" : "Save rule"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
