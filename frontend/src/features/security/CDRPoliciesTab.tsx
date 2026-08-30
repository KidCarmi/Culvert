// 2E-C Policies: CDR sanitization rules. First-match by priority (highest
// first); when nothing matches, the startup defaults (default profile +
// mode) apply. The rule NAME is the rule's identity — unique (duplicates are
// a 409) and the only key deletion accepts. Mode strings render VERBATIM:
// the engine treats an unknown mode as ENFORCE (fail-safe), but this page
// never relabels what is configured. Profile names are validated only at
// runtime against what the engine advertises — a typo shows up as engine
// errors, not as a form error here (recorded contract).
import { useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import { InputField, SelectField } from "../../design-system/forms";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../design-system/dialog";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage, type ObjectPageState } from "../objects/useObjectPage";
import { unknownOutcome, serverErrorText } from "../../shared/mutationOutcome";
import {
  addCDRPolicy,
  deleteCDRPolicy,
  getCDRPolicies,
  type CDRPolicies,
  type CDRPolicyRule,
} from "../../api/cdr";
import styles from "../policy/policy.module.css";

type PolPage = ObjectPageState<CDRPolicies>;

const MODES = ["ENFORCE", "REPORT_ONLY", "BYPASS_WITH_REPORT"] as const;

function ruleMatchSummary(r: CDRPolicyRule): string {
  const parts: string[] = [];
  if (r.sourceIP !== "") parts.push(`srcIP=${r.sourceIP}`);
  if (r.sourceIdentity !== "") parts.push(`identity=${r.sourceIdentity}`);
  if (r.sourceGroup !== "") parts.push(`group=${r.sourceGroup}`);
  if (r.authSource !== "") parts.push(`authSrc=${r.authSource}`);
  if (r.destFQDN !== "") parts.push(`destFQDN=${r.destFQDN}`);
  if (r.destCategory !== "") parts.push(`destCat=${r.destCategory}`);
  if (r.destCategoryGroup !== "")
    parts.push(`destCatGrp=${r.destCategoryGroup}`);
  if (r.destCountry.length > 0)
    parts.push(`destCountry=${r.destCountry.join(",")}`);
  return parts.length === 0 ? "any traffic" : parts.join(" ");
}

function DeleteRuleDialog({
  page,
  target,
  onDone,
  onCancel,
}: {
  page: PolPage;
  target: CDRPolicyRule;
  onDone: () => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={`Delete rule ${target.name}`}
      body={
        <>
          Removes the rule <Mono>{target.name}</Mono> (priority{" "}
          {String(target.priority)}, matches {ruleMatchSummary(target)}, profile{" "}
          <Mono>
            {target.profileName === "" ? "default" : target.profileName}
          </Mono>
          , mode <Mono>{target.mode === "" ? "ENFORCE" : target.mode}</Mono>).
          Traffic it matched falls through to lower-priority rules or the
          startup defaults on the next request.
        </>
      }
      impact="Enforcement changes immediately: matched downloads are handled by whichever rule or default now applies."
      rollback="Re-create the rule with the same fields (this surface has no config versioning by design)."
      confirmLabel="Delete rule"
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (result === "pending") return;
        const signal = page.owner.begin();
        setResult("pending");
        deleteCDRPolicy(target.name, signal)
          .then(() => {
            onDone();
            page.refreshToResolve();
          })
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("delete");
              setResult("unknown");
              onCancel();
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The delete failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={() => {
        if (result !== "pending") onCancel();
      }}
    />
  );
}

interface RuleForm {
  name: string;
  priority: string;
  mode: string;
  profileName: string;
  sourceIP: string;
  sourceGroup: string;
  destFQDN: string;
  destCategory: string;
}

const EMPTY_RULE: RuleForm = {
  name: "",
  priority: "10",
  mode: "ENFORCE",
  profileName: "",
  sourceIP: "",
  sourceGroup: "",
  destFQDN: "",
  destCategory: "",
};

export function CDRPoliciesTab({ isAdmin }: { isAdmin: boolean }): JSX.Element {
  const page = useObjectPage(["security", "cdr", "policies"], getCDRPolicies);
  const d = page.q.data;
  const [form, setForm] = useState<RuleForm>(EMPTY_RULE);
  const [addBusy, setAddBusy] = useState(false);
  const [addError, setAddError] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<CDRPolicyRule | null>(null);

  const priorityNum = Number(form.priority);
  const canAdd =
    form.name.trim() !== "" && Number.isInteger(priorityNum) && !addBusy;

  const submitAdd = (): void => {
    if (!canAdd || page.unknown !== null) return;
    const signal = page.owner.begin();
    setAddBusy(true);
    setAddError("");
    addCDRPolicy(
      {
        name: form.name.trim(),
        priority: priorityNum,
        mode: form.mode,
        profileName: form.profileName.trim(),
        sourceIP: form.sourceIP.trim(),
        sourceIdentity: "",
        sourceGroup: form.sourceGroup.trim(),
        destFQDN: form.destFQDN.trim(),
        destCategory: form.destCategory.trim(),
      },
      signal,
    )
      .then(() => {
        setForm(EMPTY_RULE);
        page.refreshToResolve();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("create");
          return;
        }
        setAddError(serverErrorText(err, "The rule could not be added."));
      })
      .finally(() => {
        setAddBusy(false);
        page.owner.settle(signal);
      });
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={d !== undefined}
          onRefresh={page.refreshToResolve}
        />
      </div>

      {page.unknown !== null && (
        <Callout variant="warning" title="Last change unconfirmed">
          The outcome of the last change is unknown (the appliance did not
          answer). Refresh to load the authoritative ruleset before making
          further changes.
        </Callout>
      )}

      {d === undefined && page.q.isPending && (
        <Skeleton>Loading CDR policy rules…</Skeleton>
      )}
      {d === undefined && page.q.isError && (
        <ErrorState title="CDR policy rules unavailable">
          The CDR policy ruleset could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {d !== undefined && (
        <Card
          title={`Rules (${String(d.count)}) — first match by priority, highest first`}
        >
          {d.rules.length === 0 ? (
            <EmptyState title="No CDR policy rules">
              With no rules, every CDR-processed download uses the startup
              defaults (default profile + mode) shown on Overview.
            </EmptyState>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <caption className="sr-only">CDR policy rules</caption>
                <thead>
                  <tr>
                    <th scope="col">Priority</th>
                    <th scope="col">Name</th>
                    <th scope="col">Matches</th>
                    <th scope="col">Profile</th>
                    <th scope="col">Mode</th>
                    <th scope="col">Hits (since restart)</th>
                    {isAdmin && <th scope="col">Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {d.rules.map((r) => (
                    <tr key={r.name}>
                      <td>{String(r.priority)}</td>
                      <td>
                        <Mono>{r.name}</Mono>
                        {!r.enabled && " (disabled)"}
                      </td>
                      <td>{ruleMatchSummary(r)}</td>
                      <td>
                        <Mono>
                          {r.profileName === "" ? "default" : r.profileName}
                        </Mono>
                      </td>
                      <td>
                        <Mono>{r.mode === "" ? "ENFORCE" : r.mode}</Mono>
                      </td>
                      <td>{String(r.hitCount)}</td>
                      {isAdmin && (
                        <td>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={page.unknown !== null}
                            onClick={() => {
                              setDeleteTarget(r);
                            }}
                          >
                            Delete…
                          </Button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className={styles.refDetail}>
            Hit counters are process-lifetime (reset on restart) and are not
            persisted. This surface has no draft/commit or config versioning by
            design — changes apply immediately and are audited.
          </p>
        </Card>
      )}

      {isAdmin && (
        <Card title="Add a rule">
          <InputField
            label="Name (unique — this is the rule's identity)"
            required
            value={form.name}
            onChange={(e) => {
              setForm({ ...form, name: e.target.value });
            }}
          />
          <InputField
            label="Priority (higher matches first)"
            required
            inputMode="numeric"
            value={form.priority}
            onChange={(e) => {
              setForm({ ...form, priority: e.target.value });
            }}
          />
          <SelectField
            label="Mode"
            value={form.mode}
            onChange={(e) => {
              setForm({ ...form, mode: e.target.value });
            }}
          >
            {MODES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </SelectField>
          <InputField
            label="Profile name"
            help="Must match a profile the engine advertises (see Overview); empty uses the default. Validated only at runtime."
            value={form.profileName}
            onChange={(e) => {
              setForm({ ...form, profileName: e.target.value });
            }}
          />
          <InputField
            label="Source IP / CIDR (empty = any)"
            value={form.sourceIP}
            onChange={(e) => {
              setForm({ ...form, sourceIP: e.target.value });
            }}
          />
          <InputField
            label="Source group (empty = any)"
            value={form.sourceGroup}
            onChange={(e) => {
              setForm({ ...form, sourceGroup: e.target.value });
            }}
          />
          <InputField
            label="Destination FQDN (exact or wildcard; empty = any)"
            value={form.destFQDN}
            onChange={(e) => {
              setForm({ ...form, destFQDN: e.target.value });
            }}
          />
          <InputField
            label="Destination category (empty = any)"
            value={form.destCategory}
            onChange={(e) => {
              setForm({ ...form, destCategory: e.target.value });
            }}
          />
          {addError !== "" && (
            <Callout variant="critical" title="Rule not added">
              {addError}
            </Callout>
          )}
          <div className={styles.toolbar}>
            <Button
              variant="primary"
              disabled={!canAdd || page.unknown !== null}
              onClick={submitAdd}
            >
              {addBusy ? "Adding…" : "Add rule"}
            </Button>
          </div>
        </Card>
      )}

      {deleteTarget !== null && (
        <DeleteRuleDialog
          page={page}
          target={deleteTarget}
          onDone={() => {
            setDeleteTarget(null);
          }}
          onCancel={() => {
            setDeleteTarget(null);
          }}
        />
      )}
    </div>
  );
}
