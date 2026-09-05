// 2F-E — the node-local draft editor of one PAC profile: fields + a
// positional rules table (rules have no identity — reordering is positional,
// a recorded backend deferral). Every edit is LOCAL until "Save draft"
// sends it under the draftRevision fence; nothing here touches the active
// profile — publishing is the detail view's ceremony.
import { useEffect, useState, type JSX } from "react";
import { Button, Callout } from "../../../design-system/primitives";
import {
  Checkbox,
  InputField,
  SelectField,
  TextareaField,
} from "../../../design-system/forms";
import { useDirtyGuard } from "../../../shared/dirtyGuard";
import {
  PAC_AVAILABILITY_MODES,
  PAC_PRIVATE_NETWORKS,
  PAC_RULE_ACTIONS,
  PAC_RULE_KINDS,
} from "../../../api/pac";
import type {
  PacPool,
  PacProfile,
  PacProfileInput,
  PacRuleInput,
} from "../../../api/pac";
import styles from "../../policy/policy.module.css";

export function draftEquals(a: PacProfileInput, b: PacProfileInput): boolean {
  return (
    JSON.stringify(normalizeDraft(a)) === JSON.stringify(normalizeDraft(b))
  );
}

function normalizeDraft(d: PacProfileInput): unknown {
  return {
    name: d.name,
    description: d.description,
    enabled: d.enabled,
    poolId: d.poolId,
    privateNetworks: d.privateNetworks,
    availabilityMode: d.availabilityMode,
    rules: d.rules.map((r) => ({
      kind: r.kind,
      pattern: r.pattern,
      action: r.action,
      scheme: r.scheme ?? "",
      port: r.port ?? 0,
      poolId: r.poolId ?? "",
    })),
  };
}

export interface ProfileDraftEditorProps {
  serverDraft: PacProfile;
  pools: readonly PacPool[];
  disabled: boolean;
  saving: boolean;
  onSave: (draft: PacProfileInput) => void;
  onDirtyChange: (dirty: boolean) => void;
}

export function ProfileDraftEditor(p: ProfileDraftEditorProps): JSX.Element {
  const [draft, setDraft] = useState<PacProfileInput>(p.serverDraft);
  const [base, setBase] = useState<PacProfile>(p.serverDraft);
  // A fresh server draft (after save/refresh) re-seeds the editor ONLY when
  // the operator has no unsaved work — never silently discards edits.
  if (base !== p.serverDraft) {
    const wasDirty = !draftEquals(draft, base);
    setBase(p.serverDraft);
    if (!wasDirty) setDraft(p.serverDraft);
  }
  const dirty = !draftEquals(draft, p.serverDraft);
  const guard = useDirtyGuard(dirty, "the unsaved PAC draft changes");
  // Parent notification is an EFFECT (never a render-time parent setState):
  // the parent gates Publish on the editor's dirty state.
  const { onDirtyChange } = p;
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);
  const ro = p.disabled || p.saving;

  const setRule = (i: number, patch: Partial<PacRuleInput>): void => {
    setDraft({
      ...draft,
      rules: draft.rules.map((r, j) => (j === i ? { ...r, ...patch } : r)),
    });
  };
  const move = (i: number, dir: -1 | 1): void => {
    const j = i + dir;
    if (j < 0 || j >= draft.rules.length) return;
    const rules = [...draft.rules];
    const a = rules[i];
    const b = rules[j];
    if (a === undefined || b === undefined) return;
    rules[i] = b;
    rules[j] = a;
    setDraft({ ...draft, rules });
  };

  return (
    <div>
      {guard.element}
      <div className={styles.editorGroup}>
        <InputField
          label="Name"
          value={draft.name}
          disabled={ro}
          onChange={(e) => {
            setDraft({ ...draft, name: e.target.value });
          }}
        />
        <TextareaField
          label="Description"
          value={draft.description}
          disabled={ro}
          rows={2}
          onChange={(e) => {
            setDraft({ ...draft, description: e.target.value });
          }}
        />
        <Checkbox
          label="Enabled (served at its PAC path)"
          checked={draft.enabled}
          disabled={ro}
          onChange={(e) => {
            setDraft({ ...draft, enabled: e.target.checked });
          }}
        />
        <SelectField
          label="Default pool"
          value={draft.poolId}
          disabled={ro}
          onChange={(e) => {
            setDraft({ ...draft, poolId: e.target.value });
          }}
        >
          <option value="">— none —</option>
          {p.pools.map((pool) => (
            <option key={pool.id} value={pool.id}>
              {pool.name !== "" ? `${pool.name} (${pool.id})` : pool.id}
            </option>
          ))}
        </SelectField>
        <SelectField
          label="Private networks"
          help="direct = RFC1918/link-local destinations bypass the proxy (a DIRECT path); proxy = everything goes through the pool"
          value={draft.privateNetworks}
          disabled={ro}
          onChange={(e) => {
            setDraft({ ...draft, privateNetworks: e.target.value });
          }}
        >
          {PAC_PRIVATE_NETWORKS.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </SelectField>
        <SelectField
          label="Availability mode"
          help="secure = never DIRECT; balanced = explicit DIRECT rules only; availability = falls back to DIRECT when the proxy is unreachable (a DIRECT path)"
          value={draft.availabilityMode}
          disabled={ro}
          onChange={(e) => {
            setDraft({ ...draft, availabilityMode: e.target.value });
          }}
        >
          {PAC_AVAILABILITY_MODES.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </SelectField>
      </div>
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <caption className={styles.srOnly}>Draft rules (positional)</caption>
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Kind</th>
              <th scope="col">Pattern</th>
              <th scope="col">Action</th>
              <th scope="col">Pool</th>
              {!ro && <th scope="col">Order</th>}
            </tr>
          </thead>
          <tbody>
            {draft.rules.map((r, i) => (
              <tr key={`rule-${String(i)}`}>
                <td>{i + 1}</td>
                <td>
                  <SelectField
                    label={`Rule ${String(i + 1)} kind`}
                    value={r.kind}
                    disabled={ro}
                    onChange={(e) => {
                      setRule(i, { kind: e.target.value });
                    }}
                  >
                    {PAC_RULE_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {k}
                      </option>
                    ))}
                  </SelectField>
                </td>
                <td>
                  <InputField
                    label={`Rule ${String(i + 1)} pattern`}
                    value={r.pattern}
                    disabled={ro}
                    onChange={(e) => {
                      setRule(i, { pattern: e.target.value });
                    }}
                  />
                </td>
                <td>
                  <SelectField
                    label={`Rule ${String(i + 1)} action`}
                    value={r.action}
                    disabled={ro}
                    onChange={(e) => {
                      setRule(i, { action: e.target.value });
                    }}
                  >
                    {PAC_RULE_ACTIONS.map((a) => (
                      <option key={a} value={a}>
                        {a === "direct" ? "direct (BYPASS)" : a}
                      </option>
                    ))}
                  </SelectField>
                </td>
                <td>
                  {r.action === "use_pool" ? (
                    <SelectField
                      label={`Rule ${String(i + 1)} pool`}
                      value={r.poolId ?? ""}
                      disabled={ro}
                      onChange={(e) => {
                        setRule(i, { poolId: e.target.value });
                      }}
                    >
                      <option value="">— profile default —</option>
                      {p.pools.map((pool) => (
                        <option key={pool.id} value={pool.id}>
                          {pool.id}
                        </option>
                      ))}
                    </SelectField>
                  ) : (
                    "—"
                  )}
                </td>
                {!ro && (
                  <td className={styles.rowActions}>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        move(i, -1);
                      }}
                      disabled={i === 0}
                    >
                      Up
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        move(i, 1);
                      }}
                      disabled={i === draft.rules.length - 1}
                    >
                      Down
                    </Button>
                    <Button
                      size="sm"
                      variant="danger-quiet"
                      onClick={() => {
                        setDraft({
                          ...draft,
                          rules: draft.rules.filter((_, j) => j !== i),
                        });
                      }}
                    >
                      Remove rule
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!ro && (
        <div className={styles.toolbarActions}>
          <Button
            size="sm"
            onClick={() => {
              setDraft({
                ...draft,
                rules: [
                  ...draft.rules,
                  { kind: "domain", pattern: "", action: "use_pool" },
                ],
              });
            }}
          >
            Add rule
          </Button>
          <Button
            size="sm"
            variant="primary"
            disabled={!dirty || p.saving}
            onClick={() => {
              p.onSave(draft);
            }}
          >
            Save draft
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={!dirty || p.saving}
            onClick={() => {
              setDraft(p.serverDraft);
            }}
          >
            Discard local edits
          </Button>
        </div>
      )}
      {dirty && (
        <Callout variant="info">
          Unsaved local edits — nothing has been sent to the appliance. Save the
          draft before publishing; publish always sends the SAVED draft you
          reviewed.
        </Callout>
      )}
    </div>
  );
}
