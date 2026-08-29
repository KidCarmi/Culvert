// 2E-A YARA: rule inventory + per-file source view, fenced create/edit
// (validate is a separate REAL dry-run call and never implies save/load),
// the delete ceremony, the reload ceremony (admin, also clears the verdict
// cache), and the engine settings (persist-before-apply on the appliance;
// disabling the engine or relaxing a fail-closed posture is a ceremony).
import { useEffect, useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
} from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import {
  Checkbox,
  InputField,
  SelectField,
  TextareaField,
} from "../../design-system/forms";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage } from "../objects/useObjectPage";
import { asRevisionConflict } from "../../api/urlcat";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import {
  createYaraRule,
  deleteYaraRule,
  getYaraInventory,
  getYaraRule,
  getYaraSettings,
  putYaraSettings,
  reloadYaraRules,
  updateYaraRule,
  validateYaraSource,
} from "../../api/contentsec";
import type { YaraRule, YaraValidateResult } from "../../api/contentsec";
import { PostureBadge } from "./OverviewTab";
import styles from "../policy/policy.module.css";

type Editor = { kind: "create" } | { kind: "edit"; rule: YaraRule };

export function YaraTab({
  isOperator,
  isAdmin,
}: {
  isOperator: boolean;
  isAdmin: boolean;
}): JSX.Element {
  const page = useObjectPage(["security", "content", "yara"], getYaraInventory);
  const settings = useObjectPage(
    ["security", "content", "yara-settings"],
    getYaraSettings,
  );
  const inv = page.q.data;
  const [editor, setEditor] = useState<Editor | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [reloading, setReloading] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [notice, setNotice] = useState("");
  const blocked = page.unknown !== null;

  page.setBoundaryCleanup(() => {
    setEditor(null);
    setDeleting(null);
    setReloading(false);
    setSettingsOpen(false);
    setNotice("");
  });

  const refreshAll = (): void => {
    page.refreshToResolve();
    settings.refreshToResolve();
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching || settings.q.isFetching}
          error={page.q.isError || settings.q.isError}
          hasData={inv !== undefined}
          onRefresh={refreshAll}
        />
      </div>

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived —
            the YARA {page.unknown} may or may not have been applied. Refresh
            and review the rules before further changes.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={refreshAll}>
                Refresh rules
              </Button>
            </div>
          </Callout>
        </div>
      )}
      {notice !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Not applied" role="alert">
            {notice}
          </Callout>
        </div>
      )}

      {inv === undefined && page.q.isPending && (
        <Skeleton>Loading YARA rules…</Skeleton>
      )}
      {inv === undefined && page.q.isError && (
        <ErrorState title="YARA rules unavailable">
          The YARA inventory could not be loaded. Refresh to try again.
        </ErrorState>
      )}

      {inv !== undefined && (
        <Card title="Rule files">
          <KeyValue
            items={[
              ["Directory", <Mono key="d">{inv.directory}</Mono>],
              ["Compiled rules", String(inv.count)],
              [
                "Parser warnings",
                inv.warnings.length === 0
                  ? "none"
                  : String(inv.warnings.length),
              ],
            ]}
          />
          {inv.warnings.length > 0 && (
            <Callout variant="warning" title="Parser warnings">
              <Mono>{inv.warnings.join(" · ")}</Mono>
            </Callout>
          )}
          {isAdmin && (
            <div className={styles.toolbarActions}>
              <Button
                size="sm"
                disabled={blocked}
                onClick={() => {
                  setEditor({ kind: "create" });
                }}
              >
                New rule file…
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={blocked}
                onClick={() => {
                  setReloading(true);
                }}
              >
                Reload from directory…
              </Button>
            </div>
          )}
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <caption className="sr-only">YARA rule files</caption>
              <thead>
                <tr>
                  <th scope="col">File</th>
                  <th scope="col">Rules inside</th>
                  {isAdmin && <th scope="col">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {inv.files.length === 0 && (
                  <tr>
                    <td colSpan={isAdmin ? 3 : 2}>
                      No rule files in the configured directory.
                    </td>
                  </tr>
                )}
                {inv.files.map((f) => (
                  <tr key={f}>
                    <td>
                      <Mono>{f}</Mono>
                    </td>
                    <td>
                      {(inv.fileRules[f] ?? []).length === 0 ? (
                        "—"
                      ) : (
                        <Mono>{(inv.fileRules[f] ?? []).join(", ")}</Mono>
                      )}
                    </td>
                    {isAdmin && (
                      <td>
                        <span className={styles.rowActions}>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={blocked}
                            aria-label={`Edit rule file ${f}`}
                            onClick={() => {
                              const signal = page.owner.begin();
                              getYaraRule(f, signal)
                                .then((rule) => {
                                  setEditor({ kind: "edit", rule });
                                })
                                .catch(() => {
                                  setNotice(
                                    `Rule file ${f} could not be read — refresh the inventory.`,
                                  );
                                })
                                .finally(() => {
                                  page.owner.settle(signal);
                                });
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={blocked}
                            aria-label={`Delete rule file ${f}`}
                            onClick={() => {
                              setDeleting(f);
                            }}
                          >
                            Delete
                          </Button>
                        </span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <YaraSettingsCard
        page={settings}
        isAdmin={isAdmin}
        open={settingsOpen}
        setOpen={setSettingsOpen}
      />

      {editor !== null && isAdmin && (
        <RuleEditorDialog
          mode={editor}
          isOperator={isOperator}
          page={page}
          onDone={() => {
            setEditor(null);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setEditor(null);
          }}
          onConflict={(text) => {
            setEditor(null);
            setNotice(text);
            page.refreshToResolve();
          }}
        />
      )}

      {deleting !== null && isAdmin && (
        <DeleteRuleDialog
          name={deleting}
          page={page}
          onDone={() => {
            setDeleting(null);
            page.refreshToResolve();
          }}
          onConflict={(text) => {
            setDeleting(null);
            setNotice(text);
            page.refreshToResolve();
          }}
          onCancel={() => {
            setDeleting(null);
          }}
        />
      )}

      {reloading && isAdmin && (
        <ReloadDialog
          page={page}
          onDone={() => {
            setReloading(false);
            refreshAll();
          }}
          onCancel={() => {
            setReloading(false);
          }}
        />
      )}
    </div>
  );
}

// ── Rule editor (create / edit) with the REAL dry-run validate ──────────────

function RuleEditorDialog({
  mode,
  isOperator,
  page,
  onDone,
  onCancel,
  onConflict,
}: {
  mode: Editor;
  isOperator: boolean;
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getYaraInventory>>>
  >;
  onDone: () => void;
  onCancel: () => void;
  onConflict: (text: string) => void;
}): JSX.Element {
  const [name, setName] = useState(mode.kind === "edit" ? mode.rule.name : "");
  const [source, setSource] = useState(
    mode.kind === "edit" ? mode.rule.source : "",
  );
  const [pending, setPending] = useState(false);
  const [serverError, setServerError] = useState("");
  const [validation, setValidation] = useState<YaraValidateResult | null>(null);
  const [validating, setValidating] = useState(false);

  useEffect(() => {
    setValidation(null);
  }, [source]);

  const runValidate = (): void => {
    const signal = page.owner.begin();
    setValidating(true);
    validateYaraSource(source, signal)
      .then(setValidation)
      .catch((err: unknown) => {
        setServerError(serverErrorText(err, "The validation request failed."));
      })
      .finally(() => {
        page.owner.settle(signal);
        setValidating(false);
      });
  };

  const submit = (): void => {
    if (name.trim() === "") {
      setServerError("A rule file name is required.");
      return;
    }
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    const call =
      mode.kind === "create"
        ? createYaraRule(name.trim(), source, signal)
        : updateYaraRule(mode.rule.name, source, mode.rule.revision, signal);
    call
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown(mode.kind === "create" ? "create" : "edit");
          onCancel();
          return;
        }
        if (asRevisionConflict(err) !== null) {
          onConflict(
            mode.kind === "create"
              ? `A rule file named ${name.trim()} already exists — nothing was replaced. Refresh and edit the existing file instead.`
              : "The rule file changed on the appliance since you loaded it. Nothing was applied — review the refreshed source and reapply your edit.",
          );
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance rejected the rule."),
        );
      })
      .finally(() => {
        page.owner.settle(signal);
        setPending(false);
      });
  };

  return (
    <Dialog
      open
      onClose={onCancel}
      title={
        mode.kind === "create"
          ? "New YARA rule file"
          : `Edit YARA rule file: ${mode.rule.name}`
      }
    >
      <DialogBody>
        {mode.kind === "create" && (
          <InputField
            label="File name (stem, no extension)"
            required
            value={name}
            disabled={pending}
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        )}
        <TextareaField
          label="Rule source"
          value={source}
          rows={12}
          disabled={pending}
          onChange={(e) => {
            setSource(e.target.value);
          }}
        />
        {isOperator && (
          <div className={styles.toolbarActions}>
            <Button
              size="sm"
              variant="ghost"
              disabled={validating || source.trim() === ""}
              onClick={runValidate}
            >
              {validating ? "Validating…" : "Validate (dry run)"}
            </Button>
          </div>
        )}
        {validation !== null && (
          <Callout
            variant={validation.valid ? "info" : "critical"}
            title={
              validation.valid
                ? `Valid — defines ${String(validation.ruleNames.length)} rule${validation.ruleNames.length === 1 ? "" : "s"}`
                : "Invalid rule source"
            }
          >
            {validation.valid ? (
              <>
                <Mono>{validation.ruleNames.join(", ")}</Mono>
                {validation.warnings.length > 0 && (
                  <> — warnings: {validation.warnings.join("; ")}</>
                )}
                <p className={styles.refDetail}>
                  Validation is a dry run: nothing was saved, loaded, or
                  activated.
                </p>
              </>
            ) : (
              (validation.error ?? "The appliance rejected the source.")
            )}
          </Callout>
        )}
        {serverError !== "" && (
          <Callout variant="critical" title="Not saved" role="alert">
            {serverError}
          </Callout>
        )}
        <p className={styles.refDetail}>
          Saving validates, writes the file to the rules directory, reloads the
          whole rule set, and clears the scan verdict cache so old-clean content
          is re-scanned.
        </p>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" disabled={pending} onClick={onCancel}>
          Cancel
        </Button>
        <Button disabled={pending} onClick={submit}>
          {mode.kind === "create" ? "Create rule file" : "Save changes"}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}

// ── Delete ceremony ─────────────────────────────────────────────────────────

function DeleteRuleDialog({
  name,
  page,
  onDone,
  onConflict,
  onCancel,
}: {
  name: string;
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getYaraInventory>>>
  >;
  onDone: () => void;
  /** Refused stale delete / vanished target: the rule is preserved (or was
   * already gone) — the parent shows the notice and refreshes to fresh truth. */
  onConflict: (text: string) => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  // 2E-A-2 §3: the ceremony is bound to the AUTHORITATIVE current revision of
  // the rule file, fetched when the dialog opens (never a list-position or
  // remembered identity) and asserted with the DELETE — a delete reviewed
  // against one version can never destroy another admin's newer version (the
  // appliance refuses it with the structured 409 and nothing is deleted).
  const [reviewed, setReviewed] = useState<YaraRule | null>(null);
  useEffect(() => {
    const ctrl = new AbortController();
    getYaraRule(name, ctrl.signal)
      .then((r) => {
        setReviewed(r);
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        onConflict(
          serverErrorText(
            err,
            `The rule file ${name} could not be loaded for review — it may already have been deleted. Review the refreshed inventory.`,
          ),
        );
      });
    return () => {
      ctrl.abort();
    };
    // The dialog is mounted per delete attempt; name is stable for its life.
  }, [name]);
  return (
    <ConfirmationDialog
      open
      tier={2}
      title={`Delete YARA rule file ${name}`}
      body={
        <>
          This removes the rule file <Mono>{name}</Mono> from the rules
          directory and reloads the rule set — every rule inside it stops
          matching immediately. The scan verdict cache is cleared.{" "}
          {reviewed === null ? (
            "Loading the current rule version…"
          ) : (
            <>
              The delete is bound to the current version just loaded (
              <Mono>{reviewed.revision.slice(0, 19)}…</Mono>); if the file
              changes first, the appliance refuses.
            </>
          )}
        </>
      }
      impact="Content previously blocked by these rules will no longer be blocked by YARA."
      rollback="Re-create the rule file with the same source."
      // The confirm control is inert (guarded no-op) until the reviewed
      // revision is loaded; the label says so.
      confirmLabel={
        reviewed === null ? "Loading current version…" : "Delete rule file"
      }
      destructive
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        if (reviewed === null) return; // review not loaded — nothing to assert
        const signal = page.owner.begin();
        setResult("pending");
        deleteYaraRule(name, reviewed.revision, signal)
          .then(onDone)
          .catch((err: unknown) => {
            if (unknownOutcome(err)) {
              page.latchUnknown("delete");
              setResult("unknown");
              onCancel();
              return;
            }
            if (asRevisionConflict(err) !== null) {
              onConflict(
                `The rule file ${name} changed on the appliance after you reviewed it. Nothing was deleted — review the refreshed inventory and retry.`,
              );
              return;
            }
            setResult("failed");
            setErrorText(serverErrorText(err, "The delete failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={onCancel}
    />
  );
}

// ── Reload ceremony (imperative) ────────────────────────────────────────────

function ReloadDialog({
  page,
  onDone,
  onCancel,
}: {
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getYaraInventory>>>
  >;
  onDone: () => void;
  onCancel: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  return (
    <ConfirmationDialog
      open
      tier={2}
      title="Reload YARA rules from the directory"
      body={
        <>
          The appliance re-reads every rule file from the configured rules
          directory and replaces the compiled rule set.
        </>
      }
      impact="The scan verdict cache is cleared: previously-clean content is re-scanned under the reloaded rules."
      rollback="Restore the previous rule files, then reload again."
      confirmLabel="Reload rules"
      result={result}
      {...(errorText !== "" ? { errorText } : {})}
      onConfirm={() => {
        const signal = page.owner.begin();
        setResult("pending");
        reloadYaraRules(signal)
          .then(onDone)
          .catch((err: unknown) => {
            setResult("failed");
            setErrorText(serverErrorText(err, "The reload failed."));
          })
          .finally(() => {
            page.owner.settle(signal);
          });
      }}
      onCancel={onCancel}
    />
  );
}

// ── Engine settings (persist-before-apply; ceremony on posture relaxation) ──

function YaraSettingsCard({
  page,
  isAdmin,
  open,
  setOpen,
}: {
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getYaraSettings>>>
  >;
  isAdmin: boolean;
  open: boolean;
  setOpen: (v: boolean) => void;
}): JSX.Element {
  const s = page.q.data;
  return (
    <Card title="Engine settings">
      {s === undefined ? (
        page.q.isError ? (
          <p className={styles.refDetail}>
            The engine settings could not be loaded.
          </p>
        ) : (
          <Skeleton>Loading engine settings…</Skeleton>
        )
      ) : (
        <>
          <KeyValue
            items={[
              ["Engine", s.enabled ? "enabled" : "disabled"],
              ["Per-scan timeout", `${String(s.timeoutSecs)}s`],
              ["Max in-flight scans", String(s.maxInflight)],
              ["On timeout", <PostureBadge key="t" value={s.onTimeout} />],
              [
                "On saturation",
                <PostureBadge key="s" value={s.onSaturation} />,
              ],
              ["Alert when degraded", s.alertDegraded ? "yes" : "no"],
            ]}
          />
          {isAdmin && (
            <div className={styles.toolbarActions}>
              <Button
                size="sm"
                onClick={() => {
                  setOpen(true);
                }}
              >
                Edit settings…
              </Button>
            </div>
          )}
          {open && isAdmin && (
            <SettingsEditorDialog
              current={s}
              page={page}
              onDone={() => {
                setOpen(false);
                page.refreshToResolve();
              }}
              onCancel={() => {
                setOpen(false);
              }}
            />
          )}
        </>
      )}
    </Card>
  );
}

function SettingsEditorDialog({
  current,
  page,
  onDone,
  onCancel,
}: {
  current: Awaited<ReturnType<typeof getYaraSettings>>;
  page: ReturnType<
    typeof useObjectPage<Awaited<ReturnType<typeof getYaraSettings>>>
  >;
  onDone: () => void;
  onCancel: () => void;
}): JSX.Element {
  const [enabled, setEnabled] = useState(current.enabled);
  const [timeoutSecs, setTimeoutSecs] = useState(String(current.timeoutSecs));
  const [maxInflight, setMaxInflight] = useState(String(current.maxInflight));
  const [onTimeout, setOnTimeout] = useState(current.onTimeout);
  const [onSaturation, setOnSaturation] = useState(current.onSaturation);
  const [alertDegraded, setAlertDegraded] = useState(current.alertDegraded);
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [serverError, setServerError] = useState("");
  const [notice, setNotice] = useState("");

  const relaxing =
    (current.enabled && !enabled) ||
    (current.onTimeout === "fail_closed" && onTimeout !== "fail_closed") ||
    (current.onSaturation === "fail_closed" && onSaturation !== "fail_closed");

  const commit = (): void => {
    const signal = page.owner.begin();
    setResult("pending");
    setServerError("");
    putYaraSettings(
      {
        enabled,
        timeoutSecs: Number(timeoutSecs),
        maxInflight: Number(maxInflight),
        onTimeout,
        onSaturation,
        alertDegraded,
      },
      current.revision,
      signal,
    )
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("edit");
          onCancel();
          return;
        }
        if (asRevisionConflict(err) !== null) {
          setNotice(
            "The engine settings changed on the appliance since you loaded them. Nothing was applied — review the refreshed values and reapply.",
          );
          setConfirming(false);
          setResult("idle");
          page.refreshToResolve();
          return;
        }
        setResult("failed");
        setServerError(
          serverErrorText(
            err,
            "The settings could not be persisted; the live engine posture is unchanged.",
          ),
        );
      })
      .finally(() => {
        page.owner.settle(signal);
      });
  };

  const submit = (): void => {
    if (relaxing) {
      setConfirming(true);
      return;
    }
    commit();
  };

  return (
    <Dialog open onClose={onCancel} title="Edit YARA engine settings">
      <DialogBody>
        {notice !== "" && (
          <Callout variant="warning" title="Not applied" role="alert">
            {notice}
          </Callout>
        )}
        <Checkbox
          label="Engine enabled"
          checked={enabled}
          onChange={(e) => {
            setEnabled(e.target.checked);
          }}
        />
        <InputField
          label="Per-scan timeout (seconds, 1–60)"
          value={timeoutSecs}
          onChange={(e) => {
            setTimeoutSecs(e.target.value);
          }}
        />
        <InputField
          label="Max in-flight scans (1–500)"
          value={maxInflight}
          onChange={(e) => {
            setMaxInflight(e.target.value);
          }}
        />
        <SelectField
          label="On timeout"
          value={onTimeout}
          onChange={(e) => {
            setOnTimeout(e.target.value);
          }}
        >
          <option value="fail_closed">fail_closed (block content)</option>
          <option value="fail_open_with_alert">
            fail_open_with_alert (admit + alert)
          </option>
        </SelectField>
        <SelectField
          label="On saturation"
          value={onSaturation}
          onChange={(e) => {
            setOnSaturation(e.target.value);
          }}
        >
          <option value="fail_closed">fail_closed (block content)</option>
          <option value="fail_open_with_alert">
            fail_open_with_alert (admit + alert)
          </option>
        </SelectField>
        <Checkbox
          label="Alert when degraded"
          checked={alertDegraded}
          onChange={(e) => {
            setAlertDegraded(e.target.checked);
          }}
        />
        {serverError !== "" && (
          <Callout variant="critical" title="Not saved" role="alert">
            {serverError}
          </Callout>
        )}
        <p className={styles.refDetail}>
          A saved change is durable AND live (persist-before-apply): if the
          appliance cannot persist it, nothing changes.
        </p>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button onClick={submit}>Save settings</Button>
      </DialogFooter>
      <ConfirmationDialog
        open={confirming}
        tier={2}
        title="Reduce YARA scanning coverage"
        body={
          <>
            {current.enabled && !enabled && (
              <p>
                This DISABLES the YARA engine — no traffic is scanned by YARA
                until it is re-enabled.
              </p>
            )}
            {current.onTimeout === "fail_closed" &&
              onTimeout !== "fail_closed" && (
                <p>
                  On-timeout posture relaxes from fail_closed to{" "}
                  <Mono>{onTimeout}</Mono>: content whose scan times out is
                  ADMITTED instead of blocked.
                </p>
              )}
            {current.onSaturation === "fail_closed" &&
              onSaturation !== "fail_closed" && (
                <p>
                  On-saturation posture relaxes from fail_closed to{" "}
                  <Mono>{onSaturation}</Mono>: content arriving while the engine
                  is saturated is ADMITTED instead of blocked.
                </p>
              )}
          </>
        }
        impact="Scanning coverage is materially reduced for live traffic."
        rollback="Re-save the previous settings."
        confirmLabel="Apply reduced coverage"
        destructive
        result={result}
        {...(serverError !== "" ? { errorText: serverError } : {})}
        onConfirm={commit}
        onCancel={() => {
          setConfirming(false);
          setResult("idle");
        }}
      />
    </Dialog>
  );
}
