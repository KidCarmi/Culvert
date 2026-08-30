// 2E-C Test: the admin file-test harness. IMPERATIVE (§10): the file runs
// through Sluice in REPORT_ONLY mode — original bytes are never replaced —
// under the admin's own identity, and the run is audited. Success means only
// that THIS file was processed by A pooled instance right now; it is not a
// claim that production traffic is being sanitized. Never auto-retried; a
// timeout renders truthfully as "no result within the deadline" (the engine
// may still have finished the scan — nothing is inferred).
import { useRef, useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  KeyValue,
  Mono,
} from "../../design-system/primitives";
import { useObjectPage } from "../objects/useObjectPage";
import { unknownOutcome, serverErrorText } from "../../shared/mutationOutcome";
import { getCDRConfig, testCDRFile, type CDRTestResult } from "../../api/cdr";
import styles from "../policy/policy.module.css";

type RunState =
  | { kind: "idle" }
  | { kind: "running"; filename: string }
  | { kind: "result"; filename: string; result: CDRTestResult }
  | { kind: "failed"; filename: string; error: string }
  | { kind: "unknown"; filename: string };

export function CDRTestTab({ isAdmin }: { isAdmin: boolean }): JSX.Element {
  // The config is only needed for the size cap + enablement context.
  const page = useObjectPage(["security", "cdr", "test-config"], getCDRConfig);
  const cfg = page.q.data;
  const [run, setRun] = useState<RunState>({ kind: "idle" });
  const [file, setFile] = useState<File | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);

  if (!isAdmin) {
    return (
      <Callout variant="info" title="Admin only">
        Running a file through the CDR engine exercises live credentials and the
        engine path, so the test harness is available to administrators only.
      </Callout>
    );
  }

  const maxMB =
    cfg !== undefined && cfg.maxFileSizeMB > 0 ? cfg.maxFileSizeMB : 50;
  const tooLarge = file !== null && file.size > maxMB * 1024 * 1024;

  const start = (): void => {
    if (file === null || tooLarge || run.kind === "running") return;
    const signal = page.owner.begin();
    const filename = file.name;
    setRun({ kind: "running", filename });
    testCDRFile(file, signal)
      .then((result) => {
        setRun({ kind: "result", filename, result });
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          setRun({ kind: "unknown", filename });
          return;
        }
        setRun({
          kind: "failed",
          filename,
          error: serverErrorText(err, "The test failed."),
        });
      })
      .finally(() => {
        page.owner.settle(signal);
      });
  };

  return (
    <div>
      <Card title="Run a file through the engine (report-only)">
        <p className={styles.refDetail}>
          The file is uploaded to this appliance and streamed to a pooled Sluice
          instance with mode REPORT_ONLY: the engine reports what it would flag,
          and the original bytes are never replaced. The run is attributed to
          your admin identity in the audit trail. Bounded at {String(maxMB)} MB
          and about 60 seconds.
        </p>
        <input
          ref={fileInput}
          type="file"
          aria-label="Test file"
          onChange={(e) => {
            const f = e.target.files?.[0] ?? null;
            setFile(f);
          }}
        />
        {tooLarge && file !== null && (
          <Callout variant="critical" title="File too large">
            {file.name} exceeds the configured {String(maxMB)} MB cap and would
            be refused by the appliance.
          </Callout>
        )}
        <div className={styles.toolbar}>
          <Button
            variant="primary"
            disabled={file === null || tooLarge || run.kind === "running"}
            onClick={start}
          >
            {run.kind === "running" ? "Running…" : "Run test"}
          </Button>
        </div>
      </Card>

      {run.kind === "failed" && (
        <Callout variant="critical" title={`Test of ${run.filename} failed`}>
          {run.error} The test is never retried automatically.
        </Callout>
      )}
      {run.kind === "unknown" && (
        <Callout variant="warning" title={`No result for ${run.filename}`}>
          The appliance did not answer within the deadline. The engine may or
          may not have finished processing the file — no result is inferred, and
          the test is never retried automatically. You may run it again
          explicitly (report-only tests do not change any configuration).
        </Callout>
      )}
      {run.kind === "result" && (
        <Card title={`Result for ${run.filename}`}>
          <KeyValue
            items={[
              ["Engine status", run.result.status],
              [
                "Original",
                `${run.result.originalType === "" ? "unknown type" : run.result.originalType}, ${String(run.result.originalSize)} bytes`,
              ],
              ["Sanitized size", String(run.result.sanitizedSize)],
              ["Engine duration", `${String(run.result.durationMs)} ms`],
              [
                "Sanitized SHA-256",
                run.result.sanitizedSha256 === ""
                  ? "—"
                  : run.result.sanitizedSha256,
              ],
            ]}
          />
          {run.result.errorMessage !== "" && (
            <Callout variant="critical" title="Engine error">
              <Mono>{run.result.errorMessage}</Mono>
            </Callout>
          )}
          {run.result.threats.length === 0 ? (
            <p className={styles.refDetail}>
              The engine flagged no threats in this file. That is a statement
              about THIS file and the profile used — not about production
              traffic or other content.
            </p>
          ) : (
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <caption className="sr-only">
                  Threats the engine flagged
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Type</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Location</th>
                    <th scope="col">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {run.result.threats.map((t, i) => (
                    <tr key={`${t.type}-${String(i)}`}>
                      <td>
                        <Mono>{t.type}</Mono>
                      </td>
                      <td>{t.severity}</td>
                      <td>
                        <Mono>{t.location}</Mono>
                      </td>
                      <td>{t.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className={styles.refDetail}>
            In REPORT_ONLY mode nothing was removed — the report shows what
            ENFORCE mode would have acted on.
          </p>
        </Card>
      )}
    </div>
  );
}
