// 2D-B §20 — URL category lookup. Manual Run only (never per keystroke),
// nothing persisted anywhere (no storage, no route state). Exact server
// facts rendered; "Uncategorized" is taxonomy truth, not an access verdict.
import { useEffect, useRef, useState, type JSX } from "react";
import {
  Button,
  Callout,
  KeyValue,
  Mono,
  Spinner,
  StatusBadge,
} from "../../design-system/primitives";
import { InputField } from "../../design-system/forms";
import { lookupUrlCategory } from "../../api/urlcat";
import type { UrlCategoryLookup } from "../../api/urlcat";
import { serverErrorText } from "../../shared/mutationOutcome";
import { createRequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import styles from "../policy/policy.module.css";

export function UrlCatLookupTab(): JSX.Element {
  const [host, setHost] = useState("");
  const [result, setResult] = useState<UrlCategoryLookup | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const ownerRef = useRef(createRequestRunOwner());

  // Auth boundary: clear input + result + any in-flight run (§42).
  useEffect(() => {
    const owner = ownerRef.current;
    const cleanup = (): void => {
      owner.abort();
      setHost("");
      setResult(null);
      setError("");
      setPending(false);
    };
    const unregister = registerAuthCleanup(cleanup);
    return () => {
      unregister();
      owner.abort();
    };
  }, []);

  const run = (): void => {
    const target = host.trim();
    if (target === "") return;
    const signal = ownerRef.current.begin();
    setPending(true);
    setError("");
    lookupUrlCategory(target, signal)
      .then((res) => {
        setResult(res);
      })
      .catch((err: unknown) => {
        if (signal.aborted) return;
        setResult(null);
        setError(serverErrorText(err, "Lookup failed."));
      })
      .finally(() => {
        setPending(false);
      });
  };

  return (
    <section aria-label="URL category lookup">
      <div className={styles.calloutSpace}>
        <InputField
          label="Hostname"
          value={host}
          onChange={(e) => {
            setHost(e.target.value);
          }}
          placeholder="example.com"
        />
        <Button onClick={run} disabled={pending || host.trim() === ""}>
          Run lookup
        </Button>
        {pending && <Spinner />}
      </div>
      {error !== "" && (
        <Callout variant="critical" title="Lookup failed" role="alert">
          {error}
        </Callout>
      )}
      {result !== null && (
        <div aria-label="lookup result">
          <KeyValue
            items={[
              ["Host", <Mono key="h">{result.host}</Mono>],
              [
                "Category",
                result.category === "" ? (
                  <span key="c">
                    Uncategorized{" "}
                    <span className={styles.refDetail}>
                      (taxonomy truth — not an access verdict)
                    </span>
                  </span>
                ) : (
                  <Mono key="c">{result.category}</Mono>
                ),
              ],
              [
                "Tier",
                result.tier === "" ? "—" : <Mono key="t">{result.tier}</Mono>,
              ],
              [
                "Matched by",
                result.matchedBy === "" ? (
                  "—"
                ) : (
                  <Mono key="m">{result.matchedBy}</Mono>
                ),
              ],
              [
                "Blocklist",
                result.blocked ? (
                  <StatusBadge key="b" status="critical">
                    Blocked (
                    {result.blockSource === ""
                      ? "blocklist"
                      : result.blockSource}
                    )
                  </StatusBadge>
                ) : (
                  <StatusBadge key="b" status="neutral">
                    Not on the blocklist
                  </StatusBadge>
                ),
              ],
            ]}
          />
        </div>
      )}
    </section>
  );
}
