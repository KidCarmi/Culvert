// 2D-A — shared T1 delete ceremony for object-management surfaces.
//
// Delete integrity (§3/§13/§18): the dialog pre-fetches Where Used for
// operator clarity, but it NEVER concludes "safe to delete" from a zero
// preflight — the server's reference walk (running rules AND an active draft
// candidate) is the single authority, and a concurrent reference still fails
// safely as the structured 409, which this dialog renders with the REAL
// consumers and stable-ID deep links. No optimistic removal; an unknown
// outcome latches the page until a fresh snapshot resolves it.
import { useState, type JSX, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button, Callout, Mono, Spinner } from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { getObjectReferences } from "../../api/policy";
import type { ObjectRefConsumer, ObjectRefType } from "../../api/policy";
import { asReferenceBlock } from "../../api/objects";
import { asPolicyConflict } from "../../api/policyWrite";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { consumerDestination } from "../policy/WhereUsed";
import type { ObjectPageState } from "./useObjectPage";
import styles from "../policy/policy.module.css";

export function ObjectDeleteDialog<T>({
  objType,
  objName,
  objId,
  body,
  doDelete,
  page,
  onDone,
  onCancel,
  onConflictNotice,
}: {
  objType: ObjectRefType;
  objName: string;
  objId: string;
  body: ReactNode;
  doDelete: (signal: AbortSignal) => Promise<void>;
  page: ObjectPageState<T>;
  onDone: () => void;
  onCancel: () => void;
  /** version-fence conflict: the dialog closes and the page shows the notice */
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const [pending, setPending] = useState(false);
  const [refBlock, setRefBlock] = useState<readonly ObjectRefConsumer[] | null>(
    null,
  );
  const [serverError, setServerError] = useState("");

  // Operator-clarity preflight (explicit interest = opening this dialog). The
  // result is INFORMATION — never a permission decision.
  const refsQ = useQuery({
    queryKey: ["objects", "references", objType, objName],
    staleTime: 0,
    retry: false,
    queryFn: ({ signal }) => getObjectReferences(objType, objName, signal),
  });

  const confirm = (): void => {
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    doDelete(signal)
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("delete");
          onCancel();
          return;
        }
        const block = asReferenceBlock(err);
        if (block !== null) {
          // The server's refusal is authoritative — render the real consumers.
          setRefBlock(block.referencedBy);
          return;
        }
        const conflict = asPolicyConflict(err);
        if (conflict !== null) {
          onConflictNotice(
            "The objects changed since you loaded them. The delete was not applied — review the refreshed objects and retry.",
          );
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance refused the delete."),
        );
      })
      .finally(() => {
        page.owner.settle(signal);
        setPending(false);
      });
  };

  const preRefs = refsQ.data?.referencedBy ?? [];

  return (
    <Dialog
      open
      onClose={() => {
        if (!pending) onCancel();
      }}
      title={`Delete: ${objName}`}
      closeOnEscape={!pending}
    >
      <DialogBody>
        <p>{body}</p>
        <p className={styles.refDetail}>
          Object ID <Mono>{objId}</Mono>
        </p>

        {refBlock !== null ? (
          <Callout variant="critical" title="Delete refused — still referenced">
            The appliance refused the delete because these consumers reference
            the object right now (this is the authoritative server check — it
            also covers references staged in an active Policy Draft):
            <ConsumerTable refs={refBlock} />
          </Callout>
        ) : (
          <>
            {refsQ.isPending && (
              <Spinner label="Checking current references…" />
            )}
            {refsQ.isError && (
              <Callout variant="warning" title="Reference preview unavailable">
                The Where Used preview could not be loaded. The delete is still
                safe to attempt — the appliance itself refuses while the object
                is referenced.
              </Callout>
            )}
            {refsQ.isSuccess && preRefs.length > 0 && (
              <Callout variant="warning" title="Currently referenced">
                {String(preRefs.length)}{" "}
                {preRefs.length === 1
                  ? "consumer references"
                  : "consumers reference"}{" "}
                this object — the appliance will refuse the delete while any
                remain:
                <ConsumerTable refs={preRefs} />
              </Callout>
            )}
            {refsQ.isSuccess && preRefs.length === 0 && (
              <p className={styles.refDetail}>
                No references were found at this moment. The appliance re-checks
                at delete time — a reference created meanwhile still refuses the
                delete.
              </p>
            )}
          </>
        )}

        {serverError !== "" && (
          <Callout variant="critical" title="Delete failed" role="alert">
            {serverError}
          </Callout>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" disabled={pending} onClick={onCancel}>
          {refBlock !== null ? "Close" : "Cancel"}
        </Button>
        {refBlock === null && (
          <Button variant="danger" disabled={pending} onClick={confirm}>
            Delete
          </Button>
        )}
      </DialogFooter>
    </Dialog>
  );
}

function ConsumerTable({
  refs,
}: {
  refs: readonly ObjectRefConsumer[];
}): JSX.Element {
  return (
    <table className={styles.table}>
      <caption className="sr-only">Referencing consumers</caption>
      <thead>
        <tr>
          <th scope="col">Consumer</th>
          <th scope="col">Type</th>
          <th scope="col">Via</th>
        </tr>
      </thead>
      <tbody>
        {refs.map((c, i) => (
          <tr key={`${c.consumerType}:${c.id !== "" ? c.id : String(i)}`}>
            <td>{consumerDestination(c)}</td>
            <td>{c.consumerType}</td>
            <td className={styles.refDetail}>{c.detail}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
