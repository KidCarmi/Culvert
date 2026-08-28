// 2D-B §19 — T2 delete ceremony for a URL category. The server's reference
// walk (Access Rules with DestCategory + Category Groups containing the
// name) is the single delete-safety authority: the preflight here is
// operator guidance only, and a race between preflight and delete still
// fails safely as the server's structured 409. No optimistic delete.
import { useState, type JSX } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button, Callout, Mono, Spinner } from "../../design-system/primitives";
import { Dialog, DialogBody, DialogFooter } from "../../design-system/dialog";
import { getObjectReferences } from "../../api/policy";
import type { ObjectRefConsumer } from "../../api/policy";
import { asReferenceBlock } from "../../api/objects";
import { asRevisionConflict, deleteUrlCategory } from "../../api/urlcat";
import type { UrlCategoryRow, UrlCategoryState } from "../../api/urlcat";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { consumerDestination } from "../policy/WhereUsed";
import type { ObjectPageState } from "./useObjectPage";
import styles from "../policy/policy.module.css";

export function UrlCategoryDeleteDialog({
  row,
  revision,
  page,
  onDone,
  onCancel,
  onConflictNotice,
}: {
  row: UrlCategoryRow;
  revision: string;
  page: ObjectPageState<UrlCategoryState>;
  onDone: () => void;
  onCancel: () => void;
  onConflictNotice: (text: string) => void;
}): JSX.Element {
  const [pending, setPending] = useState(false);
  const [refBlock, setRefBlock] = useState<readonly ObjectRefConsumer[] | null>(
    null,
  );
  const [serverError, setServerError] = useState("");

  // Preflight Where Used — information for the operator, never a permission
  // decision (§4).
  const refsQ = useQuery({
    queryKey: ["objects", "references", "category", row.name],
    staleTime: 0,
    retry: false,
    queryFn: ({ signal }) => getObjectReferences("category", row.name, signal),
  });

  const confirm = (): void => {
    const signal = page.owner.begin();
    setPending(true);
    setServerError("");
    deleteUrlCategory(row.name, revision, signal)
      .then(() => {
        onDone();
      })
      .catch((err: unknown) => {
        if (unknownOutcome(err)) {
          page.latchUnknown("delete");
          onConflictNotice(
            "The delete's outcome is unconfirmed — refresh the taxonomy and references before retrying.",
          );
          return;
        }
        const block = asReferenceBlock(err);
        if (block !== null) {
          setRefBlock(block.referencedBy);
          return;
        }
        const conflict = asRevisionConflict(err);
        if (conflict !== null) {
          onConflictNotice(
            "The taxonomy changed since this page was loaded (stale revision). Nothing was deleted — refresh and retry on the current state.",
          );
          return;
        }
        setServerError(
          serverErrorText(err, "The appliance refused the delete."),
        );
      })
      .finally(() => {
        setPending(false);
      });
  };

  return (
    <Dialog open onClose={onCancel} title={`Delete category — ${row.name}`}>
      <DialogBody>
        <p>
          Deleting <Mono>{row.name}</Mono> removes its classification from this
          node&apos;s admin taxonomy. Access Rules or Category Groups that still
          reference the name block the delete (the appliance refuses with the
          real consumers). Feed or baseline sources may still classify some of
          these hosts through another layer — deleting the category does not
          suppress the signed SaaS or UT1 taxonomy.
        </p>
        {refsQ.isPending && <Spinner />}
        {refsQ.data !== undefined && refsQ.data.referencedBy.length > 0 && (
          <Callout variant="warning" title="Currently referenced">
            <ul>
              {refsQ.data.referencedBy.map((c, i) => (
                <li key={i}>{consumerDestination(c)}</li>
              ))}
            </ul>
            The appliance will refuse the delete while these references exist.
          </Callout>
        )}
        {refBlock !== null && (
          <Callout
            variant="critical"
            title="Delete refused — still referenced"
            role="alert"
          >
            <ul>
              {refBlock.map((c, i) => (
                <li key={i}>{consumerDestination(c)}</li>
              ))}
            </ul>
          </Callout>
        )}
        {serverError !== "" && (
          <Callout variant="critical" title="Not deleted" role="alert">
            {serverError}
          </Callout>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button variant="danger" onClick={confirm} disabled={pending}>
          Delete category
        </Button>
      </DialogFooter>
    </Dialog>
  );
}

// keep the module import shape stable for the page (styles referenced above)
void styles;
