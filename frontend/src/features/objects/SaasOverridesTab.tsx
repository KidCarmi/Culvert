// 2D-B §§32–36 — admin SaaS category overrides: Added / Recategorized /
// Tombstones, layered over the signed effective view.
//
//   - Every override key owns its host AND the entire subdomain subtree —
//     explained BEFORE Save (§32); rows are never presented as exact-host.
//   - PUT is FULL-SET replacement fenced by the server-owned override
//     revision (§34) — a stale token is the structured 409, never a silent
//     overwrite. An empty set is clear-all: T2 with current counts (§36).
//   - Server owns normalization/validation (§33); this editor mirrors only
//     trivial line parsing and renders the server's refusal verbatim.
//   - Category input is free text with suggestions from known local
//     categories — no fabricated authoritative dropdown.
import { useEffect, useMemo, useRef, useState, type JSX } from "react";
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
import { TextareaField } from "../../design-system/forms";
import { SnapshotBar, useSnapshot } from "../../shared/snapshot";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import { createRequestRunOwner } from "../../shared/runOwner";
import { registerAuthCleanup } from "../../auth/teardown";
import { useDirtyGuard } from "../../shared/dirtyGuard";
import {
  asRevisionConflict,
  getSaasFeedOverrides,
  putSaasFeedOverrides,
} from "../../api/urlcat";
import styles from "../policy/policy.module.css";

// "host = category" per line for the two mapped kinds.
function mapToLines(m: Readonly<Record<string, string>>): string {
  return Object.entries(m)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([h, c]) => `${h} = ${c}`)
    .join("\n");
}

function linesToMap(text: string): {
  map: Record<string, string>;
  bad: readonly string[];
} {
  const map: Record<string, string> = {};
  const bad: string[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    const idx = line.indexOf("=");
    if (idx <= 0 || idx === line.length - 1) {
      bad.push(line);
      continue;
    }
    const host = line.slice(0, idx).trim();
    const cat = line.slice(idx + 1).trim();
    if (host === "" || cat === "") {
      bad.push(line);
      continue;
    }
    map[host] = cat;
  }
  return { map, bad };
}

function linesToHosts(text: string): readonly string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

export function SaasOverridesTab({
  isAdmin,
}: {
  isAdmin: boolean;
}): JSX.Element {
  const q = useSnapshot(["objects", "saas-overrides"], getSaasFeedOverrides);
  const d = q.data;

  const [addedText, setAddedText] = useState("");
  const [recatText, setRecatText] = useState("");
  const [tombText, setTombText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [confirming, setConfirming] = useState<"replace" | "clear" | null>(
    null,
  );
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<JSX.Element | null>(null);
  const ownerRef = useRef(createRequestRunOwner());
  const seededRevision = useRef<string | null>(null);

  // Seed the editor from the snapshot exactly once per loaded revision;
  // never clobber operator edits on background refetches.
  useEffect(() => {
    if (d === undefined) return;
    if (seededRevision.current === d.revision && dirty) return;
    if (seededRevision.current !== d.revision && !dirty) {
      seededRevision.current = d.revision;
      setAddedText(mapToLines(d.added));
      setRecatText(mapToLines(d.recategorized));
      setTombText(d.tombstones.join("\n"));
    }
  }, [d, dirty]);

  useEffect(() => {
    const owner = ownerRef.current;
    const cleanup = (): void => {
      owner.abort();
      setAddedText("");
      setRecatText("");
      setTombText("");
      setDirty(false);
      setConfirming(null);
      setPending(false);
      setNotice(null);
      seededRevision.current = null;
    };
    const unregister = registerAuthCleanup(cleanup);
    return () => {
      unregister();
      owner.abort();
    };
  }, []);

  const guard = useDirtyGuard(dirty, "the unsaved category-override changes");

  const parsedAdded = useMemo(() => linesToMap(addedText), [addedText]);
  const parsedRecat = useMemo(() => linesToMap(recatText), [recatText]);
  const tombstones = useMemo(() => linesToHosts(tombText), [tombText]);
  const parseErrors = [...parsedAdded.bad, ...parsedRecat.bad];
  const targetEmpty =
    Object.keys(parsedAdded.map).length === 0 &&
    Object.keys(parsedRecat.map).length === 0 &&
    tombstones.length === 0;

  const doSave = (): void => {
    if (d === undefined) return;
    const signal = ownerRef.current.begin();
    setPending(true);
    setNotice(null);
    putSaasFeedOverrides(
      {
        added: parsedAdded.map,
        recategorized: parsedRecat.map,
        tombstones,
      },
      d.revision,
      signal,
    )
      .then((res) => {
        setConfirming(null);
        setDirty(false);
        seededRevision.current = null;
        if (res.clusterPublishRejected !== null) {
          setNotice(
            <Callout
              variant="warning"
              title="Saved locally — fleet publish rejected"
              role="alert"
            >
              The override set is saved on this control plane, but the new fleet
              snapshot was rejected. Data-plane nodes remain on the last valid
              published configuration.
            </Callout>,
          );
        } else {
          setNotice(
            <Callout variant="success" title="Overrides replaced" role="status">
              The full override set is durable and applied to the effective
              view.
            </Callout>,
          );
        }
        void q.refetch();
      })
      .catch((err: unknown) => {
        setConfirming(null);
        if (unknownOutcome(err)) {
          setNotice(
            <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
              The connection was lost before the appliance answered — refresh
              the override revision and effective status before any retry.
            </Callout>,
          );
          void q.refetch();
          return;
        }
        const conflict = asRevisionConflict(err);
        if (conflict !== null) {
          setNotice(
            <Callout
              variant="warning"
              title="Not applied — overrides changed"
              role="alert"
            >
              Another administrator replaced the override set since this page
              loaded. Nothing was written — refresh and re-apply your change on
              the current set.
            </Callout>,
          );
          void q.refetch();
          return;
        }
        setNotice(
          <Callout variant="critical" title="Not saved" role="alert">
            {serverErrorText(err, "The appliance refused the override set.")}
          </Callout>,
        );
      })
      .finally(() => {
        setPending(false);
      });
  };

  if (q.isPending) return <Skeleton>Loading overrides…</Skeleton>;
  if (q.isError) return <ErrorState title="Could not load overrides" />;
  if (d === undefined) return <></>;

  const counts = {
    added: Object.keys(d.added).length,
    recategorized: Object.keys(d.recategorized).length,
    tombstones: d.tombstones.length,
  };
  const canEdit = isAdmin && d.editable;

  return (
    <section aria-label="Category overrides">
      {guard.element}
      <div className={styles.calloutSpace}>
        <SnapshotBar
          updatedAt={q.dataUpdatedAt}
          fetching={q.isFetching}
          error={q.isError}
          hasData
          onRefresh={() => {
            void q.refetch();
          }}
        />
      </div>
      {!d.editable && (
        <Callout variant="warning" title="Control-plane managed">
          Category overrides are owned by the control plane on this data-plane
          node — read-only here.
        </Callout>
      )}
      <Callout variant="info" title="Subtree scope">
        Every override key owns its host AND the entire subdomain subtree.
        Recategorizing <Mono>example.com</Mono> affects example.com and all its
        subdomains; a tombstone for <Mono>example.com</Mono> suppresses that
        whole feed subtree.
      </Callout>
      <Card title={`Added (${String(counts.added)})`}>
        <TextareaField
          label="host = category — one per line; inserts a host the feed does not carry"
          value={addedText}
          rows={6}
          disabled={!canEdit || pending}
          onChange={(e) => {
            setAddedText(e.target.value);
            setDirty(true);
          }}
        />
      </Card>
      <Card title={`Recategorized (${String(counts.recategorized)})`}>
        <TextareaField
          label="host = category — one per line; repoints a feed-carried subtree"
          value={recatText}
          rows={6}
          disabled={!canEdit || pending}
          onChange={(e) => {
            setRecatText(e.target.value);
            setDirty(true);
          }}
        />
      </Card>
      <Card title={`Tombstones (${String(counts.tombstones)})`}>
        <TextareaField
          label="host — one per line; suppresses that feed subtree entirely"
          value={tombText}
          rows={6}
          disabled={!canEdit || pending}
          onChange={(e) => {
            setTombText(e.target.value);
            setDirty(true);
          }}
        />
      </Card>
      {parseErrors.length > 0 && (
        <Callout variant="warning" title="Unparseable lines">
          {parseErrors.length} line(s) are not in <Mono>host = category</Mono>{" "}
          form and will be ignored: <Mono>{parseErrors.join(", ")}</Mono>
        </Callout>
      )}
      {canEdit && (
        <div className={styles.calloutSpace}>
          <Button
            disabled={pending || !dirty}
            onClick={() => {
              setConfirming(targetEmpty ? "clear" : "replace");
            }}
          >
            {targetEmpty ? "Clear all overrides" : "Replace override set"}
          </Button>
        </div>
      )}
      {notice}
      <Dialog
        open={confirming !== null}
        onClose={() => {
          setConfirming(null);
        }}
        title={
          confirming === "clear"
            ? "Clear ALL overrides"
            : "Replace override set"
        }
      >
        <DialogBody>
          {confirming === "clear" ? (
            <>
              <p>
                Saving an EMPTY set clears every override — classification for
                entire host subtrees can change back to the feed&apos;s view.
              </p>
              <KeyValue
                items={[
                  ["Added", String(counts.added)],
                  ["Recategorized", String(counts.recategorized)],
                  ["Tombstones", String(counts.tombstones)],
                  [
                    "Total to remove",
                    String(
                      counts.added + counts.recategorized + counts.tombstones,
                    ),
                  ],
                ]}
              />
            </>
          ) : (
            <p>
              This replaces the FULL override set on the appliance (
              {String(Object.keys(parsedAdded.map).length)} added,{" "}
              {String(Object.keys(parsedRecat.map).length)} recategorized,{" "}
              {String(tombstones.length)} tombstones). Every key governs its
              whole subdomain subtree. The server validates and may refuse the
              set as a whole.
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button
            variant="ghost"
            onClick={() => {
              setConfirming(null);
            }}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button
            variant={confirming === "clear" ? "danger" : "primary"}
            onClick={doSave}
            disabled={pending}
          >
            {confirming === "clear" ? "Clear all" : "Replace set"}
          </Button>
        </DialogFooter>
      </Dialog>
    </section>
  );
}
