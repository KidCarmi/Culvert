// 2F-E — PAC profiles: the listing (the cluster-synced active profiles plus
// the virtual, legacy-managed `default`), profile creation (admin; the
// bound DIRECT challenge applies to CREATE as well), and the per-profile
// lifecycle detail. Lifecycle, drafts and history are NODE-LOCAL and say so.
import { useEffect, useState, type JSX } from "react";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  ErrorState,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../../design-system/primitives";
import {
  Checkbox,
  InputField,
  SelectField,
  TextareaField,
} from "../../../design-system/forms";
import {
  ConfirmationDialog,
  type ConfirmResult,
} from "../../../design-system/dialog";
import { SnapshotBar } from "../../../shared/snapshot";
import { useAuth } from "../../../auth/AuthProvider";
import { useObjectPage } from "../../objects/useObjectPage";
import { serverErrorText } from "../../../shared/mutationOutcome";
import {
  PAC_AVAILABILITY_MODES,
  PAC_PRIVATE_NETWORKS,
  createPacProfile,
  getPacProfiles,
} from "../../../api/pac";
import type {
  PacChallenge,
  PacFenceRefusal,
  PacIssuesRefusal,
  PacProfileInput,
} from "../../../api/pac";
import { classifyDispatchFailure } from "./pacLifecycle";
import { readPacRecovery } from "./pacRecovery";
import {
  ChallengeCeremony,
  ChallengeStaleCallout,
  FenceCallout,
  IssuesCallout,
  NODE_LOCAL_NOTE,
} from "./pacShared";
import { ProfileDetail } from "./ProfileDetail";
import { useDiscardGuard } from "./discardGuard";
import styles from "../../policy/policy.module.css";

const EMPTY_FORM: PacProfileInput = {
  id: "",
  name: "",
  description: "",
  enabled: true,
  poolId: "",
  rules: [],
  privateNetworks: "proxy",
  availabilityMode: "secure",
  revision: 1,
};

type CreateState =
  | { kind: "closed" }
  | {
      kind: "editing";
      form: PacProfileInput;
      result: ConfirmResult;
      errorText: string;
    }
  | {
      kind: "challenge";
      form: PacProfileInput;
      challenge: PacChallenge;
      result: ConfirmResult;
      errorText: string;
    };

export function ProfilesTab({
  isAdmin,
  onDirtyChange,
}: {
  isAdmin: boolean;
  /** 2F-E correction (finding 4): the page guards tab switches on it */
  onDirtyChange?: (dirty: boolean) => void;
}): JSX.Element {
  const { state: auth } = useAuth();
  const subject = auth.user ?? "";
  const page = useObjectPage(["network", "pac", "profiles"], getPacProfiles);
  const listing = page.q.data;
  const [selected, setSelected] = useState<string | null>(null);
  const [create, setCreate] = useState<CreateState>({ kind: "closed" });
  const [fence, setFence] = useState<PacFenceRefusal | null>(null);
  const [stale, setStale] = useState<PacChallenge | null>(null);
  const [issues, setIssues] = useState<PacIssuesRefusal | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [markerProfile, setMarkerProfile] = useState<string | null>(null);
  const [storeState, setStoreState] = useState<
    "ok" | "unreadable" | "unavailable"
  >("ok");
  const [detailDirty, setDetailDirty] = useState(false);
  const discard = useDiscardGuard("the unsaved PAC draft changes");

  // An unresolved operation for ANY profile is surfaced on the list so the
  // operator can open that profile and recover; a store that cannot be
  // read is surfaced too (it withholds every lifecycle dispatch).
  useEffect(() => {
    const read = readPacRecovery(subject);
    setMarkerProfile(read.kind === "valid" ? read.marker.profileId : null);
    setStoreState(
      read.kind === "unreadable" || read.kind === "unavailable"
        ? read.kind
        : "ok",
    );
  }, [subject, selected, page.q.dataUpdatedAt]);

  if (selected !== null) {
    return (
      <>
        {discard.element}
        <ProfileDetail
          id={selected}
          isAdmin={isAdmin}
          pools={listing?.pools ?? []}
          onDirtyChange={(d) => {
            setDetailDirty(d);
            onDirtyChange?.(d);
          }}
          onBack={() => {
            discard.request(detailDirty, () => {
              setDetailDirty(false);
              onDirtyChange?.(false);
              setSelected(null);
              page.refreshToResolve();
            });
          }}
          onChanged={() => {
            page.refreshToResolve();
          }}
        />
      </>
    );
  }

  const runCreate = async (
    form: PacProfileInput,
    confirm?: {
      challenge: string;
      value: string;
      binding: Readonly<Record<string, unknown>>;
    },
  ): Promise<void> => {
    if (listing === undefined) return;
    setFence(null);
    setStale(null);
    setIssues(null);
    const signal = page.owner.begin();
    try {
      const created = await createPacProfile(
        form,
        listing.collectionEtag,
        confirm,
        signal,
      );
      setCreate({ kind: "closed" });
      setNotice(
        `Profile ${created.id} created (revision ${String(created.revision)}). Open it to edit the draft and publish.`,
      );
      page.refreshToResolve();
    } catch (err) {
      const f = classifyDispatchFailure(err);
      switch (f.kind) {
        case "fence":
          setCreate({ kind: "closed" });
          setFence(f.fence);
          page.refreshToResolve();
          break;
        case "challenge":
          if (f.challenge.code === "confirm_required")
            setCreate({
              kind: "challenge",
              form,
              challenge: f.challenge,
              result: "idle",
              errorText: "",
            });
          else {
            setCreate({ kind: "closed" });
            setStale(f.challenge);
            page.refreshToResolve();
          }
          break;
        case "issues":
          setCreate({ kind: "editing", form, result: "idle", errorText: "" });
          setIssues(f.issues);
          break;
        case "unknown":
          setCreate({ kind: "closed" });
          page.latchUnknown("create");
          break;
        default:
          setCreate({
            kind: "editing",
            form,
            result: "failed",
            errorText:
              f.kind === "refused"
                ? f.text
                : serverErrorText(err, "Create refused."),
          });
      }
    } finally {
      page.owner.settle(signal);
    }
  };

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={listing !== undefined}
          onRefresh={() => {
            page.refreshToResolve();
          }}
        />
        {isAdmin && listing !== undefined && page.unknown === null && (
          <Button
            size="sm"
            variant="primary"
            onClick={() => {
              setCreate({
                kind: "editing",
                form: EMPTY_FORM,
                result: "idle",
                errorText: "",
              });
            }}
          >
            New profile
          </Button>
        )}
      </div>
      <p className={styles.authNote}>{NODE_LOCAL_NOTE}</p>
      {page.unknown !== null && (
        <Callout variant="unknown" title="Last change unconfirmed" role="alert">
          A request was sent but no result was observed. Refresh to resolve
          against the appliance before creating more profiles.
        </Callout>
      )}
      {markerProfile !== null && (
        <Callout
          variant="unknown"
          title="Unresolved publish/rollback operation"
          role="alert"
        >
          An operation on profile <Mono>{markerProfile}</Mono> was dispatched
          without an observed result. Publish and rollback are withheld on EVERY
          profile until it is resolved: open that profile and use Recover (or
          the typed Abandon).
        </Callout>
      )}
      {storeState !== "ok" && (
        <Callout
          variant="warning"
          title={`Recovery store ${storeState}`}
          role="alert"
        >
          The browser storage that holds the operation-identity marker is{" "}
          {storeState}; an earlier operation may be unresolved. Publish and
          rollback are withheld on every profile until the storage is repaired
          or this tab is closed.
        </Callout>
      )}
      {notice !== null && (
        <Callout variant="success" role="status">
          {notice}
        </Callout>
      )}
      {fence !== null && (
        <FenceCallout fence={fence} tokenLabel="collectionEtag" />
      )}
      {stale !== null && <ChallengeStaleCallout challenge={stale} />}
      {issues !== null && <IssuesCallout issues={issues} />}

      {listing === undefined && page.q.isPending && (
        <Skeleton>Loading profiles…</Skeleton>
      )}
      {listing === undefined && page.q.isError && (
        <ErrorState title="Profiles unavailable">
          {serverErrorText(page.q.error, "The PAC profiles could not be read.")}
        </ErrorState>
      )}
      {listing !== undefined && (
        <>
          <Card title="Default profile (legacy)">
            <p>
              <Mono>{listing.defaultProfile.pacPath}</Mono> —{" "}
              {listing.defaultProfile.enabled ? "enabled" : "disabled"}; proxy{" "}
              {listing.defaultProfile.proxyHost !== ""
                ? `${listing.defaultProfile.proxyHost}:${String(listing.defaultProfile.proxyPort)}`
                : "(none — fail-open DIRECT)"}
              ; {String(listing.defaultProfile.exclusions)} exclusion(s);
              availability {listing.defaultProfile.availabilityMode}; private
              networks {listing.defaultProfile.privateNetworks}. Managed on the
              Legacy tab.
            </p>
          </Card>
          <Card title={`Profiles (${String(listing.profiles.length)})`}>
            {listing.profiles.length === 0 ? (
              <EmptyState title="No profiles yet">
                Profiles steer clients per site or group; create one to start a
                node-local draft.
              </EmptyState>
            ) : (
              <div className={styles.tableWrap}>
                <table className={styles.table}>
                  <caption className={styles.srOnly}>PAC profiles</caption>
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">Id</th>
                      <th scope="col">State</th>
                      <th scope="col">Pool</th>
                      <th scope="col">Mode</th>
                      <th scope="col">Rules</th>
                      <th scope="col">Revision</th>
                      <th scope="col">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {listing.profiles.map((pr) => (
                      <tr key={pr.id}>
                        <td className={styles.nameCell}>{pr.name}</td>
                        <td>
                          <Mono>{pr.id}</Mono>
                        </td>
                        <td>
                          <StatusBadge status={pr.enabled ? "ok" : "neutral"}>
                            {pr.enabled ? "enabled" : "disabled"}
                          </StatusBadge>
                        </td>
                        <td>{pr.poolId !== "" ? pr.poolId : "—"}</td>
                        <td>
                          {pr.availabilityMode}
                          {pr.availabilityMode !== "secure" ||
                          pr.privateNetworks === "direct" ||
                          pr.rules.some((r) => r.action === "direct")
                            ? " · DIRECT-capable"
                            : ""}
                        </td>
                        <td>{pr.rules.length}</td>
                        <td>{pr.revision}</td>
                        <td className={styles.rowActions}>
                          <Button
                            size="sm"
                            onClick={() => {
                              setSelected(pr.id);
                            }}
                          >
                            Open
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}

      {create.kind === "editing" && listing !== undefined && (
        <ConfirmationDialog
          open
          tier={2}
          title="New PAC profile"
          body={
            <div className={styles.editorGroup}>
              <InputField
                label="Id (stable; letters, digits, dashes)"
                value={create.form.id}
                onChange={(e) => {
                  setCreate({
                    ...create,
                    form: { ...create.form, id: e.target.value },
                  });
                }}
              />
              <InputField
                label="Name"
                value={create.form.name}
                onChange={(e) => {
                  setCreate({
                    ...create,
                    form: { ...create.form, name: e.target.value },
                  });
                }}
              />
              <TextareaField
                label="Description"
                rows={2}
                value={create.form.description}
                onChange={(e) => {
                  setCreate({
                    ...create,
                    form: { ...create.form, description: e.target.value },
                  });
                }}
              />
              <Checkbox
                label="Enabled"
                checked={create.form.enabled}
                onChange={(e) => {
                  setCreate({
                    ...create,
                    form: { ...create.form, enabled: e.target.checked },
                  });
                }}
              />
              <SelectField
                label="Default pool"
                value={create.form.poolId}
                onChange={(e) => {
                  setCreate({
                    ...create,
                    form: { ...create.form, poolId: e.target.value },
                  });
                }}
              >
                <option value="">— none —</option>
                {listing.pools.map((pool) => (
                  <option key={pool.id} value={pool.id}>
                    {pool.id}
                  </option>
                ))}
              </SelectField>
              <SelectField
                label="Private networks"
                value={create.form.privateNetworks}
                onChange={(e) => {
                  setCreate({
                    ...create,
                    form: { ...create.form, privateNetworks: e.target.value },
                  });
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
                value={create.form.availabilityMode}
                onChange={(e) => {
                  setCreate({
                    ...create,
                    form: {
                      ...create.form,
                      availabilityMode: e.target.value,
                    },
                  });
                }}
              >
                {PAC_AVAILABILITY_MODES.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </SelectField>
            </div>
          }
          impact="The profile becomes active at once at /pac/<id>.pac (revision 1) with no rules; rules are authored in its node-local draft and published from there. DIRECT-capable settings draw a typed confirmation."
          rollback="Delete the profile."
          confirmLabel="Create profile"
          result={create.result}
          {...(create.errorText !== "" ? { errorText: create.errorText } : {})}
          onConfirm={() => {
            if (create.result === "pending") return;
            setCreate({ ...create, result: "pending" });
            void runCreate(create.form);
          }}
          onCancel={() => {
            setCreate({ kind: "closed" });
          }}
        />
      )}
      {create.kind === "challenge" && (
        <ChallengeCeremony
          open
          actionLabel="Create with bypass"
          challenge={create.challenge}
          result={create.result}
          errorText={create.errorText}
          onConfirm={(typed) => {
            if (create.result === "pending") return;
            setCreate({ ...create, result: "pending" });
            void runCreate(create.form, {
              challenge: create.challenge.challenge,
              value: typed,
              binding: create.challenge.binding,
            });
          }}
          onCancel={() => {
            setCreate({ kind: "closed" });
          }}
        />
      )}
    </div>
  );
}
