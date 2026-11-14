import { Badge } from "../../ui";
import { operationInfo, ruleSentence } from "../policy/selector";
import type {
  ManifestRow,
  MembershipDetail,
  NamedRef,
  RuleDetail,
  SelectorDetail,
} from "./contract";

/**
 * The exact authority a restored rule or membership would make effective (P1.18.4 FC4-1). Everything here is a function of the detail the service
 * resolved from stored ids: this module never looks a name up, never compares display names and never decides anything. The same sentence is used
 * for the checkbox's accessible name, the row and the confirmation, so what is ticked, what is read and what is confirmed cannot drift apart.
 */

const KIND_WORD = {
  user: "user",
  group: "group",
  agent: "agent",
  endpoint: "endpoint",
} as const;

/** "agent sample-ci-runner (ID a-ci)". A record that no longer exists shows only its id and says so. */
export function refText(ref: NamedRef): string {
  if (ref.missing)
    return `${KIND_WORD[ref.kind]} with ID ${ref.id} (no longer exists)`;
  return `${KIND_WORD[ref.kind]} ${ref.name} (ID ${ref.id})`;
}

function selectorConstraints(selector: SelectorDetail): string[] {
  const parts: string[] = [];
  if (selector.composeProject !== "")
    parts.push(`Compose project ${selector.composeProject}`);
  if (selector.composeService !== "")
    parts.push(`Compose service ${selector.composeService}`);
  if (selector.imagePattern !== "")
    parts.push(`image ${selector.imagePattern}`);
  if (selector.pinnedContainerId !== "")
    parts.push(`pinned container ID ${selector.pinnedContainerId}`);
  if (selector.pinnedImageDigest !== "")
    parts.push(`pinned image digest ${selector.pinnedImageDigest}`);
  return parts;
}

function limits(detail: RuleDetail): string[] {
  const parts: string[] = [];
  if (detail.logTailMax !== null)
    parts.push(`at most ${detail.logTailMax} log lines`);
  if (detail.stopTimeoutMax !== null)
    parts.push(`stop timeout at most ${detail.stopTimeoutMax} seconds`);
  return parts;
}

export function ruleText(detail: RuleDetail): string {
  const base = ruleSentence({
    effect: detail.effect,
    subjectKind:
      detail.subject.kind === "endpoint" ? "user" : detail.subject.kind,
    subjectName: detail.subject.missing
      ? `with ID ${detail.subject.id} (no longer exists)`
      : `${detail.subject.name} (ID ${detail.subject.id})`,
    operation: detail.operation,
    target: `“${detail.selector.containerName}”`,
    nameIsPattern: detail.selector.nameType === "glob",
  });
  const extra = [...selectorConstraints(detail.selector), ...limits(detail)];
  const endpoint = `on ${refText(detail.endpoint)}`;
  return `${base} ${endpoint}${extra.length > 0 ? `, only with ${extra.join(", ")}` : ""}. Operation ${detail.operation}, selector ${detail.selector.id}.`;
}

export function membershipText(detail: MembershipDetail): string {
  return `${refText(detail.member)} is a member of ${refText(detail.group)}.`;
}

/** The sentence for a row, or null when the row has no identifying detail (then it must not be selectable). */
export function exactText(row: ManifestRow): string | null {
  if (row.detail === null) return null;
  return row.detail.kind === "rule"
    ? ruleText(row.detail)
    : membershipText(row.detail);
}

export function needsDetail(row: ManifestRow): boolean {
  return (
    row.kind === "policy" ||
    row.kind === "user_membership" ||
    row.kind === "agent_membership"
  );
}

function missingRefs(detail: ManifestRow["detail"]): NamedRef[] {
  if (detail === null) return [];
  return (
    detail.kind === "rule"
      ? [detail.subject, detail.endpoint]
      : [detail.member, detail.group]
  ).filter((ref) => ref.missing);
}

/**
 * Whether the page may offer a checkbox for this row at all. The server's `approvable` is necessary but not sufficient: a rule or membership
 * the page cannot describe exactly, or whose subject, endpoint, member or group no longer exists, is shown with the reason and NO checkbox,
 * so an approval is never asked for something the person was not told precisely.
 */
export type Reviewable =
  { ok: true } | { ok: false; why: "details_missing" | "record_missing" };

export function reviewable(row: ManifestRow): Reviewable {
  if (!needsDetail(row)) return { ok: true };
  if (row.detail === null) return { ok: false, why: "details_missing" };
  if (missingRefs(row.detail).length > 0)
    return { ok: false, why: "record_missing" };
  return { ok: true };
}

export function reviewableCopy(
  why: "details_missing" | "record_missing",
): string {
  return why === "details_missing"
    ? "Mandatary didn’t send the details needed to show exactly what approving this would allow, so it can’t be selected. Reload the page."
    : "A record it refers to no longer exists, so it can’t be selected. It stays switched off.";
}

function Pair({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-x-3 sm:grid-cols-[11rem_1fr]">
      <dt className="text-xs font-semibold text-muted sm:pt-0.5">{label}</dt>
      <dd className="min-w-0 break-words text-sm">{children}</dd>
    </div>
  );
}

function RefValue({ value }: { value: NamedRef }) {
  return (
    <>
      <span className="font-medium">
        {value.missing ? value.id : value.name}
      </span>{" "}
      <span className="text-muted">({KIND_WORD[value.kind]}, ID </span>
      <code className="font-mono text-[0.8125rem]">{value.id}</code>
      <span className="text-muted">)</span>
      {value.missing ? (
        <>
          {" "}
          <Badge tone="warning" icon="alert">
            No longer exists
          </Badge>
        </>
      ) : null}
    </>
  );
}

/** What approving this entry would make effective, as labelled facts. Rendered for rules and memberships only. */
export function DetailBlock({ row }: { row: ManifestRow }) {
  const detail = row.detail;
  if (detail === null) return null;
  if (detail.kind === "membership") {
    return (
      <dl
        aria-label="Exactly what approving this restores"
        className="mt-2 space-y-1.5 rounded-control border border-line bg-sunken p-3"
      >
        <Pair label={detail.member.kind === "agent" ? "Agent" : "User"}>
          <RefValue value={detail.member} />
        </Pair>
        <Pair label="Group">
          <RefValue value={detail.group} />
        </Pair>
      </dl>
    );
  }
  const info = operationInfo(detail.operation);
  const constraints = selectorConstraints(detail.selector);
  const caps = limits(detail);
  return (
    <dl
      aria-label="Exactly what approving this restores"
      className="mt-2 space-y-1.5 rounded-control border border-line bg-sunken p-3"
    >
      <Pair label="Effect">
        <span className="font-medium">
          {detail.effect === "allow" ? "Allow" : "Deny"}
        </span>
      </Pair>
      <Pair label="Operation">
        {info.label} <span className="text-muted">(</span>
        <code className="font-mono text-[0.8125rem]">{detail.operation}</code>
        <span className="text-muted">)</span>
      </Pair>
      <Pair label="Applies to">
        <RefValue value={detail.subject} />
      </Pair>
      <Pair label="Endpoint">
        <RefValue value={detail.endpoint} />
      </Pair>
      <Pair
        label={
          detail.selector.nameType === "glob"
            ? "Container name pattern"
            : "Container name"
        }
      >
        <code className="font-mono text-[0.8125rem]">
          {detail.selector.containerName}
        </code>
        {detail.selector.nameType === "glob" ? (
          <span className="text-muted">
            {" "}
            (matches every container whose name fits the pattern)
          </span>
        ) : null}
      </Pair>
      {constraints.length > 0 ? (
        <Pair label="Only when">{constraints.join("; ")}</Pair>
      ) : null}
      {caps.length > 0 ? <Pair label="Limits">{caps.join("; ")}</Pair> : null}
      <Pair label="Selector ID">
        <code className="font-mono text-[0.8125rem]">{detail.selector.id}</code>
      </Pair>
    </dl>
  );
}
