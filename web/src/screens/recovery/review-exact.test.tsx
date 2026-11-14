import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  localEndpoint,
  manifest,
  ref,
  sampleDigest,
  selector,
} from "../../gallery/recoveryFixtures";
import { ThemeProvider } from "../../theme";
import type { ManifestRow, ReviewScreenProps, RowDetail } from "./contract";
import { ReviewScreen } from "./review";

/**
 * P1.18.4 FC4-1: restore approval selection AND confirmation identify the exact authority being approved. These tests drive the real screen with
 * synthetic manifests: same operation for a different subject or target, similar names, reordered records, stale or missing details, both themes,
 * keyboard operation. The server resolves every name by stored id; the screen only ever shows what it was given.
 */

afterEach(cleanup);

const rule = (
  id: string,
  detail: Partial<Extract<RowDetail, { kind: "rule" }>> = {},
  over: Partial<ManifestRow> = {},
): ManifestRow => ({
  kind: "policy",
  id,
  label: "ALLOW container:logs",
  origin: "imported",
  sourceState: "active",
  decision: "pending",
  approvable: true,
  blockedReason: null,
  needs: "approval",
  comparison: {
    kind: "rule",
    imported: "allow",
    effective: "allow",
    localDenyKept: false,
  },
  detail: {
    kind: "rule",
    effect: "allow",
    operation: "container:logs",
    subject: ref("agent", "a-1", "sample-bot"),
    endpoint: localEndpoint,
    selector: selector({ id: "sel-web", containerName: "sample-web" }),
    logTailMax: null,
    stopTimeoutMax: null,
    ...detail,
  },
  digest: sampleDigest("policy", id),
  ...over,
});

const membership = (
  kind: "user_membership" | "agent_membership",
  member: ReturnType<typeof ref>,
  group: ReturnType<typeof ref>,
): ManifestRow => ({
  kind,
  id: `${member.id}:${group.id}`,
  label: `${member.name} in ${group.name}`,
  origin: "imported",
  sourceState: "active",
  decision: "pending",
  approvable: true,
  blockedReason: null,
  needs: "approval",
  comparison: { kind: "none" },
  detail: { kind: "membership", member, group },
  digest: sampleDigest(kind, `${member.id}:${group.id}`),
});

function props(
  items: readonly ManifestRow[],
  patch: Partial<ReviewScreenProps> = {},
): ReviewScreenProps {
  return {
    load: { kind: "ready", data: { ...manifest, items } },
    approval: { kind: "idle" },
    credentialsHref: (id) => `/agents?agent=${id}`,
    onRetry: () => undefined,
    onApprove: () => undefined,
    ...patch,
  };
}

const themes = ["light", "dark"] as const;
function mount(ui: ReactElement, theme: "light" | "dark") {
  return render(<ThemeProvider initial={theme}>{ui}</ThemeProvider>);
}
const names = () =>
  (screen.queryAllByRole("checkbox") as HTMLInputElement[]).map(
    (box) =>
      box.getAttribute("aria-label") ?? box.labels?.[0]?.textContent ?? "",
  );
const boxNamed = (name: string | RegExp) =>
  screen.getByRole("checkbox", { name }) as HTMLInputElement;
const approveBtn = () =>
  screen.getByRole("button", {
    name: /^Approve \d+ selected…$/,
  }) as HTMLButtonElement;

describe.each(themes)(
  "exact authority in selection and confirmation (%s theme)",
  (theme) => {
    test("the same operation for a different subject or a different target is told apart in the checkbox name, the row and the confirmation", () => {
      const onApprove = vi.fn();
      const items = [
        rule("p-agent"), // allow logs of web for agent sample-bot
        rule("p-group", { subject: ref("group", "g-1", "sample-ops") }), // same operation and selector, different subject
        rule("p-other-target", {
          selector: selector({ id: "sel-db", containerName: "sample-db" }),
        }), // same subject and operation, different target
        rule("p-deny", { effect: "deny" }, { label: "DENY container:logs" }), // same everything but the effect
      ];
      mount(<ReviewScreen {...props(items, { onApprove })} />, theme);
      const labels = names();
      expect(labels).toHaveLength(4);
      expect(new Set(labels).size).toBe(4); // no two checkboxes share an accessible name
      expect(labels[0]).toBe(
        "Rule Allow agent sample-bot (ID a-1) to read logs of “sample-web” on endpoint sample-local (ID ep-local). Operation container:logs, selector sel-web.",
      );
      expect(labels[1]).toContain(
        "Allow group sample-ops (ID g-1) to read logs of “sample-web”",
      );
      expect(labels[2]).toContain("read logs of “sample-db”");
      expect(labels[3]).toContain(
        "Deny agent sample-bot (ID a-1) from reading logs of “sample-web”",
      );

      fireEvent.click(boxNamed(/^Rule Allow group sample-ops \(ID g-1\)/));
      expect(boxNamed(labels[0] as string).checked).toBe(false); // the lookalike was not ticked by it
      fireEvent.click(approveBtn());
      const dialog = screen.getByRole("group", { name: "Approve 1 record?" });
      const list = within(dialog).getByRole("list", {
        name: "Records to approve",
      });
      expect(list.textContent).toContain(
        "Allow group sample-ops (ID g-1) to read logs of “sample-web” on endpoint sample-local (ID ep-local)",
      );
      expect(list.textContent).not.toContain("sample-bot");
      fireEvent.click(
        within(dialog).getByRole("button", { name: "Approve 1 record" }),
      );
      expect(onApprove).toHaveBeenCalledWith([
        {
          kind: "policy",
          id: "p-group",
          digest: sampleDigest("policy", "p-group"),
        },
      ]);
    });

    test("similar display names resolve to different ids and are never merged: the id is part of every name", () => {
      const items = [
        rule("p-a", { subject: ref("group", "g-ops", "sample-ops") }),
        rule("p-b", { subject: ref("group", "g-ops-2", "sample-ops ") }), // trailing space
        rule("p-c", { subject: ref("group", "g-ops-3", "Sample-Ops") }), // case
      ];
      mount(<ReviewScreen {...props(items)} />, theme);
      const labels = names();
      expect(new Set(labels).size).toBe(3);
      expect(labels.some((label) => label.includes("(ID g-ops)"))).toBe(true);
      expect(labels.some((label) => label.includes("(ID g-ops-2)"))).toBe(true);
      expect(labels.some((label) => label.includes("(ID g-ops-3)"))).toBe(true);
      fireEvent.click(boxNamed(/\(ID g-ops-2\)/));
      expect(
        (screen.getAllByRole("checkbox") as HTMLInputElement[]).filter(
          (box) => box.checked,
        ),
      ).toHaveLength(1);
    });

    test("a membership names BOTH the principal and the group, including the same agent in two groups and two agents in one group", () => {
      const bot = ref("agent", "a-1", "sample-bot");
      const ops = ref("group", "g-ops", "sample-ops");
      const items = [
        membership("agent_membership", bot, ops),
        membership(
          "agent_membership",
          bot,
          ref("group", "g-dev", "sample-dev"),
        ),
        membership(
          "agent_membership",
          ref("agent", "a-2", "sample-bot-two"),
          ops,
        ),
        membership("user_membership", ref("user", "u-1", "sample-robin"), ops),
      ];
      mount(<ReviewScreen {...props(items)} />, theme);
      const labels = names();
      expect(new Set(labels).size).toBe(4);
      expect(labels[0]).toBe(
        "Group member (agent) agent sample-bot (ID a-1) is a member of group sample-ops (ID g-ops).",
      );
      expect(labels[1]).toContain("group sample-dev (ID g-dev)");
      expect(labels[3]).toBe(
        "Group member (user) user sample-robin (ID u-1) is a member of group sample-ops (ID g-ops).",
      );
      const facts = factsOf("agent_membership", "a-1:g-ops");
      expect(facts.map(([label]) => label)).toEqual(["Agent", "Group"]);
      expect(facts[0]?.[1]).toContain("sample-bot (agent, ID a-1)");
      expect(facts[1]?.[1]).toContain("sample-ops (group, ID g-ops)");
    });
  },
);

/** The labelled facts of one row's "exactly what approving this restores" block, as [label, text] pairs. */
function factsOf(kind: string, id: string): Array<[string, string]> {
  const row = document.querySelector(
    `li[data-record="${kind}:${id}"]`,
  ) as HTMLElement | null;
  const block = row?.querySelector(
    'dl[aria-label="Exactly what approving this restores"]',
  );
  if (!block) throw new Error(`no detail block for ${kind}:${id}`);
  return Array.from(block.querySelectorAll("dt")).map(
    (dt) =>
      [dt.textContent ?? "", dt.nextElementSibling?.textContent ?? ""] as [
        string,
        string,
      ],
  );
}

test("the selector, every constraint and every limit are shown for a rule", () => {
  const items = [
    rule("p-strict", {
      effect: "deny",
      operation: "container:stop",
      subject: ref("user", "u-1", "sample-robin"),
      selector: selector({
        id: "sel-x",
        containerName: "sample-batch-*",
        nameType: "glob",
        composeProject: "sample-platform",
        composeService: "batch",
        imagePattern: "registry.invalid/batch:*",
        pinnedContainerId: "c0ffee0123456789",
        pinnedImageDigest: "sha256:abcdef0123456789",
      }),
      logTailMax: null,
      stopTimeoutMax: 30,
    }),
    rule("p-logs", { logTailMax: 500 }),
  ];
  mount(<ReviewScreen {...props(items)} />, "light");
  const strict = new Map(factsOf("policy", "p-strict"));
  expect(strict.get("Effect")).toBe("Deny");
  expect(strict.get("Operation")).toContain("container:stop");
  expect(strict.get("Applies to")).toContain("sample-robin (user, ID u-1)");
  expect(strict.get("Endpoint")).toContain(
    "sample-local (endpoint, ID ep-local)",
  );
  expect(strict.get("Container name pattern")).toContain("sample-batch-*");
  expect(strict.get("Container name pattern")).toContain(
    "matches every container whose name fits the pattern",
  );
  expect(strict.get("Only when")).toBe(
    "Compose project sample-platform; Compose service batch; image registry.invalid/batch:*; pinned container ID c0ffee0123456789; pinned image digest sha256:abcdef0123456789",
  );
  expect(strict.get("Limits")).toBe("stop timeout at most 30 seconds");
  expect(strict.get("Selector ID")).toBe("sel-x");
  const logs = new Map(factsOf("policy", "p-logs"));
  expect(logs.get("Container name")).toBe("sample-web");
  expect(logs.get("Limits")).toBe("at most 500 log lines");
  expect(logs.has("Only when")).toBe(false);
  // The checkbox name carries the same constraints, so a screen reader hears them before ticking.
  expect(names()[0]).toContain(
    "only with Compose project sample-platform, Compose service batch, image registry.invalid/batch:*, pinned container ID c0ffee0123456789, pinned image digest sha256:abcdef0123456789, stop timeout at most 30 seconds",
  );
});

test("reordered records keep their own names, ids and digests: selection follows the record, not its position", () => {
  const items = [
    rule("p-1", { subject: ref("group", "g-1", "sample-ops") }),
    rule("p-2", { subject: ref("group", "g-2", "sample-dev") }),
    rule("p-3", { subject: ref("agent", "a-3", "sample-bot") }),
  ];
  const onApprove = vi.fn();
  const first = render(
    <ThemeProvider initial="light">
      <ReviewScreen
        {...props(items, {
          onApprove,
          initial: { selected: [{ kind: "policy", id: "p-2" }] },
        })}
      />
    </ThemeProvider>,
  );
  const before = names();
  expect(
    (screen.getAllByRole("checkbox") as HTMLInputElement[]).map(
      (box) => box.checked,
    ),
  ).toEqual([false, true, false]);
  first.rerender(
    <ThemeProvider initial="light">
      <ReviewScreen
        {...props([...items].reverse(), {
          onApprove,
          initial: { selected: [{ kind: "policy", id: "p-2" }] },
        })}
      />
    </ThemeProvider>,
  );
  const after = names();
  expect(after).toEqual([...before].reverse());
  // The ticked box is still the one for p-2 (sample-dev), wherever it now sits.
  expect(
    (screen.getAllByRole("checkbox") as HTMLInputElement[]).map(
      (box) => box.checked,
    ),
  ).toEqual([false, true, false]);
  expect(boxNamed(/group sample-dev \(ID g-2\)/).checked).toBe(true);
  fireEvent.click(approveBtn());
  fireEvent.click(
    within(screen.getByRole("group", { name: "Approve 1 record?" })).getByRole(
      "button",
      { name: "Approve 1 record" },
    ),
  );
  expect(onApprove).toHaveBeenCalledWith([
    { kind: "policy", id: "p-2", digest: sampleDigest("policy", "p-2") },
  ]);
});

test("missing or stale identifying details prevent an approval the person could not describe: no checkbox, a reason, nothing counted", () => {
  const noDetail = { ...rule("p-nodetail"), detail: null } as ManifestRow;
  const gone = rule("p-gone", { subject: ref("group", "g-gone", "x", true) }); // the subject no longer exists
  const memberGone = membership(
    "agent_membership",
    ref("agent", "a-gone", "x", true),
    ref("group", "g-ops", "sample-ops"),
  );
  const noMembershipDetail = {
    ...membership(
      "user_membership",
      ref("user", "u-1", "sample-robin"),
      ref("group", "g-ops", "sample-ops"),
    ),
    detail: null,
  } as ManifestRow;
  const fine = rule("p-fine");
  mount(
    <ReviewScreen
      {...props([noDetail, gone, memberGone, noMembershipDetail, fine])}
    />,
    "light",
  );
  expect(screen.getAllByRole("checkbox")).toHaveLength(1); // only the rule that can be described exactly
  for (const id of ["policy:p-nodetail", "user_membership:u-1:g-ops"]) {
    const row = within(
      document.querySelector(`li[data-record="${id}"]`) as HTMLElement,
    );
    expect(row.queryByRole("checkbox"), id).toBeNull();
    expect(
      row.getByText(
        /didn’t send the details needed to show exactly what approving this would allow/,
      ),
      id,
    ).toBeTruthy();
  }
  for (const id of ["policy:p-gone", "agent_membership:a-gone:g-ops"]) {
    const row = within(
      document.querySelector(`li[data-record="${id}"]`) as HTMLElement,
    );
    expect(row.queryByRole("checkbox"), id).toBeNull();
    expect(
      row.getByText(
        /A record it refers to no longer exists, so it can’t be selected/,
      ),
      id,
    ).toBeTruthy();
    expect(row.getByText("No longer exists")).toBeTruthy();
  }
  // Selecting the one describable rule never drags the others in.
  fireEvent.click(screen.getAllByRole("checkbox")[0] as HTMLElement);
  expect(approveBtn().textContent).toBe("Approve 1 selected…");
});

test("a record that changed after review is refused as stale, nothing is approved, the selection is kept and the list can be reloaded", () => {
  const onRetry = vi.fn();
  const items = [
    rule("p-1"),
    rule("p-2", { subject: ref("group", "g-1", "sample-ops") }),
  ];
  const view = mount(
    <ReviewScreen
      {...props(items, {
        approval: { kind: "working" },
        initial: {
          selected: [{ kind: "policy", id: "p-1" }],
          confirming: true,
        },
        onRetry,
      })}
    />,
    "light",
  );
  view.rerender(
    <ThemeProvider initial="light">
      <ReviewScreen
        {...props(items, {
          approval: {
            kind: "conflict",
            failures: [{ kind: "policy", id: "p-1", reason: "stale_details" }],
          },
          initial: { selected: [{ kind: "policy", id: "p-1" }] },
          onRetry,
        })}
      />
    </ThemeProvider>,
  );
  const alert = screen.getByRole("alert");
  expect(alert.textContent).toContain("Nothing was approved");
  expect(alert.textContent).toContain(
    "It changed after you reviewed it, so it was not approved. Reload the list and review it again.",
  );
  expect(boxNamed(/\(ID a-1\)/).checked).toBe(true);
  fireEvent.click(
    within(alert).getByRole("button", { name: "Reload the list" }),
  );
  expect(onRetry).toHaveBeenCalledTimes(1);
});

test("keyboard: every selectable record is a native checkbox in reading order, the confirmation list is focusable and Escape returns to the opener", () => {
  const items = [
    rule("p-1"),
    rule("p-2", { subject: ref("group", "g-1", "sample-ops") }),
    membership(
      "agent_membership",
      ref("agent", "a-1", "sample-bot"),
      ref("group", "g-1", "sample-ops"),
    ),
  ];
  mount(<ReviewScreen {...props(items)} />, "dark");
  const boxes = screen.getAllByRole("checkbox") as HTMLInputElement[];
  expect(
    boxes.every(
      (box) =>
        box.tagName === "INPUT" && box.type === "checkbox" && box.tabIndex >= 0,
    ),
  ).toBe(true);
  // DOM order equals the order the manifest lists them in within a section: rules, then members are separate sections in a fixed order.
  const sectionOrder = Array.from(document.querySelectorAll("section h3")).map(
    (heading) => heading.textContent,
  );
  expect(sectionOrder).toEqual(["Group members", "Rules"]);
  const trigger = document.getElementById(
    "review-approve-open",
  ) as HTMLButtonElement;
  fireEvent.click(boxes[0] as HTMLElement);
  fireEvent.click(trigger);
  const dialog = screen.getByRole("group", { name: "Approve 1 record?" });
  const list = within(dialog).getByRole("list", { name: "Records to approve" });
  expect(list.tabIndex).toBe(0); // scrollable text is reachable by keyboard
  fireEvent.keyDown(dialog, { key: "Escape" });
  expect(screen.queryByRole("group", { name: /^Approve/ })).toBeNull();
  expect(document.activeElement).toBe(trigger);
});
