#!/usr/bin/env python3
"""Versioned release acceptance report of P1.20 (standard library only).

Every release criterion names the concrete results that establish it ("CHECK-ID@artifact"). An artifact is one raw result document of
the evidence archive (see evidence.py); the report reads its compact summary from `docs/release/evidence/summaries/` and shows the
SHA-256 of the RAW document, which the summary records and ARCHIVE.sha256 lists, never a digest typed in by hand. A criterion is

  PASS        every linked result is PASS and every linked artifact has a digest
  FAIL        at least one linked result is FAIL
  UNVERIFIED  anything else: no link at all, a link with no result, a BLOCKED/skipped result, an artifact without a digest. A missing
              target, browser or architecture can therefore never count as a pass.

A criterion may also name ADVERSE runs (`adverse.refs`, "CHECK@artifact": failed or contradictory runs that are kept in the evidence).
While `adverse.state` is "open", a FAIL among them fails the criterion whatever the final run says. It stops counting only when a
reviewed change sets the state to "dispositioned" and records the disposition (who decided, on what basis, what it does and does NOT
claim) in `adverse`. A dispositioned criterion is reported as "PASS WITH DISCLOSURES": the adverse runs stay listed as the FAIL they
were, and a clean final run never erases a contradictory same-content failure.

The overall verdict is "ACCEPTED" only when every criterion is PASS and every acceptance gate of the catalog (independent exact-head
review, owner merge) is closed. When the criteria are met but a gate is open the report says so ("CRITERIA MET - ACCEPTANCE PENDING").

Two verification levels exist and are reported separately:

  --check            COMPACT: the committed catalog, ARCHIVE.sha256 and summaries are mutually consistent (every summary is bound to its
                     raw archive member by digest and revision) and the committed report is what they produce. The raw archive is NOT read.
  --audit-archive D  FULL: additionally the staged archive D (evidence.py stage) is audited: every member digest, completeness, and every
                     summary regenerated from its raw member byte for byte.

    python3 tests/release/report.py --evidence docs/release/evidence --criteria tests/release/criteria.json --out docs/release/phase1-release-acceptance.md [--check] [--audit-archive STAGED]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence  # noqa: E402

ORDER = {"FAIL": 0, "UNVERIFIED": 1, "PASS": 2}
sha256_file = evidence.sha256_file


# How an adverse group stops counting, and the text that must say why. "dispositioned": the owner decided (a policy decision, not a
# pass). "remediated": the defect was fixed (in the product or the test harness), a regression test pins the fix and fresh evidence of the criterion passes
# (a technical closure, not an owner decision). A group in either state WITHOUT its text keeps counting: the closure is never silent.
CLOSING_TEXT = {"dispositioned": "disposition", "remediated": "remediation"}


def adverse_groups(criterion):
    """The criterion's adverse groups: one dict (the original shape) or a list of dicts, as a list."""
    adv = criterion.get("adverse")
    if not adv:
        return []
    return [adv] if isinstance(adv, dict) else list(adv)


def group_closed(group):
    key = CLOSING_TEXT.get(group.get("state", ""))
    return bool(key and str(group.get(key, "")).strip())


def evaluate(criteria, results, digests, adverse=None):
    """criteria: [{id, text, evidence: ["CHECK@artifact", ...], ...}]; results: {"CHECK@artifact": "PASS"|...}; digests: {artifact: sha256}.
    Returns one row per criterion with its status and the evaluated links."""
    rows = []
    for c in criteria:
        links, status = [], "PASS"
        if not c.get("evidence"):
            status = "UNVERIFIED"
        for ref in c.get("evidence", []):
            artifact = ref.rsplit("@", 1)[1] if "@" in ref else ""
            res = results.get(ref)
            dig = digests.get(artifact)
            if res == "FAIL":
                link = "FAIL"
            elif res == "PASS" and dig:
                link = "PASS"
            else:
                link = "UNVERIFIED"
            links.append({"ref": ref, "result": res or "none", "digest": dig, "link": link})
            if ORDER[link] < ORDER[status]:
                status = link
        adverse_links, closed_links = [], []
        for adv in adverse_groups(c):
            closed = group_closed(adv)
            for ref in adv.get("refs", []):
                res = (adverse or {}).get(ref)
                link = {"ref": ref, "result": res or "none", "digest": digests.get(ref.rsplit("@", 1)[1] if "@" in ref else ""), "state": adv.get("state", "open")}
                adverse_links.append(link)
                if closed:
                    closed_links.append(link)
                elif res != "PASS" and ORDER["FAIL" if res == "FAIL" else "UNVERIFIED"] < ORDER[status]:
                    status = "FAIL" if res == "FAIL" else "UNVERIFIED"
        # An adverse run that is not PASS and was closed (dispositioned or remediated) makes the PASS a PASS WITH DISCLOSURES (never a silent one).
        disclosed = status == "PASS" and any(a["result"] != "PASS" for a in closed_links)
        rows.append(dict(c, status=status, links=links, adverse_links=adverse_links, disclosed=disclosed))
    return rows


def verify_sums(evdir):
    """Every committed evidence file (catalog, archive manifest, summaries) is listed in SHA256SUMS with its digest, so an edited file is
    detected even when it is not one of the linked results. Returns a list of problems (empty = consistent)."""
    path = os.path.join(evdir, "SHA256SUMS")
    if not os.path.exists(path):
        return ["SHA256SUMS is missing"]
    listed, problems = {}, []
    with open(path) as fh:
        for ln in fh:
            if not ln.strip():
                continue
            digest, _, name = ln.rstrip("\n").partition("  ")
            listed[name] = digest
    for name, digest in sorted(listed.items()):
        f = os.path.join(evdir, name)
        if not os.path.exists(f):
            problems.append("listed but missing: " + name)
        elif sha256_file(f) != digest:
            problems.append("digest mismatch: " + name)
    on_disk = set()
    for root, _, files in os.walk(evdir):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), evdir).replace(os.sep, "/")
            if rel != "SHA256SUMS":
                on_disk.add(rel)
    problems += ["not listed: " + n for n in sorted(on_disk - set(listed))]
    return problems


seal = evidence.seal  # the maintainer's step after a regeneration: rewrite SHA256SUMS over every file of the evidence directory


def load_evidence(evdir):
    """(catalog, results, digests, meta): the result of every check of every artifact, keyed "CHECK@artifact", and the SHA-256 of the RAW
    document each summary was derived from (the digest that ARCHIVE.sha256 lists; evidence.verify_compact binds the two)."""
    with open(os.path.join(evdir, "catalog.json")) as fh:
        catalog = json.load(fh)
    results, digests, meta = {}, {}, {}
    for name, a in catalog["artifacts"].items():
        path = os.path.join(evdir, a["file"])
        if not os.path.exists(path):
            continue
        with open(path) as fh:
            doc = json.load(fh)
        digests[name] = (doc.get("source") or {}).get("sha256") or sha256_file(path)
        meta[name] = a
        if a["kind"] == "results":
            for r in doc.get("results", []):
                results["%s@%s" % (r["id"], name)] = r["status"]
    return catalog, results, digests, meta


def mb(v):
    return "%.2f MB (%d B)" % (v / 1e6, v) if isinstance(v, (int, float)) and not isinstance(v, bool) else "not measured"


def measured_table(evdir, catalog):
    """The measured values behind the budget criteria, read from the committed summaries (never typed). Missing values read 'not measured'."""
    rows = []
    for name, a in catalog["artifacts"].items():
        path = os.path.join(evdir, a["file"])
        if a["kind"] != "results" or not os.path.exists(path):
            continue
        with open(path) as fh:
            doc = json.load(fh)
        fp = (doc.get("evidence") or {}).get("footprint")
        if not fp:
            continue
        env = (doc.get("evidence") or {}).get("environment", {})
        idle = {r["label"]: r for r in fp.get("idle", [])}
        ld = fp.get("load") or {}
        img = (fp.get("image") or {}).get("compressed", {})

        def steady(label):
            r = idle.get(label)
            return "%s idle (max of the final %s s of %s s); start-up peak %s, stabilized at %s s" % (mb(r.get("VmRSS_steady_max")), r.get("steady_window_s"), r.get("window_s"), mb(r.get("VmRSS_peak_in_window")), r.get("settled_under_budget_at_s")) if r else "not measured"
        rows.append((name, "%s %s, %s CPUs, Docker %s" % (env.get("os_arch"), env.get("os"), env.get("cpus"), env.get("docker_server")), mb(img.get("bytes")), steady("fresh"), steady("configured"), steady("after-restart"),
                     "peak %s; high-water mark %s; %s s; REST %s ok / %s non-200, MCP %s ok / %s errors" % (mb(ld.get("VmRSS_peak_sampled")), mb(ld.get("VmHWM_after")), ld.get("seconds"), sum((ld.get("rest") or {}).get(k, 0) for k in ("status", "logs")),
                                                                                                         (ld.get("rest") or {}).get("errors"), (ld.get("mcp") or {}).get("ok"), (ld.get("mcp") or {}).get("errors"))))
    return rows


def verdict(rows):
    n = {k: sum(1 for r in rows if r["status"] == k) for k in ORDER}
    ok = bool(rows) and n["FAIL"] == 0 and n["UNVERIFIED"] == 0  # an empty report is never an acceptance
    return ok, n


def open_gates(catalog):
    return [g for g in catalog.get("acceptance_gates", []) if g.get("state") != "closed"]


def overall(rows, catalog):
    """ACCEPTED only with every criterion PASS and every acceptance gate closed; otherwise the criteria level is stated, never promoted."""
    ok, _ = verdict(rows)
    if not ok:
        return "NOT ACCEPTED"
    gates = open_gates(catalog)
    return "CRITERIA MET - ACCEPTANCE PENDING" if gates else "ACCEPTED"


def render(catalog, rows, digests, meta, results, evdir):
    ok, n = verdict(rows)
    disclosed = sum(1 for r in rows if r.get("disclosed"))
    L = []
    w = L.append
    arch = catalog["archive"]
    w("# Phase 1 release acceptance, security and footprint report (P1.20)")
    w("")
    w("> Generated by `tests/release/report.py` from the compact evidence in `docs/release/evidence/` (catalog, archive manifest and summaries); `python3 tests/release/report.py --check` fails when this page is stale or edited by hand. The raw run output is in the evidence archive named in section 2; `--check` does not read it, `--audit-archive` does.")
    w("> This is acceptance evidence for one release candidate. It is **not** a NIST, FIPS, product-qualification or runtime-compatibility claim, and it does not authorize a merge or a deployment (Nico alone merges).")
    w("")
    w("## 1. Verdict")
    w("")
    rc = catalog["release_candidate"]
    w("| Item | Value |")
    w("| --- | --- |")
    for k, v in rc.items():
        w("| %s | %s |" % (k.replace("_", " "), v))
    w("")
    w("**Overall: %s.** %d criteria: %d PASS (%d of them with explicit disclosures), %d FAIL, %d UNVERIFIED. A criterion with no linked result, a skipped/BLOCKED result or an artifact without a digest is UNVERIFIED and never counts as a pass." % (
        overall(rows, catalog), len(rows), n["PASS"], disclosed, n["FAIL"], n["UNVERIFIED"]))
    w("")
    gates = catalog.get("acceptance_gates", [])
    if gates:
        w("Acceptance gates that this page cannot attest by itself (the page is evidence; it is not the reviewer or the owner):")
        w("")
        for g in gates:
            w("* **%s** - %s: %s" % (g["id"], g["text"], g.get("state", "open").upper()))
        w("")
    for note in catalog.get("verdict_notes", []):
        w("* " + note)
    w("")
    w("## 2. Evidence archive and what was verified")
    w("")
    loc = arch.get("location", {})
    w("| Item | Value |")
    w("| --- | --- |")
    w("| archive id | `%s` |" % arch["id"])
    w("| tarball | `%s`, %s bytes, SHA-256 `%s` |" % (arch["tarball"], arch["tarball_bytes"], arch["tarball_sha256"]))
    w("| members | %s, every one listed with its SHA-256 in `docs/release/evidence/ARCHIVE.sha256` (SHA-256 of that manifest: `%s`) |" % (arch["members"], arch["manifest_sha256"]))
    sup = arch.get("supersedes")
    if sup:
        w("| supersedes | `%s` (tarball `%s`, %s bytes, SHA-256 `%s`, %s members, manifest `%s` with SHA-256 `%s`). The older archive is left unchanged in its own draft release; this archive contains every one of its members with the identical SHA-256, which `--check` proves from the two committed manifests |" % (
            sup["id"], sup["tarball"], sup["tarball_bytes"], sup["tarball_sha256"], sup["members"], sup["manifest"], sup["manifest_sha256"]))
    w("| durable location | %s |" % loc.get("description", "not recorded"))
    w("| read-back | %s |" % arch.get("read_back", "not recorded"))
    w("")
    w("**Verification levels.** `report.py --check` is a **compact-summary verification**: the committed catalog, archive manifest and summaries are consistent with each other (each summary names its raw archive member, that member's SHA-256 and revision, and they equal the manifest and the catalog) and this page is what they produce. It does **not** open the archive. A **full raw-archive audit** (`tests/release/evidence.py stage` then `report.py --audit-archive`) obtains the archive, verifies its tarball digest, size, member list and every member digest, and regenerates every summary from its raw member byte for byte. Pull-request CI performs only the compact verification, because it needs no credential; the full audit needs read access to the archive.")
    w("")
    for note in arch.get("notes", []):
        w("* " + note)
    w("")
    w("## 3. Evidence artifacts (SHA-256 of the raw document, from the archive manifest)")
    w("")
    w("| Artifact | Archived raw file | SHA-256 (raw) | Revision | Produced by |")
    w("| --- | --- | --- | --- | --- |")
    for name, a in catalog["artifacts"].items():
        w("| `%s` | `%s` | `%s` | `%s` | %s |" % (name, a.get("member", "?"), digests.get(name, "MISSING"), (a.get("revision") or "unrecorded")[:12], a["source"]))
    w("")
    w("## 4. Measured values behind the budgets")
    w("")
    w("Budgets (technical-decisions.md 10.2, MB = 10^6 bytes): image <= 60 MB compressed; idle <= 50 MB resident after stabilization (final 60 s of a 300 s observation window after readiness, SQLite initialized, one local Docker endpoint connected); load <= 150 MB resident under 20 clients and 5 streams.")
    w("")
    w("Idle method as applied: RSS (`VmRSS` of the service process, read on the host) is sampled every 5 s from readiness for 300 s; the gated value is the **maximum** of the samples inside the final 60 s (the strictest aggregation; the median is in the archived evidence). The **start-up transient** (its peak and the time until the process stabilizes under 50 MB) is reported in the same cells and as its own check; the idle limit does not apply to it. The 150 MB load budget and the 60 MB image budget are unchanged.")
    w("")
    w("| Environment (artifact) | Host | Compressed image | Idle after first start | Idle configured | Idle after restart | Load |")
    w("| --- | --- | --- | --- | --- | --- | --- |")
    for r in measured_table(evdir, catalog):
        w("| `%s` | %s |" % (r[0], " | ".join(x.replace("|", "\\|") for x in r[1:])))
    w("")
    w("## 5. Criteria")
    w("")
    groups = []
    for r in rows:
        if r["group"] not in groups:
            groups.append(r["group"])
    for g in groups:
        w("### " + g)
        w("")
        w("| ID | Criterion | Status | Linked results (artifact digest prefix) | Limits |")
        w("| --- | --- | --- | --- | --- |")
        for r in [x for x in rows if x["group"] == g]:
            links = "<br>".join("%s `%s` %s" % ("✔" if l["link"] == "PASS" else ("✘" if l["link"] == "FAIL" else "?"), l["ref"].split("@")[0] + "@" + l["ref"].split("@")[1], (l["digest"] or "no digest")[:12]) for l in r["links"]) or "none"
            lim = (r.get("limits") or "")
            by_ref = {a["ref"]: a for a in r["adverse_links"]}
            for adv in adverse_groups(r):
                lim += (" " if lim else "") + "Adverse runs (%s): %s. %s" % (
                    adv.get("state", "open"), ", ".join("%s %s (%s)" % (a["ref"], a["result"], (a["digest"] or "no digest")[:12]) for a in (by_ref[x] for x in adv.get("refs", []))),
                    adv.get(CLOSING_TEXT.get(adv.get("state", ""), "disposition"), ""))
            status = "PASS WITH DISCLOSURES" if r.get("disclosed") else r["status"]
            w("| %s | %s | **%s** | %s | %s |" % (r["id"], r["text"].replace("|", "\\|"), status, links, lim.replace("|", "\\|")))
        w("")
    dispositions = catalog.get("dispositions", [])
    remediations = catalog.get("remediations", [])
    if dispositions or remediations:
        w("## 6. Owner-approved dispositions" + (" and remediated adverse results" if remediations else ""))
        w("")
    if dispositions:
        w("A disposition changes how an adverse result is **classified**; it does not rewrite the result. The historical adverse runs stay FAIL in the archive and above. Each disposition states what it does not claim.")
        w("")
        for d in dispositions:
            w("### %s - %s" % (d["id"], d["title"]))
            w("")
            w("* **Decision:** " + d["decision"])
            w("* **Approved by:** " + d["approved_by"])
            w("* **Reference:** " + d["reference"])
            for k, label in (("kept_visible", "Kept visible"), ("not_claimed", "Not claimed"), ("residual_risk", "Residual risk")):
                if d.get(k):
                    w("* **%s:** %s" % (label, d[k]))
            w("")
    if remediations:
        w("A remediation is **not** an owner decision: a defect found by review was fixed (in the product, or, where the entry says so, in the test harness), a regression test pins the fix, and fresh evidence of the affected criteria passes. The adverse run is not rewritten (it stays FAIL in the archive and in the criteria that list it); only its effect on the criteria changes, and only because the criterion's own fresh checks pass. Each remediation states what it does not establish.")
        w("")
        for d in remediations:
            w("### %s - %s" % (d["id"], d["title"]))
            w("")
            w("* **Adverse run:** " + d["adverse_run"])
            w("* **Finding and cause:** " + d["finding"])
            w("* **Fix:** " + d["fix"])
            w("* **Regression tests:** " + d["tests"])
            w("* **Fresh evidence:** " + d["fresh_evidence"])
            for k, label in (("not_established", "Not established"), ("reference", "Reference")):
                if d.get(k):
                    w("* **%s:** %s" % (label, d[k]))
            w("")
    pub = catalog.get("publication")
    if pub:
        w("## 7. Registry publication")
        w("")
        w(pub["status"])
        w("")
        for line in pub.get("details", []):
            w("* " + line)
        w("")
    if catalog.get("findings"):
        w("## 8. Findings recorded by this run")
        w("")
        w("These are observations made while producing the evidence. They are not criteria and are not hidden by the verdict above; each names where it is evidenced and what it needs.")
        w("")
        for f in catalog["findings"]:
            w("### %s - %s" % (f["id"], f["title"]))
            w("")
            w(f["detail"])
            w("")
    return "\n".join(L) + "\n"


def build(evdir, criteria_path):
    problems = verify_sums(evdir) + evidence.verify_compact(evdir)
    if problems:
        raise SystemExit("evidence is not consistent: " + "; ".join(problems[:5]))
    catalog, results, digests, meta = load_evidence(evdir)
    with open(criteria_path) as fh:
        criteria = json.load(fh)["criteria"]
    rows = evaluate(criteria, results, digests, results)
    return catalog, rows, digests, meta, results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--criteria", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--check", action="store_true", help="compact verification: fail when --out differs from what the compact evidence produces")
    ap.add_argument("--audit-archive", metavar="STAGED", help="also run the FULL audit of the archive staged by `evidence.py stage`")
    a = ap.parse_args()
    if a.audit_archive:
        problems, counts = evidence.audit_archive(a.evidence, a.audit_archive)
        if problems:
            for p in problems[:20]:
                print("AUDIT FAILED: " + p, file=sys.stderr)
            return 1
        print("FULL ARCHIVE AUDIT PASSED: %(members_verified)d members verified against ARCHIVE.sha256, %(summaries_regenerated)d summaries regenerated from the raw members" % counts)
    catalog, rows, digests, meta, results = build(a.evidence, a.criteria)
    text = render(catalog, rows, digests, meta, results, a.evidence)
    ok, n = verdict(rows)
    state = overall(rows, catalog)
    if a.check:
        have = None
        if os.path.exists(a.out):
            with open(a.out) as fh:
                have = fh.read()
        if have != text:
            print("STALE: %s does not match the committed evidence" % a.out, file=sys.stderr)
            return 1
        print("report consistent (compact-summary verification; the raw archive was %s): %s - %s (%d PASS, %d FAIL, %d UNVERIFIED)" % (
            "audited above" if a.audit_archive else "NOT read", a.out, state, n["PASS"], n["FAIL"], n["UNVERIFIED"]))
        return 0
    with open(a.out, "w") as fh:
        fh.write(text)
    print("wrote %s: %s (%d PASS, %d FAIL, %d UNVERIFIED)" % (a.out, state, n["PASS"], n["FAIL"], n["UNVERIFIED"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
