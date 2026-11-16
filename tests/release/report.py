#!/usr/bin/env python3
"""Versioned release acceptance report of P1.20 (standard library only).

Every release criterion names the concrete results that establish it ("CHECK-ID@artifact"), where each artifact is
a committed evidence file whose SHA-256 is computed here, never typed in. A criterion is

  PASS        every linked result is PASS and every linked artifact exists with a digest
  FAIL        at least one linked result is FAIL
  UNVERIFIED  anything else: no link at all, a link with no result, a BLOCKED/skipped result, an artifact without a
              digest. A missing target, browser or architecture can therefore never count as a pass.

A criterion may also name sealed ADVERSE runs (`adverse.refs`, "CHECK@diagnostics/<file>.json": failed or contradictory runs that are kept
in the evidence). While `adverse.state` is "open", a FAIL among them fails the criterion whatever the final run says; it stops counting only when a
reviewed change sets the state to "dispositioned" and records the disposition (cause established, product/fixture/harness) in `adverse.disposition`.
A clean final run therefore never erases a contradictory same-content failure.

The overall verdict is "ACCEPTED" only when every criterion is PASS. `--check` recomputes the report from the
committed evidence and fails when the committed markdown is stale or was edited by hand (tests/release/
test_report_consistency.py runs it in CI).

    python3 tests/release/report.py --evidence docs/release/evidence --criteria tests/release/criteria.json --out docs/release/phase1-release-acceptance.md [--check]
"""
import argparse
import hashlib
import json
import os
import sys

ORDER = {"FAIL": 0, "UNVERIFIED": 1, "PASS": 2}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


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
        adv = c.get("adverse") or {}
        adverse_links = []
        for ref in adv.get("refs", []):
            res = (adverse or {}).get(ref)
            adverse_links.append({"ref": ref, "result": res or "none", "digest": digests.get(ref.rsplit("@", 1)[1] if "@" in ref else "")})
            if adv.get("state") != "dispositioned" and res != "PASS" and ORDER["FAIL" if res == "FAIL" else "UNVERIFIED"] < ORDER[status]:
                status = "FAIL" if res == "FAIL" else "UNVERIFIED"
        rows.append(dict(c, status=status, links=links, adverse_links=adverse_links))
    return rows


def verify_sums(evdir):
    """Every committed evidence file (raw logs included) is listed in SHA256SUMS with its digest, so an edited log is detected even when it
    is not one of the linked results files. Returns a list of problems (empty = consistent)."""
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
            rel = os.path.relpath(os.path.join(root, fn), evdir)
            if rel != "SHA256SUMS":
                on_disk.add(rel)
    problems += ["not listed: " + n for n in sorted(on_disk - set(listed))]
    return problems


def load_adverse(evdir, criteria):
    """Results of the sealed adverse runs a criterion names: ({"CHECK@file": status}, {file: sha256}). A missing file stays unlinked (UNVERIFIED)."""
    res, dig = {}, {}
    for c in criteria:
        for ref in (c.get("adverse") or {}).get("refs", []):
            check, _, rel = ref.partition("@")
            path = os.path.join(evdir, rel)
            if not rel or not os.path.exists(path):
                continue
            dig[rel] = sha256_file(path)
            with open(path) as fh:
                doc = json.load(fh)
            for r in doc.get("results", []):
                if r.get("id") == check:
                    res[ref] = r.get("status")
    return res, dig


def load_evidence(evdir):
    with open(os.path.join(evdir, "manifest.json")) as fh:
        manifest = json.load(fh)
    results, digests, meta = {}, {}, {}
    for name, a in manifest["artifacts"].items():
        path = os.path.join(evdir, a["file"])
        if not os.path.exists(path):
            continue
        digests[name] = sha256_file(path)
        meta[name] = a
        if a["kind"] == "results":
            with open(path) as fh:
                doc = json.load(fh)
            for r in doc.get("results", []):
                results["%s@%s" % (r["id"], name)] = r["status"]
    return manifest, results, digests, meta


def mb(v):
    return "%.2f MB (%d B)" % (v / 1e6, v) if isinstance(v, (int, float)) and not isinstance(v, bool) else "not measured"


def measured_table(evdir, manifest):
    """The measured values behind the budget criteria, read from the committed harness results (never typed). Missing values read 'not measured'."""
    rows = []
    for name, a in manifest["artifacts"].items():
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


def render(manifest, rows, digests, meta, results, evdir):
    ok, n = verdict(rows)
    L = []
    w = L.append
    w("# Phase 1 release acceptance, security and footprint report (P1.20)")
    w("")
    w("> Generated by `tests/release/report.py` from the committed files in `docs/release/evidence/`; `python3 tests/release/report.py --check` fails when this page is stale or edited by hand.")
    w("> This is acceptance evidence for one release candidate. It is **not** a NIST, FIPS, product-qualification or runtime-compatibility claim, and it does not authorize a merge or a deployment (Nico alone merges).")
    w("")
    w("## 1. Verdict")
    w("")
    rc = manifest["release_candidate"]
    w("| Item | Value |")
    w("| --- | --- |")
    for k, v in rc.items():
        w("| %s | %s |" % (k.replace("_", " "), v))
    w("")
    w("**Overall: %s.** %d criteria: %d PASS, %d FAIL, %d UNVERIFIED. A criterion with no linked result, a skipped/BLOCKED result or an artifact without a digest is UNVERIFIED and never counts as a pass." % (
        "ACCEPTED" if ok else "NOT ACCEPTED", len(rows), n["PASS"], n["FAIL"], n["UNVERIFIED"]))
    w("")
    for note in manifest.get("verdict_notes", []):
        w("* " + note)
    w("")
    w("## 2. Evidence artifacts (SHA-256 computed from the committed files)")
    w("")
    w("| Artifact | File | SHA-256 | Produced by |")
    w("| --- | --- | --- | --- |")
    for name, a in manifest["artifacts"].items():
        w("| `%s` | `%s` | `%s` | %s |" % (name, a["file"], digests.get(name, "MISSING"), a["source"]))
    w("")
    w("## 3. Measured values behind the budgets")
    w("")
    w("Budgets (technical-decisions.md 10.2, MB = 10^6 bytes): image <= 60 MB compressed; idle <= 50 MB resident after stabilization (final 60 s of a 300 s observation window after readiness, SQLite initialized, one local Docker endpoint connected); load <= 150 MB resident under 20 clients and 5 streams.")
    w("")
    w("Idle method as applied: RSS (`VmRSS` of the service process, read on the host) is sampled every 5 s from readiness for 300 s; the gated value is the **maximum** of the samples inside the final 60 s (the strictest aggregation; the median is in the evidence). The **start-up transient** (its peak and the time until the process stabilizes under 50 MB) is reported in the same cells and as its own check; the idle limit does not apply to it. The 150 MB load budget and the 60 MB image budget are unchanged.")
    w("")
    w("| Environment (artifact) | Host | Compressed image | Idle after first start | Idle configured | Idle after restart | Load |")
    w("| --- | --- | --- | --- | --- | --- | --- |")
    for r in measured_table(evdir, manifest):
        w("| `%s` | %s |" % (r[0], " | ".join(x.replace("|", "\\|") for x in r[1:])))
    w("")
    w("## 4. Criteria")
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
            adv = r.get("adverse") or {}
            if adv:
                lim += (" " if lim else "") + "Sealed adverse runs (%s): %s. %s" % (
                    adv.get("state", "open"), ", ".join("%s %s" % (a["ref"], a["result"]) for a in r["adverse_links"]), adv.get("disposition", ""))
            w("| %s | %s | **%s** | %s | %s |" % (r["id"], r["text"].replace("|", "\\|"), r["status"], links, lim.replace("|", "\\|")))
        w("")
    if manifest.get("findings"):
        w("## 5. Findings recorded by this run")
        w("")
        w("These are observations made while producing the evidence. They are not criteria and are not hidden by the verdict above; each names where it is evidenced and what it needs.")
        w("")
        for f in manifest["findings"]:
            w("### %s - %s" % (f["id"], f["title"]))
            w("")
            w(f["detail"])
            w("")
    return "\n".join(L) + "\n"


def build(evdir, criteria_path):
    problems = verify_sums(evdir)
    if problems:
        raise SystemExit("evidence is not consistent with SHA256SUMS: " + "; ".join(problems[:5]))
    manifest, results, digests, meta = load_evidence(evdir)
    with open(criteria_path) as fh:
        criteria = json.load(fh)["criteria"]
    adverse, adverse_digests = load_adverse(evdir, criteria)
    digests = dict(digests, **adverse_digests)
    rows = evaluate(criteria, results, digests, adverse)
    return manifest, rows, digests, meta, results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--criteria", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--check", action="store_true", help="fail when --out differs from what the evidence produces")
    a = ap.parse_args()
    manifest, rows, digests, meta, results = build(a.evidence, a.criteria)
    text = render(manifest, rows, digests, meta, results, a.evidence)
    ok, n = verdict(rows)
    if a.check:
        have = None
        if os.path.exists(a.out):
            with open(a.out) as fh:
                have = fh.read()
        if have != text:
            print("STALE: %s does not match the committed evidence" % a.out, file=sys.stderr)
            return 1
        print("report consistent: %s (%d PASS, %d FAIL, %d UNVERIFIED)" % (a.out, n["PASS"], n["FAIL"], n["UNVERIFIED"]))
        return 0
    with open(a.out, "w") as fh:
        fh.write(text)
    print("wrote %s: %s (%d PASS, %d FAIL, %d UNVERIFIED)" % (a.out, "ACCEPTED" if ok else "NOT ACCEPTED", n["PASS"], n["FAIL"], n["UNVERIFIED"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
