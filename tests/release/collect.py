#!/usr/bin/env python3
"""Turn the raw output of the release gates into a `results` document (standard library only) that report.py can link.

Nothing is "assumed": every status is computed from the recorded process exit codes AND from what the raw output
actually says, so a gate that exited 0 without producing the evidence it exists to produce (no test lines, no scan
results, an empty SBOM, one colour scheme only) is FAIL, not PASS. A step that was not run has no entry at all, which
report.py reports as UNVERIFIED.

    collect.py gates    --in DIR --out FILE   gates.tsv + web.tsv (+ the logs next to them)
    collect.py browsers --in DIR --out FILE   browsers.tsv (+ one go test -v log per engine/viewport)
    collect.py jobs     --in FILE --out FILE   the jobs document of one hosted workflow run
    collect.py scan     --trivy FILE --sbom FILE --version FILE --out FILE --arch NAME
"""
import argparse
import json
import os
import re
import sys

ENGINES = ("chromium", "firefox", "webkit")
SUBTEST = re.compile(r"^\s*--- (PASS|FAIL|SKIP): (Test\w+)/(\w+)/([^/\s]+)/(light|dark)\b")
TOPLEVEL = re.compile(r"^--- (PASS|FAIL|SKIP): (Test\w+)\b")


def rows(path):
    out = {}
    if not os.path.exists(path):
        return out
    for ln in open(path):
        p = ln.rstrip("\n").split("\t")
        if len(p) == 3:
            out[p[0]] = (int(p[1]), int(p[2]))
    return out


def read(path):
    try:
        with open(path, errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def result(i, ok, detail):
    return {"id": i, "status": "PASS" if ok else "FAIL", "detail": detail}


def parse_gotest(text):
    ok_pkgs = len(re.findall(r"^ok\s+\S+", text, re.M))
    failed = len(re.findall(r"^(FAIL|--- FAIL|panic:)", text, re.M))
    return ok_pkgs, failed


def parse_vitest(text):
    m = re.search(r"Tests\s+(\d+) passed \((\d+)\)", text)
    files = re.search(r"Test Files\s+(\d+) passed \((\d+)\)", text)
    failed = re.search(r"\b(\d+) failed\b", text)
    return (int(m.group(1)) if m else 0, int(m.group(2)) if m else 0, int(files.group(1)) if files else 0, bool(failed))


def npm_high_critical(text):
    try:
        v = json.loads(text)["metadata"]["vulnerabilities"]
        return int(v.get("high", 0)) + int(v.get("critical", 0)), sum(int(x) for x in v.values())
    except (ValueError, KeyError, TypeError):
        return None, None


def gates(d):
    g, w = rows(os.path.join(d, "gates.tsv")), rows(os.path.join(d, "web.tsv"))
    res = []

    def rc(name, table, ident, what):
        if name not in table:
            return None
        code, secs = table[name]
        r = result(ident, code == 0, "%s: exit %d in %d s" % (what, code, secs))
        res.append(r)
        return code == 0

    rc("gofmt", g, "GATE-GOFMT", "gofmt -l over cmd internal web tests/{security,adapters,release}")
    rc("govet", g, "GATE-GOVET", "go vet ./...")
    rc("gomodverify", g, "GATE-GOMOD-VERIFY", "go mod verify")
    rc("golangci", g, "GATE-GOLANGCI", "pinned golangci-lint run ./...")
    rc("gosec", g, "GATE-GOSEC", "pinned gosec ./...")
    if "govulncheck" in g:
        txt = read(os.path.join(d, "govulncheck.log"))
        res.append(result("GATE-GOVULNCHECK", g["govulncheck"][0] == 0 and "No vulnerabilities found" in txt, "pinned govulncheck ./... (reachability-based): exit %d; says %r" % (g["govulncheck"][0], "No vulnerabilities found" if "No vulnerabilities found" in txt else txt.strip()[-120:])))
    if "gotest-short" in g:
        pk, bad = parse_gotest(read(os.path.join(d, "gotest-short.log")))
        res.append(result("GATE-GOTEST", g["gotest-short"][0] == 0 and pk >= 15 and bad == 0, "go test -count=1 ./cmd/... ./internal/... ./tests/...: exit %d, %d packages ok, %d failures" % (g["gotest-short"][0], pk, bad)))
    rc("releasepytest", g, "GATE-RELEASE-HARNESS-TESTS", "tests/release/test_release.py (hermetic harness tests)")
    rc("imagepytest", g, "GATE-ISOLATION-TESTS", "tests/image/test_isolation.py (isolation guard tests)")
    rc("ci-budget", g, "GATE-CI-BUDGET", "node --test scripts/ci-budget.test.mjs")
    rc("typecheck", w, "GATE-WEB-TYPECHECK", "tsc --noEmit")
    rc("eslint", w, "GATE-WEB-LINT", "eslint --max-warnings 0")
    if "vitest" in w:
        n, total, files, failed = parse_vitest(read(os.path.join(d, "vitest.log")))
        res.append(result("GATE-WEB-VITEST", w["vitest"][0] == 0 and n > 0 and n == total and not failed, "vitest run: exit %d, %d/%d tests passed in %d files" % (w["vitest"][0], n, total, files)))
    if "npm-audit" in w:
        hc, total = npm_high_critical(read(os.path.join(d, "npm-audit.json")))
        res.append(result("GATE-NPM-AUDIT", w["npm-audit"][0] == 0 and hc == 0, "npm audit --audit-level=high: exit %d; high+critical %s of %s advisories" % (w["npm-audit"][0], hc, total)))
    return {"results": res}


def browsers(d):
    t = rows(os.path.join(d, "browsers.tsv"))
    res = []
    for name, (code, secs) in sorted(t.items()):
        text = read(os.path.join(d, name + ".log"))
        lines = text.splitlines()
        sub = [m.groups() for m in (SUBTEST.match(ln) for ln in lines) if m]
        top = [m.groups() for m in (TOPLEVEL.match(ln) for ln in lines) if m]
        passed = [s for s in sub if s[0] == "PASS"]
        badsub = [s for s in sub if s[0] != "PASS"] + [x for x in top if x[0] != "PASS"]
        schemes = {s[4] for s in passed}
        engine = name.split("-")[0]
        engines = {s[2] for s in passed}
        tests = {s[1] for s in passed}
        ok = code == 0 and not badsub and schemes == {"light", "dark"} and engine in engines and len(passed) >= 6 and {"TestAdminUIBrowser", "TestSecurityUIBrowser"} <= tests
        res.append(result("GATE-BROWSER-" + name, ok, "go test -tags=webauthnbrowser (%s): exit %d in %d s; %d scenario/scheme subtests passed on %s; schemes %s; failed/skipped %d" % (name, code, secs, len(passed), sorted(engines), sorted(schemes), len(badsub))))
    return {"results": res}


def scan(trivy_path, sbom_path, version_path, arch):
    res = []
    try:
        tr = json.load(open(trivy_path))
    except (OSError, ValueError):
        tr = None
    if tr is None or not isinstance(tr.get("Results"), list) or not tr["Results"]:
        res.append(result("SCAN-TRIVY-" + arch, False, "no Trivy results document: a scanner failure is not a pass"))
    else:
        vulns = [v for r in tr["Results"] for v in (r.get("Vulnerabilities") or []) if v.get("Severity") in ("HIGH", "CRITICAL")]
        targets = [r.get("Target") for r in tr["Results"]]
        res.append(result("SCAN-TRIVY-" + arch, not vulns, "%s; %d result target(s) scanned (%s); HIGH/CRITICAL findings: %d%s" % (read(version_path).strip().splitlines()[0] if read(version_path) else "version unrecorded", len(targets), ", ".join(map(str, targets))[:160], len(vulns), (" -> " + ", ".join(sorted({v.get("VulnerabilityID", "?") for v in vulns}))[:200]) if vulns else "")))
    try:
        sb = json.load(open(sbom_path))
        comps = sb.get("components") or []
        ok = sb.get("bomFormat") == "CycloneDX" and len(comps) > 0
        res.append(result("SCAN-SBOM-" + arch, ok, "%s %s, %d components" % (sb.get("bomFormat"), sb.get("specVersion"), len(comps))))
    except (OSError, ValueError):
        res.append(result("SCAN-SBOM-" + arch, False, "no SBOM document"))
    return {"results": res}


def jobs(path):
    """Hosted CI: the jobs API document of one workflow run (`gh api repos/.../actions/runs/ID/jobs`). A job counts only when it
    completed with conclusion `success`; skipped, cancelled, neutral and in-progress jobs are FAIL, never a pass."""
    try:
        doc = json.load(open(path))
        js = doc["jobs"]
    except (OSError, ValueError, KeyError, TypeError):
        return {"results": [result("HOSTED-JOBS", False, "no jobs document")]}
    res = []
    for j in js:
        ok = j.get("status") == "completed" and j.get("conclusion") == "success" and bool(j.get("steps")) and all(s.get("conclusion") == "success" for s in j["steps"] if s.get("conclusion") != "skipped")
        res.append(result("HOSTED-" + re.sub(r"[^A-Za-z0-9.]+", "-", j.get("name", "?")).strip("-"), ok, "%s: %s/%s" % (j.get("name"), j.get("status"), j.get("conclusion"))))
    if not res:
        res.append(result("HOSTED-JOBS", False, "the run has no jobs"))
    return {"results": res}


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    for n in ("gates", "browsers"):
        s = sp.add_parser(n)
        s.add_argument("--in", dest="inp", required=True)
        s.add_argument("--out", required=True)
    s = sp.add_parser("jobs")
    s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--out", required=True)
    s = sp.add_parser("scan")
    s.add_argument("--trivy", required=True)
    s.add_argument("--sbom", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--arch", required=True)
    s.add_argument("--out", required=True)
    a = ap.parse_args()
    doc = gates(a.inp) if a.cmd == "gates" else browsers(a.inp) if a.cmd == "browsers" else jobs(a.inp) if a.cmd == "jobs" else scan(a.trivy, a.sbom, a.version, a.arch)
    with open(a.out, "w") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")
    bad = [r["id"] for r in doc["results"] if r["status"] != "PASS"]
    print("%s: %d results, %d not PASS%s" % (a.cmd, len(doc["results"]), len(bad), (" " + str(bad)) if bad else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
