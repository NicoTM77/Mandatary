#!/usr/bin/env python3
"""Hermetic contract tests (standard library only, no network) of the dev-image publication wiring in .github/workflows/ci.yml.

The workflow is read as text (no YAML library is assumed on a runner). The `publish` job's `if:` is NOT merely grepped: a small evaluator of
the GitHub expression subset the workflow uses (contexts, == != ! && || and parentheses; string comparison is case-insensitive as in GitHub)
evaluates it for every event, ref, repository and needed-job result below, so a loosened condition fails a scenario, not a regex.

    python3 tests/publish/test_workflow.py
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import publish_dev_image as pub  # noqa: E402


def read(rel):
    with open(os.path.join(ROOT, rel)) as fh:
        return fh.read()


WORKFLOW = read(".github/workflows/ci.yml")


def split_jobs(text):
    """{job id: block text} for the top-level jobs (two-space-indented keys under `jobs:`); comment lines belong to the job that follows."""
    body = text.split("\njobs:\n", 1)[1]
    jobs, cur, buf = {}, None, []
    for line in body.split("\n"):
        if re.match(r"^  #", line):
            continue  # a job-level comment block (it documents the job that follows; it is not job configuration)
        m = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", line)
        if m:
            if cur:
                jobs[cur] = "\n".join(buf)
            cur, buf = m.group(1), []
        elif cur:
            buf.append(line)
    if cur:
        jobs[cur] = "\n".join(buf)
    return jobs


JOBS = split_jobs(WORKFLOW)


def job_key(block, key):
    """The value of a four-space-indented key of a job block (single line)."""
    m = re.search(r"^    %s: (.*)$" % re.escape(key), block, re.M)
    return m.group(1).strip() if m else None


def job_if(block):
    value = job_key(block, "if")
    m = re.match(r"^\$\{\{ (.*) \}\}$", value or "")
    return m.group(1) if m else value


def step_ifs(block):
    return re.findall(r"^        if: (.*)$", block, re.M)


# ------------------------------------------------------------------------------------------------------------ a GitHub expression subset

TOKEN = re.compile(r"\s*(?:(&&|\|\||==|!=|!|\(|\))|'((?:[^']|'')*)'|([A-Za-z_][A-Za-z0-9_.-]*))")


class Expr:
    """Evaluates the expression subset used by the workflow. Unknown functions or syntax raise, so a new construct cannot slip through."""

    def __init__(self, text, ctx, status="success"):
        self.toks, i = [], 0
        while i < len(text):
            if not text[i:].strip():
                break
            m = TOKEN.match(text, i)
            if not m:
                raise ValueError("cannot parse %r at %r" % (text, text[i:i + 12]))
            if m.group(1):
                self.toks.append(("op", m.group(1)))
            elif m.group(2) is not None:
                self.toks.append(("str", m.group(2).replace("''", "'")))
            else:
                self.toks.append(("id", m.group(3)))
            i = m.end()
        self.pos, self.ctx, self.status = 0, ctx, status

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def take(self):
        if self.pos >= len(self.toks):
            raise ValueError("unexpected end of expression")
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def run(self):
        v = self.or_()
        if self.pos != len(self.toks):
            raise ValueError("trailing tokens")
        return bool(v)

    def or_(self):
        v = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            r = self.and_()
            v = v or r
        return v

    def and_(self):
        v = self.eq()
        while self.peek() == ("op", "&&"):
            self.take()
            r = self.eq()
            v = v and r
        return v

    def eq(self):
        v = self.not_()
        while self.peek() in (("op", "=="), ("op", "!=")):
            op = self.take()[1]
            r = self.not_()
            same = (str(v).lower() == str(r).lower()) if (v is not None and r is not None) else (v is None and r is None)
            v = same if op == "==" else not same
        return v

    def not_(self):
        if self.peek() == ("op", "!"):
            self.take()
            return not self.not_()
        return self.primary()

    def primary(self):
        kind, val = self.take()
        if kind == "op" and val == "(":
            v = self.or_()
            if self.take() != ("op", ")"):
                raise ValueError("missing )")
            return v
        if kind == "str":
            return val
        if kind == "id":
            if self.peek() == ("op", "("):  # a function call: only the status functions are known
                self.take()
                if self.take() != ("op", ")"):
                    raise ValueError("function with arguments is not supported: " + val)
                if val == "success":
                    return self.status == "success"
                if val == "always":
                    return True
                if val == "cancelled":
                    return self.status == "cancelled"
                if val == "failure":
                    return self.status == "failure"
                raise ValueError("unsupported function " + val)
            if val in ("true", "false"):
                return val == "true"
            if val == "null":
                return None
            return self.ctx.get(val)
        raise ValueError("unexpected token")


def evaluate_job_if(block, ctx, needs_results):
    """Would GitHub start this job? The condition is combined with the implicit success() when it names no status function."""
    expr = job_if(block)
    status = "success" if all(r == "success" for r in needs_results.values()) else "failure"
    if expr is None:
        return status == "success"
    named = re.search(r"\b(success|always|cancelled|failure)\(\)", expr)
    ok = Expr(expr, ctx, status).run()
    return ok if named else (ok and status == "success")


def context(event="push", ref="refs/heads/main", repo="NicoTM77/Mandatary", needs=None):
    ctx = {"github.event_name": event, "github.ref": ref, "github.repository": repo}
    for job, result in (needs or {}).items():
        ctx["needs.%s.result" % job] = result
    return ctx


PUBLISH = JOBS["publish"]
OTHERS = [j for j in JOBS if j != "publish"]
ALL_SUCCESS = {j: "success" for j in OTHERS}


class Trigger(unittest.TestCase):
    def test_the_publish_job_runs_for_a_successful_push_to_main_of_the_canonical_repository(self):
        self.assertTrue(evaluate_job_if(PUBLISH, context(needs=ALL_SUCCESS), ALL_SUCCESS))

    def test_it_never_runs_for_another_event_ref_or_repository(self):
        cases = {
            "same-repository pull request": context("pull_request", "refs/pull/25/merge"),
            "pull request targeting main": context("pull_request", "refs/heads/main"),
            "pull_request_target": context("pull_request_target", "refs/heads/main"),
            "manual run on main": context("workflow_dispatch", "refs/heads/main"),
            "manual run on a branch": context("workflow_dispatch", "refs/heads/feature"),
            "scheduled run": context("schedule", "refs/heads/main"),
            "branch push": context("push", "refs/heads/mandatary/t_836268ff-p1.20"),
            "a branch that only starts with main": context("push", "refs/heads/main-hotfix"),
            "tag push": context("push", "refs/tags/v1.0.0"),
            "tag named main": context("push", "refs/tags/main"),
            "push to main of a fork": context("push", "refs/heads/main", "someone/Mandatary"),
            "push to main of a lookalike repository": context("push", "refs/heads/main", "NicoTM77/Mandatary-fork"),
        }
        for name, ctx in cases.items():
            with self.subTest(name):
                ctx.update({"needs.%s.result" % j: "success" for j in OTHERS})
                self.assertFalse(evaluate_job_if(PUBLISH, ctx, ALL_SUCCESS), name)

    def test_a_failed_cancelled_skipped_or_missing_gate_keeps_it_from_running(self):
        for job in OTHERS:
            for bad in ("failure", "cancelled", "skipped", "neutral", None):
                with self.subTest(job=job, result=bad):
                    needs = dict(ALL_SUCCESS)
                    if bad is None:
                        del needs[job]
                    else:
                        needs[job] = bad
                    self.assertFalse(evaluate_job_if(PUBLISH, context(needs=needs), needs))

    def test_the_condition_does_not_hide_behind_an_always_or_a_status_override(self):
        expr = job_if(PUBLISH)
        self.assertNotRegex(expr, r"always\(\)|cancelled\(\)|failure\(\)")
        self.assertNotRegex(expr, r"\|\|")  # a single conjunction: nothing offers a second way in

    def test_the_condition_evaluator_itself_rejects_what_it_does_not_know(self):
        with self.assertRaises(ValueError):
            Expr("contains(github.ref, 'main')", {}).run()
        with self.assertRaises(ValueError):
            Expr("github.ref ==", {"github.ref": "x"}).run()

    def test_the_workflow_triggers_are_the_expected_ones_only(self):
        on = WORKFLOW.split("\npermissions:", 1)[0]
        self.assertRegex(on, r"(?m)^  pull_request:\s*$")
        self.assertRegex(on, r"(?m)^  push:\n    branches: \[main\]$")
        self.assertRegex(on, r"(?m)^  workflow_dispatch:\s*$")
        self.assertNotRegex(on, r"pull_request_target|tags:|schedule|workflow_run|release:|repository_dispatch")


class Needs(unittest.TestCase):
    def test_publish_depends_on_every_other_job_of_the_workflow(self):
        needs = job_key(PUBLISH, "needs")
        listed = set(re.findall(r"[a-z][a-z0-9-]*", needs.strip("[]")))
        self.assertEqual(listed, set(OTHERS))  # a gate added later must be added here too, or this test fails
        self.assertIn("image", listed)  # both architectures: one matrix job covering linux/amd64 and linux/arm64
        self.assertIn("storage-arm64", listed)
        for j in OTHERS:
            self.assertIn("needs.%s.result == 'success'" % j, job_if(PUBLISH))

    def test_the_image_job_covers_both_architectures_on_native_runners(self):
        image = JOBS["image"]
        self.assertRegex(image, r"platform: linux/amd64\n\s+runner: ubuntu-24\.04\n")
        self.assertRegex(image, r"platform: linux/arm64\n\s+runner: ubuntu-24\.04-arm\n")

    def test_the_security_aggregation_is_unchanged(self):
        sec = JOBS["security"]
        self.assertEqual(job_key(sec, "needs"), "[baseline, negative-control, image]")
        self.assertEqual(job_key(sec, "if"), "${{ always() }}")


class Permissions(unittest.TestCase):
    def test_the_workflow_default_and_every_other_job_stay_read_only(self):
        top = WORKFLOW.split("\njobs:\n", 1)[0]
        self.assertRegex(top, r"(?m)^permissions:\n  contents: read\n(?!  )")
        for name, block in JOBS.items():
            if name != "publish":
                self.assertNotRegex(block, r"(?m)^    permissions:", name)
                self.assertNotRegex(block, r"packages|id-token|write", name)

    def test_only_the_publish_job_has_package_write_and_nothing_wider(self):
        m = re.search(r"(?m)^    permissions:\n((?:      .*\n)+)", PUBLISH)
        self.assertIsNotNone(m)
        perms = dict(re.findall(r"^      ([a-z-]+): (\w+)$", m.group(1), re.M))
        self.assertEqual(perms, {"contents": "read", "packages": "write"})
        self.assertEqual(len(re.findall(r"packages: write", WORKFLOW)), 1)

    def test_the_credential_and_the_registry_are_only_touched_inside_the_publish_job(self):
        outside = "\n".join(b for n, b in JOBS.items() if n != "publish") + WORKFLOW.split("\njobs:\n", 1)[0]
        for forbidden in ("GITHUB_TOKEN", "secrets.", "docker login", "ghcr.io/nicotm77", "publish_dev_image.py publish", "publish_dev_image.py gate", "--password"):
            self.assertNotIn(forbidden, re.sub(r"(?m)^\s*#.*$", "", outside), forbidden)
        self.assertEqual(len(re.findall(r"secrets\.GITHUB_TOKEN", WORKFLOW)), 1)
        self.assertNotRegex(WORKFLOW, r"(?i)\bPAT\b|personal.access|secrets\.(?!GITHUB_TOKEN)")

    def test_no_job_checks_out_with_persisted_credentials_or_a_pull_request_head(self):
        self.assertNotIn("persist-credentials: true", WORKFLOW)
        self.assertNotRegex(WORKFLOW, r"github\.event\.pull_request\.head|github\.head_ref")
        for name, block in JOBS.items():
            for m in re.finditer(r"uses: actions/checkout@\S+\n\s+with:\n((?:\s+.+\n)+)", block + "\n"):
                self.assertIn("persist-credentials: false", m.group(1), name)


class Steps(unittest.TestCase):
    def test_the_tested_image_is_kept_only_for_a_push_to_main_and_only_in_the_image_job(self):
        image = JOBS["image"]
        guarded = re.findall(r"- name: Keep the tested image for promotion \(main push only\)\n\s+if: (.+)\n", image)
        self.assertEqual(guarded, ["${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"])
        up = re.search(r"- uses: actions/upload-artifact@\S+ # v4\n\s+if: (.+)\n\s+with:\n\s+name: tested-image-", image)
        self.assertIsNotNone(up)
        self.assertEqual(up.group(1), guarded[0])
        for event, ref, expect in (("push", "refs/heads/main", True), ("pull_request", "refs/pull/1/merge", False), ("push", "refs/heads/x", False),
                                   ("workflow_dispatch", "refs/heads/main", False), ("push", "refs/tags/v1", False)):
            e = re.match(r"^\$\{\{ (.*) \}\}$", guarded[0]).group(1)
            self.assertEqual(Expr(e, context(event, ref)).run(), expect, (event, ref))
        for name, block in JOBS.items():
            if name not in ("image", "publish"):
                self.assertNotIn("tested-image", block, name)

    def test_the_promoted_artifact_is_the_one_the_image_job_kept_and_publish_runs_the_script_without_overrides(self):
        self.assertIn("pattern: tested-image-*", PUBLISH)
        self.assertRegex(PUBLISH, r"actions/download-artifact@[0-9a-f]{40} # v4")
        self.assertIn("python3 scripts/publish_dev_image.py gate", PUBLISH)
        run = re.search(r"run: (python3 scripts/publish_dev_image\.py publish.*)", PUBLISH).group(1)
        self.assertEqual(run, 'python3 scripts/publish_dev_image.py publish --tested "$RUNNER_TEMP/promote"')
        self.assertNotIn("--fixture-registry", WORKFLOW)
        self.assertRegex(PUBLISH, r"fetch-depth: 0")  # the freshness guard needs the history
        self.assertEqual(len(re.findall(r"GITHUB_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}", PUBLISH)), 1)
        self.assertRegex(PUBLISH, r"NEEDS_RESULTS: \$\{\{ toJSON\(needs\) \}\}")

    def test_the_gate_step_comes_before_anything_is_downloaded_or_authenticated(self):
        self.assertLess(PUBLISH.index("publish_dev_image.py gate"), PUBLISH.index("download-artifact"))
        self.assertLess(PUBLISH.index("download-artifact"), PUBLISH.index("publish_dev_image.py publish"))

    def test_publication_is_serialized_without_cancelling_and_verification_is_not_cancelled_for_it(self):
        m = re.search(r"(?m)^    concurrency:\n      group: (\S+)\n      cancel-in-progress: (\w+)$", PUBLISH)
        self.assertIsNotNone(m)
        self.assertEqual((m.group(1), m.group(2)), ("publish-dev-image", "false"))
        top = WORKFLOW.split("\njobs:\n", 1)[0]
        group = re.search(r"(?m)^  group: (.*)$", top).group(1)
        self.assertIn("github.sha", group)  # every main push has its own CI group: a later push never cancels an earlier main run
        e = re.match(r"^ci-\$\{\{ (.*) \}\}$", group).group(1)
        self.assertEqual(evaluate_group(e, "push", "refs/heads/main", "a" * 40), "main-" + "a" * 40)
        self.assertEqual(evaluate_group(e, "pull_request", "refs/pull/25/merge", "b" * 40), "refs/pull/25/merge")  # a pull request keeps one run per ref
        self.assertEqual(evaluate_group(e, "push", "refs/heads/feature", "c" * 40), "refs/heads/feature")

    def test_the_budget_of_the_publish_job_is_bounded(self):
        self.assertEqual(job_key(PUBLISH, "timeout-minutes"), "20")
        self.assertEqual(job_key(PUBLISH, "runs-on"), "ubuntu-24.04")

    def test_the_target_in_the_workflow_text_and_in_the_script_agree(self):
        self.assertIn("ghcr.io/nicotm77/mandatary:dev", PUBLISH)
        self.assertEqual(pub.IMAGE + ":" + pub.TAG, "ghcr.io/nicotm77/mandatary:dev")
        self.assertIn("github.repository == '%s'" % pub.REPOSITORY, job_if(PUBLISH))
        self.assertEqual(set(pub.REQUIRED_JOBS), set(OTHERS))  # the script's own gate requires exactly the workflow's other jobs

    def test_every_action_is_pinned_to_a_commit(self):
        for ref in re.findall(r"uses: (\S+@\S+)", WORKFLOW):
            self.assertRegex(ref, r"@[0-9a-f]{40}$")


def evaluate_group(expr, event, ref, sha):
    """The concurrency group expression: `A && format('main-{0}', github.sha) || github.ref`, evaluated as GitHub does for the && / || idiom."""
    m = re.match(r"^(.*) && format\('main-\{0\}', github\.sha\) \|\| github\.ref$", expr)
    assert m, expr
    cond = Expr(m.group(1), context(event, ref)).run()
    return ("main-%s" % sha) if cond else ref


if __name__ == "__main__":
    unittest.main(verbosity=2)
