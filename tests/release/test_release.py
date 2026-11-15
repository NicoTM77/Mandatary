#!/usr/bin/env python3
"""Hermetic tests of the pure parts of the P1.20 release harness (no Docker, no network): the budget evaluator, the
/proc parsers, the outcome classification, the expected-usage tally and the OCI size reader. Each positive case has a
negative twin, so a gate that always passes (or always fails) is caught here.

    python3 tests/release/test_release.py
"""
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "image"))
sys.path.insert(0, HERE)
import footprint  # noqa: E402
import matrix  # noqa: E402
import collect  # noqa: E402
import report  # noqa: E402


class Budgets(unittest.TestCase):
    def test_a_real_measurement_within_the_budget_passes(self):
        self.assertTrue(footprint.within(49_999_999, footprint.BUDGET_IDLE_RSS_BYTES))
        self.assertTrue(footprint.within(footprint.BUDGET_IDLE_RSS_BYTES, footprint.BUDGET_IDLE_RSS_BYTES))

    def test_one_byte_over_the_budget_fails(self):
        self.assertFalse(footprint.within(footprint.BUDGET_IDLE_RSS_BYTES + 1, footprint.BUDGET_IDLE_RSS_BYTES))
        self.assertFalse(footprint.within(footprint.BUDGET_LOAD_RSS_BYTES + 1, footprint.BUDGET_LOAD_RSS_BYTES))
        self.assertFalse(footprint.within(footprint.BUDGET_IMAGE_BYTES + 1, footprint.BUDGET_IMAGE_BYTES))

    def test_a_missing_or_zero_or_boolean_measurement_is_never_a_pass(self):
        for bad in (None, 0, -1, "12", True, False, float("nan")):
            self.assertFalse(footprint.within(bad, footprint.BUDGET_IDLE_RSS_BYTES), repr(bad))

    def test_budgets_are_the_approved_numbers_in_the_strict_unit(self):
        self.assertEqual((footprint.BUDGET_IMAGE_BYTES, footprint.BUDGET_IDLE_RSS_BYTES, footprint.BUDGET_LOAD_RSS_BYTES), (60_000_000, 50_000_000, 150_000_000))


class Proc(unittest.TestCase):
    STATUS = "Name:\tmandatary\nVmPeak:\t  900000 kB\nVmSize:\t  800000 kB\nVmHWM:\t   60000 kB\nVmRSS:\t   31000 kB\nRssAnon:\t   14000 kB\nRssFile:\t   17000 kB\nVmSwap:\t       0 kB\n"

    def test_parse_status_reads_kib_as_bytes(self):
        s = footprint.parse_status(self.STATUS)
        self.assertEqual(s["VmRSS"], 31000 * 1024)
        self.assertEqual(s["VmHWM"], 60000 * 1024)
        self.assertEqual(s["RssAnon"] + s["RssFile"], s["VmRSS"])

    def test_a_garbled_line_is_ignored_not_guessed(self):
        s = footprint.parse_status("VmRSS:\tmany kB\nVmHWM:\t5 kB\n")
        self.assertNotIn("VmRSS", s)
        self.assertEqual(s["VmHWM"], 5 * 1024)

    def test_percentiles_are_nearest_rank_and_empty_is_zero(self):
        v = list(range(1, 101))
        self.assertEqual(footprint.percentile(v, 0.5), 51.0)
        self.assertEqual(footprint.percentile(v, 0.99), 99.0)
        self.assertEqual(footprint.percentile([], 0.5), 0.0)
        self.assertEqual(footprint.latency_summary([3, 1, 2])["p50_ms"], 2.0)


def build_oci(layers, attestation=None):
    """A minimal OCI archive: index -> manifest -> config + layers (each blob has a real size)."""
    blobs = {}

    def put(data):
        import hashlib
        d = hashlib.sha256(data).hexdigest()
        blobs["blobs/sha256/" + d] = data
        return "sha256:" + d
    layer_descs = [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": put(b), "size": len(b)} for b in layers]
    config = json.dumps({"rootfs": {"diff_ids": ["sha256:" + "0" * 64] * len(layers)}}).encode()
    man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": put(config), "size": len(config), "mediaType": "application/vnd.oci.image.config.v1+json"}, "layers": layer_descs}).encode()
    entries = [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": put(man), "size": len(man)}]
    if attestation:
        att = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": put(b"{}"), "size": 2, "mediaType": "application/vnd.oci.image.config.v1+json"},
                          "layers": [{"mediaType": "application/vnd.in-toto+json", "digest": put(attestation), "size": len(attestation)}]}).encode()
        index_inner = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [dict(entries[0], platform={"os": "linux", "architecture": "amd64"}),
                                  {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": put(att), "size": len(att), "annotations": {"vnd.docker.reference.type": "attestation-manifest"}}]}).encode()
        entries = [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": put(index_inner), "size": len(index_inner)}]
    blobs["index.json"] = json.dumps({"schemaVersion": 2, "manifests": entries}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in blobs.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue(), len(man) + len(config) + sum(len(b) for b in layers)


class Oci(unittest.TestCase):
    def measure(self, raw):
        with tempfile.NamedTemporaryFile(suffix=".tar") as fh:
            fh.write(raw)
            fh.flush()
            return footprint.oci_compressed_size(fh.name)

    def test_the_size_is_manifest_config_and_every_layer(self):
        raw, want = build_oci([b"a" * 1000, b"b" * 2500])
        total, layers = self.measure(raw)
        self.assertEqual(total, want)
        self.assertEqual(sorted(x["size"] for x in layers), [1000, 2500])

    def test_an_attestation_manifest_is_not_counted_as_part_of_the_runtime_image(self):
        raw, want = build_oci([b"a" * 1000], attestation=b"s" * 50_000)
        total, layers = self.measure(raw)
        self.assertEqual(len(layers), 1)
        self.assertLess(total, 50_000)  # the 50 kB attestation would have pushed it over


class SaveSize(unittest.TestCase):
    def archive(self, layers, diff_ids=("sha256:aa",), with_manifest=True):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            def add(name, data):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            cfg = json.dumps({"rootfs": {"diff_ids": list(diff_ids)}}).encode()
            add("cfg.json", cfg)
            names = []
            for i, data in enumerate(layers):
                add("l%d/layer.tar" % i, data)
                names.append("l%d/layer.tar" % i)
            if with_manifest:
                add("manifest.json", json.dumps([{"Config": "cfg.json", "Layers": names}]).encode())
        return buf.getvalue(), len(cfg)

    def measure(self, raw):
        with tempfile.NamedTemporaryFile(suffix=".tar") as fh:
            fh.write(raw)
            fh.flush()
            return footprint.save_compressed_size(fh.name)

    def test_the_size_is_every_layer_compressed_plus_config_and_manifest(self):
        compressible, random = b"a" * 1_000_000, os.urandom(50_000)
        raw, cfg_len = self.archive([compressible, random], diff_ids=("sha256:aa", "sha256:bb"))
        total, layers, diff_ids = self.measure(raw)
        self.assertEqual(diff_ids, ["sha256:aa", "sha256:bb"])
        self.assertLess(layers[0]["size"], 5_000)  # a megabyte of one byte really is compressed: the figure is not the uncompressed size
        self.assertGreater(layers[1]["size"], 49_000)  # random data does not shrink
        self.assertGreater(total, layers[0]["size"] + layers[1]["size"] + cfg_len)  # the manifest is counted as well
        self.assertLess(total, 1_000_000)

    def test_an_unrecognised_archive_is_an_error_not_a_size(self):
        raw, _ = self.archive([b"x"], with_manifest=False)
        with self.assertRaises(ValueError):
            self.measure(raw)


class Outcomes(unittest.TestCase):
    def test_rest_classification(self):
        self.assertEqual(matrix.norm_rest(200, {"a": 1}), (200, "", ""))
        self.assertEqual(matrix.norm_rest(204, None), (200, "", ""))
        self.assertEqual(matrix.norm_rest(403, {"error": {"code": "forbidden", "reason": "default_deny"}}), (403, "forbidden", "default_deny"))
        self.assertEqual(matrix.norm_rest(404, "<html>"), (404, "", ""))

    def test_mcp_classification_matches_rest_for_the_same_failure(self):
        self.assertEqual(matrix.norm_mcp({"connected": True, "is_error": True, "error_code": "forbidden", "error_reason": "default_deny"}), (403, "forbidden", "default_deny"))
        self.assertEqual(matrix.norm_mcp({"http_status": 401, "http_code": "unauthenticated"}), (401, "unauthenticated", ""))
        self.assertEqual(matrix.norm_mcp({"connected": True, "protocol_error": "jsonrpc -32602: unknown tool"}), (404, "not_found", "protocol"))
        self.assertEqual(matrix.norm_mcp({"connected": True}), (200, "", ""))

    def test_a_daemon_refusal_is_either_class_but_never_a_success_or_a_denial(self):
        self.assertTrue(matrix.BACKEND.matches((502, "backend_failed", "")))
        self.assertTrue(matrix.BACKEND.matches((400, "invalid_request", "")))
        for bad in ((200, "", ""), (403, "forbidden", "default_deny"), (401, "unauthenticated", ""), (404, "not_found", "")):
            self.assertFalse(matrix.BACKEND.matches(bad), bad)

    def test_a_result_that_never_connected_is_not_a_success(self):
        self.assertNotEqual(matrix.norm_mcp({}), (200, "", ""))

    def test_an_expectation_rejects_the_wrong_class(self):
        self.assertTrue(matrix.DENY.matches((403, "forbidden", "default_deny")))
        self.assertFalse(matrix.DENY.matches((200, "", "")))
        self.assertFalse(matrix.DENY.matches((403, "forbidden", "restore_quarantined")))
        self.assertFalse(matrix.UNAUTH.matches((403, "forbidden", "")))
        self.assertTrue(matrix.NOT_FOUND.matches((404, "", "")) and matrix.NOT_FOUND.matches((404, "not_found", "")))
        self.assertFalse(matrix.NOT_FOUND.matches((200, "", "")))


CTX = {"A": "ctr-a", "B": "ctr-b", "C": "ctr-c", "self": "mandatary-self", "self_id": "f" * 64, "peer": "peer", "peer_id": "e" * 64, "missing": "nothing-here"}


class Cases(unittest.TestCase):
    def setUp(self):
        self.cases = matrix.build_cases(CTX)

    def test_case_ids_are_unique(self):
        ids = [c.id for c in self.cases] + [c.id for c in matrix.rest_only_cases(CTX)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_success_is_accounted_as_allowed_with_a_selector(self):
        oks = [c for c in self.cases if c.expect is matrix.OK]
        self.assertGreaterEqual(len(oks), 15)
        for c in oks:
            self.assertEqual(c.count[2], "allowed", c.id)
            self.assertIsNotNone(c.count[1], c.id)

    def test_nothing_unauthenticated_or_protected_is_accounted(self):
        for c in self.cases:
            if c.expect is matrix.UNAUTH or c.id.startswith(("S-self", "S-peer", "E-unknown")):
                self.assertIsNone(c.count, c.id)

    def test_every_default_denial_has_no_selector_and_only_the_explicit_deny_names_one(self):
        for c in self.cases:
            if c.expect is matrix.DENY and c.count:
                if c.id.startswith("X-dn-") and c.id.endswith("-B"):
                    self.assertEqual(c.count[1], CTX["B"], c.id)
                else:
                    self.assertIsNone(c.count[1], c.id)

    def test_a_stop_is_always_followed_by_a_start_for_the_same_agent_and_target(self):
        for who in ("a", "dn"):
            seq = [c.op for c in self.cases if c.id.startswith("X-%s-" % who) and c.id.endswith("-A")]
            self.assertEqual(seq[seq.index("stop"):seq.index("stop") + 2], ["stop", "start"])

    def test_the_cross_product_is_complete(self):
        for who in ("a", "ro", "none", "dn", "grp"):
            for t in ("A", "B"):
                for op in matrix.ORDER:
                    self.assertTrue(any(c.id == "X-%s-%s-%s" % (who, op, t) for c in self.cases), (who, op, t))

    def test_the_expected_totals_are_pinned(self):
        t = matrix.Tally(lambda w: "rel-" + w, lambda w: "rel-owner")
        for c in self.cases:
            t.add_case(c, 2)
        # 94 cases x 2 transports; 76 accounted per transport pass (16 allowed ... see the harness), the rest are 401, self/peer, endpoint refusals
        self.assertEqual(t.events(), 2 * sum(1 for c in self.cases if c.count is not None))
        totals = t.totals()
        self.assertEqual(totals[("rel-a", "rel-owner", "ctr-a", "container:restart")], (2, 0, 0))
        self.assertEqual(totals[("rel-none", "rel-owner", None, "container:stop")], (0, 4, 0))  # A and B, twice
        self.assertEqual(totals[("rel-dn", "rel-owner", "ctr-b", "container:logs")], (0, 2, 0))
        self.assertEqual(totals[("rel-wild", "rel-owner", "*", "container:start")], (0, 0, 2))

    def test_tally_and_measurement_comparison(self):
        exp = {("a", "u", "x", "container:logs"): (1, 2, 3)}
        self.assertEqual(matrix.diff_totals(exp, dict(exp)), [])
        self.assertTrue(matrix.diff_totals(exp, {("a", "u", "x", "container:logs"): (1, 2, 4)}))
        self.assertTrue(matrix.diff_totals(exp, {}))
        self.assertTrue(matrix.diff_totals({}, exp))
        rows = [("a", "u", "x", "container:logs", 1, 0, 0), ("a", "u", "x", "container:logs", 0, 2, 3), ("z", "u", None, "container:stop", 0, 0, 0)]
        self.assertEqual(matrix.merge_rows(rows), exp)


class Collect(unittest.TestCase):
    def tree(self, files):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        for name, text in files.items():
            with open(os.path.join(d, name), "w") as fh:
                fh.write(text)
        return d

    def by_id(self, doc):
        return {r["id"]: r["status"] for r in doc["results"]}

    GOOD_GO = "".join("ok  \tgithub.com/x/p%d\t0.1s\n" % i for i in range(20))

    def test_gates_pass_only_with_exit_zero_and_the_evidence_the_gate_exists_to_produce(self):
        d = self.tree({"gates.tsv": "govulncheck\t0\t5\ngotest-short\t0\t9\ngofmt\t0\t0\nnode-scripts\t0\t3\n", "govulncheck.log": "No vulnerabilities found.\n", "gotest-short.log": self.GOOD_GO,
                       "web.tsv": "vitest\t0\t9\nnpm-audit\t0\t1\n", "vitest.log": " Test Files  3 passed (3)\n      Tests  10 passed (10)\n", "npm-audit.json": json.dumps({"metadata": {"vulnerabilities": {"high": 0, "critical": 0, "low": 2}}})})
        got = self.by_id(collect.gates(d))
        self.assertEqual(set(got.values()), {"PASS"}, got)
        self.assertEqual(set(got), {"GATE-GOVULNCHECK", "GATE-GOTEST", "GATE-GOFMT", "GATE-NODE-SCRIPTS", "GATE-WEB-VITEST", "GATE-NPM-AUDIT"})  # steps that did not run have no entry

    def test_the_product_tree_comparison_passes_only_when_nothing_differs(self):
        same = self.tree({"product-tree.txt": "compared 8c1a55a..0d8b431 over cmd internal web\n"})
        self.assertEqual(self.by_id(collect.gates(same)), {"GATE-PRODUCT-TREE": "PASS"})
        differs = self.tree({"product-tree.txt": "compared 8c1a55a..0d8b431 over cmd internal web\ninternal/auth/x.go\n"})
        self.assertEqual(self.by_id(collect.gates(differs)), {"GATE-PRODUCT-TREE": "FAIL"})
        empty = self.tree({"product-tree.txt": ""})
        self.assertEqual(self.by_id(collect.gates(empty)), {"GATE-PRODUCT-TREE": "FAIL"})  # no comparison recorded is not "no difference"

    def test_a_gate_that_exited_zero_without_its_evidence_is_a_failure(self):
        d = self.tree({"gates.tsv": "govulncheck\t0\t5\ngotest-short\t0\t9\n", "govulncheck.log": "scanner crashed\n", "gotest-short.log": "ok  \tgithub.com/x/p\t0.1s\n",
                       "web.tsv": "vitest\t0\t9\nnpm-audit\t0\t1\n", "vitest.log": "no summary\n", "npm-audit.json": "not json"})
        got = self.by_id(collect.gates(d))
        self.assertEqual(set(got.values()), {"FAIL"}, got)

    def test_a_nonzero_exit_or_a_vulnerability_or_a_failed_test_fails(self):
        d = self.tree({"gates.tsv": "govet\t1\t2\ngotest-short\t0\t9\n", "gotest-short.log": self.GOOD_GO + "--- FAIL: TestX (0.00s)\nFAIL\n",
                       "web.tsv": "npm-audit\t1\t1\n", "npm-audit.json": json.dumps({"metadata": {"vulnerabilities": {"high": 1, "critical": 0}}})})
        got = self.by_id(collect.gates(d))
        self.assertEqual(got, {"GATE-GOVET": "FAIL", "GATE-GOTEST": "FAIL", "GATE-NPM-AUDIT": "FAIL"})

    BR_OK = "".join("    --- PASS: %s/chromium/flow-%d/%s (1s)\n" % (t, i, sch) for t in ("TestAdminUIBrowser", "TestSecurityUIBrowser") for i in range(2) for sch in ("light", "dark")) + "--- PASS: TestAdminUIBrowser (3s)\nPASS\n"

    def test_a_browser_run_needs_both_colour_schemes_the_named_engine_and_no_skip(self):
        d = self.tree({"browsers.tsv": "chromium-desktop\t0\t100\n", "chromium-desktop.log": self.BR_OK})
        self.assertEqual(self.by_id(collect.browsers(d)), {"GATE-BROWSER-chromium-desktop": "PASS"})
        light_only = "".join(ln for ln in self.BR_OK.splitlines(True) if "/dark" not in ln)
        wrong_engine = self.BR_OK.replace("/chromium/", "/firefox/")
        skipped = self.BR_OK + "    --- SKIP: TestAdminUIBrowser/chromium/x/dark (0s)\n"
        for name, text in (("light only", light_only), ("other engine", wrong_engine), ("a skipped scenario", skipped), ("empty", "PASS\n")):
            d = self.tree({"browsers.tsv": "chromium-desktop\t0\t100\n", "chromium-desktop.log": text})
            self.assertEqual(self.by_id(collect.browsers(d)), {"GATE-BROWSER-chromium-desktop": "FAIL"}, name)
        d = self.tree({"browsers.tsv": "chromium-desktop\t1\t100\n", "chromium-desktop.log": self.BR_OK})
        self.assertEqual(self.by_id(collect.browsers(d)), {"GATE-BROWSER-chromium-desktop": "FAIL"})

    def test_scan_results(self):
        good = {"Results": [{"Target": "img (debian)", "Vulnerabilities": [{"Severity": "LOW", "VulnerabilityID": "CVE-1"}]}]}
        bad = {"Results": [{"Target": "img", "Vulnerabilities": [{"Severity": "CRITICAL", "VulnerabilityID": "CVE-2"}]}]}
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [{"name": "a"}]}

        def run(trivy, sb):
            files = {"v.txt": "Version: 0.76.2\n"}
            if trivy is not None:
                files["t.json"] = trivy if isinstance(trivy, str) else json.dumps(trivy)
            if sb is not None:
                files["s.json"] = json.dumps(sb)
            d = self.tree(files)
            return self.by_id(collect.scan(os.path.join(d, "t.json"), os.path.join(d, "s.json"), os.path.join(d, "v.txt"), "amd64"))
        self.assertEqual(run(good, sbom), {"SCAN-TRIVY-amd64": "PASS", "SCAN-SBOM-amd64": "PASS"})
        self.assertEqual(run(bad, sbom)["SCAN-TRIVY-amd64"], "FAIL")
        self.assertEqual(run({"Results": []}, sbom)["SCAN-TRIVY-amd64"], "FAIL")  # nothing scanned is not "no findings"
        self.assertEqual(run(None, None), {"SCAN-TRIVY-amd64": "FAIL", "SCAN-SBOM-amd64": "FAIL"})
        self.assertEqual(run(good, dict(sbom, components=[]))["SCAN-SBOM-amd64"], "FAIL")

    def test_hosted_jobs_count_only_when_completed_successfully(self):
        step = {"conclusion": "success"}
        doc = {"jobs": [{"name": "Baseline (Go 1.27.4)", "status": "completed", "conclusion": "success", "steps": [step]},
                        {"name": "Image (linux/arm64)", "status": "completed", "conclusion": "failure", "steps": [step]},
                        {"name": "Skipped one", "status": "completed", "conclusion": "skipped", "steps": []},
                        {"name": "Running", "status": "in_progress", "conclusion": None, "steps": [step]},
                        {"name": "Odd step", "status": "completed", "conclusion": "success", "steps": [step, {"conclusion": "failure"}]}]}
        d = self.tree({"jobs.json": json.dumps(doc)})
        got = self.by_id(collect.jobs(os.path.join(d, "jobs.json")))
        self.assertEqual(got, {"HOSTED-Baseline-Go-1.27.4": "PASS", "HOSTED-Image-linux-arm64": "FAIL", "HOSTED-Skipped-one": "FAIL", "HOSTED-Running": "FAIL", "HOSTED-Odd-step": "FAIL"})
        self.assertEqual(self.by_id(collect.jobs(os.path.join(d, "missing.json"))), {"HOSTED-JOBS": "FAIL"})
        d = self.tree({"jobs.json": json.dumps({"jobs": []})})
        self.assertEqual(self.by_id(collect.jobs(os.path.join(d, "jobs.json"))), {"HOSTED-JOBS": "FAIL"})


class Criteria(unittest.TestCase):
    ARTIFACTS = {"vm-amd64", "ci-amd64", "ci-arm64", "scan-amd64", "scan-arm64", "gates", "browsers", "hosted-ci"}

    def setUp(self):
        with open(os.path.join(HERE, "criteria.json")) as fh:
            self.crit = json.load(fh)["criteria"]

    def test_every_criterion_has_a_unique_id_a_group_and_linked_evidence(self):
        ids = [c["id"] for c in self.crit]
        self.assertEqual(len(ids), len(set(ids)))
        for c in self.crit:
            self.assertTrue(c["group"] and c["text"], c["id"])
            self.assertTrue(c["evidence"], c["id"])  # a criterion with no evidence can only ever be UNVERIFIED: that is a gap, not a design
            self.assertEqual(len(c["evidence"]), len(set(c["evidence"])), c["id"])

    def test_every_evidence_reference_names_a_known_artifact(self):
        for c in self.crit:
            for ref in c["evidence"]:
                check, _, artifact = ref.rpartition("@")
                self.assertTrue(check, ref)
                self.assertIn(artifact, self.ARTIFACTS, ref)

    def test_the_named_release_criteria_are_all_present(self):
        have = {c["id"] for c in self.crit}
        for want in ("SH-1", "SH-2a", "SH-2b", "SH-2c", "SH-3", "SH-4", "SH-5", "SH-6", "SH-7a", "SH-7b", "SH-7c", "SH-8", "SH-9a", "SH-9b", "SH-10", "P1-E1", "P1-E2", "P1-E3", "P1-E4", "P1-E5"):
            self.assertIn(want, have)


class Docs(unittest.TestCase):
    def run_check(self, files):
        import core
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, rel)) or d, exist_ok=True)
            with open(os.path.join(d, rel), "w") as fh:
                fh.write(text)
        out = {}

        class C:
            a = types.SimpleNamespace(repo=d)

            def check(self, i, n, ok, det=""):
                out[i] = ok
        core.docs_check(C())
        return out

    GOOD = {"README.md": "see [limits](docs/deployment.md) known limitation\n", "development.md": "x", "docker-compose.yml": "", "deploy/compose.proxy.yml": "", "deploy/env.example": "",
            "docs/deployment.md": "docker-compose.yml deploy/compose.proxy.yml deploy/env.example Not implemented Evidence and limits Self-protection and readiness First administrator",
            "docs/api-mcp.md": "unsupported: exec, discovery, raw docker"}

    def test_a_consistent_tree_passes_every_documentation_check(self):
        self.assertEqual(set(self.run_check(self.GOOD).values()), {True})

    def test_a_broken_link_a_missing_shipped_file_or_a_missing_statement_fails_its_own_check(self):
        bad = dict(self.GOOD, **{"docs/x.md": "[gone](nowhere.md) [ext](https://example.org/x)"})
        self.assertEqual([k for k, v in self.run_check(bad).items() if not v], ["REL-DOCS-LINKS"])
        bad = dict(self.GOOD)
        del bad["deploy/env.example"]
        self.assertEqual([k for k, v in self.run_check(bad).items() if not v], ["REL-DOCS-DEPLOY"])
        bad = dict(self.GOOD, **{"docs/api-mcp.md": "nothing here"})
        self.assertEqual([k for k, v in self.run_check(bad).items() if not v], ["REL-DOCS-UNAVAILABLE"])
        bad = dict(self.GOOD, **{"docs/deployment.md": "docker-compose.yml deploy/compose.proxy.yml deploy/env.example"})
        self.assertEqual([k for k, v in self.run_check(bad).items() if not v], ["REL-DOCS-LIMITS"])


class EnvironmentFacts(unittest.TestCase):
    VERSION = json.dumps({"Client": {"Version": "29.9.3"}, "Server": {"Version": "29.9.3", "ApiVersion": "1.56", "Os": "linux", "Arch": "amd64"}})
    INFO = json.dumps({"ID": "abc", "KernelVersion": "7.0.0", "OperatingSystem": "Ubuntu", "NCPU": 4, "MemTotal": 33_000_000_000, "Driver": "overlayfs", "CgroupDriver": "systemd", "CgroupVersion": "2"})

    def test_a_complete_description_names_every_fact(self):
        import release
        got = release.describe_environment(self.VERSION, self.INFO, "5.7.1")
        self.assertEqual((got["docker_server"], got["api"], got["os_arch"], got["kernel"], got["cpus"], got["compose"], got["daemon_id"]), ("29.9.3", "1.56", "linux/amd64", "7.0.0", 4, "5.7.1", "abc"))
        self.assertNotIn("missing", got)

    def test_a_missing_fact_is_named_and_unreadable_output_is_an_error_not_an_empty_record(self):
        import release
        got = release.describe_environment(json.dumps({"Server": {"Version": "1"}}), self.INFO, "")
        self.assertIn("api", got["missing"])
        self.assertIn("compose", got["missing"])
        self.assertEqual(release.describe_environment("not json", self.INFO, "x")["error"], "docker version/info unreadable")


class Harness(unittest.TestCase):
    def test_the_release_harness_refuses_to_run_without_a_declared_daemon_identity(self):
        p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "release.py"), "--image", "x", "--platform", "linux/amd64", "--repo", ".", "--work", "/nonexistent/w",
                            "--host-binary", "h", "--mcp-client", "m", "--sha", "0" * 40, "--results", "/nonexistent/r.json", "--docker-host", "unix:///var/run/docker.sock"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2)
        self.assertIn("--expect-daemon-id", p.stderr)

    def test_the_release_harness_refuses_an_ambient_or_remote_endpoint(self):
        with tempfile.TemporaryDirectory() as d:
            r = os.path.join(d, "r.json")
            p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "release.py"), "--image", "x", "--platform", "linux/amd64", "--repo", ".", "--work", os.path.join(d, "w"),
                                "--host-binary", "h", "--mcp-client", "m", "--sha", "0" * 40, "--results", r, "--docker-host", "tcp://127.0.0.1:2375", "--expect-daemon-id", "X"],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 1)
            with open(r) as fh:
                doc = json.load(fh)
            self.assertEqual([x["id"] for x in doc["results"]], ["ISO-00"])
            self.assertFalse(os.path.exists(os.path.join(d, "w")))  # nothing was created


class Report(unittest.TestCase):
    def test_a_criterion_without_a_result_or_digest_is_never_a_pass(self):
        crit = [{"id": "C1", "text": "x", "evidence": []}, {"id": "C2", "text": "y", "evidence": ["REL-A@res"]}]
        results = {"REL-A@res": "PASS"}
        arts = {"res": "ab" * 32}
        rows = report.evaluate(crit, results, arts)
        self.assertEqual(rows[0]["status"], "UNVERIFIED")  # nothing linked
        self.assertEqual(rows[1]["status"], "PASS")
        self.assertEqual(report.evaluate(crit, results, {})[1]["status"], "UNVERIFIED")  # no digest for the artifact
        results["REL-A@res"] = "FAIL"
        self.assertEqual(report.evaluate(crit, results, arts)[1]["status"], "FAIL")

    def test_one_failing_link_fails_the_criterion_even_when_others_pass(self):
        crit = [{"id": "C", "text": "", "evidence": ["A@r", "B@r"]}]
        self.assertEqual(report.evaluate(crit, {"A@r": "PASS", "B@r": "FAIL"}, {"r": "00"})[0]["status"], "FAIL")
        self.assertEqual(report.evaluate(crit, {"A@r": "PASS", "B@r": "BLOCKED"}, {"r": "00"})[0]["status"], "UNVERIFIED")
        self.assertEqual(report.evaluate(crit, {"A@r": "PASS"}, {"r": "00"})[0]["status"], "UNVERIFIED")  # B has no result at all

    def test_the_verdict_is_accepted_only_when_every_criterion_passes(self):
        row = lambda s: {"status": s}  # noqa: E731
        self.assertTrue(report.verdict([row("PASS"), row("PASS")])[0])
        self.assertFalse(report.verdict([row("PASS"), row("UNVERIFIED")])[0])
        self.assertFalse(report.verdict([row("PASS"), row("FAIL")])[0])
        self.assertFalse(report.verdict([])[0])  # an empty report is never an acceptance

    def test_a_stale_or_hand_edited_report_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            ev = os.path.join(d, "ev")
            os.mkdir(ev)
            with open(os.path.join(ev, "r.json"), "w") as fh:
                json.dump({"results": [{"id": "A", "status": "PASS"}]}, fh)
            with open(os.path.join(ev, "manifest.json"), "w") as fh:
                json.dump({"release_candidate": {"head": "x"}, "artifacts": {"r": {"file": "r.json", "kind": "results", "source": "test"}}}, fh)
            def sums():
                with open(os.path.join(ev, "SHA256SUMS"), "w") as sf:
                    sf.write("".join("%s  %s\n" % (report.sha256_file(os.path.join(ev, n)), n) for n in ("manifest.json", "r.json")))
            sums()
            crit = os.path.join(d, "criteria.json")
            with open(crit, "w") as fh:
                json.dump({"criteria": [{"id": "C", "group": "g", "text": "t", "evidence": ["A@r"]}]}, fh)
            out = os.path.join(d, "out.md")
            run = lambda *extra: subprocess.run([sys.executable, "-I", os.path.join(HERE, "report.py"), "--evidence", ev, "--criteria", crit, "--out", out, *extra], capture_output=True, text=True)  # noqa: E731
            self.assertEqual(run().returncode, 0)
            self.assertEqual(run("--check").returncode, 0)
            with open(out, "a") as fh:
                fh.write("hand edit\n")
            self.assertEqual(run("--check").returncode, 1)
            run()
            with open(os.path.join(ev, "r.json"), "w") as fh:
                json.dump({"results": [{"id": "A", "status": "FAIL"}]}, fh)  # the evidence changed after SHA256SUMS and the report were written
            r = run("--check")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("SHA256SUMS", r.stderr)
            sums()  # re-sealed but the report was not regenerated: still stale
            self.assertEqual(run("--check").returncode, 1)
            self.assertEqual(run().returncode, 0)
            self.assertEqual(run("--check").returncode, 0)
            with open(os.path.join(ev, "extra.log"), "w") as fh:
                fh.write("an unlisted file")
            self.assertNotEqual(run("--check").returncode, 0)  # a file nobody sealed


if __name__ == "__main__":
    unittest.main(verbosity=2)
