#!/usr/bin/env python3
"""Hermetic tests (no Docker, no network, no credential) of the P1.20 evidence design: compact summaries, the verified raw archive and the
report that is generated from them. Every fixture archive is built here from scratch; the one test that reads the repository's own
committed evidence only does the COMPACT verification a fresh clone can do.

    python3 tests/release/test_evidence.py

What is pinned, each with a negative twin:
  * local regeneration (staged raw members -> summaries -> seal -> report) and that it is deterministic;
  * archive resolution and staging (a local tarball, a draft-release asset through a fake `gh`), unavailable evidence, a wrong asset;
  * digest mismatches (tarball, size, member, manifest) and provenance mismatches (member, source digest, revision, summary content);
  * a hostile archive (path traversal, absolute path, symlink, duplicate, unlisted member, too many members) is refused before use;
  * the report is fail-closed: a missing summary or artifact is UNVERIFIED, an open adverse run fails, a disposition is PASS WITH
    DISCLOSURES (never a silent PASS), an open acceptance gate is "ACCEPTANCE PENDING", never "ACCEPTED";
  * compact verification and the full archive audit are different checks and say so.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence  # noqa: E402
import report  # noqa: E402

REV_A = "a" * 40
REV_B = "b" * 40


def slurp(path, mode="r"):
    with open(path, mode) as fh:
        return fh.read()


def jload(path):
    with open(path) as fh:
        return json.load(fh)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def results_doc(status="PASS", sha=REV_A, extra=None):
    doc = {"source_sha": sha, "platform": "linux/amd64", "pass": 1 if status == "PASS" else 0, "not_pass": 0 if status == "PASS" else 1,
           "results": [{"id": "A", "status": status, "detail": "first"}, {"id": "B", "status": "PASS", "detail": "second"}],
           "evidence": {"footprint": {"idle": [{"label": "fresh", "VmRSS_steady_max": 28_000_000, "curve": list(range(100))}]}}}
    doc.update(extra or {})
    return doc


class Fx:
    """A complete miniature evidence set: raw members -> archive tarball -> committed evidence directory -> report."""

    def __init__(self, root, status="PASS", adverse=None, gates=None, disposition=False):
        self.root = root
        self.raw = os.path.join(root, "raw")
        self.ev = os.path.join(root, "ev")
        self.tar = os.path.join(root, "out", "arch-v1.tar.gz")
        self.manifest = os.path.join(root, "out", "ARCHIVE.sha256")
        os.makedirs(os.path.dirname(self.tar), exist_ok=True)
        write(os.path.join(self.raw, "run1", "results.json"), json.dumps(results_doc(status)))
        write(os.path.join(self.raw, "run1", "release.log"), "bulky raw log\n" * 100)
        if adverse:
            write(os.path.join(self.raw, "diag", "bad.json"), json.dumps(results_doc("FAIL", REV_B)))
        evidence.pack([("r1", self.raw)], self.tar, self.manifest)
        os.makedirs(os.path.join(self.ev, "summaries"))
        write(os.path.join(self.ev, "ARCHIVE.sha256"), slurp(self.manifest))
        artifacts = {"run1": self.art("run1", "r1/run1/results.json", REV_A)}
        if adverse:
            artifacts["bad"] = self.art("bad", "r1/diag/bad.json", REV_B)
        for name, a in artifacts.items():
            self.summary(name, a)
        self.catalog = {
            "schema": evidence.CATALOG_SCHEMA,
            "release_candidate": {"code commit": REV_A},
            "archive": {
                "id": "arch-v1", "tarball": os.path.basename(self.tar), "tarball_sha256": evidence.sha256_file(self.tar),
                "tarball_bytes": os.path.getsize(self.tar), "manifest": "ARCHIVE.sha256",
                "manifest_sha256": evidence.sha256_file(self.manifest), "members": len(evidence.parse_manifest(slurp(self.manifest))[0]),
                "location": {"kind": "github-release", "repo": "o/r", "tag": "arch-v1", "description": "a fixture draft release"},
            },
            "artifacts": artifacts,
            "acceptance_gates": gates or [],
            "dispositions": [],
            "findings": [],
            "verdict_notes": [],
        }
        self.criteria = os.path.join(root, "criteria.json")
        crit = {"id": "C", "group": "g", "text": "t", "evidence": ["A@run1", "B@run1"]}
        if adverse:
            crit["adverse"] = {"state": "dispositioned" if disposition else "open", "refs": ["A@bad"], "disposition": "owner-approved fixture disposition"}
        write(self.criteria, json.dumps({"criteria": [crit]}))
        self.out = os.path.join(root, "report.md")
        self.save_catalog()

    def art(self, name, member, rev):
        return {"file": "summaries/%s.json" % name, "kind": "results", "member": member, "revision": rev, "revision_basis": "fixture", "source": "fixture"}

    def summary(self, name, a):
        raw = os.path.join(self.raw, *a["member"].split("/")[1:])
        write(os.path.join(self.ev, a["file"]), evidence.canonical(evidence.summarize(raw, a["member"], name)))

    def save_catalog(self):
        write(os.path.join(self.ev, "catalog.json"), evidence.canonical(self.catalog))
        evidence.seal(self.ev)

    def run_report(self, *extra):
        return subprocess.run([sys.executable, "-I", os.path.join(HERE, "report.py"), "--evidence", self.ev, "--criteria", self.criteria, "--out", self.out, *extra],
                              capture_output=True, text=True)

    def stage(self, **kw):
        """Stage into a fresh, empty directory; returns (problems, staged_dir_or_None) like evidence.stage."""
        self.staged_n = getattr(self, "staged_n", 0) + 1
        dest = os.path.join(self.root, "staging", "s%d" % self.staged_n)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        return evidence.stage(self.ev, dest, **kw)


class Tmp(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.d = self._t.name


class FakeGh:
    """A stand-in for `gh api` (the runner of evidence.release_asset): lists the releases and serves one asset, and records the calls."""

    def __init__(self, tar_path, tag="arch-v1", asset="arch-v1.tar.gz", fail=False):
        self.tar_path, self.tag, self.asset, self.fail = tar_path, tag, asset, fail
        self.calls = []

    def __call__(self, cmd, capture_output=True, timeout=None):
        self.calls.append(cmd)
        joined = " ".join(cmd)
        if self.fail:
            return types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"HTTP 404")
        if "releases?per_page" in joined:
            return types.SimpleNamespace(returncode=0, stdout=json.dumps([{"tag_name": self.tag, "draft": True, "assets": [{"name": self.asset, "id": 7}]}]).encode(), stderr=b"")
        if "releases/assets/7" in joined:
            with open(self.tar_path, "rb") as fh:
                return types.SimpleNamespace(returncode=0, stdout=fh.read(), stderr=b"")
        return types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"unexpected call")


def fake_gh(tar_path, **kw):
    return FakeGh(tar_path, **kw)


class Regeneration(Tmp):
    def test_the_committed_summaries_are_what_the_staged_raw_members_produce_and_regeneration_is_deterministic(self):
        fx = Fx(self.d)
        problems, staged = fx.stage(tarball=fx.tar)
        self.assertEqual(problems, [])
        p, counts = evidence.audit_archive(fx.ev, staged)
        self.assertEqual((p, counts["summaries_regenerated"], counts["members_verified"]), ([], 1, 2))
        before = slurp(os.path.join(fx.ev, "summaries", "run1.json"))
        self.assertEqual(evidence.regenerate(fx.ev, staged), ["run1"])
        self.assertEqual(slurp(os.path.join(fx.ev, "summaries", "run1.json")), before)  # byte for byte
        self.assertEqual(fx.run_report().returncode, 0)

    def test_a_changed_raw_run_changes_the_summary_and_then_the_report(self):
        fx = Fx(self.d)
        self.assertEqual(fx.run_report().returncode, 0)
        good = slurp(fx.out)
        # a different raw run is staged (e.g. a re-run): regeneration rewrites the summary, the old report is stale until regenerated
        alt = os.path.join(self.d, "staged-alt")
        write(os.path.join(alt, "r1", "run1", "results.json"), json.dumps(results_doc("FAIL")))
        evidence.regenerate(fx.ev, alt)
        evidence.seal(fx.ev)
        self.assertNotEqual(slurp(os.path.join(fx.ev, "summaries", "run1.json")).count("FAIL"), 0)
        self.assertEqual(fx.run_report("--check").returncode, 1)  # stale against the new summary (and its source digest no longer matches the manifest)
        self.assertEqual(slurp(fx.out), good)

    def test_the_audit_detects_a_summary_that_the_raw_member_does_not_produce(self):
        fx = Fx(self.d)
        _, staged = fx.stage(tarball=fx.tar)
        s = os.path.join(fx.ev, "summaries", "run1.json")
        doc = jload(s)
        doc["results"][0]["status"] = "PASS" if doc["results"][0]["status"] != "PASS" else "FAIL"  # a doctored result
        write(s, evidence.canonical(doc))
        problems, _ = evidence.audit_archive(fx.ev, staged)
        self.assertTrue(any("committed summary is not what the raw member produces" in p for p in problems), problems)

    def test_long_lists_are_cut_to_their_length_and_scalars_are_kept(self):
        fx = Fx(self.d)
        s = jload(os.path.join(fx.ev, "summaries", "run1.json"))
        self.assertEqual(s["evidence"]["footprint"]["idle"][0]["curve"], {"omitted_list_length": 100})
        self.assertEqual(s["evidence"]["footprint"]["idle"][0]["VmRSS_steady_max"], 28_000_000)


class Staging(Tmp):
    def test_a_local_tarball_is_staged_with_every_member_verified(self):
        fx = Fx(self.d)
        problems, staged = fx.stage(tarball=fx.tar)
        self.assertEqual(problems, [])
        self.assertTrue(os.path.exists(os.path.join(staged, "r1", "run1", "release.log")))

    def test_the_archive_is_resolved_from_a_draft_release_with_the_callers_own_gh(self):
        fx = Fx(self.d)
        gh = fake_gh(fx.tar)
        problems, staged = fx.stage(gh=["gh"], runner=gh)
        self.assertEqual(problems, [])
        self.assertTrue(os.path.exists(os.path.join(staged, "r1", "run1", "results.json")))
        self.assertTrue(all(c[0] == "gh" and c[1] == "api" for c in gh.calls))  # only `gh api`, no other command, no token handling here

    def test_unavailable_evidence_is_a_failure_never_a_pass(self):
        fx = Fx(self.d)
        problems, staged = fx.stage(gh=["gh"], runner=fake_gh(fx.tar, fail=True))
        self.assertIsNone(staged)
        self.assertTrue(any("unavailable" in p for p in problems), problems)
        problems, staged = fx.stage(tarball=os.path.join(self.d, "no-such.tar.gz"))
        self.assertIsNone(staged)
        self.assertTrue(any("unavailable" in p for p in problems), problems)
        problems, staged = fx.stage()  # nothing to read and no fetchable location given
        self.assertIsNone(staged)
        self.assertTrue(problems)

    def test_a_release_without_the_named_asset_or_tag_is_unavailable(self):
        fx = Fx(self.d)
        for kw in ({"asset": "other.tar.gz"}, {"tag": "other-tag"}):
            problems, staged = fx.stage(gh=["gh"], runner=fake_gh(fx.tar, **kw))
            self.assertIsNone(staged)
            self.assertTrue(any("not found" in p for p in problems), problems)

    def test_a_modified_tarball_is_a_digest_mismatch(self):
        fx = Fx(self.d)
        with open(fx.tar, "ab") as fh:
            fh.write(b"\0")
        problems, staged = fx.stage(tarball=fx.tar)
        self.assertIsNone(staged)
        self.assertTrue(any("size mismatch" in p for p in problems), problems)
        raw = bytearray(slurp(fx.tar, "rb"))[:-1]
        raw[len(raw) // 2] ^= 0xFF  # same size, one corrupted byte
        write_bytes = os.path.join(self.d, "corrupt.tar.gz")
        with open(write_bytes, "wb") as fh:
            fh.write(bytes(raw))
        problems, staged = fx.stage(tarball=write_bytes)
        self.assertIsNone(staged)
        self.assertTrue(any("digest mismatch" in p for p in problems), problems)

    def test_a_member_that_differs_from_the_manifest_is_a_digest_mismatch_even_when_the_tarball_matches_the_catalog(self):
        fx = Fx(self.d)
        write(os.path.join(fx.raw, "run1", "release.log"), "tampered\n")
        tar2 = os.path.join(self.d, "out", "tampered.tar.gz")
        evidence.pack([("r1", fx.raw)], tar2, os.path.join(self.d, "out", "m2"))
        fx.catalog["archive"]["tarball_sha256"] = evidence.sha256_file(tar2)  # the catalog was (wrongly) updated to the new tarball
        fx.catalog["archive"]["tarball_bytes"] = os.path.getsize(tar2)
        fx.save_catalog()
        problems, staged = fx.stage(tarball=tar2)  # but ARCHIVE.sha256 still lists the old member digest
        self.assertIsNone(staged)
        self.assertTrue(any(p.startswith("digest mismatch: r1/run1/release.log") for p in problems), problems)

    def test_an_archive_with_a_missing_or_unlisted_member_is_refused(self):
        fx = Fx(self.d)
        os.remove(os.path.join(fx.raw, "run1", "release.log"))
        tar2 = os.path.join(self.d, "out", "missing.tar.gz")
        evidence.pack([("r1", fx.raw)], tar2, os.path.join(self.d, "out", "m2"))
        fx.catalog["archive"]["tarball_sha256"] = evidence.sha256_file(tar2)
        fx.catalog["archive"]["tarball_bytes"] = os.path.getsize(tar2)
        fx.save_catalog()
        problems, _ = fx.stage(tarball=tar2)
        self.assertTrue(any("listed in the manifest but absent" in p for p in problems), problems)
        write(os.path.join(fx.raw, "run1", "release.log"), "bulky raw log\n" * 100)
        write(os.path.join(fx.raw, "run1", "extra.log"), "not in the manifest\n")
        tar3 = os.path.join(self.d, "out", "extra.tar.gz")
        evidence.pack([("r1", fx.raw)], tar3, os.path.join(self.d, "out", "m3"))
        fx.catalog["archive"]["tarball_sha256"] = evidence.sha256_file(tar3)
        fx.catalog["archive"]["tarball_bytes"] = os.path.getsize(tar3)
        fx.save_catalog()
        problems, _ = fx.stage(tarball=tar3)
        self.assertTrue(any("not in the manifest" in p for p in problems), problems)

    def test_the_staging_directory_must_be_empty(self):
        fx = Fx(self.d)
        dest = os.path.join(self.d, "busy")
        write(os.path.join(dest, "keep.txt"), "x")
        problems, staged = evidence.stage(fx.ev, dest, tarball=fx.tar)
        self.assertIsNone(staged)
        self.assertTrue(any("not empty" in p for p in problems), problems)


def hostile(path, entries):
    """A tarball that holds the given (name, kind, data) entries; kinds: file, symlink."""
    with tarfile.open(path, "w:gz") as tf:
        for name, kind, data in entries:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))


class HostileArchive(Tmp):
    def manifest_for(self, entries):
        return {n: evidence.sha256_bytes(d) for n, k, d in entries if k == "file"}

    def test_unsafe_members_are_refused_and_nothing_is_written_outside_the_destination(self):
        for name, kind in (("../escape.txt", "file"), ("/abs/escape.txt", "file"), ("ok/../../escape.txt", "file"), ("link", "symlink"), ("a b.txt", "file")):
            tar = os.path.join(self.d, "h.tar.gz")
            entries = [(name, kind, b"x")]
            hostile(tar, entries)
            dest = os.path.join(self.d, "dest-" + str(abs(hash(name))))
            problems = evidence.extract(tar, dest, {"ok.txt": "0" * 64})
            self.assertTrue(problems, name)
            self.assertFalse(os.path.exists(os.path.join(self.d, "escape.txt")), name)
            self.assertFalse(os.path.exists("/abs/escape.txt"))

    def test_a_duplicate_member_and_an_unlisted_member_are_refused(self):
        entries = [("a.txt", "file", b"one"), ("a.txt", "file", b"two")]
        tar = os.path.join(self.d, "d.tar.gz")
        hostile(tar, entries)
        problems = evidence.extract(tar, os.path.join(self.d, "d1"), {"a.txt": evidence.sha256_bytes(b"one")})
        self.assertTrue(any("duplicate member" in p for p in problems), problems)
        problems = evidence.extract(tar, os.path.join(self.d, "d2"), {"other.txt": evidence.sha256_bytes(b"one")})
        self.assertTrue(any("not in the manifest" in p for p in problems), problems)

    def test_too_many_members_and_an_unreadable_archive_are_refused(self):
        entries = [("m%d.txt" % i, "file", b"") for i in range(evidence.MAX_MEMBERS + 2)]
        tar = os.path.join(self.d, "many.tar.gz")
        hostile(tar, entries)
        problems = evidence.extract(tar, os.path.join(self.d, "many"), self.manifest_for(entries))
        self.assertTrue(any("more than" in p for p in problems), problems)
        bad = os.path.join(self.d, "garbage.tar.gz")
        write(bad, "this is not a tarball")
        problems = evidence.extract(bad, os.path.join(self.d, "garbage"), {})
        self.assertTrue(any("cannot be read" in p for p in problems), problems)

    def test_the_manifest_parser_is_strict(self):
        good = "%s  a/b.txt\n" % ("a" * 64)
        self.assertEqual(evidence.parse_manifest(good)[1], [])
        for bad in ("%s a/b.txt\n" % ("a" * 64), "short  a/b.txt\n", "%s  ../x\n" % ("a" * 64), "%s  /abs\n" % ("a" * 64),
                    good + good, "%s  z.txt\n%s  a.txt\n" % ("a" * 64, "b" * 64)):
            self.assertTrue(evidence.parse_manifest(bad)[1], bad)


class CompactVerification(Tmp):
    def problems(self, fx):
        return evidence.verify_compact(fx.ev)

    def test_a_consistent_evidence_directory_verifies_without_reading_the_archive(self):
        fx = Fx(self.d)
        os.remove(fx.tar)  # the archive is not needed for the compact level
        self.assertEqual(self.problems(fx), [])
        r = fx.run_report()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(fx.run_report("--check").returncode, 0)
        self.assertIn("raw archive was NOT read", fx.run_report("--check").stdout)

    def test_a_missing_summary_or_manifest_is_a_failure(self):
        fx = Fx(self.d)
        os.remove(os.path.join(fx.ev, "summaries", "run1.json"))
        self.assertTrue(any("summary" in p and "missing" in p for p in self.problems(fx)))
        r = fx.run_report()
        self.assertNotEqual(r.returncode, 0)
        fx2 = Fx(os.path.join(self.d, "second"))
        os.remove(os.path.join(fx2.ev, "ARCHIVE.sha256"))
        self.assertTrue(any("ARCHIVE.sha256 is missing" in p for p in self.problems(fx2)))

    def test_a_summary_bound_to_a_different_raw_document_is_a_provenance_mismatch(self):
        fx = Fx(self.d)
        s = os.path.join(fx.ev, "summaries", "run1.json")
        doc = jload(s)
        doc["source"]["sha256"] = "0" * 64
        write(s, evidence.canonical(doc))
        evidence.seal(fx.ev)  # a re-sealed but forged summary: SHA256SUMS cannot catch it, the manifest binding does
        self.assertTrue(any("provenance mismatch" in p for p in self.problems(fx)), self.problems(fx))
        self.assertNotEqual(fx.run_report().returncode, 0)

    def test_a_summary_derived_from_another_member_is_a_provenance_mismatch(self):
        fx = Fx(self.d)
        fx.catalog["artifacts"]["run1"]["member"] = "r1/run1/release.log"
        fx.save_catalog()
        self.assertTrue(any("derived from r1/run1/results.json, the catalog names r1/run1/release.log" in p for p in self.problems(fx)))
        fx.catalog["artifacts"]["run1"]["member"] = "r1/run1/not-in-the-archive.json"
        fx.save_catalog()
        self.assertTrue(any("not in ARCHIVE.sha256" in p for p in self.problems(fx)))

    def test_a_revision_the_catalog_does_not_state_or_that_differs_is_a_revision_mismatch(self):
        fx = Fx(self.d)
        fx.catalog["artifacts"]["run1"]["revision"] = REV_B  # the raw run was made at REV_A
        fx.save_catalog()
        self.assertTrue(any("revision mismatch" in p for p in self.problems(fx)), self.problems(fx))
        fx.catalog["artifacts"]["run1"]["revision"] = "abc123"  # abbreviated: not a revision
        fx.save_catalog()
        self.assertTrue(any("no full revision" in p for p in self.problems(fx)), self.problems(fx))

    def test_a_catalog_that_names_another_manifest_or_member_count_is_refused(self):
        fx = Fx(self.d)
        write(os.path.join(fx.ev, "ARCHIVE.sha256"), slurp(fx.manifest) + "%s  r1/zzz.txt\n" % ("c" * 64))
        evidence.seal(fx.ev)
        problems = self.problems(fx)
        self.assertTrue(any("not the manifest the catalog names" in p for p in problems), problems)
        self.assertTrue(any("lists 3 members" in p for p in problems), problems)

    def test_an_edited_or_unlisted_evidence_file_is_detected_by_the_seal(self):
        fx = Fx(self.d)
        self.assertEqual(fx.run_report().returncode, 0)
        write(os.path.join(fx.ev, "extra.log"), "an unlisted file")
        r = fx.run_report("--check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not listed", r.stderr)
        os.remove(os.path.join(fx.ev, "extra.log"))
        write(os.path.join(fx.ev, "summaries", "run1.json"), slurp(os.path.join(fx.ev, "summaries", "run1.json")) + " ")
        r = fx.run_report("--check")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("digest mismatch: summaries/run1.json", r.stderr)

    def test_the_full_audit_flag_reports_the_archive_audit_and_fails_on_a_bad_archive(self):
        fx = Fx(self.d)
        _, staged = fx.stage(tarball=fx.tar)
        r = fx.run_report("--audit-archive", staged)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("FULL ARCHIVE AUDIT PASSED", r.stdout)
        write(os.path.join(staged, "r1", "run1", "release.log"), "changed after staging\n")
        r = fx.run_report("--audit-archive", staged)
        self.assertEqual(r.returncode, 1)
        self.assertIn("digest mismatch", r.stderr)


class Verdicts(Tmp):
    def test_a_stale_or_hand_edited_report_is_detected(self):
        fx = Fx(self.d)
        self.assertEqual(fx.run_report().returncode, 0)
        self.assertEqual(fx.run_report("--check").returncode, 0)
        with open(fx.out, "a") as fh:
            fh.write("hand edit\n")
        r = fx.run_report("--check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("STALE", r.stderr)
        self.assertEqual(fx.run_report().returncode, 0)
        self.assertEqual(fx.run_report("--check").returncode, 0)

    def test_open_gates_never_read_as_accepted_and_closed_gates_do(self):
        gates = [{"id": "G1", "text": "independent review", "state": "open"}]
        fx = Fx(self.d, gates=gates)
        fx.run_report()
        self.assertIn("CRITERIA MET - ACCEPTANCE PENDING", slurp(fx.out))
        self.assertNotIn("**Overall: ACCEPTED", slurp(fx.out))
        fx.catalog["acceptance_gates"][0]["state"] = "closed"
        fx.save_catalog()
        fx.run_report()
        self.assertIn("**Overall: ACCEPTED.", slurp(fx.out))

    def test_a_failing_criterion_is_not_accepted_even_with_closed_gates(self):
        fx = Fx(self.d, status="FAIL", gates=[{"id": "G1", "text": "t", "state": "closed"}])
        fx.run_report()
        self.assertIn("**Overall: NOT ACCEPTED.", slurp(fx.out))

    def test_an_open_adverse_run_fails_the_criterion_and_a_disposition_makes_it_pass_with_disclosures_not_a_silent_pass(self):
        fx = Fx(self.d, adverse=True)
        fx.run_report()
        text = slurp(fx.out)
        self.assertIn("**FAIL**", text)
        self.assertIn("NOT ACCEPTED", text)
        fx2 = Fx(os.path.join(self.d, "disp"), adverse=True, disposition=True)
        fx2.run_report()
        text2 = slurp(fx2.out)
        self.assertIn("**PASS WITH DISCLOSURES**", text2)
        self.assertIn("owner-approved fixture disposition", text2)
        self.assertIn("A@bad FAIL", text2)  # the adverse run is still listed as the FAIL it was
        self.assertEqual(fx2.run_report("--check").returncode, 0)

    def test_a_criterion_whose_artifact_is_not_in_the_catalog_is_unverified(self):
        fx = Fx(self.d)
        write(fx.criteria, json.dumps({"criteria": [{"id": "C", "group": "g", "text": "t", "evidence": ["A@run1", "A@missing-artifact"]}]}))
        fx.run_report()
        self.assertIn("**UNVERIFIED**", slurp(fx.out))

    def test_a_secret_pattern_is_found_by_the_scanner(self):
        self.assertTrue(evidence.secret_findings("token ghp_" + "a" * 36))
        self.assertTrue(evidence.secret_findings("-----BEGIN " + "RSA PRIVATE KEY-----"))
        self.assertTrue(evidence.secret_findings("x github_pat_" + "A" * 30))
        self.assertEqual(evidence.secret_findings("a clean log line: sha256 " + "a" * 64), [])

    def test_packing_refuses_a_tree_with_a_secret_or_a_symlink(self):
        raw = os.path.join(self.d, "raw")
        write(os.path.join(raw, "a.log"), "fine\n")
        out = os.path.join(self.d, "out")
        os.makedirs(out)
        self.assertEqual(len(evidence.pack([("p", raw)], os.path.join(out, "t.tar.gz"), os.path.join(out, "m"))), 1)
        write(os.path.join(raw, "b.log"), "Authorization: token ghp_" + "b" * 36 + "\n")
        with self.assertRaises(SystemExit):
            evidence.pack([("p", raw)], os.path.join(out, "t2.tar.gz"), os.path.join(out, "m2"))
        os.remove(os.path.join(raw, "b.log"))
        os.symlink("/etc/passwd", os.path.join(raw, "link"))
        with self.assertRaises(SystemExit):
            evidence.pack([("p", raw)], os.path.join(out, "t3.tar.gz"), os.path.join(out, "m3"))

    def test_packing_is_deterministic(self):
        raw = os.path.join(self.d, "raw")
        write(os.path.join(raw, "a.log"), "one\n")
        write(os.path.join(raw, "z", "b.log"), "two\n")
        out = os.path.join(self.d, "out")
        os.makedirs(out)
        evidence.pack([("p", raw)], os.path.join(out, "1.tar.gz"), os.path.join(out, "m1"))
        os.utime(os.path.join(raw, "a.log"), (12345, 12345))
        evidence.pack([("p", raw)], os.path.join(out, "2.tar.gz"), os.path.join(out, "m2"))
        self.assertEqual(evidence.sha256_file(os.path.join(out, "1.tar.gz")), evidence.sha256_file(os.path.join(out, "2.tar.gz")))
        self.assertEqual(slurp(os.path.join(out, "m1")), slurp(os.path.join(out, "m2")))


class Supersession(Tmp):
    """Review 519 F1: a new evidence version (v2) is a superset of the older one (v1). v1 stays unchanged in its own draft release, and the
    committed manifests prove, without reading either archive, that every v1 member is in v2 byte for byte."""

    def make(self):
        fx = Fx(self.d)
        old_manifest = slurp(fx.manifest)
        old = dict(fx.catalog["archive"])
        write(os.path.join(fx.ev, "ARCHIVE.arch-v1.sha256"), old_manifest)
        extra = os.path.join(self.d, "raw2")
        write(os.path.join(extra, "adverse.json"), json.dumps(results_doc("FAIL", REV_B)))
        tar2, man2 = os.path.join(self.d, "out", "arch-v2.tar.gz"), os.path.join(self.d, "out", "ARCHIVE2.sha256")
        evidence.pack([("r1", fx.raw), ("r2", extra)], tar2, man2)
        write(os.path.join(fx.ev, "ARCHIVE.sha256"), slurp(man2))
        fx.catalog["archive"] = dict(old, id="arch-v2", tarball=os.path.basename(tar2), tarball_sha256=evidence.sha256_file(tar2), tarball_bytes=os.path.getsize(tar2),
                                     manifest_sha256=evidence.sha256_file(man2), members=len(evidence.parse_manifest(slurp(man2))[0]),
                                     supersedes={"id": old["id"], "manifest": "ARCHIVE.arch-v1.sha256", "manifest_sha256": evidence.sha256_file(fx.manifest), "tarball": old["tarball"],
                                                 "tarball_sha256": old["tarball_sha256"], "tarball_bytes": old["tarball_bytes"], "members": old["members"]})
        fx.save_catalog()
        return fx

    def test_a_version_that_keeps_every_older_member_is_consistent_and_the_report_says_so(self):
        fx = self.make()
        self.assertEqual(evidence.verify_compact(fx.ev), [])
        self.assertEqual(fx.run_report().returncode, 0)
        text = slurp(fx.out)
        self.assertIn("| supersedes | `arch-v1`", text)
        self.assertIn("contains every one of its members with the identical SHA-256", text)
        self.assertEqual(fx.run_report("--check").returncode, 0)

    def test_a_new_version_that_lost_or_changed_an_older_member_is_refused(self):
        fx = self.make()
        manifest = slurp(os.path.join(fx.ev, "ARCHIVE.sha256")).splitlines()
        # a member of v1 whose digest differs in v2
        changed = [("0" * 64 + "  " + ln.split("  ", 1)[1]) if ln.endswith("r1/run1/release.log") else ln for ln in manifest]
        write(os.path.join(fx.ev, "ARCHIVE.sha256"), "\n".join(changed) + "\n")
        fx.catalog["archive"]["manifest_sha256"] = evidence.sha256_file(os.path.join(fx.ev, "ARCHIVE.sha256"))
        fx.save_catalog()
        self.assertTrue(any("superseded member r1/run1/release.log is different" in p for p in evidence.verify_compact(fx.ev)), evidence.verify_compact(fx.ev))
        # a member of v1 that v2 no longer lists
        gone = [ln for ln in manifest if not ln.endswith("r1/run1/release.log")]
        write(os.path.join(fx.ev, "ARCHIVE.sha256"), "\n".join(gone) + "\n")
        fx.catalog["archive"]["manifest_sha256"] = evidence.sha256_file(os.path.join(fx.ev, "ARCHIVE.sha256"))
        fx.catalog["archive"]["members"] = len(gone)
        fx.save_catalog()
        problems = evidence.verify_compact(fx.ev)
        self.assertTrue(any("superseded member r1/run1/release.log is missing" in p for p in problems), problems)
        self.assertNotEqual(fx.run_report().returncode, 0)

    def test_an_edited_or_missing_older_manifest_or_an_unsafe_name_is_refused(self):
        fx = self.make()
        path = os.path.join(fx.ev, "ARCHIVE.arch-v1.sha256")
        write(path, slurp(path) + "%s  r1/extra.txt\n" % ("d" * 64))
        evidence.seal(fx.ev)
        problems = evidence.verify_compact(fx.ev)
        self.assertTrue(any("not the manifest of the superseded archive" in p for p in problems), problems)
        os.remove(path)
        evidence.seal(fx.ev)
        self.assertTrue(any("superseded archive's manifest ARCHIVE.arch-v1.sha256 is missing" in p for p in evidence.verify_compact(fx.ev)))
        for bad in ("../ARCHIVE.arch-v1.sha256", "ARCHIVE.sha256", "other.txt", "sub/ARCHIVE.x.sha256"):
            fx.catalog["archive"]["supersedes"]["manifest"] = bad
            fx.save_catalog()
            self.assertTrue(any("plain ARCHIVE*.sha256" in p for p in evidence.verify_compact(fx.ev)), bad)
        del fx.catalog["archive"]["supersedes"]["members"]
        fx.save_catalog()
        self.assertTrue(any("supersedes lacks members" in p for p in evidence.verify_compact(fx.ev)))

    def test_the_full_audit_of_the_new_version_covers_the_older_members_too(self):
        fx = self.make()
        problems, staged = fx.stage(tarball=os.path.join(self.d, "out", "arch-v2.tar.gz"))
        self.assertEqual(problems, [])
        self.assertTrue(os.path.exists(os.path.join(staged, "r1", "run1", "release.log")))  # a v1 member, served by v2
        p, counts = evidence.audit_archive(fx.ev, staged)
        self.assertEqual((p, counts["members_verified"]), ([], 3))  # two v1 members and the new one


class Committed(unittest.TestCase):
    """What a fresh clone and pull-request CI can do: the COMPACT verification of the repository's own evidence. It reads no archive."""

    root = os.path.join(HERE, "..", "..")
    ev = os.path.join(root, "docs", "release", "evidence")

    def test_the_committed_evidence_is_compactly_consistent(self):
        self.assertEqual(evidence.verify_compact(self.ev), [])
        self.assertEqual(report.verify_sums(self.ev), [])

    def test_the_committed_report_is_what_the_committed_evidence_produces(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "report.py"), "--evidence", self.ev, "--criteria", os.path.join(HERE, "criteria.json"),
                            "--out", os.path.join(self.root, "docs", "release", "phase1-release-acceptance.md"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NOT read", r.stdout)  # the compact check says what it did not do

    def test_the_committed_evidence_is_small_and_holds_no_raw_run_output(self):
        total, names = 0, []
        for base, _, files in os.walk(self.ev):
            for fn in files:
                total += os.path.getsize(os.path.join(base, fn))
                names.append(os.path.relpath(os.path.join(base, fn), self.ev).replace(os.sep, "/"))
        self.assertLess(total, 400_000, total)
        for n in names:
            # the manifest of the current archive, of any archive it supersedes (ARCHIVE.<id>.sha256), the catalog, the seal and the summaries
            self.assertTrue(n in ("catalog.json", "ARCHIVE.sha256", "SHA256SUMS") or (n.startswith("ARCHIVE.") and n.endswith(".sha256") and "/" not in n) or n.startswith("summaries/"), n)

    def test_the_catalog_keeps_every_adverse_and_historical_run_and_the_disposition_visible(self):
        cat = evidence.load_catalog(self.ev)
        self.assertIn("adverse-vm-diag-loop-1", cat["artifacts"])
        self.assertIn("adverse-vm-diag-loop-2", cat["artifacts"])
        for key in ("round-1-f306a2a", "r2-ab", "vm-run-0d8b431", "vm-run-1a01db9", "records"):
            self.assertIn(key, cat["diagnostics"])
        text = json.dumps(cat["dispositions"])
        for needle in ("2/15", "0/30", "0.106", "669", "191", "NOT met", "NOT exactly reproduced"):
            self.assertIn(needle, text)
        self.assertTrue(all(g["state"] == "open" for g in cat["acceptance_gates"]))  # nothing here closes the review or merge gates
        self.assertIn("NOT EXECUTED", cat["publication"]["status"])


class CommittedVersion2(unittest.TestCase):
    """Review 519 F1/F2/F4 against the repository's own evidence: the omitted adverse hosted run is recorded, its closure is a remediation
    (never silent), the older archive version is provably contained, and every compact file is tracked by a fresh clone."""

    root = Committed.root
    ev = Committed.ev

    def test_the_adverse_hosted_run_of_review_519_is_recorded_and_its_closure_is_a_stated_remediation(self):
        cat = evidence.load_catalog(self.ev)
        a = cat["artifacts"]["adverse-ci-e5e1856"]
        self.assertEqual(a["role"], "adverse")
        self.assertTrue(a["member"].startswith("adverse-ci-e5e1856/"))
        summary = json.load(open(os.path.join(self.ev, a["file"])))
        by_id = {r["id"]: r["status"] for r in summary["results"]}
        for check in ("REL-MATRIX-REST", "REL-MATRIX-PARITY", "REL-MATRIX-POS"):
            self.assertEqual(by_id[check], "FAIL", check)  # the historical result is not rewritten
        crit = {c["id"]: c for c in json.load(open(os.path.join(HERE, "criteria.json")))["criteria"]}
        for cid in ("SH-1", "SH-5", "P1-E1", "P1-E2", "P1-E6"):
            groups = report.adverse_groups(crit[cid])
            self.assertTrue(any(any(r.endswith("@adverse-ci-e5e1856") for r in g["refs"]) for g in groups), cid)
            self.assertTrue(all(report.group_closed(g) for g in groups if g["state"] == "remediated"), cid)
        self.assertEqual(cat["remediations"][0]["id"], "F1 / F2 of review 519")
        self.assertIn("not established", cat["remediations"][0]["not_established"])
        for ref in ("REL-STOP-LONG@vm-amd64", "REL-STOP-LONG@ci-amd64", "REL-STOP-LONG@ci-arm64"):
            self.assertIn(ref, crit["SH-5"]["evidence"])

    def test_the_new_archive_version_supersedes_the_older_one_and_the_older_manifest_is_tracked(self):
        cat = evidence.load_catalog(self.ev)
        sup = cat["archive"]["supersedes"]
        self.assertEqual((cat["archive"]["id"], sup["id"]), ("p120-evidence-v2", "p120-evidence-v1"))
        self.assertTrue(os.path.isfile(os.path.join(self.ev, sup["manifest"])))
        if shutil.which("git") and os.path.exists(os.path.join(self.root, ".git")):  # a directory, or the file of a worktree
            for rel in sorted(os.listdir(self.ev)):
                r = subprocess.run(["git", "-C", self.root, "check-ignore", "-q", "docs/release/evidence/" + rel], capture_output=True)
                self.assertEqual(r.returncode, 1, "%s is ignored by .gitignore, so a fresh clone would not have it" % rel)

    def test_sh_2d_says_the_mechanism_is_evidenced_not_that_the_cause_is_established(self):
        text = open(os.path.join(HERE, "criteria.json")).read() + json.dumps(evidence.load_catalog(self.ev)["findings"]) + open(os.path.join(self.root, "docs", "release-acceptance.md")).read()
        self.assertNotIn("The cause is established", text)
        self.assertNotIn("cause established", text)
        self.assertNotIn("the cause is established", text)
        self.assertIn("mechanism is evidenced", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
