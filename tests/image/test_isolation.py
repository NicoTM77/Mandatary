#!/usr/bin/env python3
"""Hermetic tests of the acceptance harness's isolation guard (S1.4 / SELF-13). No Docker daemon is used: a
fake `docker` executable answers `docker info` and records every invocation, so the tests can prove what the
harness did and, above all, did NOT do (no container, network, file or removal on a refused daemon).

    python3 tests/image/test_isolation.py
"""
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import isolation  # noqa: E402

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_DIR"]
with open(os.path.join(d, "calls.log"), "a") as fh:
    fh.write(json.dumps({"argv": sys.argv[1:], "DOCKER_HOST": os.environ.get("DOCKER_HOST"), "DOCKER_CONTEXT": os.environ.get("DOCKER_CONTEXT")}) + "\n")
args = sys.argv[1:]
if args[:2] == ["--host", args[1]]:
    args = args[2:]
if args[:1] == ["info"]:
    seq = os.path.join(d, "info.seq")
    docs = json.load(open(seq))
    doc = docs.pop(0) if len(docs) > 1 else docs[0]
    json.dump(docs if docs else [doc], open(seq, "w"))
    print(json.dumps(doc))
    sys.exit(0)
if args[:1] == ["version"]:
    print("29.9.3 api 1.56 linux/amd64")
sys.exit(0)
'''

GOOD = {"ID": "FIXTURE-DAEMON-ID-0001", "Name": "mandatary-test-vm", "OperatingSystem": "Ubuntu 26.04.1 LTS", "KernelVersion": "7.0.0-generic", "ServerVersion": "29.9.3"}


class Fixture:
    def __init__(self, tc, infos):
        # Under $HOME, not /tmp: the harness (like the product) refuses a --work path beneath a world-writable directory.
        self.tmp = tempfile.mkdtemp(prefix="isotest", dir=os.path.expanduser("~"))
        tc.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        exe = os.path.join(self.bin, "docker")
        with open(exe, "w") as fh:
            fh.write(FAKE_DOCKER)
        os.chmod(exe, os.stat(exe).st_mode | stat.S_IXUSR)
        self.sock = os.path.join(self.tmp, "f.sock")
        self.listener = socket.socket(socket.AF_UNIX)  # a real socket node: the guard refuses anything else
        self.listener.bind(self.sock)
        tc.addCleanup(self.listener.close)
        self.set_infos(infos)
        self.env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_DIR=self.tmp)

    def set_infos(self, infos):
        with open(os.path.join(self.tmp, "info.seq"), "w") as fh:
            json.dump(infos, fh)

    @property
    def endpoint(self):
        return "unix://" + self.sock

    def calls(self):
        p = os.path.join(self.tmp, "calls.log")
        if not os.path.exists(p):
            return []
        with open(p) as fh:
            return [json.loads(line) for line in fh]

    def run_harness(self, *extra, endpoint=None):
        work = os.path.join(self.tmp, "work")
        results = os.path.join(self.tmp, "results.json")
        cmd = [sys.executable, os.path.join(HERE, "acceptance.py"), "--image", "mandatary:test", "--platform", "linux/amd64",
               "--repo", self.tmp, "--work", work, "--sha", "0" * 40, "--scenarios", "IMG", "--results", results]
        if endpoint is not False:
            cmd += ["--docker-host", endpoint or self.endpoint]
        cmd += list(extra)
        p = subprocess.run(cmd, capture_output=True, text=True, env=self.env, timeout=120)
        doc = None
        if os.path.exists(results):
            with open(results) as fh:
                doc = json.load(fh)
        return p, doc, work


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture(self, [GOOD])
        for k in ("DOCKER_HOST", "DOCKER_CONTEXT"):
            self._saved = getattr(self, "_saved", {})
            self._saved[k] = os.environ.pop(k, None)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = self.fx.bin + os.pathsep + old_path
        os.environ["FAKE_DIR"] = self.fx.tmp
        self.addCleanup(lambda: (os.environ.__setitem__("PATH", old_path), os.environ.pop("FAKE_DIR", None),
                                 [os.environ.__setitem__(k, v) for k, v in self._saved.items() if v is not None]))

    def test_declared_daemon_by_id_or_name_is_accepted(self):
        self.assertEqual(isolation.verify(self.fx.endpoint, expect_id=GOOD["ID"])["ID"], GOOD["ID"])
        self.assertEqual(isolation.verify(self.fx.endpoint, expect_name=GOOD["Name"])["Name"], GOOD["Name"])

    def test_a_different_daemon_is_refused(self):
        with self.assertRaises(isolation.Refused):
            isolation.verify(self.fx.endpoint, expect_id="SOME-OTHER-DAEMON")
        with self.assertRaises(isolation.Refused):
            isolation.verify(self.fx.endpoint, expect_name="unraid-tower-but-not-the-declared-name")

    def test_an_expectation_is_mandatory(self):
        with self.assertRaises(isolation.Refused):
            isolation.verify(self.fx.endpoint)

    def test_unraid_is_refused_even_when_the_declared_identity_matches(self):
        for field in ("Name", "OperatingSystem", "KernelVersion"):
            bad = dict(GOOD, **{field: "Unraid 7.1.2" if field != "Name" else "Tower-unRAID"})
            self.fx.set_infos([bad])
            with self.assertRaises(isolation.Refused, msg=field):
                isolation.verify(self.fx.endpoint, expect_id=GOOD["ID"])

    def test_no_daemon_id_is_refused(self):
        self.fx.set_infos([dict(GOOD, ID="")])
        with self.assertRaises(isolation.Refused):
            isolation.verify(self.fx.endpoint, expect_name=GOOD["Name"])

    def test_only_an_explicit_absolute_unix_socket_is_accepted(self):
        for ep in ("tcp://127.0.0.1:2375", "ssh://root@host", "unix://relative.sock", "/var/run/docker.sock", "", None,
                   "unix:///tmp/a/../b.sock", "unix:///"):
            with self.assertRaises(isolation.Refused, msg=repr(ep)):
                isolation.verify(ep, expect_id=GOOD["ID"])

    def test_a_missing_socket_is_refused(self):
        with self.assertRaises(isolation.Refused):
            isolation.verify("unix://" + self.fx.tmp + "/absent.sock", expect_id=GOOD["ID"])

    def test_unsafe_ancestors_are_reported_and_safe_ones_are_not(self):
        safe = os.path.join(self.fx.tmp, "safe")
        os.makedirs(safe, mode=0o700)
        self.assertEqual(isolation.unsafe_ancestors(os.path.join(safe, "work")), [])
        os.chmod(safe, 0o770)
        self.assertEqual([d for d, _ in isolation.unsafe_ancestors(os.path.join(safe, "work"))], [safe])
        os.chmod(safe, 0o707)
        self.assertEqual([d for d, _ in isolation.unsafe_ancestors(os.path.join(safe, "work"))], [safe])
        os.chmod(safe, 0o700)
        link = os.path.join(self.fx.tmp, "link")
        os.symlink(safe, link)
        self.assertEqual([d for d, _ in isolation.unsafe_ancestors(os.path.join(link, "work"))], [link])

    def test_the_ambient_endpoint_is_never_used(self):
        os.environ["DOCKER_HOST"] = "tcp://203.0.113.9:2375"
        os.environ["DOCKER_CONTEXT"] = "production"
        isolation.verify(self.fx.endpoint, expect_id=GOOD["ID"])
        (call,) = self.fx.calls()
        self.assertEqual(call["argv"][:3], ["--host", self.fx.endpoint, "info"])
        self.assertIsNone(call["DOCKER_HOST"])
        self.assertIsNone(call["DOCKER_CONTEXT"])


class HarnessTests(unittest.TestCase):
    def test_the_endpoint_argument_is_mandatory_and_nothing_is_created(self):
        fx = Fixture(self, [GOOD])
        p, doc, work = fx.run_harness("--expect-daemon-id", GOOD["ID"], endpoint=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--docker-host", p.stderr)
        self.assertEqual(fx.calls(), [])
        self.assertFalse(os.path.exists(work))

    def test_an_expectation_argument_is_mandatory(self):
        fx = Fixture(self, [GOOD])
        p, doc, work = fx.run_harness()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--expect-daemon-id", p.stderr)
        self.assertEqual(fx.calls(), [])
        self.assertFalse(os.path.exists(work))

    def test_a_wrong_daemon_aborts_before_any_container_network_or_directory(self):
        fx = Fixture(self, [GOOD])
        p, doc, work = fx.run_harness("--expect-daemon-id", "NOT-THE-FIXTURE")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual([i["id"] for i in doc["results"]], ["ISO-00"])
        self.assertEqual(doc["results"][0]["status"], "FAIL")
        self.assertEqual(doc["pass"], 0)
        self.assertFalse(os.path.exists(work), "the work directory must not be created on a refused daemon")
        verbs = {c["argv"][2] for c in fx.calls()}
        self.assertEqual(verbs, {"info"}, "only the identity query may reach a refused daemon, saw %s" % sorted(verbs))

    def test_an_unraid_daemon_is_refused_before_setup(self):
        fx = Fixture(self, [dict(GOOD, OperatingSystem="Unraid 7.1")])
        p, doc, work = fx.run_harness("--expect-daemon-id", GOOD["ID"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual([i["id"] for i in doc["results"]], ["ISO-00"])
        self.assertEqual({c["argv"][2] for c in fx.calls()}, {"info"})

    def test_a_daemon_that_changes_before_cleanup_is_never_cleaned_up(self):
        # First answer (before setup) is the fixture; every later one is a different daemon.
        fx = Fixture(self, [GOOD, dict(GOOD, ID="A-DIFFERENT-DAEMON")])
        p, doc, work = fx.run_harness("--expect-daemon-id", GOOD["ID"])
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        ids = [i["id"] for i in doc["results"]]
        self.assertIn("ISO-01", ids)
        self.assertEqual([i for i in doc["results"] if i["id"] == "ISO-01"][0]["status"], "FAIL")
        for c in fx.calls():
            verb = [a for a in c["argv"][2:] if not a.startswith("-")][0]
            self.assertNotIn(verb, ("rm", "stop", "network", "kill", "compose"), "cleanup ran on a changed daemon: %s" % c["argv"])

    def test_a_group_writable_parent_of_the_work_directory_is_named_before_anything_is_created(self):
        fx = Fixture(self, [GOOD])
        parent = os.path.join(fx.tmp, "shared")
        os.makedirs(parent)
        os.chmod(parent, 0o775)  # what `mkdir -p` makes under umask 0002
        results = os.path.join(fx.tmp, "results.json")
        work = os.path.join(parent, "work")
        p = subprocess.run([sys.executable, os.path.join(HERE, "acceptance.py"), "--image", "mandatary:test", "--platform", "linux/amd64",
                            "--repo", fx.tmp, "--work", work, "--sha", "0" * 40, "--scenarios", "IMG", "--results", results,
                            "--docker-host", fx.endpoint, "--expect-daemon-id", GOOD["ID"]], capture_output=True, text=True, env=fx.env, timeout=120)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        with open(results) as fh:
            doc = json.load(fh)
        self.assertEqual([i["id"] for i in doc["results"]], ["WORK-00"])
        self.assertIn("0775", doc["results"][0]["detail"])
        self.assertFalse(os.path.exists(work))
        self.assertEqual({c["argv"][2] for c in fx.calls()}, {"info"})

    def test_every_docker_call_names_the_explicit_endpoint(self):
        fx = Fixture(self, [GOOD])
        fx.env["DOCKER_HOST"] = "tcp://203.0.113.9:2375"
        fx.env["DOCKER_CONTEXT"] = "production"
        fx.run_harness("--expect-daemon-id", GOOD["ID"])
        calls = fx.calls()
        self.assertGreaterEqual(len(calls), 2)
        for c in calls:
            self.assertEqual(c["argv"][:2], ["--host", fx.endpoint], c["argv"])
            self.assertIsNone(c["DOCKER_CONTEXT"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
