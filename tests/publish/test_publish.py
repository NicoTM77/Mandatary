#!/usr/bin/env python3
"""Hermetic tests (no Docker, no network, no credential) of the dev-image publication logic in scripts/publish_dev_image.py.

The docker CLI and git are replaced by a fake registry that behaves like the real one where it matters (a push stores a manifest whose
config is the loaded image's config, `imagetools create` composes an index from manifests that exist, a raw inspect returns the stored
bytes or "not found"). Each positive case has negative twins, and the mutating calls are checked for ORDER: nothing is written to the dev
tag unless both platforms were staged and verified, and nothing touches a registry before the tested archives were verified.

    python3 tests/publish/test_publish.py
"""
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "scripts"))
import publish_dev_image as pub  # noqa: E402

SHA = "1" * 40
OLD = "2" * 40
NEW = "3" * 40
TOKEN = "tok-SECRET-0123456789"
ALL_OK = {j: {"result": "success", "outputs": {}} for j in pub.REQUIRED_JOBS}


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def env(**kw):
    e = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": pub.REPOSITORY, "GITHUB_SHA": SHA,
         "NEEDS_RESULTS": json.dumps(ALL_OK), "GITHUB_TOKEN": TOKEN, "GITHUB_ACTOR": "github-actions[bot]"}
    e.update(kw)
    return {k: v for k, v in e.items() if v is not None}


def config_bytes(arch, revision, source=pub.SOURCE_URL, os_="linux", extra=""):
    return json.dumps({"architecture": arch, "os": os_, "config": {"Labels": {pub.REVISION_LABEL: revision, pub.SOURCE_LABEL: source}}, "rootfs": {"type": "layers", "diff_ids": []}, "x": extra}, sort_keys=True).encode()


def write_classic(path, arch, revision, source=pub.SOURCE_URL, os_="linux", extra="", images=1, repo_tag=None):
    cfg = config_bytes(arch, revision, source, os_, extra)
    layer = b"layer-" + arch.encode() + extra.encode()
    with tarfile.open(path, "w") as tf:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        cfg_name = hashlib.sha256(cfg).hexdigest() + ".json"
        add(cfg_name, cfg)
        add("layer0/layer.tar", layer)
        entry = {"Config": cfg_name, "RepoTags": [repo_tag or pub.LOCAL_TAG % arch], "Layers": ["layer0/layer.tar"]}
        add("manifest.json", json.dumps([entry] * images).encode())
    return sha(cfg)


def write_oci(path, arch, revision):
    cfg = config_bytes(arch, revision)
    layer = b"oci-layer"
    mf = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"mediaType": "x", "digest": sha(cfg), "size": len(cfg)},
                     "layers": [{"mediaType": "y", "digest": sha(layer), "size": len(layer)}]}).encode()
    idx = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": sha(mf), "size": len(mf)}]}).encode()
    with tarfile.open(path, "w") as tf:
        for name, data in (("index.json", idx), ("blobs/sha256/" + sha(mf).split(":")[1], mf), ("blobs/sha256/" + sha(cfg).split(":")[1], cfg),
                           ("blobs/sha256/" + sha(layer).split(":")[1], layer)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return sha(cfg)


def proc(rc=0, out=b"", err=b""):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class FakeDocker:
    """A stand-in for the docker CLI plus a tiny registry. `calls` records (args, input); `fail` names operations that fail."""

    def __init__(self, tarballs=None):
        self.calls, self.fail, self.tarballs = [], set(), dict(tarballs or {})
        self.local, self.manifests, self.tags, self.platform = {}, {}, {}, {}
        self.config_dir = None
        self.config_dirs_seen = []
        self.login_dir_mode = None
        self.push_as_index = None  # the registry stores an index where a single image manifest was pushed
        self.after_stage = None  # a hook that runs after the arm64 staging push (to simulate a concurrent writer)
        self.wrong_config_for = None  # arch whose pushed manifest is served with a different config digest
        self.bad_index = False
        self.inspect_error = None

    def names(self):
        return [" ".join(a[:3]) if a[0] == "buildx" else a[0] for a, _ in self.calls]

    def __call__(self, args, input=None):
        self.calls.append((list(args), input))
        if self.config_dir:
            self.config_dirs_seen.append(self.config_dir)
        op = args[0]
        if op == "login" and self.config_dir:
            self.login_dir_mode = stat.S_IMODE(os.stat(self.config_dir).st_mode)
        if op == "buildx":
            op = "buildx-" + args[2]
        if op in self.fail:
            return proc(1, b"", b"simulated failure of " + op.encode())
        return getattr(self, "do_" + op.replace("-", "_"))(args[1:], input)

    def do_save(self, a, _):
        out, image = a[1], a[2]
        with open(self.tarballs[image], "rb") as src, open(out, "wb") as dst:
            dst.write(src.read())
        return proc()

    def do_load(self, a, _):
        facts = pub.inspect_saved(a[1])
        with tarfile.open(a[1]) as tf:
            tags = json.load(tf.extractfile("manifest.json"))[0]["RepoTags"]
        for t in tags:
            self.local[t] = facts
        return proc(0, b"Loaded image: " + tags[0].encode())

    def do_tag(self, a, _):
        if a[0] not in self.local:
            return proc(1, b"", b"No such image")
        self.local[a[1]] = self.local[a[0]]
        return proc()

    def do_push(self, a, _):
        ref = a[0]
        facts = self.local[ref]
        cfg = facts["config_digest"]
        if self.wrong_config_for == facts["architecture"]:
            cfg = sha(b"someone else's config")
        doc = {"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"digest": cfg, "size": 1},
               "layers": [{"digest": sha(b"l" + facts["architecture"].encode()), "size": 1}]}
        mf = json.dumps(doc, sort_keys=True).encode()
        digest = sha(mf)
        self.manifests[digest] = mf
        self.platform[digest] = (facts["os"], facts["architecture"])
        if self.push_as_index == "nested":  # the listed child is itself an index that merely carries the tested config and a layer
            nested = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": [{"digest": sha(b"n"), "platform": {"os": "linux", "architecture": facts["architecture"]}}],
                                 "config": doc["config"], "layers": doc["layers"]}, sort_keys=True).encode()
            self.manifests[sha(nested)] = nested
            digest, mf = sha(nested), nested
            self.platform[digest] = (facts["os"], facts["architecture"])
        if self.push_as_index:  # a containerd-store daemon pushes the image as a one-platform index (optionally with an attestation beside it)
            entry = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest, "size": len(mf), "platform": {"os": facts["os"], "architecture": facts["architecture"]}}
            att = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": sha(b"attestation"), "size": 9, "platform": {"os": "unknown", "architecture": "unknown"},
                   "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": digest}}
            entries = {"nested": [entry], "wrapped": [entry], "attested": [entry, att], "two": [entry, dict(entry, digest=sha(b"second"))], "extra": [entry, {"digest": sha(b"x"), "platform": {"os": "linux", "architecture": "riscv64"}}],
                       "wrongplat": [dict(entry, platform={"os": "linux", "architecture": "s390x"})], "empty": [], "attonly": [att]}[self.push_as_index]
            idx = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": entries}, sort_keys=True).encode()
            self.manifests[sha(idx)] = idx
            self.platform[sha(idx)] = self.platform[digest]
            digest = sha(idx)
        self.tags[ref] = digest
        if self.after_stage and facts["architecture"] == "arm64":
            self.after_stage(self)
        return proc(0, ("The push refers to repository\n%s: digest: %s size: 523\n" % (ref.rsplit(":", 1)[1], digest)).encode())

    def do_buildx_inspect(self, a, _):
        ref = a[-1]
        if self.inspect_error and ref.endswith(":dev"):
            return proc(1, b"", self.inspect_error)
        if "@" in ref:
            d = ref.split("@", 1)[1]
            if d in self.manifests:
                return proc(0, self.manifests[d])
        elif ref in self.tags:
            return proc(0, self.manifests[self.tags[ref]])
        return proc(1, b"", ("%s: not found" % ref).encode())

    def do_buildx_create(self, a, _):
        tag = a[a.index("--tag") + 1]
        ann = {}
        for i, x in enumerate(a):
            if x == "--annotation":
                k, v = a[i + 1].split(":", 1)[1].split("=", 1)
                ann[k] = v
        srcs = [x for x in a if "@sha256:" in x]
        entries = []
        for s in srcs:
            d = s.split("@", 1)[1]
            if d not in self.manifests:
                return proc(1, b"", b"not found: " + s.encode())
            os_, arch = self.platform[d]
            if self.bad_index:
                arch = "amd64"
            entries.append({"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": d, "size": len(self.manifests[d]), "platform": {"os": os_, "architecture": arch}})
        idx = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": entries, "annotations": ann}, sort_keys=True).encode()
        self.manifests[sha(idx)] = idx
        self.tags[tag] = sha(idx)
        return proc()

    def do_login(self, a, input):
        return proc()

    def do_logout(self, a, _):
        return proc()

    def writes(self):
        """Names of the calls that write to a registry."""
        return [n for n in self.names() if n in ("push", "buildx imagetools create", "login")]

    def dev(self):
        return self.tags.get("%s:%s" % (pub.IMAGE, pub.TAG))


class FakeGit:
    def __init__(self, ancestors=(), unknown=False):
        self.ancestors, self.unknown, self.calls = set(ancestors), unknown, []

    def __call__(self, args, input=None):
        self.calls.append(args)
        if self.unknown:
            return proc(128, b"", b"fatal: Not a valid commit name")
        old, new = args[-2], args[-1]
        return proc(0 if old == new or (old, new) in self.ancestors else 1)  # like git: a commit is an ancestor of itself


class Tmp(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.d = self._t.name

    def build_tested(self, sha_=SHA, amd64=None, arm64=None, record_sha=None):
        """Build the two tested archives as the Image jobs would: `record` over the fake docker. Returns (tested_dir, fake_docker)."""
        build = os.path.join(self.d, "build")
        os.makedirs(build, exist_ok=True)
        tars = {}
        for arch, kw in (("amd64", amd64 or {}), ("arm64", arm64 or {})):
            tars[pub.LOCAL_TAG % arch] = os.path.join(build, "src-%s.tar" % arch)
            write_classic(tars[pub.LOCAL_TAG % arch], arch, kw.get("revision", sha_), **{k: v for k, v in kw.items() if k != "revision"})
        fd = FakeDocker(tars)
        out = os.path.join(self.d, "promote")
        for arch in pub.ARCHES:
            pub.record(fd, pub.LOCAL_TAG % arch, arch, os.path.join(out, "tested-image-" + arch), record_sha or sha_)
        return out, FakeDocker()


class Gate(unittest.TestCase):
    def test_a_successful_push_to_main_of_the_canonical_repository_opens_the_gate(self):
        self.assertEqual(pub.gate(env()), SHA)

    def test_every_other_event_ref_or_repository_is_refused(self):
        cases = {
            "pull_request": {"GITHUB_EVENT_NAME": "pull_request"},
            "pull_request_target": {"GITHUB_EVENT_NAME": "pull_request_target"},
            "workflow_dispatch": {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            "schedule": {"GITHUB_EVENT_NAME": "schedule"},
            "branch push": {"GITHUB_REF": "refs/heads/feature"},
            "a branch named like main": {"GITHUB_REF": "refs/heads/main2"},
            "tag push": {"GITHUB_REF": "refs/tags/v1.0.0"},
            "pull ref": {"GITHUB_REF": "refs/pull/25/merge"},
            "fork": {"GITHUB_REPOSITORY": "someone/Mandatary"},
            "case-changed repository": {"GITHUB_REPOSITORY": "nicotm77/mandatary"},
            "pr base ref set": {"GITHUB_BASE_REF": "main"},
            "pr head ref set": {"GITHUB_HEAD_REF": "feature"},
            "no commit": {"GITHUB_SHA": "abc"},
            "no needs": {"NEEDS_RESULTS": "{}"},
            "needs not json": {"NEEDS_RESULTS": "not json"},
            "needs not an object": {"NEEDS_RESULTS": "[]"},
        }
        for name, over in cases.items():
            with self.subTest(name):
                with self.assertRaises(pub.Refuse):
                    pub.gate(env(**over))

    def test_a_failed_cancelled_skipped_or_missing_required_job_refuses(self):
        for job in pub.REQUIRED_JOBS:
            for bad in ("failure", "cancelled", "skipped", None, "", "neutral"):
                with self.subTest(job=job, result=bad):
                    needs = json.loads(json.dumps(ALL_OK))
                    if bad is None:
                        del needs[job]
                    else:
                        needs[job]["result"] = bad
                    with self.assertRaises(pub.Refuse):
                        pub.gate(env(NEEDS_RESULTS=json.dumps(needs)))
            with self.subTest(job=job, result="not an object"):
                needs = dict(ALL_OK, **{job: "success"})
                with self.assertRaises(pub.Refuse):
                    pub.gate(env(NEEDS_RESULTS=json.dumps(needs)))

    def test_both_architecture_jobs_and_every_gate_are_required(self):
        self.assertEqual(set(pub.REQUIRED_JOBS), {"baseline", "negative-control", "storage-arm64", "image", "security"})

    def test_the_cli_gate_exits_1_for_a_pull_request_and_0_for_main(self):
        with mock.patch.dict(os.environ, env(), clear=True):
            self.assertEqual(pub.main(["gate"]), 0)
        with mock.patch.dict(os.environ, env(GITHUB_EVENT_NAME="pull_request"), clear=True):
            self.assertEqual(pub.main(["gate"]), 1)


class SavedImage(Tmp):
    def test_the_config_digest_is_computed_from_the_archive_for_both_layouts(self):
        p = os.path.join(self.d, "c.tar")
        digest = write_classic(p, "amd64", SHA)
        f = pub.inspect_saved(p)
        self.assertEqual((f["config_digest"], f["os"], f["architecture"], f["labels"][pub.REVISION_LABEL]), (digest, "linux", "amd64", SHA))
        q = os.path.join(self.d, "o.tar")
        digest = write_oci(q, "arm64", SHA)
        self.assertEqual(pub.inspect_saved(q)["config_digest"], digest)

    def test_a_config_that_is_not_what_its_file_name_claims_gets_its_own_digest(self):
        p = os.path.join(self.d, "c.tar")
        cfg = config_bytes("amd64", SHA)
        with tarfile.open(p, "w") as tf:
            for name, data in (("0000.json", cfg), ("manifest.json", json.dumps([{"Config": "0000.json", "RepoTags": ["x:y"], "Layers": []}]).encode())):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        self.assertEqual(pub.inspect_saved(p)["config_digest"], sha(cfg))

    def test_unreadable_multi_image_or_unknown_archives_are_refused(self):
        p = os.path.join(self.d, "two.tar")
        write_classic(p, "amd64", SHA, images=2)
        with self.assertRaises(pub.Refuse):
            pub.inspect_saved(p)
        junk = os.path.join(self.d, "junk.tar")
        with open(junk, "wb") as fh:
            fh.write(b"not a tar")
        with self.assertRaises(pub.Refuse):
            pub.inspect_saved(junk)
        empty = os.path.join(self.d, "empty.tar")
        with tarfile.open(empty, "w"):
            pass
        with self.assertRaises(pub.Refuse):
            pub.inspect_saved(empty)

    def test_facts_must_be_this_commit_this_platform_and_this_repository(self):
        f = {"os": "linux", "architecture": "amd64", "labels": {pub.REVISION_LABEL: SHA, pub.SOURCE_LABEL: pub.SOURCE_URL}}
        pub.check_facts(f, "amd64", SHA)
        for name, bad in (("arch", dict(f, architecture="arm64")), ("os", dict(f, os="windows")), ("revision", dict(f, labels={pub.REVISION_LABEL: OLD, pub.SOURCE_LABEL: pub.SOURCE_URL})),
                          ("source", dict(f, labels={pub.REVISION_LABEL: SHA, pub.SOURCE_LABEL: "https://github.com/other/repo"})), ("no labels", dict(f, labels={}))):
            with self.subTest(name):
                with self.assertRaises(pub.Refuse):
                    pub.check_facts(bad, "amd64", SHA)

    def test_record_refuses_an_image_of_another_commit(self):
        tar = os.path.join(self.d, "s.tar")
        write_classic(tar, "amd64", OLD)
        with self.assertRaises(pub.Refuse):
            pub.record(FakeDocker({"i": tar}), "i", "amd64", os.path.join(self.d, "o"), SHA)

    def test_record_refuses_when_docker_save_fails_or_the_arch_is_unknown(self):
        tar = os.path.join(self.d, "s.tar")
        write_classic(tar, "amd64", SHA)
        fd = FakeDocker({"i": tar})
        fd.fail.add("save")
        with self.assertRaises(pub.Refuse):
            pub.record(fd, "i", "amd64", os.path.join(self.d, "o"), SHA)
        with self.assertRaises(pub.Refuse):
            pub.record(FakeDocker({"i": tar}), "i", "riscv64", os.path.join(self.d, "o"), SHA)

    def test_load_record_verifies_the_archive_against_its_record(self):
        out, _ = self.build_tested()
        rec, tar = pub.load_record(out, "amd64", SHA)
        self.assertEqual(rec["config_digest"], pub.inspect_saved(tar)["config_digest"])
        with self.assertRaises(pub.Refuse):  # the record is for another commit than the one being published
            pub.load_record(out, "amd64", NEW)
        with self.assertRaises(pub.Refuse):  # the record is for the other architecture
            pub.load_record(out, "arm64", NEW)
        with open(tar, "ab") as fh:
            fh.write(b"x")
        with self.assertRaises(pub.Refuse):  # a tampered archive is no longer the recorded one
            pub.load_record(out, "amd64", SHA)

    def test_a_replaced_archive_with_a_matching_size_but_another_config_is_refused(self):
        out, _ = self.build_tested()
        tar = os.path.join(out, "tested-image-arm64", "image-arm64.tar")
        other = os.path.join(self.d, "other.tar")
        write_classic(other, "arm64", SHA, extra="different")
        with open(other, "rb") as src, open(tar, "wb") as dst:
            dst.write(src.read())
        with self.assertRaises(pub.Refuse):
            pub.load_record(out, "arm64", SHA)  # SHA-256 of the archive no longer equals the recorded one

    def test_a_record_whose_config_digest_is_not_the_archives_is_refused_even_with_the_right_archive_digest(self):
        out, _ = self.build_tested()
        rec_path = os.path.join(out, "tested-image-amd64", "image-amd64.json")
        with open(rec_path) as fh:
            rec = json.load(fh)
        rec["config_digest"] = sha(b"another config")
        with open(rec_path, "w") as fh:
            json.dump(rec, fh)
        with self.assertRaises(pub.Refuse) as cm:
            pub.load_record(out, "amd64", SHA)
        self.assertIn("recorded config digest", str(cm.exception))

    def test_a_missing_record_or_archive_is_refused(self):
        with self.assertRaises(pub.Refuse):
            pub.load_record(os.path.join(self.d, "nothing"), "amd64", SHA)


class Publish(Tmp):
    def run_publish(self, fd=None, git=None, tested=None, e=None, **kw):
        out, fresh = self.build_tested() if tested is None else (tested, None)
        fd = fd or fresh
        self.logs = []
        return pub.publish(fd, git or FakeGit(), out, SHA, e or env(), log=self.logs.append, **kw), fd

    def test_a_first_publication_stages_both_platforms_then_writes_one_index_last(self):
        res, fd = self.run_publish()
        self.assertTrue(res["published"])
        names = fd.names()
        creates = [i for i, n in enumerate(names) if n == "buildx imagetools create"]
        pushes = [i for i, n in enumerate(names) if n == "push"]
        self.assertEqual((len(creates), len(pushes)), (1, 2))
        self.assertGreater(creates[0], max(pushes))  # the dev tag is written once, after BOTH platforms were staged
        self.assertEqual(names[-1], "logout")
        idx = json.loads(fd.manifests[fd.dev()])
        self.assertEqual(idx["mediaType"], pub.OCI_INDEX)
        self.assertEqual(sorted((m["platform"]["os"], m["platform"]["architecture"]) for m in idx["manifests"]), [("linux", "amd64"), ("linux", "arm64")])
        self.assertEqual(idx["annotations"][pub.ANN_REVISION], SHA)
        self.assertEqual(idx["annotations"][pub.ANN_SOURCE], pub.SOURCE_URL)
        self.assertEqual(res["index"], fd.dev())
        for arch in pub.ARCHES:  # the staged manifest holds exactly the tested config
            mf = json.loads(fd.manifests[res["staged"][arch]])
            with open(os.path.join(self.d, "promote", "tested-image-" + arch, "image-%s.json" % arch)) as fh:
                rec = json.load(fh)
            self.assertEqual(mf["config"]["digest"], rec["config_digest"])
        self.assertEqual(set(t for t in fd.tags if ":build-" in t), {"%s:build-%s-%s" % (pub.IMAGE, SHA, a) for a in pub.ARCHES})
        self.assertNotIn("%s:latest" % pub.IMAGE, fd.tags)  # no other tag than dev (and the per-commit staging tags)

    def test_nothing_touches_a_registry_before_both_tested_archives_were_verified(self):
        out, _ = self.build_tested()
        with open(os.path.join(out, "tested-image-arm64", "image-arm64.tar"), "ab") as fh:
            fh.write(b"tamper")
        fd = FakeDocker()
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertEqual(fd.calls, [])  # no login, no inspect, no push

    def test_the_token_goes_to_login_on_stdin_only_and_never_into_arguments_logs_or_a_kept_config(self):
        res, fd = self.run_publish()
        logins = [(a, i) for a, i in fd.calls if a[0] == "login"]
        self.assertEqual(len(logins), 1)
        args, stdin = logins[0]
        self.assertIn("--password-stdin", args)
        self.assertEqual(stdin, TOKEN.encode())
        for a, _ in fd.calls:
            self.assertNotIn(TOKEN, " ".join(a))
        self.assertNotIn(TOKEN, "\n".join(self.logs))
        self.assertNotIn(TOKEN, json.dumps(res))
        self.assertEqual(len(set(fd.config_dirs_seen)), 1)  # one private Docker config for the whole run ...
        self.assertFalse(os.path.exists(fd.config_dirs_seen[0]))  # ... removed at the end
        self.assertIsNone(fd.config_dir)
        self.assertLess(fd.names().index("login"), fd.names().index("push"))

    def test_a_missing_token_refuses_before_any_registry_call(self):
        out, fd = self.build_tested()
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(), out, SHA, env(GITHUB_TOKEN=None), log=lambda *_: None)
        self.assertEqual(fd.calls, [])

    def test_a_failed_arm64_staging_leaves_dev_untouched_and_never_creates_the_index(self):
        out, fd = self.build_tested()
        orig = fd.do_push

        def push(a, i):
            return proc(1, b"", b"denied") if a[0].endswith("-arm64") else orig(a, i)

        fd.do_push = push
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("buildx imagetools create", fd.names())
        self.assertIsNone(fd.dev())
        self.assertEqual(fd.names()[-1], "logout")  # and the credential is still dropped

    def test_a_pushed_manifest_that_does_not_hold_the_tested_config_is_refused(self):
        out, fd = self.build_tested()
        fd.wrong_config_for = "arm64"
        with self.assertRaises(pub.Refuse) as cm:
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("not the tested", str(cm.exception))
        self.assertIsNone(fd.dev())
        self.assertNotIn("buildx imagetools create", fd.names())

    def test_an_image_pushed_as_a_one_platform_index_is_promoted_by_its_image_manifest(self):
        for mode in ("wrapped", "attested"):  # the containerd image store, with and without a build attestation beside the image
            with self.subTest(mode):
                out, fd = self.build_tested()
                fd.push_as_index = mode
                res = pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                idx = json.loads(fd.manifests[fd.dev()])
                self.assertEqual(len(idx["manifests"]), 2)  # the dev index holds the two image manifests, never the wrapper indexes or the attestations
                for arch in pub.ARCHES:
                    mf = json.loads(fd.manifests[res["staged"][arch]])
                    self.assertNotIn("manifests", mf)
                    self.assertEqual(mf["mediaType"], "application/vnd.docker.distribution.manifest.v2+json")

    def test_a_pushed_index_in_any_other_shape_is_refused(self):
        for mode in ("two", "extra", "wrongplat", "empty", "attonly", "nested"):
            with self.subTest(mode):
                out, fd = self.build_tested()
                fd.push_as_index = mode
                with self.assertRaises(pub.Refuse):
                    pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                self.assertIsNone(fd.dev())
                self.assertNotIn("buildx imagetools create", fd.names())

    def test_a_listed_child_served_with_other_bytes_than_its_digest_is_refused(self):
        out, fd = self.build_tested()
        fd.push_as_index = "wrapped"
        orig = fd.do_buildx_inspect

        def inspect(a, i):
            r = orig(a, i)
            if "@" in a[-1] and r.returncode == 0 and b'"manifests"' not in r.stdout:
                return proc(0, r.stdout + b" ")  # only the image manifest is tampered with; the index above it is served as pushed
            return r

        fd.do_buildx_inspect = inspect
        with self.assertRaises(pub.Refuse) as cm:
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("is not the listed", str(cm.exception))

    def test_a_listed_child_that_does_not_hold_the_tested_config_is_refused(self):
        out, fd = self.build_tested()
        fd.push_as_index = "wrapped"
        fd.wrong_config_for = "amd64"
        with self.assertRaises(pub.Refuse) as cm:
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("not the tested", str(cm.exception))

    def test_a_failed_push_is_a_failure_even_when_it_printed_a_digest(self):
        out, fd = self.build_tested()
        orig = fd.do_push

        def push(a, i):
            r = orig(a, i)
            return proc(1, r.stdout, b"error: connection reset") if a[0].endswith("-amd64") else r

        fd.do_push = push
        with self.assertRaises(pub.Refuse) as cm:
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("docker push failed", str(cm.exception))
        self.assertIsNone(fd.dev())

    def test_the_private_docker_config_is_owner_only_when_the_credential_is_written(self):
        res, fd = self.run_publish()
        self.assertEqual(fd.login_dir_mode, 0o700)

    def test_a_registry_that_serves_other_bytes_than_the_pushed_digest_is_refused(self):
        out, fd = self.build_tested()
        orig = fd.do_buildx_inspect

        def inspect(a, i):
            r = orig(a, i)
            if "@" in a[-1] and r.returncode == 0:
                return proc(0, r.stdout + b" ")
            return r

        fd.do_buildx_inspect = inspect
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIsNone(fd.dev())

    def test_a_failed_index_create_publishes_nothing(self):
        out, fd = self.build_tested()
        fd.fail.add("buildx-create")
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIsNone(fd.dev())

    def test_an_index_that_reads_back_wrong_fails_the_run(self):
        out, fd = self.build_tested()
        fd.bad_index = True  # both entries claim linux/amd64
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)

    def test_the_index_must_hold_exactly_the_two_staged_manifests(self):
        out, fd = self.build_tested()
        reg = pub.Registry(fd)
        res = pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        idx = json.loads(fd.manifests[fd.dev()])
        third = {"digest": sha(b"third"), "platform": {"os": "linux", "architecture": "s390x"}}
        for name, mutate in (("a duplicate platform", lambda d: d["manifests"].append(dict(d["manifests"][0]))), ("a third platform", lambda d: d["manifests"].append(dict(third))),
                             ("a docker list type swapped for junk", lambda d: d.update(mediaType="text/plain")),
                             ("an unknown platform", lambda d: d["manifests"][1]["platform"].update(architecture="s390x")), ("another revision", lambda d: d["annotations"].update({pub.ANN_REVISION: OLD})),
                             ("a foreign digest", lambda d: d["manifests"][0].update(digest=sha(b"foreign")))):
            with self.subTest(name):
                doc = json.loads(json.dumps(idx))
                mutate(doc)
                raw = json.dumps(doc, sort_keys=True).encode()
                fd.manifests[sha(raw)] = raw
                fd.tags["%s:%s" % (pub.IMAGE, pub.TAG)] = sha(raw)
                with self.assertRaises(pub.Refuse):
                    reg.verify_index(res["staged"], SHA)

    def test_a_stale_run_does_not_overwrite_a_newer_dev_tag(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, NEW)
        before = fd.dev()
        with self.assertRaises(pub.Skip):
            pub.publish(fd, FakeGit(ancestors=[(SHA, NEW)]), out, SHA, env(), log=lambda *_: None)  # SHA is an ancestor of NEW: older
        self.assertEqual(fd.dev(), before)
        self.assertNotIn("push", fd.names())

    def test_a_diverged_dev_revision_is_skipped_and_left_untouched_not_refused(self):
        # review 519 F3: a dev revision that is neither an ancestor of this commit nor the other way round (merge-base exits 1) is a
        # SKIP (not a failure, dev byte-identical), exactly like an older commit; only an unorderable history refuses.
        out, fd = self.build_tested()
        self.seed_dev(fd, NEW)
        before = fd.dev()
        with self.assertRaises(pub.Skip):
            pub.publish(fd, FakeGit(ancestors=[]), out, SHA, env(), log=lambda *_: None)
        self.assertEqual(fd.dev(), before)
        self.assertNotIn("push", fd.names())
        out2, fd2 = self.build_tested()
        self.seed_dev(fd2, NEW)
        with self.assertRaises(pub.Refuse):  # the order cannot be evaluated at all: refused, nothing written
            pub.publish(fd2, FakeGit(unknown=True), out2, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd2.names())

    def test_a_newer_commit_replaces_an_older_dev_revision(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, OLD)
        old = fd.dev()
        res = pub.publish(fd, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertNotEqual(fd.dev(), old)
        self.assertEqual(json.loads(fd.manifests[fd.dev()])["annotations"][pub.ANN_REVISION], SHA)
        self.assertTrue(res["published"])

    def test_a_repeated_run_of_the_same_commit_is_a_verified_no_op(self):
        out, fd = self.build_tested()
        pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        fd.calls.clear()
        with self.assertRaises(pub.Skip):
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd.names())
        self.assertNotIn("buildx imagetools create", fd.names())

    def test_a_dev_tag_without_a_revision_or_an_unreadable_one_stops_the_run(self):
        out, fd = self.build_tested()
        raw = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": []}).encode()
        fd.manifests[sha(raw)] = raw
        fd.tags["%s:%s" % (pub.IMAGE, pub.TAG)] = sha(raw)
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd.names())
        out2, fd2 = self.build_tested()
        fd2.inspect_error = b"dial tcp: i/o timeout"  # not a 'not found': fail closed
        with self.assertRaises(pub.Refuse):
            pub.publish(fd2, FakeGit(), out2, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd2.names())

    def test_a_history_that_cannot_be_ordered_refuses(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, OLD)
        with self.assertRaises(pub.Refuse):
            pub.publish(fd, FakeGit(unknown=True), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd.names())

    def test_a_dev_tag_that_moves_while_staging_is_not_overwritten(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, OLD)
        fd.after_stage = lambda d: self.seed_dev(d, NEW)  # a concurrent writer wins during staging
        with self.assertRaises(pub.Skip):
            pub.publish(fd, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertEqual(json.loads(fd.manifests[fd.dev()])["annotations"][pub.ANN_REVISION], NEW)
        self.assertNotIn("buildx imagetools create", fd.names())

    def test_a_failed_login_or_load_publishes_nothing(self):
        for op in ("login", "load"):
            with self.subTest(op):
                out, fd = self.build_tested()
                fd.fail.add(op)
                with self.assertRaises(pub.Refuse):
                    pub.publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                self.assertIsNone(fd.dev())
                self.assertNotIn("push", fd.names())

    def test_the_fixture_mode_skips_the_login_only_for_a_local_registry(self):
        out, fd = self.build_tested()
        res = pub.publish(fd, FakeGit(), out, SHA, env(GITHUB_TOKEN=None), image="localhost:5000/mandatary", fixture=True, log=lambda *_: None)
        self.assertTrue(res["published"])
        self.assertNotIn("login", fd.names())

    def seed_dev(self, fd, revision):
        raw = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "annotations": {pub.ANN_REVISION: revision},
                          "manifests": [{"digest": sha(b"a"), "platform": {"os": "linux", "architecture": "amd64"}}, {"digest": sha(b"b"), "platform": {"os": "linux", "architecture": "arm64"}}]}, sort_keys=True).encode()
        fd.manifests[sha(raw)] = raw
        fd.tags["%s:%s" % (pub.IMAGE, pub.TAG)] = sha(raw)


def read_source():
    with open(os.path.join(HERE, "..", "..", "scripts", "publish_dev_image.py")) as fh:
        return fh.read()


class Source(unittest.TestCase):
    src = read_source()

    def test_the_credential_is_never_placed_on_a_command_line_or_echoed(self):
        self.assertIn("--password-stdin", self.src)
        self.assertNotRegex(self.src, r"--password[ =]")
        self.assertNotRegex(self.src, r"echo[^\n]*TOKEN")
        self.assertNotRegex(self.src, r"print\([^\n]*token")

    def test_the_target_is_fixed_to_the_ghcr_dev_tag_of_this_repository(self):
        self.assertEqual((pub.IMAGE, pub.TAG, pub.REPOSITORY), ("ghcr.io/nicotm77/mandatary", "dev", "NicoTM77/Mandatary"))
        for forbidden in (":latest", ":stable", "--tag %s:v"):
            self.assertNotIn(forbidden, self.src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
