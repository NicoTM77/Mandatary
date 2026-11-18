#!/usr/bin/env python3
"""Hermetic tests (no Docker, no network, no credential) of the dev-image publication logic in scripts/publish_dev_image.py.

The docker CLI and git are replaced by a fake registry that behaves like the real one where it matters (a push stores a manifest whose
config is the loaded image's config, `imagetools create` composes an index from manifests that exist, a raw inspect returns the stored
bytes or "not found"). Each positive case has negative twins, and the mutating calls are checked for ORDER: nothing is written to the dev
tag unless both platforms were staged and verified, and nothing touches a registry before the tested archives were verified.

    python3 tests/publish/test_publish.py
"""
import base64
import hashlib
import http.server
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import threading
import types
import unittest
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "scripts"))
import publish_dev_image as pub  # noqa: E402

SHA = "1" * 40
OLD = "2" * 40
NEW = "3" * 40
TOKEN = "tok-SECRET-0123456789"
DOCKER_V2 = "application/vnd.docker.distribution.manifest.v2+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
FIXTURES = os.path.join(HERE, "fixtures", "c5-old-dev")
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


def recorded_config(out, arch):
    """The config digest `record` wrote for the tested image of <arch> (what the published image must hold)."""
    with open(os.path.join(out, "tested-image-" + arch, "image-%s.json" % arch)) as fh:
        return json.load(fh)["config_digest"]


def proc(rc=0, out=b"", err=b""):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class FakeDocker:
    """A stand-in for the docker CLI plus a tiny registry. `calls` records (args, input); `fail` names operations that fail."""

    def __init__(self, tarballs=None):
        self.calls, self.fail, self.tarballs = [], set(), dict(tarballs or {})
        self.local, self.manifests, self.tags, self.platform, self.blobs = {}, {}, {}, {}, set()
        self.config_dir = None
        self.config_dirs_seen = []
        self.login_dir_mode = None
        self.push_as_index = None  # the registry stores an index where a single image manifest was pushed
        self.after_stage = None  # a hook that runs after the arm64 staging push (to simulate a concurrent writer)
        self.wrong_config_for = None  # arch whose pushed manifest is served with a different config digest
        self.bad_index = False
        self.inspect_error = None
        # What the pushed platform manifests are: the classic image store of a hosted runner pushes Docker v2 manifests, a containerd store pushes OCI ones.
        self.child_media = DOCKER_V2
        # How `buildx imagetools create` behaves. "oci": always writes an OCI index annotated as asked (the long-standing default of this fake).
        # "classic": the buildx of the hosted runner; Docker v2 children give a Docker manifest list, which cannot carry annotations, written with exit 0
        # and the annotations left out. "strict": a newer buildx; it refuses Docker v2 children ("annotations are not supported for Docker manifest lists")
        # and writes nothing. OCI children give an annotated OCI index in every mode. "write_then_fail": the registry took an annotated OCI index and the
        # command still reports failure (the client failed after the write).
        self.create_mode = "oci"
        self.drop_annotations = set()  # annotation keys that a create reporting success silently leaves out of the index it wrote

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
        oci = self.child_media == OCI_MANIFEST
        layer = sha(b"l" + facts["architecture"].encode())
        doc = {"schemaVersion": 2, "mediaType": self.child_media, "config": {"mediaType": OCI_CONFIG if oci else DOCKER_CONFIG, "digest": cfg, "size": 1},
               "layers": [{"mediaType": OCI_LAYER if oci else DOCKER_LAYER, "digest": layer, "size": 1}]}
        self.blobs.update({cfg, layer})  # a registry accepts a manifest only when the blobs it names are there
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
            entries.append({"mediaType": json.loads(self.manifests[d])["mediaType"], "digest": d, "size": len(self.manifests[d]), "platform": {"os": os_, "architecture": arch}})
        docker_children = any(e["mediaType"] == DOCKER_V2 for e in entries)
        index = {"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": entries, "annotations": {k: v for k, v in ann.items() if k not in self.drop_annotations}}
        if docker_children and self.create_mode == "strict":
            return proc(1, b"", b"annotations are not supported for Docker manifest lists; use oci-mediatypes=true")
        if docker_children and self.create_mode == "classic":  # a Docker manifest list has no annotations: they are dropped and the command still succeeds
            index = {"schemaVersion": 2, "mediaType": pub.DOCKER_LIST, "manifests": entries}
        idx = json.dumps(index, sort_keys=True).encode()
        self.manifests[sha(idx)] = idx
        self.tags[tag] = sha(idx)
        if self.create_mode == "write_then_fail":
            return proc(1, b"", b"connection reset after the registry took the write")
        return proc()

    def do_login(self, a, input):
        return proc()

    def do_logout(self, a, _):
        return proc()

    def writes(self):
        """Names of the calls that write to a registry."""
        return [n for n in self.names() if n in ("push", "api-put", "buildx imagetools create", "login")]

    def dev(self):
        return self.tags.get("%s:%s" % (pub.IMAGE, pub.TAG))


class FakeApi:
    """The registry API behind HttpRegistry (PUT of one manifest under a tag), over the same fake registry. Like a real registry it validates the
    Content-Type against the manifest's own mediaType and refuses a manifest that names a blob it does not hold."""

    def __init__(self, fd, image=pub.IMAGE):
        self.fd, self.image, self.calls = fd, image, []
        self.fail = False  # the registry refuses the write (permission, quota, ...)
        self.reported = None  # the digest the registry claims in its answer, when it is not the real one
        self.corrupt = False  # the registry stores other bytes than the ones it was given

    def put_manifest(self, reference, body, media_type):
        self.calls.append((reference, body, media_type))
        self.fd.calls.append((["api-put", reference], None))  # visible in the order of the registry operations (FakeDocker.names)
        if self.fail:
            raise pub.Refuse("the registry refused the manifest %s (HTTP 403)" % reference)
        doc = json.loads(body)
        if doc.get("mediaType") != media_type:
            raise pub.Refuse("the registry refused the manifest %s (HTTP 400: mediaType does not match the Content-Type)" % reference)
        named = [doc["config"]["digest"]] + [l["digest"] for l in doc["layers"]]
        if any(d not in self.fd.blobs for d in named):
            raise pub.Refuse("the registry refused the manifest %s (HTTP 400: MANIFEST_BLOB_UNKNOWN)" % reference)
        digest = sha(body)
        stored = body + b" " if self.corrupt else body
        self.fd.manifests[digest] = stored
        for other, raw in list(self.fd.manifests.items()):  # the platform is a property of the image the config belongs to
            if other != digest and other in self.fd.platform and json.loads(raw).get("config", {}).get("digest") == doc["config"]["digest"]:
                self.fd.platform[digest] = self.fd.platform[other]
        self.fd.tags["%s:%s" % (self.image, reference)] = digest
        return self.reported or digest


def publish(fd, *args, **kw):
    """pub.publish over the fake registry, which also provides the registry API (the one call docker cannot make)."""
    kw.setdefault("api", FakeApi(fd, kw.get("image", pub.IMAGE)))
    return pub.publish(fd, *args, **kw)


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
        return publish(fd, git or FakeGit(), out, SHA, e or env(), log=self.logs.append, **kw), fd

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
        for arch in pub.ARCHES:  # the staged manifest holds exactly the tested config, as an OCI manifest (the pushed Docker v2 one was converted)
            mf = json.loads(fd.manifests[res["staged"][arch]])
            with open(os.path.join(self.d, "promote", "tested-image-" + arch, "image-%s.json" % arch)) as fh:
                rec = json.load(fh)
            self.assertEqual(mf["config"]["digest"], rec["config_digest"])
            self.assertEqual(mf["mediaType"], OCI_MANIFEST)
        self.assertEqual(set(t for t in fd.tags if ":build-" in t), {"%s:build-%s-%s%s" % (pub.IMAGE, SHA, a, suffix) for a in pub.ARCHES for suffix in ("", "-oci")})
        self.assertNotIn("%s:latest" % pub.IMAGE, fd.tags)  # no other tag than dev (and the per-commit staging tags)

    def test_nothing_touches_a_registry_before_both_tested_archives_were_verified(self):
        out, _ = self.build_tested()
        with open(os.path.join(out, "tested-image-arm64", "image-arm64.tar"), "ab") as fh:
            fh.write(b"tamper")
        fd = FakeDocker()
        with self.assertRaises(pub.Refuse):
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
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
            publish(fd, FakeGit(), out, SHA, env(GITHUB_TOKEN=None), log=lambda *_: None)
        self.assertEqual(fd.calls, [])

    def test_a_failed_arm64_staging_leaves_dev_untouched_and_never_creates_the_index(self):
        out, fd = self.build_tested()
        orig = fd.do_push

        def push(a, i):
            return proc(1, b"", b"denied") if a[0].endswith("-arm64") else orig(a, i)

        fd.do_push = push
        with self.assertRaises(pub.Refuse):
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("buildx imagetools create", fd.names())
        self.assertIsNone(fd.dev())
        self.assertEqual(fd.names()[-1], "logout")  # and the credential is still dropped

    def test_a_pushed_manifest_that_does_not_hold_the_tested_config_is_refused(self):
        out, fd = self.build_tested()
        fd.wrong_config_for = "arm64"
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("not the tested", str(cm.exception))
        self.assertIsNone(fd.dev())
        self.assertNotIn("buildx imagetools create", fd.names())
        for media in (DOCKER_V2, OCI_MANIFEST):  # and it is refused when that image is staged: the next one is not even pushed
            with self.subTest(media):
                out, fd = self.build_tested()
                fd.child_media, fd.wrong_config_for = media, "amd64"
                with self.assertRaises(pub.Refuse) as cm:
                    publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                self.assertIn("not the tested", str(cm.exception))
                self.assertEqual(fd.names().count("push"), 1)
                self.assertNotIn("api-put", fd.names())

    def test_an_image_pushed_as_a_one_platform_index_is_promoted_by_its_image_manifest(self):
        for mode in ("wrapped", "attested"):  # the containerd image store, with and without a build attestation beside the image
            with self.subTest(mode):
                out, fd = self.build_tested()
                fd.push_as_index = mode
                res = publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                idx = json.loads(fd.manifests[fd.dev()])
                self.assertEqual(len(idx["manifests"]), 2)  # the dev index holds the two image manifests, never the wrapper indexes or the attestations
                for arch in pub.ARCHES:
                    mf = json.loads(fd.manifests[res["staged"][arch]])
                    self.assertNotIn("manifests", mf)
                    self.assertEqual(mf["mediaType"], OCI_MANIFEST)  # the Docker v2 image manifest inside the wrapper was converted

    def test_a_pushed_index_in_any_other_shape_is_refused(self):
        for mode in ("two", "extra", "wrongplat", "empty", "attonly", "nested"):
            with self.subTest(mode):
                out, fd = self.build_tested()
                fd.push_as_index = mode
                with self.assertRaises(pub.Refuse):
                    publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                self.assertIsNone(fd.dev())
                self.assertNotIn("buildx imagetools create", fd.names())
                self.assertEqual(fd.names().count("push"), 1)  # refused when the first image is staged, not later by the pre-write check
                self.assertNotIn("api-put", fd.names())

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
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("is not the listed", str(cm.exception))

    def test_a_listed_child_that_does_not_hold_the_tested_config_is_refused(self):
        out, fd = self.build_tested()
        fd.push_as_index = "wrapped"
        fd.wrong_config_for = "amd64"
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("not the tested", str(cm.exception))

    def test_a_failed_push_is_a_failure_even_when_it_printed_a_digest(self):
        out, fd = self.build_tested()
        orig = fd.do_push

        def push(a, i):
            r = orig(a, i)
            return proc(1, r.stdout, b"error: connection reset") if a[0].endswith("-amd64") else r

        fd.do_push = push
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("docker push failed", str(cm.exception))
        self.assertIsNone(fd.dev())

    def test_the_private_docker_config_is_owner_only_when_the_credential_is_written(self):
        res, fd = self.run_publish()
        self.assertEqual(fd.login_dir_mode, 0o700)

    def test_a_registry_that_serves_other_bytes_than_the_pushed_digest_is_refused(self):
        for media in (DOCKER_V2, OCI_MANIFEST):
            with self.subTest(media):
                out, fd = self.build_tested()
                fd.child_media = media
                orig = fd.do_buildx_inspect

                def inspect(a, i, orig=orig):
                    r = orig(a, i)
                    if "@" in a[-1] and r.returncode == 0:
                        return proc(0, r.stdout + b" ")
                    return r

                fd.do_buildx_inspect = inspect
                with self.assertRaises(pub.Refuse):
                    publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                self.assertIsNone(fd.dev())
                self.assertEqual(fd.names().count("push"), 1)  # refused at the first image, before anything is converted or staged beside it
                self.assertNotIn("api-put", fd.names())

    def test_a_failed_index_create_publishes_nothing(self):
        out, fd = self.build_tested()
        fd.fail.add("buildx-create")
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertIsNone(fd.dev())
        self.assertIn("create failed", str(cm.exception))
        self.assertIn("unchanged", str(cm.exception))  # the failure message reports what dev serves afterwards, it does not assume

    def test_an_index_that_reads_back_wrong_fails_the_run(self):
        out, fd = self.build_tested()
        fd.bad_index = True  # both entries claim linux/amd64
        with self.assertRaises(pub.Refuse):
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)

    def test_the_index_must_hold_exactly_the_two_staged_manifests(self):
        out, fd = self.build_tested()
        reg = pub.Registry(fd)
        res = publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        configs = {a: recorded_config(out, a) for a in pub.ARCHES}
        intact = fd.dev()
        self.assertEqual(reg.verify_index(res["staged"], SHA, configs), intact)  # the intact index passes
        idx = json.loads(fd.manifests[intact])
        third = {"digest": sha(b"third"), "platform": {"os": "linux", "architecture": "s390x"}}
        for name, mutate in (("a duplicate platform", lambda d: d["manifests"].append(dict(d["manifests"][0]))), ("a third platform", lambda d: d["manifests"].append(dict(third))),
                             ("a docker list type swapped for junk", lambda d: d.update(mediaType="text/plain")),
                             ("an annotated docker list instead of the OCI index", lambda d: d.update(mediaType=pub.DOCKER_LIST)),
                             ("a child listed with the docker v2 media type", lambda d: d["manifests"][0].update(mediaType=DOCKER_V2)),
                             ("an unknown platform", lambda d: d["manifests"][1]["platform"].update(architecture="s390x")), ("another revision", lambda d: d["annotations"].update({pub.ANN_REVISION: OLD})),
                             ("another source", lambda d: d["annotations"].update({pub.ANN_SOURCE: "https://github.com/other/repo"})),
                             ("no source", lambda d: d["annotations"].pop(pub.ANN_SOURCE)),
                             ("a foreign digest", lambda d: d["manifests"][0].update(digest=sha(b"foreign")))):
            with self.subTest(name):
                doc = json.loads(json.dumps(idx))
                mutate(doc)
                raw = json.dumps(doc, sort_keys=True).encode()
                fd.manifests[sha(raw)] = raw
                fd.tags["%s:%s" % (pub.IMAGE, pub.TAG)] = sha(raw)
                with self.assertRaises(pub.Refuse):
                    reg.verify_index(res["staged"], SHA, configs)
        with self.subTest("a child that does not hold the tested config"):  # the index is intact; the registry's child is not the tested image
            fd.tags["%s:%s" % (pub.IMAGE, pub.TAG)] = intact
            with self.assertRaises(pub.Refuse) as cm:
                reg.verify_index(res["staged"], SHA, dict(configs, arm64=sha(b"another tested config")))
            self.assertIn("not the tested", str(cm.exception))

    def test_a_stale_run_does_not_overwrite_a_newer_dev_tag(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, NEW)
        before = fd.dev()
        with self.assertRaises(pub.Skip):
            publish(fd, FakeGit(ancestors=[(SHA, NEW)]), out, SHA, env(), log=lambda *_: None)  # SHA is an ancestor of NEW: older
        self.assertEqual(fd.dev(), before)
        self.assertNotIn("push", fd.names())

    def test_a_diverged_dev_revision_is_skipped_and_left_untouched_not_refused(self):
        # review 519 F3: a dev revision that is neither an ancestor of this commit nor the other way round (merge-base exits 1) is a
        # SKIP (not a failure, dev byte-identical), exactly like an older commit; only an unorderable history refuses.
        out, fd = self.build_tested()
        self.seed_dev(fd, NEW)
        before = fd.dev()
        with self.assertRaises(pub.Skip):
            publish(fd, FakeGit(ancestors=[]), out, SHA, env(), log=lambda *_: None)
        self.assertEqual(fd.dev(), before)
        self.assertNotIn("push", fd.names())
        out2, fd2 = self.build_tested()
        self.seed_dev(fd2, NEW)
        with self.assertRaises(pub.Refuse):  # the order cannot be evaluated at all: refused, nothing written
            publish(fd2, FakeGit(unknown=True), out2, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd2.names())

    def test_a_newer_commit_replaces_an_older_dev_revision(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, OLD)
        old = fd.dev()
        res = publish(fd, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertNotEqual(fd.dev(), old)
        self.assertEqual(json.loads(fd.manifests[fd.dev()])["annotations"][pub.ANN_REVISION], SHA)
        self.assertTrue(res["published"])

    def test_a_repeated_run_of_the_same_commit_is_a_verified_no_op(self):
        out, fd = self.build_tested()
        publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        fd.calls.clear()
        with self.assertRaises(pub.Skip):
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd.names())
        self.assertNotIn("buildx imagetools create", fd.names())

    def test_a_dev_tag_without_a_revision_or_an_unreadable_one_stops_the_run(self):
        out, fd = self.build_tested()
        raw = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": []}).encode()
        fd.manifests[sha(raw)] = raw
        fd.tags["%s:%s" % (pub.IMAGE, pub.TAG)] = sha(raw)
        with self.assertRaises(pub.Refuse):
            publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd.names())
        out2, fd2 = self.build_tested()
        fd2.inspect_error = b"dial tcp: i/o timeout"  # not a 'not found': fail closed
        with self.assertRaises(pub.Refuse):
            publish(fd2, FakeGit(), out2, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd2.names())

    def test_a_history_that_cannot_be_ordered_refuses(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, OLD)
        with self.assertRaises(pub.Refuse):
            publish(fd, FakeGit(unknown=True), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("push", fd.names())

    def test_a_dev_tag_that_moves_while_staging_is_not_overwritten(self):
        out, fd = self.build_tested()
        self.seed_dev(fd, OLD)
        fd.after_stage = lambda d: self.seed_dev(d, NEW)  # a concurrent writer wins during staging
        with self.assertRaises(pub.Skip):
            publish(fd, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertEqual(json.loads(fd.manifests[fd.dev()])["annotations"][pub.ANN_REVISION], NEW)
        self.assertNotIn("buildx imagetools create", fd.names())

    def test_a_failed_login_or_load_publishes_nothing(self):
        for op in ("login", "load"):
            with self.subTest(op):
                out, fd = self.build_tested()
                fd.fail.add(op)
                with self.assertRaises(pub.Refuse):
                    publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                self.assertIsNone(fd.dev())
                self.assertNotIn("push", fd.names())

    def test_the_fixture_mode_skips_the_login_only_for_a_local_registry(self):
        out, fd = self.build_tested()
        res = publish(fd, FakeGit(), out, SHA, env(GITHUB_TOKEN=None), image="localhost:5000/mandatary", fixture=True, log=lambda *_: None)
        self.assertTrue(res["published"])
        self.assertNotIn("login", fd.names())

    def seed_dev(self, fd, revision):
        raw = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "annotations": {pub.ANN_REVISION: revision},
                          "manifests": [{"digest": sha(b"a"), "platform": {"os": "linux", "architecture": "amd64"}}, {"digest": sha(b"b"), "platform": {"os": "linux", "architecture": "arm64"}}]}, sort_keys=True).encode()
        fd.manifests[sha(raw)] = raw
        fd.tags["%s:%s" % (pub.IMAGE, pub.TAG)] = sha(raw)

class IndexPublication(Tmp):
    """Finding F-C5-1: the first real main publication wrote `dev` as a Docker manifest list without the revision annotation, because the hosted runner's
    classic image store pushes Docker v2 platform manifests and its buildx dropped the annotation while `imagetools create` exited 0. The corrected
    publication converts each pushed Docker v2 manifest to its OCI form (same config and layer blobs) before anything is written to `dev`, refuses before the
    write when that cannot be done, and verifies the written index by reading it back. These tests exercise the real Registry.stage / convert_to_oci /
    create_index / verify_index / publish code over the fake registry."""

    def arrange(self, child_media=DOCKER_V2, create_mode="oci"):
        out, fd = self.build_tested()
        fd.child_media, fd.create_mode = child_media, create_mode
        return out, fd

    def stage_both(self, fd, out, api=None):
        reg, staged = pub.Registry(fd, api=api or FakeApi(fd)), {}
        for a in pub.ARCHES:
            rec, tar = pub.load_record(out, a, SHA)
            self.assertEqual(fd(["load", "--input", tar]).returncode, 0)
            staged[a] = reg.stage(pub.LOCAL_TAG % a, a, SHA, rec["config_digest"])
        return reg, staged

    def configs(self, out):
        return {a: recorded_config(out, a) for a in pub.ARCHES}

    def dev_index(self, fd):
        return json.loads(fd.manifests[fd.dev()])

    def assert_children_are_the_tested_oci_images(self, fd, out, doc):
        """Both descriptors are OCI image manifests of the right platform, and each manifest holds the config digest of the tested image."""
        self.assertEqual(sorted((m["platform"]["os"], m["platform"]["architecture"]) for m in doc["manifests"]), [("linux", "amd64"), ("linux", "arm64")])
        for m in doc["manifests"]:
            self.assertEqual(m["mediaType"], OCI_MANIFEST)
            child = json.loads(fd.manifests[m["digest"]])
            self.assertEqual(child["mediaType"], OCI_MANIFEST)
            self.assertEqual(child["config"], {"mediaType": OCI_CONFIG, "digest": recorded_config(out, m["platform"]["architecture"]), "size": child["config"]["size"]})
            self.assertTrue(child["layers"] and all(l["mediaType"] == OCI_LAYER for l in child["layers"]))

    def bad_dev(self, fd):
        """The real unannotated Docker manifest list that the first main publication left on dev (captured read-only from ghcr.io)."""
        return seed_raw(fd, read_fixture("dev-index.json"))

    # -- the ordinary valid publication (positive controls)

    def test_an_annotated_oci_index_of_oci_platform_manifests_is_published_and_verified(self):
        for mode in ("oci", "classic", "strict"):  # OCI children give an annotated OCI index whatever the buildx, and need no conversion
            with self.subTest(create_mode=mode):
                out, fd = self.arrange(OCI_MANIFEST, mode)
                api = FakeApi(fd)
                res = publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None, api=api)
                self.assertTrue(res["published"])
                self.assertEqual(api.calls, [])  # already OCI: nothing is converted or written beside the pushed images
                doc = self.dev_index(fd)
                self.assertEqual(doc["mediaType"], pub.OCI_INDEX)
                self.assertEqual(doc["annotations"], {pub.ANN_REVISION: SHA, pub.ANN_SOURCE: pub.SOURCE_URL})
                self.assert_children_are_the_tested_oci_images(fd, out, doc)
                self.assertEqual(res["index"], fd.dev())

    def test_docker_v2_platform_manifests_are_converted_and_published_as_an_annotated_oci_index(self):
        for mode in ("oci", "classic", "strict"):  # the buildx behaviour no longer matters: the children given to it are OCI
            with self.subTest(create_mode=mode):
                out, fd = self.arrange(DOCKER_V2, mode)
                api = FakeApi(fd)
                res = publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None, api=api)
                doc = self.dev_index(fd)
                self.assertEqual(doc["mediaType"], pub.OCI_INDEX)
                self.assertEqual(doc["annotations"], {pub.ANN_REVISION: SHA, pub.ANN_SOURCE: pub.SOURCE_URL})
                self.assert_children_are_the_tested_oci_images(fd, out, doc)
                self.assertEqual(res["index"], fd.dev())
                self.assertEqual([(ref, mt) for ref, _, mt in api.calls], [("build-%s-%s-oci" % (SHA, a), OCI_MANIFEST) for a in pub.ARCHES])
                writes = fd.writes()  # the order: login, the pushes, the two OCI manifests, and only then the one create
                self.assertEqual(writes, ["login", "push", "api-put", "push", "api-put", "buildx imagetools create"])
                for m in doc["manifests"]:
                    arch = m["platform"]["architecture"]
                    pushed = json.loads(fd.manifests[fd.tags["%s:build-%s-%s" % (pub.IMAGE, SHA, arch)]])  # the Docker v2 manifest the push made, still there
                    child = json.loads(fd.manifests[m["digest"]])
                    self.assertEqual(pushed["mediaType"], DOCKER_V2)
                    self.assertNotEqual(fd.tags["%s:build-%s-%s" % (pub.IMAGE, SHA, arch)], m["digest"])
                    self.assertEqual(fd.tags["%s:build-%s-%s-oci" % (pub.IMAGE, SHA, arch)], m["digest"])
                    self.assertEqual(child["config"]["digest"], pushed["config"]["digest"])  # the blobs are the same objects
                    self.assertEqual([(l["digest"], l["size"]) for l in child["layers"]], [(l["digest"], l["size"]) for l in pushed["layers"]])

    def test_the_staged_manifests_are_the_oci_forms_of_the_tested_images(self):
        out, fd = self.arrange(DOCKER_V2)
        reg, staged = self.stage_both(fd, out)
        for a in pub.ARCHES:
            mf = json.loads(fd.manifests[staged[a]])
            self.assertEqual(mf["mediaType"], OCI_MANIFEST)
            self.assertEqual(mf["config"]["digest"], recorded_config(out, a))
            self.assertEqual(fd.platform[staged[a]], ("linux", a))

    # -- the conversion/publication boundary: whatever cannot be made the promised publication is refused BEFORE dev is written

    def refused_before_the_write(self, fd, out, older, **kw):
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None, **kw)
        self.assertNotIn("buildx imagetools create", fd.names())  # the write was never attempted
        self.assertEqual(fd.dev(), older)  # dev is byte-identical
        self.assertEqual(fd.names()[-1], "logout")
        return str(cm.exception)

    def test_a_registry_that_will_not_take_the_oci_manifest_leaves_dev_untouched(self):
        for name, setup, expected in (("write refused", lambda api: setattr(api, "fail", True), "refused the manifest"),
                                      ("another digest reported", lambda api: setattr(api, "reported", sha(b"another")), "reports digest"),
                                      ("other bytes stored", lambda api: setattr(api, "corrupt", True), "not the written OCI manifest")):
            with self.subTest(name):
                out, fd = self.arrange(DOCKER_V2)
                self.seed_dev(fd, OLD)
                old = fd.dev()
                api = FakeApi(fd)
                setup(api)
                self.assertIn(expected, self.refused_before_the_write(fd, out, old, api=api))

    def test_a_docker_v2_manifest_is_never_converted_without_a_registry_api(self):
        out, fd = self.arrange(DOCKER_V2)
        reg = pub.Registry(fd, api=None)
        rec, tar = pub.load_record(out, "amd64", SHA)
        fd(["load", "--input", tar])
        with self.assertRaises(pub.Refuse) as cm:
            reg.stage(pub.LOCAL_TAG % "amd64", "amd64", SHA, rec["config_digest"])
        self.assertIn("no registry API", str(cm.exception))

    def test_a_conversion_that_does_not_keep_the_tested_config_is_refused(self):
        out, fd = self.arrange(DOCKER_V2)
        orig = pub.oci_manifest_bytes

        def other_config(doc, config_digest):
            body = json.loads(orig(doc, config_digest))
            body["config"]["digest"] = sha(b"another config")  # a conversion that changes the image's identity
            return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

        self.seed_dev(fd, OLD)
        old = fd.dev()
        api = FakeApi(fd)
        api.fd.blobs.add(sha(b"another config"))
        with mock.patch.object(pub, "oci_manifest_bytes", other_config):
            self.assertIn("not the tested", self.refused_before_the_write(fd, out, old, api=api))

    def test_a_conversion_that_loses_a_layer_is_refused_by_the_read_back_of_the_written_manifest(self):
        out, fd = self.arrange(DOCKER_V2)
        orig = pub.oci_manifest_bytes

        def lose_the_layers(doc, config_digest):
            body = json.loads(orig(doc, config_digest))
            body["layers"] = []  # a consistent OCI manifest of the same config, but not the pushed image's layers
            return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

        self.seed_dev(fd, OLD)
        old = fd.dev()
        with mock.patch.object(pub, "oci_manifest_bytes", lose_the_layers):
            self.assertIn("does not hold the layers", self.refused_before_the_write(fd, out, old))

    def test_an_oci_manifest_is_the_tested_image_only_with_the_oci_media_types_and_the_tested_config(self):
        cfg = sha(b"tested config")
        good = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {"mediaType": OCI_CONFIG, "digest": cfg, "size": 1}, "layers": [{"mediaType": OCI_LAYER, "digest": sha(b"l"), "size": 1}]}
        pub.Registry.require_oci_image(good, "amd64", cfg, [sha(b"l")])
        for name, bad in (("a docker v2 manifest", dict(good, mediaType=DOCKER_V2)), ("an index", dict(good, mediaType=pub.OCI_INDEX, manifests=[])),
                          ("a docker config media type", dict(good, config=dict(good["config"], mediaType=DOCKER_CONFIG))),
                          ("another config", dict(good, config=dict(good["config"], digest=sha(b"another")))), ("not an object", [])):
            with self.subTest(name):
                with self.assertRaises(pub.Refuse):
                    pub.Registry.require_oci_image(bad, "amd64", cfg)
        with self.assertRaises(pub.Refuse):  # other layers than the pushed ones
            pub.Registry.require_oci_image(good, "amd64", cfg, [sha(b"another layer")])

    def test_staged_children_that_are_not_oci_never_reach_the_create(self):
        # Even if the conversion were skipped, the create is not attempted over a Docker v2 child: it would write an unannotated Docker list (or fail).
        for mode in ("classic", "strict", "oci"):
            with self.subTest(create_mode=mode):
                out, fd = self.arrange(DOCKER_V2, mode)
                self.seed_dev(fd, OLD)
                old = fd.dev()
                skip = lambda self_, doc, arch, sha_, cfg: sha(json.dumps(doc, sort_keys=True).encode())  # the digest of the pushed Docker v2 manifest
                with mock.patch.object(pub.Registry, "convert_to_oci", skip):
                    message = self.refused_before_the_write(fd, out, old)
                self.assertIn("not an OCI image manifest", message)
                self.assertIn("dev is not written", message)

    def test_the_config_of_a_staged_oci_child_is_checked_against_the_tested_one_before_the_write(self):
        out, fd = self.arrange(OCI_MANIFEST)
        reg, staged = self.stage_both(fd, out)
        with self.assertRaises(pub.Refuse) as cm:
            reg.create_index(staged, SHA, dict(self.configs(out), amd64=sha(b"another tested config")))
        self.assertIn("not the tested", str(cm.exception))
        self.assertIsNone(fd.dev())
        self.assertNotIn("buildx imagetools create", fd.names())

    # -- verification after the write: the create's exit status is never taken for a publication

    def test_a_create_that_exits_0_but_drops_an_annotation_is_refused_by_the_read_back_after_the_write(self):
        for key, expected in ((pub.ANN_REVISION, "revision annotation"), (pub.ANN_SOURCE, "source annotation")):
            with self.subTest(dropped=key):
                out, fd = self.arrange(OCI_MANIFEST)
                self.seed_dev(fd, OLD)
                old = fd.dev()
                fd.drop_annotations = {key}
                reg, staged = self.stage_both(fd, out)
                self.assertIsNone(reg.create_index(staged, SHA, self.configs(out)))  # command success: nothing in it says it is wrong
                self.assertNotEqual(fd.dev(), old)  # the registry now holds the new index ...
                self.assertEqual(self.dev_index(fd)["mediaType"], pub.OCI_INDEX)
                self.assertNotIn(key, self.dev_index(fd)["annotations"])  # ... without the annotation
                with self.assertRaises(pub.Refuse) as cm:
                    reg.verify_index(staged, SHA, self.configs(out))  # only the read-back catches it
                self.assertIn(expected, str(cm.exception))
                out2, fd2 = self.arrange(DOCKER_V2)  # and through the whole publication, with Docker v2 children converted on the way
                self.seed_dev(fd2, OLD)
                fd2.drop_annotations = {key}
                with self.assertRaises(pub.Refuse) as cm:
                    publish(fd2, FakeGit(ancestors=[(OLD, SHA)]), out2, SHA, env(), log=lambda *_: None)
                self.assertIn(expected, str(cm.exception))
                self.assertNotIn(key, self.dev_index(fd2)["annotations"])  # dev WAS written and stays as written; the run is red

    def test_a_docker_manifest_list_written_by_a_create_is_refused_by_the_read_back(self):
        # Defence in depth: with the conversion skipped and the pre-write check removed, the classic buildx writes an unannotated Docker list and exits 0.
        out, fd = self.arrange(DOCKER_V2, "classic")
        self.seed_dev(fd, OLD)
        old = fd.dev()
        skip = lambda self_, doc, arch, sha_, cfg: sha(json.dumps(doc, sort_keys=True).encode())
        with mock.patch.object(pub.Registry, "convert_to_oci", skip), mock.patch.object(pub.Registry, "require_oci_children", lambda *a, **k: None):
            with self.assertRaises(pub.Refuse) as cm:
                publish(fd, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertIn("not an OCI image index", str(cm.exception))
        self.assertNotIn("create failed", str(cm.exception))  # it is the READ-BACK that refused, after a create that exited 0
        self.assertEqual(fd.names().count("buildx imagetools create"), 1)
        self.assertEqual(fd.names()[-1], "logout")  # the credential is still dropped
        doc = self.dev_index(fd)  # the actual post-write state: dev WAS replaced by a Docker list of the two tested Docker v2 images, with no annotation at all
        self.assertNotEqual(fd.dev(), old)
        self.assertEqual(doc["mediaType"], pub.DOCKER_LIST)
        self.assertNotIn("annotations", doc)
        for m in doc["manifests"]:
            self.assertEqual(m["mediaType"], DOCKER_V2)
            self.assertEqual(json.loads(fd.manifests[m["digest"]])["config"]["digest"], recorded_config(out, m["platform"]["architecture"]))

    def test_a_refusal_after_the_write_is_not_a_refusal_before_the_write(self):
        skip = lambda self_, doc, arch, sha_, cfg: sha(json.dumps(doc, sort_keys=True).encode())
        # (1) refused before any write by the create command itself ("strict" buildx; the pre-write check is removed to reach it): dev is byte-identical
        out, before = self.arrange(DOCKER_V2, "strict")
        self.seed_dev(before, OLD)
        old = before.dev()
        with mock.patch.object(pub.Registry, "convert_to_oci", skip), mock.patch.object(pub.Registry, "require_oci_children", lambda *a, **k: None):
            with self.assertRaises(pub.Refuse) as cm:
                publish(before, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertIn("create failed", str(cm.exception))
        self.assertIn("unchanged", str(cm.exception))
        self.assertEqual(before.dev(), old)
        # (2) a create that reports FAILURE after the registry took the write: dev HAS changed, and the message says so instead of assuming
        out, failed = self.arrange(OCI_MANIFEST, "write_then_fail")
        self.seed_dev(failed, OLD)
        old = failed.dev()
        with self.assertRaises(pub.Refuse) as cm:
            publish(failed, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertIn("create failed", str(cm.exception))
        self.assertIn("HAS CHANGED", str(cm.exception))
        self.assertNotEqual(failed.dev(), old)
        self.assertEqual(self.dev_index(failed)["annotations"][pub.ANN_REVISION], SHA)
        # (3) a create that exits 0 and the read-back refuses (an annotation silently dropped): dev has changed, and the failure is the read-back's
        out, after = self.arrange(OCI_MANIFEST)
        self.seed_dev(after, OLD)
        old = after.dev()
        after.drop_annotations = {pub.ANN_REVISION}
        with self.assertRaises(pub.Refuse) as cm:
            publish(after, FakeGit(ancestors=[(OLD, SHA)]), out, SHA, env(), log=lambda *_: None)
        self.assertNotIn("create failed", str(cm.exception))
        self.assertNotEqual(after.dev(), old)  # a read-back failure does NOT leave dev untouched

    def test_a_create_failure_that_cannot_be_read_back_says_the_state_is_unknown(self):
        out, fd = self.arrange(OCI_MANIFEST, "strict")
        reg, staged = self.stage_both(fd, out)
        fd.fail.add("buildx-create")
        fd.inspect_error = b"dial tcp: i/o timeout"  # dev cannot be read afterwards
        with self.assertRaises(pub.Refuse) as cm:
            reg.create_index(staged, SHA, self.configs(out), before=None)
        self.assertIn("not known", str(cm.exception))

    def test_the_tested_config_and_platform_identity_checks_hold_for_both_child_media_types(self):
        for media in (DOCKER_V2, OCI_MANIFEST):
            with self.subTest(media=media, case="another config"):
                out, fd = self.arrange(media)
                fd.wrong_config_for = "arm64"
                with self.assertRaises(pub.Refuse) as cm:
                    publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                self.assertIn("not the tested", str(cm.exception))
                self.assertIsNone(fd.dev())
                self.assertNotIn("buildx imagetools create", fd.names())
            with self.subTest(media=media, case="platforms read back wrong"):
                out, fd = self.arrange(media)
                fd.bad_index = True  # both index entries claim linux/amd64
                with self.assertRaises(pub.Refuse):
                    publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
            with self.subTest(media=media, case="another revision in the annotation"):
                out, fd = self.arrange(media)
                reg, staged = self.stage_both(fd, out)
                reg.create_index(staged, OLD, self.configs(out))  # an index annotated with a revision that is not this commit's
                with self.assertRaises(pub.Refuse):
                    reg.verify_index(staged, SHA, self.configs(out))

    # -- what an unannotated dev means for ordinary publication (the state the first main run left behind)

    def test_an_ordinary_run_refuses_the_unannotated_dev_and_every_registry_write(self):
        out, fd = self.arrange(DOCKER_V2)
        old = self.bad_dev(fd)
        for attempt, rev in (("the same commit", SHA), ("a newer commit", NEW)):
            with self.subTest(attempt):
                fd.calls.clear()
                out2 = out if rev == SHA else self.build_tested(sha_=rev)[0]
                with self.assertRaises(pub.Refuse) as cm:
                    publish(fd, FakeGit(ancestors=[(SHA, NEW)]), out2, rev, env(), log=lambda *_: None)  # no recovery is offered
                self.assertIn("no revision annotation", str(cm.exception))
                for write in ("push", "api-put", "buildx imagetools create"):
                    self.assertNotIn(write, fd.names())
                self.assertEqual(fd.dev(), old)  # the evidence is preserved, not replaced

    seed_dev = Publish.seed_dev  # the same earlier dev tag (an annotated OCI index of another revision) as the freshness tests use


def read_fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as fh:
        return fh.read()


def seed_raw(fd, raw, image=pub.IMAGE):
    """Make `raw` the manifest the dev tag of `image` serves; returns its digest."""
    fd.manifests[sha(raw)] = raw
    fd.tags["%s:%s" % (image, pub.TAG)] = sha(raw)
    return sha(raw)


class OciConversion(unittest.TestCase):
    """oci_manifest_bytes: the pure conversion of a Docker v2 image manifest to an OCI one. The real manifests are those the hosted runner pushed (read
    anonymously from ghcr.io, tests/publish/fixtures/c5-old-dev), 15 gzip layers each."""
    GOLDEN = {"amd64": "sha256:662bc115d46328a555174c59c87ffe45d8ca2b202de00b325144ef5c51697bd9", "arm64": "sha256:cf5c92b29ec9a9b4c906dcbbb28316d66981119468071d702e861c2c2d06e8d1"}

    def real(self, arch):
        return json.loads(read_fixture("child-%s-manifest.json" % arch))

    def test_the_real_hosted_runner_manifests_convert_without_touching_a_blob(self):
        for arch in pub.ARCHES:
            with self.subTest(arch):
                src = self.real(arch)
                self.assertEqual(src["mediaType"], DOCKER_V2)
                body = pub.oci_manifest_bytes(src, src["config"]["digest"])
                out = json.loads(body)
                self.assertEqual(out["mediaType"], OCI_MANIFEST)
                self.assertEqual(out["config"], {"mediaType": OCI_CONFIG, "digest": src["config"]["digest"], "size": src["config"]["size"]})
                self.assertEqual(len(out["layers"]), 15)
                self.assertEqual([(l["digest"], l["size"]) for l in out["layers"]], [(l["digest"], l["size"]) for l in src["layers"]])
                self.assertEqual({l["mediaType"] for l in out["layers"]}, {OCI_LAYER})
                self.assertEqual(set(out), {"schemaVersion", "mediaType", "config", "layers"})
                self.assertEqual(body, pub.oci_manifest_bytes(src, src["config"]["digest"]))  # canonical: the same input gives the same bytes
                self.assertEqual(sha(body), self.GOLDEN[arch])  # pinned: a change of the conversion is a deliberate act

    def test_a_manifest_that_cannot_be_converted_without_loss_is_refused(self):
        src = self.real("amd64")
        cfg = src["config"]["digest"]

        def edit(fn):
            doc = json.loads(json.dumps(src))
            fn(doc)
            return doc

        cases = {
            "another tested config": (src, sha(b"another config")),
            "already OCI": (edit(lambda d: d.update(mediaType=OCI_MANIFEST)), cfg),
            "an index": (edit(lambda d: d.update(mediaType=pub.OCI_INDEX)), cfg),
            "schema version 1": (edit(lambda d: d.update(schemaVersion=1)), cfg),
            "an unknown top-level field": (edit(lambda d: d.update(annotations={"a": "b"})), cfg),
            "an unknown config field": (edit(lambda d: d["config"].update(urls=["http://x"])), cfg),
            "an unknown config media type": (edit(lambda d: d["config"].update(mediaType="application/x-other")), cfg),
            "a foreign layer": (edit(lambda d: d["layers"][0].update(mediaType="application/vnd.docker.image.rootfs.foreign.diff.tar.gzip")), cfg),
            "a layer with urls": (edit(lambda d: d["layers"][0].update(urls=["http://x"])), cfg),
            "a zstd layer": (edit(lambda d: d["layers"][0].update(mediaType="application/vnd.oci.image.layer.v1.tar+zstd")), cfg),
            "no layers": (edit(lambda d: d.update(layers=[])), cfg),
            "layers that are not a list": (edit(lambda d: d.update(layers={})), cfg),
            "a malformed layer digest": (edit(lambda d: d["layers"][0].update(digest="sha256:short")), cfg),
            "a negative size": (edit(lambda d: d["layers"][0].update(size=-1)), cfg),
            "a boolean size": (edit(lambda d: d["layers"][0].update(size=True)), cfg),
            "no config": (edit(lambda d: d.pop("config")), cfg),
            "not an object": ([], cfg),
        }
        for name, (doc, config_digest) in cases.items():
            with self.subTest(name):
                with self.assertRaises(pub.Refuse):
                    pub.oci_manifest_bytes(doc, config_digest)


class RecoveryTests(Tmp):
    """The one-time, narrowly guarded replacement of the known bad dev manifest (finding F-C5-1). The registry tag write has no compare-and-swap, so these
    tests pin what the code can do instead: an exact digest, an explicit and repository-bound exception, a second read right before the write, the same
    ordering and verification as any publication, and no persistence once the manifest is gone."""
    OLD_DIGEST = "sha256:0c8894070085f72c9709f191cfcc7c0998ff3950c39aa4b5887df4bff6d0486e"
    OLD_REVISION = "666ee9ce16d80440a9969c72b653975e84ba8ced"

    def arrange(self):
        out, fd = self.build_tested()  # Docker v2 children, like the hosted runner
        return out, fd, seed_raw(fd, read_fixture("dev-index.json"))

    def git(self):
        return FakeGit(ancestors=[(self.OLD_REVISION, SHA)])

    def test_the_recorded_state_is_the_one_the_owner_approved_and_its_provenance_checks_out(self):
        self.assertEqual(tuple(pub.KNOWN_BAD_DEV), (pub.IMAGE, pub.TAG, self.OLD_DIGEST, self.OLD_REVISION))
        self.assertEqual((pub.IMAGE, pub.TAG), ("ghcr.io/nicotm77/mandatary", "dev"))
        raw = read_fixture("dev-index.json")
        self.assertEqual(sha(raw), self.OLD_DIGEST)  # the preserved raw index is exactly the manifest the recovery is authorised for
        doc = json.loads(raw)
        self.assertEqual(doc["mediaType"], pub.DOCKER_LIST)
        self.assertNotIn("annotations", doc)
        self.assertEqual(sorted(m["platform"]["architecture"] for m in doc["manifests"]), ["amd64", "arm64"])
        for m in doc["manifests"]:  # the digest chain down to the config labels, which carry the revision it is judged by
            arch = m["platform"]["architecture"]
            manifest = read_fixture("child-%s-manifest.json" % arch)
            self.assertEqual(sha(manifest), m["digest"])
            cfg = read_fixture("child-%s-config.json" % arch)
            self.assertEqual(sha(cfg), json.loads(manifest)["config"]["digest"])
            facts = json.loads(cfg)
            self.assertEqual((facts["os"], facts["architecture"]), ("linux", arch))
            self.assertEqual(facts["config"]["Labels"][pub.REVISION_LABEL], self.OLD_REVISION)
            self.assertEqual(facts["config"]["Labels"][pub.SOURCE_LABEL], pub.SOURCE_URL)

    def test_a_run_that_is_not_offered_the_recovery_refuses_the_known_bad_dev(self):
        out, fd, old = self.arrange()
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, self.git(), out, SHA, env(), log=lambda *_: None)
        self.assertIn("no revision annotation", str(cm.exception))
        self.assertEqual(fd.dev(), old)
        for write in ("push", "api-put", "buildx imagetools create"):
            self.assertNotIn(write, fd.names())

    def test_the_recovery_replaces_exactly_the_recorded_manifest_and_reads_the_result_back(self):
        out, fd, old = self.arrange()
        logs = []
        res = publish(fd, self.git(), out, SHA, env(), log=logs.append, recovery=pub.KNOWN_BAD_DEV)
        self.assertEqual(res["recovered"], self.OLD_DIGEST)
        self.assertNotEqual(fd.dev(), old)
        self.assertEqual(res["index"], fd.dev())
        doc = json.loads(fd.manifests[fd.dev()])
        self.assertEqual(doc["mediaType"], pub.OCI_INDEX)  # read back: the intended media type, the annotations, the tested children
        self.assertEqual(doc["annotations"], {pub.ANN_REVISION: SHA, pub.ANN_SOURCE: pub.SOURCE_URL})
        IndexPublication.assert_children_are_the_tested_oci_images(self, fd, out, doc)
        self.assertEqual(fd.writes(), ["login", "push", "api-put", "push", "api-put", "buildx imagetools create"])  # one write of dev, last
        text = "\n".join(logs)  # the old state is in the job log before the replacement
        self.assertIn("RECOVERY", text)
        self.assertIn(self.OLD_DIGEST, text)
        self.assertIn(pub.DOCKER_LIST, text)
        self.assertIn("7fe3d3924efa361fb2afb1973842a6df6fb1091f3f6a6e46e0f48297081f5c18", text)  # the old amd64 child descriptor
        self.assertLess(text.index("RECOVERY"), text.index("published"))

    def test_the_second_run_after_the_recovery_is_an_ordinary_verified_no_op(self):
        out, fd, _ = self.arrange()
        publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)
        fd.calls.clear()
        with self.assertRaises(pub.Skip):
            publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)
        for write in ("push", "api-put", "buildx imagetools create"):
            self.assertNotIn(write, fd.names())

    def test_another_expected_digest_is_refused_before_any_write(self):
        out, fd, old = self.arrange()
        wrong = pub.Recovery(pub.IMAGE, pub.TAG, sha(b"another manifest"), self.OLD_REVISION)
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, recovery=wrong)
        self.assertIn("not the one state", str(cm.exception))
        self.assertEqual(fd.dev(), old)
        self.assertEqual(fd.writes(), ["login"])  # only the credential was used: no staging, no conversion, no create

    def test_another_unannotated_manifest_is_refused_even_with_the_recovery_offered(self):
        out, fd, old = self.arrange()
        for name, raw in (("the same document with other bytes", read_fixture("dev-index.json") + b"\n"),
                          ("an empty index", json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": []}).encode()),
                          ("an annotation that is not a revision", json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": [], "annotations": {pub.ANN_REVISION: "main"}}).encode())):
            with self.subTest(name):
                fd.calls.clear()
                seed_raw(fd, raw)
                with self.assertRaises(pub.Refuse) as cm:
                    publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)
                self.assertIn("not the one state", str(cm.exception))
                self.assertEqual(fd.dev(), sha(raw))
                self.assertEqual(fd.writes(), ["login"])

    def test_a_dev_that_changes_while_the_run_stages_is_not_replaced(self):
        devref = "%s:%s" % (pub.IMAGE, pub.TAG)
        other = json.dumps({"schemaVersion": 2, "mediaType": pub.OCI_INDEX, "manifests": [], "x": "someone else's"}).encode()
        for name, change in (("replaced by another unannotated manifest", lambda d: seed_raw(d, other)),
                             ("replaced by a newer annotated index", lambda d: Publish.seed_dev(self, d, NEW)),
                             ("deleted", lambda d: d.tags.pop(devref))):
            with self.subTest(name):
                out, fd, old = self.arrange()
                fd.after_stage = change  # the concurrent writer acts after the last push, before the run's second read
                with self.assertRaises(pub.Refuse) as cm:
                    publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)
                self.assertRegex(str(cm.exception), "no longer the manifest|not the one state")  # refused, not skipped: a different state is not authorised
                self.assertNotIn("buildx imagetools create", fd.names())
                self.assertNotEqual(fd.dev(), old)  # whatever the other writer left stays (or dev stays absent): it was not overwritten

    def test_the_recovery_is_bound_to_this_repository_and_to_the_dev_tag(self):
        local = "localhost:5000/mandatary"
        out, fd, _ = self.arrange()
        old = seed_raw(fd, read_fixture("dev-index.json"), image=local)  # the same bytes in another repository
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, image=local, fixture=True, recovery=pub.KNOWN_BAD_DEV)
        self.assertIn("no revision annotation", str(cm.exception))
        self.assertEqual(fd.tags["%s:%s" % (local, pub.TAG)], old)
        self.assertEqual(fd.writes(), [])
        for name, rec in (("another tag", pub.Recovery(pub.IMAGE, "latest", self.OLD_DIGEST, self.OLD_REVISION)),
                          ("another repository", pub.Recovery("ghcr.io/other/mandatary", pub.TAG, self.OLD_DIGEST, self.OLD_REVISION))):
            with self.subTest(name):
                out2, fd2, old2 = self.arrange()
                with self.assertRaises(pub.Refuse) as cm:
                    publish(fd2, self.git(), out2, SHA, env(), log=lambda *_: None, recovery=rec)
                self.assertIn("no revision annotation", str(cm.exception))
                self.assertEqual(fd2.dev(), old2)

    def test_the_recovery_does_not_apply_to_an_annotated_dev_and_changes_no_ordinary_rule(self):
        for name, seed, ancestors, outcome in (("an older annotated dev is replaced as usual", OLD, [(OLD, SHA)], "published"),
                                               ("a newer annotated dev is skipped as stale", NEW, [], "skipped"),
                                               ("the same commit is a repeated run", SHA, [], "skipped")):
            with self.subTest(name):
                out, fd = self.build_tested()
                if seed == SHA:
                    publish(fd, FakeGit(), out, SHA, env(), log=lambda *_: None)
                else:
                    Publish.seed_dev(self, fd, seed)
                before = fd.dev()
                try:
                    res = publish(fd, FakeGit(ancestors=ancestors), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)
                    self.assertEqual((outcome, res["recovered"]), ("published", None))
                    self.assertNotEqual(fd.dev(), before)
                except pub.Skip:
                    self.assertEqual(outcome, "skipped")
                    self.assertEqual(fd.dev(), before)

    def test_the_recovery_does_not_relax_the_freshness_order(self):
        out, fd, old = self.arrange()
        with self.assertRaises(pub.Skip):
            publish(fd, FakeGit(ancestors=[]), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)  # the run's commit is not newer than the recorded one
        self.assertEqual(fd.dev(), old)
        self.assertEqual(fd.writes(), ["login"])
        with self.assertRaises(pub.Refuse):
            publish(fd, FakeGit(unknown=True), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)  # an order that cannot be evaluated refuses
        self.assertEqual(fd.dev(), old)

    def test_a_recovery_whose_read_back_fails_is_not_a_recovery_and_leaves_no_bypass_behind(self):
        out, fd, old = self.arrange()
        fd.drop_annotations = {pub.ANN_REVISION}  # the create exits 0 and the index it wrote has no revision
        with self.assertRaises(pub.Refuse) as cm:
            publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, recovery=pub.KNOWN_BAD_DEV)
        self.assertIn("revision annotation", str(cm.exception))
        written = fd.dev()
        self.assertNotEqual(written, old)  # the write happened: the read-back failure does not undo it, and the run is red
        fd.calls.clear()
        for rec in (None, pub.KNOWN_BAD_DEV):  # the exception is spent: neither an ordinary run nor an offered recovery may replace this new state
            with self.assertRaises(pub.Refuse):
                publish(fd, self.git(), out, SHA, env(), log=lambda *_: None, recovery=rec)
            self.assertEqual(fd.dev(), written)
            for write in ("push", "api-put", "buildx imagetools create"):
                self.assertNotIn(write, fd.names())

    def test_the_command_line_offers_the_recovery_to_the_real_image_only(self):
        seen = []

        def capture(docker, git, tested, sha_, env_, **kw):
            seen.append(kw)
            return {"published": True, "index": "sha256:" + "a" * 64, "staged": {"amd64": "sha256:" + "b" * 64, "arm64": "sha256:" + "c" * 64}, "recovered": None}

        with mock.patch.object(pub, "publish", capture), mock.patch.dict(os.environ, env(), clear=True):
            self.assertEqual(pub.main(["publish", "--tested", self.d_unused()]), 0)
            self.assertEqual(pub.main(["publish", "--tested", self.d_unused(), "--fixture-registry", "localhost:5000/mandatary"]), 0)
        self.assertIs(seen[0]["recovery"], pub.KNOWN_BAD_DEV)
        self.assertEqual(seen[0]["image"], pub.IMAGE)
        self.assertIsNone(seen[1]["recovery"])
        self.assertTrue(seen[1]["fixture"])

    def d_unused(self):
        return os.path.join(self.d, "unused")


class FakeRegistryServer:
    """A loopback HTTP registry with the standard token handshake: a PUT without a bearer token is answered 401 with a Bearer challenge, the token endpoint
    wants basic authentication (actor:TOKEN), and a PUT with the bearer token stores the manifest. Everything it receives is recorded."""
    BEARER = "bearer-0123456789abcdef"

    def __init__(self, auth=True, challenge=None, realm_host=None, redirect_to=None, put_status=201, digest_header="same", token_status=200, actor="octo", token_redirect_to=None):
        self.requests, self.stored = [], {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def record(self, body=b""):
                outer.requests.append({"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})

            def reply(self, status, headers=None, body=b""):
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.record()
                if not self.path.startswith("/token"):
                    return self.reply(404)
                if token_redirect_to:
                    return self.reply(302, {"Location": token_redirect_to})
                want = "Basic " + base64.b64encode(("%s:%s" % (actor, TOKEN)).encode()).decode()
                if token_status != 200 or self.headers.get("Authorization") != want:
                    return self.reply(401)
                self.reply(200, {"Content-Type": "application/json"}, json.dumps({"token": outer.BEARER}).encode())

            def do_PUT(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.record(body)
                if redirect_to:
                    return self.reply(307, {"Location": redirect_to})
                if auth and self.headers.get("Authorization") != "Bearer " + outer.BEARER:
                    realm = 'Bearer realm="http://%s/token",service="fake-registry",scope="repository:mandatary:pull"' % (realm_host or outer.host)
                    return self.reply(401, {"WWW-Authenticate": challenge or realm})
                outer.stored[self.path] = (self.headers.get("Content-Type"), body)
                headers = {} if digest_header is None else {"Docker-Content-Digest": sha(body) if digest_header == "same" else digest_header}
                self.reply(put_status, headers)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host = "127.0.0.1:%d" % self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class HttpRegistryTests(unittest.TestCase):
    """HttpRegistry over real HTTP against a loopback server (no external network): the registry's token handshake, and where the credential may go."""
    BODY = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST}, sort_keys=True).encode()
    STAGE = "build-%s-amd64-oci" % SHA

    def test_only_the_oci_staging_tags_can_be_written_and_nothing_is_sent_for_another_tag(self):
        srv = self.server()
        reg = self.registry(srv)
        for tag in ("dev", "latest", "build-%s-amd64" % SHA, "build-%s-s390x-oci" % SHA, "build-%s-amd64-oci" % ("g" * 40), "../dev", "build-%s-amd64-oci/x" % SHA, "build-%s-amd64-oci\n" % SHA, ""):
            with self.subTest(tag):
                with self.assertRaises(pub.Refuse):
                    reg.put_manifest(tag, self.BODY, OCI_MANIFEST)
        self.assertEqual(srv.requests, [])  # refused before any request, so no credential left the process either
        self.assertEqual(reg.put_manifest("build-%s-arm64-oci" % SHA, self.BODY, OCI_MANIFEST), sha(self.BODY))

    def server(self, **kw):
        srv = FakeRegistryServer(**kw)
        self.addCleanup(srv.stop)
        return srv

    def registry(self, srv, token=TOKEN):
        return pub.HttpRegistry("%s/mandatary" % srv.host, token, "octo", timeout=10)

    def test_the_manifest_is_put_after_the_token_handshake_and_the_credential_goes_to_the_token_endpoint_only(self):
        srv = self.server()
        digest = self.registry(srv).put_manifest("build-%s-amd64-oci" % SHA, self.BODY, OCI_MANIFEST)
        self.assertEqual(digest, sha(self.BODY))
        self.assertEqual(srv.stored["/v2/mandatary/manifests/build-%s-amd64-oci" % SHA], (OCI_MANIFEST, self.BODY))
        first, token, second = srv.requests
        self.assertEqual((first["method"], second["method"], token["method"]), ("PUT", "PUT", "GET"))
        self.assertNotIn("authorization", first["headers"])  # the first attempt carries no credential at all
        self.assertEqual(token["headers"]["authorization"], "Basic " + base64.b64encode(("octo:%s" % TOKEN).encode()).decode())
        query = urllib.parse.parse_qs(urllib.parse.urlparse(token["path"]).query)
        self.assertEqual(query, {"scope": ["repository:mandatary:pull,push"], "service": ["fake-registry"]})
        self.assertEqual(second["headers"]["authorization"], "Bearer " + srv.BEARER)  # the manifest PUT carries the short-lived bearer token, not the credential
        for r in srv.requests:
            self.assertNotIn(TOKEN, r["path"])
            if r is not token:
                self.assertNotIn(TOKEN, json.dumps(r["headers"]))
        self.assertNotIn(srv.BEARER, token["path"])

    def test_a_registry_that_asks_for_no_authentication_gets_none(self):
        srv = self.server(auth=False)
        self.assertEqual(self.registry(srv, token="").put_manifest(self.STAGE, self.BODY, OCI_MANIFEST), sha(self.BODY))
        self.assertEqual([r["method"] for r in srv.requests], ["PUT"])

    def test_a_token_endpoint_on_another_host_never_receives_the_credential(self):
        elsewhere = self.server()
        srv = self.server(realm_host=elsewhere.host)
        with self.assertRaises(pub.Refuse) as cm:
            self.registry(srv).put_manifest(self.STAGE, self.BODY, OCI_MANIFEST)
        self.assertIn("another host", str(cm.exception))
        self.assertEqual(elsewhere.requests, [])
        self.assertEqual([r["method"] for r in srv.requests], ["PUT"])  # and not even the registry itself got the credential

    def test_a_redirect_is_not_followed(self):
        elsewhere = self.server()
        srv = self.server(redirect_to="http://%s/v2/mandatary/manifests/t" % elsewhere.host)
        with self.assertRaises(pub.Refuse):
            self.registry(srv).put_manifest(self.STAGE, self.BODY, OCI_MANIFEST)
        self.assertEqual(elsewhere.requests, [])
        srv = self.server(token_redirect_to="http://%s/token" % elsewhere.host)  # the credential would travel with a followed redirect of the token request
        with self.assertRaises(pub.Refuse) as cm:
            self.registry(srv).put_manifest(self.STAGE, self.BODY, OCI_MANIFEST)
        self.assertIn("token endpoint refused", str(cm.exception))
        self.assertEqual(elsewhere.requests, [])

    def test_an_answer_that_is_not_the_digest_of_the_bytes_sent_is_refused(self):
        for name, header in (("another digest", sha(b"other")), ("no digest", None)):
            with self.subTest(name):
                with self.assertRaises(pub.Refuse):
                    self.registry(self.server(digest_header=header)).put_manifest(self.STAGE, self.BODY, OCI_MANIFEST)

    def test_a_refusal_by_the_registry_or_its_token_endpoint_is_refused(self):
        for name, kw, expected in (("write refused", {"put_status": 403}, "HTTP 403"), ("token refused", {"token_status": 401}, "token endpoint refused"),
                                   ("an authentication this script does not use", {"challenge": 'Basic realm="registry"'}, "does not use")):
            with self.subTest(name):
                with self.assertRaises(pub.Refuse) as cm:
                    self.registry(self.server(**kw)).put_manifest(self.STAGE, self.BODY, OCI_MANIFEST)
                self.assertIn(expected, str(cm.exception))

    def test_a_registry_that_cannot_be_reached_is_refused_without_leaking_the_credential(self):
        srv = self.server()
        reg = self.registry(srv)
        srv.stop()
        with self.assertRaises(pub.Refuse) as cm:
            reg.put_manifest(self.STAGE, self.BODY, OCI_MANIFEST)
        self.assertNotIn(TOKEN, str(cm.exception))

    def test_only_a_loopback_registry_is_spoken_to_in_the_clear(self):
        self.assertEqual(pub.HttpRegistry("ghcr.io/nicotm77/mandatary").scheme, "https")
        self.assertEqual(pub.HttpRegistry("registry.example.test:5000/mandatary").scheme, "https")
        self.assertEqual(pub.HttpRegistry("localhost:5000/mandatary").scheme, "http")
        self.assertEqual(pub.HttpRegistry("127.0.0.1:5055/mandatary").scheme, "http")
        self.assertEqual(pub.HttpRegistry("ghcr.io/nicotm77/mandatary").path, "nicotm77/mandatary")
        with self.assertRaises(pub.Refuse):
            pub.HttpRegistry("ghcr.io")



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
