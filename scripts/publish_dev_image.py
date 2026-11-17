#!/usr/bin/env python3
"""Promote the exact, already tested images of a successful main run to ghcr.io/nicotm77/mandatary:dev (standard library only).

The CI workflow publishes only from a successful `push` to refs/heads/main of NicoTM77/Mandatary, after every required gate of that exact commit
succeeded (both architecture jobs included). This script is the part that runs in the publishing job; it is also exercised, hermetically and
against a fake registry, by tests/publish/test_publish.py.

    publish_dev_image.py record  --image mandatary-ci:ARCH --arch ARCH --out DIR     (Image job, after its tests passed, main push only)
    publish_dev_image.py gate                                                          (publishing job: re-check the event and every needed result)
    publish_dev_image.py publish --tested DIR                                          (publishing job: verify, stage, index, verify)

What is promoted is the tested artifact itself, not a rebuild: `record` saves the image the Image job just ran its acceptance on and records the
digest of its config (computed from the saved archive, never from a daemon's opinion); `publish` re-computes it, loads the archive and pushes it
under a per-commit staging tag, and accepts the pushed platform manifest only when its config digest is the tested one (the config carries the
labels, so the revision and source labels are covered by it). The `dev` tag is written once, by one `imagetools create` of an index that holds
exactly the two staged platform manifests, after BOTH are staged and verified; the result is read back (index, both platform descriptors,
digests, revision annotation) before the run reports success. Nothing is written to `dev` for a stale run: the current `dev` revision must be
an ancestor of (or equal to) this commit, so an older main run can never overwrite a newer tag.

The registry credential is the workflow's own GITHUB_TOKEN. It is read from the environment, handed to `docker login` on stdin only, kept in a
private temporary Docker config that is removed at the end, and is never put on a command line or printed.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

IMAGE = "ghcr.io/nicotm77/mandatary"
REPOSITORY = "NicoTM77/Mandatary"
SOURCE_URL = "https://github.com/NicoTM77/Mandatary"
TAG = "dev"
REQUIRED_JOBS = ("baseline", "negative-control", "storage-arm64", "image", "security")
ARCHES = ("amd64", "arm64")
LOCAL_TAG = "mandatary-ci:%s"
REVISION_LABEL = "org.opencontainers.image.revision"
SOURCE_LABEL = "org.opencontainers.image.source"
ANN_REVISION = REVISION_LABEL
ANN_SOURCE = SOURCE_LABEL
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PUSH_DIGEST = re.compile(r"\bdigest: (sha256:[0-9a-f]{64})\b")
MAX_JSON = 4 << 20
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
INDEX_TYPES = (OCI_INDEX, DOCKER_LIST)
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")


class Refuse(Exception):
    """The publication does not proceed (nothing was written to the dev tag)."""


class Skip(Exception):
    """The publication is not needed or not allowed for this run and that is not a failure (a stale or repeated run)."""


def sha256_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------------------------------------------------------ the gate


def gate(env, fixture=False):
    """Refuse unless this is a successful push to main of the canonical repository and every required job succeeded. Returns the commit."""
    if not fixture:
        if env.get("GITHUB_EVENT_NAME") != "push":
            raise Refuse("event is %r: publication runs only for a push" % env.get("GITHUB_EVENT_NAME"))
        if env.get("GITHUB_REF") != "refs/heads/main":
            raise Refuse("ref is %r: publication runs only for refs/heads/main" % env.get("GITHUB_REF"))
        if env.get("GITHUB_REPOSITORY") != REPOSITORY:
            raise Refuse("repository is %r: publication runs only in %s" % (env.get("GITHUB_REPOSITORY"), REPOSITORY))
        if env.get("GITHUB_BASE_REF") or env.get("GITHUB_HEAD_REF"):
            raise Refuse("this is a pull request run (a base or head ref is set)")
    sha = env.get("GITHUB_SHA", "")
    if not HEX40.match(sha):
        raise Refuse("GITHUB_SHA is not a full commit")
    try:
        needs = json.loads(env.get("NEEDS_RESULTS", ""))
    except ValueError:
        raise Refuse("NEEDS_RESULTS is not the JSON of the needed jobs")
    if not isinstance(needs, dict):
        raise Refuse("NEEDS_RESULTS is not an object")
    for job in REQUIRED_JOBS:
        result = (needs.get(job) or {}).get("result") if isinstance(needs.get(job), dict) else None
        if result != "success":
            raise Refuse("required job %r did not succeed (result: %r)" % (job, result))
    return sha


# ------------------------------------------------------------------------------------------------------------------- the saved image


def _read(tf, member, limit=MAX_JSON):
    f = tf.extractfile(member)
    if f is None:
        raise Refuse("unreadable archive member %s" % member.name)
    data = f.read(limit + 1)
    if len(data) > limit:
        raise Refuse("archive member %s is too large" % member.name)
    return data


def inspect_saved(path):
    """The facts of a `docker save` archive, read from the archive itself: {config_digest, os, architecture, labels}. Supports the classic
    layout (manifest.json) and the OCI layout (index.json + blobs). Anything else, or more than one image, is refused."""
    try:
        with tarfile.open(path, "r:*") as tf:
            names = {m.name: m for m in tf.getmembers() if m.isfile()}
            if "manifest.json" in names:
                entries = json.loads(_read(tf, names["manifest.json"]))
                if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
                    raise Refuse("the archive does not hold exactly one image")
                cfg_name = entries[0].get("Config", "")
                if cfg_name not in names:
                    raise Refuse("the archive's config is missing")
                cfg = _read(tf, names[cfg_name])
            elif "index.json" in names:
                index = json.loads(_read(tf, names["index.json"]))
                manifests = index.get("manifests") if isinstance(index, dict) else None
                if not isinstance(manifests, list) or len(manifests) != 1:
                    raise Refuse("the OCI archive does not hold exactly one image")
                blob = _blob(tf, names, manifests[0].get("digest", ""))
                mf = json.loads(blob)
                if mf.get("mediaType") in INDEX_TYPES:
                    raise Refuse("the OCI archive holds an index, not one image manifest")
                cfg = _blob(tf, names, (mf.get("config") or {}).get("digest", ""))
            else:
                raise Refuse("unrecognised image archive layout")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise Refuse("the image archive cannot be read: %s" % exc.__class__.__name__)
    try:
        doc = json.loads(cfg)
    except ValueError:
        raise Refuse("the image config is not JSON")
    labels = (doc.get("config") or {}).get("Labels") or {}
    return {"config_digest": sha256_bytes(cfg), "os": doc.get("os"), "architecture": doc.get("architecture"), "labels": labels if isinstance(labels, dict) else {}}


def _blob(tf, names, digest):
    if not DIGEST.match(digest or ""):
        raise Refuse("malformed blob digest in the OCI archive")
    member = names.get("blobs/sha256/" + digest.split(":", 1)[1])
    if member is None:
        raise Refuse("blob %s is missing from the OCI archive" % digest)
    data = _read(tf, member)
    if sha256_bytes(data) != digest:
        raise Refuse("blob %s does not match its digest" % digest)
    return data


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def check_facts(facts, arch, sha, source=SOURCE_URL):
    """The saved image must be this commit's linux/<arch> image with this repository as its source."""
    if facts["os"] != "linux" or facts["architecture"] != arch:
        raise Refuse("the image is %s/%s, expected linux/%s" % (facts["os"], facts["architecture"], arch))
    if facts["labels"].get(REVISION_LABEL) != sha:
        raise Refuse("the image revision label %r is not the commit %s" % (facts["labels"].get(REVISION_LABEL), sha))
    if facts["labels"].get(SOURCE_LABEL) != source:
        raise Refuse("the image source label %r is not %s" % (facts["labels"].get(SOURCE_LABEL), source))


def record(docker, image, arch, out, sha):
    """Save the tested image and write the record that `publish` verifies. The image must be this commit's linux/<arch> image."""
    if arch not in ARCHES:
        raise Refuse("unknown architecture %r" % arch)
    os.makedirs(out, exist_ok=True)
    tar = os.path.join(out, "image-%s.tar" % arch)
    p = docker(["save", "--output", tar, image])
    if p.returncode != 0:
        raise Refuse("docker save failed")
    facts = inspect_saved(tar)
    check_facts(facts, arch, sha)
    rec = {"arch": arch, "revision": sha, "config_digest": facts["config_digest"], "tar_sha256": sha256_file(tar), "image": image}
    with open(os.path.join(out, "image-%s.json" % arch), "w") as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return rec


def load_record(tested, arch, sha, source=SOURCE_URL):
    """Verify one recorded tested image against its archive and the commit; returns (record, tar_path). Touches no registry."""
    rec_path = os.path.join(tested, "tested-image-%s" % arch, "image-%s.json" % arch)
    if not os.path.isfile(rec_path):
        rec_path = os.path.join(tested, "image-%s.json" % arch)
    tar = os.path.join(os.path.dirname(rec_path), "image-%s.tar" % arch)
    if not os.path.isfile(rec_path) or not os.path.isfile(tar):
        raise Refuse("the tested image of %s is missing (record or archive)" % arch)
    with open(rec_path) as fh:
        try:
            rec = json.load(fh)
        except ValueError:
            raise Refuse("the record of %s is not JSON" % arch)
    if rec.get("arch") != arch or rec.get("revision") != sha:
        raise Refuse("the record of %s is for revision %r / arch %r, not %s / %s" % (arch, rec.get("revision"), rec.get("arch"), sha, arch))
    if not DIGEST.match(str(rec.get("config_digest", ""))) or not DIGEST.match(str(rec.get("tar_sha256", ""))):
        raise Refuse("the record of %s holds no digests" % arch)
    if sha256_file(tar) != rec["tar_sha256"]:
        raise Refuse("the archive of %s is not the one that was recorded (SHA-256 mismatch)" % arch)
    facts = inspect_saved(tar)
    if facts["config_digest"] != rec["config_digest"]:
        raise Refuse("the archive of %s does not hold the recorded config digest" % arch)
    check_facts(facts, arch, sha, source)
    return rec, tar


# --------------------------------------------------------------------------------------------------------------------------- the registry


class Registry:
    """The few registry operations of the publication, over an injectable docker runner (a fake in the hermetic tests)."""

    def __init__(self, docker, image=IMAGE):
        self.docker, self.image = docker, image

    def raw(self, ref):
        """(rc, stdout bytes, stderr text) of the raw manifest of `ref`."""
        p = self.docker(["buildx", "imagetools", "inspect", "--raw", ref])
        err = p.stderr.decode("utf-8", "replace") if isinstance(p.stderr, bytes) else (p.stderr or "")
        return p.returncode, p.stdout, err

    def manifest(self, ref):
        rc, out, err = self.raw(ref)
        if rc != 0:
            raise Refuse("cannot read %s: %s" % (ref, err.strip()[:200]))
        if len(out) > MAX_JSON:
            raise Refuse("the manifest of %s is too large" % ref)
        try:
            return json.loads(out), sha256_bytes(out)
        except ValueError:
            raise Refuse("the manifest of %s is not JSON" % ref)

    def current_dev(self):
        """None when the tag does not exist yet, else (revision, index digest, index). Any other failure refuses (fail closed)."""
        rc, out, err = self.raw("%s:%s" % (self.image, TAG))
        if rc != 0:
            low = err.lower()
            if "not found" in low or "manifest unknown" in low or "404" in low or "name unknown" in low:
                return None
            raise Refuse("cannot read the current %s tag: %s" % (TAG, err.strip()[:200]))
        try:
            doc = json.loads(out)
        except ValueError:
            raise Refuse("the current %s tag is not JSON" % TAG)
        rev = (doc.get("annotations") or {}).get(ANN_REVISION) if isinstance(doc, dict) else None
        if not rev or not HEX40.match(rev):
            raise Refuse("the current %s tag carries no revision annotation: a human must decide before it is overwritten" % TAG)
        return rev, sha256_bytes(out), doc

    def stage(self, local, arch, sha, config_digest):
        """Push the loaded image under its per-commit staging tag; accept it only when the pushed manifest's config is the tested one."""
        ref = "%s:build-%s-%s" % (self.image, sha, arch)
        if self.docker(["tag", local, ref]).returncode != 0:
            raise Refuse("docker tag failed for %s" % arch)
        p = self.docker(["push", ref])
        if p.returncode != 0:
            raise Refuse("docker push failed for %s" % arch)
        out = p.stdout.decode("utf-8", "replace") if isinstance(p.stdout, bytes) else (p.stdout or "")
        m = PUSH_DIGEST.findall(out)
        if not m:
            raise Refuse("docker push of %s reported no digest" % arch)
        digest = m[-1]
        doc, got = self.manifest("%s@%s" % (self.image, digest))
        if got != digest:
            raise Refuse("the registry served a manifest whose digest %s is not the pushed %s" % (got, digest))
        if doc.get("mediaType") in INDEX_TYPES or "manifests" in doc:
            # A daemon with the containerd image store pushes the image as a one-platform index (plus, possibly, build attestations). The
            # image manifest inside it is what is promoted; the index is accepted only in exactly that shape.
            digest = self._child_image(doc, arch)
            doc, got = self.manifest("%s@%s" % (self.image, digest))
            if got != digest:
                raise Refuse("the registry served a manifest whose digest %s is not the listed %s" % (got, digest))
        if doc.get("mediaType") not in MANIFEST_TYPES or "manifests" in doc:
            raise Refuse("the pushed %s object is not a single image manifest" % arch)
        if (doc.get("config") or {}).get("digest") != config_digest:
            raise Refuse("the pushed %s manifest holds config %s, not the tested %s" % (arch, (doc.get("config") or {}).get("digest"), config_digest))
        if not doc.get("layers"):
            raise Refuse("the pushed %s manifest has no layers" % arch)
        return digest

    @staticmethod
    def _child_image(index, arch):
        """The digest of the single linux/<arch> image manifest of a pushed one-platform index; build attestations may sit beside it, nothing else."""
        entries = index.get("manifests")
        if not isinstance(entries, list) or not entries:
            raise Refuse("the pushed %s index lists no manifest" % arch)
        images = []
        for e in entries:
            if not isinstance(e, dict):
                raise Refuse("the pushed %s index holds a malformed entry" % arch)
            if (e.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest":
                continue
            images.append(e)
        if len(images) != 1:
            raise Refuse("the pushed %s index holds %d image manifests, expected exactly one" % (arch, len(images)))
        e = images[0]
        plat = e.get("platform") or {}
        if (plat.get("os"), plat.get("architecture")) != ("linux", arch) or not DIGEST.match(str(e.get("digest", ""))):
            raise Refuse("the pushed %s index entry is %s/%s, expected linux/%s" % (arch, plat.get("os"), plat.get("architecture"), arch))
        return e["digest"]

    def create_index(self, staged, sha):
        refs = ["%s@%s" % (self.image, staged[a]) for a in ARCHES]
        args = ["buildx", "imagetools", "create", "--tag", "%s:%s" % (self.image, TAG),
                "--annotation", "index:%s=%s" % (ANN_REVISION, sha), "--annotation", "index:%s=%s" % (ANN_SOURCE, SOURCE_URL)] + refs
        if self.docker(args).returncode != 0:
            raise Refuse("imagetools create failed (the dev tag was not updated by a completed create)")

    def verify_index(self, staged, sha):
        """Read the dev tag back: an index of exactly the two staged manifests, linux/amd64 and linux/arm64, annotated with this revision."""
        doc, digest = self.manifest("%s:%s" % (self.image, TAG))
        if doc.get("mediaType") not in INDEX_TYPES:
            raise Refuse("the dev tag is not an index (%r)" % doc.get("mediaType"))
        entries = doc.get("manifests")
        if not isinstance(entries, list) or len(entries) != len(ARCHES):
            raise Refuse("the dev index holds %s manifests, expected exactly %d" % (len(entries) if isinstance(entries, list) else "no", len(ARCHES)))
        seen = {}
        for e in entries:
            plat = e.get("platform") or {}
            key = (plat.get("os"), plat.get("architecture"))
            if key in seen:
                raise Refuse("duplicate platform %s/%s in the dev index" % key)
            seen[key] = e.get("digest")
        for a in ARCHES:
            if seen.get(("linux", a)) != staged[a]:
                raise Refuse("the dev index platform linux/%s is %r, not the staged %s" % (a, seen.get(("linux", a)), staged[a]))
        if (doc.get("annotations") or {}).get(ANN_REVISION) != sha:
            raise Refuse("the dev index revision annotation is not %s" % sha)
        return digest


def ancestor(git, old, new):
    p = git(["merge-base", "--is-ancestor", old, new])
    if p.returncode == 0:
        return True
    if p.returncode == 1:
        return False
    raise Refuse("cannot order revisions %s and %s (is the history fetched?)" % (old[:12], new[:12]))


def publish(docker, git, tested, sha, env, image=IMAGE, source=SOURCE_URL, fixture=False, log=print):
    """The whole publication. Returns {published, index, staged}; raises Refuse (nothing published) or Skip (stale or already current)."""
    # 1. Everything that can be checked without the registry is checked first: no login and no write unless both tested images are good.
    records = {a: load_record(tested, a, sha, source) for a in ARCHES}
    reg = Registry(docker, image)
    cfg_dir = None
    token = env.get("GITHUB_TOKEN", "")
    if not fixture:
        if not token:
            raise Refuse("no GITHUB_TOKEN in the environment")
        cfg_dir = tempfile.mkdtemp(prefix="docker-config-")
        os.chmod(cfg_dir, 0o700)
        docker.config_dir = cfg_dir
    try:
        if not fixture:
            p = docker(["login", "ghcr.io", "--username", env.get("GITHUB_ACTOR") or "github-actions", "--password-stdin"], input=token.encode())
            if p.returncode != 0:
                raise Refuse("docker login failed")
        # 2. Order: this commit must not be older than what dev already is.
        cur = reg.current_dev()
        if cur is not None:
            rev = cur[0]
            if rev == sha:
                reg.verify_index(_staged_from_index(cur[2]), sha)
                raise Skip("dev already is %s (a repeated run); nothing to do" % sha)
            if not ancestor(git, rev, sha):
                raise Skip("dev is at %s, which is not an ancestor of %s: this run is stale and does not overwrite it" % (rev[:12], sha[:12]))
        # 3. Load, stage and verify both platforms. A failure here leaves dev untouched.
        staged = {}
        for a in ARCHES:
            rec, tar = records[a]
            if docker(["load", "--input", tar]).returncode != 0:
                raise Refuse("docker load failed for %s" % a)
            staged[a] = reg.stage(LOCAL_TAG % a, a, sha, rec["config_digest"])
            log("staged linux/%s: %s@%s (tested config %s)" % (a, image, staged[a], rec["config_digest"]))
        # 4. Re-read dev right before writing it (the publishing jobs are serialized, this keeps the check close to the write).
        again = reg.current_dev()
        if again is not None and again[0] != (cur[0] if cur else None):
            raise Skip("dev changed to %s while this run was staging" % again[0][:12])
        reg.create_index(staged, sha)
        index = reg.verify_index(staged, sha)
        log("published %s:%s -> %s (linux/amd64 %s, linux/arm64 %s, revision %s)" % (image, TAG, index, staged["amd64"], staged["arm64"], sha))
        return {"published": True, "index": index, "staged": staged}
    finally:
        if not fixture:
            try:
                docker(["logout", "ghcr.io"])
            finally:
                if cfg_dir:
                    shutil.rmtree(cfg_dir, ignore_errors=True)
                    docker.config_dir = None


def _staged_from_index(doc):
    out = {}
    for e in doc.get("manifests", []):
        p = e.get("platform") or {}
        if p.get("os") == "linux" and p.get("architecture") in ARCHES:
            out[p["architecture"]] = e.get("digest")
    if set(out) != set(ARCHES):
        raise Refuse("the current dev index lacks a linux/amd64 or linux/arm64 manifest")
    return out


# ------------------------------------------------------------------------------------------------------------------------------- the CLI


class Runner:
    """subprocess wrapper; `docker.config_dir` points the docker CLI at a private config directory while logged in."""

    def __init__(self, exe, timeout=600):
        self.exe, self.timeout, self.config_dir = exe, timeout, None

    def __call__(self, args, input=None):
        env = dict(os.environ)
        if self.config_dir:
            env["DOCKER_CONFIG"] = self.config_dir
        return subprocess.run([self.exe] + list(args), input=input, capture_output=True, timeout=self.timeout, env=env, check=False)  # noqa: S603


def _summary(lines):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as fh:
            fh.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("record")
    s.add_argument("--image", required=True)
    s.add_argument("--arch", required=True, choices=ARCHES)
    s.add_argument("--out", required=True)
    sp.add_parser("gate")
    s = sp.add_parser("publish")
    s.add_argument("--tested", required=True)
    s.add_argument("--fixture-registry", help="TESTS ONLY: push to this local registry repository instead of ghcr.io (skips the event gate and the login)")
    a = ap.parse_args(argv)
    env = os.environ
    try:
        if a.cmd == "gate":
            sha = gate(env)
            print("publication gate open for %s on %s" % (sha, env.get("GITHUB_REF")))
            return 0
        if a.cmd == "record":
            sha = env.get("GITHUB_SHA", "")
            if not HEX40.match(sha):
                raise Refuse("GITHUB_SHA is not a full commit")
            rec = record(Runner("docker"), a.image, a.arch, a.out, sha)
            print("recorded %s: config %s, archive %s" % (a.arch, rec["config_digest"], rec["tar_sha256"]))
            return 0
        fixture = bool(a.fixture_registry)
        sha = gate(env, fixture=fixture)
        res = publish(Runner("docker"), Runner("git", 60), a.tested, sha, env, image=a.fixture_registry or IMAGE, fixture=fixture)
        _summary(["### dev image published", "", "* `%s:%s` -> `%s`" % (a.fixture_registry or IMAGE, TAG, res["index"]),
                  "* linux/amd64 `%s`, linux/arm64 `%s`, revision `%s`" % (res["staged"]["amd64"], res["staged"]["arm64"], sha)])
        return 0
    except Skip as exc:
        print("SKIPPED (not a failure): %s" % exc)
        _summary(["### dev image NOT published (skipped)", "", str(exc)])
        return 0
    except Refuse as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        _summary(["### dev image NOT published (refused)", "", str(exc)])
        return 1


if __name__ == "__main__":
    sys.exit(main())
