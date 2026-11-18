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

What is published is an OCI image INDEX (annotated with the revision and the source) of two OCI platform manifests. A hosted runner's classic image
store pushes Docker v2 platform manifests, and a Docker manifest list cannot carry annotations (the first main publication wrote exactly that: finding
F-C5-1). So each pushed Docker v2 manifest is converted, before anything is written to `dev`, to its OCI form: the same config blob and the same
layer blobs, only the media types change, so the config digest (the tested image's identity) is unchanged. The OCI manifest is written under a
per-commit staging tag with a plain registry API call (the docker CLI cannot put a manifest it did not build), read back, and checked against the
tested config digest. If the platform manifests cannot be made OCI, nothing is written to `dev`.

The registry credential is the workflow's own GITHUB_TOKEN. It is read from the environment, handed to `docker login` on stdin only, kept in a
private temporary Docker config that is removed at the end, used as the HTTP basic credential of the registry's token endpoint only (same host,
no redirect is followed) and never put on a command line or printed.

One-time recovery (finding F-C5-1): the dev tag currently holds an unannotated Docker manifest list, and an ordinary run refuses to overwrite a tag
that carries no revision. The ONLY exception is KNOWN_BAD_DEV: it applies to ghcr.io/nicotm77/mandatary:dev only, only while the tag serves exactly
the manifest with the recorded digest, and it is checked again right before the write. Any other digest or state is refused. It is inert once
that manifest is gone. A registry tag write has no compare-and-swap: see docs/ci-image-publication.md for what that leaves open.
"""
import argparse
import base64
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

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
STAGING_OCI_TAG = re.compile(r"^build-[0-9a-f]{40}-(?:amd64|arm64)-oci\Z")
PUSH_DIGEST = re.compile(r"\bdigest: (sha256:[0-9a-f]{64})\b")
MAX_JSON = 4 << 20
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
INDEX_TYPES = (OCI_INDEX, DOCKER_LIST)
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
MANIFEST_TYPES = (OCI_MANIFEST, DOCKER_MANIFEST)
# Docker v2 -> OCI media types of the layer blobs of an image manifest. The blobs themselves (and so every digest) are untouched. Anything else is refused.
LAYER_TO_OCI = {"application/vnd.docker.image.rootfs.diff.tar.gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
                "application/vnd.docker.image.rootfs.diff.tar": "application/vnd.oci.image.layer.v1.tar"}

# The one registry state a one-time recovery may replace (finding F-C5-1): the Docker manifest list the first main publication left on `dev`, with
# no annotation. Its children are the config-verified images of revision `revision` (read anonymously and kept as evidence on the C5 card).
Recovery = collections.namedtuple("Recovery", "image tag digest revision")
KNOWN_BAD_DEV = Recovery(IMAGE, TAG, "sha256:0c8894070085f72c9709f191cfcc7c0998ff3950c39aa4b5887df4bff6d0486e", "666ee9ce16d80440a9969c72b653975e84ba8ced")
# What the dev tag serves: the revision it is judged by, the digest, parsed and raw bytes of its manifest, and whether it is the recovery state.
Dev = collections.namedtuple("Dev", "revision digest doc raw recovering")
_UNKNOWN = object()


class Refuse(Exception):
    """The publication does not proceed. Raised before the create, nothing was written to the dev tag; raised by the create's failure or by the
    read-back after it, dev may have been written (the message then says what dev serves)."""


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


def oci_manifest_bytes(doc, config_digest):
    """The OCI image manifest (canonical JSON bytes) of a Docker v2 image manifest: the config and every layer keep their digest and size (the blobs are
    the same objects), only the media types change. Refuses a manifest of another kind, another config than the tested one, an unknown blob media type,
    a foreign layer (`urls`), or any field it does not know, so that nothing is silently dropped."""
    if not isinstance(doc, dict) or doc.get("schemaVersion") != 2 or doc.get("mediaType") != DOCKER_MANIFEST:
        raise Refuse("the manifest is not a Docker v2 image manifest, so it cannot be converted")
    if set(doc) - {"schemaVersion", "mediaType", "config", "layers"}:
        raise Refuse("the Docker v2 manifest has fields that would be lost in the conversion: %s" % sorted(set(doc) - {"schemaVersion", "mediaType", "config", "layers"}))

    def blob(d, media_map, what):
        if not isinstance(d, dict) or set(d) - {"mediaType", "size", "digest"}:
            raise Refuse("the Docker v2 %s descriptor has fields that would be lost in the conversion" % what)
        if d.get("mediaType") not in media_map:
            raise Refuse("the Docker v2 %s has media type %r, which has no OCI equivalent here" % (what, d.get("mediaType")))
        if not DIGEST.match(str(d.get("digest", ""))) or not isinstance(d.get("size"), int) or isinstance(d.get("size"), bool) or d["size"] < 0:
            raise Refuse("the Docker v2 %s descriptor holds no valid digest and size" % what)
        return {"mediaType": media_map[d["mediaType"]], "digest": d["digest"], "size": d["size"]}

    cfg = blob(doc.get("config"), {DOCKER_CONFIG: OCI_CONFIG}, "config")
    if cfg["digest"] != config_digest:
        raise Refuse("the Docker v2 manifest holds config %s, not the tested %s" % (cfg["digest"], config_digest))
    layers = doc.get("layers")
    if not isinstance(layers, list) or not layers:
        raise Refuse("the Docker v2 manifest has no layers")
    out = {"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": cfg, "layers": [blob(l, LAYER_TO_OCI, "layer") for l in layers]}
    return json.dumps(out, sort_keys=True, separators=(",", ":")).encode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A registry call that is redirected is refused: the credential must not follow it anywhere."""

    def redirect_request(self, *args, **kwargs):
        return None


class HttpRegistry:
    """The one registry write the docker CLI cannot make: PUT a manifest (bytes this script built) under a tag of its own repository, with the registry's
    standard token authentication (a 401 challenge names the token endpoint; the credential goes there as HTTP basic authentication and nowhere else:
    same host, https or loopback, no redirect, never in a URL, header of another request or message)."""

    def __init__(self, image, token="", actor="", timeout=60):
        host, _, path = image.partition("/")
        if not host or not path:
            raise Refuse("%r is not a registry repository" % image)
        self.host, self.path, self.token, self.actor, self.timeout = host, path, token, actor or "github-actions", timeout
        self.loopback = host.rsplit(":", 1)[0] in ("localhost", "127.0.0.1")
        self.scheme = "http" if self.loopback else "https"
        handlers = [_NoRedirect()] + ([urllib.request.ProxyHandler({})] if self.loopback else [])
        self.opener = urllib.request.build_opener(*handlers)

    def _open(self, req):
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.headers, r.read(MAX_JSON + 1)
        except urllib.error.HTTPError as exc:  # also a refused redirect
            return exc.code, exc.headers, exc.read(MAX_JSON + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise Refuse("the registry request failed: %s" % exc.__class__.__name__)

    def _bearer(self, challenge):
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge or ""))
        if not (challenge or "").lower().startswith("bearer ") or not fields.get("realm"):
            raise Refuse("the registry asks for an authentication this script does not use")
        realm = urllib.parse.urlparse(fields["realm"])
        if realm.scheme != self.scheme or realm.netloc != self.host or realm.fragment or realm.username or realm.password:
            raise Refuse("the registry names a token endpoint on another host or scheme (%s): the credential is not sent there" % realm.netloc)
        query = {"scope": "repository:%s:pull,push" % self.path}
        if fields.get("service"):
            query["service"] = fields["service"]
        headers = {}
        if self.token:
            headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (self.actor, self.token)).encode("utf-8")).decode("ascii")
        url = "%s://%s%s?%s" % (self.scheme, self.host, realm.path, urllib.parse.urlencode(query))
        status, _, body = self._open(urllib.request.Request(url, headers=headers, method="GET"))
        if status != 200:
            raise Refuse("the registry's token endpoint refused the request (HTTP %d)" % status)
        try:
            tok = json.loads(body)
        except ValueError:
            raise Refuse("the registry's token endpoint did not answer JSON")
        value = (tok.get("token") or tok.get("access_token")) if isinstance(tok, dict) else None
        if not value or not isinstance(value, str):
            raise Refuse("the registry's token endpoint returned no token")
        return value

    def put_manifest(self, reference, body, media_type):
        """PUT `body` as the manifest `reference` (a tag) and return its digest, which the registry must report as the SHA-256 of exactly these bytes.
        Only the per-commit OCI staging tags can be written this way: the dev tag is written by `imagetools create` alone, and no other tag by anything."""
        if not STAGING_OCI_TAG.match(reference):
            raise Refuse("%r is not a staging tag: the registry API writes only build-<commit>-<arch>-oci" % reference)
        want = sha256_bytes(body)
        url = "%s://%s/v2/%s/manifests/%s" % (self.scheme, self.host, self.path, urllib.parse.quote(reference, safe=""))
        bearer = None
        status, hdr = 0, {}
        for _attempt in range(2):
            headers = {"Content-Type": media_type}
            if bearer:
                headers["Authorization"] = "Bearer " + bearer
            status, hdr, _body = self._open(urllib.request.Request(url, data=body, headers=headers, method="PUT"))
            if status == 401 and bearer is None:
                bearer = self._bearer(hdr.get("WWW-Authenticate"))
                continue
            break
        if status not in (200, 201):
            raise Refuse("the registry refused the manifest %s (HTTP %d)" % (reference, status))
        got = hdr.get("Docker-Content-Digest")
        if got != want:
            raise Refuse("the registry reports digest %r for the manifest %s, expected %s" % (got, reference, want))
        return want


class Registry:
    """The few registry operations of the publication, over an injectable docker runner (a fake in the hermetic tests)."""

    def __init__(self, docker, image=IMAGE, api=None):
        self.docker, self.image, self.api = docker, image, api

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

    def _read_dev(self):
        """None when the tag does not exist yet, else the raw bytes it serves. Any other failure refuses (fail closed)."""
        rc, out, err = self.raw("%s:%s" % (self.image, TAG))
        if rc != 0:
            low = err.lower()
            if "not found" in low or "manifest unknown" in low or "404" in low or "name unknown" in low:
                return None
            raise Refuse("cannot read the current %s tag: %s" % (TAG, err.strip()[:200]))
        if len(out) > MAX_JSON:
            raise Refuse("the current %s tag is too large" % TAG)
        return out

    def dev_digest(self):
        """The digest of the manifest the dev tag serves now, None when it does not exist."""
        out = self._read_dev()
        return None if out is None else sha256_bytes(out)

    def current_dev(self, recovery=None):
        """None when the tag does not exist yet, else a Dev. Any other failure refuses (fail closed).

        A tag without a usable revision annotation is refused: a human must decide before it is overwritten. The single exception is `recovery` (the
        explicit, one-time KNOWN_BAD_DEV, handed over by the caller): it applies to this repository's dev tag only and only while the tag serves
        exactly the manifest with the recorded digest; the revision it is then judged by is the recorded one. Any other digest is refused."""
        out = self._read_dev()
        if out is None:
            return None
        try:
            doc = json.loads(out)
        except ValueError:
            raise Refuse("the current %s tag is not JSON" % TAG)
        digest = sha256_bytes(out)
        rev = (doc.get("annotations") or {}).get(ANN_REVISION) if isinstance(doc, dict) else None
        if rev and HEX40.match(rev):
            return Dev(rev, digest, doc, out, False)
        if recovery is not None and recovery.image == self.image and recovery.tag == TAG:
            if digest != recovery.digest:
                raise Refuse("the current %s tag (%s) carries no revision annotation and is not the one state its recovery is authorised for (%s): "
                             "refused, a human must decide before it is overwritten" % (TAG, digest, recovery.digest))
            return Dev(recovery.revision, digest, doc, out, True)
        raise Refuse("the current %s tag carries no revision annotation: a human must decide before it is overwritten" % TAG)

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
        if doc.get("mediaType") == DOCKER_MANIFEST:
            # A classic image store pushes Docker v2 manifests, which an annotated OCI index cannot honestly list: promote the OCI form of the same image.
            digest = self.convert_to_oci(doc, arch, sha, config_digest)
        return digest

    def convert_to_oci(self, doc, arch, sha, config_digest):
        """Write the OCI form of a pushed Docker v2 image manifest (same config and layer blobs, only the media types differ) under the staging tag
        `build-<commit>-<arch>-oci`, read it back, and return its digest. The tested config digest must survive unchanged. Any failure refuses,
        before anything is written to the dev tag."""
        body = oci_manifest_bytes(doc, config_digest)
        want = sha256_bytes(body)
        if self.api is None:
            raise Refuse("the %s manifest is a Docker v2 manifest and there is no registry API to write its OCI form" % arch)
        ref = "build-%s-%s-oci" % (sha, arch)
        got = self.api.put_manifest(ref, body, OCI_MANIFEST)
        if got != want:
            raise Refuse("the registry reports digest %s for the OCI manifest of %s, expected %s" % (got, arch, want))
        back, back_digest = self.manifest("%s@%s" % (self.image, want))
        if back_digest != want:
            raise Refuse("the registry served a manifest whose digest %s is not the written OCI manifest %s" % (back_digest, want))
        self.require_oci_image(back, arch, config_digest, [l.get("digest") for l in doc["layers"]])
        return want

    @staticmethod
    def require_oci_image(doc, arch, config_digest, layer_digests=None):
        """The object is an OCI image manifest holding exactly the tested config (and, when given, the layers) of linux/<arch>."""
        if not isinstance(doc, dict) or doc.get("mediaType") != OCI_MANIFEST or "manifests" in doc:
            raise Refuse("the %s platform manifest is not an OCI image manifest (%r)" % (arch, doc.get("mediaType") if isinstance(doc, dict) else None))
        cfg = doc.get("config") or {}
        if cfg.get("digest") != config_digest or cfg.get("mediaType") != OCI_CONFIG:
            raise Refuse("the %s OCI manifest holds config %s (%s), not the tested %s" % (arch, cfg.get("digest"), cfg.get("mediaType"), config_digest))
        if layer_digests is not None and [l.get("digest") for l in doc.get("layers") or []] != layer_digests:
            raise Refuse("the %s OCI manifest does not hold the layers of the pushed image" % arch)

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

    def require_oci_children(self, staged, configs):
        """Refuse BEFORE the dev tag is written unless both staged platform manifests are, as the registry serves them now, OCI image manifests that hold
        the tested config: a Docker v2 child makes `imagetools create` write a Docker manifest list (no annotations) or fail, and neither is the
        publication that is promised."""
        for a in ARCHES:
            doc, digest = self.manifest("%s@%s" % (self.image, staged[a]))
            if digest != staged[a]:
                raise Refuse("the registry served a manifest whose digest %s is not the staged %s" % (digest, staged[a]))
            try:
                self.require_oci_image(doc, a, configs[a])
            except Refuse as exc:
                raise Refuse("%s: dev is not written" % exc)

    def create_index(self, staged, sha, configs, before=_UNKNOWN):
        """Write the dev tag: one `imagetools create` of an index of the two staged OCI manifests, annotated with the revision and the source. This IS the
        write. `before` is the digest dev served just before (None: absent); it only serves to report what a FAILED create left behind."""
        self.require_oci_children(staged, configs)
        refs = ["%s@%s" % (self.image, staged[a]) for a in ARCHES]
        args = ["buildx", "imagetools", "create", "--tag", "%s:%s" % (self.image, TAG),
                "--annotation", "index:%s=%s" % (ANN_REVISION, sha), "--annotation", "index:%s=%s" % (ANN_SOURCE, SOURCE_URL)] + refs
        p = self.docker(args)
        if p.returncode != 0:
            raise Refuse("imagetools create failed (exit status %s); %s" % (p.returncode, self._after_failed_create(before)))

    def _after_failed_create(self, before):
        """A failed command is not proof that nothing was written (the registry may have taken the write before the client failed): say what dev serves."""
        try:
            now = self.dev_digest()
        except Refuse as exc:
            return "dev could not be read afterwards (%s), so whether it was changed is not known" % exc
        if before is _UNKNOWN:
            return "dev serves %s afterwards" % now
        if now == before:
            return "dev was read back afterwards and is unchanged (%s)" % now
        return "dev was read back afterwards and HAS CHANGED (was %s, is %s): a failed create is not proof that nothing was written" % (before, now)

    def verify_index(self, staged, sha, configs):
        """Read the dev tag back, independently of the create's exit status: an OCI image index of exactly the two staged OCI manifests, linux/amd64 and
        linux/arm64, annotated with this revision and this source, each of which holds the tested config of its platform."""
        doc, digest = self.manifest("%s:%s" % (self.image, TAG))
        if doc.get("mediaType") != OCI_INDEX:
            raise Refuse("the dev tag is not an OCI image index (%r)" % doc.get("mediaType"))
        entries = doc.get("manifests")
        if not isinstance(entries, list) or len(entries) != len(ARCHES):
            raise Refuse("the dev index holds %s manifests, expected exactly %d" % (len(entries) if isinstance(entries, list) else "no", len(ARCHES)))
        seen = {}
        for e in entries:
            plat = e.get("platform") or {}
            key = (plat.get("os"), plat.get("architecture"))
            if key in seen:
                raise Refuse("duplicate platform %s/%s in the dev index" % key)
            seen[key] = e
        for a in ARCHES:
            e = seen.get(("linux", a)) or {}
            if e.get("digest") != staged[a]:
                raise Refuse("the dev index platform linux/%s is %r, not the staged %s" % (a, e.get("digest"), staged[a]))
            if e.get("mediaType") != OCI_MANIFEST:
                raise Refuse("the dev index lists the linux/%s platform manifest as %r, not an OCI image manifest" % (a, e.get("mediaType")))
        annotations = doc.get("annotations") or {}
        if annotations.get(ANN_REVISION) != sha:
            raise Refuse("the dev index revision annotation is not %s" % sha)
        if annotations.get(ANN_SOURCE) != SOURCE_URL:
            raise Refuse("the dev index source annotation is not %s" % SOURCE_URL)
        for a in ARCHES:  # the tested identity of each child, read from the registry
            child, child_digest = self.manifest("%s@%s" % (self.image, staged[a]))
            if child_digest != staged[a]:
                raise Refuse("the registry served a manifest whose digest %s is not the listed %s" % (child_digest, staged[a]))
            self.require_oci_image(child, a, configs[a])
        return digest


def ancestor(git, old, new):
    p = git(["merge-base", "--is-ancestor", old, new])
    if p.returncode == 0:
        return True
    if p.returncode == 1:
        return False
    raise Refuse("cannot order revisions %s and %s (is the history fetched?)" % (old[:12], new[:12]))


def publish(docker, git, tested, sha, env, image=IMAGE, source=SOURCE_URL, fixture=False, log=print, api=None, recovery=None):
    """The whole publication. Returns {published, index, staged, recovered}; raises Refuse or Skip (stale or already current).

    A Refuse raised before the create leaves dev as it was. The create is the write: a Refuse from the read-back after it (or from a create that
    reported failure) can mean dev was changed, and the message says what dev serves.

    `recovery` (the one-time KNOWN_BAD_DEV, only ever passed by main() for the real image) lets this run replace that exact unannotated manifest, once."""
    # 1. Everything that can be checked without the registry is checked first: no login and no write unless both tested images are good.
    records = {a: load_record(tested, a, sha, source) for a in ARCHES}
    configs = {a: records[a][0]["config_digest"] for a in ARCHES}
    token = env.get("GITHUB_TOKEN", "")
    reg = Registry(docker, image, api or HttpRegistry(image, token, env.get("GITHUB_ACTOR", "")))
    cfg_dir = None
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
        cur = reg.current_dev(recovery)
        if cur is not None:
            rev = cur.revision
            if rev == sha and not cur.recovering:
                reg.verify_index(_staged_from_index(cur.doc), sha, configs)
                raise Skip("dev already is %s (a repeated run); nothing to do" % sha)
            if not ancestor(git, rev, sha):
                raise Skip("dev is at %s, which is not an ancestor of %s: this run is stale and does not overwrite it" % (rev[:12], sha[:12]))
        # 3. Load, stage and verify both platforms (the OCI form of each is what is staged). A failure here leaves dev untouched.
        staged = {}
        for a in ARCHES:
            rec, tar = records[a]
            if docker(["load", "--input", tar]).returncode != 0:
                raise Refuse("docker load failed for %s" % a)
            staged[a] = reg.stage(LOCAL_TAG % a, a, sha, rec["config_digest"])
            log("staged linux/%s: %s@%s (tested config %s)" % (a, image, staged[a], rec["config_digest"]))
        # 4. Re-read dev right before writing it (the publishing jobs are serialized, this keeps the check close to the write). A registry tag write
        #    cannot be made conditional on what the tag holds (no compare-and-swap): the window between this read and the create is short, not closed.
        again = reg.current_dev(recovery)
        if cur is not None and cur.recovering:
            # The recovery is authorised for exactly one state. Anything else now (another digest, annotated, absent) is not authorised: refuse and report.
            if again is None or not again.recovering or again.digest != cur.digest:
                raise Refuse("dev is no longer the manifest %s the recovery is authorised for (now %s): not replaced" % (cur.digest, again.digest if again else "absent"))
            log("RECOVERY (one time, finding F-C5-1): replacing %s:%s, digest %s, which carries no revision annotation; its raw index follows" % (image, TAG, cur.digest))
            log(cur.raw.decode("utf-8", "replace"))
        elif again is not None and again.revision != (cur.revision if cur else None):
            raise Skip("dev changed to %s while this run was staging" % again.revision[:12])
        reg.create_index(staged, sha, configs, before=cur.digest if cur else None)
        index = reg.verify_index(staged, sha, configs)
        log("published %s:%s -> %s (linux/amd64 %s, linux/arm64 %s, revision %s)" % (image, TAG, index, staged["amd64"], staged["arm64"], sha))
        return {"published": True, "index": index, "staged": staged, "recovered": cur.digest if cur is not None and cur.recovering else None}
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
        # The one-time recovery is offered to the real image only, never to a fixture registry; it applies only to the exact recorded manifest.
        res = publish(Runner("docker"), Runner("git", 60), a.tested, sha, env, image=a.fixture_registry or IMAGE, fixture=fixture, recovery=None if fixture else KNOWN_BAD_DEV)
        lines = ["### dev image published", "", "* `%s:%s` -> `%s`" % (a.fixture_registry or IMAGE, TAG, res["index"]),
                 "* linux/amd64 `%s`, linux/arm64 `%s`, revision `%s`" % (res["staged"]["amd64"], res["staged"]["arm64"], sha)]
        if res.get("recovered"):
            lines.append("* one-time recovery (finding F-C5-1): replaced the unannotated manifest `%s`; read back as an annotated OCI index of the tested images" % res["recovered"])
        _summary(lines)
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
