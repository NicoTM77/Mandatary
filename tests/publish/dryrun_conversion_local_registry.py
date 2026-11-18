#!/usr/bin/env python3
"""DRY RUN of the OCI conversion and the one-time recovery in scripts/publish_dev_image.py against a THROWAWAY LOCAL registry (registry:2 on 127.0.0.1) on an
isolated, disposable Docker host (the Mandatary test VM). Never ghcr.io, no credential, no production daemon. A maintainer tool: it is not run in CI and needs
docker with buildx, git and the registry:2 image.

    python3 -I tests/publish/dryrun_conversion_local_registry.py NEW_EMPTY_WORKDIR DIRECTORY_OF_publish_dev_image.py

What is real: the registry, `docker build`/`save`/`push`/`load`, `buildx imagetools inspect`/`create`, and every HTTP call of HttpRegistry. What is NOT real: the VM's
daemon uses the containerd image store and pushes OCI manifests, while a hosted runner's classic store pushes Docker v2 manifests. ClassicStoreDocker therefore
rewrites each pushed image manifest into its Docker v2 form (a PUT of the same blobs under the same tag) and reports that digest, as the classic store would. The
unannotated Docker manifest list that the first main publication left on ghcr.io is rebuilt with the real `imagetools create` over such children."""
import json
import os
import subprocess
import sys
import types
import urllib.request

WORK, SCRIPTS = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
sys.path.insert(0, SCRIPTS)
import publish_dev_image as pub  # noqa: E402

PORT = 5057
REG = "p120-c5pubfix-registry"
REPO = "localhost:%d/mandatary" % PORT
ACCEPT = ", ".join([pub.OCI_INDEX, pub.DOCKER_LIST, pub.OCI_MANIFEST, pub.DOCKER_MANIFEST])
FAILURES = []


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, check=False, **kw)


def check(name, ok, detail=""):
    print("%s %s %s" % ("PASS" if ok else "FAIL", name, detail))
    if not ok:
        FAILURES.append(name)


def get(path):
    req = urllib.request.Request("http://127.0.0.1:%d/v2/mandatary/%s" % (PORT, path), headers={"Accept": ACCEPT})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


class ClassicStoreDocker(pub.Runner):
    """The docker CLI of a hosted runner (classic image store): a pushed image is a Docker v2 manifest."""

    def __call__(self, args, input=None):
        p = super().__call__(args, input)
        if args[0] != "push" or p.returncode != 0:
            return p
        tag = args[1].rsplit(":", 1)[1]
        doc = json.loads(get("manifests/" + tag))
        if "manifests" in doc:  # the containerd store pushes a one-platform index (and an attestation): take the image manifest
            image = [m for m in doc["manifests"] if (m.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest"][0]
            doc = json.loads(get("manifests/" + image["digest"]))
        if doc["mediaType"] != pub.OCI_MANIFEST:
            return p
        classic = {"schemaVersion": 2, "mediaType": pub.DOCKER_MANIFEST,
                   "config": dict(doc["config"], mediaType=pub.DOCKER_CONFIG),
                   "layers": [dict(l, mediaType=[k for k, v in pub.LAYER_TO_OCI.items() if v == l["mediaType"]][0]) for l in doc["layers"]]}
        body = json.dumps(classic, indent=3).encode()
        digest = pub.HttpRegistry(REPO).put_manifest(tag, body, pub.DOCKER_MANIFEST)
        return types.SimpleNamespace(returncode=0, stdout=("%s: digest: %s size: %d\n" % (tag, digest, len(body))).encode(), stderr=b"")


def build_and_record(ctx, sha, outdir, docker):
    for arch in pub.ARCHES:
        r = sh(["docker", "buildx", "build", "--platform", "linux/" + arch, "--build-arg", "VCS_REF=" + sha, "--load", "-t", "mandatary-ci:" + arch, ctx])
        assert r.returncode == 0, r.stderr[-400:]
        pub.record(docker, "mandatary-ci:" + arch, arch, os.path.join(outdir, "tested-image-" + arch), sha)


def dev_raw():
    return get("manifests/dev")


def main():
    os.makedirs(WORK, exist_ok=True)
    os.chdir(WORK)
    repo = os.path.join(WORK, "repo")
    os.makedirs(repo)
    for cmd in (["git", "init", "-q", "."], ["git", "config", "user.email", "t@example.test"], ["git", "config", "user.name", "t"]):
        sh(cmd, cwd=repo)
    commits = []
    for text in ("a", "b", "c"):
        with open(os.path.join(repo, "f"), "w") as fh:
            fh.write(text)
        sh(["git", "add", "f"], cwd=repo)
        sh(["git", "commit", "-q", "-m", text], cwd=repo)
        commits.append(sh(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip())
    A, B, C = commits
    print("A=%s B=%s C=%s" % tuple(commits))
    ctx = os.path.join(WORK, "ctx")
    os.makedirs(ctx)
    with open(os.path.join(ctx, "marker"), "w") as fh:
        fh.write("marker\n")
    with open(os.path.join(ctx, "Dockerfile"), "w") as fh:
        fh.write('FROM scratch\nARG VCS_REF\nLABEL org.opencontainers.image.source="https://github.com/NicoTM77/Mandatary" org.opencontainers.image.revision="${VCS_REF}"\nCOPY marker /marker\n')
    docker = ClassicStoreDocker("docker")
    git = pub.Runner("git", 60)
    try:
        print("== registry")
        sh(["docker", "run", "-d", "--name", REG, "-p", "127.0.0.1:%d:5000" % PORT, "registry:2"])
        for _ in range(30):
            if sh(["curl", "-fsS", "http://127.0.0.1:%d/v2/" % PORT]).returncode == 0:
                break
            sh(["sleep", "1"])
        env = {"GITHUB_ACTOR": "x"}
        os.chdir(repo)

        print("== S1 first publication of A: Docker v2 children are converted, dev is an annotated OCI index")
        build_and_record(ctx, A, os.path.join(WORK, "tested-A"), docker)
        logs = []
        res = pub.publish(docker, git, os.path.join(WORK, "tested-A"), A, env, image=REPO, fixture=True, log=logs.append)
        print("\n".join(logs))
        raw = dev_raw()
        idx = json.loads(raw)
        check("S1 dev is an OCI image index", idx["mediaType"] == pub.OCI_INDEX, idx["mediaType"])
        check("S1 annotations", idx.get("annotations") == {pub.ANN_REVISION: A, pub.ANN_SOURCE: pub.SOURCE_URL}, json.dumps(idx.get("annotations")))
        check("S1 platforms", sorted(m["platform"]["architecture"] for m in idx["manifests"]) == ["amd64", "arm64"])
        for m in idx["manifests"]:
            child = json.loads(get("manifests/" + m["digest"]))
            rec = json.load(open(os.path.join(WORK, "tested-A", "tested-image-%s" % m["platform"]["architecture"], "image-%s.json" % m["platform"]["architecture"])))
            check("S1 %s child is an OCI manifest holding the tested config" % m["platform"]["architecture"],
                  m["mediaType"] == pub.OCI_MANIFEST and child["mediaType"] == pub.OCI_MANIFEST and child["config"]["digest"] == rec["config_digest"], child["config"]["digest"])
            pushed = json.loads(get("manifests/build-%s-%s" % (A, m["platform"]["architecture"])))
            check("S1 %s pushed Docker v2 manifest kept, same blobs" % m["platform"]["architecture"], pushed["mediaType"] == pub.DOCKER_MANIFEST
                  and [l["digest"] for l in pushed["layers"]] == [l["digest"] for l in child["layers"]] and pushed["config"]["digest"] == child["config"]["digest"])
        print("-- raw dev index:\n" + raw.decode())
        out = sh(["docker", "buildx", "imagetools", "inspect", REPO + ":dev"])
        print(out.stdout)
        check("S1 a repeated run is a verified no-op", _skipped(docker, git, os.path.join(WORK, "tested-A"), A))

        print("== S2 the first-main-run state: an unannotated Docker manifest list on dev (real imagetools create over Docker v2 children)")
        build_and_record(ctx, B, os.path.join(WORK, "tested-B"), docker)
        reg = pub.Registry(docker, REPO, pub.HttpRegistry(REPO))
        docker_children = {}
        for arch in pub.ARCHES:
            rec, tar = pub.load_record(os.path.join(WORK, "tested-B"), arch, B)
            docker(["load", "--input", tar])
            docker_children[arch] = _push_docker_v2(docker, arch, B)
        r = sh(["docker", "buildx", "imagetools", "create", "--tag", REPO + ":dev"] + ["%s@%s" % (REPO, docker_children[a]) for a in pub.ARCHES])
        print("imagetools create (no annotations) rc=%d %s" % (r.returncode, r.stderr.strip()[:200]))
        bad = dev_raw()
        bad_doc = json.loads(bad)
        check("S2 dev is now an unannotated Docker manifest list", bad_doc["mediaType"] == pub.DOCKER_LIST and "annotations" not in bad_doc, bad_doc["mediaType"])
        bad_digest = pub.sha256_bytes(bad)
        print("bad dev digest", bad_digest)
        build_and_record(ctx, C, os.path.join(WORK, "tested-C"), docker)
        try:
            pub.publish(docker, git, os.path.join(WORK, "tested-C"), C, env, image=REPO, fixture=True, log=print)
            check("S2 an ordinary run refuses the unannotated dev", False)
        except pub.Refuse as exc:
            check("S2 an ordinary run refuses the unannotated dev", "no revision annotation" in str(exc), str(exc)[:120])
        check("S2 dev unchanged by the refused run", dev_raw() == bad)
        wrong = pub.Recovery(REPO, pub.TAG, "sha256:" + "0" * 64, B)
        try:
            pub.publish(docker, git, os.path.join(WORK, "tested-C"), C, env, image=REPO, fixture=True, log=print, recovery=wrong)
            check("S2 a recovery for another digest is refused", False)
        except pub.Refuse as exc:
            check("S2 a recovery for another digest is refused", "not the one state" in str(exc), str(exc)[:120])
        check("S2 dev unchanged by the refused recovery", dev_raw() == bad)

        print("== S3 the one-time recovery, exact digest: replaced, read back")
        recovery = pub.Recovery(REPO, pub.TAG, bad_digest, B)
        logs = []
        res = pub.publish(docker, git, os.path.join(WORK, "tested-C"), C, env, image=REPO, fixture=True, log=logs.append, recovery=recovery)
        print("\n".join(logs))
        new = json.loads(dev_raw())
        check("S3 recovered the recorded manifest", res["recovered"] == bad_digest and pub.sha256_bytes(dev_raw()) == res["index"] != bad_digest)
        check("S3 dev is an annotated OCI index of the tested images of C", new["mediaType"] == pub.OCI_INDEX and new["annotations"][pub.ANN_REVISION] == C
              and all(m["mediaType"] == pub.OCI_MANIFEST for m in new["manifests"]))
        check("S3 the old Docker list is still readable by digest (untagged)", _readable(REPO, bad_digest))
        check("S3 a second run with the recovery offered is a verified no-op", _skipped(docker, git, os.path.join(WORK, "tested-C"), C, recovery))
    finally:
        sh(["docker", "rm", "-fv", REG])
        for arch in pub.ARCHES:
            sh(["docker", "image", "rm", "-f", "mandatary-ci:" + arch])
        tags = sh(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"]).stdout.split()
        for t in tags:
            if t.startswith(REPO + ":"):
                sh(["docker", "image", "rm", "-f", t])
        print("cleanup done")
    print("FAILURES: %s" % FAILURES)
    return 1 if FAILURES else 0


def _push_docker_v2(docker, arch, sha):
    ref = "%s:dockerv2-%s-%s" % (REPO, sha, arch)
    docker(["tag", pub.LOCAL_TAG % arch, ref])
    p = docker(["push", ref])
    return pub.PUSH_DIGEST.findall(p.stdout.decode())[-1]


def _readable(repo, digest):
    try:
        return pub.sha256_bytes(get("manifests/" + digest)) == digest
    except Exception:  # noqa: BLE001
        return False


def _skipped(docker, git, tested, sha, recovery=None):
    try:
        pub.publish(docker, git, tested, sha, {"GITHUB_ACTOR": "x"}, image=REPO, fixture=True, log=lambda *_: None, recovery=recovery)
    except pub.Skip:
        return True
    except pub.Refuse as exc:
        print("refused:", exc)
    return False


if __name__ == "__main__":
    sys.exit(main())
