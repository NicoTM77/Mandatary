"""Mutation check of scripts/publish_dev_image.py against tests/publish/test_publish.py (a maintainer tool, not run in CI).
usage: python3 -I tests/publish/mutate_publish.py REPO_ROOT NEW_EMPTY_WORKDIR [TEST_CLASS ...]
Every mutant must make the test suite FAIL; a surviving mutant is printed. With TEST_CLASS names (for example IndexPublication RecoveryTests) only those test
classes are run, to show which tests alone kill a mutant."""
import os
import shutil
import subprocess
import sys

repo, work = sys.argv[1], sys.argv[2]
src = open(os.path.join(repo, "scripts", "publish_dev_image.py")).read()
MUTANTS = [
    # the gate
    ("gate accepts pull_request", 'if env.get("GITHUB_EVENT_NAME") != "push":', 'if False:'),
    ("gate accepts any ref", 'if env.get("GITHUB_REF") != "refs/heads/main":', 'if False:'),
    ("gate accepts any repository", 'if env.get("GITHUB_REPOSITORY") != REPOSITORY:', 'if False:'),
    ("gate ignores pr refs", 'if env.get("GITHUB_BASE_REF") or env.get("GITHUB_HEAD_REF"):', 'if False:'),
    ("gate ignores needs results", 'if result != "success":', 'if False:'),
    ("a required job is dropped", 'REQUIRED_JOBS = ("baseline", "negative-control", "storage-arm64", "image", "security")', 'REQUIRED_JOBS = ("baseline", "negative-control", "image", "security")'),
    ("skipped counts as success", 'if result != "success":', 'if result not in ("success", "skipped"):'),
    # the tested image and its binding to what is pushed
    ("config digest not compared", 'if (doc.get("config") or {}).get("digest") != config_digest:', 'if False:'),
    ("served bytes not compared to the pushed digest", 'if got != digest:', 'if False:'),
    ("a wrapped index with several images accepted", 'if len(images) != 1:', 'if False:'),
    ("child platform unchecked", 'if (plat.get("os"), plat.get("architecture")) != ("linux", arch) or not DIGEST.match(str(e.get("digest", ""))):', 'if False:'),
    ("child bytes not compared", 'if got != digest:\n                raise Refuse("the registry served a manifest whose digest %s is not the listed %s"', 'if False:\n                raise Refuse("the registry served a manifest whose digest %s is not the listed %s"'),
    ("child must be a plain manifest", 'if doc.get("mediaType") not in MANIFEST_TYPES or "manifests" in doc:', 'if False:'),
    ("archive sha not checked", 'if sha256_file(tar) != rec["tar_sha256"]:', 'if False:'),
    ("recorded config not compared", 'if facts["config_digest"] != rec["config_digest"]:', 'if False:'),
    ("revision label not checked", 'if facts["labels"].get(REVISION_LABEL) != sha:', 'if False:'),
    ("source label not checked", 'if facts["labels"].get(SOURCE_LABEL) != source:', 'if False:'),
    ("arch not checked", 'if facts["os"] != "linux" or facts["architecture"] != arch:', 'if False:'),
    # freshness and ordering
    ("ancestor check dropped", 'if not ancestor(git, rev, sha):', 'if False:'),
    ("repeat run republishes", 'if rev == sha and not cur.recovering:', 'if False:'),
    ("dev re-read dropped", 'elif again is not None and again.revision != (cur.revision if cur else None):', 'elif False:'),
    ("unknown dev revision tolerated", 'if rev and HEX40.match(rev):', 'if True:'),
    ("unreadable dev treated as absent", 'if "not found" in low or "manifest unknown" in low or "404" in low or "name unknown" in low:', 'if True:'),
    # the OCI conversion (finding F-C5-1)
    ("docker v2 manifests are not converted", '        if doc.get("mediaType") == DOCKER_MANIFEST:', '        if False:'),
    ("conversion keeps another config", 'if cfg["digest"] != config_digest:', 'if False:'),
    ("conversion read-back digest not compared", 'if back_digest != want:', 'if False:'),
    ("conversion read-back layers not compared", 'if layer_digests is not None and [l.get("digest") for l in doc.get("layers") or []] != layer_digests:', 'if False:'),
    ("conversion api digest not compared", 'if got != want:\n            raise Refuse("the registry reports digest %s for the OCI manifest', 'if False:\n            raise Refuse("the registry reports digest %s for the OCI manifest'),
    ("unknown layer media type passes", 'if d.get("mediaType") not in media_map:', 'if False:'),
    ("unknown descriptor fields dropped silently", 'if not isinstance(d, dict) or set(d) - {"mediaType", "size", "digest"}:', 'if not isinstance(d, dict):'),
    ("unknown manifest fields dropped silently", 'if set(doc) - {"schemaVersion", "mediaType", "config", "layers"}:', 'if False:'),
    ("oci config media type not required", 'or cfg.get("mediaType") != OCI_CONFIG:', ':'),
    ("pre-write oci check removed", 'self.require_oci_children(staged, configs)', 'pass'),
    ("pre-write check ignores the tested config", 'self.require_oci_image(doc, a, configs[a])', 'self.require_oci_image(doc, a, (doc.get("config") or {}).get("digest"))'),
    # the read-back
    ("index revision annotation not checked", 'if annotations.get(ANN_REVISION) != sha:', 'if False:'),
    ("index source annotation not checked", 'if annotations.get(ANN_SOURCE) != SOURCE_URL:', 'if False:'),
    ("a docker list is accepted as the index", 'if doc.get("mediaType") != OCI_INDEX:', 'if doc.get("mediaType") not in INDEX_TYPES:'),
    ("index child media type not checked", 'if e.get("mediaType") != OCI_MANIFEST:', 'if False:'),
    ("index children not read back", 'self.require_oci_image(child, a, configs[a])', 'pass'),
    ("index platforms not checked", 'if e.get("digest") != staged[a]:', 'if False:'),
    ("index size not checked", 'if not isinstance(entries, list) or len(entries) != len(ARCHES):', 'if False:'),
    ("create success taken for verification", 'index = reg.verify_index(staged, sha, configs)', 'index = ""'),
    ("create failure ignored", 'if p.returncode != 0:\n            raise Refuse("imagetools create failed', 'if False:\n            raise Refuse("imagetools create failed'),
    ("a failed create is reported as unchanged", 'if now == before:', 'if True:'),
    # the one-time recovery
    ("recovery accepts any digest", 'if digest != recovery.digest:', 'if False:'),
    ("recovery not bound to the repository and tag", 'if recovery is not None and recovery.image == self.image and recovery.tag == TAG:', 'if recovery is not None:'),
    ("recovery not rechecked before the write", 'if again is None or not again.recovering or again.digest != cur.digest:', 'if False:'),
    ("recovery state change only skips", 'raise Refuse("dev is no longer the manifest %s the recovery is authorised for (now %s): not replaced"', 'raise Skip("dev is no longer the manifest %s the recovery is authorised for (now %s): not replaced"'),
    ("recovery not logged", 'log(cur.raw.decode("utf-8", "replace"))', 'pass'),
    ("recovery offered to a fixture registry", 'recovery=None if fixture else KNOWN_BAD_DEV', 'recovery=KNOWN_BAD_DEV'),
    ("recovery never offered", 'recovery=None if fixture else KNOWN_BAD_DEV', 'recovery=None'),
    ("recorded digest changed", '"sha256:0c8894070085f72c', '"sha256:0c8894070086f72c'),
    ("recorded revision changed", '"666ee9ce16d80440a9969c72b653975e84ba8ced")', '"666ee9ce16d80440a9969c72b653975e84ba8cee")'),
    # the registry API
    ("token realm host not checked", 'if realm.scheme != self.scheme or realm.netloc != self.host or realm.fragment or realm.username or realm.password:', 'if False:'),
    ("redirects are followed", 'def redirect_request(self, *args, **kwargs):\n        return None', 'def redirect_request(self, *args, **kwargs):\n        return super().redirect_request(*args, **kwargs)'),
    ("api digest header not checked", 'if got != want:\n            raise Refuse("the registry reports digest %r for the manifest', 'if False:\n            raise Refuse("the registry reports digest %r for the manifest'),
    ("push scope not requested", '"repository:%s:pull,push" % self.path', '"repository:%s:pull" % self.path'),
    ("the credential is not sent to the token endpoint", 'if self.token:\n            headers["Authorization"]', 'if False:\n            headers["Authorization"]'),
    ("the api writes any tag", 'if not STAGING_OCI_TAG.match(reference):', 'if False:'),
    ("non-loopback registries use http", 'self.scheme = "http" if self.loopback else "https"', 'self.scheme = "http"'),
    # the credential
    ("token on the command line", '"--password-stdin"], input=token.encode())', '"--password", token], input=token.encode())'),
    ("logout dropped", 'docker(["logout", "ghcr.io"])', 'pass'),
    ("login before verification", 'records = {a: load_record(tested, a, sha, source) for a in ARCHES}', 'records = {}\n    for a in ARCHES:\n        records[a] = load_record(tested, a, sha, source) if a == "amd64" else None\n    docker(["login"])'),
    ("push failure ignored", 'if p.returncode != 0:\n            raise Refuse("docker push failed for %s" % arch)', 'if False:\n            pass'),
    ("token file mode", 'os.chmod(cfg_dir, 0o700)', 'os.chmod(cfg_dir, 0o777)'),
]
survivors = []
ONLY = [s for s in os.environ.get("MUTANT_ONLY", "").split("|") if s]  # optional: run only the mutants whose name contains one of these
for index, (name, old, new) in enumerate(MUTANTS):
    if ONLY and not any(s in name for s in ONLY):
        continue
    if old not in src:
        print("PATTERN MISSING:", name)
        survivors.append(name + " (pattern missing)")
        continue
    d = os.path.join(work, "m%02d" % index)
    os.makedirs(os.path.join(d, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(d, "tests", "publish"), exist_ok=True)
    with open(os.path.join(d, "scripts", "publish_dev_image.py"), "w") as fh:
        fh.write(src.replace(old, new, 1))
    shutil.copy(os.path.join(repo, "tests", "publish", "test_publish.py"), os.path.join(d, "tests", "publish", "test_publish.py"))
    shutil.copytree(os.path.join(repo, "tests", "publish", "fixtures"), os.path.join(d, "tests", "publish", "fixtures"))
    p = subprocess.run([sys.executable, "-I", os.path.join(d, "tests", "publish", "test_publish.py")] + sys.argv[3:], capture_output=True, text=True)
    killed = p.returncode != 0
    print("%-8s %s" % ("KILLED" if killed else "SURVIVED", name))
    if not killed:
        survivors.append(name)
print("%d mutants, survivors: %s" % (len(MUTANTS), survivors))
